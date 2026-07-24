mod auth_gate;
mod config;
mod credentials;
mod domain;
mod errors;
mod files;
mod google;
mod local_auth;
mod mcp;
mod mime;
mod oauth;
mod state;
mod storage;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Router, middleware, routing};
use http::HeaderName;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use config::ServerConfig;
use google::http as google_http;
use google::session::SessionCache;
use mcp::server::GoogleMcp;
use oauth::google::GoogleOAuthClient;
use oauth::proxy;
use state::{AppState, Tenancy};
use storage::{Db, accounts, codes::sweep_expired};

#[tokio::main]
async fn main() {
    // Subcommand selects the transport / identity model:
    //   (default) http  — multi-tenant HTTP server (unchanged, OAuth 2.1)
    //   stdio           — single-tenant MCP over stdin/stdout for Claude Desktop
    //   auth            — one-time browser sign-in that stores the local account
    match std::env::args().nth(1).as_deref() {
        None | Some("http") => run_http().await,
        Some("stdio") => run_stdio().await,
        Some("auth") => run_auth().await,
        Some(other) => {
            eprintln!("unknown subcommand `{other}`. usage: google-mcp [http|stdio|auth]");
            std::process::exit(2);
        }
    }
}

/// Initialize tracing. In stdio mode logs MUST go to stderr — stdout is the
/// MCP JSON-RPC channel and any stray byte there corrupts the protocol.
fn init_tracing(to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("google_mcp=info,rmcp=warn,reqwest=warn"));
    if to_stderr {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn load_config() -> ServerConfig {
    match ServerConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    }
}

async fn open_database(cfg: &ServerConfig) -> Db {
    match Db::open(&cfg.database_url).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not open database at {}: {e}", cfg.database_url);
            std::process::exit(2);
        }
    }
}

/// Local (stdio) mode auto-provisions the two crypto secrets so the `.mcpb`
/// bundle carries none. When `JWT_SECRET` / `STORAGE_ENCRYPTION_KEY` are absent
/// from the environment, they are loaded from `<DATABASE_URL>.keys` — generated
/// and persisted there on first run — and injected into the process env before
/// the config is read.
///
/// Must be called **after** `dotenvy::dotenv()`. `dotenvy` never overwrites a
/// variable that is already set, so anything injected here would otherwise win
/// over a `.env` file and silently swap the key that decrypts an existing
/// database.
fn ensure_local_secrets() -> Result<(), String> {
    let env_jwt = optional_env("JWT_SECRET");
    let env_key = optional_env("STORAGE_ENCRYPTION_KEY");
    if env_jwt.is_some() && env_key.is_some() {
        return Ok(());
    }

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "./google-mcp.db".to_string());
    let keyfile = PathBuf::from(format!("{db_url}.keys"));

    let (mut file_jwt, mut file_key) = (None, None);
    match std::fs::read_to_string(&keyfile) {
        Ok(content) => {
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("JWT_SECRET=").filter(|v| !v.is_empty()) {
                    file_jwt = Some(v.to_string());
                } else if let Some(v) = line
                    .strip_prefix("STORAGE_ENCRYPTION_KEY=")
                    .filter(|v| !v.is_empty())
                {
                    file_key = Some(v.to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("could not read {}: {e}", keyfile.display())),
    }

    // Prefer an env-supplied value even when persisting, so the keyfile and the
    // running process never disagree about a secret.
    let jwt = env_jwt
        .clone()
        .or(file_jwt.clone())
        .unwrap_or_else(random_hex_64);
    let key = env_key
        .clone()
        .or(file_key.clone())
        .unwrap_or_else(random_storage_key);

    // Only rewrite when the file does not already hold exactly these values.
    // Rewriting on every launch would risk truncating a perfectly good keyfile,
    // and losing STORAGE_ENCRYPTION_KEY makes every stored token undecryptable.
    if file_jwt.as_deref() != Some(&jwt) || file_key.as_deref() != Some(&key) {
        write_keyfile(&keyfile, &jwt, &key)?;
    }

    // SAFETY: `set_var` requires that no other thread concurrently reads or
    // writes the environment. This runs at the top of the chosen subcommand,
    // before any task or client has been spawned, so the tokio workers are
    // parked and nothing else touches the environment.
    unsafe {
        if env_jwt.is_none() {
            std::env::set_var("JWT_SECRET", &jwt);
        }
        if env_key.is_none() {
            std::env::set_var("STORAGE_ENCRYPTION_KEY", &key);
        }
    }
    Ok(())
}

fn optional_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn random_hex_64() -> String {
    use rand::RngCore;
    let mut b = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_storage_key() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Write the keyfile atomically and never world-readable.
///
/// The temp file is created with `create_new` at mode `0600`, so the secrets are
/// never briefly readable by other local users (a plain create-then-chmod leaves
/// exactly that window) and a pre-planted symlink cannot redirect the write. The
/// rename is atomic, so an interrupted run can never leave a half-written or
/// empty keyfile behind.
fn write_keyfile(path: &Path, jwt: &str, key: &str) -> Result<(), String> {
    use std::io::Write;

    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let _ = std::fs::remove_file(&tmp);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("could not create {}: {e}", tmp.display()))?;

    let write = (|| -> std::io::Result<()> {
        writeln!(f, "JWT_SECRET={jwt}")?;
        writeln!(f, "STORAGE_ENCRYPTION_KEY={key}")?;
        f.sync_all()
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("could not write {}: {e}", tmp.display()));
    }
    drop(f);

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("could not install {}: {e}", path.display())
    })
}

fn build_oauth_client(cfg: &ServerConfig, http: &Arc<reqwest::Client>) -> GoogleOAuthClient {
    GoogleOAuthClient::new(
        cfg.google_client_id.clone(),
        cfg.google_client_secret.clone(),
        cfg.google_redirect_uri(),
        domain::google_scopes(&cfg.enabled_domains),
        (**http).clone(),
    )
}

// ---------------------------------------------------------------------------
// HTTP mode (default) — unchanged multi-tenant server.
// ---------------------------------------------------------------------------

async fn run_http() {
    init_tracing(false);

    let cfg = load_config();
    tracing::info!(?cfg, "starting google-mcp (http)");

    let db = open_database(&cfg).await;
    tracing::info!("database opened at {}", cfg.database_url);

    let http = Arc::new(google_http::build());
    let google_oauth = Arc::new(build_oauth_client(&cfg, &http));
    let session_cache = SessionCache::new(
        db.clone(),
        Arc::clone(&google_oauth),
        cfg.storage_encryption_key,
    );

    let state = AppState {
        config: Arc::new(cfg),
        db: db.clone(),
        http: Arc::clone(&http),
        google_oauth,
        session_cache,
        tenancy: Tenancy::MultiTenant,
    };

    spawn_oauth_state_sweeper(db.clone());

    let app = build_router(state.clone());

    let addr: SocketAddr = format!("{}:{}", state.config.host, state.config.port)
        .parse()
        .unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("google-mcp listening on http://{addr}");

    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("shutting down");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// stdio mode — single-tenant MCP over stdin/stdout (Claude Desktop / .mcpb).
// ---------------------------------------------------------------------------

async fn run_stdio() {
    init_tracing(true); // stderr only — stdout is the MCP channel

    // Load `.env` first: `ensure_local_secrets` injects into the process
    // environment, and dotenvy will not overwrite an already-set variable, so
    // provisioning before this would shadow a `.env`-supplied key.
    let _ = dotenvy::dotenv();
    if let Err(e) = ensure_local_secrets() {
        eprintln!("{e}");
        std::process::exit(2);
    }
    let cfg = load_config();
    let db = open_database(&cfg).await;
    let http = Arc::new(google_http::build());
    let google_oauth = Arc::new(build_oauth_client(&cfg, &http));
    let session_cache = SessionCache::new(
        db.clone(),
        Arc::clone(&google_oauth),
        cfg.storage_encryption_key,
    );

    let sub = match accounts::latest_google_sub(&db).await {
        Ok(sub) => sub,
        Err(e) => {
            // Do not silently degrade to "no account": that would tell the user
            // to sign in when the real problem is the store.
            eprintln!("could not read the local account store: {e}");
            std::process::exit(2);
        }
    };
    match &sub {
        Some(s) => tracing::info!("single-tenant stdio bound to account sub={s}"),
        None => tracing::warn!(
            "no Google account connected yet — use the `google_authenticate` tool to sign in"
        ),
    }
    let tenancy = Tenancy::Single(Arc::new(std::sync::RwLock::new(
        sub.map(|s| Arc::from(s.as_str())),
    )));

    let state = AppState {
        config: Arc::new(cfg),
        db,
        http,
        google_oauth,
        session_cache,
        tenancy,
    };
    let mcp = GoogleMcp::new(state);

    tracing::info!("serving google-mcp over stdio");
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let running = match rmcp::serve_server(mcp, transport).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("stdio serve init failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = running.waiting().await {
        eprintln!("stdio session ended with error: {e}");
    }
}

// ---------------------------------------------------------------------------
// auth mode — one-time browser loopback sign-in, stores the local account.
// ---------------------------------------------------------------------------

async fn run_auth() {
    init_tracing(true);

    // Load `.env` first: `ensure_local_secrets` injects into the process
    // environment, and dotenvy will not overwrite an already-set variable, so
    // provisioning before this would shadow a `.env`-supplied key.
    let _ = dotenvy::dotenv();
    if let Err(e) = ensure_local_secrets() {
        eprintln!("{e}");
        std::process::exit(2);
    }
    let cfg = load_config();
    let db = open_database(&cfg).await;
    let http = Arc::new(google_http::build());
    let google_oauth = build_oauth_client(&cfg, &http);
    let scopes = domain::google_scopes(&cfg.enabled_domains);

    match local_auth::run_loopback(
        &google_oauth,
        &cfg.base_url,
        &db,
        &cfg.storage_encryption_key,
        scopes,
        true,
    )
    .await
    {
        Ok(outcome) => {
            println!("Connected Google account: {}", outcome.email);
            eprintln!("Saved. The server is ready — Claude Desktop will use it over stdio.");
        }
        Err(e) => {
            eprintln!("sign-in failed: {e}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared HTTP wiring (used by run_http).
// ---------------------------------------------------------------------------

fn build_router(state: AppState) -> Router {
    let cors = build_cors(&state.config);

    // rmcp Streamable HTTP service. The factory closure is invoked once
    // per session; we hand each one its own GoogleMcp pointing at the
    // shared AppState. Stateless-mode (NeverSessionManager) keeps things
    // simple: each request is independent.
    let mcp_state = state.clone();
    let mut mcp_config = StreamableHttpServerConfig::default();
    mcp_config.stateful_mode = false;
    mcp_config.json_response = true;
    let mcp_service = StreamableHttpService::new(
        move || Ok(GoogleMcp::new(mcp_state.clone())),
        Arc::new(NeverSessionManager::default()),
        mcp_config,
    );

    let mcp_routes = Router::new()
        .route("/mcp", routing::any_service(mcp_service))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_gate::require_bearer,
        ));

    Router::new()
        .route("/health", routing::get(health))
        .route(
            "/.well-known/oauth-authorization-server",
            routing::get(proxy::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            routing::get(proxy::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            routing::get(proxy::protected_resource_metadata),
        )
        .route("/oauth/register", routing::post(proxy::register))
        .route("/authorize", routing::get(proxy::authorize))
        .route(
            "/oauth/google/callback",
            routing::get(proxy::google_callback),
        )
        .route("/oauth/token", routing::post(proxy::token))
        .merge(mcp_routes)
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

fn build_cors(cfg: &ServerConfig) -> CorsLayer {
    let mut layer = CorsLayer::new().allow_methods(Any).allow_headers([
        AUTHORIZATION,
        CONTENT_TYPE,
        HeaderName::from_static("mcp-session-id"),
        HeaderName::from_static("mcp-protocol-version"),
    ]);
    if cfg.cors_allow_localhost {
        // Permissive for dev — origins can include arbitrary localhost ports.
        layer = layer.allow_origin(Any);
    } else {
        // Production: only Claude.ai/Claude.com origins.
        let origins = ["https://claude.ai", "https://claude.com"];
        let parsed: Vec<http::HeaderValue> = origins
            .into_iter()
            .filter_map(|o| http::HeaderValue::from_str(o).ok())
            .collect();
        layer = layer.allow_origin(parsed);
    }
    layer
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

fn spawn_oauth_state_sweeper(db: Db) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
        interval.tick().await; // skip first immediate tick
        loop {
            interval.tick().await;
            match sweep_expired(&db).await {
                Ok(n) if n > 0 => tracing::debug!("swept {n} expired oauth_codes/states rows"),
                Ok(_) => {}
                Err(e) => tracing::warn!(err = ?e, "sweep_expired failed"),
            }
        }
    });
}
