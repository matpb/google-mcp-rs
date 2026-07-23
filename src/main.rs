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
/// from the environment, generate them once and persist beside the database
/// (`<DATABASE_URL>.keys`, mode 0600), then inject into the process env before
/// config is read. Existing/env-supplied values are always respected.
fn ensure_local_secrets() {
    use std::io::Write;

    let need_jwt = std::env::var("JWT_SECRET")
        .ok()
        .filter(|v| !v.is_empty())
        .is_none();
    let need_key = std::env::var("STORAGE_ENCRYPTION_KEY")
        .ok()
        .filter(|v| !v.is_empty())
        .is_none();
    if !need_jwt && !need_key {
        return;
    }

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "./google-mcp.db".to_string());
    let keyfile = format!("{db_url}.keys");

    let (mut jwt, mut key) = (None, None);
    if let Ok(content) = std::fs::read_to_string(&keyfile) {
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("JWT_SECRET=") {
                jwt = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("STORAGE_ENCRYPTION_KEY=") {
                key = Some(v.to_string());
            }
        }
    }

    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let jwt = jwt.unwrap_or_else(|| {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    });
    let key = key.unwrap_or_else(|| {
        use base64::Engine;
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    });

    if let Ok(mut f) = std::fs::File::create(&keyfile) {
        let _ = writeln!(f, "JWT_SECRET={jwt}");
        let _ = writeln!(f, "STORAGE_ENCRYPTION_KEY={key}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600));
        }
    }

    // SAFETY: called at process startup before any task reads the environment.
    unsafe {
        if need_jwt {
            std::env::set_var("JWT_SECRET", &jwt);
        }
        if need_key {
            std::env::set_var("STORAGE_ENCRYPTION_KEY", &key);
        }
    }
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

    ensure_local_secrets();
    let cfg = load_config();
    let db = open_database(&cfg).await;
    let http = Arc::new(google_http::build());
    let google_oauth = Arc::new(build_oauth_client(&cfg, &http));
    let session_cache = SessionCache::new(
        db.clone(),
        Arc::clone(&google_oauth),
        cfg.storage_encryption_key,
    );

    let sub = accounts::first_google_sub(&db).await.unwrap_or(None);
    match &sub {
        Some(s) => tracing::info!("single-tenant stdio bound to account sub={s}"),
        None => tracing::warn!("no Google account connected yet — run `google-mcp auth` once"),
    }
    let tenancy = Tenancy::Single(sub.map(|s| Arc::from(s.as_str())));

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

    ensure_local_secrets();
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
