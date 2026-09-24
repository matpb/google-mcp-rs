mod auth_gate;
mod config;
mod credentials;
mod domain;
mod errors;
mod files;
mod google;
mod host_guard;
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
use storage::{Db, accounts, clients, codes::sweep_expired};
use tower_http::cors::AllowOrigin;

const USAGE: &str =
    "usage: google-mcp [http|stdio|auth|accounts list|accounts revoke <email-or-sub>|version|help]";

#[tokio::main]
async fn main() {
    // Subcommand selects the transport / identity model:
    //   (default) http  — multi-tenant HTTP server (unchanged, OAuth 2.1)
    //   stdio           — single-tenant MCP over stdin/stdout for local MCP clients
    //   auth            — one-time browser sign-in that stores the local account
    //   version / help  — print version / usage and exit
    match std::env::args().nth(1).as_deref() {
        None | Some("http") => run_http().await,
        Some("stdio") => run_stdio().await,
        Some("auth") => run_auth().await,
        Some("accounts") => run_accounts(std::env::args().skip(2).collect()).await,
        Some("version" | "--version" | "-V") => {
            println!("google-mcp {}", env!("CARGO_PKG_VERSION"));
        }
        Some("help" | "--help" | "-h") => println!("{USAGE}"),
        Some(other) => {
            eprintln!("unknown subcommand `{other}`. {USAGE}");
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

/// Loads `JWT_SECRET` / `STORAGE_ENCRYPTION_KEY` from `<DATABASE_URL>.keys` when unset, generating the file on first run.
/// Must run after `dotenvy::dotenv()`: dotenvy never overwrites a set variable, so a `.env` key would otherwise silently win.
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
    #[allow(unsafe_code)]
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
    let mut b = [0u8; 64];
    getrandom::fill(&mut b).expect("OS RNG failure");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_storage_key() -> String {
    use base64::Engine;
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS RNG failure");
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
        cfg.allowed_google_accounts.clone(),
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
// stdio mode — single-tenant MCP over stdin/stdout (local MCP clients).
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
        cfg.allowed_google_accounts.clone(),
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
// accounts subcommand — works alongside a running server (SQLite WAL).
// ---------------------------------------------------------------------------

async fn run_accounts(args: Vec<String>) {
    init_tracing(true);
    let _ = dotenvy::dotenv();
    if let Err(e) = ensure_local_secrets() {
        eprintln!("{e}");
        std::process::exit(2);
    }
    let cfg = load_config();
    let db = open_database(&cfg).await;
    match args.first().map(String::as_str) {
        Some("list") => accounts_list(&db).await,
        Some("revoke") => match args.get(1) {
            Some(target) => accounts_revoke(&cfg, &db, target).await,
            None => {
                eprintln!("usage: google-mcp accounts revoke <email-or-sub>");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!("usage: google-mcp accounts [list|revoke <email-or-sub>]");
            std::process::exit(2);
        }
    }
}

fn fmt_unix(secs: i64) -> String {
    let fmt = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]");
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(&fmt).ok())
        .unwrap_or_else(|| secs.to_string())
}

async fn accounts_list(db: &Db) {
    match accounts::list_all(db).await {
        Ok(rows) => {
            println!(
                "{:<24} {:<32} {:<17} {:<17} {:<17}",
                "sub", "email", "created (UTC)", "updated (UTC)", "last refresh (UTC)"
            );
            for a in rows {
                println!(
                    "{:<24} {:<32} {:<17} {:<17} {:<17}",
                    a.google_sub,
                    a.email,
                    fmt_unix(a.created_at),
                    fmt_unix(a.updated_at),
                    a.last_refresh_at.map_or_else(|| "-".to_string(), fmt_unix)
                );
            }
        }
        Err(e) => {
            eprintln!("could not list accounts: {e}");
            std::process::exit(1);
        }
    }
}

async fn accounts_revoke(cfg: &ServerConfig, db: &Db, target: &str) {
    let account = match accounts::find_by_email_or_sub(db, target).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            eprintln!("no account found matching `{target}`");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("lookup failed: {e}");
            std::process::exit(1);
        }
    };

    let now = storage::now_secs();
    if let Err(e) = storage::revocations::revoke(db, &account.google_sub, now).await {
        eprintln!("could not write revocation tombstone: {e}");
        std::process::exit(1);
    }
    println!(
        "tombstoned sub={} (JWTs issued before now are now invalid)",
        account.google_sub
    );

    match accounts::get_refresh_token(db, &cfg.storage_encryption_key, &account.google_sub).await {
        Ok(Some(rt)) => {
            let http = google_http::build();
            match oauth::google::revoke_token(&http, &rt).await {
                Ok(()) => println!("revoked refresh token with Google"),
                Err(e) => eprintln!("warning: Google revoke call failed (best-effort): {e}"),
            }
        }
        Ok(None) => eprintln!("warning: no refresh token stored to revoke with Google"),
        Err(e) => eprintln!("warning: could not decrypt refresh token: {e}"),
    }

    if let Err(e) = accounts::delete(db, &account.google_sub).await {
        eprintln!("could not delete account row: {e}");
        std::process::exit(1);
    }
    println!("deleted account row for {}", account.email);
}

// ---------------------------------------------------------------------------
// Shared HTTP wiring (used by run_http).
// ---------------------------------------------------------------------------

fn build_router(state: AppState) -> Router {
    let cors = build_cors(&state.config);
    let allowed_hosts =
        host_guard::allowed_host_strings(&state.config.base_url, &state.config.allowed_hosts);

    // rmcp Streamable HTTP service. The factory closure is invoked once
    // per session; we hand each one its own GoogleMcp pointing at the
    // shared AppState. Stateless-mode (NeverSessionManager) keeps things
    // simple: each request is independent.
    let mcp_state = state.clone();
    let mut mcp_config = StreamableHttpServerConfig::default();
    mcp_config.legacy_session_mode = false;
    mcp_config.json_response = true;
    mcp_config = mcp_config.with_allowed_hosts(allowed_hosts);
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

    // Every route except /health is behind the Host allowlist — a wildcard
    // Host used against DNS rebinding could otherwise reach OAuth endpoints.
    let guarded = Router::new()
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
            "/authorize/consent",
            routing::post(proxy::authorize_consent),
        )
        .route(
            "/oauth/google/callback",
            routing::get(proxy::google_callback),
        )
        .route("/oauth/token", routing::post(proxy::token))
        .merge(mcp_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            host_guard::check_host,
        ));

    Router::new()
        .route("/health", routing::get(health))
        .merge(guarded)
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
        // Dev-only: any localhost/127.0.0.1/[::1] origin, any scheme/port —
        // never `Any`, which would also allow arbitrary third-party origins.
        layer = layer.allow_origin(AllowOrigin::predicate(|origin, _| {
            is_loopback_origin(origin)
        }));
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

fn is_loopback_origin(origin: &http::HeaderValue) -> bool {
    origin
        .to_str()
        .ok()
        .and_then(|s| url::Url::parse(s).ok())
        .is_some_and(|u| {
            matches!(
                u.host_str(),
                Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
            )
        })
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
            match clients::delete_stale_unused(&db, 24 * 3600).await {
                Ok(n) if n > 0 => tracing::debug!("swept {n} stale unused mcp_clients rows"),
                Ok(_) => {}
                Err(e) => tracing::warn!(err = ?e, "delete_stale_unused failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{HeaderValue, Request};
    use tower::ServiceExt;

    #[test]
    fn loopback_origin_accepted() {
        assert!(is_loopback_origin(&HeaderValue::from_static(
            "http://localhost:5173"
        )));
        assert!(is_loopback_origin(&HeaderValue::from_static(
            "http://127.0.0.1:3000"
        )));
    }

    #[test]
    fn non_loopback_origin_rejected() {
        assert!(!is_loopback_origin(&HeaderValue::from_static(
            "https://evil.example"
        )));
    }

    async fn test_state(base_url: &str, allowed_hosts: Vec<String>) -> AppState {
        let db = Db::open_in_memory().await.expect("open in-memory db");
        let http = Arc::new(reqwest::Client::new());
        let google_oauth = Arc::new(GoogleOAuthClient::new(
            "test-cid",
            "test-csecret",
            format!("{base_url}/oauth/google/callback"),
            domain::google_scopes(&[domain::Domain::Gmail]),
            (*http).clone(),
        ));
        let session_cache =
            SessionCache::new(db.clone(), Arc::clone(&google_oauth), [0u8; 32], vec![]);
        let config = Arc::new(ServerConfig {
            host: "127.0.0.1".parse().unwrap(),
            port: 8433,
            base_url: base_url.to_string(),
            google_client_id: "test-cid".to_string(),
            google_client_secret: "test-csecret".to_string(),
            jwt_secret: vec![0u8; 32],
            storage_encryption_key: [0u8; 32],
            database_url: ":memory:".to_string(),
            cors_allow_localhost: true,
            allowed_hosts,
            enabled_domains: vec![domain::Domain::Gmail],
            allowed_google_accounts: vec![],
            file_jail: None,
            file_maintenance: files::FileMaintenance::Off,
        });
        AppState {
            config,
            db,
            http,
            google_oauth,
            session_cache,
            tenancy: Tenancy::MultiTenant,
        }
    }

    #[tokio::test]
    async fn mcp_with_garbage_bearer_is_401_invalid_token() {
        let state = test_state("http://localhost:8433", vec![]).await;
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(http::header::HOST, "localhost:8433")
            .header(http::header::AUTHORIZATION, "Bearer garbage")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains(r#"error="invalid_token""#));
    }

    #[tokio::test]
    async fn well_known_with_evil_host_is_403() {
        let state = test_state("http://localhost:8433", vec![]).await;
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/oauth-authorization-server")
            .header(http::header::HOST, "evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn well_known_with_allowed_host_but_evil_forwarded_host_is_403() {
        let state = test_state("http://localhost:8433", vec![]).await;
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/oauth-authorization-server")
            .header(http::header::HOST, "localhost:8433")
            .header("x-forwarded-host", "evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorize_on_non_base_host_redirects_to_base_url_with_same_query() {
        let state = test_state("http://localhost:8433", vec!["evil.example".to_string()]).await;
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/authorize?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fx%2Fcb&code_challenge=a&code_challenge_method=S256")
            .header(http::header::HOST, "evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp
            .headers()
            .get(http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("http://localhost:8433/authorize?"));
        assert!(loc.contains("client_id=x"));
    }

    #[tokio::test]
    async fn revoked_token_is_401_invalid_token() {
        let state = test_state("http://localhost:8433", vec![]).await;
        let now = oauth::jwt::now_secs();
        let claims = oauth::jwt::Claims {
            iss: "http://localhost:8433".to_string(),
            sub: "sub-revoked".to_string(),
            iat: now,
            exp: now + 3600,
            aud: "http://localhost:8433/mcp".to_string(),
        };
        let jwt = oauth::jwt::sign(&state.config.jwt_secret, &claims).unwrap();
        storage::revocations::revoke(&state.db, "sub-revoked", (now + 1) as i64)
            .await
            .unwrap();

        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(http::header::HOST, "localhost:8433")
            .header(http::header::AUTHORIZATION, format!("Bearer {jwt}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains("token revoked"));
    }

    #[tokio::test]
    async fn health_ignores_host_allowlist() {
        let state = test_state("http://localhost:8433", vec![]).await;
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .header(http::header::HOST, "10.0.0.5")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
