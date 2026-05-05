mod auth_gate;
mod config;
mod credentials;
mod errors;
mod google;
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
use oauth::google::{DEFAULT_SCOPES, GoogleOAuthClient};
use oauth::proxy;
use state::AppState;
use storage::{Db, codes::sweep_expired};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("google_mcp=info,rmcp=warn,reqwest=warn")),
        )
        .init();

    let cfg = match ServerConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    tracing::info!(?cfg, "starting google-mcp");

    let db = match Db::open(&cfg.database_url).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not open database at {}: {e}", cfg.database_url);
            std::process::exit(2);
        }
    };
    tracing::info!("database opened at {}", cfg.database_url);

    let http = Arc::new(google_http::build());

    let google_oauth = Arc::new(GoogleOAuthClient::new(
        cfg.google_client_id.clone(),
        cfg.google_client_secret.clone(),
        cfg.google_redirect_uri(),
        DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect(),
        (*http).clone(),
    ));

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
