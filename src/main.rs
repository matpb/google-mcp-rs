mod auth_gate;
mod config;
mod credentials;
mod errors;
mod google;
mod mcp;
mod mime;
mod oauth;
mod storage;

use std::net::SocketAddr;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use config::ServerConfig;

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

    // Phase-0 skeleton: only /health is wired. /mcp, /oauth/*, well-known
    // endpoints land in subsequent phases.
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse().unwrap();
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

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}
