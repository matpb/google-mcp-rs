//! One-time browser loopback sign-in for single-tenant (stdio) deployments.
//!
//! Used by both the `auth` CLI subcommand and the in-session
//! `google_authenticate` tool. Binds a short-lived listener on the `BASE_URL`
//! port, opens the user's browser to Google's consent screen, captures the
//! callback, exchanges the code, and stores the encrypted account locally.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::Html;
use axum::{Router, routing};
use tokio::net::TcpListener;

use crate::oauth::google::{GoogleOAuthClient, parse_id_token};
use crate::storage::{Db, accounts};

/// The connected account, returned on success.
pub struct AuthOutcome {
    pub email: String,
    #[allow(dead_code)]
    pub google_sub: String,
}

struct Shared {
    tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<Result<String, String>>>>,
    expected_state: String,
}

#[derive(serde::Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Run the loopback OAuth flow to completion. `open` controls whether the
/// browser is launched automatically (the URL is always logged to stderr as a
/// fallback). Returns the connected account or a human-readable error.
pub async fn run_loopback(
    oauth: &GoogleOAuthClient,
    base_url: &str,
    db: &Db,
    storage_key: &[u8; 32],
    default_scopes: Vec<String>,
    open: bool,
) -> Result<AuthOutcome, String> {
    // The listener must answer on the same host:port as the registered redirect
    // URI (BASE_URL + /oauth/google/callback).
    let uri: http::Uri = base_url
        .parse()
        .map_err(|e| format!("invalid BASE_URL `{base_url}`: {e}"))?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });

    let expected_state = uuid::Uuid::new_v4().simple().to_string();
    let auth_url = oauth.build_authorize_url(&expected_state, None);

    let (tx, rx) = tokio::sync::oneshot::channel::<Result<String, String>>();
    let shared = Arc::new(Shared {
        tx: std::sync::Mutex::new(Some(tx)),
        expected_state,
    });
    let app = Router::new()
        .route("/oauth/google/callback", routing::get(callback))
        .with_state(shared);

    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("could not bind loopback listener on 127.0.0.1:{port}: {e}"))?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    if open {
        open_browser(&auth_url);
    }
    eprintln!("Sign in with Google at:\n{auth_url}\n");

    let code = match rx.await {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            server.abort();
            return Err(e);
        }
        Err(_) => {
            server.abort();
            return Err("sign-in cancelled (callback channel closed)".to_string());
        }
    };
    // Let the browser render the success page before we drop the listener.
    tokio::time::sleep(Duration::from_millis(400)).await;
    server.abort();

    let grant = oauth
        .exchange_code(&code)
        .await
        .map_err(|e| format!("token exchange failed: {e}"))?;
    let id_token = grant
        .id_token
        .as_deref()
        .ok_or_else(|| "Google did not return an id_token (need 'openid' scope)".to_string())?;
    let id = parse_id_token(id_token).map_err(|e| format!("could not parse id_token: {e}"))?;
    let refresh_token = grant.refresh_token.as_deref().ok_or_else(|| {
        "Google did not return a refresh_token. Revoke prior access at \
         https://myaccount.google.com/permissions and try again."
            .to_string()
    })?;
    let scopes: Vec<String> = grant
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or(default_scopes);
    let email = id.email.clone().unwrap_or_default();

    accounts::upsert(
        db,
        storage_key,
        accounts::UpsertAccount {
            google_sub: id.sub.clone(),
            email: email.clone(),
            refresh_token: refresh_token.to_string(),
            scopes,
        },
    )
    .await
    .map_err(|e| format!("could not store account: {e}"))?;

    Ok(AuthOutcome {
        email,
        google_sub: id.sub,
    })
}

async fn callback(
    State(shared): State<Arc<Shared>>,
    Query(q): Query<CallbackQuery>,
) -> Html<&'static str> {
    let result = if let Some(err) = q.error {
        Err(format!("Google returned error: {err}"))
    } else if q.state.as_deref() != Some(shared.expected_state.as_str()) {
        Err("state mismatch (possible CSRF)".to_string())
    } else if let Some(code) = q.code {
        Ok(code)
    } else {
        Err("callback missing authorization code".to_string())
    };
    let ok = result.is_ok();
    if let Some(tx) = shared.tx.lock().unwrap().take() {
        let _ = tx.send(result);
    }
    if ok {
        Html(
            "<!doctype html><html><body style=\"font-family:sans-serif;max-width:540px;margin:4rem auto;padding:0 1rem\">\
             <h1 style=\"color:#2a6\">Connected to Google</h1>\
             <p>You can close this tab and return to Claude.</p></body></html>",
        )
    } else {
        Html(
            "<!doctype html><html><body style=\"font-family:sans-serif;max-width:540px;margin:4rem auto;padding:0 1rem\">\
             <h1 style=\"color:#b00\">Sign-in failed</h1>\
             <p>Check the terminal for details. You can close this tab.</p></body></html>",
        )
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
