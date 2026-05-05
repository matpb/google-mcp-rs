//! Shared `reqwest::Client` used by both the OAuth client and the Gmail
//! API client. Built once at startup with sane timeouts and a clear UA so
//! Google's logs identify us.

use std::time::Duration;

pub fn build() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("google-mcp/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Some(Duration::from_secs(30)))
        .build()
        .expect("reqwest client")
}
