//! Google Calendar v3 client. Same shape as the Sheets / Drive / Docs
//! clients: a thin reqwest wrapper that authenticates with the user's
//! current access token and forwards Google's JSON to callers as
//! `serde_json::Value`.
//!
//! Calendar IDs are typically `"primary"`, an email address, or a
//! `…@group.calendar.google.com` ID. `@` is a path-safe character per
//! RFC 3986, so we format IDs into the URL directly without escaping —
//! matching how `sheets.rs` formats A1 ranges.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum CalendarError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Calendar returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Calendar response: {0}")]
    Parse(serde_json::Error),
}

const BASE: &str = "https://www.googleapis.com/calendar/v3";

#[derive(Clone)]
pub struct CalendarClient {
    http: reqwest::Client,
    access_token: String,
}

impl CalendarClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    // ---------------------------------------------------------------------
    // Calendars + CalendarList
    // ---------------------------------------------------------------------

    /// List calendars on the user's calendar list (i.e. calendars they're
    /// subscribed to, including their own primary plus any shared calendars).
    pub async fn list_calendar_list(
        &self,
        max_results: Option<u32>,
        page_token: Option<&str>,
        show_deleted: bool,
        show_hidden: bool,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(n) = max_results {
            q.push(("maxResults".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            q.push(("pageToken".into(), t.into()));
        }
        if show_deleted {
            q.push(("showDeleted".into(), "true".into()));
        }
        if show_hidden {
            q.push(("showHidden".into(), "true".into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/users/me/calendarList"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_calendar(&self, calendar_id: &str) -> Result<Value, CalendarError> {
        self.request(
            Method::GET,
            format!("{BASE}/calendars/{calendar_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    /// Create a new secondary calendar owned by the user. Body must include
    /// `{"summary":"..."}`; optional `description`, `location`, `timeZone`.
    pub async fn create_calendar(&self, body: &Value) -> Result<Value, CalendarError> {
        self.request(Method::POST, format!("{BASE}/calendars"), Some(body), &[])
            .await
    }

    /// Permanently delete a secondary calendar. The user's primary calendar
    /// cannot be deleted.
    pub async fn delete_calendar(&self, calendar_id: &str) -> Result<Value, CalendarError> {
        self.request(
            Method::DELETE,
            format!("{BASE}/calendars/{calendar_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    pub async fn list_events(
        &self,
        calendar_id: &str,
        params: &EventsListQuery<'_>,
    ) -> Result<Value, CalendarError> {
        let q = params.to_query();
        self.request(
            Method::GET,
            format!("{BASE}/calendars/{calendar_id}/events"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_event(
        &self,
        calendar_id: &str,
        event_id: &str,
        time_zone: Option<&str>,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(tz) = time_zone {
            q.push(("timeZone".into(), tz.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/calendars/{calendar_id}/events/{event_id}"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn create_event(
        &self,
        calendar_id: &str,
        body: &Value,
        send_updates: Option<&str>,
        conference_data_version: Option<u8>,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(s) = send_updates {
            q.push(("sendUpdates".into(), s.into()));
        }
        if let Some(v) = conference_data_version {
            q.push(("conferenceDataVersion".into(), v.to_string()));
        }
        self.request(
            Method::POST,
            format!("{BASE}/calendars/{calendar_id}/events"),
            Some(body),
            &q,
        )
        .await
    }

    /// Calendar's natural-language quick add: a single string like
    /// "Lunch with Sara tomorrow at 1pm" creates a fully-formed event.
    pub async fn quick_add_event(
        &self,
        calendar_id: &str,
        text: &str,
        send_updates: Option<&str>,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> = vec![("text".into(), text.into())];
        if let Some(s) = send_updates {
            q.push(("sendUpdates".into(), s.into()));
        }
        self.request(
            Method::POST,
            format!("{BASE}/calendars/{calendar_id}/events/quickAdd"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn patch_event(
        &self,
        calendar_id: &str,
        event_id: &str,
        body: &Value,
        send_updates: Option<&str>,
        conference_data_version: Option<u8>,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(s) = send_updates {
            q.push(("sendUpdates".into(), s.into()));
        }
        if let Some(v) = conference_data_version {
            q.push(("conferenceDataVersion".into(), v.to_string()));
        }
        self.request(
            Method::PATCH,
            format!("{BASE}/calendars/{calendar_id}/events/{event_id}"),
            Some(body),
            &q,
        )
        .await
    }

    pub async fn delete_event(
        &self,
        calendar_id: &str,
        event_id: &str,
        send_updates: Option<&str>,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(s) = send_updates {
            q.push(("sendUpdates".into(), s.into()));
        }
        self.request(
            Method::DELETE,
            format!("{BASE}/calendars/{calendar_id}/events/{event_id}"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn move_event(
        &self,
        calendar_id: &str,
        event_id: &str,
        destination_calendar_id: &str,
        send_updates: Option<&str>,
    ) -> Result<Value, CalendarError> {
        let mut q: Vec<(String, String)> =
            vec![("destination".into(), destination_calendar_id.into())];
        if let Some(s) = send_updates {
            q.push(("sendUpdates".into(), s.into()));
        }
        self.request(
            Method::POST,
            format!("{BASE}/calendars/{calendar_id}/events/{event_id}/move"),
            None::<&()>,
            &q,
        )
        .await
    }

    // ---------------------------------------------------------------------
    // Misc
    // ---------------------------------------------------------------------

    /// Free/busy query across one or more calendars within a time window.
    /// Body shape: `{"timeMin":"...","timeMax":"...","items":[{"id":"..."}]}`.
    pub async fn freebusy(&self, body: &Value) -> Result<Value, CalendarError> {
        self.request(Method::POST, format!("{BASE}/freeBusy"), Some(body), &[])
            .await
    }

    /// Returns the palette of `colorId`s usable on calendars and events.
    pub async fn list_colors(&self) -> Result<Value, CalendarError> {
        self.request(Method::GET, format!("{BASE}/colors"), None::<&()>, &[])
            .await
    }

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<Value, CalendarError> {
        let needs_zero_len = body.is_none() && method == Method::POST;
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(&self.access_token);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.json(b);
        } else if needs_zero_len {
            // Google's frontend rejects POST without Content-Length:0 with HTTP 411.
            // Affects events/quickAdd and events/{id}/move where the payload is in
            // the query string.
            req = req.header(reqwest::header::CONTENT_LENGTH, "0");
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            if text.is_empty() {
                return Ok(serde_json::json!({}));
            }
            return serde_json::from_str(&text).map_err(CalendarError::Parse);
        }
        Err(CalendarError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }
}

/// Parameters for `events.list`. Constructed by the tool layer and turned
/// into a flat key/value query string.
#[derive(Debug, Default)]
pub struct EventsListQuery<'a> {
    pub time_min: Option<&'a str>,
    pub time_max: Option<&'a str>,
    pub q: Option<&'a str>,
    pub max_results: Option<u32>,
    pub page_token: Option<&'a str>,
    pub single_events: Option<bool>,
    pub order_by: Option<&'a str>,
    pub show_deleted: bool,
    pub time_zone: Option<&'a str>,
    pub updated_min: Option<&'a str>,
}

impl<'a> EventsListQuery<'a> {
    fn to_query(&self) -> Vec<(String, String)> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(v) = self.time_min {
            q.push(("timeMin".into(), v.into()));
        }
        if let Some(v) = self.time_max {
            q.push(("timeMax".into(), v.into()));
        }
        if let Some(v) = self.q {
            q.push(("q".into(), v.into()));
        }
        if let Some(n) = self.max_results {
            q.push(("maxResults".into(), n.to_string()));
        }
        if let Some(v) = self.page_token {
            q.push(("pageToken".into(), v.into()));
        }
        if let Some(b) = self.single_events {
            q.push(("singleEvents".into(), b.to_string()));
        }
        if let Some(v) = self.order_by {
            q.push(("orderBy".into(), v.into()));
        }
        if self.show_deleted {
            q.push(("showDeleted".into(), "true".into()));
        }
        if let Some(tz) = self.time_zone {
            q.push(("timeZone".into(), tz.into()));
        }
        if let Some(v) = self.updated_min {
            q.push(("updatedMin".into(), v.into()));
        }
        q
    }
}

/// Allowed values for the `sendUpdates` query parameter on event mutations.
pub const SEND_UPDATES_VALUES: &[&str] = &["all", "externalOnly", "none"];

/// Allowed values for the `orderBy` parameter on `events.list`.
pub const EVENTS_ORDER_BY_VALUES: &[&str] = &["startTime", "updated"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_list_query_builds_keyvalues() {
        let q = EventsListQuery {
            time_min: Some("2026-01-01T00:00:00Z"),
            time_max: Some("2026-02-01T00:00:00Z"),
            q: Some("standup"),
            max_results: Some(50),
            page_token: None,
            single_events: Some(true),
            order_by: Some("startTime"),
            show_deleted: false,
            time_zone: Some("America/Montreal"),
            updated_min: None,
        }
        .to_query();
        let pairs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert!(pairs.contains(&("timeMin", "2026-01-01T00:00:00Z")));
        assert!(pairs.contains(&("timeMax", "2026-02-01T00:00:00Z")));
        assert!(pairs.contains(&("q", "standup")));
        assert!(pairs.contains(&("maxResults", "50")));
        assert!(pairs.contains(&("singleEvents", "true")));
        assert!(pairs.contains(&("orderBy", "startTime")));
        assert!(pairs.contains(&("timeZone", "America/Montreal")));
        // Untouched fields are absent.
        assert!(!pairs.iter().any(|(k, _)| *k == "pageToken"));
        assert!(!pairs.iter().any(|(k, _)| *k == "showDeleted"));
        assert!(!pairs.iter().any(|(k, _)| *k == "updatedMin"));
    }

    #[test]
    fn events_list_query_default_is_empty() {
        let q = EventsListQuery::default().to_query();
        assert!(q.is_empty());
    }

    #[test]
    fn send_updates_values_are_canonical() {
        assert!(SEND_UPDATES_VALUES.contains(&"all"));
        assert!(SEND_UPDATES_VALUES.contains(&"externalOnly"));
        assert!(SEND_UPDATES_VALUES.contains(&"none"));
        assert_eq!(SEND_UPDATES_VALUES.len(), 3);
    }
}
