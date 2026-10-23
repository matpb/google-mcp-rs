//! Google Health tools (read-only, opt-in). Separate `#[tool_router(router = health_router)]`
//! impl block, composed in `mcp/server.rs` only when the `health` domain is enabled.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::json;

use crate::domain::Domain;
use crate::errors::{McpError, to_mcp};
use crate::google::health::{
    self, DailyRollupArgs, HealthClient, ListArgs, RollupArgs, parse_point_id,
};
use crate::google::session::SessionError;
use crate::mcp::common;
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;
use crate::oauth::GoogleOAuthError;

#[tool_router(router = health_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "health_list_data_types",
        description = "START HERE. No API call: returns the catalog of Google Health data types as `{ dataTypes: [{dataType, kind, payloadKey, operations}], filterHints: {kind: hint} }`. `dataType` is the hyphenated name every other health_* tool takes as `data_type`; `payloadKey` is the camelCase key holding the values inside a data point; `operations` says which tools work: list and reconcile -> health_list_data_points, get -> health_get_data_point, rollup -> health_rollup, dailyRollup -> health_daily_rollup. `kind` (interval, sample, daily, session, sleep, ecg, food) decides how `start`/`end` filters work. Units used by the API: distance in millimeters, weight in grams, durations as \"123s\", timestamps RFC3339 with a separate utc offset."
    )]
    async fn health_list_data_types(
        &self,
        Parameters(_): Parameters<HealthNoParams>,
    ) -> Result<String, ErrorData> {
        Ok(health::catalog_json().to_string())
    }

    #[tool(
        name = "health_get_identity",
        description = "The user's Google Health identity: `{ name, legacyUserId, healthUserId }`. `legacyUserId` is the old Fitbit user id."
    )]
    async fn health_get_identity(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(_): Parameters<HealthNoParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .identity()
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_get_profile",
        description = "The user's profile: `{ age, membershipStartDate (YYYY-MM-DD), userConfiguredWalkingStrideLengthMm, userConfiguredRunningStrideLengthMm }`. Stride lengths are in millimeters."
    )]
    async fn health_get_profile(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(_): Parameters<HealthNoParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .profile()
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_get_settings",
        description = "The user's Health settings: unit preferences (distance, height, weight, water, temperature, glucose, swim), `timeZone`, `utcOffset`, `languageLocale` and stride settings. Check the units and time zone here before interpreting local-time filters."
    )]
    async fn health_get_settings(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(_): Parameters<HealthNoParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .settings()
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_get_irn_profile",
        description = "Irregular Rhythm Notifications (IRN) enrollment: `{ onboardingStatus, enrollmentStatus, updateTime }`. Use health_list_data_points with `irregular-rhythm-notification` for the notifications themselves."
    )]
    async fn health_get_irn_profile(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(_): Parameters<HealthNoParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .irn_profile()
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_list_paired_devices",
        description = "List paired wearables: `{ pairedDevices: [{name, deviceType, batteryStatus, batteryLevel, lastSyncTime, deviceVersion, features}], nextPageToken? }`. Use it to see battery, last sync time and firmware version. MAC addresses are omitted."
    )]
    async fn health_list_paired_devices(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<HealthPairedDevicesParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .paired_devices(p.page_size, nz(&p.page_token))
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_list_data_points",
        description = "List raw data points of one type, newest first: `{ dataType, dataPoints, nextPageToken?, dataSource? }` (`dataSource` is hoisted to the top when every point shares it). `data_type` must support list (or reconcile when `reconcile=true`); see health_list_data_types. Filter with `start` (inclusive) and `end` (exclusive): either LOCAL (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`, no zone, the user's own clock) or ABSOLUTE (RFC3339 with `Z` or an offset), and both bounds must be the same kind. Session types (exercise, hydration-log, nutrition-log, irregular-rhythm-notification) accept local bounds only; daily types take a date (a datetime is cut to its date); `electrocardiogram` takes an absolute `start` only; `food` types take no time bounds. Sleep is filtered by when it ENDS. Or pass a raw `filter` (verbatim, exclusive with start/end). `reconcile=true` merges all sources into one de-duplicated stream. `page_size` defaults to 200, but the API caps exercise and sleep at 25, and a sleep or exercise page can hold fewer points than `page_size`, even zero, while `nextPageToken` is set, so keep paging until it is absent. `page_size` is only a hint: the API ignores it for minute- or second-level types, so bound those reads by a time range instead. For heart-rate prefer health_rollup: it samples about once a second, so a day is thousands of points. Units: distance millimeters, weight grams, durations like \"123s\"."
    )]
    async fn health_list_data_points(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<HealthListDataPointsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .list_data_points(&ListArgs {
                data_type: &p.data_type,
                start: nz(&p.start),
                end: nz(&p.end),
                filter: nz(&p.filter),
                data_source_family: nz(&p.data_source_family),
                page_size: p.page_size,
                page_token: nz(&p.page_token),
                reconcile: p.reconcile,
            })
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_get_data_point",
        description = "Fetch one data point by id. `id` is the digits or a full name `users/<me|digits>/dataTypes/<type>/dataPoints/<digits>` whose type must equal `data_type`. Only types whose operations include get (blood-glucose, body-fat, core-body-temperature, weight, height, exercise, sleep, hydration-log, nutrition-log, food, food-measurement-unit). Returns the slimmed point."
    )]
    async fn health_get_data_point(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<HealthGetDataPointParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .get_data_point(&p.data_type, &p.id)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_rollup",
        description = "Aggregate a data type over fixed time windows: `{ dataType, rollupDataPoints: [{startTime, endTime, <payloadKey>: {...}}], nextPageToken? }`. `start` and `end` are ABSOLUTE RFC3339 with `Z` or an offset (end exclusive). `window` is the bucket size: `90s`, `15m`, `1h`, `1d` or bare seconds like `3600`, minimum 1 second. The API limits the range to 14 days for calories-in-heart-rate-zone, heart-rate, active-minutes and total-calories, and to 90 days for the rest. Only types whose operations include rollup. Best for heart-rate (for example 5-minute windows) instead of listing thousands of samples. For per-local-day totals use health_daily_rollup."
    )]
    async fn health_rollup(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<HealthRollupParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .rollup(&RollupArgs {
                data_type: &p.data_type,
                start: &p.start,
                end: &p.end,
                window: &p.window,
                data_source_family: nz(&p.data_source_family),
                page_size: p.page_size,
                page_token: nz(&p.page_token),
            })
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_daily_rollup",
        description = "Per-day totals or averages in the user's local days: `{ dataType, rollupDataPoints: [{date, endDate, <payloadKey>: {...}}], nextPageToken? }`. `start_date` is inclusive and `end_date` exclusive, both `YYYY-MM-DD`; `window_days` (default 1) groups several days per bucket. The best tool for \"steps per day this month\" or \"average heart rate per day\". Range limits are the same as health_rollup (14 days for calories-in-heart-rate-zone, heart-rate, active-minutes and total-calories; 90 days for the rest). Only types whose operations include dailyRollup. Daily-kind types (daily-resting-heart-rate, daily-heart-rate-variability, ...) are already one value per day: read them with health_list_data_points, not this tool."
    )]
    async fn health_daily_rollup(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<HealthDailyRollupParams>,
    ) -> Result<String, ErrorData> {
        let client = self.health_for(&parts).await?;
        client
            .daily_rollup(&DailyRollupArgs {
                data_type: &p.data_type,
                start_date: &p.start_date,
                end_date: &p.end_date,
                window_days: p.window_days,
                data_source_family: nz(&p.data_source_family),
                page_size: p.page_size,
                page_token: nz(&p.page_token),
            })
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "health_export_exercise_tcx",
        description = "Export one exercise as a TCX file (GPS track, heart rate, laps) written to `dest_path` inside FILE_ROOT. Returns `{ path, sizeBytes }`; the XML never enters the context. `exercise_id` is the digits or full name of an exercise data point (find it with health_list_data_points `exercise`). `partial_data` (default true) includes points without GPS. Needs the activity and location scopes."
    )]
    async fn health_export_exercise_tcx(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<HealthExportTcxParams>,
    ) -> Result<String, ErrorData> {
        common::ensure_non_empty(&p.dest_path, "dest_path", "health")?;
        parse_point_id("exercise", &p.exercise_id).map_err(to_mcp)?;
        let jail = self
            .state
            .config
            .file_jail
            .as_ref()
            .ok_or_else(|| no_file_root("dest_path"))?;
        jail.resolve_write(&p.dest_path).map_err(to_mcp)?;
        let client = self.health_for(&parts).await?;
        let bytes = client
            .export_exercise_tcx(&p.exercise_id, p.partial_data)
            .await
            .map_err(to_mcp)?;
        let written = jail.write(&p.dest_path, &bytes).map_err(to_mcp)?;
        Ok(json!({
            "path": written.display().to_string(),
            "sizeBytes": bytes.len(),
        })
        .to_string())
    }
}

impl GoogleMcp {
    /// Health rejects tokens carrying any non-health scope, so mint a
    /// health-only token from the stored refresh token.
    pub(crate) async fn health_for(&self, parts: &Parts) -> Result<HealthClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        let scoped = self
            .state
            .session_cache
            .resolve_scoped(&session.google_sub, Domain::Health.google_scopes())
            .await
            .map_err(scoped_session_error)?;
        Ok(HealthClient::new(
            (*self.state.http).clone(),
            scoped.access_token,
        ))
    }
}

/// An `invalid_scope` refusal means the account never granted the Health scopes.
fn scoped_session_error(e: SessionError) -> ErrorData {
    if let SessionError::Google(GoogleOAuthError::TokenEndpoint { error, .. }) = &e
        && error == "invalid_scope"
    {
        return McpError::invalid_input(
            "this Google account has not granted the Google Health scopes",
        )
        .with_service("health")
        .with_hint(
            "Enable the health domain (ENABLED_DOMAINS=default,health) and sign in again: run `google_authenticate` in stdio mode, or reconnect the connector in HTTP mode.",
        )
        .into();
    }
    to_mcp(e)
}

/// Optional string param with empty or blank values treated as absent.
fn nz(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.trim().is_empty())
}

/// Error for when a tool needs `FILE_ROOT` but the operator hasn't enabled it.
fn no_file_root(what: &str) -> ErrorData {
    McpError::invalid_input(format!(
        "this server has no file-exchange directory configured (FILE_ROOT unset), so `{what}` cannot be used"
    ))
    .with_service("health")
    .with_hint("Ask the operator to set FILE_ROOT and bind-mount it into the container.")
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nz_treats_empty_and_blank_as_absent() {
        assert_eq!(nz(&None), None);
        assert_eq!(nz(&Some(String::new())), None);
        assert_eq!(nz(&Some("  ".into())), None);
        assert_eq!(nz(&Some("x".into())), Some("x"));
    }

    #[test]
    fn invalid_scope_maps_to_a_regrant_message() {
        let e = scoped_session_error(SessionError::Google(GoogleOAuthError::TokenEndpoint {
            status: reqwest::StatusCode::BAD_REQUEST,
            error: "invalid_scope".into(),
            description: None,
        }));
        assert!(e.message.contains("not granted the Google Health scopes"));
        let data = e.data.unwrap();
        assert_eq!(data["category"], "invalid_input");
        assert!(
            data["hint"]
                .as_str()
                .unwrap()
                .contains("google_authenticate")
        );

        let other = scoped_session_error(SessionError::Google(GoogleOAuthError::TokenEndpoint {
            status: reqwest::StatusCode::BAD_REQUEST,
            error: "invalid_request".into(),
            description: None,
        }));
        assert!(!other.message.contains("Health scopes"));
    }

    #[test]
    fn no_file_root_is_invalid_input_naming_the_field() {
        let e = no_file_root("dest_path");
        assert!(e.message.contains("FILE_ROOT unset"));
        assert!(e.message.contains("dest_path"));
        assert_eq!(e.data.unwrap()["category"], "invalid_input");
    }
}
