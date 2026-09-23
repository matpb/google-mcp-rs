//! Shared helpers for the domain tool modules: error reclassification and
//! simple field validation reused across gmail/calendar/docs/drive/people/
//! searchconsole/sheets/tasks.

use http::StatusCode;
use rmcp::ErrorData;

use crate::errors::{McpError, to_mcp};

/// Domain error types that carry an HTTP status on their `Api` variant.
pub(crate) trait ApiStatus {
    fn api_status(&self) -> Option<StatusCode>;
}

macro_rules! impl_api_status {
    ($($t:ty),+ $(,)?) => {
        $(impl ApiStatus for $t {
            fn api_status(&self) -> Option<StatusCode> {
                match self {
                    Self::Api { status, .. } => Some(*status),
                    #[allow(unreachable_patterns)]
                    _ => None,
                }
            }
        })+
    };
}

impl_api_status!(
    crate::google::gmail::GmailError,
    crate::google::calendar::CalendarError,
    crate::google::docs::DocsError,
    crate::google::drive::DriveError,
    crate::google::people::PeopleError,
    crate::google::searchconsole::SearchConsoleError,
    crate::google::sheets::SheetsError,
    crate::google::tasks::TasksError,
);

/// Re-classify a domain 404 into a typed `NotFound` carrying `kind`/`id`.
pub(crate) fn reclassify_not_found<E>(
    e: E,
    kind: &'static str,
    id: &str,
    service: &'static str,
) -> ErrorData
where
    E: ApiStatus + Into<McpError>,
{
    if e.api_status() == Some(StatusCode::NOT_FOUND) {
        return McpError::not_found(kind, id, service).into();
    }
    to_mcp(e)
}

/// Reject a blank/whitespace-only required string field.
pub(crate) fn ensure_non_empty(
    s: &str,
    field: &str,
    service: &'static str,
) -> Result<(), ErrorData> {
    if s.trim().is_empty() {
        return Err(
            McpError::invalid_input(format!("`{field}` must not be empty"))
                .with_service(service)
                .into(),
        );
    }
    Ok(())
}
