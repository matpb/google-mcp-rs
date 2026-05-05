//! Google Calendar tools. Separate `#[tool_router(router = calendar_router)]`
//! impl block — composed with the other domain routers in
//! `mcp/server.rs`'s constructor via `ToolRouter::Add`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::errors::{McpError, to_mcp};
use crate::google::calendar::{
    CalendarClient, CalendarError, EVENTS_ORDER_BY_VALUES, EventsListQuery, SEND_UPDATES_VALUES,
};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = calendar_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "calendar_list_calendars",
        description = "List the calendars on the user's calendar list (primary + any subscribed calendars). Returns `{ items: [{id, summary, accessRole, primary, …}], nextPageToken }`. Use this to discover calendar IDs for the other tools."
    )]
    async fn calendar_list_calendars(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarListCalendarsParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        client
            .list_calendar_list(
                p.max_results,
                p.page_token.as_deref(),
                p.show_deleted,
                p.show_hidden,
            )
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "calendar_get_calendar",
        description = "Get a calendar's metadata (summary, description, time zone, location). Use `\"primary\"` for the user's main calendar."
    )]
    async fn calendar_get_calendar(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarGetCalendarParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let cid = p.calendar_id.clone();
        client
            .get_calendar(&p.calendar_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "calendar", &cid))
    }

    #[tool(
        name = "calendar_create_calendar",
        description = "Create a new secondary calendar owned by the authenticated user. Returns the full calendar resource (including its `id`, which is what other Calendar tools expect)."
    )]
    async fn calendar_create_calendar(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarCreateCalendarParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let mut body = json!({"summary": p.summary});
        if let Some(d) = p.description {
            body["description"] = json!(d);
        }
        if let Some(l) = p.location {
            body["location"] = json!(l);
        }
        if let Some(tz) = p.time_zone {
            body["timeZone"] = json!(tz);
        }
        client
            .create_calendar(&body)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "calendar_delete_calendar",
        description = "Permanently delete a secondary calendar. **Irreversible** — every event in the calendar is removed. The user's primary calendar cannot be deleted."
    )]
    async fn calendar_delete_calendar(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarDeleteCalendarParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let cid = p.calendar_id.clone();
        client
            .delete_calendar(&p.calendar_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "calendar", &cid))
    }

    #[tool(
        name = "calendar_list_events",
        description = "List or search events on a calendar. By default expands recurring events into individual instances (`single_events=true`) so each item has a concrete start/end. Filter with `time_min`/`time_max` (RFC3339), `q` (free-text search), or `updated_min`. Returns `{ items: [...], nextPageToken, timeZone }`."
    )]
    async fn calendar_list_events(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarListEventsParams>,
    ) -> Result<String, ErrorData> {
        validate_order_by(p.order_by.as_deref(), p.single_events)?;
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let cid = p.calendar_id.clone();
        let q = EventsListQuery {
            time_min: p.time_min.as_deref(),
            time_max: p.time_max.as_deref(),
            q: p.q.as_deref(),
            max_results: p.max_results,
            page_token: p.page_token.as_deref(),
            single_events: Some(p.single_events),
            order_by: p.order_by.as_deref(),
            show_deleted: p.show_deleted,
            time_zone: p.time_zone.as_deref(),
            updated_min: p.updated_min.as_deref(),
        };
        client
            .list_events(&p.calendar_id, &q)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "calendar", &cid))
    }

    #[tool(
        name = "calendar_get_event",
        description = "Get a single event by ID. Returns the full Event resource including attendees, recurrence, conferenceData, attachments, and reminders."
    )]
    async fn calendar_get_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarGetEventParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let eid = p.event_id.clone();
        client
            .get_event(&p.calendar_id, &p.event_id, p.time_zone.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "event", &eid))
    }

    #[tool(
        name = "calendar_create_event",
        description = "Create an event. Pass timed events with `start_date_time` + `end_date_time` (RFC3339), all-day events with `start_date` + `end_date` (YYYY-MM-DD; end is exclusive). For recurring events also pass `recurrence` (RRULE strings) and `time_zone`. Set `add_conference=true` to attach a Google Meet link. `send_updates` controls whether attendees are emailed (default `none`)."
    )]
    async fn calendar_create_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarCreateEventParams>,
    ) -> Result<String, ErrorData> {
        validate_send_updates(p.send_updates.as_deref())?;
        validate_event_fields(&p.event, /* require_summary_and_window= */ true)?;
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let cid = p.calendar_id.clone();
        let body = build_event_body(&p.event)?;
        let conf_version = if p.event.add_conference {
            Some(1)
        } else {
            None
        };
        client
            .create_event(
                &p.calendar_id,
                &body,
                p.send_updates.as_deref(),
                conf_version,
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "calendar", &cid))
    }

    #[tool(
        name = "calendar_quick_add_event",
        description = "Create an event from a single natural-language string, e.g. `Lunch with Sara tomorrow at 1pm`. Google's parser is the same as the one in the Calendar UI's quick-add bar. Returns the parsed Event resource."
    )]
    async fn calendar_quick_add_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarQuickAddEventParams>,
    ) -> Result<String, ErrorData> {
        if p.text.trim().is_empty() {
            return Err(McpError::invalid_input("`text` must not be empty").into());
        }
        validate_send_updates(p.send_updates.as_deref())?;
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let cid = p.calendar_id.clone();
        client
            .quick_add_event(&p.calendar_id, &p.text, p.send_updates.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "calendar", &cid))
    }

    #[tool(
        name = "calendar_patch_event",
        description = "Partially update an event. Only the fields you set are touched. **Note**: setting `attendees` REPLACES the list — fetch the event first if you need to add or remove a single attendee. `send_updates` controls invite emails."
    )]
    async fn calendar_patch_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarPatchEventParams>,
    ) -> Result<String, ErrorData> {
        validate_send_updates(p.send_updates.as_deref())?;
        validate_event_fields(&p.event, /* require_summary_and_window= */ false)?;
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let eid = p.event_id.clone();
        let body = build_event_body(&p.event)?;
        if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            return Err(McpError::invalid_input(
                "patch must include at least one field to update",
            )
            .with_hint("Set summary, description, location, start/end, attendees, recurrence, reminders_minutes_before, visibility, transparency, color_id, add_conference, or extra_event_fields.")
            .into());
        }
        let conf_version = if p.event.add_conference {
            Some(1)
        } else {
            None
        };
        client
            .patch_event(
                &p.calendar_id,
                &p.event_id,
                &body,
                p.send_updates.as_deref(),
                conf_version,
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "event", &eid))
    }

    #[tool(
        name = "calendar_delete_event",
        description = "Delete an event. **Irreversible** — for cancellations that should notify attendees, set `send_updates=\"all\"`."
    )]
    async fn calendar_delete_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarDeleteEventParams>,
    ) -> Result<String, ErrorData> {
        validate_send_updates(p.send_updates.as_deref())?;
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let eid = p.event_id.clone();
        client
            .delete_event(&p.calendar_id, &p.event_id, p.send_updates.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "event", &eid))
    }

    #[tool(
        name = "calendar_move_event",
        description = "Move an event from one calendar to another (the user must have write access to both). Recurring events can only be moved as a whole series."
    )]
    async fn calendar_move_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarMoveEventParams>,
    ) -> Result<String, ErrorData> {
        validate_send_updates(p.send_updates.as_deref())?;
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let eid = p.event_id.clone();
        client
            .move_event(
                &p.calendar_id,
                &p.event_id,
                &p.destination_calendar_id,
                p.send_updates.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "event", &eid))
    }

    #[tool(
        name = "calendar_respond_to_event",
        description = "Set the authenticated user's (or another attendee's) `responseStatus` on an event: `accepted`, `declined`, or `tentative`. Optionally include a comment shown to organisers. Requires the user to already be on the attendee list (otherwise Google rejects with 400)."
    )]
    async fn calendar_respond_to_event(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarRespondToEventParams>,
    ) -> Result<String, ErrorData> {
        validate_response_status(&p.response_status)?;
        validate_send_updates(p.send_updates.as_deref())?;

        let session = self.resolve_session(&parts).await?;
        let target_email = p
            .attendee_email
            .clone()
            .unwrap_or_else(|| session.email.clone());
        if target_email.is_empty() {
            return Err(McpError::invalid_input(
                "`attendee_email` not provided and the authenticated session has no email",
            )
            .with_hint("Pass `attendee_email` explicitly.")
            .into());
        }

        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let eid = p.event_id.clone();

        // Read current event, mutate the matching attendee, send back.
        let event = client
            .get_event(&p.calendar_id, &p.event_id, None)
            .await
            .map_err(|e| reclassify_calendar_not_found(e, "event", &eid))?;

        let mut attendees: Vec<Value> = event
            .get("attendees")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut matched = false;
        for a in attendees.iter_mut() {
            let email_match = a
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(&target_email))
                .unwrap_or(false);
            if email_match {
                a["responseStatus"] = json!(p.response_status);
                if let Some(c) = &p.comment {
                    a["comment"] = json!(c);
                }
                matched = true;
            }
        }
        if !matched {
            return Err(McpError::invalid_input(format!(
                "{target_email} is not on this event's attendee list"
            ))
            .with_hint(
                "Only attendees can respond. Ask the organiser to add the user as an attendee, \
                 then retry — or call `calendar_patch_event` with a new `attendees` list to add \
                 them yourself if you have write access.",
            )
            .into());
        }

        let body = json!({"attendees": attendees});
        client
            .patch_event(
                &p.calendar_id,
                &p.event_id,
                &body,
                p.send_updates.as_deref(),
                None,
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_calendar_not_found(e, "event", &eid))
    }

    #[tool(
        name = "calendar_freebusy",
        description = "Query free/busy intervals across one or more calendars within a time window. Returns `{ calendars: { id: { busy: [{start, end}] } } }`. Use this before scheduling to find conflicts."
    )]
    async fn calendar_freebusy(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<CalendarFreebusyParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        let ids: Vec<String> = if p.calendar_ids.is_empty() {
            vec!["primary".into()]
        } else {
            p.calendar_ids
        };
        let items: Vec<Value> = ids.into_iter().map(|id| json!({"id": id})).collect();
        let mut body = json!({
            "timeMin": p.time_min,
            "timeMax": p.time_max,
            "items": items,
        });
        if let Some(tz) = p.time_zone {
            body["timeZone"] = json!(tz);
        }
        client
            .freebusy(&body)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "calendar_list_colors",
        description = "Return the palette of `colorId`s recognized by the Calendar UI, both for calendars (`calendar`) and events (`event`). Each entry has `background` and `foreground` hex colors."
    )]
    async fn calendar_list_colors(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = CalendarClient::new((*self.state.http).clone(), session.access_token);
        client
            .list_colors()
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Body-less tool params for `calendar_list_colors`. Defined here (not in
/// `params.rs`) because no other tool needs it.
#[derive(Debug, schemars::JsonSchema, serde::Deserialize, Default)]
pub struct EmptyParams {}

fn validate_send_updates(v: Option<&str>) -> Result<(), ErrorData> {
    if let Some(s) = v
        && !SEND_UPDATES_VALUES.contains(&s)
    {
        return Err(
            McpError::invalid_input(format!("invalid send_updates: {s}"))
                .with_hint(format!(
                    "Recognized values: {}",
                    SEND_UPDATES_VALUES.join(", ")
                ))
                .into(),
        );
    }
    Ok(())
}

fn validate_order_by(v: Option<&str>, single_events: bool) -> Result<(), ErrorData> {
    if let Some(s) = v {
        if !EVENTS_ORDER_BY_VALUES.contains(&s) {
            return Err(McpError::invalid_input(format!("invalid order_by: {s}"))
                .with_hint(format!(
                    "Recognized values: {}",
                    EVENTS_ORDER_BY_VALUES.join(", ")
                ))
                .into());
        }
        if s == "startTime" && !single_events {
            return Err(
                McpError::invalid_input("order_by=startTime requires single_events=true")
                    .with_hint(
                        "Recurring events have no single start time when not expanded; \
                 set single_events=true or use order_by=updated.",
                    )
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_response_status(s: &str) -> Result<(), ErrorData> {
    if !matches!(s, "accepted" | "declined" | "tentative") {
        return Err(McpError::invalid_input(format!(
            "invalid response_status: {s}; must be accepted, declined, or tentative"
        ))
        .into());
    }
    Ok(())
}

/// Validate the start/end pair shape. `require_summary_and_window` enforces
/// the create-time invariant: a summary is required and a start+end pair
/// (either both timed or both all-day) must be supplied.
fn validate_event_fields(
    f: &CalendarEventFields,
    require_summary_and_window: bool,
) -> Result<(), ErrorData> {
    let start_timed = f.start_date_time.is_some();
    let start_all_day = f.start_date.is_some();
    let end_timed = f.end_date_time.is_some();
    let end_all_day = f.end_date.is_some();

    if start_timed && start_all_day {
        return Err(
            McpError::invalid_input("set EITHER start_date_time OR start_date, not both").into(),
        );
    }
    if end_timed && end_all_day {
        return Err(
            McpError::invalid_input("set EITHER end_date_time OR end_date, not both").into(),
        );
    }

    let has_start = start_timed || start_all_day;
    let has_end = end_timed || end_all_day;

    if has_start != has_end {
        return Err(McpError::invalid_input(
            "start and end must be set together — either both timed (start_date_time + end_date_time) or both all-day (start_date + end_date)",
        )
        .into());
    }

    if has_start && (start_timed != end_timed) {
        return Err(McpError::invalid_input(
            "start and end must be the same kind: both timed or both all-day",
        )
        .into());
    }

    if require_summary_and_window {
        if f.summary.as_deref().unwrap_or("").trim().is_empty() {
            return Err(McpError::invalid_input("`summary` is required to create an event").into());
        }
        if !has_start {
            return Err(McpError::invalid_input(
                "create requires a start/end pair (date_time or date)",
            )
            .with_hint(
                "Use `start_date_time` + `end_date_time` (RFC3339) for timed events, or \
                 `start_date` + `end_date` (YYYY-MM-DD; end is exclusive) for all-day events.",
            )
            .into());
        }
    }

    if let Some(v) = &f.visibility
        && !matches!(
            v.as_str(),
            "default" | "public" | "private" | "confidential"
        )
    {
        return Err(McpError::invalid_input(format!(
            "invalid visibility: {v}; must be default, public, private, or confidential"
        ))
        .into());
    }
    if let Some(t) = &f.transparency
        && !matches!(t.as_str(), "opaque" | "transparent")
    {
        return Err(McpError::invalid_input(format!(
            "invalid transparency: {t}; must be opaque or transparent"
        ))
        .into());
    }
    if let Some(attendees) = &f.attendees {
        for a in attendees {
            if let Some(rs) = &a.response_status
                && !matches!(
                    rs.as_str(),
                    "needsAction" | "accepted" | "declined" | "tentative"
                )
            {
                return Err(McpError::invalid_input(format!(
                    "invalid attendee.response_status: {rs}"
                ))
                .into());
            }
        }
    }

    Ok(())
}

/// Translate `CalendarEventFields` into a Calendar API Event resource patch.
/// All fields are optional; the result contains only the keys the caller set.
fn build_event_body(f: &CalendarEventFields) -> Result<Value, ErrorData> {
    let mut body = serde_json::Map::new();

    if let Some(s) = &f.summary {
        body.insert("summary".into(), json!(s));
    }
    if let Some(s) = &f.description {
        body.insert("description".into(), json!(s));
    }
    if let Some(s) = &f.location {
        body.insert("location".into(), json!(s));
    }

    if let Some(start) = build_event_endpoint(
        f.start_date_time.as_deref(),
        f.start_date.as_deref(),
        f.time_zone.as_deref(),
    ) {
        body.insert("start".into(), start);
    }
    if let Some(end) = build_event_endpoint(
        f.end_date_time.as_deref(),
        f.end_date.as_deref(),
        f.time_zone.as_deref(),
    ) {
        body.insert("end".into(), end);
    }

    if let Some(list) = &f.attendees {
        let arr: Vec<Value> = list
            .iter()
            .map(|a| {
                let mut m = serde_json::Map::new();
                m.insert("email".into(), json!(a.email));
                if let Some(n) = &a.display_name {
                    m.insert("displayName".into(), json!(n));
                }
                if a.optional {
                    m.insert("optional".into(), json!(true));
                }
                if let Some(rs) = &a.response_status {
                    m.insert("responseStatus".into(), json!(rs));
                }
                Value::Object(m)
            })
            .collect();
        body.insert("attendees".into(), json!(arr));
    }

    if let Some(rules) = &f.recurrence {
        body.insert("recurrence".into(), json!(rules));
    }

    if let Some(mins) = &f.reminders_minutes_before {
        let overrides: Vec<Value> = mins
            .iter()
            .map(|m| json!({"method": "popup", "minutes": m}))
            .collect();
        body.insert(
            "reminders".into(),
            json!({
                "useDefault": false,
                "overrides": overrides,
            }),
        );
    }

    if let Some(v) = &f.visibility {
        body.insert("visibility".into(), json!(v));
    }
    if let Some(t) = &f.transparency {
        body.insert("transparency".into(), json!(t));
    }
    if let Some(c) = &f.color_id {
        body.insert("colorId".into(), json!(c));
    }
    if f.add_conference {
        body.insert(
            "conferenceData".into(),
            json!({
                "createRequest": {
                    "requestId": Uuid::new_v4().to_string(),
                    "conferenceSolutionKey": {"type": "hangoutsMeet"},
                }
            }),
        );
    }

    if let Some(extra) = &f.extra_event_fields {
        let Some(extra_obj) = extra.as_object() else {
            return Err(
                McpError::invalid_input("`extra_event_fields` must be a JSON object").into(),
            );
        };
        for (k, v) in extra_obj {
            body.insert(k.clone(), v.clone());
        }
    }

    Ok(Value::Object(body))
}

fn build_event_endpoint(
    date_time: Option<&str>,
    date: Option<&str>,
    time_zone: Option<&str>,
) -> Option<Value> {
    if let Some(dt) = date_time {
        let mut m = serde_json::Map::new();
        m.insert("dateTime".into(), json!(dt));
        if let Some(tz) = time_zone {
            m.insert("timeZone".into(), json!(tz));
        }
        Some(Value::Object(m))
    } else if let Some(d) = date {
        let mut m = serde_json::Map::new();
        m.insert("date".into(), json!(d));
        // All-day events ignore timeZone on the endpoint, but Google
        // accepts it on the parent event.
        Some(Value::Object(m))
    } else {
        None
    }
}

/// Re-classify a Calendar 404 with the right resource kind so agents
/// target the right discovery (`calendar_list_calendars` vs
/// `calendar_list_events`).
fn reclassify_calendar_not_found(e: CalendarError, kind: &'static str, id: &str) -> ErrorData {
    if let CalendarError::Api { status, .. } = &e
        && status.as_u16() == 404
    {
        return McpError::not_found(kind, id, "calendar").into();
    }
    to_mcp(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(
        start_dt: Option<&str>,
        end_dt: Option<&str>,
        summary: Option<&str>,
    ) -> CalendarEventFields {
        CalendarEventFields {
            summary: summary.map(|s| s.to_string()),
            start_date_time: start_dt.map(|s| s.to_string()),
            end_date_time: end_dt.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn create_requires_summary() {
        let f = fields(
            Some("2026-05-05T10:00:00Z"),
            Some("2026-05-05T11:00:00Z"),
            None,
        );
        let e = validate_event_fields(&f, true).unwrap_err();
        assert!(e.message.contains("summary"));
    }

    #[test]
    fn create_requires_start_end_pair() {
        let f = fields(None, None, Some("Standup"));
        let e = validate_event_fields(&f, true).unwrap_err();
        assert!(e.message.contains("start/end"));
    }

    #[test]
    fn rejects_mixed_timed_and_all_day_endpoints() {
        let f = CalendarEventFields {
            summary: Some("Standup".into()),
            start_date_time: Some("2026-05-05T10:00:00Z".into()),
            end_date: Some("2026-05-05".into()),
            ..Default::default()
        };
        let e = validate_event_fields(&f, true).unwrap_err();
        assert!(e.message.contains("same kind"));
    }

    #[test]
    fn rejects_both_start_kinds() {
        let f = CalendarEventFields {
            summary: Some("X".into()),
            start_date_time: Some("2026-05-05T10:00:00Z".into()),
            start_date: Some("2026-05-05".into()),
            end_date_time: Some("2026-05-05T11:00:00Z".into()),
            ..Default::default()
        };
        let e = validate_event_fields(&f, true).unwrap_err();
        assert!(e.message.contains("start_date_time"));
    }

    #[test]
    fn patch_allows_no_window() {
        let f = CalendarEventFields {
            summary: Some("New title".into()),
            ..Default::default()
        };
        validate_event_fields(&f, false).unwrap();
    }

    #[test]
    fn build_body_emits_timed_event() {
        let f = CalendarEventFields {
            summary: Some("Standup".into()),
            start_date_time: Some("2026-05-05T10:00:00-04:00".into()),
            end_date_time: Some("2026-05-05T10:30:00-04:00".into()),
            time_zone: Some("America/Montreal".into()),
            ..Default::default()
        };
        let body = build_event_body(&f).unwrap();
        let obj = body.as_object().unwrap();
        assert_eq!(obj["summary"], json!("Standup"));
        assert_eq!(obj["start"]["dateTime"], json!("2026-05-05T10:00:00-04:00"));
        assert_eq!(obj["start"]["timeZone"], json!("America/Montreal"));
        assert_eq!(obj["end"]["dateTime"], json!("2026-05-05T10:30:00-04:00"));
    }

    #[test]
    fn build_body_emits_all_day_event() {
        let f = CalendarEventFields {
            summary: Some("Vacation".into()),
            start_date: Some("2026-07-01".into()),
            end_date: Some("2026-07-15".into()),
            ..Default::default()
        };
        let body = build_event_body(&f).unwrap();
        let obj = body.as_object().unwrap();
        assert_eq!(obj["start"]["date"], json!("2026-07-01"));
        assert_eq!(obj["end"]["date"], json!("2026-07-15"));
        assert!(obj["start"].get("dateTime").is_none());
    }

    #[test]
    fn build_body_emits_reminders_overrides() {
        let f = CalendarEventFields {
            summary: Some("X".into()),
            reminders_minutes_before: Some(vec![10, 60]),
            ..Default::default()
        };
        let body = build_event_body(&f).unwrap();
        let r = body["reminders"].clone();
        assert_eq!(r["useDefault"], json!(false));
        let overrides = r["overrides"].as_array().unwrap();
        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides[0]["method"], json!("popup"));
        assert_eq!(overrides[0]["minutes"], json!(10));
        assert_eq!(overrides[1]["minutes"], json!(60));
    }

    #[test]
    fn build_body_emits_conference_create_request() {
        let f = CalendarEventFields {
            summary: Some("X".into()),
            add_conference: true,
            ..Default::default()
        };
        let body = build_event_body(&f).unwrap();
        let cd = &body["conferenceData"];
        assert_eq!(
            cd["createRequest"]["conferenceSolutionKey"]["type"],
            json!("hangoutsMeet")
        );
        assert!(cd["createRequest"]["requestId"].as_str().unwrap().len() > 8);
    }

    #[test]
    fn build_body_merges_extra_fields() {
        let f = CalendarEventFields {
            summary: Some("X".into()),
            extra_event_fields: Some(json!({"guestsCanModify": true, "summary": "override"})),
            ..Default::default()
        };
        let body = build_event_body(&f).unwrap();
        // Extra fields are merged on top of structured fields.
        assert_eq!(body["summary"], json!("override"));
        assert_eq!(body["guestsCanModify"], json!(true));
    }

    #[test]
    fn build_body_rejects_non_object_extra_fields() {
        let f = CalendarEventFields {
            summary: Some("X".into()),
            extra_event_fields: Some(json!([1, 2, 3])),
            ..Default::default()
        };
        let e = build_event_body(&f).unwrap_err();
        assert!(e.message.contains("extra_event_fields"));
    }

    #[test]
    fn order_by_starttime_requires_single_events() {
        let e = validate_order_by(Some("startTime"), false).unwrap_err();
        assert!(e.message.contains("startTime"));
        validate_order_by(Some("startTime"), true).unwrap();
        validate_order_by(Some("updated"), false).unwrap();
    }

    #[test]
    fn send_updates_validates_against_canonical_set() {
        validate_send_updates(None).unwrap();
        validate_send_updates(Some("all")).unwrap();
        validate_send_updates(Some("none")).unwrap();
        let e = validate_send_updates(Some("everyone")).unwrap_err();
        assert!(e.message.contains("send_updates"));
    }

    #[test]
    fn response_status_validates() {
        validate_response_status("accepted").unwrap();
        validate_response_status("declined").unwrap();
        validate_response_status("tentative").unwrap();
        validate_response_status("needsAction").unwrap_err();
        validate_response_status("yes").unwrap_err();
    }
}
