//! Google Sheets tools. Separate `#[tool_router(router = sheets_router)]`
//! impl block — composed with `gmail_router` and `drive_router` in
//! `mcp/server.rs`'s constructor via `ToolRouter::Add`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::google::sheets::{SheetsClient, SheetsError};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = sheets_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "sheets_create",
        description = "Create a new spreadsheet. Optionally seed it with named sheet tabs and a locale/time zone. Returns the new spreadsheet's full resource (including its `spreadsheetId`)."
    )]
    async fn sheets_create(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsCreateParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        let mut props = json!({"title": p.title});
        if let Some(l) = p.locale {
            props["locale"] = json!(l);
        }
        if let Some(tz) = p.time_zone {
            props["timeZone"] = json!(tz);
        }
        let mut body = json!({"properties": props});
        if !p.sheet_titles.is_empty() {
            let sheets: Vec<Value> = p
                .sheet_titles
                .iter()
                .map(|t| json!({"properties":{"title": t}}))
                .collect();
            body["sheets"] = json!(sheets);
        }
        client
            .create(&body)
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_get",
        description = "Get a spreadsheet's metadata (or a specific A1 range with cell data). Pass `include_grid_data=true` for cell-level detail; otherwise you get titles, sheet IDs, and properties — much smaller."
    )]
    async fn sheets_get(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsGetParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        client
            .get(
                &p.spreadsheet_id,
                &p.ranges,
                p.include_grid_data,
                p.fields.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_get_values",
        description = "Read values from an A1 range (e.g. `Sheet1!A1:C10` or just `Sheet1` for the whole tab). Returns `{ range, majorDimension, values: [[...]] }`."
    )]
    async fn sheets_get_values(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsGetValuesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        client
            .get_values(
                &p.spreadsheet_id,
                &p.range,
                p.major_dimension.as_deref(),
                p.value_render_option.as_deref(),
                p.date_time_render_option.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_batch_get_values",
        description = "Read values from multiple A1 ranges in a single API call. Returns `{ valueRanges: [{range, values}, ...] }`."
    )]
    async fn sheets_batch_get_values(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsBatchGetValuesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        client
            .batch_get_values(
                &p.spreadsheet_id,
                &p.ranges,
                p.major_dimension.as_deref(),
                p.value_render_option.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_update_values",
        description = "Write a 2-D array of values into an A1 range. `value_input_option=USER_ENTERED` parses formulas/dates the way the Sheets UI does; `RAW` (default) stores values verbatim."
    )]
    async fn sheets_update_values(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsUpdateValuesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        let opt = p.value_input_option.as_deref().unwrap_or("RAW");
        client
            .update_values(
                &p.spreadsheet_id,
                &p.range,
                &p.values,
                opt,
                p.major_dimension.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_append_values",
        description = "Append rows to a table-shaped range. Sheets locates the bottom of the table within the supplied range and writes underneath. `insert_data_option=INSERT_ROWS` pushes existing rows down; `OVERWRITE` (default) replaces them."
    )]
    async fn sheets_append_values(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsAppendValuesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        let opt = p.value_input_option.as_deref().unwrap_or("RAW");
        client
            .append_values(
                &p.spreadsheet_id,
                &p.range,
                &p.values,
                opt,
                p.insert_data_option.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_clear_values",
        description = "Clear all values from an A1 range (formatting is preserved)."
    )]
    async fn sheets_clear_values(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsClearValuesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        client
            .clear_values(&p.spreadsheet_id, &p.range)
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_batch_update_values",
        description = "Write multiple ranges in one API call. Body: `{\"valueInputOption\":\"USER_ENTERED|RAW\",\"data\":[{\"range\":\"...\",\"values\":[[...]]}]}`."
    )]
    async fn sheets_batch_update_values(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsBatchUpdateValuesParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        client
            .batch_update_values(&p.spreadsheet_id, &p.body)
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_batch_update",
        description = "Schema-level batch update: add/delete sheets, update cell formatting, conditional formatting, charts, banding, named ranges, etc. Body: `{\"requests\":[{\"addSheet\":{...}},{\"updateCells\":{...}},...],\"includeSpreadsheetInResponse\":bool}`. See https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/request for the full request type catalog."
    )]
    async fn sheets_batch_update(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsBatchUpdateParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        client
            .batch_update(&p.spreadsheet_id, &p.body)
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_add_sheet",
        description = "Convenience: add a new tab (sheet) to an existing spreadsheet. Wraps `sheets_batch_update` with a single `addSheet` request."
    )]
    async fn sheets_add_sheet(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsAddSheetParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        let mut props = json!({"title": p.title});
        if p.row_count.is_some() || p.column_count.is_some() {
            let mut grid = json!({});
            if let Some(r) = p.row_count {
                grid["rowCount"] = json!(r);
            }
            if let Some(c) = p.column_count {
                grid["columnCount"] = json!(c);
            }
            props["gridProperties"] = grid;
        }
        let body = json!({
            "requests": [{
                "addSheet": {"properties": props}
            }],
            "includeSpreadsheetInResponse": false,
        });
        client
            .batch_update(&p.spreadsheet_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }

    #[tool(
        name = "sheets_delete_sheet",
        description = "Convenience: remove a tab from a spreadsheet by its numeric `sheet_id` (NOT its title — get IDs from `sheets_get`'s `sheets[].properties.sheetId`)."
    )]
    async fn sheets_delete_sheet(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SheetsDeleteSheetParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = SheetsClient::new((*self.state.http).clone(), session.access_token);
        let body = json!({
            "requests": [{
                "deleteSheet": {"sheetId": p.sheet_id}
            }],
        });
        client
            .batch_update(&p.spreadsheet_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(sheets_to_error)
    }
}

fn sheets_to_error(e: SheetsError) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}
