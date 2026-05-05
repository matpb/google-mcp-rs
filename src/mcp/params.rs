//! All `Params` structs for the rmcp tool surface, in one place.
//! Easier to scan and review the schema than scrolling through tool bodies.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::mime::{AttachmentInput, Recipient};

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailSearchThreadsParams {
    /// Gmail search query, e.g. `from:someone@example.com is:unread`.
    /// See https://support.google.com/mail/answer/7190.
    pub q: String,
    /// Page size (default 100, max 500).
    #[serde(default)]
    pub max_results: Option<u32>,
    /// Pagination cursor from a previous call.
    #[serde(default)]
    pub page_token: Option<String>,
    /// Restrict to threads with all of these label IDs.
    #[serde(default)]
    pub label_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetThreadParams {
    pub id: String,
    /// `minimal`, `metadata`, `full` (default), or `raw`.
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetMessageParams {
    pub id: String,
    /// `minimal`, `metadata`, `full` (default), or `raw`.
    #[serde(default)]
    pub format: Option<String>,
    /// When `format=metadata`, restricts the headers returned.
    #[serde(default)]
    pub metadata_headers: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailListMessagesParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub include_spam_trash: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailListAttachmentsParams {
    pub message_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailDownloadAttachmentParams {
    pub message_id: String,
    pub attachment_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetThreadUrlParams {
    pub thread_id: String,
    /// Optional Gmail account index (the `u/{idx}` path segment). If omitted,
    /// the URL uses the connected account's email so it routes correctly when
    /// the user is signed into multiple Google accounts in the browser.
    #[serde(default)]
    pub account_index: Option<u8>,
}

// ---------------------------------------------------------------------------
// Send / Draft
// ---------------------------------------------------------------------------

/// Common payload shared between `gmail_send` and the draft tools.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailComposeParams {
    /// Recipients in the To: header. At least one of `to`, `cc`, `bcc` required.
    #[serde(default)]
    pub to: Vec<Recipient>,
    #[serde(default)]
    pub cc: Vec<Recipient>,
    #[serde(default)]
    pub bcc: Vec<Recipient>,
    /// Subject line. Ignored if `reply_to_message_id` is set and this is empty
    /// (the original subject with a single `Re: ` prefix is used instead).
    #[serde(default)]
    pub subject: String,
    /// Plain-text body. At least one of `body_text` / `body_html` required.
    #[serde(default)]
    pub body_text: Option<String>,
    /// HTML body. When both are present, a `multipart/alternative` is sent.
    #[serde(default)]
    pub body_html: Option<String>,
    /// Attachments — base64-encoded data inline OR an absolute server-side
    /// path. 24 MB cap, total.
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
    /// Gmail message ID of the message being replied to. When set, this tool
    /// fetches that message's `Message-Id`/`References`/`Subject`/`threadId`
    /// and builds a properly-threaded reply (In-Reply-To + References headers,
    /// `Re:` subject prefix, threadId on the API request).
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    /// Explicit Gmail thread ID. Usually inferred from `reply_to_message_id`.
    /// Only set this if you know what you're doing.
    #[serde(default)]
    pub thread_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailSendParams {
    #[serde(flatten)]
    pub compose: GmailComposeParams,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailCreateDraftParams {
    #[serde(flatten)]
    pub compose: GmailComposeParams,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetDraftParams {
    pub id: String,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailListDraftsParams {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailUpdateDraftParams {
    pub id: String,
    #[serde(flatten)]
    pub compose: GmailComposeParams,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailDeleteDraftParams {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailSendDraftParams {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailGetLabelParams {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailCreateLabelParams {
    pub name: String,
    /// `labelShow` (default), `labelHide`, or `labelShowIfUnread`.
    #[serde(default)]
    pub label_list_visibility: Option<String>,
    /// `show` (default) or `hide`.
    #[serde(default)]
    pub message_list_visibility: Option<String>,
    #[serde(default)]
    pub color: Option<crate::google::gmail::LabelColor>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailUpdateLabelParams {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub label_list_visibility: Option<String>,
    #[serde(default)]
    pub message_list_visibility: Option<String>,
    #[serde(default)]
    pub color: Option<crate::google::gmail::LabelColor>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailDeleteLabelParams {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Organize
// ---------------------------------------------------------------------------

/// What kind of object a label-modifying tool should target.
#[derive(Debug, Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum LabelTarget {
    Message,
    Thread,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailModifyLabelsParams {
    pub target: LabelTarget,
    /// ID of the message OR thread to modify (matches `target`).
    pub id: String,
    #[serde(default)]
    pub add_label_ids: Vec<String>,
    #[serde(default)]
    pub remove_label_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailLabelChangeParams {
    pub target: LabelTarget,
    /// IDs to apply the change to. Each ID is mutated independently;
    /// the tool returns an array of results.
    pub ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GmailTrashParams {
    pub target: LabelTarget,
    pub ids: Vec<String>,
}

// ===========================================================================
// Sheets
// ===========================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsCreateParams {
    pub title: String,
    /// Optional initial sheet titles (each becomes a tab).
    #[serde(default)]
    pub sheet_titles: Vec<String>,
    /// Optional locale (e.g. `en_US`).
    #[serde(default)]
    pub locale: Option<String>,
    /// Optional time zone (e.g. `America/Montreal`).
    #[serde(default)]
    pub time_zone: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsGetParams {
    pub spreadsheet_id: String,
    /// Restrict to specific A1 ranges (otherwise the whole spreadsheet).
    #[serde(default)]
    pub ranges: Vec<String>,
    /// Include the actual cell data (heavy). Default false.
    #[serde(default)]
    pub include_grid_data: bool,
    /// Field mask (e.g. `properties.title,sheets.properties`). Default returns the full resource.
    #[serde(default)]
    pub fields: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsGetValuesParams {
    pub spreadsheet_id: String,
    /// A1 range, e.g. `Sheet1!A1:C10` or `Sheet1` for a whole tab.
    pub range: String,
    /// `ROWS` (default) or `COLUMNS`.
    #[serde(default)]
    pub major_dimension: Option<String>,
    /// `FORMATTED_VALUE` (default), `UNFORMATTED_VALUE`, or `FORMULA`.
    #[serde(default)]
    pub value_render_option: Option<String>,
    /// `SERIAL_NUMBER` (default) or `FORMATTED_STRING`.
    #[serde(default)]
    pub date_time_render_option: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsBatchGetValuesParams {
    pub spreadsheet_id: String,
    pub ranges: Vec<String>,
    #[serde(default)]
    pub major_dimension: Option<String>,
    #[serde(default)]
    pub value_render_option: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsUpdateValuesParams {
    pub spreadsheet_id: String,
    pub range: String,
    /// 2-D array, e.g. `[["A1","B1"],["A2","B2"]]`.
    pub values: serde_json::Value,
    /// `RAW` (default — values stored as-is) or `USER_ENTERED` (parses
    /// formulas, dates, percentages like the UI does).
    #[serde(default)]
    pub value_input_option: Option<String>,
    #[serde(default)]
    pub major_dimension: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsAppendValuesParams {
    pub spreadsheet_id: String,
    /// A1 range that defines the table to append to (e.g. `Sheet1!A:Z`).
    pub range: String,
    pub values: serde_json::Value,
    /// `RAW` (default) or `USER_ENTERED`.
    #[serde(default)]
    pub value_input_option: Option<String>,
    /// `OVERWRITE` (default — replace existing rows) or `INSERT_ROWS` (push them down).
    #[serde(default)]
    pub insert_data_option: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsClearValuesParams {
    pub spreadsheet_id: String,
    pub range: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsBatchUpdateValuesParams {
    pub spreadsheet_id: String,
    /// Body for the values:batchUpdate API. Pass the full body, e.g.
    /// `{"valueInputOption":"USER_ENTERED","data":[{"range":"...","values":[[...]]}]}`.
    pub body: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsBatchUpdateParams {
    pub spreadsheet_id: String,
    /// Full body for spreadsheets:batchUpdate, e.g.
    /// `{"requests":[{"addSheet":{"properties":{"title":"X"}}}],"includeSpreadsheetInResponse":true}`.
    /// See https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/request
    pub body: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsAddSheetParams {
    pub spreadsheet_id: String,
    pub title: String,
    /// Optional grid size; defaults to Google's defaults.
    #[serde(default)]
    pub row_count: Option<u32>,
    #[serde(default)]
    pub column_count: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheetsDeleteSheetParams {
    pub spreadsheet_id: String,
    /// Numeric sheetId of the tab to delete (NOT its title).
    pub sheet_id: i64,
}

// ===========================================================================
// Drive
// ===========================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveListFilesParams {
    /// Drive query (https://developers.google.com/drive/api/guides/search-files),
    /// e.g. `name contains 'invoice' and mimeType = 'application/pdf'`.
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub page_size: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
    /// Field mask. Default returns id,name,mimeType,parents,modifiedTime,size,webViewLink.
    #[serde(default)]
    pub fields: Option<String>,
    /// e.g. `modifiedTime desc`, `name`, `createdTime desc`.
    #[serde(default)]
    pub order_by: Option<String>,
    /// `drive`, `appDataFolder`, or `photos`. Default `drive`.
    #[serde(default)]
    pub spaces: Option<String>,
    /// Set true to include items from Shared Drives (and to send the
    /// supportsAllDrives flag automatically).
    #[serde(default)]
    pub include_items_from_all_drives: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveGetFileParams {
    pub file_id: String,
    #[serde(default)]
    pub fields: Option<String>,
    #[serde(default)]
    pub supports_all_drives: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveCreateFolderParams {
    pub name: String,
    /// Parent folder ID. Omit for root.
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveCreateFileParams {
    pub name: String,
    /// MIME type for the upload (e.g. `text/plain`, `application/pdf`).
    pub mime_type: String,
    /// Base64-encoded file content.
    pub data_base64: String,
    /// Optional Drive folder to nest the file under.
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveUpdateMetadataParams {
    pub file_id: String,
    /// Optional rename.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Comma-separated list of parent IDs to add (e.g. for moving into a folder).
    #[serde(default)]
    pub add_parents: Option<String>,
    /// Comma-separated list of parent IDs to remove.
    #[serde(default)]
    pub remove_parents: Option<String>,
    /// Star/unstar.
    #[serde(default)]
    pub starred: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveUpdateContentParams {
    pub file_id: String,
    pub mime_type: String,
    pub data_base64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveDownloadFileParams {
    pub file_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveExportFileParams {
    pub file_id: String,
    /// Target MIME type, e.g. `application/pdf`,
    /// `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`,
    /// `text/csv`, `text/markdown`.
    pub export_mime_type: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveCopyFileParams {
    pub file_id: String,
    /// Optional new name; defaults to `Copy of <original>`.
    #[serde(default)]
    pub name: Option<String>,
    /// Parent folder for the copy.
    #[serde(default)]
    pub parent_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveTrashFileParams {
    pub file_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveDeletePermanentParams {
    pub file_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveSharePermissionParams {
    pub file_id: String,
    /// `reader`, `commenter`, `writer`, `fileOrganizer`, `organizer`, or `owner`.
    pub role: String,
    /// `user`, `group`, `domain`, or `anyone`.
    pub r#type: String,
    /// Required when `type=user` or `type=group`.
    #[serde(default)]
    pub email_address: Option<String>,
    /// Required when `type=domain`.
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_send_notification")]
    pub send_notification_email: bool,
    #[serde(default)]
    pub email_message: Option<String>,
}

fn default_send_notification() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveListPermissionsParams {
    pub file_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DriveDeletePermissionParams {
    pub file_id: String,
    pub permission_id: String,
}

// ===========================================================================
// Docs
// ===========================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsCreateParams {
    pub title: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsGetParams {
    pub document_id: String,
    /// `DEFAULT_FOR_CURRENT_ACCESS` (default), `SUGGESTIONS_INLINE`,
    /// `PREVIEW_SUGGESTIONS_ACCEPTED`, `PREVIEW_WITHOUT_SUGGESTIONS`.
    #[serde(default)]
    pub suggestions_view_mode: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsGetTextParams {
    pub document_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsAppendTextParams {
    pub document_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsInsertTextParams {
    pub document_id: String,
    pub text: String,
    /// Character index where to insert (0 = before everything; 1 = after
    /// the document's leading section break which is the typical
    /// "start of body" position).
    pub index: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsReplaceTextParams {
    pub document_id: String,
    pub find: String,
    pub replace: String,
    /// Default false — case-insensitive search.
    #[serde(default)]
    pub match_case: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsBatchUpdateParams {
    pub document_id: String,
    /// Full body for documents:batchUpdate, e.g.
    /// `{"requests":[{"insertText":{"location":{"index":1},"text":"..."}}]}`.
    /// See https://developers.google.com/docs/api/reference/rest/v1/documents/request
    pub body: serde_json::Value,
}

/// A character index range. End is exclusive (Docs convention).
/// All indexes count UTF-16 code units (matches what `docs_get` returns).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DocsRange {
    pub start_index: u32,
    pub end_index: u32,
}

/// Subset of Docs `TextStyle` exposed to agents. Pass only the fields you
/// want to set; omitted fields are left untouched.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct DocsTextStyleSpec {
    #[serde(default)]
    pub bold: Option<bool>,
    #[serde(default)]
    pub italic: Option<bool>,
    #[serde(default)]
    pub underline: Option<bool>,
    #[serde(default)]
    pub strikethrough: Option<bool>,
    /// Font size in points (e.g. 14).
    #[serde(default)]
    pub font_size_pt: Option<f64>,
    /// Font family name (e.g. "Roboto", "Roboto Mono", "Arial").
    #[serde(default)]
    pub font_family: Option<String>,
    /// Foreground (text) color as `#rrggbb` hex.
    #[serde(default)]
    pub foreground_color_hex: Option<String>,
    /// Background (highlight) color as `#rrggbb` hex.
    #[serde(default)]
    pub background_color_hex: Option<String>,
    /// Hyperlink URL. Pass an empty string to remove an existing link.
    #[serde(default)]
    pub link_url: Option<String>,
    /// `SUBSCRIPT`, `SUPERSCRIPT`, or `NONE`.
    #[serde(default)]
    pub baseline_offset: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsInsertStyledParams {
    pub document_id: String,
    pub text: String,
    /// Where to insert. Omit to append at the end of the body.
    #[serde(default)]
    pub at_index: Option<u32>,
    /// Optional text styling applied to ALL inserted text. Use
    /// `docs_format_text` to style a substring after the fact.
    #[serde(default)]
    pub text_style: Option<DocsTextStyleSpec>,
    /// Optional named paragraph style: `NORMAL_TEXT` (default), `TITLE`,
    /// `SUBTITLE`, `HEADING_1`, `HEADING_2`, `HEADING_3`, `HEADING_4`,
    /// `HEADING_5`, `HEADING_6`. Applied to the paragraph(s) containing
    /// the inserted text.
    #[serde(default)]
    pub paragraph_style: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsFormatTextParams {
    pub document_id: String,
    /// Style this exact range. Mutually exclusive with `match`.
    #[serde(default)]
    pub range: Option<DocsRange>,
    /// Find every occurrence of this string and style each match.
    /// Mutually exclusive with `range`. Matches that span multiple
    /// `textRun` boundaries (e.g. across a bold↔normal style edge) are
    /// not detected — split your search if necessary.
    #[serde(default, rename = "match")]
    pub match_text: Option<String>,
    /// Default false (case-insensitive) when matching by text.
    #[serde(default)]
    pub match_case: bool,
    /// Text styling to apply.
    #[serde(default)]
    pub text_style: Option<DocsTextStyleSpec>,
    /// Optional paragraph styling (named style type).
    #[serde(default)]
    pub paragraph_style: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsMakeListParams {
    pub document_id: String,
    /// Range covering the paragraphs to listify.
    pub range: DocsRange,
    /// Convenience: `bullet` (default) or `numbered`. Ignored when
    /// `bullet_preset` is provided.
    #[serde(default)]
    pub style: Option<String>,
    /// Override the preset directly. Common values:
    /// `BULLET_DISC_CIRCLE_SQUARE`, `BULLET_ARROW_DIAMOND_DISC`,
    /// `BULLET_CHECKBOX`, `NUMBERED_DECIMAL_ALPHA_ROMAN`,
    /// `NUMBERED_DECIMAL_NESTED`. See
    /// https://developers.google.com/docs/api/reference/rest/v1/documents/request#bulletglyphpreset
    #[serde(default)]
    pub bullet_preset: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsInsertTableParams {
    pub document_id: String,
    pub rows: u32,
    pub columns: u32,
    /// Where to insert. Omit to append at the end of the body.
    #[serde(default)]
    pub at_index: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocsInsertImageParams {
    pub document_id: String,
    /// Public HTTPS URL for the image (PNG, JPEG, or GIF; up to 50 MB
    /// and 25 megapixels). Drive image URLs work if the file is shared
    /// publicly.
    pub image_url: String,
    /// Optional explicit width in points (e.g. 200). If omitted, Docs
    /// uses the image's natural size.
    #[serde(default)]
    pub width_pt: Option<f64>,
    /// Optional explicit height in points.
    #[serde(default)]
    pub height_pt: Option<f64>,
    /// Where to insert. Omit to append at the end of the body.
    #[serde(default)]
    pub at_index: Option<u32>,
}
