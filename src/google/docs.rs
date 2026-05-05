//! Google Docs v1 client. Native API for creating, reading, and mutating
//! Google Docs as a structured tree of paragraphs, runs, tables, and lists.
//!
//! For agents, the highest-value endpoint is `get` — combined with a
//! plain-text extractor that flattens the body's `StructuralElement` tree
//! into a single string the agent can reason over.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum DocsError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Docs returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Docs response: {0}")]
    Parse(serde_json::Error),
}

const BASE: &str = "https://docs.googleapis.com/v1/documents";

#[derive(Clone)]
pub struct DocsClient {
    http: reqwest::Client,
    access_token: String,
}

impl DocsClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    /// Create a new doc. Body shape: `{ "title": "..." }` (other fields
    /// like `body` cannot be set on creation per Google's API — populate
    /// content via a follow-up `batch_update` call).
    pub async fn create(&self, body: &Value) -> Result<Value, DocsError> {
        self.request(Method::POST, BASE.to_string(), Some(body), &[])
            .await
    }

    /// Get a document. `suggestions_view_mode` controls how tracked
    /// suggestions are merged: `DEFAULT_FOR_CURRENT_ACCESS`,
    /// `SUGGESTIONS_INLINE`, `PREVIEW_SUGGESTIONS_ACCEPTED`,
    /// `PREVIEW_WITHOUT_SUGGESTIONS`.
    pub async fn get(
        &self,
        document_id: &str,
        suggestions_view_mode: Option<&str>,
    ) -> Result<Value, DocsError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(s) = suggestions_view_mode {
            q.push(("suggestionsViewMode".into(), s.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/{document_id}"),
            None::<&()>,
            &q,
        )
        .await
    }

    /// Schema-level batch update: insertText, deleteContentRange,
    /// replaceAllText, updateTextStyle, updateParagraphStyle,
    /// createNamedRange, insertTable, etc. Body:
    /// `{"requests":[{...}],"writeControl":{"requiredRevisionId":"..."}?}`.
    /// See https://developers.google.com/docs/api/reference/rest/v1/documents/request
    pub async fn batch_update(&self, document_id: &str, body: &Value) -> Result<Value, DocsError> {
        self.request(
            Method::POST,
            format!("{BASE}/{document_id}:batchUpdate"),
            Some(body),
            &[],
        )
        .await
    }

    async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
    ) -> Result<Value, DocsError> {
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(&self.access_token);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            if text.is_empty() {
                return Ok(serde_json::json!({}));
            }
            return serde_json::from_str(&text).map_err(DocsError::Parse);
        }
        Err(DocsError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }
}

/// UTF-16 code-unit length of `s`. Docs API indexes count UTF-16 code
/// units, NOT bytes or Unicode scalars; agents passing string lengths to
/// us must use this metric. For ASCII text it equals byte length; for
/// emoji or non-BMP characters one scalar can occupy two units.
pub fn utf16_len(s: &str) -> u32 {
    s.encode_utf16().count() as u32
}

/// The end-of-body index, derived from the last `body.content[]`
/// element's `endIndex`. The body's trailing newline lives at
/// `end_of_body() - 1`; that's where text inserted via
/// `endOfSegmentLocation` lands.
pub fn end_of_body(doc: &Value) -> Option<u32> {
    doc.pointer("/body/content")?
        .as_array()?
        .last()?
        .get("endIndex")?
        .as_u64()
        .map(|n| n as u32)
}

/// Convert a `#rrggbb` (or `rrggbb`) hex color to the Docs API's
/// `RgbColor` shape: `{ red, green, blue }` with each channel as a
/// float in [0, 1]. Returns `None` for malformed input.
pub fn hex_to_rgb(hex: &str) -> Option<Value> {
    let h = hex.trim().trim_start_matches('#');
    if h.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&h[0..2], 16).ok()? as f64 / 255.0;
    let g = u8::from_str_radix(&h[2..4], 16).ok()? as f64 / 255.0;
    let b = u8::from_str_radix(&h[4..6], 16).ok()? as f64 / 255.0;
    Some(json!({"red": r, "green": g, "blue": b}))
}

/// Build an `updateTextStyle` request applied to a range. Returns
/// `None` if no styling fields are set (so the caller can drop the
/// request entirely instead of sending a no-op).
///
/// Recognized fields on `style`:
/// - `bold`, `italic`, `underline`, `strikethrough` (booleans)
/// - `font_size_pt` (number, points)
/// - `font_family` (e.g. "Roboto", "Arial")
/// - `foreground_color_hex` / `background_color_hex` (`#rrggbb`)
/// - `link_url` (wrap range in a hyperlink; pass empty string to remove)
/// - `baseline_offset` (`SUBSCRIPT` / `SUPERSCRIPT` / `NONE`)
pub fn text_style_request(start: u32, end: u32, style: &TextStyleSpec) -> Option<Value> {
    let mut fields: Vec<&'static str> = vec![];
    let mut text_style = serde_json::Map::new();

    if let Some(b) = style.bold {
        fields.push("bold");
        text_style.insert("bold".into(), json!(b));
    }
    if let Some(b) = style.italic {
        fields.push("italic");
        text_style.insert("italic".into(), json!(b));
    }
    if let Some(b) = style.underline {
        fields.push("underline");
        text_style.insert("underline".into(), json!(b));
    }
    if let Some(b) = style.strikethrough {
        fields.push("strikethrough");
        text_style.insert("strikethrough".into(), json!(b));
    }
    if let Some(sz) = style.font_size_pt {
        fields.push("fontSize");
        text_style.insert("fontSize".into(), json!({"magnitude": sz, "unit": "PT"}));
    }
    if let Some(ff) = &style.font_family {
        fields.push("weightedFontFamily");
        text_style.insert("weightedFontFamily".into(), json!({"fontFamily": ff}));
    }
    if let Some(hex) = &style.foreground_color_hex
        && let Some(rgb) = hex_to_rgb(hex)
    {
        fields.push("foregroundColor");
        text_style.insert(
            "foregroundColor".into(),
            json!({"color": {"rgbColor": rgb}}),
        );
    }
    if let Some(hex) = &style.background_color_hex
        && let Some(rgb) = hex_to_rgb(hex)
    {
        fields.push("backgroundColor");
        text_style.insert(
            "backgroundColor".into(),
            json!({"color": {"rgbColor": rgb}}),
        );
    }
    if let Some(url) = &style.link_url {
        fields.push("link");
        if url.is_empty() {
            text_style.insert("link".into(), json!(null));
        } else {
            text_style.insert("link".into(), json!({"url": url}));
        }
    }
    if let Some(offset) = &style.baseline_offset {
        fields.push("baselineOffset");
        text_style.insert("baselineOffset".into(), json!(offset));
    }

    if fields.is_empty() {
        return None;
    }
    Some(json!({
        "updateTextStyle": {
            "range": {"startIndex": start, "endIndex": end},
            "textStyle": Value::Object(text_style),
            "fields": fields.join(","),
        }
    }))
}

/// Build an `updateParagraphStyle` request that sets `namedStyleType`
/// (NORMAL_TEXT, TITLE, SUBTITLE, HEADING_1…6) over the range.
pub fn paragraph_style_request(start: u32, end: u32, named_style_type: &str) -> Value {
    json!({
        "updateParagraphStyle": {
            "range": {"startIndex": start, "endIndex": end},
            "paragraphStyle": {"namedStyleType": named_style_type},
            "fields": "namedStyleType",
        }
    })
}

/// Walk a Document and find every occurrence of `needle` within an
/// individual `textRun`. Returns absolute (UTF-16) ranges. Limitation:
/// matches that span multiple runs (e.g. across a bold↔normal boundary)
/// are not detected; the agent can split-and-search if that matters.
pub fn find_match_ranges(doc: &Value, needle: &str, case_sensitive: bool) -> Vec<(u32, u32)> {
    let mut out = vec![];
    if let Some(content) = doc.pointer("/body/content").and_then(|v| v.as_array()) {
        find_in_elements(content, needle, case_sensitive, &mut out);
    }
    out
}

fn find_in_elements(
    elements: &[Value],
    needle: &str,
    case_sensitive: bool,
    out: &mut Vec<(u32, u32)>,
) {
    for el in elements {
        if let Some(para) = el.get("paragraph")
            && let Some(pe_list) = para.get("elements").and_then(|v| v.as_array())
        {
            for pe in pe_list {
                if let Some(tr) = pe.get("textRun") {
                    let start = pe.get("startIndex").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let content = tr.get("content").and_then(|v| v.as_str()).unwrap_or("");
                    find_in_run(content, start, needle, case_sensitive, out);
                }
            }
        }
        if let Some(table) = el.get("table")
            && let Some(rows) = table.get("tableRows").and_then(|v| v.as_array())
        {
            for row in rows {
                if let Some(cells) = row.get("tableCells").and_then(|v| v.as_array()) {
                    for cell in cells {
                        if let Some(cell_content) = cell.get("content").and_then(|v| v.as_array()) {
                            find_in_elements(cell_content, needle, case_sensitive, out);
                        }
                    }
                }
            }
        }
    }
}

fn find_in_run(
    content: &str,
    run_start: u32,
    needle: &str,
    case_sensitive: bool,
    out: &mut Vec<(u32, u32)>,
) {
    let (haystack, needle_norm) = if case_sensitive {
        (content.to_string(), needle.to_string())
    } else {
        (content.to_lowercase(), needle.to_lowercase())
    };
    if needle_norm.is_empty() {
        return;
    }
    let needle_utf16 = utf16_len(needle);
    let mut search_pos = 0;
    while let Some(idx) = haystack[search_pos..].find(&needle_norm) {
        let abs = search_pos + idx;
        let utf16_offset = utf16_len(&content[..abs]);
        out.push((
            run_start + utf16_offset,
            run_start + utf16_offset + needle_utf16,
        ));
        search_pos = abs + needle_norm.len();
    }
}

/// Shape of a text-style spec used by the formatting helpers.
/// Defined here so both `google::docs` and `mcp::params` agree on field
/// names without a circular dep.
#[derive(Debug, Clone, Default)]
pub struct TextStyleSpec {
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub underline: Option<bool>,
    pub strikethrough: Option<bool>,
    pub font_size_pt: Option<f64>,
    pub font_family: Option<String>,
    pub foreground_color_hex: Option<String>,
    pub background_color_hex: Option<String>,
    pub link_url: Option<String>,
    pub baseline_offset: Option<String>,
}

/// Recognized values for `updateParagraphStyle.namedStyleType`.
pub const PARAGRAPH_STYLE_NAMES: &[&str] = &[
    "NORMAL_TEXT",
    "TITLE",
    "SUBTITLE",
    "HEADING_1",
    "HEADING_2",
    "HEADING_3",
    "HEADING_4",
    "HEADING_5",
    "HEADING_6",
];

/// Common bullet presets accepted by the Docs API. Listed here so the
/// `docs_make_list` tool's description has a quick reference.
pub const BULLET_PRESETS: &[&str] = &[
    "BULLET_DISC_CIRCLE_SQUARE",
    "BULLET_DIAMONDX_ARROW3D_SQUARE",
    "BULLET_CHECKBOX",
    "BULLET_ARROW_DIAMOND_DISC",
    "BULLET_STAR_CIRCLE_SQUARE",
    "BULLET_ARROW3D_CIRCLE_SQUARE",
    "BULLET_LEFTTRIANGLE_DIAMOND_DISC",
    "BULLET_DIAMONDX_HOLLOWDIAMOND_SQUARE",
    "BULLET_DIAMOND_CIRCLE_SQUARE",
    "NUMBERED_DECIMAL_ALPHA_ROMAN",
    "NUMBERED_DECIMAL_ALPHA_ROMAN_PARENS",
    "NUMBERED_DECIMAL_NESTED",
    "NUMBERED_UPPERALPHA_ALPHA_ROMAN",
    "NUMBERED_UPPERROMAN_UPPERALPHA_DECIMAL",
    "NUMBERED_ZERODECIMAL_ALPHA_ROMAN",
];

/// Flatten a Docs `Document` resource into plain text. Walks the
/// `body.content[]` tree, extracting `textRun.content` from paragraphs
/// and recursing into tables. Lists, headings, and other paragraph
/// styles are not differentiated — this is meant for agents that want
/// to read a doc's content as a string.
pub fn extract_plain_text(doc: &Value) -> String {
    let mut out = String::new();
    if let Some(content) = doc.pointer("/body/content").and_then(|v| v.as_array()) {
        for element in content {
            walk_structural_element(element, &mut out);
        }
    }
    out
}

fn walk_structural_element(el: &Value, out: &mut String) {
    if let Some(para) = el.get("paragraph")
        && let Some(elements) = para.get("elements").and_then(|v| v.as_array())
    {
        for pe in elements {
            walk_paragraph_element(pe, out);
        }
    }
    if let Some(table) = el.get("table")
        && let Some(rows) = table.get("tableRows").and_then(|v| v.as_array())
    {
        for row in rows {
            if let Some(cells) = row.get("tableCells").and_then(|v| v.as_array()) {
                for cell in cells {
                    if let Some(cell_content) = cell.get("content").and_then(|v| v.as_array()) {
                        for ce in cell_content {
                            walk_structural_element(ce, out);
                        }
                    }
                }
            }
        }
    }
    if let Some(toc) = el.get("tableOfContents")
        && let Some(content) = toc.get("content").and_then(|v| v.as_array())
    {
        for ce in content {
            walk_structural_element(ce, out);
        }
    }
}

fn walk_paragraph_element(pe: &Value, out: &mut String) {
    if let Some(tr) = pe.get("textRun")
        && let Some(text) = tr.get("content").and_then(|v| v.as_str())
    {
        out.push_str(text);
    }
    // autoText (page numbers, page count, …) has no inline content; the
    // value is resolved at render time. Surface a placeholder so agents
    // know there's a token there.
    if pe.get("autoText").is_some() {
        out.push_str("[autoText]");
    }
    if let Some(_pb) = pe.get("pageBreak") {
        out.push('\n');
    }
    if let Some(_hr) = pe.get("horizontalRule") {
        out.push_str("\n---\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_text_from_simple_doc() {
        let doc = json!({
            "body": {
                "content": [
                    {
                        "paragraph": {
                            "elements": [
                                {"textRun": {"content": "Hello "}},
                                {"textRun": {"content": "world!\n"}}
                            ]
                        }
                    },
                    {
                        "paragraph": {
                            "elements": [
                                {"textRun": {"content": "Second paragraph.\n"}}
                            ]
                        }
                    }
                ]
            }
        });
        assert_eq!(
            extract_plain_text(&doc),
            "Hello world!\nSecond paragraph.\n"
        );
    }

    #[test]
    fn extract_text_from_table() {
        let doc = json!({
            "body": {
                "content": [
                    {
                        "table": {
                            "tableRows": [
                                {
                                    "tableCells": [
                                        {
                                            "content": [
                                                {"paragraph":{"elements":[{"textRun":{"content":"A1\n"}}]}}
                                            ]
                                        },
                                        {
                                            "content": [
                                                {"paragraph":{"elements":[{"textRun":{"content":"B1\n"}}]}}
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        });
        let text = extract_plain_text(&doc);
        assert!(text.contains("A1"));
        assert!(text.contains("B1"));
    }

    #[test]
    fn extract_text_handles_empty_doc() {
        let doc = json!({"body": {"content": []}});
        assert_eq!(extract_plain_text(&doc), "");
    }

    #[test]
    fn extract_text_handles_missing_body() {
        let doc = json!({});
        assert_eq!(extract_plain_text(&doc), "");
    }

    #[test]
    fn utf16_len_handles_ascii_and_emoji() {
        assert_eq!(utf16_len("hello"), 5);
        // 🙂 is U+1F642, surrogate pair = 2 UTF-16 units.
        assert_eq!(utf16_len("hi 🙂"), 5);
        // CJK ideograph fits in 1 UTF-16 unit.
        assert_eq!(utf16_len("你好"), 2);
    }

    #[test]
    fn end_of_body_reads_last_endindex() {
        let doc = json!({
            "body": {
                "content": [
                    {"endIndex": 1, "sectionBreak": {}},
                    {"endIndex": 42, "paragraph": {}}
                ]
            }
        });
        assert_eq!(end_of_body(&doc), Some(42));
    }

    #[test]
    fn end_of_body_returns_none_when_missing() {
        assert_eq!(end_of_body(&json!({})), None);
        assert_eq!(end_of_body(&json!({"body": {"content": []}})), None);
    }

    #[test]
    fn hex_to_rgb_parses_six_char_hex() {
        let v = hex_to_rgb("#ff0000").unwrap();
        assert!((v["red"].as_f64().unwrap() - 1.0).abs() < 1e-9);
        assert_eq!(v["green"], 0.0);
        assert_eq!(v["blue"], 0.0);

        let v = hex_to_rgb("00ff80").unwrap();
        assert_eq!(v["red"], 0.0);
        assert!((v["green"].as_f64().unwrap() - 1.0).abs() < 1e-9);
        assert!((v["blue"].as_f64().unwrap() - 128.0 / 255.0).abs() < 1e-9);
    }

    #[test]
    fn hex_to_rgb_rejects_malformed() {
        assert!(hex_to_rgb("xyz").is_none());
        assert!(hex_to_rgb("#abc").is_none()); // 3-char shorthand not accepted
        assert!(hex_to_rgb("").is_none());
        assert!(hex_to_rgb("#xxxxxx").is_none());
    }

    #[test]
    fn text_style_request_returns_none_when_empty() {
        let style = TextStyleSpec::default();
        assert!(text_style_request(0, 5, &style).is_none());
    }

    #[test]
    fn text_style_request_packs_known_fields() {
        let style = TextStyleSpec {
            bold: Some(true),
            italic: Some(false),
            font_size_pt: Some(14.0),
            font_family: Some("Roboto Mono".into()),
            foreground_color_hex: Some("#16a766".into()),
            link_url: Some("https://example.com".into()),
            ..Default::default()
        };
        let req = text_style_request(10, 20, &style).unwrap();
        let upd = &req["updateTextStyle"];
        assert_eq!(upd["range"]["startIndex"], 10);
        assert_eq!(upd["range"]["endIndex"], 20);
        let fields: &str = upd["fields"].as_str().unwrap();
        assert!(fields.contains("bold"));
        assert!(fields.contains("italic"));
        assert!(fields.contains("fontSize"));
        assert!(fields.contains("weightedFontFamily"));
        assert!(fields.contains("foregroundColor"));
        assert!(fields.contains("link"));
        let ts = &upd["textStyle"];
        assert_eq!(ts["bold"], true);
        assert_eq!(ts["italic"], false);
        assert_eq!(ts["fontSize"]["magnitude"], 14.0);
        assert_eq!(ts["fontSize"]["unit"], "PT");
        assert_eq!(ts["weightedFontFamily"]["fontFamily"], "Roboto Mono");
        assert_eq!(ts["link"]["url"], "https://example.com");
    }

    #[test]
    fn text_style_request_link_empty_url_clears_link() {
        let style = TextStyleSpec {
            link_url: Some("".into()),
            ..Default::default()
        };
        let req = text_style_request(0, 5, &style).unwrap();
        assert!(req["updateTextStyle"]["textStyle"]["link"].is_null());
    }

    #[test]
    fn paragraph_style_request_uses_correct_shape() {
        let req = paragraph_style_request(0, 10, "HEADING_2");
        let upd = &req["updateParagraphStyle"];
        assert_eq!(upd["range"]["startIndex"], 0);
        assert_eq!(upd["range"]["endIndex"], 10);
        assert_eq!(upd["paragraphStyle"]["namedStyleType"], "HEADING_2");
        assert_eq!(upd["fields"], "namedStyleType");
    }

    #[test]
    fn find_match_ranges_finds_within_run() {
        let doc = json!({
            "body": {
                "content": [{
                    "paragraph": {
                        "elements": [{
                            "startIndex": 1,
                            "endIndex": 17,
                            "textRun": {"content": "TODO call Mat\n"}
                        }]
                    }
                }]
            }
        });
        let ranges = find_match_ranges(&doc, "TODO", true);
        assert_eq!(ranges, vec![(1, 5)]);
    }

    #[test]
    fn find_match_ranges_case_insensitive() {
        let doc = json!({
            "body": {
                "content": [{
                    "paragraph": {
                        "elements": [{
                            "startIndex": 1,
                            "endIndex": 30,
                            "textRun": {"content": "Hello WORLD and hello world\n"}
                        }]
                    }
                }]
            }
        });
        let ci = find_match_ranges(&doc, "hello", false);
        assert_eq!(ci.len(), 2);
        // Both matches should have length 5
        for (s, e) in &ci {
            assert_eq!(e - s, 5);
        }

        let cs = find_match_ranges(&doc, "hello", true);
        assert_eq!(cs.len(), 1, "case-sensitive only matches lowercase 'hello'");
    }

    #[test]
    fn find_match_ranges_walks_tables() {
        let doc = json!({
            "body": {
                "content": [{
                    "table": {
                        "tableRows": [{
                            "tableCells": [{
                                "content": [{
                                    "paragraph": {
                                        "elements": [{
                                            "startIndex": 5,
                                            "endIndex": 15,
                                            "textRun": {"content": "needle\n"}
                                        }]
                                    }
                                }]
                            }]
                        }]
                    }
                }]
            }
        });
        let ranges = find_match_ranges(&doc, "needle", true);
        assert_eq!(ranges, vec![(5, 11)]);
    }

    #[test]
    fn extract_text_handles_horizontal_rule() {
        let doc = json!({
            "body": {
                "content": [{
                    "paragraph": {
                        "elements": [
                            {"textRun":{"content":"before"}},
                            {"horizontalRule":{}},
                            {"textRun":{"content":"after"}}
                        ]
                    }
                }]
            }
        });
        let text = extract_plain_text(&doc);
        assert!(text.contains("before"));
        assert!(text.contains("after"));
        assert!(text.contains("---"));
    }
}
