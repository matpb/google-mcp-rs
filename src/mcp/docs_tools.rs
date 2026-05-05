//! Google Docs tools. Separate `#[tool_router(router = docs_router)]`
//! impl block — composed with the other domain routers in `server.rs`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::{McpError, to_mcp};
use crate::google::docs::{
    BULLET_PRESETS, DocsClient, DocsError, PARAGRAPH_STYLE_NAMES, TextStyleSpec, end_of_body,
    extract_plain_text, find_match_ranges, hex_to_rgb, paragraph_style_request, text_style_request,
    utf16_len,
};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = docs_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "docs_create",
        description = "Create a new Google Doc with the given title. Returns the document resource (including its `documentId`). The doc starts empty — populate content via docs_append_text, docs_insert_text, or docs_batch_update."
    )]
    async fn docs_create(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsCreateParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        let body = json!({"title": p.title});
        client
            .create(&body)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "docs_get",
        description = "Get a Google Doc's full structured payload (paragraphs, runs, lists, tables, headers, footers, styles). Heavy. For agents that just need to read content, prefer docs_get_text."
    )]
    async fn docs_get(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsGetParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        client
            .get(&p.document_id, p.suggestions_view_mode.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))
    }

    #[tool(
        name = "docs_get_text",
        description = "Fetch a Google Doc and return its body content as flattened plain text. Walks paragraphs, runs, and tables; lists and headings are inlined without markup. Returns `{ documentId, title, text, revisionId }`."
    )]
    async fn docs_get_text(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsGetTextParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        let doc = client
            .get(&p.document_id, None)
            .await
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;
        let text = extract_plain_text(&doc);
        let title = doc.get("title").cloned().unwrap_or(json!(null));
        let revision_id = doc.get("revisionId").cloned().unwrap_or(json!(null));
        Ok(json!({
            "documentId": p.document_id,
            "title": title,
            "revisionId": revision_id,
            "text": text,
        })
        .to_string())
    }

    #[tool(
        name = "docs_append_text",
        description = "Append plain text to the end of a Google Doc. Use `\\n` for line breaks. Wraps a `batchUpdate` with `insertText { endOfSegmentLocation: {} }`."
    )]
    async fn docs_append_text(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsAppendTextParams>,
    ) -> Result<String, ErrorData> {
        if p.text.is_empty() {
            return Err(McpError::invalid_input("`text` must not be empty").into());
        }
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        let body = json!({
            "requests": [{
                "insertText": {
                    "endOfSegmentLocation": {},
                    "text": p.text,
                }
            }]
        });
        client
            .batch_update(&p.document_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))
    }

    #[tool(
        name = "docs_insert_text",
        description = "Insert plain text at a specific character index (0 = before everything; 1 = the typical 'start of body' position, just after the leading section break). Wraps `batchUpdate` with `insertText { location: { index } }`."
    )]
    async fn docs_insert_text(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsInsertTextParams>,
    ) -> Result<String, ErrorData> {
        if p.text.is_empty() {
            return Err(McpError::invalid_input("`text` must not be empty").into());
        }
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        let body = json!({
            "requests": [{
                "insertText": {
                    "location": {"index": p.index},
                    "text": p.text,
                }
            }]
        });
        client
            .batch_update(&p.document_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))
    }

    #[tool(
        name = "docs_replace_text",
        description = "Find every occurrence of `find` in the doc and replace with `replace`. `match_case` defaults to false (case-insensitive). Wraps `batchUpdate` with a single `replaceAllText` request. Returns Google's report including `occurrencesChanged`."
    )]
    async fn docs_replace_text(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsReplaceTextParams>,
    ) -> Result<String, ErrorData> {
        if p.find.is_empty() {
            return Err(McpError::invalid_input("`find` must not be empty")
                .with_hint("Replacing every empty match would touch every position in the doc.")
                .into());
        }
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        let body = json!({
            "requests": [{
                "replaceAllText": {
                    "containsText": {"text": p.find, "matchCase": p.match_case},
                    "replaceText": p.replace,
                }
            }]
        });
        client
            .batch_update(&p.document_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))
    }

    #[tool(
        name = "docs_batch_update",
        description = "Power-user: pass a raw `batchUpdate` body with any combination of requests (insertText, deleteContentRange, replaceAllText, updateTextStyle, updateParagraphStyle, createNamedRange, insertTable, insertSectionBreak, etc.). Body: `{\"requests\":[{...}],\"writeControl\":{...}?}`. See https://developers.google.com/docs/api/reference/rest/v1/documents/request"
    )]
    async fn docs_batch_update(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsBatchUpdateParams>,
    ) -> Result<String, ErrorData> {
        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);
        client
            .batch_update(&p.document_id, &p.body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))
    }

    // -----------------------------------------------------------------
    // Formatting helpers
    // -----------------------------------------------------------------

    #[tool(
        name = "docs_insert_styled",
        description = "Insert text with optional text styling (bold/italic/underline/strikethrough/font size/font family/colors/link/baseline) and optional paragraph styling (HEADING_1…6, TITLE, SUBTITLE, NORMAL_TEXT). Omit `at_index` to append at the end of the body. Returns the inserted range so chained operations can keep going. Indexes count UTF-16 code units."
    )]
    async fn docs_insert_styled(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsInsertStyledParams>,
    ) -> Result<String, ErrorData> {
        if p.text.is_empty() {
            return Err(McpError::invalid_input("`text` must not be empty").into());
        }
        if let Some(name) = &p.paragraph_style {
            validate_paragraph_style(name)?;
        }
        if let Some(style) = &p.text_style {
            validate_text_style_colors(style)?;
        }

        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);

        let text_len = utf16_len(&p.text);

        // Compute the future inserted-range start. For end-of-body
        // inserts we need the current end; for explicit indexes we use
        // them directly.
        let (insert_request, range_start) = match p.at_index {
            Some(idx) => (
                json!({
                    "insertText": {
                        "location": {"index": idx},
                        "text": p.text,
                    }
                }),
                idx,
            ),
            None => {
                let doc = client
                    .get(&p.document_id, None)
                    .await
                    .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;
                let end = end_of_body(&doc).ok_or_else(|| -> ErrorData {
                    McpError::internal("could not determine end of body — doc has no body content")
                        .with_service("docs")
                        .into()
                })?;
                let start = end.saturating_sub(1);
                (
                    json!({
                        "insertText": {
                            "endOfSegmentLocation": {},
                            "text": p.text,
                        }
                    }),
                    start,
                )
            }
        };
        let range_end = range_start + text_len;

        let mut requests = vec![insert_request];
        let style_spec = p.text_style.as_ref().map(spec_from_param);
        if let Some(spec) = &style_spec
            && let Some(req) = text_style_request(range_start, range_end, spec)
        {
            requests.push(req);
        }
        if let Some(name) = &p.paragraph_style {
            requests.push(paragraph_style_request(range_start, range_end, name));
        }

        let body = json!({"requests": requests});
        let result = client
            .batch_update(&p.document_id, &body)
            .await
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;

        Ok(json!({
            "documentId": p.document_id,
            "insertedRange": {"startIndex": range_start, "endIndex": range_end},
            "textLengthUtf16": text_len,
            "result": result,
        })
        .to_string())
    }

    #[tool(
        name = "docs_format_text",
        description = "Apply text and/or paragraph styling. Pass EITHER `range: {start_index, end_index}` for an exact range OR `match: \"...\"` to style every occurrence (case-insensitive by default; set `match_case=true` for exact). At least one of `text_style` / `paragraph_style` must be provided. Returns the list of ranges actually styled. Note: matches that span multiple textRun boundaries (style edges) are not detected; split your search if needed."
    )]
    async fn docs_format_text(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsFormatTextParams>,
    ) -> Result<String, ErrorData> {
        match (p.range.is_some(), p.match_text.is_some()) {
            (true, true) => {
                return Err(
                    McpError::invalid_input("`range` and `match` are mutually exclusive")
                        .with_hint("Pass exactly one of them.")
                        .into(),
                );
            }
            (false, false) => {
                return Err(McpError::invalid_input(
                    "must pass either `range` or `match`",
                )
                .with_hint(
                    "Use `range` for an exact slice, `match` to style every occurrence of a substring.",
                )
                .into());
            }
            _ => {}
        }
        if p.text_style.is_none() && p.paragraph_style.is_none() {
            return Err(McpError::invalid_input(
                "no styling supplied: pass at least one of `text_style` / `paragraph_style`",
            )
            .into());
        }
        if let Some(name) = &p.paragraph_style {
            validate_paragraph_style(name)?;
        }
        if let Some(style) = &p.text_style {
            validate_text_style_colors(style)?;
        }
        if let Some(needle) = &p.match_text
            && needle.is_empty()
        {
            return Err(McpError::invalid_input("`match` must not be empty")
                .with_hint("Empty matches would touch every position in the doc.")
                .into());
        }

        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);

        // Compute the list of ranges to style.
        let ranges: Vec<(u32, u32)> = if let Some(r) = &p.range {
            if r.start_index >= r.end_index {
                return Err(McpError::invalid_input(format!(
                    "invalid range: start_index ({}) must be less than end_index ({})",
                    r.start_index, r.end_index
                ))
                .into());
            }
            vec![(r.start_index, r.end_index)]
        } else {
            let needle = p.match_text.as_deref().unwrap();
            let doc = client
                .get(&p.document_id, None)
                .await
                .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;
            find_match_ranges(&doc, needle, p.match_case)
        };

        if ranges.is_empty() {
            return Ok(json!({
                "documentId": p.document_id,
                "rangesAffected": [],
                "occurrencesChanged": 0,
                "note": "no occurrences found within textRun boundaries",
            })
            .to_string());
        }

        let style_spec = p.text_style.as_ref().map(spec_from_param);
        let mut requests: Vec<Value> = vec![];
        for (s, e) in &ranges {
            if let Some(spec) = &style_spec
                && let Some(req) = text_style_request(*s, *e, spec)
            {
                requests.push(req);
            }
            if let Some(name) = &p.paragraph_style {
                requests.push(paragraph_style_request(*s, *e, name));
            }
        }
        if requests.is_empty() {
            // text_style was empty (no fields set) and no paragraph_style.
            return Err(McpError::invalid_input(
                "all styling fields were empty — nothing to apply",
            )
            .into());
        }

        let body = json!({"requests": requests});
        let result = client
            .batch_update(&p.document_id, &body)
            .await
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;

        Ok(json!({
            "documentId": p.document_id,
            "rangesAffected": ranges
                .iter()
                .map(|(s, e)| json!({"startIndex": s, "endIndex": e}))
                .collect::<Vec<_>>(),
            "occurrencesChanged": ranges.len(),
            "result": result,
        })
        .to_string())
    }

    #[tool(
        name = "docs_make_list",
        description = "Convert paragraphs in a range to a bulleted or numbered list. Pass `style: \"bullet\"` (default) or `\"numbered\"`, or override directly with `bullet_preset` (e.g. `BULLET_DISC_CIRCLE_SQUARE`, `BULLET_CHECKBOX`, `NUMBERED_DECIMAL_NESTED`). The range should cover the paragraph(s) you want to listify; Docs applies the bullets at paragraph granularity."
    )]
    async fn docs_make_list(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsMakeListParams>,
    ) -> Result<String, ErrorData> {
        if p.range.start_index >= p.range.end_index {
            return Err(McpError::invalid_input(format!(
                "invalid range: start_index ({}) must be less than end_index ({})",
                p.range.start_index, p.range.end_index
            ))
            .into());
        }

        let preset = match (p.bullet_preset.as_deref(), p.style.as_deref()) {
            (Some(explicit), _) => explicit.to_string(),
            (None, Some("numbered")) => "NUMBERED_DECIMAL_ALPHA_ROMAN".to_string(),
            (None, _) => "BULLET_DISC_CIRCLE_SQUARE".to_string(),
        };

        if !BULLET_PRESETS.contains(&preset.as_str()) {
            return Err(
                McpError::invalid_input(format!("unknown bullet_preset: {preset}"))
                    .with_hint(format!("Recognized presets: {}", BULLET_PRESETS.join(", ")))
                    .into(),
            );
        }

        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);

        let body = json!({
            "requests": [{
                "createParagraphBullets": {
                    "range": {
                        "startIndex": p.range.start_index,
                        "endIndex": p.range.end_index,
                    },
                    "bulletPreset": preset,
                }
            }]
        });
        let result = client
            .batch_update(&p.document_id, &body)
            .await
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;

        Ok(json!({
            "documentId": p.document_id,
            "range": {"startIndex": p.range.start_index, "endIndex": p.range.end_index},
            "bulletPreset": preset,
            "result": result,
        })
        .to_string())
    }

    #[tool(
        name = "docs_insert_table",
        description = "Insert an empty table at `at_index` (omit for end of body) with `rows` × `columns` cells. Returns the requested position. Populate cells via subsequent `docs_insert_text` calls (cell start indexes can be discovered by calling `docs_get` after the table is in place — look at `body.content[].table.tableRows[].tableCells[].startIndex`)."
    )]
    async fn docs_insert_table(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsInsertTableParams>,
    ) -> Result<String, ErrorData> {
        if p.rows == 0 || p.columns == 0 {
            return Err(McpError::invalid_input("`rows` and `columns` must be at least 1").into());
        }
        // Google's hard limits: 20 cols × 100 rows max in the API.
        if p.rows > 100 || p.columns > 20 {
            return Err(McpError::invalid_input(format!(
                "table too large: rows={} cols={}; Docs API caps at 100 rows × 20 columns",
                p.rows, p.columns
            ))
            .into());
        }

        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);

        let location = match p.at_index {
            Some(idx) => json!({"location": {"index": idx}}),
            None => json!({"endOfSegmentLocation": {}}),
        };
        let mut insert_table = serde_json::Map::new();
        insert_table.insert("rows".into(), json!(p.rows));
        insert_table.insert("columns".into(), json!(p.columns));
        if let Some(obj) = location.as_object() {
            for (k, v) in obj {
                insert_table.insert(k.clone(), v.clone());
            }
        }

        let body = json!({
            "requests": [{"insertTable": Value::Object(insert_table)}]
        });
        let result = client
            .batch_update(&p.document_id, &body)
            .await
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;

        Ok(json!({
            "documentId": p.document_id,
            "rows": p.rows,
            "columns": p.columns,
            "atIndex": p.at_index,
            "result": result,
            "hint": "To populate the table, call docs_get and walk body.content[] to find the new table's tableRows[].tableCells[].startIndex; use docs_insert_text with each cell's startIndex+1.",
        })
        .to_string())
    }

    #[tool(
        name = "docs_insert_image",
        description = "Insert an inline image from a public HTTPS URL at `at_index` (omit for end of body). Optional `width_pt` / `height_pt` set the rendered size in points; omit to use the image's natural size. Constraints: PNG / JPEG / GIF only, max 50 MB, max 25 megapixels. The URL must be publicly reachable from Google's servers (Drive image URLs work if the file is shared widely)."
    )]
    async fn docs_insert_image(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<DocsInsertImageParams>,
    ) -> Result<String, ErrorData> {
        if !p.image_url.starts_with("https://") {
            return Err(McpError::invalid_input("`image_url` must be HTTPS")
                .with_hint("Google fetches the image server-side and rejects non-HTTPS URLs.")
                .into());
        }

        let session = self.resolve_session(&parts).await?;
        let client = DocsClient::new((*self.state.http).clone(), session.access_token);

        let mut insert_image = serde_json::Map::new();
        insert_image.insert("uri".into(), json!(p.image_url));
        if let Some(idx) = p.at_index {
            insert_image.insert("location".into(), json!({"index": idx}));
        } else {
            insert_image.insert("endOfSegmentLocation".into(), json!({}));
        }
        if p.width_pt.is_some() || p.height_pt.is_some() {
            let mut size = serde_json::Map::new();
            if let Some(w) = p.width_pt {
                size.insert("width".into(), json!({"magnitude": w, "unit": "PT"}));
            }
            if let Some(h) = p.height_pt {
                size.insert("height".into(), json!({"magnitude": h, "unit": "PT"}));
            }
            insert_image.insert("objectSize".into(), Value::Object(size));
        }

        let body = json!({
            "requests": [{"insertInlineImage": Value::Object(insert_image)}]
        });
        let result = client
            .batch_update(&p.document_id, &body)
            .await
            .map_err(|e| reclassify_docs_not_found(e, &p.document_id))?;

        Ok(json!({
            "documentId": p.document_id,
            "imageUrl": p.image_url,
            "atIndex": p.at_index,
            "result": result,
        })
        .to_string())
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_paragraph_style(name: &str) -> Result<(), ErrorData> {
    if !PARAGRAPH_STYLE_NAMES.contains(&name) {
        return Err(
            McpError::invalid_input(format!("invalid paragraph_style: {name}"))
                .with_hint(format!(
                    "Recognized values: {}",
                    PARAGRAPH_STYLE_NAMES.join(", ")
                ))
                .into(),
        );
    }
    Ok(())
}

fn validate_text_style_colors(style: &DocsTextStyleSpec) -> Result<(), ErrorData> {
    if let Some(hex) = &style.foreground_color_hex
        && hex_to_rgb(hex).is_none()
    {
        return Err(McpError::invalid_input(format!(
            "`foreground_color_hex` is not a valid #rrggbb hex color: {hex}"
        ))
        .with_hint("Pass 6 hex digits, optionally prefixed with '#', e.g. '#16a766'.")
        .into());
    }
    if let Some(hex) = &style.background_color_hex
        && hex_to_rgb(hex).is_none()
    {
        return Err(McpError::invalid_input(format!(
            "`background_color_hex` is not a valid #rrggbb hex color: {hex}"
        ))
        .with_hint("Pass 6 hex digits, optionally prefixed with '#', e.g. '#fff2cc'.")
        .into());
    }
    if let Some(o) = &style.baseline_offset
        && !matches!(o.as_str(), "SUBSCRIPT" | "SUPERSCRIPT" | "NONE")
    {
        return Err(McpError::invalid_input(format!(
            "invalid baseline_offset: {o}; must be SUBSCRIPT, SUPERSCRIPT, or NONE"
        ))
        .into());
    }
    Ok(())
}

fn spec_from_param(p: &DocsTextStyleSpec) -> TextStyleSpec {
    TextStyleSpec {
        bold: p.bold,
        italic: p.italic,
        underline: p.underline,
        strikethrough: p.strikethrough,
        font_size_pt: p.font_size_pt,
        font_family: p.font_family.clone(),
        foreground_color_hex: p.foreground_color_hex.clone(),
        background_color_hex: p.background_color_hex.clone(),
        link_url: p.link_url.clone(),
        baseline_offset: p.baseline_offset.clone(),
    }
}

/// Re-classify a Docs 404 with the document kind so agents target the
/// right discovery (`drive_list_files` with the Doc mimeType).
fn reclassify_docs_not_found(e: DocsError, document_id: &str) -> ErrorData {
    if let DocsError::Api { status, .. } = &e
        && status.as_u16() == 404
    {
        return McpError::not_found("document", document_id, "docs").into();
    }
    to_mcp(e)
}
