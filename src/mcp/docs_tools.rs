//! Google Docs tools. Separate `#[tool_router(router = docs_router)]`
//! impl block — composed with the other domain routers in `server.rs`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::json;

use crate::errors::{McpError, to_mcp};
use crate::google::docs::{DocsClient, DocsError, extract_plain_text};
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
