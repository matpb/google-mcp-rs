//! Google Docs v1 client. Native API for creating, reading, and mutating
//! Google Docs as a structured tree of paragraphs, runs, tables, and lists.
//!
//! For agents, the highest-value endpoint is `get` — combined with a
//! plain-text extractor that flattens the body's `StructuralElement` tree
//! into a single string the agent can reason over.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;

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
