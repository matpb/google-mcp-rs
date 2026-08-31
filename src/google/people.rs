//! Google People API v1 client. Same shape as `tasks`: a thin reqwest wrapper
//! authenticated with the user's access token, forwarding Google's JSON.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum PeopleError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("People returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse People response: {0}")]
    Parse(serde_json::Error),
}

const BASE: &str = "https://people.googleapis.com/v1";

/// Field set returned when the caller does not ask for specific ones. People
/// rejects a read with no `personFields` at all, so every read defaults here.
pub const DEFAULT_PERSON_FIELDS: &str = "names,nicknames,emailAddresses,phoneNumbers,organizations,addresses,biographies,birthdays,urls,memberships,metadata";

/// Normalize a contact ID to the `people/c123` resource name the API expects,
/// so a caller may pass either form.
pub fn person_resource_name(id: &str) -> String {
    let id = id.trim();
    if id.starts_with("people/") {
        id.to_string()
    } else {
        format!("people/{id}")
    }
}

/// Same normalization for `contactGroups/xyz`.
pub fn group_resource_name(id: &str) -> String {
    let id = id.trim();
    if id.starts_with("contactGroups/") {
        id.to_string()
    } else {
        format!("contactGroups/{id}")
    }
}

#[derive(Clone)]
pub struct PeopleClient {
    http: reqwest::Client,
    access_token: String,
}

impl PeopleClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    pub async fn list_connections(
        &self,
        person_fields: &str,
        page_size: Option<u32>,
        page_token: Option<&str>,
        sort_order: Option<&str>,
    ) -> Result<Value, PeopleError> {
        let mut q: Vec<(String, String)> = vec![("personFields".into(), person_fields.to_string())];
        if let Some(n) = page_size {
            q.push(("pageSize".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            q.push(("pageToken".into(), t.into()));
        }
        if let Some(s) = sort_order {
            q.push(("sortOrder".into(), s.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/people/me/connections"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_person(
        &self,
        resource_name: &str,
        person_fields: &str,
    ) -> Result<Value, PeopleError> {
        self.request(
            Method::GET,
            format!("{BASE}/{resource_name}"),
            None::<&()>,
            &[("personFields".into(), person_fields.to_string())],
        )
        .await
    }

    pub async fn batch_get(
        &self,
        resource_names: &[String],
        person_fields: &str,
    ) -> Result<Value, PeopleError> {
        let mut q: Vec<(String, String)> = vec![("personFields".into(), person_fields.to_string())];
        for r in resource_names {
            q.push(("resourceNames".into(), r.clone()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/people:batchGet"),
            None::<&()>,
            &q,
        )
        .await
    }

    /// People requires a warmup request with an empty query before the first
    /// real search, otherwise the search index returns nothing.
    pub async fn search_contacts(
        &self,
        query: &str,
        read_mask: &str,
        page_size: Option<u32>,
    ) -> Result<Value, PeopleError> {
        let warmup = [
            ("query".to_string(), String::new()),
            ("readMask".to_string(), read_mask.to_string()),
        ];
        let _ = self
            .request(
                Method::GET,
                format!("{BASE}/people:searchContacts"),
                None::<&()>,
                &warmup,
            )
            .await;

        let mut q: Vec<(String, String)> = vec![
            ("query".into(), query.to_string()),
            ("readMask".into(), read_mask.to_string()),
        ];
        if let Some(n) = page_size {
            q.push(("pageSize".into(), n.to_string()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/people:searchContacts"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn create_contact(&self, person: &Value) -> Result<Value, PeopleError> {
        self.request(
            Method::POST,
            format!("{BASE}/people:createContact"),
            Some(person),
            &[],
        )
        .await
    }

    pub async fn update_contact(
        &self,
        resource_name: &str,
        person: &Value,
        update_person_fields: &str,
        person_fields: &str,
    ) -> Result<Value, PeopleError> {
        self.request(
            Method::PATCH,
            format!("{BASE}/{resource_name}:updateContact"),
            Some(person),
            &[
                (
                    "updatePersonFields".into(),
                    update_person_fields.to_string(),
                ),
                ("personFields".into(), person_fields.to_string()),
            ],
        )
        .await
    }

    pub async fn delete_contact(&self, resource_name: &str) -> Result<Value, PeopleError> {
        self.request(
            Method::DELETE,
            format!("{BASE}/{resource_name}:deleteContact"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn list_contact_groups(
        &self,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<Value, PeopleError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(n) = page_size {
            q.push(("pageSize".into(), n.to_string()));
        }
        if let Some(t) = page_token {
            q.push(("pageToken".into(), t.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/contactGroups"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_contact_group(
        &self,
        resource_name: &str,
        max_members: Option<u32>,
    ) -> Result<Value, PeopleError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(n) = max_members {
            q.push(("maxMembers".into(), n.to_string()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/{resource_name}"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn create_contact_group(&self, name: &str) -> Result<Value, PeopleError> {
        self.request(
            Method::POST,
            format!("{BASE}/contactGroups"),
            Some(&json!({ "contactGroup": { "name": name } })),
            &[],
        )
        .await
    }

    pub async fn update_contact_group(
        &self,
        resource_name: &str,
        name: &str,
        etag: Option<&str>,
    ) -> Result<Value, PeopleError> {
        let mut group = json!({ "name": name });
        if let Some(e) = etag {
            group["etag"] = json!(e);
        }
        self.request(
            Method::PUT,
            format!("{BASE}/{resource_name}"),
            Some(&json!({ "contactGroup": group })),
            &[],
        )
        .await
    }

    pub async fn delete_contact_group(
        &self,
        resource_name: &str,
        delete_contacts: bool,
    ) -> Result<Value, PeopleError> {
        self.request(
            Method::DELETE,
            format!("{BASE}/{resource_name}"),
            None::<&()>,
            &[("deleteContacts".into(), delete_contacts.to_string())],
        )
        .await
    }

    pub async fn modify_group_members(
        &self,
        resource_name: &str,
        add: &[String],
        remove: &[String],
    ) -> Result<Value, PeopleError> {
        self.request(
            Method::POST,
            format!("{BASE}/{resource_name}/members:modify"),
            Some(&json!({
                "resourceNamesToAdd": add,
                "resourceNamesToRemove": remove,
            })),
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
    ) -> Result<Value, PeopleError> {
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
            // Google's frontend rejects body-less POSTs without Content-Length:0 (HTTP 411).
            req = req.header(reqwest::header::CONTENT_LENGTH, "0");
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            if text.is_empty() {
                return Ok(serde_json::json!({}));
            }
            return serde_json::from_str(&text).map_err(PeopleError::Parse);
        }
        Err(PeopleError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn person_resource_name_accepts_both_forms() {
        assert_eq!(person_resource_name("c123"), "people/c123");
        assert_eq!(person_resource_name("people/c123"), "people/c123");
        assert_eq!(person_resource_name("  people/c123  "), "people/c123");
    }

    #[test]
    fn group_resource_name_accepts_both_forms() {
        assert_eq!(group_resource_name("myGroup"), "contactGroups/myGroup");
        assert_eq!(
            group_resource_name("contactGroups/myGroup"),
            "contactGroups/myGroup"
        );
    }

    #[test]
    fn default_person_fields_covers_the_common_contact_shape() {
        for needle in ["names", "emailAddresses", "phoneNumbers", "organizations"] {
            assert!(
                DEFAULT_PERSON_FIELDS.split(',').any(|f| f == needle),
                "missing default person field: {needle}"
            );
        }
    }
}
