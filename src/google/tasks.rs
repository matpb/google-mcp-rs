//! Google Tasks v1 client. Same shape as `sheets`: a thin reqwest wrapper
//! authenticated with the user's access token, forwarding Google's JSON.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum TasksError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Tasks returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Tasks response: {0}")]
    Parse(serde_json::Error),
}

const BASE: &str = "https://tasks.googleapis.com/tasks/v1";

#[derive(Clone)]
pub struct TasksClient {
    http: reqwest::Client,
    access_token: String,
}

impl TasksClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    pub async fn list_tasklists(
        &self,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<Value, TasksError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(m) = max_results {
            q.push(("maxResults".into(), m.to_string()));
        }
        if let Some(t) = page_token {
            q.push(("pageToken".into(), t.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/users/@me/lists"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_tasklist(&self, tasklist_id: &str) -> Result<Value, TasksError> {
        self.request(
            Method::GET,
            format!("{BASE}/users/@me/lists/{tasklist_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn create_tasklist(&self, title: &str) -> Result<Value, TasksError> {
        let body = serde_json::json!({"title": title});
        self.request(
            Method::POST,
            format!("{BASE}/users/@me/lists"),
            Some(&body),
            &[],
        )
        .await
    }

    pub async fn update_tasklist(
        &self,
        tasklist_id: &str,
        title: &str,
    ) -> Result<Value, TasksError> {
        let body = serde_json::json!({"id": tasklist_id, "title": title});
        self.request(
            Method::PATCH,
            format!("{BASE}/users/@me/lists/{tasklist_id}"),
            Some(&body),
            &[],
        )
        .await
    }

    pub async fn delete_tasklist(&self, tasklist_id: &str) -> Result<Value, TasksError> {
        self.request(
            Method::DELETE,
            format!("{BASE}/users/@me/lists/{tasklist_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_tasks(
        &self,
        tasklist_id: &str,
        show_completed: bool,
        show_hidden: bool,
        show_deleted: bool,
        due_min: Option<&str>,
        due_max: Option<&str>,
        completed_min: Option<&str>,
        completed_max: Option<&str>,
        updated_min: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<Value, TasksError> {
        let mut q: Vec<(String, String)> = vec![
            ("showCompleted".into(), show_completed.to_string()),
            ("showHidden".into(), show_hidden.to_string()),
            ("showDeleted".into(), show_deleted.to_string()),
        ];
        for (k, v) in [
            ("dueMin", due_min),
            ("dueMax", due_max),
            ("completedMin", completed_min),
            ("completedMax", completed_max),
            ("updatedMin", updated_min),
        ] {
            if let Some(v) = v {
                q.push((k.into(), v.into()));
            }
        }
        if let Some(m) = max_results {
            q.push(("maxResults".into(), m.to_string()));
        }
        if let Some(t) = page_token {
            q.push(("pageToken".into(), t.into()));
        }
        self.request(
            Method::GET,
            format!("{BASE}/lists/{tasklist_id}/tasks"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn get_task(&self, tasklist_id: &str, task_id: &str) -> Result<Value, TasksError> {
        self.request(
            Method::GET,
            format!("{BASE}/lists/{tasklist_id}/tasks/{task_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn create_task(
        &self,
        tasklist_id: &str,
        body: &Value,
        parent: Option<&str>,
        previous: Option<&str>,
    ) -> Result<Value, TasksError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(p) = parent {
            q.push(("parent".into(), p.into()));
        }
        if let Some(p) = previous {
            q.push(("previous".into(), p.into()));
        }
        self.request(
            Method::POST,
            format!("{BASE}/lists/{tasklist_id}/tasks"),
            Some(body),
            &q,
        )
        .await
    }

    pub async fn patch_task(
        &self,
        tasklist_id: &str,
        task_id: &str,
        body: &Value,
    ) -> Result<Value, TasksError> {
        self.request(
            Method::PATCH,
            format!("{BASE}/lists/{tasklist_id}/tasks/{task_id}"),
            Some(body),
            &[],
        )
        .await
    }

    pub async fn delete_task(&self, tasklist_id: &str, task_id: &str) -> Result<Value, TasksError> {
        self.request(
            Method::DELETE,
            format!("{BASE}/lists/{tasklist_id}/tasks/{task_id}"),
            None::<&()>,
            &[],
        )
        .await
    }

    pub async fn move_task(
        &self,
        tasklist_id: &str,
        task_id: &str,
        parent: Option<&str>,
        previous: Option<&str>,
        destination_tasklist: Option<&str>,
    ) -> Result<Value, TasksError> {
        let mut q: Vec<(String, String)> = vec![];
        if let Some(p) = parent {
            q.push(("parent".into(), p.into()));
        }
        if let Some(p) = previous {
            q.push(("previous".into(), p.into()));
        }
        if let Some(d) = destination_tasklist {
            q.push(("destinationTasklist".into(), d.into()));
        }
        self.request(
            Method::POST,
            format!("{BASE}/lists/{tasklist_id}/tasks/{task_id}/move"),
            None::<&()>,
            &q,
        )
        .await
    }

    pub async fn clear_completed(&self, tasklist_id: &str) -> Result<Value, TasksError> {
        self.request(
            Method::POST,
            format!("{BASE}/lists/{tasklist_id}/clear"),
            None::<&()>,
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
    ) -> Result<Value, TasksError> {
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
            return serde_json::from_str(&text).map_err(TasksError::Parse);
        }
        Err(TasksError::Api {
            status,
            message: text.chars().take(800).collect(),
        })
    }
}
