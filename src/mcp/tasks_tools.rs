//! Google Tasks tools. Separate `#[tool_router(router = tasks_router)]`
//! impl block — composed in `mcp/server.rs`'s constructor via `ToolRouter::Add`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::{McpError, to_mcp};
use crate::google::tasks::{TasksClient, TasksError};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = tasks_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "tasks_list_tasklists",
        description = "List the user's task lists. Returns `{ items: [{id, title, updated}, ...] }`. The list `id` is what every other tasks_* tool takes as `tasklist_id`; `@default` always resolves to the user's default list."
    )]
    async fn tasks_list_tasklists(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksListTasklistsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        client
            .list_tasklists(p.max_results, p.page_token.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "tasks_get_tasklist",
        description = "Get one task list's metadata by ID (or `@default`)."
    )]
    async fn tasks_get_tasklist(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksTasklistIdParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.tasklist_id.clone();
        client
            .get_tasklist(&p.tasklist_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "tasklist", &id))
    }

    #[tool(
        name = "tasks_create_tasklist",
        description = "Create a new task list. Returns the new list resource including its `id`."
    )]
    async fn tasks_create_tasklist(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksCreateTasklistParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.title, "title")?;
        let client = self.tasks_for(&parts).await?;
        client
            .create_tasklist(&p.title)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "tasks_update_tasklist",
        description = "Rename an existing task list."
    )]
    async fn tasks_update_tasklist(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksUpdateTasklistParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.title, "title")?;
        let client = self.tasks_for(&parts).await?;
        let id = p.tasklist_id.clone();
        client
            .update_tasklist(&p.tasklist_id, &p.title)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "tasklist", &id))
    }

    #[tool(
        name = "tasks_delete_tasklist",
        description = "Delete a task list and every task in it. Irreversible — there is no trash for task lists. Prefer `tasks_clear_completed` when you only want to tidy up."
    )]
    async fn tasks_delete_tasklist(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksTasklistIdParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.tasklist_id.clone();
        client
            .delete_tasklist(&p.tasklist_id)
            .await
            .map(|_| json!({"deleted": id}).to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "tasklist", &p.tasklist_id))
    }

    #[tool(
        name = "tasks_list",
        description = "List the tasks in a list (default `@default`). Subtasks carry a `parent` field and `position` orders siblings. Set `show_completed=false` for the open items only."
    )]
    async fn tasks_list(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksListParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.tasklist_id.clone();
        client
            .list_tasks(
                &p.tasklist_id,
                p.show_completed,
                p.show_hidden,
                p.show_deleted,
                p.due_min.as_deref(),
                p.due_max.as_deref(),
                p.completed_min.as_deref(),
                p.completed_max.as_deref(),
                p.updated_min.as_deref(),
                p.max_results,
                p.page_token.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "tasklist", &id))
    }

    #[tool(name = "tasks_get", description = "Get one task by ID.")]
    async fn tasks_get(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksTaskIdParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.task_id.clone();
        client
            .get_task(&p.tasklist_id, &p.task_id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "task", &id))
    }

    #[tool(
        name = "tasks_create",
        description = "Create a task. `due` is RFC3339 but Google Tasks keeps only the DATE part — a time of day is silently dropped, so tasks cannot carry a due time. Pass `parent` to make it a subtask, `previous` to place it after a given sibling."
    )]
    async fn tasks_create(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksCreateParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.title, "title")?;
        ensure_notes_fit(p.notes.as_deref())?;
        let client = self.tasks_for(&parts).await?;
        let mut body = json!({"title": p.title});
        if let Some(n) = &p.notes {
            body["notes"] = json!(n);
        }
        if let Some(d) = &p.due {
            body["due"] = json!(d);
        }
        if p.completed {
            body["status"] = json!("completed");
        }
        let id = p.tasklist_id.clone();
        client
            .create_task(
                &p.tasklist_id,
                &body,
                p.parent.as_deref(),
                p.previous.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "tasklist", &id))
    }

    #[tool(
        name = "tasks_update",
        description = "Patch a task's title, notes, due date, or status. Only the fields you pass are touched. Pass `due=\"\"` to clear the due date; setting `status=needsAction` reopens a completed task."
    )]
    async fn tasks_update(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksUpdateParams>,
    ) -> Result<String, ErrorData> {
        ensure_notes_fit(p.notes.as_deref())?;
        if let Some(s) = &p.status {
            ensure_status(s)?;
        }
        if p.title.is_none() && p.notes.is_none() && p.due.is_none() && p.status.is_none() {
            return Err(McpError::invalid_input("nothing to update")
                .with_hint("Pass at least one of `title`, `notes`, `due`, or `status`.")
                .into());
        }
        let client = self.tasks_for(&parts).await?;
        let mut body = json!({"id": p.task_id});
        if let Some(t) = &p.title {
            body["title"] = json!(t);
        }
        if let Some(n) = &p.notes {
            body["notes"] = json!(n);
        }
        if let Some(d) = &p.due {
            body["due"] = if d.is_empty() { Value::Null } else { json!(d) };
        }
        if let Some(s) = &p.status {
            body["status"] = json!(s);
            if s == "needsAction" {
                body["completed"] = Value::Null;
            }
        }
        let id = p.task_id.clone();
        client
            .patch_task(&p.tasklist_id, &p.task_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "task", &id))
    }

    #[tool(
        name = "tasks_complete",
        description = "Convenience: tick a task off (or untick it with `completed=false`). Wraps `tasks_update`'s status flip and clears the completion timestamp when reopening."
    )]
    async fn tasks_complete(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksCompleteParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let body = if p.completed {
            json!({"id": p.task_id, "status": "completed"})
        } else {
            json!({"id": p.task_id, "status": "needsAction", "completed": Value::Null})
        };
        let id = p.task_id.clone();
        client
            .patch_task(&p.tasklist_id, &p.task_id, &body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "task", &id))
    }

    #[tool(
        name = "tasks_move",
        description = "Reposition a task: reparent it (`parent`), reorder it among siblings (`previous`), or send it to another list (`destination_tasklist`). Omitting `previous` moves it to the top."
    )]
    async fn tasks_move(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksMoveParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.task_id.clone();
        client
            .move_task(
                &p.tasklist_id,
                &p.task_id,
                p.parent.as_deref(),
                p.previous.as_deref(),
                p.destination_tasklist.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "task", &id))
    }

    #[tool(
        name = "tasks_delete",
        description = "Delete a task. It is soft-deleted (recoverable via `tasks_list` with `show_deleted=true` until the list is cleared)."
    )]
    async fn tasks_delete(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksTaskIdParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.task_id.clone();
        client
            .delete_task(&p.tasklist_id, &p.task_id)
            .await
            .map(|_| json!({"deleted": id}).to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "task", &p.task_id))
    }

    #[tool(
        name = "tasks_clear_completed",
        description = "Hide every completed task in a list (the Tasks UI's \"Delete all completed tasks\"). They stop appearing in normal listings but remain reachable with `show_hidden=true`."
    )]
    async fn tasks_clear_completed(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<TasksTasklistIdParams>,
    ) -> Result<String, ErrorData> {
        let client = self.tasks_for(&parts).await?;
        let id = p.tasklist_id.clone();
        client
            .clear_completed(&p.tasklist_id)
            .await
            .map(|_| json!({"cleared": id}).to_string())
            .map_err(|e| reclassify_tasks_not_found(e, "tasklist", &p.tasklist_id))
    }
}

impl GoogleMcp {
    pub(crate) async fn tasks_for(&self, parts: &Parts) -> Result<TasksClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        Ok(TasksClient::new(
            (*self.state.http).clone(),
            session.access_token,
        ))
    }
}

fn reclassify_tasks_not_found(e: TasksError, kind: &'static str, id: &str) -> ErrorData {
    if let TasksError::Api { status, .. } = &e
        && status.as_u16() == 404
    {
        return McpError::not_found(kind, id, "tasks").into();
    }
    to_mcp(e)
}

fn ensure_non_empty(s: &str, field: &str) -> Result<(), ErrorData> {
    if s.trim().is_empty() {
        return Err(
            McpError::invalid_input(format!("`{field}` must not be empty"))
                .with_service("tasks")
                .into(),
        );
    }
    Ok(())
}

/// Tasks rejects notes over 8192 characters with an opaque 400.
fn ensure_notes_fit(notes: Option<&str>) -> Result<(), ErrorData> {
    const MAX: usize = 8192;
    if let Some(n) = notes
        && n.chars().count() > MAX
    {
        return Err(McpError::invalid_input(format!(
            "`notes` is {} characters; Google Tasks allows at most {MAX}",
            n.chars().count()
        ))
        .with_service("tasks")
        .into());
    }
    Ok(())
}

fn ensure_status(s: &str) -> Result<(), ErrorData> {
    if s != "needsAction" && s != "completed" {
        return Err(McpError::invalid_input(format!("unknown status '{s}'"))
            .with_hint("Valid values: `needsAction`, `completed`.")
            .with_service("tasks")
            .into());
    }
    Ok(())
}
