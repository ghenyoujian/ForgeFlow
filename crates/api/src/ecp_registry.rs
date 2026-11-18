//! HTTP adapter for discovery-only Agent Registry and Executor Profiles.
use super::*;
use axum::extract::Path;
use forgeflow_store::ecp_registry::{AgentRegistrationInput, ExecutorProfileInput};
use serde_json::Value;

async fn member(
    s: &App,
    headers: &HeaderMap,
    workspace: &str,
) -> Result<auth::SessionActor, ApiError> {
    let actor = workspaces::current_actor(s, headers).await?;
    if s.store
        .workspace_role(&actor.account_id, workspace)
        .await?
        .is_none()
    {
        return Err(workspaces::forbidden("workspace membership required"));
    }
    Ok(actor)
}

pub async fn snapshot(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let actor = member(&s, &headers, &workspace).await?;
    Ok(view(
        s.store
            .registry_snapshot(&actor.account_id, &workspace)
            .await?,
    ))
}

pub async fn register(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AgentRegistrationInput>,
) -> ApiResult<Value> {
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key != body.request_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key must match agent request_key",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .register_agent(&actor.account_id, &workspace, body)
            .await?,
    ))
}

pub async fn freeze_profile(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ExecutorProfileInput>,
) -> ApiResult<Value> {
    if headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .len()
        < 16
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key is required for profile freeze",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .freeze_executor_profile(&actor.account_id, &workspace, body)
            .await?,
    ))
}
