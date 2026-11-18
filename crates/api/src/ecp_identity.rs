//! HTTP adapter for immutable principals and capability grants.
use super::*;
use axum::extract::Path;
use forgeflow_store::ecp_identity::CapabilityGrantInput;
use serde::Deserialize;
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

pub async fn principals(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    member(&s, &headers, &workspace).await?;
    Ok(view(s.store.workspace_principals(&workspace).await?))
}

pub async fn grants(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let actor = member(&s, &headers, &workspace).await?;
    Ok(view(
        s.store
            .workspace_capability_grants(&actor.account_id, &workspace)
            .await?,
    ))
}

pub async fn create_grant(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CapabilityGrantInput>,
) -> ApiResult<Value> {
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key != body.request_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key must match capability request_key",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_capability_grant(&actor.account_id, &workspace, body)
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrant {
    pub expected_revision: i64,
}

pub async fn revoke_grant(
    State(s): State<App>,
    Path((workspace, grant)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RevokeGrant>,
) -> ApiResult<Value> {
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .revoke_capability_grant(
                &actor.account_id,
                &workspace,
                &grant,
                body.expected_revision,
            )
            .await?,
    ))
}
