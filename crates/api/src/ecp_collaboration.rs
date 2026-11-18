//! HTTP adapter for the durable Phase 4 collaboration facts.
use super::*;
use axum::extract::Path;
use forgeflow_store::ecp_collaboration::{
    AssignmentInput, AssignmentTransitionInput, DecisionInput, EscalationInput, ProposalInput,
    ReviewInput,
};
use serde_json::Value;

fn require_key(headers: &HeaderMap, body_key: &str) -> Result<(), ApiError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key.len() < 16 || key.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key is required for ECP collaboration commands",
        ));
    }
    if !body_key.is_empty() && key != body_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_MISMATCH",
            "Idempotency-Key must match request_key",
        ));
    }
    Ok(())
}

fn require_path_identity(path: &str, body: &str, label: &str) -> Result<(), ApiError> {
    if path != body {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            format!("{label} does not match the route identity"),
        ));
    }
    Ok(())
}

fn require_workspace_identity(headers: &HeaderMap, workspace: &str) -> Result<(), ApiError> {
    let scoped = headers
        .get("x-forgeflow-workspace")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if scoped != workspace {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "workspace header does not match the route identity",
        ));
    }
    Ok(())
}

pub async fn create_assignment(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AssignmentInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_ecp_assignment(&actor.account_id, &workspace, body)
            .await?,
    ))
}

pub async fn accept_assignment(
    State(s): State<App>,
    Path((workspace, assignment)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<AssignmentTransitionInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .accept_ecp_assignment(&actor.account_id, &assignment, body)
            .await?,
    ))
}

pub async fn create_proposal(
    State(s): State<App>,
    Path((workspace, assignment)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ProposalInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    require_path_identity(&assignment, &body.assignment_id, "assignment_id")?;
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store.create_ecp_proposal(&actor.account_id, body).await?,
    ))
}

pub async fn create_review(
    State(s): State<App>,
    Path((workspace, proposal)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ReviewInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    require_path_identity(&proposal, &body.proposal_id, "proposal_id")?;
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store.create_ecp_review(&actor.account_id, body).await?,
    ))
}

pub async fn create_decision(
    State(s): State<App>,
    Path((workspace, proposal)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<DecisionInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    require_path_identity(&proposal, &body.proposal_id, "proposal_id")?;
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store.create_ecp_decision(&actor.account_id, body).await?,
    ))
}

pub async fn create_assignment_escalation(
    State(s): State<App>,
    Path((workspace, assignment)): Path<(String, String)>,
    headers: HeaderMap,
    Json(mut body): Json<EscalationInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    if let Some(value) = &body.assignment_id {
        require_path_identity(&assignment, value, "assignment_id")?;
    }
    if body.assignment_id.is_none() {
        body.assignment_id = Some(assignment);
    }
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_ecp_escalation(&actor.account_id, body)
            .await?,
    ))
}

pub async fn create_proposal_escalation(
    State(s): State<App>,
    Path((workspace, proposal)): Path<(String, String)>,
    headers: HeaderMap,
    Json(mut body): Json<EscalationInput>,
) -> ApiResult<Value> {
    require_workspace_identity(&headers, &workspace)?;
    if let Some(value) = &body.proposal_id {
        require_path_identity(&proposal, value, "proposal_id")?;
    }
    if body.proposal_id.is_none() {
        body.proposal_id = Some(proposal);
    }
    require_key(&headers, &body.request_key)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_ecp_escalation(&actor.account_id, body)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_route_and_scope_must_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forgeflow-workspace", "workspace-a".parse().unwrap());
        assert!(require_workspace_identity(&headers, "workspace-a").is_ok());
        assert!(require_workspace_identity(&headers, "workspace-b").is_err());
    }

    #[test]
    fn missing_workspace_scope_is_rejected() {
        let headers = HeaderMap::new();
        assert!(require_workspace_identity(&headers, "workspace-a").is_err());
    }
}
