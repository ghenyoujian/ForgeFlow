//! HTTP adapter for ECP Phase 6 resource/cost governance.
use super::*;
use axum::extract::Path;
use forgeflow_store::ecp_resources::{
    BudgetReservationInput, CostLedgerInput, LeaseRevocationInput, ResourceProfileInput,
};
use serde_json::Value;

fn require_idempotency(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if value.len() < 16 || value.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key is required for resource commands",
        ));
    }
    Ok(value)
}

pub async fn create_profile(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ResourceProfileInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_ecp_resource_profile(&actor.account_id, &workspace, body)
            .await?,
    ))
}

pub async fn reserve_budget(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BudgetReservationInput>,
) -> ApiResult<Value> {
    let key = require_idempotency(&headers)?;
    if key != body.idempotency_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key must match reservation idempotency_key",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .reserve_ecp_budget(&actor.account_id, &workspace, body)
            .await?,
    ))
}

pub async fn record_cost(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CostLedgerInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .record_ecp_cost(&actor.account_id, &workspace, body)
            .await?,
    ))
}

pub async fn revoke_lease(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<LeaseRevocationInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .revoke_ecp_lease(&actor.account_id, &workspace, body)
            .await?,
    ))
}
