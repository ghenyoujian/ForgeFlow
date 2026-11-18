//! HTTP adapter for durable ECP Conversation/Message/Delivery primitives.
use super::*;
use axum::extract::{Path, Query};
use forgeflow_store::ecp_messaging::{
    CheckpointInput, ConversationInput, ConversationRevokeInput, DeliveryClaimInput,
    DeliveryFailureInput, MessageInput, ReceiptInput, ThreadInput,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct CursorQuery {
    #[serde(default)]
    pub after: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    100
}
fn require_idempotency(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if value.len() < 16 || value.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key is required for ECP messaging commands",
        ));
    }
    Ok(value)
}

pub async fn create_conversation(
    State(s): State<App>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ConversationInput>,
) -> ApiResult<Value> {
    let request_key = require_idempotency(&headers)?;
    if body.request_key != request_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_MISMATCH",
            "Idempotency-Key must match request_key",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_ecp_conversation(&actor.account_id, &workspace, body)
            .await?,
    ))
}
pub async fn create_thread(
    State(s): State<App>,
    Path(conversation): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ThreadInput>,
) -> ApiResult<Value> {
    let request_key = require_idempotency(&headers)?;
    if body.request_key != request_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_MISMATCH",
            "Idempotency-Key must match request_key",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .create_ecp_thread(&actor.account_id, &conversation, body)
            .await?,
    ))
}
pub async fn send_message(
    State(s): State<App>,
    Path(conversation): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MessageInput>,
) -> ApiResult<Value> {
    let request_key = require_idempotency(&headers)?;
    if body.client_request_id != request_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_MISMATCH",
            "Idempotency-Key must match client_request_id",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .send_ecp_message(&actor.account_id, &conversation, body)
            .await?,
    ))
}
pub async fn list_messages(
    State(s): State<App>,
    Path(conversation): Path<String>,
    Query(query): Query<CursorQuery>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .list_ecp_messages(&actor.account_id, &conversation, query.after, query.limit)
            .await?,
    ))
}
pub async fn receipt(
    State(s): State<App>,
    Path(delivery): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ReceiptInput>,
) -> ApiResult<Value> {
    let request_key = require_idempotency(&headers)?;
    if body.request_key != request_key {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_MISMATCH",
            "Idempotency-Key must match request_key",
        ));
    }
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .ack_ecp_delivery(&actor.account_id, &delivery, body)
            .await?,
    ))
}

pub async fn checkpoint(
    State(s): State<App>,
    Path(conversation): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CheckpointInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .checkpoint_ecp_inbox(&actor.account_id, &conversation, body)
            .await?,
    ))
}

pub async fn claim_delivery(
    State(s): State<App>,
    Path(delivery): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DeliveryClaimInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .claim_ecp_delivery(&actor.account_id, &delivery, body)
            .await?,
    ))
}

pub async fn fail_delivery(
    State(s): State<App>,
    Path(delivery): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DeliveryFailureInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .fail_ecp_delivery(&actor.account_id, &delivery, body)
            .await?,
    ))
}

pub async fn revoke_conversation(
    State(s): State<App>,
    Path(conversation): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ConversationRevokeInput>,
) -> ApiResult<Value> {
    require_idempotency(&headers)?;
    let actor = workspaces::current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .revoke_ecp_conversation(&actor.account_id, &conversation, body)
            .await?,
    ))
}
