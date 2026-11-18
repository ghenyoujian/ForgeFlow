//! Worker-sidecar adapter; DSH receives a private UDS and cannot authenticate here.
use super::*;

pub async fn native_controller(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Value> {
    if !actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_AUTH_REQUIRED",
            "native controller requires trusted Worker service authentication",
        ));
    }
    if s.auth.is_shutting_down()
        && matches!(
            body.get("operation").and_then(Value::as_str),
            Some("admit" | "model_request")
        )
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVER_DRAINING",
            "native admissions and model requests stop during drain",
        ));
    }
    let worker = headers
        .get("x-forgeflow-worker-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "WORKER_ID_REQUIRED",
                "trusted sidecar Worker identity required",
            )
        })?;
    let project = body
        .get("project_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "IDENTITY_MISMATCH",
                "project identity required",
            )
        })?;
    if body.get("attempt_id").and_then(Value::as_str) != Some(attempt.as_str()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path and RPC body differ",
        ));
    }
    s.auth
        .worker_scope(&actor, Some(worker), Some(project))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    crate::workers::authorized_attempt(&s, &actor, project, &attempt).await?;
    let generation = body.get("generation").cloned().unwrap_or(Value::Null);
    match s.store.collaboration_rpc(worker, body).await {
        Ok(reply) => Ok(Json(reply)),
        Err(forgeflow_store::StoreError::Domain(error)) => Ok(Json(
            json!({"ok":false,"generation":generation,"code":error.code}),
        )),
        Err(error) => Err(error.into()),
    }
}
