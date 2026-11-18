use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
pub async fn register(
    State(s): State<App>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<WorkerRegisterRequest>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&body.worker_id), body.project_id.as_deref())
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    if actor.worker && body.project_id.is_none() && actor.project_id.is_some() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_SCOPE_DENIED",
            "project identity is required by deployment worker scope",
        ));
    }
    identity(&headers, &actor)?;
    s.store.register_worker(body).await?;
    Ok(view(json!({"registered":true})))
}
pub async fn heartbeat(
    State(s): State<App>,
    Path(worker): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<WorkerHeartbeatRequest>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&body.worker_id), None)
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    identity(&headers, &actor)?;
    if body.worker_id != worker {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "worker path/body differ",
        ));
    }
    s.store.heartbeat_worker(body).await?;
    Ok(view(json!({"heartbeat_recorded":true})))
}
#[derive(Deserialize)]
pub struct Claim {
    project_id: String,
    #[serde(default)]
    known_attempt_ids: Vec<String>,
}
pub async fn claim(
    State(s): State<App>,
    Path(worker): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<Claim>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&worker), Some(&body.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    identity(&headers, &actor)?;
    let envelope = s
        .store
        .claim_with_known_attempts(&worker, &body.project_id, &body.known_attempt_ids)
        .await?;
    Ok(Json(json!({"envelope":envelope})))
}
#[derive(Deserialize)]
pub struct Control {
    project_id: String,
    generation: i64,
    worker_id: String,
}
pub async fn control(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<Control>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&q.worker_id), Some(&q.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    authorized_attempt(&s, &actor, &q.project_id, &attempt).await?;
    let result = s
        .store
        .attempt_control(&q.project_id, &attempt, q.generation, &q.worker_id)
        .await?;
    Ok(Json(
        json!({"valid":result.valid&&!s.auth.is_shutting_down(),"cancel_requested":result.cancel_requested||s.auth.is_shutting_down(),"lease_expires_at":result.lease_expires_at.unwrap_or_default()}),
    ))
}
pub async fn worker_event(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<WorkerEvent>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&body.worker_id), Some(&body.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    identity(&headers, &actor)?;
    if body.attempt_id != attempt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path/body differ",
        ));
    }
    authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    s.store.record_worker_event(body).await?;
    Ok(view(json!({"recorded":true})))
}
pub async fn worker_result(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<WorkerResult>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&body.worker_id), Some(&body.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    identity(&headers, &actor)?;
    if body.attempt_id != attempt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path/body differ",
        ));
    }
    authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    let result = s.store.worker_result(body).await?;
    Ok(view(result))
}
pub async fn artifact_content(
    State(s): State<App>,
    Extension(actor): Extension<Principal>,
    Path(artifact): Path<String>,
    Query(q): Query<ArtifactQuery>,
) -> Result<Response, ApiError> {
    if actor.worker && q.project_id.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "PROJECT_SCOPE_REQUIRED",
            "worker artifact read requires project_id",
        ));
    }
    if actor.worker {
        s.auth
            .worker_scope(&actor, None, q.project_id.as_deref())
            .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    }
    if !safe_component(&artifact) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_ARTIFACT_ID",
            "artifact must be a safe ID",
        ));
    }
    let projects = if let Some(p) = q.project_id {
        vec![p]
    } else {
        s.store
            .list_projects()
            .await?
            .into_iter()
            .map(|p| p.project_id)
            .collect()
    };
    for p in projects {
        if let Ok(doc) = s.store.get_document(&p, "artifacts", &artifact).await {
            let relative = doc.get("path").and_then(Value::as_str).ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "ARTIFACT_DESCRIPTOR_INVALID",
                    "artifact needs path",
                )
            })?;
            let path = checked_path(&s.data_root.join("artifacts"), relative)?;
            let bytes = tokio::fs::read(path).await.map_err(|e| {
                ApiError::new(StatusCode::NOT_FOUND, "ARTIFACT_MISSING", e.to_string())
            })?;
            if bytes.len() > 32 * 1024 * 1024 {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "ARTIFACT_TOO_LARGE",
                    "artifact exceeds inline transfer limit",
                ));
            }
            let expected = doc.get("sha256").and_then(Value::as_str).ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "ARTIFACT_DESCRIPTOR_INVALID",
                    "artifact needs sha256",
                )
            })?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            if digest != expected {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "ARTIFACT_HASH_MISMATCH",
                    "artifact content differs from immutable descriptor",
                ));
            }
            return Ok((
                [
                    ("content-type", "application/octet-stream"),
                    ("x-content-type-options", "nosniff"),
                ],
                bytes,
            )
                .into_response());
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "ARTIFACT_NOT_FOUND",
        "no persisted artifact descriptor found",
    ))
}
#[derive(Deserialize)]
pub struct ArtifactQuery {
    project_id: Option<String>,
}
fn safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn checked_path(root: &std::path::Path, relative: &str) -> Result<PathBuf, ApiError> {
    let rel = std::path::Path::new(relative);
    if !rel.is_absolute()
        && rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "PATH_TRAVERSAL",
            "relative artifact path required",
        ));
    }
    let canonical = root
        .join(rel)
        .canonicalize()
        .map_err(|e| ApiError::new(StatusCode::NOT_FOUND, "ARTIFACT_MISSING", e.to_string()))?;
    let root = root.canonicalize().map_err(|e| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "ARTIFACT_ROOT_MISSING",
            e.to_string(),
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "PATH_TRAVERSAL",
            "artifact resolves outside data root",
        ));
    }
    Ok(canonical)
}
#[derive(Deserialize)]
pub struct LogQuery {
    offset: Option<u64>,
    limit_bytes: Option<usize>,
}
pub async fn logs(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Value> {
    if !safe_component(&attempt) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_ATTEMPT_ID",
            "attempt ID has invalid characters",
        ));
    }
    let path = checked_path(
        &s.data_root.join("attempts"),
        &format!("{attempt}/stdout.ndjson"),
    )?;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| ApiError::new(StatusCode::NOT_FOUND, "LOG_NOT_FOUND", e.to_string()))?;
    let offset = q.offset.unwrap_or(0);
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "LOG_READ_FAILED",
                e.to_string(),
            )
        })?;
    let mut bytes = vec![0; q.limit_bytes.unwrap_or(65536).clamp(1, 1024 * 1024)];
    let n = file.read(&mut bytes).await.map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "LOG_READ_FAILED",
            e.to_string(),
        )
    })?;
    bytes.truncate(n);
    Ok(view(
        json!({"attempt_id":attempt,"offset":offset,"bytes":n,"next_offset":offset+n as u64,"text":String::from_utf8_lossy(&bytes)}),
    ))
}
pub async fn lease_heartbeat(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<HeartbeatRequest>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&body.worker_id), Some(&body.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    identity(&headers, &actor)?;
    if body.attempt_id != attempt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path/body differ",
        ));
    }
    authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    Ok(view(s.store.heartbeat(body).await?))
}
#[derive(Deserialize)]
pub struct GatewayScope {
    project_id: String,
}
pub async fn gateway_scope(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<GatewayScope>,
) -> ApiResult<Value> {
    identity(&headers, &actor)?;
    if actor.worker {
        s.auth
            .worker_scope(&actor, None, Some(&body.project_id))
            .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    }
    authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    let gateway = s.gateway.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "GATEWAY_UNCONFIGURED",
            "hard model budget gateway is not configured",
        )
    })?;
    let token = gateway
        .issue_scope(&body.project_id, &attempt)
        .await
        .map_err(|e| ApiError::new(e.status, &e.code, "model request scope denied"))?;
    Ok(Json(
        json!({"data":{"scope_token":token,"endpoint":"/v1/messages","project_id":body.project_id,"attempt_id":attempt}}),
    ))
}
pub async fn bindings(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<Control>,
) -> ApiResult<Value> {
    s.auth
        .worker_scope(&actor, Some(&q.worker_id), Some(&q.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    authorized_attempt(&s, &actor, &q.project_id, &attempt).await?;
    let control = s
        .store
        .attempt_control(&q.project_id, &attempt, q.generation, &q.worker_id)
        .await?;
    if !control.valid {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "LEASE_STALE",
            "execution binding read requires current generation and assigned worker lease",
        ));
    }
    Ok(view(
        s.store.attempt_bindings(&q.project_id, &attempt).await?,
    ))
}

/// Request fields cannot supply another Worker's assignment rights. Owner
/// management remains authorized; lease/generation checks stay in Store.
pub(crate) async fn authorized_attempt(
    state: &App,
    actor: &Principal,
    project: &str,
    attempt: &str,
) -> Result<Attempt, ApiError> {
    state
        .auth
        .worker_scope(actor, None, Some(project))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    let actual = state.store.get_attempt(project, attempt).await?;
    state
        .auth
        .worker_scope(actor, Some(&actual.worker_id), Some(&actual.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    Ok(actual)
}
