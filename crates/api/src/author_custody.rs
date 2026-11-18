//! Explicit Owner author closure preserves every unresolved custody reservation.
use super::*;

#[derive(Deserialize)]
pub struct CustodyQuery {
    pub project_id: String,
}

fn owner(actor: &Principal) -> Result<(), ApiError> {
    if actor.worker || !matches!(actor.actor_id.as_str(), "owner" | "owner-service") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_AUTHORIZATION_REQUIRED",
            "custody recovery requires Owner authentication",
        ));
    }
    Ok(())
}

pub async fn observe(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<WorkerResult>,
) -> ApiResult<Value> {
    if !actor.worker || actor.worker_id.is_none() || actor.project_id.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_AUTH_REQUIRED",
            "physical author stop requires a scoped Worker credential",
        ));
    }
    identity(&headers, &actor)?;
    if body.attempt_id != attempt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path and observation differ",
        ));
    }
    let actual = crate::workers::authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    if body.worker_id != actual.worker_id || body.generation != actual.generation {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_SCOPE_DENIED",
            "stop observation differs from the original assigned Worker",
        ));
    }
    Ok(view(s.store.record_author_stop_observation(body).await?))
}

pub async fn close(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<CloseAuthorRetainCustodyRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    if body.attempt_id != attempt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path and recovery request differ",
        ));
    }
    crate::workers::authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    let identity = identity(&headers, &actor)?;
    Ok(view(
        s.store.close_author_retain_custody(identity, body).await?,
    ))
}

pub async fn status(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<CustodyQuery>,
) -> ApiResult<Value> {
    owner(&actor)?;
    crate::workers::authorized_attempt(&s, &actor, &query.project_id, &attempt).await?;
    Ok(view(
        s.store
            .author_custody_status(&query.project_id, &attempt)
            .await?,
    ))
}

pub async fn release_physical(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ReleaseStoppedPhysicalResourcesRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    if body.attempt_id != attempt {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path and physical recovery differ",
        ));
    }
    crate::workers::authorized_attempt(&s, &actor, &body.project_id, &attempt).await?;
    Ok(view(
        s.store
            .release_stopped_physical_resources(identity(&headers, &actor)?, body)
            .await?,
    ))
}
