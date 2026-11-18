//! Owner-only Capsule discovery and immutable policy preparation. None of these
//! handlers creates an Attempt, launches a process or authorizes a write.
use super::*;
use axum::extract::Query;
use forgeflow_store::capsules::{CapsuleContextRequest, CapsulePolicyRequest};
use serde::Deserialize;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

fn owner(actor: &Principal) -> Result<(), ApiError> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "Capsule discovery and policy registration require Owner identity",
        ));
    }
    Ok(())
}

fn page(value: Value) -> Json<Value> {
    Json(
        json!({"data":value["items"],"next_cursor":value["next_cursor"],"observed_at":Utc::now(),"source":"postgres","authorization_granted":false}),
    )
}

pub async fn list(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(page(
        s.store
            .capsules(
                &project,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}

pub async fn detail(
    State(s): State<App>,
    Path((project, attempt)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(view(s.store.attempt_capsule(&project, &attempt).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    binding: CapsuleBinding,
}

pub async fn check(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Json(body): Json<CheckRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(view(s.store.check_capsule(&project, &body.binding).await?))
}

pub async fn context(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<CapsuleContextRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(view(
        json!({"environment":s.store.capsule_context(&project, &query).await?,"qualification":"NOT_EVALUATED","authorization_granted":false}),
    ))
}

pub async fn policies(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(page(
        s.store
            .capsule_policies(
                &project,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}

pub async fn register(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<CapsulePolicyRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(Json(
        s.store
            .register_capsule_policy(identity(&headers, &actor)?, &project, body)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_policy_and_checks_reject_replacement_authority_fields() {
        assert!(serde_json::from_value::<CapsulePolicyRequest>(json!({
            "schema_version":"forgeflow.capsule-policy.v1","executor_profile_id":"executor",
            "resource_profile_id":"resource","model_route_id":"route","mode":"CLAUDE_LEAF",
            "team_write_policy":"AGGREGATE_WRITE_SCOPE","qualification_ref":{"artifact_id":"probe","sha256":"a".repeat(64)},
            "envelope":{"lease_id":"replacement"}
        })).is_err());
        assert!(serde_json::from_value::<CapsuleContextRequest>(json!({
            "executor_profile_id":"executor","resource_profile_id":"resource","model_route_id":"route",
            "launch":true
        })).is_err());
        assert!(
            serde_json::from_value::<CheckRequest>(json!({"binding":null,"write_set":["/"]}))
                .is_err()
        );
    }
}
