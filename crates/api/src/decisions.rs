//! Owner decisions backed by typed Store commands, never generic document authority.
use super::*;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionListQuery {
    pub project_id: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenDecision {
    pub scope_id: String,
    pub expected_policy_revision: u64,
    pub note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeDecision {
    pub expected_revision: u64,
    pub note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferDecision {
    pub expected_revision: u64,
    pub revisit_at: chrono::DateTime<Utc>,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveDecision {
    pub expected_revision: u64,
    pub expected_policy_revision: u64,
    pub reason: String,
}

fn authorize(actor: &Principal, project: Option<&str>) -> Result<(), ApiError> {
    if actor.worker || !matches!(actor.actor_id.as_str(), "owner" | "owner-service") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "decisions require Owner authorization",
        ));
    }
    if actor
        .project_id
        .as_deref()
        .is_some_and(|bound| project != Some(bound))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "AUTHORITY_SCOPE_VIOLATION",
            "decision project differs from authenticated scope",
        ));
    }
    Ok(())
}

fn revision(value: u64) -> Result<(), ApiError> {
    if value == 0 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "a positive expected revision is required",
        ));
    }
    Ok(())
}

pub async fn list(
    State(state): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<DecisionListQuery>,
) -> ApiResult<Value> {
    if query.project_id.as_ref().is_some_and(|id| id != &project) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "AUTHORITY_SCOPE_VIOLATION",
            "query project must match the decision route",
        ));
    }
    list_in_scope(&state, &actor, Some(project), query).await
}

pub async fn global_list(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<DecisionListQuery>,
) -> ApiResult<Value> {
    list_in_scope(&state, &actor, query.project_id.clone(), query).await
}

async fn list_in_scope(
    state: &App,
    actor: &Principal,
    project: Option<String>,
    query: DecisionListQuery,
) -> ApiResult<Value> {
    authorize(actor, project.as_deref())?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500) as usize;
    let mut decisions = Vec::new();
    if let Some(project) = &project {
        state.store.get_project(project).await?;
        decisions = state.store.list_decisions(project).await?;
    } else {
        // Only current project identities and typed v1 decisions enter the inbox.
        // Legacy arbitrary JSON documents cannot acquire authority via this route.
        for project in state.store.list_projects().await? {
            decisions.extend(state.store.list_decisions(&project.project_id).await?);
        }
    }
    decisions.sort_by(|left, right| {
        (&left.project_id, &left.decision_id).cmp(&(&right.project_id, &right.decision_id))
    });
    if let Some(cursor) = query.cursor {
        if project.is_some() {
            decisions.retain(|decision| decision.decision_id > cursor);
        } else {
            let (project_cursor, decision_cursor): (String, String) = serde_json::from_str(&cursor)
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "INVALID_CURSOR",
                        "global decision cursor must be a JSON project/decision pair",
                    )
                })?;
            decisions.retain(|decision| {
                (&decision.project_id, &decision.decision_id) > (&project_cursor, &decision_cursor)
            });
        }
    }
    let more = decisions.len() > limit;
    decisions.truncate(limit);
    let next_cursor = if more {
        decisions.last().map(|decision| {
            if project.is_some() {
                decision.decision_id.clone()
            } else {
                serde_json::to_string(&(&decision.project_id, &decision.decision_id))
                    .expect("decision cursor serializable")
            }
        })
    } else {
        None
    };
    let mut response = view(decisions);
    response.0["next_cursor"] = json!(next_cursor);
    response.0["scope"] = json!({"project_id":project,"schema_version":"forgeflow.decision-inbox.v1","snapshot_across_pages":false});
    Ok(response)
}

pub async fn detail(
    State(state): State<App>,
    Path((project, decision)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    authorize(&actor, Some(&project))?;
    state.store.get_project(&project).await?;
    Ok(view(state.store.get_decision(&project, &decision).await?))
}

pub async fn create(
    State(state): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<OpenDecision>,
) -> ApiResult<Value> {
    authorize(&actor, Some(&project))?;
    revision(body.expected_policy_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Decision(DecisionCommand::OpenPausedPolicy {
            project_id: project,
            scope_id: body.scope_id,
            expected_policy_revision: body.expected_policy_revision,
            note: body.note,
        }),
    )
    .await
}

pub async fn acknowledge(
    State(state): State<App>,
    Path((project, decision)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<AcknowledgeDecision>,
) -> ApiResult<Value> {
    authorize(&actor, Some(&project))?;
    revision(body.expected_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Decision(DecisionCommand::Acknowledge {
            project_id: project,
            decision_id: decision,
            expected_revision: body.expected_revision,
            note: body.note,
        }),
    )
    .await
}

pub async fn defer(
    State(state): State<App>,
    Path((project, decision)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<DeferDecision>,
) -> ApiResult<Value> {
    authorize(&actor, Some(&project))?;
    revision(body.expected_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Decision(DecisionCommand::Defer {
            project_id: project,
            decision_id: decision,
            expected_revision: body.expected_revision,
            revisit_at: body.revisit_at,
            reason: body.reason,
        }),
    )
    .await
}

pub async fn resolve(
    State(state): State<App>,
    Path((project, decision)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ResolveDecision>,
) -> ApiResult<Value> {
    authorize(&actor, Some(&project))?;
    revision(body.expected_revision)?;
    revision(body.expected_policy_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Decision(DecisionCommand::Resolve {
            project_id: project,
            decision_id: decision,
            expected_revision: body.expected_revision,
            expected_policy_revision: body.expected_policy_revision,
            reason: body.reason,
        }),
    )
    .await
}
