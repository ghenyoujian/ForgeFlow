//! User planning commands and consistent, read-only resource forecast projections.
use super::*;
use forgeflow_scheduler::planning::{AvailabilityWindow, PlanningScope, PlanningTask};
use std::collections::{BTreeMap, BTreeSet};

pub async fn overview(State(s): State<App>, Path(project): Path<String>) -> ApiResult<Value> {
    let data = s.store.planning_overview(&project).await?;
    Ok(Json(
        json!({"read_model_version":data["revision"],"observed_at":data["as_of"],"source":"postgres","next_cursor":null,"data":data}),
    ))
}
pub async fn assignment_context(
    State(s): State<App>,
    Path(project): Path<String>,
) -> ApiResult<Value> {
    let data = s.store.assignment_context(&project).await?;
    Ok(Json(
        json!({"read_model_version":data["revision"],"observed_at":data["as_of"],"source":"postgres","next_cursor":null,"data":data}),
    ))
}
#[derive(Deserialize)]
pub struct TaskListQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    #[serde(flatten)]
    pub filter: forgeflow_store::TaskListFilter,
}
pub async fn task_list(
    State(s): State<App>,
    Path(project): Path<String>,
    axum::extract::Query(q): axum::extract::Query<TaskListQuery>,
) -> ApiResult<Value> {
    Ok(Json(
        s.store
            .task_page(
                &project,
                &q.filter,
                q.cursor.as_deref(),
                q.limit.unwrap_or(100),
            )
            .await?,
    ))
}
pub async fn inputs(State(s): State<App>, Path(project): Path<String>) -> ApiResult<Value> {
    Ok(view(s.store.planning_snapshot(&project).await?))
}
pub async fn estimate(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(estimate): Json<TaskEstimate>,
) -> ApiResult<Value> {
    if estimate.project_id != project {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "estimate project differs",
        ));
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutDocument {
            project_id: project,
            collection: "task_estimates".into(),
            id: estimate.estimate_id.clone(),
            expected_revision: None,
            value: serde_json::to_value(estimate).map_err(contract_error)?,
        },
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRequest {
    pub input_revision: u64,
    #[serde(default)]
    pub planning_input_digest: Option<String>,
    pub start_at: chrono::DateTime<Utc>,
    pub end_at: chrono::DateTime<Utc>,
    #[serde(default)]
    pub availability: Vec<AvailabilityWindow>,
    #[serde(default)]
    pub worker_scope_id: Option<String>,
    #[serde(default)]
    pub task_ids: Vec<String>,
    #[serde(default)]
    pub duration_overrides: BTreeMap<String, f64>,
    #[serde(default)]
    pub capacity_overrides: BTreeMap<String, u64>,
}
fn error(code: &str, message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}
fn contract_error(error: serde_json::Error) -> ApiError {
    self::error("PLANNING_INPUT_INVALID", error.to_string())
}
pub async fn scenario(
    State(s): State<App>,
    Path(project): Path<String>,
    Json(body): Json<ScenarioRequest>,
) -> ApiResult<Value> {
    let snapshot = s.store.planning_snapshot(&project).await?;
    let stale = match &body.planning_input_digest {
        Some(digest) => snapshot["planning_input_digest"].as_str() != Some(digest.as_str()),
        None => snapshot["revision"].as_u64() != Some(body.input_revision),
    };
    if stale {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "REVISION_CONFLICT",
            "planning facts changed; refresh and compute again",
        ));
    }
    if body.end_at <= body.start_at {
        return Err(error(
            "VALIDATION_ERROR",
            "positive planning window required",
        ));
    }
    if body
        .duration_overrides
        .values()
        .any(|v| !v.is_finite() || *v <= 0.0 || *v > 1_000_000.0)
    {
        return Err(error(
            "VALIDATION_ERROR",
            "scenario duration must be positive finite hours",
        ));
    }
    let windows = if body.availability.is_empty() {
        vec![AvailabilityWindow {
            start_at: body.start_at,
            end_at: body.end_at,
        }]
    } else {
        body.availability.clone()
    };
    if windows
        .iter()
        .any(|w| w.start_at < body.start_at || w.end_at > body.end_at)
    {
        return Err(error(
            "VALIDATION_ERROR",
            "working availability outside planning window",
        ));
    }
    let tasks: Vec<TaskCard> =
        serde_json::from_value(snapshot["tasks"].clone()).map_err(contract_error)?;
    let teams: Vec<Team> =
        serde_json::from_value(snapshot["teams"].clone()).map_err(contract_error)?;
    let policies: Vec<ResourcePolicy> =
        serde_json::from_value(snapshot["resource_policies"].clone()).map_err(contract_error)?;
    if body.worker_scope_id.as_ref().is_some_and(|id| {
        !policies
            .iter()
            .any(|p| &p.scope_id == id && p.worker_id.is_some())
    }) {
        return Err(error(
            "VALIDATION_ERROR",
            "registered Worker resource scope required",
        ));
    }
    let task_ids: BTreeSet<_> = tasks.iter().map(|task| task.task_id.as_str()).collect();
    let task_revisions: BTreeMap<_, _> = tasks
        .iter()
        .map(|task| (task.task_id.as_str(), task.task_revision))
        .collect();
    let selected: BTreeSet<_> = body.task_ids.iter().cloned().collect();
    if selected.len() != body.task_ids.len()
        || selected.iter().any(|id| !task_ids.contains(id.as_str()))
        || body
            .duration_overrides
            .keys()
            .any(|id| !task_ids.contains(id.as_str()))
    {
        return Err(error(
            "VALIDATION_ERROR",
            "unknown or duplicate task selection",
        ));
    }
    let completed: BTreeSet<String> =
        serde_json::from_value(snapshot["completed_task_ids"].clone()).map_err(contract_error)?;
    let mut estimates = BTreeMap::<String, TaskEstimate>::new();
    let mut schedules = BTreeMap::<String, Schedule>::new();
    let mut owners = BTreeMap::<String, forgeflow_planner::OwnerTerritory>::new();
    let mut priorities = BTreeMap::new();
    for document in snapshot["documents"]
        .as_array()
        .ok_or_else(|| error("PLANNING_INPUT_INVALID", "documents missing"))?
    {
        let value = &document["value"];
        match document["collection"].as_str() {
            Some("task_estimates") => {
                let estimate: TaskEstimate =
                    serde_json::from_value(value.clone()).map_err(contract_error)?;
                if task_revisions.get(estimate.task_id.as_str()) == Some(&estimate.task_revision)
                    && estimates
                        .get(&estimate.task_id)
                        .is_none_or(|old| old.estimate_version < estimate.estimate_version)
                {
                    estimates.insert(estimate.task_id.clone(), estimate);
                }
            }
            Some("schedules") => {
                let schedule: Schedule =
                    serde_json::from_value(value.clone()).map_err(contract_error)?;
                if schedules
                    .get(&schedule.task_id)
                    .is_none_or(|old| old.baseline_version < schedule.baseline_version)
                {
                    schedules.insert(schedule.task_id.clone(), schedule);
                }
            }
            Some("owners") => {
                let mut owner = value.clone();
                owner
                    .as_object_mut()
                    .ok_or_else(|| error("PLANNING_INPUT_INVALID", "owner missing"))?
                    .remove("revision");
                let owner: forgeflow_planner::OwnerTerritory =
                    serde_json::from_value(owner).map_err(contract_error)?;
                owners.insert(owner.owner_id.clone(), owner);
            }
            Some("queue_entries") => {
                if let Some(task) = value["task_id"].as_str() {
                    priorities.insert(
                        task.to_string(),
                        value["priority"]
                            .as_i64()
                            .unwrap_or(0)
                            .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                    );
                }
            }
            _ => {}
        }
    }
    if body.capacity_overrides.iter().any(|(id, tier)| {
        !policies.iter().any(|p| &p.scope_id == id) || ![1, 4, 10, 32, 64].contains(tier)
    }) {
        return Err(error(
            "VALIDATION_ERROR",
            "capacity scenario needs a registered scope and active tier 1/4/10/32/64",
        ));
    }
    let mut scopes = Vec::new();
    for policy in &policies {
        let mut allocated = ResourceVector::default();
        if snapshot["resource_limits"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["scope_id"].as_str() == Some(&policy.scope_id))
            .count()
            != 7
        {
            return Err(error(
                "PLANNING_INPUT_INVALID",
                "every resource dimension must have authoritative allocation",
            ));
        }
        for limit in snapshot["resource_limits"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["scope_id"].as_str() == Some(&policy.scope_id))
        {
            let used = limit["allocated"]
                .as_u64()
                .ok_or_else(|| error("PLANNING_INPUT_INVALID", "allocation missing"))?;
            match limit["dimension"].as_str() {
                Some("active_slot") => allocated.active_slot = used,
                Some("coding_slot") => allocated.coding_slot = used,
                Some("cpu_units") => allocated.cpu_units = used,
                Some("memory_bytes") => allocated.memory_bytes = used,
                Some("build_permit") => allocated.build_permit = used,
                Some("gpu_permit") => allocated.gpu_permit = used,
                Some("provider_inflight") => allocated.provider_inflight = used,
                _ => return Err(error("PLANNING_INPUT_INVALID", "unknown dimension")),
            }
        }
        let mut limits = policy.limits.clone();
        if let Some(tier) = body.capacity_overrides.get(&policy.scope_id) {
            limits.active_slot = *tier;
        }
        scopes.push(PlanningScope {
            scope_id: policy.scope_id.clone(),
            limits,
            allocated,
            paused: policy.paused,
        });
    }
    let team_map: BTreeMap<_, _> = teams
        .iter()
        .map(|team| (team.team_id.as_str(), team))
        .collect();
    let mut planned = Vec::new();
    for task in &tasks {
        if completed.contains(&task.task_id)
            || (!selected.is_empty() && !selected.contains(&task.task_id))
        {
            continue;
        }
        let mut lineage = BTreeSet::new();
        let mut cursor = Some(task.team_id.clone());
        let mut valid_lineage = true;
        while let Some(team) = cursor {
            if !lineage.insert(team.clone()) {
                valid_lineage = false;
                break;
            }
            let Some(node) = team_map.get(team.as_str()) else {
                valid_lineage = false;
                break;
            };
            if node.paused {
                valid_lineage = false;
            }
            cursor = node.parent_team_id.clone();
        }
        let owner_root = owners
            .get(&task.owner_id)
            .and_then(|o| o.root_team_id.as_ref());
        if owner_root.is_none_or(|root| !lineage.contains(root)) {
            valid_lineage = false;
        }
        let mut scope_ids = Vec::new();
        for policy in &policies {
            let applicable = if let Some(worker) = &policy.worker_id {
                body.worker_scope_id.as_deref() == Some(&policy.scope_id) && !worker.is_empty()
            } else if policy.project_id.is_none() {
                true
            } else if policy.project_id.as_deref() == Some(&project) {
                policy.team_id.as_ref().is_none_or(|t| lineage.contains(t))
            } else {
                false
            };
            if applicable {
                scope_ids.push(policy.scope_id.clone());
            }
        }
        // Missing required policy layers cannot yield an apparently valid forecast.
        if !policies
            .iter()
            .any(|p| p.project_id.is_none() && p.worker_id.is_none())
            || !policies
                .iter()
                .any(|p| p.project_id.as_deref() == Some(&project) && p.team_id.is_none())
            || lineage.iter().any(|team| {
                !policies.iter().any(|p| {
                    p.project_id.as_deref() == Some(&project) && p.team_id.as_ref() == Some(team)
                })
            })
        {
            valid_lineage = false;
        }
        if !valid_lineage {
            scope_ids.clear();
        }
        let (duration_hours, duration_source) = if let Some(value) =
            body.duration_overrides.get(&task.task_id)
        {
            (Some(*value), "USER_SCENARIO_OVERRIDE")
        } else if let Some(value) = estimates.get(&task.task_id).and_then(|e| e.duration_hours) {
            (Some(value), "REVIEWED_TASK_ESTIMATE")
        } else if let Some(schedule) = schedules.get(&task.task_id) {
            (
                Some(
                    (schedule.planned_end - schedule.planned_start).num_milliseconds() as f64
                        / 3_600_000.0,
                ),
                "CURRENT_PLAN_INTERVAL",
            )
        } else {
            (None, "UNKNOWN")
        };
        planned.push(PlanningTask {
            task_id: task.task_id.clone(),
            owner_id: task.owner_id.clone(),
            team_id: task.team_id.clone(),
            priority: *priorities.get(&task.task_id).unwrap_or(&0),
            dependencies: task.dependencies.clone(),
            duration_hours,
            duration_source: duration_source.into(),
            resource_request: task.resource_request.clone(),
            scope_ids,
        });
    }
    let forecast = tokio::task::spawn_blocking(move || {
        forgeflow_scheduler::planning::forecast(&planned, &scopes, &completed, windows)
    })
    .await
    .map_err(|e| error("PLANNING_FAILED", e.to_string()))?
    .map_err(|e| error("PLANNING_INVALID", e))?;
    Ok(view(
        json!({"forecast":forecast,"input_revision":snapshot["revision"],"requested_revision":body.input_revision,
        "planning_input_digest":snapshot["planning_input_digest"],"input_changed_since_request":snapshot["revision"].as_u64()!=Some(body.input_revision),"as_of":snapshot["as_of"],
        "source":"POSTGRESQL_REPEATABLE_READ","worker_scope_id":body.worker_scope_id,"execution_rights_granted":false,
        "qualification":"PLANNING_PROJECTION_ONLY","capacity_overrides":body.capacity_overrides,"worker_placement":if body.worker_scope_id.is_some(){"EXPLICIT_SCOPE"}else{"UNVERIFIED"}}),
    ))
}
