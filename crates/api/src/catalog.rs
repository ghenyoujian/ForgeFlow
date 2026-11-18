use super::*;
use axum::extract::Query;
use serde::Deserialize;

pub async fn projects(State(s): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    paged(&s, None, "projects", q).await
}
pub async fn project(State(s): State<App>, Path(p): Path<String>) -> ApiResult<Value> {
    Ok(view(s.store.get_project(&p).await?))
}
pub async fn create_project(
    State(s): State<App>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut p): Json<Project>,
) -> ApiResult<Value> {
    if p.project_id.is_empty() {
        p.project_id = generated_id(&headers, &actor)?;
    }
    if let Some((_, workspace)) = actor
        .actor_id
        .strip_prefix("account:")
        .and_then(|v| v.split_once("@workspace:"))
    {
        if !p.root_path.is_empty() {
            return Err(super::workspaces::forbidden(
                "新工作区项目由服务管理仓库，请勿填写服务器本地路径",
            ));
        }
        if p.name.trim().is_empty()
            || p.name.len() > 160
            || uuid::Uuid::parse_str(&p.project_id).is_err()
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "project requires a name and a generated UUID",
            ));
        }
        let target = s
            .data_root
            .join("workspaces")
            .join(workspace)
            .join("repositories")
            .join(format!(
                "{}.git",
                forgeflow_planner::sha256(p.project_id.as_bytes())
            ));
        let copy = target.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            if !copy.exists() {
                forgeflow_git::init_managed_repository(None, &copy).map_err(|e| e.to_string())?;
            }
            let git = |args: &[&str]| -> Result<String, String> {
                let out = std::process::Command::new("/usr/bin/git")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("LANG", "C")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .arg("-C")
                    .arg(&copy)
                    .args(args)
                    .stdin(std::process::Stdio::null())
                    .output()
                    .map_err(|e| e.to_string())?;
                if !out.status.success() {
                    return Err("managed repository initialization failed".into());
                }
                Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            };
            if git(&["rev-parse", "--verify", "refs/heads/main"]).is_err() {
                let tree = git(&["mktree"])?;
                let commit = git(&[
                    "-c",
                    "user.name=ForgeFlow",
                    "-c",
                    "user.email=workspace@localhost",
                    "commit-tree",
                    &tree,
                    "-m",
                    "Initialize workspace project",
                ])?;
                git(&["update-ref", "refs/heads/main", &commit])?;
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "REPOSITORY_CREATE_FAILED",
                "repository initialization interrupted",
            )
        })?
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "REPOSITORY_CREATE_FAILED",
                e,
            )
        })?;
        p.root_path = target.to_string_lossy().into_owned();
        p.authority_mode = AuthorityMode::Managed;
        return command(&s, &headers, &actor, CatalogCommand::CreateProject(p)).await;
    }
    let known_target = s.data_root.join("repositories").join(format!(
        "{}.git",
        forgeflow_planner::sha256(p.project_id.as_bytes())
    ));
    if !std::path::Path::new(&p.root_path).is_dir()
        && !(p.authority_mode == AuthorityMode::Managed && known_target.exists())
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "REPOSITORY_NOT_FOUND",
            "project root_path must exist",
        ));
    }
    if p.authority_mode == AuthorityMode::Managed && known_target.exists() {
        p.root_path = known_target.to_string_lossy().into_owned();
    } else if p.authority_mode == AuthorityMode::Managed {
        let source = PathBuf::from(&p.root_path).canonicalize().map_err(|e| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "REPOSITORY_NOT_FOUND",
                e.to_string(),
            )
        })?;
        let bare = git_read(&source, &["rev-parse", "--is-bare-repository"])? == "true";
        if !bare {
            if !git_read(&source, &["status", "--porcelain"])?.is_empty() {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "REPOSITORY_DIRTY",
                    "commit or preserve source changes before managed import",
                ));
            }
            let directory = s.data_root.join("repositories");
            tokio::fs::create_dir_all(&directory).await.map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "REPOSITORY_CREATE_FAILED",
                    e.to_string(),
                )
            })?;
            let target = directory.join(format!(
                "{}.git",
                forgeflow_planner::sha256(p.project_id.as_bytes())
            ));
            if !target.exists() {
                let source_copy = source.clone();
                let target_copy = target.clone();
                tokio::task::spawn_blocking(move || {
                    forgeflow_git::init_managed_repository(Some(&source_copy), &target_copy)
                })
                .await
                .map_err(|e| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "REPOSITORY_CREATE_FAILED",
                        e.to_string(),
                    )
                })?
                .map_err(|e| {
                    ApiError::new(
                        StatusCode::CONFLICT,
                        "REPOSITORY_CREATE_FAILED",
                        e.to_string(),
                    )
                })?;
            }
            if git_read(&target, &["rev-parse", "--is-bare-repository"])? != "true" {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "REPOSITORY_AUTHORITY_CONFLICT",
                    "managed destination is not a bare Git authority",
                ));
            }
            p.root_path = target.to_string_lossy().into_owned();
        } else {
            p.root_path = source.to_string_lossy().into_owned();
        }
    }
    command(&s, &headers, &actor, CatalogCommand::CreateProject(p)).await
}
#[derive(Deserialize)]
pub struct ProjectUpdate {
    project: Project,
    expected_revision: u64,
}
pub async fn update_project(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ProjectUpdate>,
) -> ApiResult<Value> {
    if p != body.project.project_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "path and project identity differ",
        ));
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::UpdateProject {
            project: body.project,
            expected_revision: body.expected_revision,
        },
    )
    .await
}
pub async fn requirements(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "requirements", q).await
}
pub async fn create_requirement(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut r): Json<Requirement>,
) -> ApiResult<Value> {
    r.project_id = p;
    if r.requirement_id.is_empty() {
        r.requirement_id = generated_id(&headers, &actor)?;
    }
    command(&s, &headers, &actor, CatalogCommand::CreateRequirement(r)).await
}
pub async fn teams(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "teams", q).await
}
pub async fn create_team(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut team): Json<Team>,
) -> ApiResult<Value> {
    team.project_id = p;
    if team.team_id.is_empty() {
        team.team_id = generated_id(&headers, &actor)?;
    }
    command(&s, &headers, &actor, CatalogCommand::CreateTeam(team)).await
}
pub async fn tasks(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "tasks", q).await
}
pub async fn task(State(s): State<App>, Path((p, t)): Path<(String, String)>) -> ApiResult<Value> {
    Ok(view(s.store.get_task(&p, &t).await?))
}
pub async fn flows(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    let collection = if q.view.as_deref() == Some("summary") {
        "flow_summaries"
    } else {
        "flows"
    };
    paged(&s, Some(&p), collection, q).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowParentGuard {
    pub flow_revision: u64,
    pub revision: u64,
    pub source_revision: String,
}
#[derive(Deserialize)]
pub struct FlowWrite {
    flow: FlowRevision,
    expected_revision: Option<u64>,
    context: Option<forgeflow_planner::CompileContext>,
    parent_guard: Option<FlowParentGuard>,
}
pub async fn put_flow(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut body): Json<FlowWrite>,
) -> ApiResult<Value> {
    body.flow.project_id = p.clone();
    if let Some(context) = body.context.take() {
        let authoritative = authoritative_context(&s, &p, context.clone()).await?;
        if body.parent_guard.is_some()
            && (context.source_revision != authoritative.source_revision
                || context.requirement_semantic_digests
                    != authoritative.requirement_semantic_digests
                || serde_json::to_value(&context.requirements).ok()
                    != serde_json::to_value(&authoritative.requirements).ok()
                || serde_json::to_value(&context.owners).ok()
                    != serde_json::to_value(&authoritative.owners).ok()
                || context.current_inputs != authoritative.current_inputs
                || serde_json::to_value(&context.contracts).ok()
                    != serde_json::to_value(&authoritative.contracts).ok())
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "CONTEXT_STALE",
                "reviewed assignment context changed; reload and preview again",
            ));
        }
        body.context = Some(authoritative);
    }
    if body.flow.state == FlowState::Committed {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "USE_FLOW_COMMIT",
            "committed state requires compiled approval command",
        ));
    }
    if let Some(context) = &mut body.context {
        bind_requirement_refs(context, &body.flow.tasks);
        for task in &mut body.flow.tasks {
            if let Some(spec) = context.task_specs.get(&task.task_id) {
                task.input_digest = forgeflow_planner::canonical_task_input_digest(task, spec);
            }
        }
        body.flow.input_digest = forgeflow_planner::semantic_digest(&body.flow, context);
    }
    command(
        &s,
        &headers,
        &actor,
        if let Some(guard) = body.parent_guard {
            CatalogCommand::PutFlowFromParent {
                flow: body.flow,
                expected_revision: body.expected_revision,
                context: serde_json::to_value(body.context.ok_or_else(|| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "CONTEXT_REQUIRED",
                        "reviewed assignment needs context",
                    )
                })?)
                .expect("context serializable"),
                parent_flow_revision: guard.flow_revision,
                parent_expected_revision: guard.revision,
                expected_source_revision: guard.source_revision,
            }
        } else {
            CatalogCommand::PutFlow {
                flow: body.flow,
                expected_revision: body.expected_revision,
                context: body
                    .context
                    .map(|c| serde_json::to_value(c).expect("context serializable")),
            }
        },
    )
    .await
}
fn flow_key(key: &str) -> Result<(String, u64), ApiError> {
    let (p, r) = key.rsplit_once(':').ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_FLOW_ID",
            "flow ID must be project_id:flow_revision",
        )
    })?;
    Ok((
        p.into(),
        r.parse().map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_FLOW_ID",
                "flow_revision must be a number",
            )
        })?,
    ))
}
pub async fn flow(State(s): State<App>, Path(key): Path<String>) -> ApiResult<Value> {
    let (p, r) = flow_key(&key)?;
    Ok(view(s.store.get_flow(&p, r).await?))
}
pub async fn project_flow(
    State(s): State<App>,
    Path((p, r)): Path<(String, u64)>,
) -> ApiResult<Value> {
    Ok(view(s.store.get_flow(&p, r).await?))
}
pub async fn flow_context(State(s): State<App>, Path(key): Path<String>) -> ApiResult<Value> {
    let (p, r) = flow_key(&key)?;
    Ok(view(stored_compile_context(&s, &p, r).await?))
}

pub(crate) async fn stored_compile_context(
    s: &App,
    p: &str,
    r: u64,
) -> Result<forgeflow_planner::CompileContext, ApiError> {
    let value = s
        .store
        .get_document(p, "flow_contexts", &r.to_string())
        .await?;
    let mut value = value.get("value").cloned().unwrap_or(value);
    if let Some(object) = value.as_object_mut() {
        object.remove("revision");
    }
    let context = serde_json::from_value(value).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "COMPILE_CONTEXT_INVALID",
            e.to_string(),
        )
    })?;
    Ok(context)
}
async fn compile_context(
    s: &App,
    p: &str,
    r: u64,
) -> Result<forgeflow_planner::CompileContext, ApiError> {
    let context = stored_compile_context(s, p, r).await?;
    let flow = s.store.get_flow(p, r).await?;
    if flow.state == FlowState::Committed {
        s.store.validate_current_flow_context(p, r).await?;
        return Ok(context);
    }
    let mut context = authoritative_context(s, p, context).await?;
    bind_requirement_refs(&mut context, &flow.tasks);
    Ok(context)
}
pub async fn check_flow(
    State(s): State<App>,
    Path(key): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let identity = identity(&headers, &actor)?;
    let (p, r) = flow_key(&key)?;
    let flow = s.store.get_flow(&p, r).await?;
    let context = compile_context(&s, &p, r).await?;
    let report = forgeflow_planner::compile(&flow, &context);
    let value = serde_json::to_value(&report).expect("check report serializable");
    let receipt = s
        .store
        .execute_command(
            identity,
            CatalogCommand::PutDocument {
                project_id: p,
                collection: "findings".into(),
                id: format!("flow-{r}-{}", generated_id(&headers, &actor)?),
                expected_revision: None,
                value: value.clone(),
            },
        )
        .await?;
    Ok(Json(
        json!({"data":report,"operation_id":receipt.operation_id,"replayed":receipt.replayed}),
    ))
}

/// Check a proposed draft against current authority without persisting any
/// Flow, finding, event, operation or execution identity.
pub async fn check_flow_draft(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut body): Json<FlowWrite>,
) -> ApiResult<Value> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "draft checks require Owner identity",
        ));
    }
    let _identity = identity(&headers, &actor)?;
    if body.flow.project_id != p {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "draft Flow belongs to another project",
        ));
    }
    s.store.get_project(&p).await?;
    let supplied = body.context.take().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "CONTEXT_REQUIRED",
            "draft check requires compile context",
        )
    })?;
    let mut context = authoritative_context(&s, &p, supplied).await?;
    bind_requirement_refs(&mut context, &body.flow.tasks);
    for task in &mut body.flow.tasks {
        if let Some(spec) = context.task_specs.get(&task.task_id) {
            task.input_digest = forgeflow_planner::canonical_task_input_digest(task, spec);
        }
    }
    body.flow.input_digest = forgeflow_planner::semantic_digest(&body.flow, &context);
    context.observed_at = Utc::now().to_rfc3339();
    let parent = if let Some(revision) = body.flow.parent_revision {
        Some(s.store.get_flow(&p, revision).await?)
    } else {
        None
    };
    let previous: std::collections::BTreeMap<_, _> = parent
        .as_ref()
        .into_iter()
        .flat_map(|flow| &flow.tasks)
        .map(|task| (task.task_id.as_str(), task))
        .collect();
    let mut changed: std::collections::BTreeSet<_> = body
        .flow
        .tasks
        .iter()
        .filter(|task| {
            previous.get(task.task_id.as_str()).is_none_or(|old| {
                old.title != task.title
                    || old.owner_id != task.owner_id
                    || old.team_id != task.team_id
                    || old.dependencies != task.dependencies
                    || old.input_digest != task.input_digest
            })
        })
        .map(|task| task.task_id.clone())
        .collect();
    let proposed_ids: std::collections::BTreeSet<_> = body
        .flow
        .tasks
        .iter()
        .map(|task| task.task_id.as_str())
        .collect();
    let removed: Vec<_> = previous
        .keys()
        .filter(|id| !proposed_ids.contains(**id))
        .map(|id| id.to_string())
        .collect();
    changed.extend(removed.iter().cloned());
    let mut successors = std::collections::BTreeMap::<String, Vec<String>>::new();
    for task in body.flow.tasks.iter().chain(
        parent
            .as_ref()
            .into_iter()
            .flat_map(|flow| flow.tasks.iter()),
    ) {
        for dependency in &task.dependencies {
            successors
                .entry(dependency.clone())
                .or_default()
                .push(task.task_id.clone());
        }
    }
    let mut affected = changed.clone();
    let mut pending: Vec<_> = changed.iter().cloned().collect();
    while let Some(id) = pending.pop() {
        for next in successors.get(&id).into_iter().flatten() {
            if affected.insert(next.clone()) {
                pending.push(next.clone());
            }
        }
    }
    let execution = s.store.assignment_context(&p).await?;
    let active: Vec<_> = execution["attempts"].as_array().into_iter().flatten().filter(|attempt| attempt["terminal_at"].is_null() && attempt["task_id"].as_str().is_some_and(|id| affected.contains(id))).map(|attempt| json!({"task_id":attempt["task_id"],"attempt_id":attempt["attempt_id"],"state":attempt["state"]})).collect();
    let policies = s.store.resource_policies(&p).await?;
    let mut resource_findings = Vec::new();
    let team_parents: std::collections::BTreeMap<_, _> = execution["teams"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|team| {
            Some((
                team["team_id"].as_str()?.to_string(),
                team["parent_team_id"].as_str().map(str::to_owned),
            ))
        })
        .collect();
    for task in body
        .flow
        .tasks
        .iter()
        .filter(|task| changed.contains(&task.task_id))
    {
        let mut ancestry = std::collections::BTreeSet::new();
        let mut cursor = Some(task.team_id.clone());
        while let Some(team) = cursor {
            if !ancestry.insert(team.clone()) {
                break;
            }
            cursor = team_parents.get(&team).cloned().flatten();
        }
        for policy in policies.iter().filter(|policy| {
            policy.worker_id.is_none()
                && policy
                    .team_id
                    .as_ref()
                    .is_none_or(|team| ancestry.contains(team))
        }) {
            for ((dimension, demand), (_, limit)) in task
                .resource_request
                .dimensions()
                .into_iter()
                .zip(policy.limits.dimensions())
            {
                if demand > limit {
                    resource_findings.push(json!({"task_id":task.task_id,"scope_id":policy.scope_id,"dimension":dimension,"requested":demand,"limit":limit,"reason":"单项任务需求超过该资源范围上限"}));
                }
            }
        }
    }
    let impact = json!({"removed_task_ids":removed,"changed_task_ids":changed,"affected_task_ids":affected,"active_attempts":active,"resource_findings":resource_findings,"execution_rights_granted":false});
    let flow = body.flow;
    let report = tokio::task::spawn_blocking(move || forgeflow_planner::compile(&flow, &context))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PLANNING_FAILED",
                "planning check interrupted",
            )
        })?;
    let mut report = serde_json::to_value(report).expect("check report serializable");
    report["impact"] = impact;
    Ok(view(report))
}
#[derive(Deserialize)]
pub struct Revision {
    expected_revision: u64,
}
pub async fn commit_flow(
    State(s): State<App>,
    Path(key): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<Revision>,
) -> ApiResult<Value> {
    let (p, r) = flow_key(&key)?;
    let approved_by = actor.actor_id.clone();
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::CommitFlow {
            project_id: p,
            flow_revision: r,
            expected_revision: body.expected_revision,
            approved_by,
        },
    )
    .await
}

pub async fn attempts(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "attempts", q).await
}
#[derive(Deserialize)]
pub struct ProjectQuery {
    project_id: Option<String>,
    worker_id: Option<String>,
}
pub async fn attempt(
    State(s): State<App>,
    Path(a): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ProjectQuery>,
) -> ApiResult<Value> {
    let project = q.project_id.or_else(|| {
        if actor.worker {
            actor.project_id.clone()
        } else {
            None
        }
    });
    if actor.worker {
        s.auth
            .worker_scope(&actor, q.worker_id.as_deref(), project.as_deref())
            .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    }
    let p = resolve_attempt_project(&s, &a, project).await?;
    let attempt = crate::workers::authorized_attempt(&s, &actor, &p, &a).await?;
    if actor.worker {
        let worker = q.worker_id.ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "WORKER_SCOPE_REQUIRED",
                "worker_id query is required for scoped attempt read",
            )
        })?;
        s.auth
            .worker_scope(&actor, Some(&worker), Some(&p))
            .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
        if attempt.worker_id != worker {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "WORKER_SCOPE_DENIED",
                "attempt is assigned to another worker",
            ));
        }
    }
    Ok(view(attempt))
}

#[derive(Deserialize)]
pub struct CancelBody {
    project_id: String,
    expected_revision: u64,
    reason: String,
}
pub async fn cancel(
    State(s): State<App>,
    Path(a): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<CancelBody>,
) -> ApiResult<Value> {
    let i = identity(&headers, &actor)?;
    let receipt = s
        .store
        .cancel(CancelRequest {
            actor_id: i.actor_id,
            idempotency_key: i.idempotency_key,
            project_id: body.project_id,
            attempt_id: a,
            expected_revision: body.expected_revision,
            reason: body.reason,
        })
        .await?;
    Ok(view(receipt))
}
pub async fn admit(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut body): Json<AdmissionRequest>,
) -> ApiResult<Value> {
    let i = identity(&headers, &actor)?;
    body.project_id = p;
    body.actor_id = i.actor_id;
    body.idempotency_key = i.idempotency_key;
    Ok(view(s.store.admit(body).await?))
}
pub async fn evidence(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "evidence", q).await
}
pub async fn record_evidence(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut receipt): Json<EvidenceReceipt>,
) -> ApiResult<Value> {
    identity(&headers, &actor)?;
    receipt.project_id = p;
    s.store.record_evidence(receipt.clone()).await?;
    Ok(view(receipt))
}
pub async fn resources(State(s): State<App>, Path(p): Path<String>) -> ApiResult<Value> {
    Ok(view(s.store.resource_policies(&p).await?))
}
#[derive(Deserialize)]
pub struct PolicyWrite {
    policy: ResourcePolicy,
    expected_revision: Option<u64>,
}
pub async fn put_policy(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut body): Json<PolicyWrite>,
) -> ApiResult<Value> {
    body.policy.project_id = Some(p);
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutResourcePolicy {
            policy: body.policy,
            expected_revision: body.expected_revision,
        },
    )
    .await
}
pub async fn documents(
    State(s): State<App>,
    Path((p, c)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), &format!("documents:{c}"), q).await
}
pub async fn document(
    State(s): State<App>,
    Path((p, c, id)): Path<(String, String, String)>,
) -> ApiResult<Value> {
    Ok(view(s.store.get_document(&p, &c, &id).await?))
}
#[derive(Deserialize)]
pub struct DocumentWrite {
    pub id: String,
    pub expected_revision: Option<u64>,
    pub value: Value,
}
pub async fn put_document(
    State(s): State<App>,
    Path((p, c)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<DocumentWrite>,
) -> ApiResult<Value> {
    if c == "planning_catalogs" {
        let catalog: PlanningCatalogRegistration =
            serde_json::from_value(body.value).map_err(|e| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "PLANNING_CATALOG_INVALID",
                    e.to_string(),
                )
            })?;
        if catalog.catalog_id != body.id {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "IDENTITY_MISMATCH",
                "document and planning catalog identities differ",
            ));
        }
        return command(
            &s,
            &headers,
            &actor,
            CatalogCommand::RegisterPlanningCatalog {
                project_id: p,
                expected_revision: body.expected_revision,
                catalog,
            },
        )
        .await;
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutDocument {
            project_id: p,
            collection: c,
            id: body.id,
            expected_revision: body.expected_revision,
            value: body.value,
        },
    )
    .await
}
macro_rules! document_routes {
    ($get:ident,$post:ident,$collection:literal) => {
        pub async fn $get(
            State(s): State<App>,
            Path(p): Path<String>,
            Query(q): Query<ListQuery>,
        ) -> ApiResult<Value> {
            paged(&s, Some(&p), concat!("documents:", $collection), q).await
        }
        pub async fn $post(
            State(s): State<App>,
            Path(p): Path<String>,
            Extension(actor): Extension<Principal>,
            headers: HeaderMap,
            Json(body): Json<DocumentWrite>,
        ) -> ApiResult<Value> {
            command(
                &s,
                &headers,
                &actor,
                CatalogCommand::PutDocument {
                    project_id: p,
                    collection: $collection.into(),
                    id: body.id,
                    expected_revision: body.expected_revision,
                    value: body.value,
                },
            )
            .await
        }
    };
}
document_routes!(sources, put_source, "sources");
document_routes!(contracts, put_contract_document, "contracts");
document_routes!(milestones, put_milestone, "milestones");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MilestoneAcceptanceRequest {
    pub expected_revision: u64,
    pub baseline_version: u64,
}
pub async fn accept_milestone(
    State(s): State<App>,
    Path((project_id, milestone_id)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<MilestoneAcceptanceRequest>,
) -> ApiResult<Value> {
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::AcceptMilestone {
            project_id,
            milestone_id,
            expected_revision: body.expected_revision,
            baseline_version: body.baseline_version,
        },
    )
    .await
}
document_routes!(schedule, put_schedule, "schedules");
pub async fn findings(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "documents:findings", q).await
}
pub async fn portfolio(State(s): State<App>) -> ApiResult<Value> {
    Ok(view(s.store.portfolio_overview().await?))
}

pub async fn all_resources(State(s): State<App>) -> ApiResult<Value> {
    let overview = s.store.resource_overview().await?;
    Ok(view(overview["data"]["policies"].clone()))
}

pub async fn resolve_attempt_project(
    s: &App,
    a: &str,
    p: Option<String>,
) -> Result<String, ApiError> {
    if let Some(p) = p {
        return Ok(p);
    }
    for p in s.store.list_projects().await? {
        if s.store.get_attempt(&p.project_id, a).await.is_ok() {
            return Ok(p.project_id);
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "ATTEMPT_NOT_FOUND",
        "attempt not found",
    ))
}
#[derive(Deserialize)]
pub struct RequirementUpdate {
    requirement: Requirement,
    expected_revision: u64,
}
pub async fn update_requirement(
    State(s): State<App>,
    Path((project, requirement)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<RequirementUpdate>,
) -> ApiResult<Value> {
    if body.requirement.project_id != project || body.requirement.requirement_id != requirement {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "requirement path/body differ",
        ));
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::UpdateRequirement {
            requirement: body.requirement,
            expected_revision: body.expected_revision,
        },
    )
    .await
}

fn generated_id(headers: &HeaderMap, actor: &Principal) -> Result<String, ApiError> {
    let identity = identity(headers, actor)?;
    Ok(forgeflow_planner::sha256(
        format!("{}:{}", identity.actor_id, identity.idempotency_key).as_bytes(),
    )[..32]
        .to_string())
}
#[derive(Deserialize)]
pub struct SourceImport {
    name: String,
    format: forgeflow_planner::RequirementFormat,
    content: String,
}
pub async fn import_source(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<SourceImport>,
) -> ApiResult<Value> {
    let source_id = generated_id(&headers, &actor)?;
    let mut parsed =
        forgeflow_planner::normalize_requirements(&source_id, &body.content, body.format).map_err(
            |error| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "SOURCE_PARSE_FAILED",
                    error.to_string(),
                )
            },
        )?;
    for requirement in &mut parsed.requirements {
        requirement.source_document = source_id.clone();
        if matches!(body.format, forgeflow_planner::RequirementFormat::Markdown) {
            requirement.requirement_id = format!("{source_id}:{}", requirement.requirement_id);
        }
    }
    let requirements = parsed
        .requirements
        .iter()
        .map(|r| Requirement {
            project_id: project.clone(),
            requirement_id: r.requirement_id.clone(),
            title: r.acceptance.clone(),
            source_anchor: format!("{}#{}", source_id, r.anchor),
            outcome: r.acceptance.clone(),
            scope: "imported requirement; refine before admission".into(),
            acceptance: vec![r.acceptance.clone()],
            priority: r.priority,
            weight: 1,
            deferred_reason: r.deferred_reason.clone(),
            revision: 1,
        })
        .collect();
    let source = json!({"source_id":source_id,"name":body.name,"format":body.format,"utf8_bytes":body.content.len(),"requirement_count":parsed.requirements.len(),"content":body.content,"raw_sha256":parsed.raw_sha256,"semantic_sha256":parsed.semantic_sha256,"requirements":parsed.requirements});
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::ImportRequirements {
            project_id: project,
            source_id,
            source,
            requirements,
        },
    )
    .await
}
pub async fn get_source(
    State(s): State<App>,
    Path((p, id)): Path<(String, String)>,
) -> ApiResult<Value> {
    Ok(view(s.store.get_document(&p, "sources", &id).await?))
}

pub async fn put_contract(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(mut body): Json<DocumentWrite>,
) -> ApiResult<Value> {
    if body.value.get("frozen").and_then(Value::as_bool) == Some(true)
        || body.value.get("state").and_then(Value::as_str) == Some("FROZEN")
        || body
            .value
            .get("passing_consumers")
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty())
        || ["independent_receipt_id", "integration_receipt_id"]
            .iter()
            .any(|k| body.value.get(*k).is_some_and(|v| !v.is_null()))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "CONTRACT_RECEIPTS_REQUIRED",
            "freeze and consumer verification are derived from independent durable evidence",
        ));
    }
    if let Some(schema) = body.value.get("schema") {
        let hash =
            forgeflow_planner::sha256(&serde_json::to_vec(schema).expect("schema serializable"));
        body.value["spec_sha256"] = hash.into();
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutDocument {
            project_id: p,
            collection: "contracts".into(),
            id: body.id,
            expected_revision: body.expected_revision,
            value: body.value,
        },
    )
    .await
}
pub async fn snapshot(State(s): State<App>, Path(p): Path<String>) -> ApiResult<Value> {
    let snapshot = s.store.snapshot(&p).await?;
    Ok(Json(
        json!({"read_model_version":snapshot["revision"],"observed_at":snapshot["as_of"],"source":"postgres","data":snapshot,"next_cursor":null}),
    ))
}
pub async fn owner_territories(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "documents:owners", q).await
}
pub async fn put_owner(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<DocumentWrite>,
) -> ApiResult<Value> {
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutDocument {
            project_id: p,
            collection: "owners".into(),
            id: body.id,
            expected_revision: body.expected_revision,
            value: body.value,
        },
    )
    .await
}
#[derive(Deserialize)]
pub struct QueueRequest {
    task_id: String,
    expected_revision: u64,
    #[serde(default)]
    worker_id: String,
    #[serde(default)]
    worker_scope_id: String,
    #[serde(default)]
    scope_ids: Vec<String>,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_lease")]
    lease_seconds: u32,
}
fn default_lease() -> u32 {
    30
}
pub async fn enqueue(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<QueueRequest>,
) -> ApiResult<Value> {
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::EnqueueTask {
            project_id: p,
            task_id: body.task_id,
            expected_revision: body.expected_revision,
            worker_id: body.worker_id,
            priority: body.priority,
            lease_seconds: body.lease_seconds,
            worker_scope_id: body.worker_scope_id,
            scope_ids: body.scope_ids,
        },
    )
    .await
}

pub async fn queue_entries(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "documents:queue_entries", q).await
}
#[derive(Deserialize)]
pub struct ArtifactWrite {
    content_utf8: String,
    kind: String,
}
pub async fn create_artifact(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ArtifactWrite>,
) -> ApiResult<Value> {
    identity(&headers, &actor)?;
    let digest = forgeflow_planner::sha256(body.content_utf8.as_bytes());
    let id = format!("artifact-{digest}");
    let path = s.data_root.join("artifacts").join(&id);
    if !path.exists() {
        let temporary = s
            .data_root
            .join("artifacts")
            .join(format!(".{id}.{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&temporary, body.content_utf8.as_bytes())
            .await
            .map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ARTIFACT_WRITE_FAILED",
                    e.to_string(),
                )
            })?;
        tokio::fs::rename(temporary, &path).await.map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ARTIFACT_WRITE_FAILED",
                e.to_string(),
            )
        })?;
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutArtifact {
            project_id: p,
            id,
            path: path.to_string_lossy().into_owned(),
            sha256: digest,
            kind: body.kind,
            bytes: body.content_utf8.len() as u64,
        },
    )
    .await
}
#[derive(Deserialize)]
pub struct InputSnapshots {
    paths: Vec<String>,
}
pub async fn input_snapshots(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<InputSnapshots>,
) -> ApiResult<Value> {
    let i = identity(&headers, &actor)?;
    if body.paths.len() > 256 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "INPUT_LIMIT",
            "at most 256 snapshot paths per request",
        ));
    }
    let project = s.store.get_project(&p).await?;
    let root = PathBuf::from(&project.root_path)
        .canonicalize()
        .map_err(|e| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "REPOSITORY_NOT_FOUND",
                e.to_string(),
            )
        })?;
    let mut snapshots = Vec::new();
    for relative in body.paths {
        let path = std::path::Path::new(&relative);
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "PATH_TRAVERSAL",
                "snapshot path must be relative and normalized",
            ));
        }
        let path = root
            .join(path)
            .canonicalize()
            .map_err(|e| ApiError::new(StatusCode::NOT_FOUND, "INPUT_NOT_FOUND", e.to_string()))?;
        if !path.starts_with(&root) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "PATH_TRAVERSAL",
                "snapshot path resolves outside project",
            ));
        }
        let bytes = tokio::fs::read(&path).await.map_err(|e| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "INPUT_READ_FAILED",
                e.to_string(),
            )
        })?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "INPUT_TOO_LARGE",
                "snapshot input exceeds 32 MiB",
            ));
        }
        let digest = forgeflow_planner::sha256(&bytes);
        snapshots.push(json!({"sha256":digest,"bytes":bytes.len(),"path":relative,"absolute_path":path,"relative_path":relative}));
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::RegisterInputSnapshots {
            project_id: p,
            snapshots,
        },
    )
    .await
}
#[derive(Deserialize)]
pub struct FreezeRequest {
    project_id: String,
    version: u64,
    expected_revision: u64,
    producer_receipt_id: String,
    consumer_receipt_ids: Vec<String>,
}
pub async fn freeze_contract(
    State(s): State<App>,
    Path(contract): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<FreezeRequest>,
) -> ApiResult<Value> {
    let i = identity(&headers, &actor)?;
    Ok(view(
        s.store
            .freeze_contract(FreezeContractRequest {
                actor_id: i.actor_id,
                idempotency_key: i.idempotency_key,
                project_id: body.project_id,
                contract_id: contract,
                version: body.version,
                expected_revision: body.expected_revision,
                producer_receipt_id: body.producer_receipt_id,
                consumer_receipt_ids: body.consumer_receipt_ids,
            })
            .await?,
    ))
}
pub async fn put_global_policy(
    State(s): State<App>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<PolicyWrite>,
) -> ApiResult<Value> {
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutResourcePolicy {
            policy: body.policy,
            expected_revision: body.expected_revision,
        },
    )
    .await
}

pub(crate) async fn authoritative_context(
    s: &App,
    p: &str,
    mut context: forgeflow_planner::CompileContext,
) -> Result<forgeflow_planner::CompileContext, ApiError> {
    let requirements = s.store.list_requirements(p).await?;
    context.requirement_semantic_digests = requirements
        .iter()
        .map(|r| {
            (
                r.requirement_id.clone(),
                forgeflow_planner::requirement_semantic_digest(r),
            )
        })
        .collect();
    context.requirements = requirements
        .iter()
        .map(|r| {
            let (source, anchor) = r
                .source_anchor
                .split_once('#')
                .unwrap_or(("manual", r.source_anchor.as_str()));
            forgeflow_planner::Requirement {
                requirement_id: r.requirement_id.clone(),
                source_document: source.into(),
                anchor: anchor.into(),
                acceptance: r.acceptance.join("\n"),
                priority: r.priority,
                deferred_reason: r.deferred_reason.clone(),
            }
        })
        .collect();
    context.owners = s
        .store
        .list_documents(p, "owners")
        .await?
        .into_iter()
        .map(|mut value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("revision");
            }
            serde_json::from_value(value).map_err(|e| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "OWNER_TERRITORY_INVALID",
                    e.to_string(),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    context.current_inputs.clear();
    for snapshot in s.store.list_documents(p, "input_snapshots").await? {
        if let (Some(path), Some(hash)) = (
            snapshot.get("relative_path").and_then(Value::as_str),
            snapshot.get("sha256").and_then(Value::as_str),
        ) {
            context.current_inputs.insert(path.into(), hash.into());
        }
    }
    context.contracts.clear();
    for c in s.store.list_documents(p, "contract_versions").await? {
        context.contracts.push(forgeflow_planner::ContractSnapshot {
            contract_id: c
                .get("contract_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            version: c.get("version").and_then(Value::as_u64).unwrap_or(0),
            spec_sha256: c
                .get("spec_sha256")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            source_sha256: c
                .get("source_sha256")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            frozen: c.get("frozen").and_then(Value::as_bool).unwrap_or(false),
            required_consumers: serde_json::from_value(
                c.get("required_consumers").cloned().unwrap_or(json!([])),
            )
            .unwrap_or_default(),
            passing_consumers: serde_json::from_value(
                c.get("passing_consumers").cloned().unwrap_or(json!([])),
            )
            .unwrap_or_default(),
            independent_receipt_id: c
                .get("independent_receipt_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            integration_receipt_id: c
                .get("integration_receipt_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    context.source_revision = forgeflow_planner::sha256(
        &serde_json::to_vec(&requirements).expect("requirements serializable"),
    );
    context.observed_at = String::new();
    Ok(context)
}
pub async fn resource_usage(State(s): State<App>) -> ApiResult<Value> {
    let mut overview = s.store.resource_overview().await?;
    let memory = tokio::fs::read_to_string("/proc/meminfo").await.ok();
    let bytes = |name: &str| {
        memory.as_deref().and_then(|text| {
            text.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key != name {
                    return None;
                }
                value
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()?
                    .checked_mul(1024)
            })
        })
    };
    overview["data"]["host_memory"] = json!({"total_bytes":bytes("MemTotal"),"available_bytes":bytes("MemAvailable"),"source":if memory.is_some(){"PROC_MEMINFO"}else{"UNAVAILABLE"},"observed_at":Utc::now()});
    Ok(Json(overview))
}

#[derive(Deserialize)]
pub struct TeamUpdate {
    team: Team,
    expected_revision: u64,
}
pub async fn update_team(
    State(s): State<App>,
    Path((p, t)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<TeamUpdate>,
) -> ApiResult<Value> {
    if body.team.project_id != p || body.team.team_id != t {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "team path/body differ",
        ));
    }
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::UpdateTeam {
            team: body.team,
            expected_revision: body.expected_revision,
        },
    )
    .await
}
pub async fn executors(State(s): State<App>) -> ApiResult<Value> {
    let mut values = Vec::new();
    for project in s.store.list_projects().await? {
        for profile in s
            .store
            .list_documents(&project.project_id, "executor_profiles")
            .await?
        {
            values.push(json!({"project_id":project.project_id,"profile":profile,"qualification":"INCONCLUSIVE"}));
        }
    }
    Ok(view(values))
}
#[derive(Deserialize)]
pub struct ExecutorProbe {
    project_id: String,
}
pub async fn probe_executor(
    State(s): State<App>,
    Path(id): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ExecutorProbe>,
) -> ApiResult<Value> {
    let mut doc = s
        .store
        .get_document(&body.project_id, "executor_profiles", &id)
        .await?;
    if let Some(object) = doc.as_object_mut() {
        object.remove("revision");
    }
    let profile: forgeflow_executors::HeadlessProfile =
        serde_json::from_value(doc).map_err(|e| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "EXECUTOR_PROFILE_INVALID",
                e.to_string(),
            )
        })?;
    let project = s.store.get_project(&body.project_id).await?;
    let report = forgeflow_executors::doctor(&profile, std::path::Path::new(&project.root_path))
        .map_err(|e| ApiError::new(StatusCode::CONFLICT, "EXECUTOR_UNQUALIFIED", e.to_string()))?;
    let operation_id = generated_id(&headers, &actor)?;
    command(&s,&headers,&actor,CatalogCommand::PutDocument{project_id:body.project_id,collection:"operations".into(),id:operation_id.clone(),expected_revision:None,value:json!({"operation_id":operation_id,"kind":"EXECUTOR_DOCTOR","status":"SUCCEEDED","executor_profile_id":id,"qualification":"INCONCLUSIVE","report":report})}).await
}

pub async fn integration_queue(State(s): State<App>, Path(p): Path<String>) -> ApiResult<Value> {
    Ok(view(s.store.pending_merges(&p, "refs/heads/main").await?))
}

#[derive(Deserialize)]
pub struct RepositoryProbe {
    root_path: String,
}
pub async fn probe_repository(Json(body): Json<RepositoryProbe>) -> ApiResult<Value> {
    let root = PathBuf::from(body.root_path);
    if !root.is_absolute() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "REPOSITORY_PATH_INVALID",
            "repository path must be absolute",
        ));
    }
    if !root.is_dir() {
        return Ok(view(
            json!({"root_path":root,"exists":false,"git_repository":false,"head":null,"dirty":null}),
        ));
    }
    let bare = git_read(&root, &["rev-parse", "--is-bare-repository"]);
    if bare.is_err() {
        return Ok(view(
            json!({"root_path":root,"exists":true,"git_repository":false,"head":null,"dirty":null}),
        ));
    }
    let bare = bare? == "true";
    let head = git_read(&root, &["rev-parse", "HEAD"]).ok();
    let main = git_read(&root, &["rev-parse", "refs/heads/main"]).ok();
    let branch = git_read(&root, &["symbolic-ref", "--short", "HEAD"]).ok();
    let dirty = if bare {
        Some(false)
    } else {
        git_read(&root, &["status", "--porcelain"])
            .ok()
            .map(|s| !s.is_empty())
    };
    Ok(view(
        json!({"root_path":root,"exists":true,"git_repository":true,"bare":bare,"head":head,"main_sha":main,"branch":branch,"dirty":dirty,"managed_import":"separate bare authority; source checkout preserved"}),
    ))
}
fn git_read(root: &std::path::Path, args: &[&str]) -> Result<String, ApiError> {
    use forgeflow_git::safe_probe::{ProbeQuery, read};
    let query = match args {
        ["rev-parse", "--is-bare-repository"] => ProbeQuery::Bare,
        ["rev-parse", "HEAD"] => ProbeQuery::Head,
        ["rev-parse", "refs/heads/main"] => ProbeQuery::Main,
        ["symbolic-ref", "--short", "HEAD"] => ProbeQuery::Branch,
        ["status", "--porcelain"] => ProbeQuery::Dirty,
        _ => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "GIT_PROBE_FAILED",
                "requested repository query is not allowlisted",
            ));
        }
    };
    read(root, query).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "GIT_PROBE_FAILED",
            "requested repository fact could not be read safely",
        )
    })
}

#[cfg(test)]
mod safe_git_probe_tests {
    use super::git_read;

    #[test]
    fn repository_probe_wrapper_rejects_commands_outside_the_fact_allowlist() {
        for args in [
            vec!["config", "--list"],
            vec!["status", "--porcelain", "--ignored"],
            vec!["rev-parse", "--git-dir"],
            vec!["rev-parse", "-h"],
            vec!["init"],
        ] {
            assert!(git_read(std::path::Path::new("/"), &args).is_err());
        }
    }
}
#[derive(Deserialize)]
pub struct QueueGlobal {
    project_id: String,
    #[serde(flatten)]
    request: QueueRequest,
}
pub async fn enqueue_global(
    State(s): State<App>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<QueueGlobal>,
) -> ApiResult<Value> {
    enqueue(
        State(s),
        Path(body.project_id),
        Extension(actor),
        headers,
        Json(body.request),
    )
    .await
}
pub async fn resolve_task(s: &App, id: &str) -> Result<TaskCard, ApiError> {
    let mut found = None;
    for project in s.store.list_projects().await? {
        if let Ok(task) = s.store.get_task(&project.project_id, id).await {
            if found.is_some() {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "PROJECT_SCOPE_REQUIRED",
                    "task identity exists in multiple projects; use project-scoped route",
                ));
            }
            found = Some(task);
        }
    }
    if let Some(task) = found {
        return Ok(task);
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "TASK_NOT_FOUND",
        "task not found",
    ))
}
#[derive(Deserialize)]
pub struct AdmissionScope {
    project_id: Option<String>,
}
pub async fn admission_checks(
    State(s): State<App>,
    Path(id): Path<String>,
    Json(body): Json<AdmissionScope>,
) -> ApiResult<Value> {
    let task = if let Some(p) = body.project_id {
        s.store.get_task(&p, &id).await?
    } else {
        resolve_task(&s, &id).await?
    };
    admission_check(&s, &task.project_id, &id).await
}
pub async fn scoped_admission_checks(
    State(s): State<App>,
    Path((p, id)): Path<(String, String)>,
) -> ApiResult<Value> {
    admission_check(&s, &p, &id).await
}
async fn admission_check(s: &App, p: &str, id: &str) -> ApiResult<Value> {
    let decision = forgeflow_scheduler::preview_task(&s.store, p, id)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::CONFLICT,
                "ADMISSION_CHECK_FAILED",
                e.to_string(),
            )
        })?;
    let allowed = decision
        .selected_tasks
        .iter()
        .any(|t| t.project_id == p && t.task_id == id);
    Ok(Json(
        json!({"data":{"task_id":id,"project_id":p,"allowed":allowed,"blockers":decision.blocked,"decision":decision,"dry_run":true,"reservations_created":false},"read_model_version":s.store.project_cursor(p).await?,"observed_at":Utc::now(),"source":"postgres"}),
    ))
}

#[derive(Deserialize)]
pub struct RetryRequest {
    project_id: String,
    expected_revision: u64,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    worker_id: String,
}
pub async fn retry(
    State(s): State<App>,
    Path(task): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<RetryRequest>,
) -> ApiResult<Value> {
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::EnqueueTask {
            project_id: body.project_id,
            task_id: task,
            expected_revision: body.expected_revision,
            worker_id: body.worker_id,
            priority: body.priority,
            lease_seconds: 30,
            worker_scope_id: String::new(),
            scope_ids: vec![],
        },
    )
    .await
}
#[derive(Deserialize)]
pub struct QueuePriority {
    priority: i32,
    expected_revision: u64,
}
pub async fn queue_priority(
    State(s): State<App>,
    Path((p, t)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<QueuePriority>,
) -> ApiResult<Value> {
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::ChangeQueuePriority {
            project_id: p,
            task_id: t,
            priority: body.priority,
            expected_revision: body.expected_revision,
        },
    )
    .await
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    view: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}
async fn paged(s: &App, p: Option<&str>, collection: &str, q: ListQuery) -> ApiResult<Value> {
    let before = if let Some(p) = p {
        Some(s.store.project_cursor(p).await?)
    } else {
        None
    };
    let page = s
        .store
        .paginated_catalog(p, collection, q.cursor.as_deref(), q.limit.unwrap_or(100))
        .await?;
    let after = if let Some(p) = p {
        Some(s.store.project_cursor(p).await?)
    } else {
        None
    };
    let stable = before == after;
    let projection_hash =
        forgeflow_planner::sha256(&serde_json::to_vec(&page.items).expect("page serializable"));
    Ok(Json(
        json!({"data":page.items,"read_model_version":if stable{after}else{None},"observed_at":Utc::now(),"source":"postgres","next_cursor":page.next_cursor,"projection_hash":projection_hash,"consistent_project_cursor":p.is_some()&&stable}),
    ))
}
#[derive(Deserialize)]
pub struct ContractVersionWrite {
    contract_id: String,
    version: u64,
    schema: Value,
    producer_task_id: String,
    #[serde(default)]
    source_sha256: String,
    #[serde(default)]
    required_consumers: Vec<String>,
    expected_revision: Option<u64>,
}
pub async fn contract_versions(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    paged(&s, Some(&p), "documents:contract_versions", q).await
}
pub async fn put_contract_version(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ContractVersionWrite>,
) -> ApiResult<Value> {
    if body.version == 0 || body.contract_id.is_empty() || body.producer_task_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CONTRACT_IDENTITY_REQUIRED",
            "contract/version/producer identity required",
        ));
    }
    let schema_hash =
        forgeflow_planner::sha256(&serde_json::to_vec(&body.schema).expect("schema serializable"));
    let id = format!("{}:{}", body.contract_id, body.version);
    let value = json!({"project_id":p,"contract_id":body.contract_id,"version":body.version,"spec_sha256":schema_hash,"source_sha256":body.source_sha256,"producer_task_id":body.producer_task_id,"required_consumers":body.required_consumers,"passing_consumers":[],"independent_receipt_id":null,"integration_receipt_id":null,"frozen":false,"revision":body.expected_revision.unwrap_or(0)+1,"schema":body.schema});
    command(
        &s,
        &headers,
        &actor,
        CatalogCommand::PutDocument {
            project_id: p,
            collection: "contract_versions".into(),
            id,
            expected_revision: body.expected_revision,
            value,
        },
    )
    .await
}
pub async fn latest_flow(
    State(s): State<App>,
    Path(p): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    let flow = s
        .store
        .latest_flow_view(&p, q.view.as_deref() == Some("summary"))
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "FLOW_NOT_FOUND",
                "project has no Flow revisions",
            )
        })?;
    Ok(view(flow))
}

pub async fn event_cursor(State(s): State<App>, Path(p): Path<String>) -> ApiResult<Value> {
    let cursor = s.store.project_cursor(&p).await?;
    Ok(Json(
        json!({"data":{"project_id":p,"cursor":cursor},"read_model_version":cursor,"observed_at":Utc::now(),"source":"postgres"}),
    ))
}

pub(crate) fn bind_requirement_refs(
    context: &mut forgeflow_planner::CompileContext,
    tasks: &[TaskCard],
) {
    for task in tasks {
        if let Some(spec) = context.task_specs.get_mut(&task.task_id) {
            spec.requirement_digest_refs = task
                .requirement_ids
                .iter()
                .filter_map(|id| {
                    context
                        .requirement_semantic_digests
                        .get(id)
                        .map(|hash| (id.clone(), hash.clone()))
                })
                .collect();
        }
    }
}
pub async fn current_flow_context(
    State(s): State<App>,
    Path(key): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Value> {
    let (p, r) = flow_key(&key)?;
    let context = if q.view.as_deref() == Some("summary") {
        serde_json::from_value(s.store.planning_context_metadata(&p, r).await?).map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "COMPILE_CONTEXT_INVALID",
                "stored context metadata is invalid",
            )
        })?
    } else {
        stored_compile_context(&s, &p, r).await?
    };
    Ok(view(authoritative_context(&s, &p, context).await?))
}
