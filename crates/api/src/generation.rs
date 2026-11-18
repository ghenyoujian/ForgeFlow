//! Real planning operations are queued read-only DSH attempts, then independently validated.
use super::*;
use forgeflow_planner::{DraftRequest, InputBinding};
use serde::Deserialize;
const PLANNING_MAX_MODEL_REQUESTS: u32 = 8;
const PLANNING_INTENT_SCHEMA: &str = "forgeflow.planning-intent.v1";
// Match the existing strict model-proposal parser's finite task denominator.
const PLANNING_MAX_PROPOSAL_TASKS: usize = 10_000;
const PLANNING_MAX_FINAL_BYTES: usize = 32 * 1024 * 1024;

/// Model-authored planning meaning. Authority and repeated source facts are
/// supplied by the controller, then checked by the existing proposal parser.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningIntent {
    schema_version: String,
    tasks: Vec<PlanningTaskIntent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningDependencyIntent {
    task_id: String,
    kind: forgeflow_planner::DependencyKind,
    binding_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningTaskIntent {
    task_id: String,
    title: String,
    requirement_ids: Vec<String>,
    outcome: String,
    read_set: Vec<String>,
    write_set: Vec<String>,
    dependencies: Vec<PlanningDependencyIntent>,
    resource_request: ResourceVector,
    verification_case_count: u64,
    rollback_plan: String,
    #[serde(default)]
    contract_produces: Vec<forgeflow_planner::ContractBinding>,
    #[serde(default)]
    contract_consumes: Vec<forgeflow_planner::ContractBinding>,
    #[serde(default)]
    producer_inputs: Vec<forgeflow_planner::DraftProducerInputProposal>,
    #[serde(default)]
    known_unknowns: Vec<String>,
    #[serde(default)]
    not_proven: Vec<String>,
}

#[derive(Serialize)]
struct PlanningAuthority<'a> {
    schema_version: &'static str,
    proposal_schema_version: &'static str,
    max_tasks: usize,
    source_input: &'a InputBinding,
    current_inputs: &'a std::collections::BTreeMap<String, String>,
    requirement_semantic_digests: &'a std::collections::BTreeMap<String, String>,
    owners: &'a [forgeflow_planner::OwnerTerritory],
    resolved_paths: &'a std::collections::BTreeMap<String, String>,
    contracts: &'a [forgeflow_planner::ContractSnapshot],
    resources: &'a PlanningResourceAuthority,
}

#[derive(Clone, Serialize)]
struct PlanningResourceAuthority {
    scope: &'static str,
    scopes: Vec<ResourcePolicy>,
    effective_limits: ResourceVector,
}

fn planning_authority<'a>(
    source_input: &'a InputBinding,
    context: &'a forgeflow_planner::CompileContext,
    resources: &'a PlanningResourceAuthority,
) -> PlanningAuthority<'a> {
    PlanningAuthority {
        schema_version: "forgeflow.planning-authority.v1",
        proposal_schema_version: PLANNING_INTENT_SCHEMA,
        max_tasks: PLANNING_MAX_PROPOSAL_TASKS,
        source_input,
        current_inputs: &context.current_inputs,
        requirement_semantic_digests: &context.requirement_semantic_digests,
        owners: &context.owners,
        resolved_paths: &context.resolved_paths,
        contracts: &context.contracts,
        resources,
    }
}

fn planning_resource_authority(
    request: &DraftRequest,
    context: &forgeflow_planner::CompileContext,
    teams: &[Team],
    policies: Vec<ResourcePolicy>,
) -> Result<PlanningResourceAuthority, ApiError> {
    let mut lineage = std::collections::BTreeSet::new();
    let mut cursor = Some(request.team_id.as_str());
    while let Some(id) = cursor {
        if !lineage.insert(id.to_owned()) {
            return Err(fail("PLANNING_AUTHORITY_INVALID", "team ancestry cycle"));
        }
        let team = teams.iter().find(|t| t.team_id == id).ok_or_else(|| {
            fail(
                "PLANNING_AUTHORITY_INVALID",
                "registered team ancestry required",
            )
        })?;
        cursor = team.parent_team_id.as_deref();
    }
    if context
        .owners
        .iter()
        .find(|o| o.owner_id == request.owner_id)
        .and_then(|o| o.root_team_id.as_ref())
        .is_none_or(|root| !lineage.contains(root))
    {
        return Err(fail(
            "PLANNING_AUTHORITY_INVALID",
            "selected team must descend from the registered Owner root",
        ));
    }
    let scopes: Vec<_> = policies
        .into_iter()
        .filter(|p| {
            p.worker_id.is_none()
                && (p.project_id.is_none()
                    || (p.project_id.as_ref() == Some(&request.project_id)
                        && p.team_id.as_ref().is_none_or(|team| lineage.contains(team))))
        })
        .collect();
    if !scopes.iter().any(|p| p.project_id.is_none())
        || !scopes
            .iter()
            .any(|p| p.project_id.as_ref() == Some(&request.project_id) && p.team_id.is_none())
        || lineage
            .iter()
            .any(|id| !scopes.iter().any(|p| p.team_id.as_ref() == Some(id)))
    {
        return Err(fail(
            "PLANNING_AUTHORITY_INVALID",
            "global, project and every ancestor team resource policy required",
        ));
    }
    let mut limits = scopes[0].limits.clone();
    for policy in &scopes {
        limits.active_slot = limits.active_slot.min(policy.limits.active_slot);
        limits.coding_slot = limits.coding_slot.min(policy.limits.coding_slot);
        limits.cpu_units = limits.cpu_units.min(policy.limits.cpu_units);
        limits.memory_bytes = limits.memory_bytes.min(policy.limits.memory_bytes);
        limits.build_permit = limits.build_permit.min(policy.limits.build_permit);
        limits.gpu_permit = limits.gpu_permit.min(policy.limits.gpu_permit);
        limits.provider_inflight = limits
            .provider_inflight
            .min(policy.limits.provider_inflight);
    }
    Ok(PlanningResourceAuthority {
        scope: "GLOBAL_PROJECT_TEAM_CAPS_ONLY_WORKER_PLACEMENT_UNVERIFIED",
        scopes,
        effective_limits: limits,
    })
}

fn parse_planning_intent(
    output: &str,
    request: &DraftRequest,
    source_input: &InputBinding,
    frozen: &forgeflow_planner::CompileContext,
    resources: &PlanningResourceAuthority,
) -> Result<forgeflow_planner::ModelDraftProposal, ApiError> {
    let invalid = |message: String| fail("MODEL_DRAFT_INVALID", message);
    if output.is_empty() || output.len() > PLANNING_MAX_FINAL_BYTES {
        return Err(invalid(
            "planning final must be nonempty and within the existing 32 MiB artifact bound".into(),
        ));
    }
    let intent: PlanningIntent =
        forgeflow_planner::strict_json(output).map_err(|e| invalid(e.to_string()))?;
    if intent.schema_version != PLANNING_INTENT_SCHEMA
        || intent.tasks.is_empty()
        || intent.tasks.len() > PLANNING_MAX_PROPOSAL_TASKS
        || source_input.producer_task_id.is_some()
        || source_input.sha256 != request.source.raw_sha256
        || frozen.current_inputs.get(&source_input.path) != Some(&source_input.sha256)
    {
        return Err(invalid(
            "finite source-bound planning intent required".into(),
        ));
    }
    let mut context = frozen.clone();
    context.requirements = request.source.requirements.clone();
    context.source_revision = request.source.raw_sha256.clone();
    context.task_specs.clear();
    let ids = intent
        .tasks
        .iter()
        .map(|t| {
            (
                t.task_id.clone(),
                format!(
                    "TASK-{}-r{}-{}",
                    request.project_id, request.flow_revision, t.task_id
                ),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if ids.len() != intent.tasks.len()
        || ids.keys().any(|id| {
            id.is_empty()
                || id.len() > 48
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
    {
        return Err(invalid("unique short ASCII task IDs required".into()));
    }
    let mut tasks = Vec::new();
    let mut producer_inputs = std::collections::BTreeMap::new();
    for task in intent.tasks {
        if task.title.trim().is_empty()
            || task.outcome.trim().is_empty()
            || task.rollback_plan.trim().is_empty()
            || task.verification_case_count == 0
        {
            return Err(invalid(
                "finite outcome, title, rollback and nonzero verification cases required".into(),
            ));
        }
        if task.resource_request.active_slot == 0
            || (!task.write_set.is_empty() && task.resource_request.coding_slot == 0)
            || task
                .resource_request
                .dimensions()
                .iter()
                .zip(resources.effective_limits.dimensions())
                .any(|((_, requested), (_, limit))| *requested > limit)
        {
            return Err(invalid("positive active/coding reservations within captured ancestor resource caps required".into()));
        }
        let id = ids[&task.task_id].clone();
        let mut read_set = task.read_set;
        if !read_set.contains(&source_input.path) {
            read_set.push(source_input.path.clone());
        }
        let mut future = task.producer_inputs;
        if future.iter().any(|input| input.path == source_input.path) {
            return Err(invalid(
                "the immutable source input cannot be replaced by a future producer".into(),
            ));
        }
        for input in &mut future {
            input.producer_task_id = ids
                .get(&input.producer_task_id)
                .cloned()
                .ok_or_else(|| invalid("unknown future input producer".into()))?;
        }
        let mut inputs = Vec::new();
        for path in &read_set {
            if future.iter().any(|input| &input.path == path) {
                continue;
            }
            let hash = frozen.current_inputs.get(path).ok_or_else(|| {
                invalid(format!(
                    "known input snapshot missing for {path}; future bytes require producer_inputs"
                ))
            })?;
            inputs.push(InputBinding {
                path: path.clone(),
                sha256: hash.clone(),
                producer_task_id: None,
            });
        }
        let dependency_refs = task
            .dependencies
            .into_iter()
            .map(|dependency| {
                Ok(forgeflow_planner::DependencySpec {
                    task_id: ids
                        .get(&dependency.task_id)
                        .cloned()
                        .ok_or_else(|| invalid("unknown task dependency".into()))?,
                    project_id: request.project_id.clone(),
                    kind: dependency.kind,
                    binding_id: dependency.binding_id,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        let spec = forgeflow_planner::TaskSpec {
            outcome: task.outcome,
            requirement_digest_refs: task
                .requirement_ids
                .iter()
                .filter_map(|id| {
                    frozen
                        .requirement_semantic_digests
                        .get(id)
                        .map(|hash| (id.clone(), hash.clone()))
                })
                .collect(),
            design_anchors: request
                .source
                .requirements
                .iter()
                .filter(|r| task.requirement_ids.contains(&r.requirement_id))
                .map(|r| format!("{}#{}", r.source_document, r.anchor))
                .collect(),
            inputs,
            producer_inputs: vec![],
            mandatory_paths: read_set.clone(),
            dependency_refs,
            contract_produces: task.contract_produces,
            contract_consumes: task.contract_consumes,
            execution_profile: request.execution_profile.clone(),
            verification_plan: request.verification_plan.clone(),
            verification_case_count: task.verification_case_count,
            rollback_plan: task.rollback_plan,
            known_unknowns: task.known_unknowns,
            not_proven: [
                vec!["Generated draft has no execution or product Gate qualification".into()],
                task.not_proven,
            ]
            .concat(),
            isolated_contract_probe: false,
        };
        tasks.push(TaskCard {
            project_id: request.project_id.clone(),
            task_id: id.clone(),
            task_revision: 1,
            flow_revision: request.flow_revision,
            title: task.title,
            owner_id: request.owner_id.clone(),
            team_id: request.team_id.clone(),
            requirement_ids: task.requirement_ids,
            read_set,
            write_set: task.write_set,
            dependencies: spec
                .dependency_refs
                .iter()
                .map(|d| d.task_id.clone())
                .collect(),
            state: TaskPlanningState::NeedsReview,
            input_digest: String::new(),
            resource_request: task.resource_request,
            envelope: None,
            revision: 1,
        });
        context.task_specs.insert(id.clone(), spec);
        producer_inputs.insert(id, future);
    }
    let bundle = forgeflow_planner::DraftBundle {
        generation_method: "dsh_model_assisted".into(),
        flow: FlowRevision {
            project_id: request.project_id.clone(),
            flow_revision: request.flow_revision,
            parent_revision: None,
            state: FlowState::Draft,
            tasks,
            input_digest: String::new(),
            approved_by: None,
            revision: 1,
        },
        context,
    };
    let mut wire = serde_json::to_value(bundle).map_err(contract_error)?;
    wire["flow"]["input_digest"] = Value::Null;
    for task in wire["flow"]["tasks"].as_array_mut().unwrap() {
        task["input_digest"] = Value::Null;
    }
    for (id, inputs) in producer_inputs {
        wire["context"]["task_specs"][id]["producer_inputs"] =
            serde_json::to_value(inputs).map_err(contract_error)?;
    }
    // This materializes controller-owned fields; it never rewrites or repairs
    // the original native final event or its model-authored text.
    forgeflow_planner::parse_model_draft_proposal(
        &serde_json::to_string(&wire).map_err(contract_error)?,
        request,
    )
    .map_err(|e| invalid(e.to_string()))
}

fn planning_intent_prompt(
    request: &DraftRequest,
    instruction: &str,
    source_bytes: &[u8],
    source_input: &InputBinding,
    context: &forgeflow_planner::CompileContext,
    resources: &PlanningResourceAuthority,
) -> Result<String, ApiError> {
    let example = json!({
        "schema_version": PLANNING_INTENT_SCHEMA,
        "tasks": [{
            "task_id": "T1", "title": "Finite task title",
            "requirement_ids": request.source.requirements.iter().filter(|r| r.deferred_reason.is_none()).take(1).map(|r| r.requirement_id.clone()).collect::<Vec<_>>(),
            "outcome": "Concrete result preserving the mapped source acceptance",
            "read_set": [], "write_set": [], "dependencies": [],
            "resource_request": {"active_slot":1,"coding_slot":0,"cpu_units":0,"memory_bytes":0,"build_permit":0,"gpu_permit":0,"provider_inflight":1},
            "verification_case_count":2,
            "rollback_plan":"Preserve failed artifacts; explicitly revert any integrated change"
        }]
    });
    Ok(format!(
        "Return one complete compact JSON planning intent, schema_version={PLANNING_INTENT_SCHEMA}. Read-only planning: no execution, completion, approval or leases. Keep the response concise within the existing model output grant; use one task for one finite source outcome, and finite subplans for large hierarchical work. The existing limit is {PLANNING_MAX_PROPOSAL_TASKS} tasks. Write concise title/outcome/rollback and finish every JSON object. Map every non-deferred source requirement using its exact requirement_id; preserve all original acceptance and scope. The controller supplies project/task revisions, namespaced IDs, owner/team, original requirement facts and anchors, known input hashes, approved profiles, draft state and semantic digests; do not emit those fields or a Flow/context wrapper.\nRequired task fields and JSON shape (replace example values):\n{}\nOptional task fields: contract_produces, contract_consumes, producer_inputs, known_unknowns, not_proven. Contracts use exact {{contract_id,version,spec_sha256}} registered below. Dependencies use {{task_id,kind,binding_id}}, with kind integrated/artifact/contract_frozen/gate_pass and task_id referencing a proposal task ID. Task IDs are unique ASCII letters/digits/_/- of at most 48 bytes. resource_request uses the seven canonical unsigned integer dimensions; active_slot must be positive, coding_slot must be positive for writes, and each dimension must fit the captured ancestor policy limits. Zero provider_inflight is allowed for tasks that require no model request. read_set lists normalized exact existing snapshot paths, or explicit future producer input paths. The immutable source input is automatically bound to every task. Future inputs use {{path,producer_task_id,dependency_binding_id,contract}} and optional producer_task_revision/producer_input_digest; unknown byte hashes are never invented. Producer must declare the output in write_set and exact contract_produces; consumer declares read_set, contract_consumes and matching integrated dependency. Supplied producer pins must match; existing DAG, input, contract and ownership checks remain mandatory. No isolated contract probes are authorized by this protocol. verification_case_count is a nonzero planned denominator, never evidence of executed cases. Public contract freezing remains required.\nSelected write authority:\n{}\nFrozen input and contract facts:\n{}\nUser planning instruction (source acceptance and authority remain binding):\n{}\nFull immutable design-source bundle (sha256={}):\n{}\n",
        serde_json::to_string(&example).map_err(contract_error)?,
        serde_json::to_string(&request.write_set).map_err(contract_error)?,
        serde_json::to_string(&planning_authority(source_input, context, resources))
            .map_err(contract_error)?,
        instruction,
        request.source.raw_sha256,
        String::from_utf8_lossy(source_bytes),
    ))
}

fn validate_planning_known_inputs(
    context: &forgeflow_planner::CompileContext,
) -> Result<(), ApiError> {
    for spec in context.task_specs.values() {
        for input in &spec.inputs {
            if context.current_inputs.get(&input.path) != Some(&input.sha256) {
                return Err(fail(
                    "CONTEXT_STALE",
                    format!(
                        "planning input snapshot changed for {}; preserve the original proposal and review a fresh source-bound request",
                        input.path
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn parse_planning_proposal(
    text: &str,
    request: &DraftRequest,
    source_input: &InputBinding,
    frozen: &forgeflow_planner::CompileContext,
    resources: &PlanningResourceAuthority,
) -> Result<forgeflow_planner::ModelDraftProposal, ApiError> {
    if text.is_empty() || text.len() > PLANNING_MAX_FINAL_BYTES {
        return Err(fail(
            "MODEL_DRAFT_INVALID",
            "planning final must be nonempty and within the existing 32 MiB artifact bound",
        ));
    }
    let wire: Value = forgeflow_planner::strict_json(text)
        .map_err(|e| fail("MODEL_DRAFT_INVALID", e.to_string()))?;
    if wire.get("schema_version").is_some() {
        parse_planning_intent(text, request, source_input, frozen, resources)
    } else {
        forgeflow_planner::parse_model_draft_proposal(text, request)
            .map_err(|e| fail("MODEL_DRAFT_INVALID", e.to_string()))
    }
}

fn planning_output_error(
    mut error: ApiError,
    attempt_id: &str,
    output_artifact: &ArtifactRef,
    text_bytes: Option<usize>,
) -> ApiError {
    let mut details = json!({
        "planning_attempt_id": attempt_id,
        "output_artifact": output_artifact,
        "model_text_utf8_bytes": text_bytes,
        "validation_details": error.1.details,
    });
    if error.1.code == "MODEL_DRAFT_INVALID" || error.1.code == "PLANNING_OUTPUT_INVALID" {
        details["parse_error"] = json!(error.1.message);
    }
    error.1.details = details;
    error
}

async fn current_planning_context(
    s: &App,
    project: &str,
    source_ids: &[String],
    request: &DraftRequest,
    source_input: &InputBinding,
    proposed_context: forgeflow_planner::CompileContext,
    authority_bytes: &[u8],
) -> Result<forgeflow_planner::CompileContext, ApiError> {
    let mut sources = Vec::new();
    for id in source_ids {
        sources.push(s.store.get_document(project, "sources", id).await?);
    }
    let requirements = s.store.list_requirements(project).await?;
    let source_bytes = serde_json::to_vec(&json!({"documents":sources,"requirements":requirements,"manual_requirement_policy":"explicit owner-entered requirement rows are immutable operation inputs; missing source documents are not claimed as loaded"})).map_err(contract_error)?;
    if forgeflow_evidence::sha256(&source_bytes) != request.source.raw_sha256 {
        return Err(fail(
            "CONTEXT_STALE",
            "planning source changed during native generation; preserve the original proposal and review a fresh source-bound request",
        ));
    }
    let context = super::catalog::authoritative_context(s, project, proposed_context).await?;
    let resources = planning_resource_authority(
        request,
        &context,
        &s.store.list_teams(project).await?,
        s.store.resource_policies(project).await?,
    )?;
    validate_planning_authority_snapshot(authority_bytes, source_input, &context, &resources)?;
    validate_planning_known_inputs(&context)?;
    Ok(context)
}

fn validate_planning_authority_snapshot(
    captured: &[u8],
    source_input: &InputBinding,
    context: &forgeflow_planner::CompileContext,
    resources: &PlanningResourceAuthority,
) -> Result<(), ApiError> {
    let current = serde_json::to_vec(&planning_authority(source_input, context, resources))
        .map_err(contract_error)?;
    if current != captured {
        return Err(fail(
            "CONTEXT_STALE",
            "planning authority or immutable inputs changed during native generation; preserve the original proposal and review a fresh source-bound request",
        ));
    }
    Ok(())
}
#[derive(Deserialize, Serialize, Clone)]
pub struct GenerationRequest {
    source_ids: Vec<String>,
    instruction: String,
    #[serde(default)]
    owner_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    executor_profile_id: Option<String>,
    #[serde(default)]
    verification_plan_id: Option<String>,
    #[serde(default)]
    resource_profile_id: Option<String>,
    #[serde(default)]
    max_model_requests: Option<u32>,
}
fn planning_request_limit(requested: Option<u32>) -> Result<u32, ApiError> {
    let limit = requested.unwrap_or(PLANNING_MAX_MODEL_REQUESTS);
    if limit == 0 || limit > PLANNING_MAX_MODEL_REQUESTS {
        return Err(fail(
            "PLANNING_MODEL_BUDGET_INVALID",
            format!(
                "planning model request limit must be between 1 and {PLANNING_MAX_MODEL_REQUESTS}"
            ),
        ));
    }
    Ok(limit)
}
pub async fn generate(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<GenerationRequest>,
) -> Result<Response, ApiError> {
    // Reject an invalid budget before creating an operation or queue entry.
    planning_request_limit(body.max_model_requests)?;
    let i = super::identity(&headers, &actor)?;
    let op = forgeflow_planner::sha256(format!("{}:{}", i.actor_id, i.idempotency_key).as_bytes())
        [..32]
        .to_string();
    let receipt=s.store.execute_command(i,CatalogCommand::PutDocument{project_id:project.clone(),collection:"operations".into(),id:op.clone(),expected_revision:None,value:json!({"operation_id":op,"project_id":project,"kind":"DSH_FLOW_GENERATION","status":"ACCEPTED","request":body})}).await?;
    if !receipt.replayed {
        let state = s.clone();
        let id = op.clone();
        tokio::spawn(async move {
            let result = run(&state, &project, &id, &body).await;
            let value = match result {
                Ok(value) => {
                    json!({"operation_id":id,"project_id":project,"kind":"DSH_FLOW_GENERATION","status":"SUCCEEDED","result":value})
                }
                Err(mut error) => {
                    let cleanup = cleanup_failed_planning(&state, &project, &id).await;
                    error.1.details = json!({"primary":error.1.details,"cleanup":cleanup});
                    json!({"operation_id":id,"project_id":project,"kind":"DSH_FLOW_GENERATION","status":"FAILED","error":error.1})
                }
            };
            if let Err(error) = state
                .store
                .execute_command(
                    CommandIdentity {
                        actor_id: "planning-service".into(),
                        idempotency_key: format!("{id}:settled"),
                    },
                    CatalogCommand::PutDocument {
                        project_id: project,
                        collection: "operations".into(),
                        id,
                        expected_revision: Some(1),
                        value,
                    },
                )
                .await
            {
                tracing::error!(%error,"planning settlement persistence failed");
            }
        });
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"data":receipt.value,"operation_id":op,"replayed":receipt.replayed})),
    )
        .into_response())
}
async fn run(s: &App, p: &str, op: &str, body: &GenerationRequest) -> Result<Value, ApiError> {
    let max_model_requests = planning_request_limit(body.max_model_requests)?;
    if body.source_ids.is_empty() {
        return Err(fail("SOURCE_REQUIRED", "select immutable design sources"));
    }
    let project = s.store.get_project(p).await?;
    if project.authority_mode != AuthorityMode::Managed {
        return Err(fail(
            "OBSERVED_READ_ONLY",
            "observed projects cannot execute planning sessions",
        ));
    }
    let requirements = s.store.list_requirements(p).await?;
    if requirements.is_empty() {
        return Err(fail(
            "REQUIREMENTS_REQUIRED",
            "import requirements before model planning",
        ));
    }
    let mut sources = Vec::new();
    for id in &body.source_ids {
        sources.push(s.store.get_document(p, "sources", id).await?);
    }
    for r in &requirements {
        if let Some((id, _)) = r.source_anchor.split_once('#') {
            if s.store.get_document(p, "sources", id).await.is_ok()
                && !body.source_ids.iter().any(|s| s == id)
            {
                return Err(fail(
                    "SOURCE_COVERAGE_INCOMPLETE",
                    "planning request must include every registered source used by current requirements",
                ));
            }
        }
    }
    let owners = s.store.list_documents(p, "owners").await?;
    let owner_id = body
        .owner_id
        .clone()
        .or_else(|| {
            owners
                .first()
                .and_then(|v| v["owner_id"].as_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| fail("OWNER_REQUIRED", "register a source-bound owner territory"))?;
    let owner = s.store.get_document(p, "owners", &owner_id).await?;
    let write_set = owner["include"]
        .as_array()
        .ok_or_else(|| {
            fail(
                "OWNER_PATH_VIOLATION",
                "owner territory must declare includes",
            )
        })?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let teams = s.store.list_teams(p).await?;
    let team_id = body
        .team_id
        .clone()
        .or_else(|| teams.first().map(|t| t.team_id.clone()))
        .ok_or_else(|| fail("TEAM_REQUIRED", "register a budgeted planning team"))?;
    let profile_id = select_id(
        s,
        p,
        "executor_profiles",
        body.executor_profile_id.clone(),
        "id",
    )
    .await?;
    let mut profile = s
        .store
        .get_document(p, "executor_profiles", &profile_id)
        .await?;
    strip_revision(&mut profile);
    let profile: forgeflow_executors::HeadlessProfile =
        serde_json::from_value(profile).map_err(contract_error)?;
    forgeflow_executors::doctor(&profile, std::path::Path::new(&project.root_path))
        .map_err(|e| fail("EXECUTOR_UNQUALIFIED", e.to_string()))?;
    let template_id = select_id(
        s,
        p,
        "verification_plans",
        body.verification_plan_id.clone(),
        "plan_id",
    )
    .await?;
    let mut template = s
        .store
        .get_document(p, "verification_plans", &template_id)
        .await?;
    strip_revision(&mut template);
    let mut verification: forgeflow_evidence::VerificationPlan =
        serde_json::from_value(template).map_err(contract_error)?;
    let resource_profile = select_id(
        s,
        p,
        "resource_profiles",
        body.resource_profile_id.clone(),
        "id",
    )
    .await?;
    let flows = s.store.list_flows(p).await?;
    let planning_revision = flows.iter().map(|f| f.flow_revision).max().unwrap_or(0) + 1;
    let output_revision = planning_revision + 1;
    let source_bytes=serde_json::to_vec(&json!({"documents":sources,"requirements":requirements,"manual_requirement_policy":"explicit owner-entered requirement rows are immutable operation inputs; missing source documents are not claimed as loaded"})).map_err(contract_error)?;
    let source_hash = forgeflow_evidence::sha256(&source_bytes);
    let source_id = format!("planning-source-{op}");
    let logical_path = format!("source-artifacts/{source_id}.json");
    let source_ref = artifact(s, p, op, "source", &source_bytes).await?;
    let source = forgeflow_planner::RequirementDocument {
        source_document: source_id,
        raw_sha256: source_hash.clone(),
        semantic_sha256: forgeflow_evidence::sha256(
            &serde_json::to_vec(&requirements).map_err(contract_error)?,
        ),
        requirements: requirements
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
            .collect(),
    };
    let request = DraftRequest {
        project_id: p.into(),
        flow_revision: output_revision,
        source,
        owner_id,
        team_id,
        write_set,
        execution_profile: profile_id.clone(),
        verification_plan: template_id,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(contract_error)?;
    let request_artifact = artifact(s, p, op, "draft-request", &request_bytes).await?;
    let request_path = s
        .data_root
        .join("artifacts")
        .join(&request_artifact.artifact_id);
    for command in &mut verification.commands {
        command.env.insert(
            "FORGEFLOW_DRAFT_REQUEST_PATH".into(),
            request_path.to_string_lossy().into_owned(),
        );
        command.bound_inputs.push(forgeflow_evidence::BoundInput {
            path: request_path.clone(),
            sha256: request_artifact.sha256.clone(),
        });
    }
    let task_id = format!("planning-{op}");
    let mut bootstrap_request = request.clone();
    bootstrap_request.flow_revision = planning_revision;
    let source_input = InputBinding {
        path: logical_path.clone(),
        sha256: source_hash.clone(),
        producer_task_id: None,
    };
    let mut bootstrap = forgeflow_planner::planning_bootstrap_with_source_input(
        &bootstrap_request,
        &task_id,
        source_input.clone(),
    )
    .map_err(|e| fail("PLANNING_BOOTSTRAP_INVALID", e.to_string()))?;
    let manifest = ContextManifest {
        files: vec![],
        mandatory_paths: vec![logical_path.clone()],
        artifact_inputs: vec![ContextArtifactInput {
            logical_path: logical_path.clone(),
            artifact: source_ref.clone(),
        }],
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(contract_error)?;
    let manifest_ref = artifact(s, p, op, "context", &manifest_bytes).await?;
    s.store.execute_command(phase_identity(op,"snapshot"),CatalogCommand::RegisterInputSnapshots{project_id:p.into(),snapshots:vec![json!({"path":logical_path,"relative_path":logical_path,"sha256":source_hash,"artifact":source_ref,"source_kind":"CONTROLLED_ARTIFACT"})]}).await?;
    verification.plan_id = format!("planning-verification-{op}");
    if let Some(spec) = bootstrap.context.task_specs.get_mut(&task_id) {
        spec.verification_plan = verification.plan_id.clone();
    }
    bootstrap.context = super::catalog::authoritative_context(s, p, bootstrap.context).await?;
    super::catalog::bind_requirement_refs(&mut bootstrap.context, &bootstrap.flow.tasks);
    bind_planning_model_budget(&mut bootstrap, &mut verification)?;
    let frozen_context = bootstrap.context.clone();
    let resource_authority = planning_resource_authority(
        &request,
        &frozen_context,
        &teams,
        s.store.resource_policies(p).await?,
    )?;
    if resource_authority.effective_limits.provider_inflight == 0
        || resource_authority.effective_limits.active_slot == 0
    {
        return Err(fail(
            "PLANNING_AUTHORITY_INVALID",
            "planning requires an active slot and provider reservation in every ancestor",
        ));
    }
    let authority_bytes = serde_json::to_vec(&planning_authority(
        &source_input,
        &frozen_context,
        &resource_authority,
    ))
    .map_err(contract_error)?;
    let authority_ref = artifact(s, p, op, "authority", &authority_bytes).await?;
    let authority_path = s
        .data_root
        .join("artifacts")
        .join(&authority_ref.artifact_id);
    let source_path = s.data_root.join("artifacts").join(&source_ref.artifact_id);
    let prompt = if verification.oracle_id == "a10-source-bound-planning-intent.v2" {
        planning_intent_prompt(
            &request,
            &body.instruction,
            &source_bytes,
            &source_input,
            &frozen_context,
            &resource_authority,
        )?
    } else {
        // Existing independently pinned v1 verifier profiles keep their wire
        // grammar; only a new v2 profile opts into the compact intent prompt.
        format!(
            "{}\nController-authoritative complete requirement semantic digests (use exactly these mapped references):\n{}\n\nFull immutable design-source bundle (sha256={}):\n{}\n",
            forgeflow_planner::model_draft_prompt_with_instruction(&request, &body.instruction),
            serde_json::to_string(&frozen_context.requirement_semantic_digests)
                .map_err(contract_error)?,
            source_hash,
            String::from_utf8_lossy(&source_bytes),
        )
    };
    let prompt_ref = artifact(s, p, op, "prompt", prompt.as_bytes()).await?;
    for command in &mut verification.commands {
        for (key, value) in [
            (
                "FORGEFLOW_DRAFT_REQUEST_SHA256",
                request_artifact.sha256.clone(),
            ),
            (
                "FORGEFLOW_PLANNING_AUTHORITY_PATH",
                authority_path.to_string_lossy().into_owned(),
            ),
            (
                "FORGEFLOW_PLANNING_AUTHORITY_SHA256",
                authority_ref.sha256.clone(),
            ),
            (
                "FORGEFLOW_PLANNING_SOURCE_PATH",
                source_path.to_string_lossy().into_owned(),
            ),
            (
                "FORGEFLOW_PLANNING_SOURCE_SHA256",
                source_ref.sha256.clone(),
            ),
            ("FORGEFLOW_PLANNING_TASK_ID", task_id.clone()),
            (
                "FORGEFLOW_PLANNING_INPUT_HASH",
                verification.input_hash.clone(),
            ),
            (
                "FORGEFLOW_PLANNING_CONTEXT_SHA256",
                manifest_ref.sha256.clone(),
            ),
            (
                "FORGEFLOW_PLANNING_PROMPT_SHA256",
                prompt_ref.sha256.clone(),
            ),
        ] {
            command.env.insert(key.into(), value);
        }
        command.bound_inputs.extend([
            forgeflow_evidence::BoundInput {
                path: authority_path.clone(),
                sha256: authority_ref.sha256.clone(),
            },
            forgeflow_evidence::BoundInput {
                path: source_path.clone(),
                sha256: source_ref.sha256.clone(),
            },
        ]);
    }
    s.store
        .execute_command(
            phase_identity(op, "verification-plan"),
            CatalogCommand::PutDocument {
                project_id: p.into(),
                collection: "verification_plans".into(),
                id: verification.plan_id.clone(),
                expected_revision: None,
                value: serde_json::to_value(&verification).map_err(contract_error)?,
            },
        )
        .await?;
    let base = forgeflow_git::resolve(std::path::Path::new(&project.root_path), "refs/heads/main")
        .map_err(|e| fail("REPOSITORY_UNQUALIFIED", e.to_string()))?;
    let now = Utc::now();
    let artifact_prefix = s.data_root.join("artifacts").join("planning").join(op);
    tokio::fs::create_dir_all(&artifact_prefix)
        .await
        .map_err(|e| fail("ARTIFACT_IO_FAILED", e.to_string()))?;
    bootstrap.flow.tasks[0].envelope = Some(ExecutionEnvelope {
        schema_version: "forgeflow.execution.v1".into(),
        operation_id: format!("planning-operation-{op}"),
        project_id: p.into(),
        task_id: task_id.clone(),
        task_revision: 1,
        attempt_id: format!("planning-attempt-{op}"),
        lease_id: format!("planning-lease-{op}"),
        generation: 1,
        worker_id: "pending-worker".into(),
        workspace_root: project.root_path,
        base_sha: base,
        context_manifest: ContextManifestRef {
            artifact_id: manifest_ref.artifact_id,
            sha256: manifest_ref.sha256,
            mandatory_paths: manifest.mandatory_paths,
            rendered_utf8_bytes: source_bytes.len() as u64,
            token_estimate: None,
            tokenizer_id: None,
        },
        write_set: vec![],
        prompt_artifact: prompt_ref,
        model_route_id: profile.model_route_id,
        executor_profile_id: profile_id,
        resource_profile_id: resource_profile,
        verification_plan_id: verification.plan_id,
        allowed_effects: vec![
            AllowedEffect::ReadWorkspace,
            AllowedEffect::RunApprovedCommands,
            AllowedEffect::RequestApprovedModel,
        ],
        issued_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::seconds(30)).to_rfc3339(),
        deadline_at: (now + chrono::Duration::minutes(30)).to_rfc3339(),
        artifact_prefix: artifact_prefix.to_string_lossy().into_owned(),
        secret_refs: vec![],
        idempotency_key: op.into(),
        trace_id: op.into(),
        enforcement: Enforcement {
            model_budget_mode: ModelBudgetMode::DirectObserved,
            stage_resource_mode: StageResourceMode::AttemptReservation,
            build_capable: false,
            gateway_coverage_receipt_id: None,
            tool_guard_receipt_id: None,
            attempt_reserved_build_permits: 0,
            all_model_routes_covered: false,
            disabled_tool_entry_ids: vec![],
        },
        session_purpose: SessionPurpose::Planning,
        max_model_requests,
        resume_session_id: None,
        command: None,
    });
    bootstrap.flow.input_digest =
        forgeflow_planner::semantic_digest(&bootstrap.flow, &bootstrap.context);
    s.store
        .execute_command(
            phase_identity(op, "flow"),
            CatalogCommand::PutFlow {
                flow: bootstrap.flow,
                expected_revision: None,
                context: Some(serde_json::to_value(bootstrap.context).map_err(contract_error)?),
            },
        )
        .await?;
    s.store
        .execute_command(
            phase_identity(op, "commit"),
            CatalogCommand::CommitFlow {
                project_id: p.into(),
                flow_revision: planning_revision,
                expected_revision: 1,
                approved_by: "planning-service/source-bound-bootstrap".into(),
            },
        )
        .await?;
    let task = s.store.get_task(p, &task_id).await?;
    s.store
        .execute_command(
            phase_identity(op, "enqueue"),
            CatalogCommand::EnqueueTask {
                project_id: p.into(),
                task_id: task_id.clone(),
                expected_revision: task.revision,
                worker_id: String::new(),
                priority: 100,
                lease_seconds: 30,
                worker_scope_id: String::new(),
                scope_ids: vec![],
            },
        )
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1800);
    let attempt = loop {
        if tokio::time::Instant::now() > deadline {
            return Err(fail(
                "PLANNING_TIMEOUT",
                "queued planning operation exceeded its absolute deadline",
            ));
        }
        if let Some(attempt) = s
            .store
            .list_attempts(p)
            .await?
            .into_iter()
            .find(|a| a.task_id == task_id)
        {
            if attempt.state == AttemptState::Verifying {
                break attempt;
            }
            if attempt.state.is_terminal() || attempt.state == AttemptState::RecoveryRequired {
                return Err(fail(
                    "PLANNING_EXECUTION_FAILED",
                    format!(
                        "planning attempt {} is {:?}",
                        attempt.attempt_id, attempt.state
                    ),
                ));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let raw_path = s
        .data_root
        .join("attempts")
        .join(&attempt.attempt_id)
        .join("final.json");
    let raw = tokio::fs::read(&raw_path)
        .await
        .map_err(|e| fail("PLANNING_OUTPUT_MISSING", e.to_string()))?;
    let output_artifact = ArtifactRef {
        artifact_id: format!("planning-output-{op}"),
        sha256: forgeflow_evidence::sha256(&raw),
    };
    // Publish the exact original bytes within the registered download root.
    // The original attempt journal remains untouched, including malformed output.
    let output_path = s
        .data_root
        .join("artifacts")
        .join(&output_artifact.artifact_id);
    let path = output_path.clone();
    let bytes = raw.clone();
    tokio::task::spawn_blocking(move || persist_planning_artifact(&path, &bytes))
        .await
        .map_err(|e| fail("ARTIFACT_IO_FAILED", e.to_string()))?
        .map_err(|e| fail("ARTIFACT_IO_FAILED", e.to_string()))?;
    s.store
        .execute_command(
            phase_identity(op, "raw-output"),
            CatalogCommand::PutArtifact {
                project_id: p.into(),
                id: output_artifact.artifact_id.clone(),
                path: output_path.to_string_lossy().into_owned(),
                sha256: output_artifact.sha256.clone(),
                kind: "RAW_PLANNING_MODEL_OUTPUT".into(),
                bytes: raw.len() as u64,
            },
        )
        .await?;
    if raw.is_empty() || raw.len() > PLANNING_MAX_FINAL_BYTES {
        return Err(planning_output_error(
            fail(
                "PLANNING_OUTPUT_INVALID",
                "read-only final artifact must be nonempty and within the existing 32 MiB bound",
            ),
            &attempt.attempt_id,
            &output_artifact,
            None,
        ));
    }
    let text = forgeflow_executors::extract_final_text(&raw).map_err(|e| {
        planning_output_error(
            fail("PLANNING_OUTPUT_INVALID", e.to_string()),
            &attempt.attempt_id,
            &output_artifact,
            None,
        )
    })?;
    let with_output = |error| {
        planning_output_error(
            error,
            &attempt.attempt_id,
            &output_artifact,
            Some(text.len()),
        )
    };
    let proposal = parse_planning_proposal(
        &text,
        &request,
        &source_input,
        &frozen_context,
        &resource_authority,
    )
    .map_err(with_output)?;
    let mut context = current_planning_context(
        s,
        p,
        &body.source_ids,
        &request,
        &source_input,
        proposal.context.clone(),
        &authority_bytes,
    )
    .await
    .map_err(with_output)?;
    for (task_id, requirements) in proposal.task_requirement_bindings() {
        if let Some(spec) = context.task_specs.get_mut(&task_id) {
            spec.requirement_digest_refs = requirements
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
    let sealed = forgeflow_planner::seal_model_draft_proposal(proposal, context)
        .map_err(|e| with_output(fail("MODEL_DRAFT_SOURCE_UNRESOLVED", e.to_string())))?;
    let source_resolution = json!({"algorithm":"forgeflow.model-draft.source-resolution.v1","raw_source_sha256":request.source.raw_sha256,
        "requirement_source_digest":sealed.draft.context.source_revision,"producer_inputs":sealed.producer_input_resolution,"approved":false});
    let draft = sealed.draft;
    let validation = super::operations::run(
        s.clone(),
        p,
        &attempt.attempt_id,
        &format!("planning-validation-{op}"),
        false,
    )
    .await
    .map_err(with_output)?;
    // Verification can take time. Security and input authority must still be
    // the captured version at the final draft persistence boundary.
    current_planning_context(
        s,
        p,
        &body.source_ids,
        &request,
        &source_input,
        draft.context.clone(),
        &authority_bytes,
    )
    .await
    .map_err(with_output)?;
    s.store
        .execute_command(
            phase_identity(op, "generated-draft"),
            CatalogCommand::PutFlow {
                flow: draft.flow.clone(),
                expected_revision: None,
                context: Some(serde_json::to_value(draft.context).map_err(contract_error)?),
            },
        )
        .await?;
    Ok(
        json!({"generation_method":"dsh_model_assisted","flow":draft.flow,"planning_attempt_id":attempt.attempt_id,"planning_output":output_artifact,"validation":validation,"source_resolution":source_resolution,"approved":false}),
    )
}
fn bind_planning_model_budget(
    bootstrap: &mut forgeflow_planner::DraftBundle,
    verification: &mut forgeflow_evidence::VerificationPlan,
) -> Result<(), ApiError> {
    for task in &mut bootstrap.flow.tasks {
        // The native root borrows this canonical reservation. One concurrent
        // request is separate from the envelope's eight total counted calls.
        task.resource_request.provider_inflight = 1;
        let spec = bootstrap
            .context
            .task_specs
            .get(&task.task_id)
            .ok_or_else(|| fail("TASK_SPEC_REQUIRED", "planning task semantics missing"))?;
        task.input_digest = forgeflow_planner::canonical_task_input_digest(task, spec);
    }
    verification.task_revision = 1;
    verification.input_hash = bootstrap.flow.tasks[0].input_digest.clone();
    verification.contract_version = "none".into();
    Ok(())
}
async fn select_id(
    s: &App,
    p: &str,
    collection: &str,
    explicit: Option<String>,
    field: &str,
) -> Result<String, ApiError> {
    if let Some(id) = explicit {
        return Ok(id);
    }
    let docs = s.store.list_documents(p, collection).await?;
    if docs.len() != 1 {
        return Err(fail(
            "PLANNING_PROFILE_REQUIRED",
            format!("select one registered {collection}; found {}", docs.len()),
        ));
    }
    docs[0]
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            fail(
                "PLANNING_PROFILE_INVALID",
                format!("{collection} lacks {field}"),
            )
        })
}
fn phase_identity(op: &str, stage: &str) -> CommandIdentity {
    CommandIdentity {
        actor_id: "planning-service".into(),
        idempotency_key: format!("{op}:{stage}"),
    }
}
async fn artifact(
    s: &App,
    p: &str,
    op: &str,
    kind: &str,
    bytes: &[u8],
) -> Result<ArtifactRef, ApiError> {
    let digest = forgeflow_evidence::sha256(bytes);
    let id = format!("planning-{kind}-{digest}");
    let path = s.data_root.join("artifacts").join(&id);
    let copy_path = path.clone();
    let copy_bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || persist_planning_artifact(&copy_path, &copy_bytes))
        .await
        .map_err(|e| fail("ARTIFACT_IO_FAILED", e.to_string()))?
        .map_err(|e| fail("ARTIFACT_IO_FAILED", e.to_string()))?;
    s.store
        .execute_command(
            phase_identity(op, kind),
            CatalogCommand::PutArtifact {
                project_id: p.into(),
                id: id.clone(),
                path: path.to_string_lossy().into_owned(),
                sha256: digest.clone(),
                kind: kind.into(),
                bytes: bytes.len() as u64,
            },
        )
        .await?;
    Ok(ArtifactRef {
        artifact_id: id,
        sha256: digest,
    })
}
fn persist_planning_artifact(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.nlink() != 1 || std::fs::read(path)? != bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "existing immutable planning artifact differs; original retained",
                ));
            }
            std::fs::File::open(path)?.sync_all()?;
            return std::fs::File::open(
                path.parent()
                    .ok_or_else(|| std::io::Error::other("artifact parent missing"))?,
            )?
            .sync_all();
        }
        Err(error) => return Err(error),
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("artifact parent missing"))?,
    )?
    .sync_all()?;
    Ok(())
}
fn strip_revision(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        object.remove("revision");
    }
}
fn fail(code: &str, message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code, message)
}
fn contract_error(error: serde_json::Error) -> ApiError {
    fail("PLANNING_CONTRACT_INVALID", error.to_string())
}

async fn cleanup_failed_planning(s: &App, p: &str, op: &str) -> Value {
    let task_id = format!("planning-{op}");
    match s.store.list_attempts(p).await {
        Ok(attempts) => {
            let mut cleanup = Vec::new();
            for attempt in attempts
                .into_iter()
                .filter(|a| a.task_id == task_id && !a.state.is_terminal())
            {
                let id = attempt.attempt_id.clone();
                let receipt=s.store.cancel(CancelRequest{actor_id:"planning-service".into(),idempotency_key:format!("{op}:failed-planning:{id}"),project_id:p.into(),attempt_id:id.clone(),expected_revision:attempt.revision,reason:"planning operation failed; stop proof and verifier settlement required before resource release".into()}).await;
                cleanup.push(match receipt{Ok(receipt)=>json!({"attempt_id":id,"status":receipt.status,"revision":receipt.revision}),Err(error)=>json!({"attempt_id":id,"status":"RECOVERY_REQUIRED","error":error.to_string()})});
            }
            json!(cleanup)
        }
        Err(error) => json!({"status":"RECOVERY_REQUIRED","error":error.to_string()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeflow_planner::{DraftBundle, RequirementFormat};
    use forgeflow_scheduler::{ScopeSnapshot, capacity_blockers};

    fn intent_fixture() -> (
        DraftRequest,
        InputBinding,
        forgeflow_planner::CompileContext,
        PlanningResourceAuthority,
        Value,
    ) {
        let request = DraftRequest {
            project_id: "project".into(),
            flow_revision: 2,
            source: forgeflow_planner::normalize_requirements(
                "design-source",
                "- Preserve the original source acceptance\n",
                RequirementFormat::Markdown,
            )
            .unwrap(),
            owner_id: "owner".into(),
            team_id: "planning-team".into(),
            write_set: vec!["src/result.txt".into(), "src/consumer.txt".into()],
            execution_profile: "native-planning".into(),
            verification_plan: "independent-acceptance".into(),
        };
        let source_input = InputBinding {
            path: "source-artifacts/design-source.json".into(),
            sha256: request.source.raw_sha256.clone(),
            producer_task_id: None,
        };
        let mut context = forgeflow_planner::planning_bootstrap_with_source_input(
            &request,
            "planning-task",
            source_input.clone(),
        )
        .unwrap()
        .context;
        // Bootstrap intentionally has no write authority. Production replaces
        // its owners through authoritative_context before capturing proposals;
        // represent that registered exact territory in this store-free fixture.
        context.owners[0].include = request.write_set.clone();
        context.owners[0].root_team_id = Some(request.team_id.clone());
        let limits = ResourceVector {
            active_slot: 2,
            coding_slot: 2,
            cpu_units: 2,
            memory_bytes: 64 * 1024 * 1024,
            build_permit: 1,
            gpu_permit: 0,
            provider_inflight: 1,
        };
        let resources = PlanningResourceAuthority {
            scope: "GLOBAL_PROJECT_TEAM_CAPS_ONLY_WORKER_PLACEMENT_UNVERIFIED",
            scopes: vec![],
            effective_limits: limits,
        };
        let intent = json!({"schema_version": PLANNING_INTENT_SCHEMA, "tasks": [{
            "task_id":"T1", "title":"Preserve source acceptance", "requirement_ids":[request.source.requirements[0].requirement_id],
            "outcome":"Implement and independently verify the original source acceptance", "read_set":[], "write_set":["src/result.txt"], "dependencies":[],
            "resource_request":{"active_slot":1,"coding_slot":1,"cpu_units":1,"memory_bytes":1024,"build_permit":0,"gpu_permit":0,"provider_inflight":0},
            "verification_case_count":2, "rollback_plan":"Retain failed artifacts and explicitly revert integrated changes"
        }]});
        (request, source_input, context, resources, intent)
    }

    fn decode_intent(
        request: &DraftRequest,
        input: &InputBinding,
        context: &forgeflow_planner::CompileContext,
        resources: &PlanningResourceAuthority,
        value: &Value,
    ) -> Result<forgeflow_planner::ModelDraftProposal, ApiError> {
        parse_planning_proposal(
            &serde_json::to_string(value).unwrap(),
            request,
            input,
            context,
            resources,
        )
    }

    #[test]
    fn planning_intent_minimal_proposal_compiles_with_server_authority_and_source() {
        let (request, input, context, resources, intent) = intent_fixture();
        let text = serde_json::to_string(&intent).unwrap();
        assert!(text.len() < 1024);
        let proposal = decode_intent(&request, &input, &context, &resources, &intent).unwrap();
        let sealed =
            forgeflow_planner::seal_model_draft_proposal(proposal.clone(), proposal.context)
                .unwrap();
        let task = &sealed.draft.flow.tasks[0];
        let spec = &sealed.draft.context.task_specs[&task.task_id];
        assert_eq!(task.task_id, "TASK-project-r2-T1");
        assert_eq!(task.project_id, request.project_id);
        assert_eq!(task.owner_id, request.owner_id);
        assert_eq!(task.team_id, request.team_id);
        assert_eq!(sealed.draft.context.owners[0].include, request.write_set);
        assert_eq!(task.state, TaskPlanningState::NeedsReview);
        assert!(task.envelope.is_none());
        assert_eq!(task.resource_request.provider_inflight, 0);
        assert_eq!(spec.inputs[0].path, input.path);
        assert_eq!(spec.inputs[0].sha256, request.source.raw_sha256);
        assert_eq!(spec.execution_profile, request.execution_profile);
        assert_eq!(spec.verification_plan, request.verification_plan);
        assert_eq!(
            sealed.draft.context.requirements[0].acceptance,
            request.source.requirements[0].acceptance
        );
        assert_eq!(
            spec.design_anchors[0],
            format!(
                "{}#{}",
                request.source.requirements[0].source_document,
                request.source.requirements[0].anchor
            )
        );
        assert_eq!(
            task.input_digest,
            forgeflow_planner::canonical_task_input_digest(task, spec)
        );
        assert_eq!(
            sealed.draft.flow.input_digest,
            forgeflow_planner::semantic_digest(&sealed.draft.flow, &sealed.draft.context)
        );
        let report = forgeflow_planner::compile(&sealed.draft.flow, &sealed.draft.context);
        assert!(report.passed, "{report:?}");
    }

    #[test]
    fn planning_intent_rejects_eof_duplicate_keys_and_authority_forgery() {
        let (request, input, context, resources, intent) = intent_fixture();
        let text = serde_json::to_string(&intent).unwrap();
        let eof = parse_planning_proposal(
            &text[..text.len() - 1],
            &request,
            &input,
            &context,
            &resources,
        )
        .unwrap_err();
        assert_eq!(eof.1.code, "MODEL_DRAFT_INVALID");
        assert!(eof.1.message.contains("EOF"));
        let duplicate = text.replacen(
            "\"schema_version\":",
            "\"schema_version\":\"forged\",\"schema_version\":",
            1,
        );
        assert!(
            parse_planning_proposal(&duplicate, &request, &input, &context, &resources)
                .unwrap_err()
                .1
                .message
                .contains("duplicate JSON key")
        );
        for (field, value) in [
            ("owner_id", json!("other-owner")),
            ("team_id", json!("other-team")),
            ("envelope", json!({})),
            ("input_digest", json!("a".repeat(64))),
            ("inputs", json!([])),
            ("design_anchors", json!([])),
            ("execution_profile", json!("unapproved")),
            ("isolated_contract_probe", json!(true)),
        ] {
            let mut forged = intent.clone();
            forged["tasks"][0][field] = value;
            assert!(
                decode_intent(&request, &input, &context, &resources, &forged).is_err(),
                "accepted {field}"
            );
        }
        let mut expanded = intent;
        expanded["tasks"][0]["write_set"] = json!(["outside/result.txt"]);
        assert!(decode_intent(&request, &input, &context, &resources, &expanded).is_err());
    }

    #[test]
    fn planning_intent_rejects_stale_known_inputs_and_invalid_source_coverage() {
        let (request, input, mut context, resources, mut intent) = intent_fixture();
        context
            .current_inputs
            .insert("src/input.txt".into(), "a".repeat(64));
        intent["tasks"][0]["read_set"] = json!(["src/input.txt"]);
        let proposal = decode_intent(&request, &input, &context, &resources, &intent).unwrap();
        let mut changed = proposal.context.clone();
        changed
            .current_inputs
            .insert("src/input.txt".into(), "b".repeat(64));
        assert_eq!(
            validate_planning_known_inputs(&changed).unwrap_err().1.code,
            "CONTEXT_STALE"
        );
        let mut source_changed = input.clone();
        source_changed.sha256 = "c".repeat(64);
        assert!(decode_intent(&request, &source_changed, &context, &resources, &intent).is_err());
        intent["tasks"][0]["read_set"] = json!(["src/missing.txt"]);
        assert!(decode_intent(&request, &input, &context, &resources, &intent).is_err());
        intent["tasks"][0]["read_set"] = json!([]);
        intent["tasks"][0]["requirement_ids"] = json!(["invented-requirement"]);
        assert!(decode_intent(&request, &input, &context, &resources, &intent).is_err());
    }

    #[test]
    fn planning_intent_preserves_existing_task_and_artifact_bounds_and_resource_caps() {
        let (request, input, context, resources, mut intent) = intent_fixture();
        assert_eq!(PLANNING_MAX_PROPOSAL_TASKS, 10_000);
        assert_eq!(PLANNING_MAX_FINAL_BYTES, 32 * 1024 * 1024);
        let oversized = " ".repeat(PLANNING_MAX_FINAL_BYTES + 1);
        assert!(
            parse_planning_proposal(&oversized, &request, &input, &context, &resources).is_err()
        );
        for (field, value) in [
            ("active_slot", 0),
            ("coding_slot", 0),
            ("provider_inflight", 2),
            ("gpu_permit", 1),
        ] {
            let mut invalid = intent.clone();
            invalid["tasks"][0]["resource_request"][field] = json!(value);
            assert!(
                decode_intent(&request, &input, &context, &resources, &invalid).is_err(),
                "accepted {field}={value}"
            );
        }
        let too_many: Vec<_> = (0..=PLANNING_MAX_PROPOSAL_TASKS)
            .map(|index| {
                let mut task = intent["tasks"][0].clone();
                task["task_id"] = json!(format!("T{index}"));
                task
            })
            .collect();
        intent["tasks"] = json!(too_many);
        assert!(decode_intent(&request, &input, &context, &resources, &intent).is_err());
    }

    #[test]
    fn planning_intent_legacy_full_bundle_remains_strict_and_source_bound() {
        let (request, input, context, resources, _) = intent_fixture();
        let mut bundle = forgeflow_planner::rules_based_draft(request.clone()).unwrap();
        bundle.generation_method = "dsh_model_assisted".into();
        let mut wire = serde_json::to_value(bundle).unwrap();
        wire["flow"]["input_digest"] = Value::Null;
        for task in wire["flow"]["tasks"].as_array_mut().unwrap() {
            task["input_digest"] = Value::Null;
        }
        assert!(decode_intent(&request, &input, &context, &resources, &wire).is_ok());
        wire["flow"]["tasks"][0]["owner_id"] = json!("forged-owner");
        assert!(decode_intent(&request, &input, &context, &resources, &wire).is_err());
    }

    #[test]
    fn planning_intent_future_inputs_seal_exact_pins_and_reject_wrong_pins_or_cycles() {
        let (request, input, mut context, resources, mut intent) = intent_fixture();
        let contract = forgeflow_planner::ContractBinding {
            contract_id: "result-format".into(),
            version: 1,
            spec_sha256: "a".repeat(64),
        };
        context.contracts.push(forgeflow_planner::ContractSnapshot {
            contract_id: contract.contract_id.clone(),
            version: 1,
            spec_sha256: contract.spec_sha256.clone(),
            source_sha256: "b".repeat(64),
            frozen: true,
            required_consumers: vec!["consumer".into()],
            passing_consumers: vec!["consumer".into()],
            independent_receipt_id: Some("independent-contract-proof".into()),
            integration_receipt_id: Some("contract-integrated".into()),
        });
        intent["tasks"][0]["contract_produces"] = json!([contract]);
        let mut consumer = intent["tasks"][0].clone();
        consumer["task_id"] = json!("T2");
        consumer["title"] = json!("Consume exact producer output");
        consumer["write_set"] = json!(["src/consumer.txt"]);
        consumer["read_set"] = json!(["src/result.txt"]);
        consumer["dependencies"] =
            json!([{"task_id":"T1","kind":"integrated","binding_id":"T1:integrated"}]);
        consumer["contract_produces"] = json!([]);
        consumer["contract_consumes"] = json!([contract]);
        consumer["producer_inputs"] = json!([{"path":"src/result.txt","producer_task_id":"T1","dependency_binding_id":"T1:integrated","contract":contract}]);
        intent["tasks"].as_array_mut().unwrap().push(consumer);
        let proposal = decode_intent(&request, &input, &context, &resources, &intent).unwrap();
        let sealed =
            forgeflow_planner::seal_model_draft_proposal(proposal.clone(), proposal.context)
                .unwrap();
        assert_eq!(sealed.producer_input_resolution.len(), 1);
        let binding = &sealed.draft.context.task_specs["TASK-project-r2-T2"].producer_inputs[0];
        assert_eq!(
            binding.producer_input_digest,
            sealed.draft.flow.tasks[0].input_digest
        );
        assert_eq!(binding.producer_task_revision, 1);
        let report = forgeflow_planner::compile(&sealed.draft.flow, &sealed.draft.context);
        assert!(report.passed, "{report:?}");
        for (field, value) in [
            ("producer_input_digest", json!("f".repeat(64))),
            ("producer_task_revision", json!(2)),
        ] {
            let mut wrong = intent.clone();
            wrong["tasks"][1]["producer_inputs"][0][field] = value;
            let proposal = decode_intent(&request, &input, &context, &resources, &wrong).unwrap();
            assert!(
                forgeflow_planner::seal_model_draft_proposal(proposal.clone(), proposal.context)
                    .is_err(),
                "rebound {field}"
            );
        }
        intent["tasks"][0]["dependencies"] =
            json!([{"task_id":"T2","kind":"integrated","binding_id":"T2:integrated"}]);
        let proposal = decode_intent(&request, &input, &context, &resources, &intent).unwrap();
        assert!(
            forgeflow_planner::seal_model_draft_proposal(proposal.clone(), proposal.context)
                .unwrap_err()
                .to_string()
                .contains("DAG_CYCLE")
        );
    }

    #[test]
    fn planning_intent_captured_authority_rejects_owner_input_contract_and_cap_drift() {
        let (_, input, context, resources, _) = intent_fixture();
        let captured =
            serde_json::to_vec(&planning_authority(&input, &context, &resources)).unwrap();
        assert!(
            validate_planning_authority_snapshot(&captured, &input, &context, &resources).is_ok()
        );
        let mut changed = context.clone();
        changed.owners[0].exclude.push("src/result.txt".into());
        assert_eq!(
            validate_planning_authority_snapshot(&captured, &input, &changed, &resources)
                .unwrap_err()
                .1
                .code,
            "CONTEXT_STALE"
        );
        let mut changed = context.clone();
        changed
            .current_inputs
            .insert(input.path.clone(), "c".repeat(64));
        assert!(
            validate_planning_authority_snapshot(&captured, &input, &changed, &resources).is_err()
        );
        let mut changed = context.clone();
        changed.requirement_semantic_digests.clear();
        assert!(
            validate_planning_authority_snapshot(&captured, &input, &changed, &resources).is_err()
        );
        let mut changed = context.clone();
        changed.contracts.push(forgeflow_planner::ContractSnapshot {
            contract_id: "added-contract".into(),
            version: 1,
            spec_sha256: "a".repeat(64),
            source_sha256: "b".repeat(64),
            frozen: false,
            required_consumers: vec![],
            passing_consumers: vec![],
            independent_receipt_id: None,
            integration_receipt_id: None,
        });
        assert!(
            validate_planning_authority_snapshot(&captured, &input, &changed, &resources).is_err()
        );
        let mut lowered = resources.clone();
        lowered.effective_limits.provider_inflight = 0;
        assert!(
            validate_planning_authority_snapshot(&captured, &input, &context, &lowered).is_err()
        );
    }

    #[test]
    fn planning_intent_resource_authority_uses_only_selected_ancestor_policy_limits() {
        let (request, _, mut context, resources, _) = intent_fixture();
        context.owners[0].root_team_id = Some("root-team".into());
        let teams: Vec<_> = [
            ("root-team", None),
            ("planning-team", Some("root-team")),
            ("sibling", Some("root-team")),
        ]
        .into_iter()
        .map(|(id, parent)| Team {
            project_id: request.project_id.clone(),
            team_id: id.into(),
            parent_team_id: parent.map(str::to_owned),
            name: id.into(),
            paused: false,
            revision: 1,
        })
        .collect();
        let policies: Vec<_> = [
            ("global", None, None, None),
            ("project", Some("project"), None, None),
            ("root", Some("project"), Some("root-team"), None),
            ("child", Some("project"), Some("planning-team"), None),
            ("sibling", Some("project"), Some("sibling"), None),
            ("worker", Some("project"), None, Some("pending-worker")),
        ]
        .into_iter()
        .map(|(scope, project, team, worker)| ResourcePolicy {
            scope_id: scope.into(),
            parent_scope_id: None,
            project_id: project.map(str::to_owned),
            team_id: team.map(str::to_owned),
            worker_id: worker.map(str::to_owned),
            limits: if scope == "sibling" || scope == "worker" {
                ResourceVector::default()
            } else {
                resources.effective_limits.clone()
            },
            revision: 1,
            paused: false,
        })
        .collect();
        let frozen =
            planning_resource_authority(&request, &context, &teams, policies.clone()).unwrap();
        assert_eq!(frozen.scopes.len(), 4);
        assert_eq!(frozen.effective_limits.provider_inflight, 1);
        assert_eq!(frozen.effective_limits, resources.effective_limits);
        let missing_root = policies
            .into_iter()
            .filter(|p| p.team_id.as_deref() != Some("root-team"))
            .collect();
        assert!(planning_resource_authority(&request, &context, &teams, missing_root).is_err());
        context.owners[0].root_team_id = Some("sibling".into());
        assert!(planning_resource_authority(&request, &context, &teams, frozen.scopes).is_err());
    }

    #[test]
    fn planning_output_error_exposes_only_the_original_artifact_reference() {
        let reference = ArtifactRef {
            artifact_id: "registered-native-final".into(),
            sha256: forgeflow_evidence::sha256(b"original invalid output"),
        };
        let error = planning_output_error(
            fail("MODEL_DRAFT_INVALID", "JSON input: EOF"),
            "actual-attempt",
            &reference,
            Some(3197),
        );
        assert_eq!(
            error.1.details["output_artifact"],
            serde_json::to_value(reference).unwrap()
        );
        assert_eq!(error.1.details["planning_attempt_id"], "actual-attempt");
        assert_eq!(error.1.details["model_text_utf8_bytes"], 3197);
        assert_eq!(error.1.details["parse_error"], "JSON input: EOF");
    }

    fn planning_fixture() -> (DraftBundle, forgeflow_evidence::VerificationPlan) {
        let request = DraftRequest {
            project_id: "project".into(),
            flow_revision: 1,
            source: forgeflow_planner::normalize_requirements(
                "design-source",
                "- Preserve the original source acceptance\n",
                RequirementFormat::Markdown,
            )
            .unwrap(),
            owner_id: "owner".into(),
            team_id: "planning-team".into(),
            write_set: vec!["src/".into()],
            execution_profile: "native-planning".into(),
            verification_plan: "planning-verification".into(),
        };
        let mut bootstrap = forgeflow_planner::planning_bootstrap_with_source_input(
            &request,
            "planning-task",
            InputBinding {
                path: "source-artifacts/design-source.json".into(),
                sha256: request.source.raw_sha256.clone(),
                producer_task_id: None,
            },
        )
        .unwrap();
        bootstrap.context.owners[0].root_team_id = Some(request.team_id);
        let verification = forgeflow_evidence::VerificationPlan {
            plan_id: request.verification_plan,
            task_revision: 0,
            contract_version: "unbound".into(),
            input_hash: "unbound".into(),
            environment_profile: "unit-regression".into(),
            oracle_id: "source-scope-compiler".into(),
            verifier_id: "independent".into(),
            author_id: "owner".into(),
            commands: vec![],
        };
        (bootstrap, verification)
    }

    #[test]
    fn planning_output_storage_preserves_raw_bytes_and_refuses_replacement() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = std::env::temp_dir().join(format!(
            "forgeflow-planning-artifact-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).unwrap();
        let downloads = root.join("artifacts");
        std::fs::create_dir(&downloads).unwrap();
        let path = downloads.join("planning-output-operation");
        let raw = br#"{"type":"final","text":"{truncated"}"#;
        persist_planning_artifact(&path, raw).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        persist_planning_artifact(&path, raw).unwrap();
        assert!(persist_planning_artifact(&path, b"repaired-output").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        assert!(
            path.canonicalize()
                .unwrap()
                .starts_with(downloads.canonicalize().unwrap())
        );
        let alias = downloads.join("planning-output-alias");
        symlink(&path, &alias).unwrap();
        assert!(persist_planning_artifact(&alias, raw).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn planning_model_budget_accepts_lower_caps_and_rejects_expansion_before_queue() {
        let request = |limit: Option<serde_json::Value>| {
            let mut body =
                json!({"source_ids":["registered-source"],"instruction":"Preserve source scope"});
            if let Some(limit) = limit {
                body["max_model_requests"] = limit;
            }
            serde_json::from_value::<GenerationRequest>(body)
        };
        let default = request(None).unwrap();
        assert_eq!(
            planning_request_limit(default.max_model_requests).unwrap(),
            8
        );
        let lower = request(Some(json!(7))).unwrap();
        assert_eq!(planning_request_limit(lower.max_model_requests).unwrap(), 7);
        let smallest = request(Some(json!(1))).unwrap();
        assert_eq!(
            planning_request_limit(smallest.max_model_requests).unwrap(),
            1
        );
        for invalid in [0, 9, u32::MAX] {
            let body = request(Some(json!(invalid))).unwrap();
            assert_eq!(
                planning_request_limit(body.max_model_requests)
                    .unwrap_err()
                    .1
                    .code,
                "PLANNING_MODEL_BUDGET_INVALID"
            );
        }
        for invalid in [json!(-1), json!(1.5), json!("7")] {
            assert!(request(Some(invalid)).is_err());
        }
    }

    #[test]
    fn planning_model_budget_binds_resource_task_verifier_and_read_only_envelope() {
        let (mut bootstrap, mut verification) = planning_fixture();
        let original_digest = bootstrap.flow.tasks[0].input_digest.clone();
        let source_inputs =
            serde_json::to_value(&bootstrap.context.task_specs["planning-task"].inputs).unwrap();
        bind_planning_model_budget(&mut bootstrap, &mut verification).unwrap();
        let task = &mut bootstrap.flow.tasks[0];
        let spec = &bootstrap.context.task_specs["planning-task"];
        assert_eq!(task.resource_request.active_slot, 1);
        assert_eq!(task.resource_request.provider_inflight, 1);
        assert_eq!(task.resource_request.coding_slot, 0);
        assert!(task.write_set.is_empty());
        assert_eq!(serde_json::to_value(&spec.inputs).unwrap(), source_inputs);
        assert_ne!(task.input_digest, original_digest);
        assert_eq!(
            task.input_digest,
            forgeflow_planner::canonical_task_input_digest(task, spec)
        );
        assert_eq!(verification.input_hash, task.input_digest);
        assert_eq!(verification.task_revision, task.task_revision);
        task.envelope = Some(ExecutionEnvelope {
            schema_version: "forgeflow.execution.v1".into(),
            operation_id: "planning-operation".into(),
            project_id: task.project_id.clone(),
            task_id: task.task_id.clone(),
            task_revision: task.task_revision,
            attempt_id: "pending-attempt".into(),
            lease_id: "pending-lease".into(),
            generation: 1,
            worker_id: "pending-worker".into(),
            workspace_root: "/tmp/managed-repository".into(),
            base_sha: "a".repeat(40),
            context_manifest: ContextManifestRef {
                artifact_id: "context".into(),
                sha256: "b".repeat(64),
                mandatory_paths: spec.mandatory_paths.clone(),
                rendered_utf8_bytes: 64,
                token_estimate: None,
                tokenizer_id: None,
            },
            write_set: task.write_set.clone(),
            prompt_artifact: ArtifactRef {
                artifact_id: "prompt".into(),
                sha256: "c".repeat(64),
            },
            model_route_id: "newapi/glm-5.3".into(),
            executor_profile_id: spec.execution_profile.clone(),
            resource_profile_id: "planning-resource".into(),
            verification_plan_id: verification.plan_id.clone(),
            allowed_effects: vec![
                AllowedEffect::ReadWorkspace,
                AllowedEffect::RunApprovedCommands,
                AllowedEffect::RequestApprovedModel,
            ],
            issued_at: "2026-10-10T00:00:00Z".into(),
            expires_at: "2026-10-10T00:00:30Z".into(),
            deadline_at: "2026-10-10T00:30:00Z".into(),
            artifact_prefix: "/tmp/artifacts/planning".into(),
            secret_refs: vec![],
            idempotency_key: "planning".into(),
            trace_id: "planning".into(),
            enforcement: Enforcement {
                model_budget_mode: ModelBudgetMode::DirectObserved,
                stage_resource_mode: StageResourceMode::AttemptReservation,
                build_capable: false,
                gateway_coverage_receipt_id: None,
                tool_guard_receipt_id: None,
                attempt_reserved_build_permits: 0,
                all_model_routes_covered: false,
                disabled_tool_entry_ids: vec![],
            },
            session_purpose: SessionPurpose::Planning,
            max_model_requests: PLANNING_MAX_MODEL_REQUESTS,
            resume_session_id: None,
            command: None,
        });
        let envelope = task.envelope.as_ref().unwrap();
        envelope.validate().unwrap();
        assert_eq!(envelope.max_model_requests, 8);
        assert_eq!(envelope.verification_plan_id, spec.verification_plan);
        bootstrap.flow.input_digest =
            forgeflow_planner::semantic_digest(&bootstrap.flow, &bootstrap.context);
        let report = forgeflow_planner::compile(&bootstrap.flow, &bootstrap.context);
        assert!(report.passed, "{report:?}");

        // Retaining the old zero-reservation task identity must fail compilation.
        bootstrap.flow.tasks[0].input_digest = original_digest;
        bootstrap.flow.input_digest =
            forgeflow_planner::semantic_digest(&bootstrap.flow, &bootstrap.context);
        assert!(!forgeflow_planner::compile(&bootstrap.flow, &bootstrap.context).passed);
    }

    #[test]
    fn planning_model_budget_requires_provider_capacity_in_every_ancestor() {
        let (mut bootstrap, mut verification) = planning_fixture();
        bind_planning_model_budget(&mut bootstrap, &mut verification).unwrap();
        let task = &bootstrap.flow.tasks[0];
        let mut scopes: Vec<_> = ["global", "project", "root-team", "planning-team", "worker"]
            .into_iter()
            .enumerate()
            .map(|(index, id)| ScopeSnapshot {
                policy: ResourcePolicy {
                    scope_id: id.into(),
                    parent_scope_id: index.checked_sub(1).map(|parent| {
                        ["global", "project", "root-team", "planning-team"][parent].into()
                    }),
                    project_id: (index > 0).then(|| task.project_id.clone()),
                    team_id: (index == 2 || index == 3).then(|| id.into()),
                    worker_id: (index == 4).then(|| "pending-worker".into()),
                    limits: ResourceVector {
                        active_slot: 1,
                        provider_inflight: 1,
                        ..Default::default()
                    },
                    revision: 1,
                    paused: false,
                },
                allocated: ResourceVector::default(),
            })
            .collect();
        assert!(capacity_blockers(&task.task_id, &task.resource_request, &scopes).is_empty());
        for index in 0..scopes.len() {
            scopes[index].policy.limits.provider_inflight = 0;
            let blocked = capacity_blockers(&task.task_id, &task.resource_request, &scopes);
            assert_eq!(blocked.len(), 1);
            assert_eq!(blocked[0].code, "CAPACITY_EXHAUSTED");
            assert_eq!(
                blocked[0].scope_id.as_deref(),
                Some(scopes[index].policy.scope_id.as_str())
            );
            assert_eq!(blocked[0].dimension.as_deref(), Some("provider_inflight"));
            scopes[index].policy.limits.provider_inflight = 1;
            scopes[index].allocated.provider_inflight = 1;
            assert_eq!(
                capacity_blockers(&task.task_id, &task.resource_request, &scopes).len(),
                1
            );
            scopes[index].allocated.provider_inflight = 0;
        }
    }
}
