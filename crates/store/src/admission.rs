use super::*;
use std::collections::BTreeSet;
impl Store {
    pub async fn admit(&self, request: AdmissionRequest) -> Result<AdmissionReceipt> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let result = admit_tx(&mut tx, request).await?;
        tx.commit().await?;
        Ok(result)
    }
}
impl Store {
    pub async fn dependency_ready(
        &self,
        p: &str,
        flow: u64,
        task: &str,
        dependency: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let ready = dependency_ready_tx(&mut tx, p, flow, task, dependency).await?;
        tx.commit().await?;
        Ok(ready)
    }
}
pub(crate) async fn dependency_ready_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    flow: u64,
    task: &str,
    dependency: &str,
) -> Result<bool> {
    let v:Option<Value>=sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(p).bind(flow.to_string()).fetch_optional(&mut **tx).await?;
    let Some(v) = v else { return Ok(false) };
    let context: forgeflow_planner::CompileContext = decode(v)?;
    let Some(spec) = context.task_specs.get(task) else {
        return Ok(false);
    };
    let refs: Vec<_> = spec
        .dependency_refs
        .iter()
        .filter(|d| d.task_id == dependency)
        .collect();
    if refs.is_empty() {
        return Ok(false);
    };
    for dependency in refs {
        if dependency.project_id != p {
            return Ok(false);
        };
        let mut ready:bool=match dependency.kind {
            forgeflow_planner::DependencyKind::Integrated=>sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts a JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id AND t.task_revision=a.task_revision JOIN merge_intents m ON m.project_id=a.project_id AND m.attempt_id=a.attempt_id WHERE a.project_id=$1 AND a.task_id=$2 AND a.state='SUCCEEDED' AND t.flow_revision=$3 AND m.state IN('FINALIZED','COMMITTED') AND m.data->>'integrated_sha' IS NOT NULL)").bind(p).bind(&dependency.task_id).bind(i64v(flow)?).fetch_one(&mut **tx).await?,
            forgeflow_planner::DependencyKind::Artifact=>sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts a JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id AND t.task_revision=a.task_revision JOIN evidence_receipts e ON e.project_id=a.project_id AND e.attempt_id=a.attempt_id AND e.generation=a.generation WHERE a.project_id=$1 AND a.task_id=$2 AND a.state='SUCCEEDED' AND t.flow_revision=$3 AND e.kind='STRUCTURED_ARTIFACT' AND e.data->'artifact'->>'artifact_id'=$4)").bind(p).bind(&dependency.task_id).bind(i64v(flow)?).bind(&dependency.binding_id).fetch_one(&mut **tx).await?,
            forgeflow_planner::DependencyKind::ContractFrozen=>sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contract_versions WHERE project_id=$1 AND state='FROZEN' AND contract_id||':'||version::text=$2 AND data->>'producer_task_id'=$3)").bind(p).bind(&dependency.binding_id).bind(&dependency.task_id).fetch_one(&mut **tx).await?,
            forgeflow_planner::DependencyKind::GatePass=>sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gate_runs WHERE project_id=$1 AND gate_run_id=$2 AND status='PASS' AND data->>'task_id'=$3)").bind(p).bind(&dependency.binding_id).bind(&dependency.task_id).fetch_one(&mut **tx).await?,
        };
        if !ready
            && matches!(
                dependency.kind,
                forgeflow_planner::DependencyKind::Integrated
            )
        {
            ready =
                crate::catalog::retained_candidate_dependency_ready_tx(tx, p, &dependency.task_id)
                    .await?;
        }
        if !ready {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn admit_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: AdmissionRequest,
) -> Result<AdmissionReceipt> {
    let request_json = json(&request)?;
    if let Some(v) = replay(
        tx,
        &request.actor_id,
        "admit",
        &request.idempotency_key,
        &request_json,
    )
    .await?
    {
        let mut receipt: AdmissionReceipt = decode(v)?;
        receipt.replayed = true;
        return Ok(receipt);
    }
    let p = project_lock(tx, &request.project_id).await?;
    if p.authority_mode != AuthorityMode::Managed || p.paused || p.archived {
        return Err(err(
            "ADMISSION_BLOCKED",
            "project must be managed, active and unpaused",
        ));
    }
    crate::catalog::assert_managed_repository_unique(tx, &p.project_id, &p.root_path).await?;
    let flow: FlowRevision = decode(
        sqlx::query_scalar(
            "SELECT data FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2 FOR UPDATE",
        )
        .bind(&p.project_id)
        .bind(i64v(request.flow_revision)?)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "flow not found"))?,
    )?;
    if flow.state != FlowState::Committed {
        return Err(err(
            "FLOW_NOT_COMMITTED",
            "admission requires committed planning revision",
        ));
    }
    let context_value:Value=sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2 FOR UPDATE").bind(&p.project_id).bind(request.flow_revision.to_string()).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","committed context snapshot missing"))?;
    let context: forgeflow_planner::CompileContext = decode(context_value)?;
    crate::catalog::validate_authoritative_context(tx, &p.project_id, &context).await?;
    let row = sqlx::query(
        "SELECT data,fence_epoch FROM tasks WHERE project_id=$1 AND task_id=$2 FOR UPDATE",
    )
    .bind(&p.project_id)
    .bind(&request.task_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| err("NOT_FOUND", "task not found"))?;
    let task: TaskCard = decode(row.try_get("data")?)?;
    if task.task_revision != request.task_revision || task.flow_revision != request.flow_revision {
        return Err(err(
            "REVISION_CONFLICT",
            "task revision changed after preflight",
        ));
    }
    if task.input_digest != request.input_digest {
        return Err(err("CONTEXT_STALE", "input digest changed after preflight"));
    }
    if task.state != TaskPlanningState::ReadyForAdmission {
        return Err(err("ADMISSION_BLOCKED", "task planning state is not ready"));
    }
    crate::catalog::validate_native_panel_enqueue(tx, &task).await?;
    let open:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND task_id=$2 AND terminal_at IS NULL)").bind(&p.project_id).bind(&task.task_id).fetch_one(&mut **tx).await?;
    if open {
        return Err(err(
            "ATTEMPT_ALREADY_ACTIVE",
            "task already has an open attempt",
        ));
    }
    let paused:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM owner_closure c JOIN owner_nodes n ON n.project_id=c.project_id AND n.owner_id=c.ancestor_id WHERE c.project_id=$1 AND c.descendant_id=$2 AND n.paused)").bind(&p.project_id).bind(&task.team_id).fetch_one(&mut **tx).await?;
    if paused {
        return Err(err("ADMISSION_BLOCKED", "team ancestor paused"));
    }
    for dep in &task.dependencies {
        let ready =
            dependency_ready_tx(tx, &p.project_id, task.flow_revision, &task.task_id, dep).await?;
        if !ready {
            return Err(err(
                "DEPENDENCY_UNSATISFIED",
                format!("dependency {dep} lacks current verified success"),
            ));
        }
    }
    // Isolated attempts never share intersecting mutable paths while old processes may live.
    let active:Vec<Value>=sqlx::query_scalar("SELECT envelope FROM attempts WHERE project_id=$1 AND terminal_at IS NULL ORDER BY attempt_id").bind(&p.project_id).fetch_all(&mut **tx).await?;
    for v in active {
        let e: ExecutionEnvelope = decode(v)?;
        if task
            .write_set
            .iter()
            .any(|a| e.write_set.iter().any(|b| paths_overlap(a, b)))
        {
            return Err(err(
                "OWNER_PATH_VIOLATION",
                "write set intersects an active or quarantined attempt",
            ));
        }
    }
    let frozen = task.envelope.as_ref().ok_or_else(|| {
        err(
            "EXECUTOR_UNQUALIFIED",
            "task must bind an approved execution template",
        )
    })?;
    let mut bindings = serde_json::Map::new();
    for (collection, key, profile_id) in [
        (
            "executor_profiles",
            "executor_profile",
            &frozen.executor_profile_id,
        ),
        (
            "resource_profiles",
            "resource_profile",
            &frozen.resource_profile_id,
        ),
        ("model_routes", "model_route", &frozen.model_route_id),
        (
            "verification_plans",
            "verification_plan",
            &frozen.verification_plan_id,
        ),
    ] {
        let value:Value=sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3 FOR SHARE").bind(&p.project_id).bind(collection).bind(profile_id).fetch_optional(&mut **tx).await?.ok_or_else(||err("EXECUTOR_UNQUALIFIED",format!("registered immutable {collection}/{profile_id} required")))?;
        bindings.insert(key.into(), value);
    }
    let plan: forgeflow_evidence::VerificationPlan = decode(bindings["verification_plan"].clone())?;
    if plan.plan_id != frozen.verification_plan_id
        || plan.task_revision != task.task_revision
        || plan.input_hash != task.input_digest
        || plan.commands.is_empty()
        || plan.verifier_id == plan.author_id
    {
        return Err(err(
            "VERIFIER_INVALID",
            "registered verification plan must bind task semantics and independent commands",
        ));
    }
    let roles: std::collections::BTreeSet<_> = plan.commands.iter().map(|c| c.role).collect();
    if roles.len() != 3 {
        return Err(err(
            "VERIFIER_INVALID",
            "verification plan must include author, consumer and independent commands",
        ));
    }
    if !task.write_set.is_empty() && task.resource_request.coding_slot == 0 {
        return Err(err(
            "VALIDATION_ERROR",
            "code-writing attempt must reserve a coding slot",
        ));
    }
    if bindings["executor_profile"]
        .get("id")
        .and_then(Value::as_str)
        != Some(&frozen.executor_profile_id)
    {
        return Err(err(
            "EXECUTOR_UNQUALIFIED",
            "registered executor profile identity mismatch",
        ));
    }
    bindings.insert(
        "dispatch_contract".into(),
        Value::String("CLAIM_BEFORE_EFFECTS_V1".into()),
    );
    let task_spec = context.task_specs.get(&task.task_id).ok_or_else(|| {
        err(
            "EVIDENCE_INCOMPLETE",
            "committed task specification missing",
        )
    })?;
    if let Some(root) =
        native_root_binding(tx, &task, task_spec, &bindings["executor_profile"]).await?
    {
        bindings.insert("native_root_binding".into(), root);
    }
    if let Some(retained) = crate::catalog::retained_candidate_task_binding_tx(tx, &task).await? {
        let consumed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND execution_bindings->'retained_native_candidate'->>'authorization_id'=$2)")
            .bind(&task.project_id).bind(retained["authorization_id"].as_str().unwrap_or("")).fetch_one(&mut **tx).await?;
        if consumed {
            return Err(err(
                "RETAINED_REVIEW_ALREADY_ADMITTED",
                "retained candidate authorization has already created its one actual review attempt",
            ));
        }
        bindings.insert("retained_native_candidate".into(), retained);
    }
    if bindings["executor_profile"]["kind"] == "DSH_MANAGED" {
        let retry = crate::catalog::native_panel_retry_policy_in_transaction(
            tx,
            &task.project_id,
            &task.task_id,
            task.task_revision,
        )
        .await?;
        if retry["blocked"] == true {
            return Err(err(
                "NATIVE_RETRY_REQUIRED",
                "Native cancellation prevents automatic reuse of this semantic revision",
            ));
        }
        if retry["explicit_retry_authorized"] == true {
            bindings.insert("native_retry_authorization".into(),serde_json::json!({
                "schema_version":"forgeflow.native-retry-authorization.v1","action_id":retry["retry_action_id"],
                "target_attempt_id":retry["retry_attempt_id"],"task_revision":task.task_revision,
                "request_sequence":retry["retry_sequence"],"cancel_action_id":retry["cancel_action_id"]}));
        }
    }
    let mut execution_bindings = Value::Object(bindings);
    let physical = super::collaboration::physical_binding_from_profile(
        &execution_bindings["resource_profile"],
        &frozen.resource_profile_id,
        &task.resource_request,
    )?;
    let reserved_resources = physical
        .as_ref()
        .map(|p| p.reserved_resources.clone())
        .unwrap_or_else(|| task.resource_request.clone());
    if let Some(physical) = physical {
        execution_bindings["physical_resources"] = serde_json::to_value(physical)?;
    }
    if frozen.workspace_root != p.root_path {
        return Err(err(
            "AUTHORITY_SCOPE_VIOLATION",
            "execution repository must equal authoritative project root",
        ));
    }
    let supplied = &request.envelope;
    if supplied.base_sha != frozen.base_sha
        || supplied.context_manifest != frozen.context_manifest
        || supplied.prompt_artifact != frozen.prompt_artifact
        || supplied.model_route_id != frozen.model_route_id
        || supplied.executor_profile_id != frozen.executor_profile_id
        || supplied.resource_profile_id != frozen.resource_profile_id
        || supplied.verification_plan_id != frozen.verification_plan_id
        || supplied.allowed_effects != frozen.allowed_effects
        || supplied.deadline_at != frozen.deadline_at
        || supplied.artifact_prefix != frozen.artifact_prefix
        || supplied.secret_refs != frozen.secret_refs
        || supplied.enforcement != frozen.enforcement
        || supplied.session_purpose != frozen.session_purpose
        || supplied.max_model_requests != frozen.max_model_requests
        || supplied.resume_session_id != frozen.resume_session_id
        || supplied.command != frozen.command
        || supplied.workspace_root != frozen.workspace_root
    {
        return Err(err(
            "CONTEXT_STALE",
            "submitted execution configuration differs from approved frozen task template",
        ));
    }
    let registered:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workers WHERE worker_id=$1 AND heartbeat_at>clock_timestamp()-interval '2 minutes')").bind(&request.worker_id).fetch_one(&mut **tx).await?;
    if !registered {
        return Err(err(
            "WORKER_STALE",
            "target worker must be registered and live",
        ));
    }
    let worker = sqlx::query(
        "SELECT project_id,executor_profile_ids FROM workers WHERE worker_id=$1 FOR SHARE",
    )
    .bind(&request.worker_id)
    .fetch_one(&mut **tx)
    .await?;
    let worker_project: Option<String> = worker.try_get("project_id")?;
    let profiles: Vec<String> = decode(worker.try_get("executor_profile_ids")?)?;
    if worker_project.as_deref() != Some(&p.project_id)
        || !profiles.contains(&frozen.executor_profile_id)
    {
        return Err(err(
            "WORKER_SCOPE_MISMATCH",
            "worker must be registered for this exact project and frozen executor profile",
        ));
    }
    if task.resource_request.active_slot < 1 {
        return Err(err(
            "VALIDATION_ERROR",
            "every admitted session consumes an active slot",
        ));
    }
    if request.envelope.enforcement.build_capable
        && task.resource_request.build_permit
            < u64::from(request.envelope.enforcement.attempt_reserved_build_permits)
    {
        return Err(err(
            "CAPACITY_EXHAUSTED",
            "task build request does not cover frozen reserved permits",
        ));
    }
    let scope_rows=sqlx::query("WITH RECURSIVE selected AS (SELECT scope_id,parent_scope_id FROM resource_scopes WHERE (project_id IS NULL AND worker_id IS NULL) OR worker_id=$3 OR (project_id=$1 AND (team_id IS NULL OR team_id IN(SELECT ancestor_id FROM owner_closure WHERE project_id=$1 AND descendant_id=$2))) UNION SELECT s.scope_id,s.parent_scope_id FROM resource_scopes s JOIN selected c ON s.scope_id=c.parent_scope_id) SELECT DISTINCT scope_id FROM selected ORDER BY scope_id").bind(&p.project_id).bind(&task.team_id).bind(&request.worker_id).fetch_all(&mut **tx).await?;
    let scopes: BTreeSet<String> = scope_rows.into_iter().map(|r| r.get("scope_id")).collect();
    let has_global:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_scopes WHERE project_id IS NULL AND worker_id IS NULL)").fetch_one(&mut **tx).await?;
    if scopes.is_empty() || !has_global {
        return Err(err(
            "CAPACITY_UNCONFIGURED",
            "explicit global resource policy required",
        ));
    }
    let worker_policy: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_scopes WHERE worker_id=$1)")
            .bind(&request.worker_id)
            .fetch_one(&mut **tx)
            .await?;
    if !worker_policy {
        return Err(err(
            "CAPACITY_UNCONFIGURED",
            "worker resource policy required",
        ));
    }
    let missing_ancestor:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM owner_closure c WHERE c.project_id=$1 AND c.descendant_id=$2 AND NOT EXISTS(SELECT 1 FROM resource_scopes s WHERE s.project_id=c.project_id AND s.team_id=c.ancestor_id))").bind(&p.project_id).bind(&task.team_id).fetch_one(&mut **tx).await?;
    if missing_ancestor {
        return Err(err(
            "CAPACITY_UNCONFIGURED",
            "every team ancestor requires explicit resource policy",
        ));
    }
    let mut policy_checked = false;
    for scope in &scopes {
        let row=sqlx::query("SELECT revision,paused,project_id,team_id FROM resource_scopes WHERE scope_id=$1 FOR UPDATE").bind(scope).fetch_one(&mut **tx).await?;
        if row.get::<bool, _>("paused") {
            return Err(err("ADMISSION_BLOCKED", "resource ancestor paused"));
        }
        if row.get::<Option<String>, _>("project_id").as_deref() == Some(&p.project_id)
            && row.get::<Option<String>, _>("team_id").is_none()
        {
            if row.get::<i64, _>("revision") as u64 != request.policy_revision {
                return Err(err("REVISION_CONFLICT", "project policy changed"));
            }
            policy_checked = true;
        }
        for (dimension, amount) in reserved_resources.dimensions() {
            let limit=sqlx::query("SELECT hard_limit,allocated FROM resource_limits WHERE scope_id=$1 AND dimension=$2 FOR UPDATE").bind(scope).bind(dimension).fetch_one(&mut **tx).await?;
            if amount > 0
                && i64v(amount)?
                    > limit
                        .get::<i64, _>("hard_limit")
                        .saturating_sub(limit.get::<i64, _>("allocated"))
            {
                return Err(err(
                    "CAPACITY_EXHAUSTED",
                    format!("{scope}/{dimension} exhausted or draining"),
                ));
            }
        }
    }
    if !policy_checked {
        return Err(err(
            "CAPACITY_UNCONFIGURED",
            "explicit project resource policy required",
        ));
    }
    let generation = row
        .get::<i64, _>("fence_epoch")
        .checked_add(1)
        .ok_or_else(|| err("GENERATION_EXHAUSTED", "generation overflow"))?;
    let deadline = DateTime::parse_from_rfc3339(&request.envelope.deadline_at)
        .map_err(|_| err("VALIDATION_ERROR", "invalid deadline"))?
        .with_timezone(&Utc);
    if request.lease_seconds == 0 || request.lease_seconds > 3600 {
        return Err(err("VALIDATION_ERROR", "lease TTL must be 1..3600 seconds"));
    }
    let mut envelope = frozen.clone();
    crate::materialization::materialize(
        tx,
        &p,
        &task,
        &context,
        &mut envelope,
        &mut execution_bindings,
    )
    .await?;
    // Resolving approved producer inputs can inspect files and immutable Git
    // objects. Lease TTL begins after that preparation completes.
    let now = db_now(tx).await?;
    let expires = (now + chrono::Duration::seconds(i64::from(request.lease_seconds))).min(deadline);
    envelope.operation_id = id();
    envelope.attempt_id = id();
    envelope.lease_id = id();
    envelope.project_id = p.project_id.clone();
    envelope.task_id = task.task_id.clone();
    envelope.task_revision = task.task_revision;
    envelope.generation = generation;
    if let Some(retained) = execution_bindings.get_mut("retained_native_candidate") {
        retained["target"]["attempt_id"] = serde_json::json!(envelope.attempt_id);
        retained["target"]["generation"] = serde_json::json!(generation);
    }
    envelope.worker_id = request.worker_id.clone();
    envelope.write_set = task.write_set.clone();
    envelope.idempotency_key = request.idempotency_key.clone();
    envelope.issued_at = now.to_rfc3339();
    envelope.expires_at = expires.to_rfc3339();
    crate::handoff::strict_admission_guard(tx, &p.project_id, &task, &envelope, &request.worker_id)
        .await?;
    envelope.validate()?;
    let a = Attempt {
        project_id: p.project_id.clone(),
        task_id: task.task_id.clone(),
        task_revision: task.task_revision,
        attempt_id: envelope.attempt_id.clone(),
        lease_id: envelope.lease_id.clone(),
        generation,
        worker_id: envelope.worker_id.clone(),
        operation_id: envelope.operation_id.clone(),
        base_sha: envelope.base_sha.clone(),
        state: AttemptState::Leased,
        revision: 1,
        created_at: now,
        terminal_at: None,
        result: None,
    };
    sqlx::query("UPDATE tasks SET fence_epoch=$3 WHERE project_id=$1 AND task_id=$2")
        .bind(&p.project_id)
        .bind(&task.task_id)
        .bind(generation)
        .execute(&mut **tx)
        .await?;
    crate::capsules::freeze_binding_tx(tx, &envelope, &mut execution_bindings).await?;
    let executor_profile_sha256 = crate::execution_bindings::freeze_profile_tx(
        tx,
        &a.project_id,
        &envelope.executor_profile_id,
        &mut execution_bindings,
    )
    .await?;
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,created_at,data,envelope,execution_bindings,executor_profile_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'LEASED',1,$9,$10,$11,$12,$13)").bind(&a.project_id).bind(&a.attempt_id).bind(&a.task_id).bind(i64v(a.task_revision)?).bind(&a.lease_id).bind(generation).bind(&a.worker_id).bind(&a.operation_id).bind(now).bind(json(&a)?).bind(json(&envelope)?).bind(execution_bindings).bind(executor_profile_sha256).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO leases(project_id,lease_id,attempt_id,generation,worker_id,capability_scope,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(&a.project_id).bind(&a.lease_id).bind(&a.attempt_id).bind(generation).bind(&a.worker_id).bind(json(&envelope.write_set)?).bind(now).bind(expires).execute(&mut **tx).await?;
    for scope in &scopes {
        for (dimension, amount) in reserved_resources.dimensions() {
            if amount == 0 {
                continue;
            }
            sqlx::query("UPDATE resource_limits SET allocated=allocated+$3 WHERE scope_id=$1 AND dimension=$2").bind(scope).bind(dimension).bind(i64v(amount)?).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO resource_allocations(allocation_id,project_id,attempt_id,scope_id,dimension,amount,state) VALUES($1,$2,$3,$4,$5,$6,'RESERVED')").bind(id()).bind(&a.project_id).bind(&a.attempt_id).bind(scope).bind(dimension).bind(i64v(amount)?).execute(&mut **tx).await?;
        }
    }
    event(
        tx,
        &p.project_id,
        &a.attempt_id,
        1,
        "attempt.leased",
        json(&a)?,
    )
    .await?;
    outbox(
        tx,
        &p.project_id,
        &a.operation_id,
        "attempt.start",
        json(&envelope)?,
    )
    .await?;
    let receipt = AdmissionReceipt {
        operation_id: a.operation_id.clone(),
        attempt: a,
        envelope,
        replayed: false,
    };
    save_replay(
        tx,
        &request.actor_id,
        "admit",
        &request.idempotency_key,
        &receipt.operation_id,
        &request_json,
        &json(&receipt)?,
    )
    .await?;
    Ok(receipt)
}

/// The role marker is part of TaskSpec's canonical semantic digest. A shared
/// profile never substitutes its default lead for the reviewed task position.
pub(crate) async fn native_root_binding(
    tx: &mut Transaction<'_, Postgres>,
    task: &TaskCard,
    spec: &forgeflow_planner::TaskSpec,
    profile: &Value,
) -> Result<Option<Value>> {
    let markers: Vec<_> = spec
        .design_anchors
        .iter()
        .filter_map(|anchor| anchor.strip_prefix("forgeflow:native-root:v1:"))
        .collect();
    if profile["kind"] != "DSH_MANAGED" {
        if !markers.is_empty() {
            return Err(err(
                "NATIVE_ROOT_BINDING_INVALID",
                "native root marker requires a managed DSH profile",
            ));
        }
        return Ok(None);
    }
    let mode_path = profile["native_mode"]["mode_manifest"]
        .as_str()
        .map(std::path::PathBuf::from);
    let Some(mode_path) = mode_path else {
        if !markers.is_empty() {
            return Err(err(
                "NATIVE_ROOT_BINDING_INVALID",
                "managed mode manifest is missing",
            ));
        }
        return Ok(None);
    };
    let mode = pinned_profile_json(profile, &mode_path)?;
    let policy = mode["native_root_binding_policy"].as_str();
    if policy.is_some_and(|policy| policy != "IMPORTED_PLANNING_ROLE_V1") {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "unsupported native root binding policy",
        ));
    }
    if markers.is_empty() && policy.is_none() {
        return Ok(None);
    }
    if markers.len() != 1
        || mode["schema_version"] != "forgeflow.dsh-mode.v3"
        || mode["role_catalog"]["path"] != "agent-roles.json"
        || task.input_digest != forgeflow_planner::canonical_task_input_digest(task, spec)
    {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "one reviewed digest-bound native root position is required",
        ));
    }
    let (position, claimed_hash) = markers[0]
        .split_once(':')
        .filter(|(position, hash)| {
            !position.is_empty() && valid_digest(hash) && hash.bytes().any(|b| b != b'0')
        })
        .ok_or_else(|| {
            err(
                "NATIVE_ROOT_BINDING_INVALID",
                "native root position/catalog marker is malformed",
            )
        })?;
    let catalog_path = mode_path
        .parent()
        .ok_or_else(|| {
            err(
                "NATIVE_ROOT_BINDING_INVALID",
                "mode manifest parent missing",
            )
        })?
        .join("agent-roles.json");
    let (catalog, catalog_hash) = pinned_profile_json_and_hash(profile, &catalog_path)?;
    if catalog_hash != claimed_hash
        || !crate::role_catalog::valid_catalog(&catalog, &task.project_id)
    {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "frozen native role catalog differs from the reviewed project and marker",
        ));
    }
    let roster = catalog["roster"].as_array().unwrap();
    let role_rows: Vec<_> = roster
        .iter()
        .filter(|row| row["position_id"].as_str() == Some(position))
        .collect();
    if role_rows.len() != 1 {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "native position is missing or duplicated in the frozen catalog",
        ));
    }
    let role = role_rows[0];
    let preset = role["preset_id"]
        .as_str()
        .filter(|preset| !preset.is_empty())
        .ok_or_else(|| {
            err(
                "NATIVE_ROOT_BINDING_INVALID",
                "native role preset is missing",
            )
        })?;
    if role["owner_id"].as_str() != Some(&task.owner_id)
        || role["owner_team_id"].as_str() != Some(&task.team_id)
    {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "native root position does not belong to the actual task Owner and team",
        ));
    }
    let source_markers: Vec<_> = spec
        .design_anchors
        .iter()
        .filter_map(|anchor| anchor.strip_prefix("forgeflow:native-root-planning-card:"))
        .collect();
    if source_markers.len() > 1 || source_markers.first().is_some_and(|id| id.is_empty()) {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "auxiliary planning card provenance must be singular and explicit",
        ));
    }
    let planning_id = source_markers.first().copied().unwrap_or(&task.task_id);
    let imported:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='planning_cards' AND document_id=$2 FOR SHARE")
        .bind(&task.project_id).bind(planning_id).fetch_optional(&mut **tx).await?
        .ok_or_else(||err("NATIVE_ROOT_BINDING_INVALID","native role requires an actual typed planning card or explicit auxiliary source card"))?;
    let planned_task: TaskCard = decode(imported["task"].clone())?;
    let planned_spec: forgeflow_planner::TaskSpec = decode(imported["spec"].clone())?;
    let source_card = &imported["metadata"]["source_card"];
    let source_hash = imported["metadata"]["source_card_sha256"].as_str();
    if imported["schema_version"] != "forgeflow.planning.card.v1"
        || imported["planning_only"] != true
        || imported["project_id"].as_str() != Some(&task.project_id)
        || imported["task_id"].as_str() != Some(planning_id)
        || planned_task.project_id != task.project_id
        || planned_task.task_id != planning_id
        || planned_task.input_digest
            != forgeflow_planner::canonical_task_input_digest(&planned_task, &planned_spec)
        || !source_card.is_object()
        || source_hash
            != Some(forgeflow_planner::sha256(&serde_json::to_vec(source_card)?).as_str())
    {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "typed planning card identity, semantic digest or original source hash differs",
        ));
    }
    let planning_catalog_id = imported["catalog_id"].as_str().ok_or_else(|| {
        err(
            "NATIVE_ROOT_BINDING_INVALID",
            "planning catalog identity missing",
        )
    })?;
    let planning_catalog:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='planning_catalogs' AND document_id=$2 FOR SHARE")
        .bind(&task.project_id).bind(planning_catalog_id).fetch_optional(&mut **tx).await?
        .ok_or_else(||err("NATIVE_ROOT_BINDING_INVALID","typed planning catalog missing"))?;
    if planning_catalog["source_revision"] != imported["source_revision"]
        || !planning_catalog["task_ids"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(planning_id)))
        || !planning_catalog["roster"].as_array().is_some_and(|roles| {
            roles.iter().any(|row| {
                row["agent_id"].as_str() == Some(position)
                    && row["owner_id"].as_str() == Some(&task.owner_id)
                    && row["team_id"].as_str() == Some(&task.team_id)
            })
        })
    {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "planning card provenance or selected roster Owner/team differs",
        ));
    }
    if planning_id == task.task_id
        && (imported["metadata"]["role_id"].as_str() != Some(position)
            || planned_task.owner_id != task.owner_id
            || planned_task.team_id != task.team_id)
    {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "native root position differs from the actual imported card assignment",
        ));
    }
    Ok(Some(
        serde_json::json!({"schema_version":"forgeflow.native-root-binding.v1",
        "project_id":task.project_id,"task_id":task.task_id,"task_revision":task.task_revision,
        "input_digest":task.input_digest,"owner_id":task.owner_id,"team_id":task.team_id,
        "position_id":position,"preset_id":preset,"catalog_sha256":catalog_hash,"planning_card_id":planning_id}),
    ))
}

fn pinned_profile_json(profile: &Value, path: &std::path::Path) -> Result<Value> {
    pinned_profile_json_and_hash(profile, path).map(|(value, _)| value)
}
fn pinned_profile_json_and_hash(
    profile: &Value,
    path: &std::path::Path,
) -> Result<(Value, String)> {
    use std::io::Read;
    if !path.is_absolute() {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "frozen profile source path must be absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        err(
            "NATIVE_ROOT_BINDING_INVALID",
            "frozen native profile source is unavailable",
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1_048_576 {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "frozen native profile source must be a bounded regular file",
        ));
    }
    let canonical = path.canonicalize().map_err(|_| {
        err(
            "NATIVE_ROOT_BINDING_INVALID",
            "frozen native profile source cannot be resolved",
        )
    })?;
    let pins: Vec<_> = profile["artifact_pins"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|pin| {
            pin["path"]
                .as_str()
                .is_some_and(|path| std::path::Path::new(path) == canonical)
        })
        .collect();
    if pins.len() != 1 {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "native profile must contain one exact immutable source pin",
        ));
    }
    let hash = pins[0]["sha256"]
        .as_str()
        .filter(|hash| valid_digest(hash) && hash.bytes().any(|b| b != b'0'))
        .ok_or_else(|| {
            err(
                "NATIVE_ROOT_BINDING_INVALID",
                "native source pin digest is invalid",
            )
        })?;
    let mut bytes = Vec::new();
    std::fs::File::open(&canonical)
        .and_then(|file| file.take(1_048_577).read_to_end(&mut bytes))
        .map_err(|_| {
            err(
                "NATIVE_ROOT_BINDING_INVALID",
                "native profile source could not be read",
            )
        })?;
    if bytes.len() > 1_048_576 || forgeflow_planner::sha256(&bytes) != hash {
        return Err(err(
            "NATIVE_ROOT_BINDING_INVALID",
            "native profile source bytes differ from the immutable pin",
        ));
    }
    Ok((serde_json::from_slice(&bytes)?, hash.to_owned()))
}
