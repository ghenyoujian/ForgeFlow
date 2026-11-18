use super::*;
impl Store {
    pub async fn list_projects(&self) -> Result<Vec<Project>> {
        self.all("SELECT data FROM projects ORDER BY project_id", None)
            .await
    }
    pub async fn get_project(&self, p: &str) -> Result<Project> {
        self.one("SELECT data FROM projects WHERE project_id=$1", p, None)
            .await
    }
    pub async fn list_requirements(&self, p: &str) -> Result<Vec<Requirement>> {
        self.all(
            "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id",
            Some(p),
        )
        .await
    }
    pub async fn list_teams(&self, p: &str) -> Result<Vec<Team>> {
        self.all(
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
            Some(p),
        )
        .await
    }
    pub async fn list_tasks(&self, p: &str) -> Result<Vec<TaskCard>> {
        self.all(
            "SELECT data FROM tasks WHERE project_id=$1 ORDER BY task_id",
            Some(p),
        )
        .await
    }
    pub async fn get_task(&self, p: &str, t: &str) -> Result<TaskCard> {
        self.one(
            "SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2",
            p,
            Some(t),
        )
        .await
    }
    pub async fn list_flows(&self, p: &str) -> Result<Vec<FlowRevision>> {
        self.all(
            "SELECT data FROM flow_revisions WHERE project_id=$1 ORDER BY flow_revision",
            Some(p),
        )
        .await
    }
    pub async fn get_flow(&self, p: &str, r: u64) -> Result<FlowRevision> {
        let v: Option<Value> = sqlx::query_scalar(
            "SELECT data FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2",
        )
        .bind(p)
        .bind(i64v(r)?)
        .fetch_optional(&self.pool)
        .await?;
        decode(v.ok_or_else(|| err("NOT_FOUND", "flow not found"))?)
    }
    pub async fn list_attempts(&self, p: &str) -> Result<Vec<Attempt>> {
        self.all(
            "SELECT data FROM attempts WHERE project_id=$1 ORDER BY created_at,attempt_id",
            Some(p),
        )
        .await
    }
    pub async fn get_attempt(&self, p: &str, a: &str) -> Result<Attempt> {
        self.one(
            "SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2",
            p,
            Some(a),
        )
        .await
    }
    pub async fn resource_policies(&self, p: &str) -> Result<Vec<ResourcePolicy>> {
        self.all("SELECT data FROM resource_scopes WHERE project_id=$1 OR project_id IS NULL ORDER BY scope_id",Some(p)).await
    }
    pub async fn list_evidence(&self, p: &str) -> Result<Vec<EvidenceReceipt>> {
        self.all(
            "SELECT data FROM evidence_receipts WHERE project_id=$1 ORDER BY created_at",
            Some(p),
        )
        .await
    }
    pub async fn list_documents(&self, p: &str, c: &str) -> Result<Vec<Value>> {
        validate_collection(c)?;
        let rows:Vec<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection=$2 ORDER BY document_id").bind(p).bind(c).fetch_all(&self.pool).await?;
        Ok(rows)
    }
    pub async fn get_document(&self, p: &str, c: &str, id: &str) -> Result<Value> {
        validate_collection(c)?;
        sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3").bind(p).bind(c).bind(id).fetch_optional(&self.pool).await?.ok_or_else(||err("NOT_FOUND","document not found"))
    }
    /// Verification recovery reads original service receipts, never an operator's
    /// mutable projection of a verifier operation.
    pub async fn catalog_service_receipt(&self, actor: &str, key: &str) -> Result<Option<Value>> {
        if !matches!(
            actor,
            "verification-service"
                | "verification-recovery-service"
                | "native-configuration-service"
        ) {
            return Err(err(
                "AUTHORITY_SCOPE_VIOLATION",
                "unsupported verifier receipt service",
            ));
        }
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('request',request,'response',response) FROM idempotency_records WHERE actor_id=$1 AND operation='catalog' AND idempotency_key=$2")
            .bind(actor).bind(key).fetch_optional(&self.pool).await?)
    }
    pub async fn retained_native_candidate_source(
        &self,
        p: &str,
        source_attempt: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let source = retained_native_source_tx(&mut tx, p, source_attempt).await?;
        tx.commit().await?;
        Ok(source)
    }
    pub async fn retained_candidate_acceptances(&self, p: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT d.data || jsonb_build_object('revision',d.revision) FROM documents d JOIN tasks t ON t.project_id=d.project_id AND t.task_id=d.data->'source'->>'task_id' AND t.task_revision=(d.data->'source'->>'task_revision')::bigint AND t.input_digest=d.data->'source'->>'input_digest' JOIN attempts r ON r.project_id=d.project_id AND r.attempt_id=d.data->'review'->>'attempt_id' AND r.state='SUCCEEDED' JOIN merge_intents m ON m.project_id=d.project_id AND m.intent_id=d.data->'integration'->>'intent_id' AND m.state='FINALIZED' WHERE d.project_id=$1 AND d.collection='operations' AND d.document_id LIKE 'retained-candidate-acceptance:%' ORDER BY d.document_id")
            .bind(p).fetch_all(&self.pool).await?)
    }
    async fn all<T: DeserializeOwned>(&self, q: &str, p: Option<&str>) -> Result<Vec<T>> {
        let query = sqlx::query_scalar::<_, Value>(q);
        let vals = if let Some(p) = p {
            query.bind(p).fetch_all(&self.pool).await?
        } else {
            query.fetch_all(&self.pool).await?
        };
        vals.into_iter().map(decode).collect()
    }
    async fn one<T: DeserializeOwned>(&self, q: &str, p: &str, other: Option<&str>) -> Result<T> {
        let query = sqlx::query_scalar::<_, Value>(q).bind(p);
        let v = if let Some(other) = other {
            query.bind(other).fetch_optional(&self.pool).await?
        } else {
            query.fetch_optional(&self.pool).await?
        };
        decode(v.ok_or_else(|| err("NOT_FOUND", "object not found"))?)
    }
    pub async fn execute_command(
        &self,
        identity: CommandIdentity,
        command: CatalogCommand,
    ) -> Result<CommandResult> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        super::workspaces::authorize_account_catalog(
            &mut tx,
            &identity.actor_id,
            std::slice::from_ref(&command),
        )
        .await?;
        let request = json(&command)?;
        if let Some(r) = replay(
            &mut tx,
            &identity.actor_id,
            "catalog",
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            let mut r: CommandResult = decode(r)?;
            r.replayed = true;
            tx.commit().await?;
            return Ok(r);
        }
        let value = apply_catalog(&mut tx, command, &identity.actor_id).await?;
        let result = CommandResult {
            operation_id: id(),
            value,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &identity.actor_id,
            "catalog",
            &identity.idempotency_key,
            &result.operation_id,
            &request,
            &json(&result)?,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn trusted_catalog(&self, c: CatalogCommand) -> Result<Value> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let v = apply_catalog(&mut tx, c, "internal").await?;
        tx.commit().await?;
        Ok(v)
    }
    /// Install the bundled tutorial as one reviewed planning transaction. No execution grant.
    pub async fn install_tutorial_plan(
        &self,
        identity: CommandIdentity,
        project: &str,
        commands: Vec<CatalogCommand>,
    ) -> Result<CommandResult> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        super::workspaces::authorize_account_catalog(&mut tx, &identity.actor_id, &commands)
            .await?;
        project_lock(&mut tx, project).await?;
        let request = json(&commands)?;
        if let Some(value) = replay(
            &mut tx,
            &identity.actor_id,
            "tutorial",
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            let mut result: CommandResult = decode(value)?;
            result.replayed = true;
            tx.commit().await?;
            return Ok(result);
        }
        let occupied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flow_revisions WHERE project_id=$1) OR EXISTS(SELECT 1 FROM requirements WHERE project_id=$1) OR EXISTS(SELECT 1 FROM owner_nodes WHERE project_id=$1)")
            .bind(project).fetch_one(&mut *tx).await?;
        if occupied {
            return Err(err(
                "REVISION_CONFLICT",
                "tutorial requires an empty project; existing planning is preserved",
            ));
        }
        let mut value = Value::Null;
        for cmd in commands {
            value = apply_catalog(&mut tx, cmd, &identity.actor_id).await?;
        }
        let result = CommandResult {
            operation_id: id(),
            value,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &identity.actor_id,
            "tutorial",
            &identity.idempotency_key,
            &result.operation_id,
            &request,
            &json(&result)?,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn create_project(&self, p: Project) -> Result<Project> {
        decode(
            self.trusted_catalog(CatalogCommand::CreateProject(p))
                .await?,
        )
    }
    pub async fn update_project(&self, p: Project, r: u64) -> Result<Project> {
        decode(
            self.trusted_catalog(CatalogCommand::UpdateProject {
                project: p,
                expected_revision: r,
            })
            .await?,
        )
    }
    pub async fn create_requirement(&self, r: Requirement) -> Result<Requirement> {
        decode(
            self.trusted_catalog(CatalogCommand::CreateRequirement(r))
                .await?,
        )
    }
    pub async fn create_team(&self, t: Team) -> Result<Team> {
        decode(self.trusted_catalog(CatalogCommand::CreateTeam(t)).await?)
    }
    pub async fn put_flow(&self, f: FlowRevision, r: Option<u64>) -> Result<FlowRevision> {
        decode(
            self.trusted_catalog(CatalogCommand::PutFlow {
                flow: f,
                expected_revision: r,
                context: None,
            })
            .await?,
        )
    }
    pub async fn put_resource_policy(
        &self,
        p: ResourcePolicy,
        r: Option<u64>,
    ) -> Result<ResourcePolicy> {
        decode(
            self.trusted_catalog(CatalogCommand::PutResourcePolicy {
                policy: p,
                expected_revision: r,
            })
            .await?,
        )
    }
}
fn validate_collection(c: &str) -> Result<()> {
    if [
        "sources",
        "contracts",
        "contract_versions",
        "schedules",
        "milestones",
        "findings",
        "artifacts",
        "flow_contexts",
        "operations",
        "owners",
        "decisions",
        "decision_history",
        "releases",
        "release_history",
        "release_acceptances",
        "release_exports",
        "release_archives",
        "project_phases",
        "input_snapshots",
        "verification_plans",
        "executor_profiles",
        "resource_profiles",
        "model_routes",
        "repositories",
        "queue_entries",
        "schedule_baselines",
        "milestone_baselines",
        "milestone_acceptances",
        "compiler_receipts",
        "task_estimates",
        "channel_pools",
        "planning_catalogs",
        "planning_cards",
        "native_panel_actions",
        "native_blueprint_reviews",
        "native_configuration_drafts",
        "capsule_policies",
        "delivery_settings",
        "agent_contexts",
    ]
    .contains(&c)
    {
        Ok(())
    } else {
        Err(err("VALIDATION_ERROR", "unsupported document collection"))
    }
}

fn retained_hash(domain: &str, value: &Value) -> Result<String> {
    Ok(forgeflow_planner::sha256(&serde_json::to_vec(
        &serde_json::json!([domain, value]),
    )?))
}

async fn retained_native_source_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    source_id: &str,
) -> Result<Value> {
    let source: Attempt = decode(
        sqlx::query_scalar(
            "SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2 FOR SHARE",
        )
        .bind(p)
        .bind(source_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "retained Native author attempt missing"))?,
    )?;
    if source.state != AttemptState::Cancelled || source.terminal_at.is_none() {
        return Err(err(
            "RETAINED_SOURCE_INVALID",
            "retained source must remain a stopped cancelled historical author",
        ));
    }
    let task:TaskCard=decode(sqlx::query_scalar("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3 FOR SHARE")
        .bind(p).bind(&source.task_id).bind(i64v(source.task_revision)?).fetch_optional(&mut **tx).await?.ok_or_else(||err("RETAINED_SOURCE_INVALID","original immutable Native task revision missing"))?)?;
    let current: TaskCard = decode(
        sqlx::query_scalar("SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2 FOR SHARE")
            .bind(p)
            .bind(&source.task_id)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    let context:forgeflow_planner::CompileContext=decode(sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2")
        .bind(p).bind(task.flow_revision.to_string()).fetch_one(&mut **tx).await?)?;
    let spec = context.task_specs.get(&task.task_id).ok_or_else(|| {
        err(
            "RETAINED_SOURCE_INVALID",
            "original task specification missing",
        )
    })?;
    if current.task_revision != task.task_revision
        || current.input_digest != task.input_digest
        || forgeflow_planner::canonical_task_input_digest(&task, spec) != task.input_digest
    {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "original Native task semantics changed after production",
        ));
    }
    let retry =
        native_panel_retry_policy_in_transaction(tx, p, &task.task_id, task.task_revision).await?;
    if retry["cancel_action_id"].as_str().is_some() {
        return Err(err(
            "NATIVE_RETRY_REQUIRED",
            "explicit Native cancellation cannot be silently adopted as a completed candidate",
        ));
    }
    let requirements: Vec<Requirement> = sqlx::query_scalar(
        "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id",
    )
    .bind(p)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(decode)
    .collect::<Result<_>>()?;
    for (id, digest) in &spec.requirement_digest_refs {
        if requirements
            .iter()
            .find(|requirement| &requirement.requirement_id == id)
            .map(forgeflow_planner::requirement_semantic_digest)
            .as_ref()
            != Some(digest)
        {
            return Err(err(
                "RETAINED_SOURCE_DRIFT",
                "original Native requirement semantics changed",
            ));
        }
    }
    let bindings = crate::execution_bindings::load(&mut **tx, p, source_id).await?;
    let envelope: ExecutionEnvelope = decode(
        sqlx::query_scalar("SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2")
            .bind(p)
            .bind(source_id)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    if bindings["executor_profile"]["kind"] != "DSH_MANAGED"
        || envelope.write_set != task.write_set
        || task.write_set.is_empty()
    {
        return Err(err(
            "RETAINED_SOURCE_INVALID",
            "source must be an actually admitted Native author with its original write scope",
        ));
    }
    let root =
        super::admission::native_root_binding(tx, &task, spec, &bindings["executor_profile"])
            .await?
            .ok_or_else(|| {
                err(
                    "RETAINED_SOURCE_INVALID",
                    "original immutable Native role binding missing",
                )
            })?;
    if root != bindings["native_root_binding"] {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "original Native role/catalogue binding changed",
        ));
    }
    let owner: forgeflow_planner::OwnerTerritory = context
        .owners
        .iter()
        .find(|owner| owner.owner_id == task.owner_id)
        .cloned()
        .ok_or_else(|| {
            err(
                "RETAINED_SOURCE_INVALID",
                "original owner territory missing",
            )
        })?;
    let mut current_owner: Value = sqlx::query_scalar(
        "SELECT data FROM documents WHERE project_id=$1 AND collection='owners' AND document_id=$2",
    )
    .bind(p)
    .bind(&task.owner_id)
    .fetch_one(&mut **tx)
    .await?;
    if let Some(object) = current_owner.as_object_mut() {
        object.remove("revision");
    }
    if decode::<forgeflow_planner::OwnerTerritory>(current_owner)?.include != owner.include {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "original owner write territory changed",
        ));
    }
    let models:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('request_id',request_id,'provider',provider,'model',model,'status',status,'usage_complete',usage_complete,'usage',usage,'settlement',settlement) FROM native_model_requests WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 ORDER BY request_id")
        .bind(p).bind(source_id).bind(source.generation).fetch_all(&mut **tx).await?;
    let open:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE project_id=$1 AND attempt_id=$2 AND state<>'RELEASED' AND disposed_at IS NULL AND process_stopped_at IS NULL)").bind(p).bind(source_id).fetch_one(&mut **tx).await?;
    if models.is_empty()
        || models.iter().any(|model| {
            model["status"] != "SETTLED"
                || model["usage_complete"] != true
                || model["usage"].is_null()
        })
        || open
    {
        return Err(err(
            "RETAINED_SOURCE_INVALID",
            "source Native model and child lifecycle custody must be fully closed",
        ));
    }
    let reports:Vec<Value>=sqlx::query_scalar("SELECT payload FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 AND payload ? 'outcome' ORDER BY event_id")
        .bind(p).bind(source_id).fetch_all(&mut **tx).await?;
    let mut successful = None;
    for report in reports {
        let result: WorkerResult = decode(report.clone())?;
        if result.generation == source.generation
            && result.worker_id == source.worker_id
            && result.lease_id == source.lease_id
            && result.outcome.completion_reason == "EXECUTOR_COMPLETED"
            && result.outcome.exit_code == Some(0)
            && result.evidence["process_exit_confirmed"] == true
            && super::collaboration::validate_physical_stop(
                tx,
                &source,
                &result.evidence,
                Some(&result.outcome.execution_id),
            )
            .await?
        {
            successful = Some(report);
            break;
        }
    }
    let stop = successful.ok_or_else(|| {
        err(
            "RETAINED_SOURCE_INVALID",
            "source author did not actually complete with trusted physical stop evidence",
        )
    })?;
    let manifest:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2").bind(p).bind(&envelope.context_manifest.artifact_id).fetch_one(&mut **tx).await?;
    let bytes = std::fs::read(manifest["path"].as_str().ok_or_else(|| {
        err(
            "RETAINED_SOURCE_INVALID",
            "admitted source context artifact missing",
        )
    })?)
    .map_err(|error| err("RETAINED_SOURCE_INVALID", error.to_string()))?;
    if manifest["sha256"] != envelope.context_manifest.sha256
        || forgeflow_planner::sha256(&bytes) != envelope.context_manifest.sha256
    {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "admitted source context bytes changed",
        ));
    }
    let original_manifest: ContextManifest = decode(serde_json::from_slice(&bytes)?)?;
    let project: Project = decode(
        sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
            .bind(p)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    for file in &original_manifest.files {
        validate_relative_path(&file.path)?;
        let main =
            forgeflow_git::resolve(std::path::Path::new(&project.root_path), "refs/heads/main")
                .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?;
        let output = std::process::Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_LAZY_FETCH", "1")
            .arg("-C")
            .arg(&project.root_path)
            .args(["cat-file", "blob"])
            .arg(format!("{main}:{}", file.path))
            .output()
            .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?;
        if !output.status.success() || output.stdout.len() > 32 * 1024 * 1024 {
            return Err(err(
                "RETAINED_SOURCE_DRIFT",
                "original governed main input is missing or exceeds its byte bound",
            ));
        }
        let current = output.stdout;
        if forgeflow_planner::sha256(&current) != file.sha256 {
            return Err(err(
                "RETAINED_SOURCE_DRIFT",
                "original governed input bytes changed in the current project",
            ));
        }
    }
    for input in &original_manifest.artifact_inputs {
        let artifact:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2").bind(p).bind(&input.artifact.artifact_id).fetch_one(&mut **tx).await?;
        let current = std::fs::read(artifact["path"].as_str().ok_or_else(|| {
            err(
                "RETAINED_SOURCE_DRIFT",
                "original controlled source artifact missing",
            )
        })?)
        .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?;
        if artifact["sha256"] != input.artifact.sha256
            || forgeflow_planner::sha256(&current) != input.artifact.sha256
        {
            return Err(err(
                "RETAINED_SOURCE_DRIFT",
                "original controlled source artifact bytes changed",
            ));
        }
    }
    Ok(
        serde_json::json!({"schema_version":"forgeflow.retained-native-candidate-source.v1","project_id":p,"task_id":task.task_id,"task_revision":task.task_revision,"input_digest":task.input_digest,"flow_revision":task.flow_revision,
        "attempt_id":source_id,"generation":source.generation,"base_sha":source.base_sha,"candidate":null,"owner_id":task.owner_id,"team_id":task.team_id,"write_set":task.write_set,"owner_paths":owner.include,
        "task_spec":spec,"requirement_semantic_digests":spec.requirement_digest_refs,"context_manifest":envelope.context_manifest,"native_root_binding":root,
        "execution_bindings_sha256":retained_hash("forgeflow.retained-source.bindings.v1",&bindings)?,"model_request_ids":models.iter().map(|model|model["request_id"].clone()).collect::<Vec<_>>(),
        "model_settlement_sha256":retained_hash("forgeflow.retained-source.models.v1",&serde_json::json!(models))?,"physical_stop_proof_sha256":retained_hash("forgeflow.retained-source.stop.v1",&stop)?,"planning_card_id":bindings["native_root_binding"]["planning_card_id"]}),
    )
}

async fn validate_retained_body_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    binding: &Value,
) -> Result<TaskCard> {
    let invalid = |message: &str| err("RETAINED_SOURCE_INVALID", message);
    if binding["schema_version"] != "forgeflow.retained-native-candidate.v1"
        || !valid_digest(binding["source_provenance_sha256"].as_str().unwrap_or(""))
    {
        return Err(invalid("retained candidate proof schema/digest is invalid"));
    }
    let supplied = &binding["source"];
    let source_id = supplied["attempt_id"]
        .as_str()
        .ok_or_else(|| invalid("original Native attempt is missing"))?;
    let mut source = retained_native_source_tx(tx, p, source_id).await?;
    source["candidate"] = supplied["candidate"].clone();
    if source != *supplied {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "retained source proposal differs from authoritative Native production facts",
        ));
    }
    let candidate: forgeflow_git::Candidate = decode(source["candidate"].clone())?;
    if candidate.base_sha != source["base_sha"].as_str().unwrap_or("")
        || candidate.manifest.hash != candidate.diff_manifest_hash
        || candidate.manifest.head_sha != candidate.candidate_sha
        || candidate.manifest.base_sha != candidate.base_sha
        || candidate.manifest.changes.is_empty()
    {
        return Err(invalid(
            "retained Git candidate identity differs from original production scope",
        ));
    }
    let scope = forgeflow_git::PathScope {
        owner_paths: decode(source["owner_paths"].clone())?,
        write_set: decode(source["write_set"].clone())?,
    };
    if candidate.manifest.changes.iter().any(|change| {
        !scope.permits(&change.path)
            || change
                .old_path
                .as_ref()
                .is_some_and(|path| !scope.permits(path))
    }) {
        return Err(invalid(
            "retained candidate diff escapes its original owner/write scope",
        ));
    }
    let recorded_path: Option<String> =
        sqlx::query_scalar("SELECT path FROM worktrees WHERE project_id=$1 AND attempt_id=$2")
            .bind(p)
            .bind(source_id)
            .fetch_optional(&mut **tx)
            .await?;
    let root = if let Some(path) = recorded_path {
        std::path::PathBuf::from(path)
    } else {
        // Historical native Workers published an authenticated STARTING event but
        // did not populate the legacy worktrees table. Derive only the managed
        // controller sibling path, then require that original immutable event.
        let original: Attempt = decode(
            sqlx::query_scalar("SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2")
                .bind(p)
                .bind(source_id)
                .fetch_one(&mut **tx)
                .await?,
        )?;
        let envelope: ExecutionEnvelope = decode(
            sqlx::query_scalar(
                "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
            )
            .bind(p)
            .bind(source_id)
            .fetch_one(&mut **tx)
            .await?,
        )?;
        let bindings = crate::execution_bindings::load(&mut **tx, p, source_id).await?;
        let repository = std::path::PathBuf::from(&envelope.workspace_root);
        let repositories = repository
            .parent()
            .filter(|parent| {
                parent
                    .file_name()
                    .is_some_and(|name| name == "repositories")
            })
            .ok_or_else(|| {
                invalid("historical Native repository has no managed controller boundary")
            })?;
        if uuid::Uuid::parse_str(source_id).is_err()
            || !repository.is_absolute()
            || repository
                .canonicalize()
                .map_err(|error| invalid(&error.to_string()))?
                != repository
            || bindings["executor_profile"]["kind"] != "DSH_MANAGED"
            || envelope.project_id != original.project_id
            || envelope.attempt_id != original.attempt_id
            || envelope.worker_id != original.worker_id
            || envelope.lease_id != original.lease_id
            || envelope.generation != original.generation
            || envelope.base_sha != original.base_sha
        {
            return Err(invalid(
                "historical Native worktree requires the original frozen managed DSH execution identity",
            ));
        }
        let derived = repositories
            .parent()
            .ok_or_else(|| invalid("managed controller boundary missing"))?
            .join("worktrees")
            .join(source_id);
        if derived
            .canonicalize()
            .map_err(|error| invalid(&error.to_string()))?
            != derived
        {
            return Err(invalid(
                "historical Native worktree path is not its exact canonical controller sibling",
            ));
        }
        let starts:Vec<Value>=sqlx::query_scalar("SELECT payload FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 AND payload->>'kind'='STARTING' ORDER BY event_id")
            .bind(p).bind(source_id).fetch_all(&mut **tx).await?;
        if starts.is_empty()
            || starts.iter().any(|event| {
                event["project_id"] != p
                    || event["attempt_id"] != source_id
                    || event["worker_id"] != original.worker_id
                    || event["lease_id"] != original.lease_id
                    || event["generation"].as_i64() != Some(original.generation)
                    || event["payload"]["base_sha"] != original.base_sha
                    || event["payload"]["workspace"].as_str() != derived.to_str()
            })
        {
            return Err(invalid(
                "historical Native worktree differs from its authenticated scoped Worker STARTING event",
            ));
        }
        derived
    };
    let root = root.as_path();
    // Private Git isolation is an observed storage property, not a field added
    // retroactively to older resource profile snapshots. The audit below checks
    // independent metadata/objects and rejects linked, alternate or shared storage.
    let observed = forgeflow_git::audit_private_worktree(root, &candidate.base_sha, &scope)
        .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?;
    if observed.hash != candidate.diff_manifest_hash
        || observed.head_sha != candidate.candidate_sha
        || observed
            .changes
            .iter()
            .any(|change| change.layer != "committed")
        || forgeflow_git::source_hash(root, &candidate.candidate_sha)
            .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?
            != candidate.source_hash
    {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "retained Native candidate bytes or scope changed",
        ));
    }
    let project: Project = decode(
        sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
            .bind(p)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    let main = forgeflow_git::resolve(std::path::Path::new(&project.root_path), "refs/heads/main")
        .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?;
    if !forgeflow_git::is_ancestor(
        std::path::Path::new(&project.root_path),
        &candidate.base_sha,
        &main,
    )
    .map_err(|error| err("RETAINED_SOURCE_DRIFT", error.to_string()))?
    {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "original candidate base is no longer a main ancestor",
        ));
    }
    let target = &binding["target"];
    let task_id = target["task_id"]
        .as_str()
        .ok_or_else(|| invalid("new read-only review task is missing"))?;
    let task: TaskCard = decode(
        sqlx::query_scalar("SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2 FOR SHARE")
            .bind(p)
            .bind(task_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| invalid("new read-only review task not registered"))?,
    )?;
    let envelope = task
        .envelope
        .as_ref()
        .ok_or_else(|| invalid("new read-only review envelope is not frozen"))?;
    if target["project_id"] != p
        || target["task_revision"].as_u64() != Some(task.task_revision)
        || target["input_digest"] != task.input_digest
        || !task.write_set.is_empty()
        || envelope.session_purpose != SessionPurpose::Review
        || !envelope.write_set.is_empty()
        || envelope.max_model_requests != 0
        || envelope.allowed_effects.iter().any(|effect| {
            matches!(
                effect,
                AllowedEffect::RequestApprovedModel | AllowedEffect::WriteDeclaredPaths
            )
        })
        || task.resource_request.coding_slot != 0
        || task.resource_request.provider_inflight != 0
        || task.resource_request.active_slot != 1
        || envelope.executor_profile_id != "controlled-lightweight.v1"
        || envelope.command.is_none()
        || envelope.base_sha != candidate.base_sha
        || target["executor_profile_id"] != envelope.executor_profile_id
        || target["resource_profile_id"] != envelope.resource_profile_id
        || target["model_route_id"] != envelope.model_route_id
        || target["verification_plan_id"] != envelope.verification_plan_id
        || target["static_execution_template_sha256"]
            != forgeflow_planner::static_execution_template_digest(envelope)
    {
        return Err(invalid(
            "review task must be the exact zero-model zero-write controlled verifier envelope",
        ));
    }
    let context:forgeflow_planner::CompileContext=decode(sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(p).bind(task.flow_revision.to_string()).fetch_one(&mut **tx).await?)?;
    let spec = context
        .task_specs
        .get(task_id)
        .ok_or_else(|| invalid("new review semantic specification missing"))?;
    if forgeflow_planner::canonical_task_input_digest(&task, spec) != task.input_digest
        || !spec.design_anchors.iter().any(|anchor| {
            anchor
                == &format!(
                    "forgeflow:retained-native-candidate:{}",
                    binding["source_provenance_sha256"].as_str().unwrap_or("")
                )
        })
    {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "review input digest does not freeze its retained Native source proof",
        ));
    }
    let profile:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='executor_profiles' AND document_id=$2").bind(p).bind(&envelope.executor_profile_id).fetch_one(&mut **tx).await?;
    if profile["kind"] != "CONTROLLED_LIGHTWEIGHT" {
        return Err(invalid(
            "review executor must be truthfully registered as controlled verification",
        ));
    }
    let mut plan_value:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='verification_plans' AND document_id=$2").bind(p).bind(&envelope.verification_plan_id).fetch_one(&mut **tx).await?;
    if let Some(object) = plan_value.as_object_mut() {
        object.remove("revision");
    }
    let plan: forgeflow_evidence::VerificationPlan = decode(plan_value)?;
    if plan.digest() != target["verification_plan_hash"].as_str().unwrap_or("")
        || plan.input_hash != task.input_digest
        || plan.task_revision != task.task_revision
        || plan
            .commands
            .iter()
            .map(|command| command.expected_cases.len())
            .sum::<usize>()
            != 8
        || plan.author_id == plan.verifier_id
        || plan.commands.iter().any(|command| {
            !command.program.is_absolute()
                || command
                    .bound_inputs
                    .iter()
                    .any(|input| !input.path.is_absolute())
        })
    {
        return Err(invalid(
            "new external verifier plan must freeze its exact independent eight-case denominator",
        ));
    }
    let action_id = binding["approvals"]["native_panel_action_id"]
        .as_str()
        .ok_or_else(|| invalid("actual Native START approval is missing"))?;
    let action:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='native_panel_actions' AND document_id=$2").bind(p).bind(action_id).fetch_optional(&mut **tx).await?.ok_or_else(||invalid("protected Native START approval missing"))?;
    if action["entry_source"] != "DSH_NATIVE_PANEL"
        || action["action"] != "START"
        || !matches!(action["status"].as_str(), Some("RUNNING" | "SUCCEEDED"))
        || action["config_sha256"] != binding["approvals"]["config_sha256"]
        || action["alignment_sha256"] != binding["approvals"]["alignment_sha256"]
    {
        return Err(invalid(
            "retained candidate verification requires the exact protected Native START approval",
        ));
    }
    Ok(task)
}

async fn authorize_retained_candidate_review_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    mut binding: Value,
) -> Result<Value> {
    project_lock(tx, p).await?;
    let task = validate_retained_body_tx(tx, p, &binding).await?;
    let authorization_id = format!(
        "retained-candidate-review:{}",
        retained_hash(
            "forgeflow.retained-review.identity.v1",
            &serde_json::json!([
                p,
                binding["source"]["attempt_id"],
                task.task_id,
                task.task_revision,
                task.input_digest
            ])
        )?
    );
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='operations' AND document_id=$2)").bind(p).bind(&authorization_id).fetch_one(&mut **tx).await?;
    if exists {
        return Err(err(
            "RETAINED_REVIEW_ALREADY_AUTHORIZED",
            "this exact source/review semantic revision already has its one-shot authorization",
        ));
    }
    binding["authorization_id"] = serde_json::json!(authorization_id);
    if let Some(object) = binding.as_object_mut() {
        object.remove("authorization_sha256");
    }
    let hash = retained_hash("forgeflow.retained-review.authorization.v1", &binding)?;
    binding["authorization_sha256"] = serde_json::json!(hash);
    let value = serde_json::json!({"kind":"RETAINED_NATIVE_CANDIDATE_REVIEW_AUTHORIZATION","authorization_id":authorization_id,"authorization_sha256":hash,"binding":binding,"status":"AUTHORIZED","max_once":1,"model_calls":0,"old_attempt_preserved":true});
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'operations',$2,1,$3)").bind(p).bind(&authorization_id).bind(&value).execute(&mut **tx).await?;
    event(tx,p,&authorization_id,1,"retained_candidate.review_authorized",serde_json::json!({"authorization_id":authorization_id,"source_attempt_id":binding["source"]["attempt_id"],"review_task_id":task.task_id,"model_calls":0})).await?;
    Ok(value)
}

pub(crate) async fn retained_candidate_task_binding_tx(
    tx: &mut Transaction<'_, Postgres>,
    task: &TaskCard,
) -> Result<Option<Value>> {
    let rows:Vec<Value>=sqlx::query_scalar("SELECT data->'binding' FROM documents WHERE project_id=$1 AND collection='operations' AND document_id LIKE 'retained-candidate-review:%' AND data->'binding'->'target'->>'task_id'=$2 AND data->'binding'->'target'->>'task_revision'=$3")
        .bind(&task.project_id).bind(&task.task_id).bind(task.task_revision.to_string()).fetch_all(&mut **tx).await?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() != 1 {
        return Err(err(
            "RETAINED_SOURCE_INVALID",
            "review semantic revision has ambiguous source authorization",
        ));
    }
    let binding = rows.into_iter().next().unwrap();
    validate_retained_body_tx(tx, &task.project_id, &binding).await?;
    Ok(Some(binding))
}

pub(crate) async fn validate_retained_native_candidate_binding_tx(
    tx: &mut Transaction<'_, Postgres>,
    attempt: &Attempt,
) -> Result<Option<Value>> {
    let bindings: Value = sqlx::query_scalar(
        "SELECT execution_bindings FROM attempts WHERE project_id=$1 AND attempt_id=$2",
    )
    .bind(&attempt.project_id)
    .bind(&attempt.attempt_id)
    .fetch_one(&mut **tx)
    .await?;
    let Some(binding) = bindings
        .get("retained_native_candidate")
        .filter(|value| value.is_object())
    else {
        return Ok(None);
    };
    let authorization = binding["authorization_id"].as_str().ok_or_else(|| {
        err(
            "RETAINED_SOURCE_INVALID",
            "frozen review authorization identity missing",
        )
    })?;
    let original:Value=sqlx::query_scalar("SELECT data->'binding' FROM documents WHERE project_id=$1 AND collection='operations' AND document_id=$2").bind(&attempt.project_id).bind(authorization).fetch_optional(&mut **tx).await?.ok_or_else(||err("RETAINED_SOURCE_INVALID","protected retained source authorization missing"))?;
    let mut frozen = binding.clone();
    if let Some(target) = frozen["target"].as_object_mut() {
        target.remove("attempt_id");
        target.remove("generation");
    }
    if frozen != original
        || binding["target"]["attempt_id"] != attempt.attempt_id
        || binding["target"]["generation"].as_i64() != Some(attempt.generation)
    {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "review execution identity differs from its frozen one-shot authorization",
        ));
    }
    validate_retained_body_tx(tx, &attempt.project_id, &original).await?;
    Ok(Some(binding.clone()))
}

pub(crate) async fn finalize_retained_candidate_acceptance_tx(
    tx: &mut Transaction<'_, Postgres>,
    attempt: &Attempt,
    intent: &MergeIntent,
    binding: &Value,
) -> Result<Value> {
    let source = &binding["source"];
    let id = format!(
        "retained-candidate-acceptance:{}",
        retained_hash(
            "forgeflow.retained-acceptance.identity.v1",
            &serde_json::json!([
                source["project_id"],
                source["task_id"],
                source["task_revision"],
                source["input_digest"]
            ])
        )?
    );
    let receipt_id:String=sqlx::query_scalar("SELECT receipt_id FROM evidence_receipts WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 AND kind='INDEPENDENT_VERIFICATION' ORDER BY receipt_id LIMIT 1").bind(&attempt.project_id).bind(&attempt.attempt_id).bind(attempt.generation).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","retained candidate independent receipt missing"))?;
    let value = serde_json::json!({"schema_version":"forgeflow.retained-native-candidate-acceptance.v1","kind":"RETAINED_NATIVE_CANDIDATE_ACCEPTANCE","accepted":true,"authorization_id":binding["authorization_id"],"authorization_sha256":binding["authorization_sha256"],"source":source,
        "review":{"attempt_id":attempt.attempt_id,"generation":attempt.generation,"task_id":attempt.task_id,"task_revision":attempt.task_revision,"input_digest":binding["target"]["input_digest"]},
        "integration":{"intent_id":intent.intent_id,"integrated_sha":intent.integrated_sha,"receipt_id":receipt_id},"old_attempt_preserved":true,"native_producer_lineage":true,"auxiliary_review_counts_as_product_card":false});
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'operations',$2,1,$3)").bind(&attempt.project_id).bind(&id).bind(&value).execute(&mut **tx).await?;
    event(tx,&attempt.project_id,&id,1,"retained_candidate.accepted",serde_json::json!({"source_task_id":source["task_id"],"source_attempt_id":source["attempt_id"],"review_attempt_id":attempt.attempt_id,"intent_id":intent.intent_id,"native_producer_lineage":true})).await?;
    Ok(value)
}

pub(crate) async fn retained_candidate_dependency_ready_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    source_task: &str,
) -> Result<bool> {
    let rows:Vec<Value>=sqlx::query_scalar("SELECT d.data FROM documents d JOIN tasks t ON t.project_id=d.project_id AND t.task_id=d.data->'source'->>'task_id' AND t.task_revision=(d.data->'source'->>'task_revision')::bigint AND t.input_digest=d.data->'source'->>'input_digest' JOIN attempts r ON r.project_id=d.project_id AND r.attempt_id=d.data->'review'->>'attempt_id' AND r.state='SUCCEEDED' JOIN merge_intents m ON m.project_id=d.project_id AND m.intent_id=d.data->'integration'->>'intent_id' AND m.state='FINALIZED' WHERE d.project_id=$1 AND d.collection='operations' AND d.document_id LIKE 'retained-candidate-acceptance:%' AND d.data->'source'->>'task_id'=$2 AND d.data->>'accepted'='true'")
        .bind(p).bind(source_task).fetch_all(&mut **tx).await?;
    if rows.len() != 1 {
        return Ok(false);
    }
    let source = &rows[0]["source"];
    let attempt: Attempt = decode(
        sqlx::query_scalar("SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2")
            .bind(p)
            .bind(source["attempt_id"].as_str().unwrap_or(""))
            .fetch_one(&mut **tx)
            .await?,
    )?;
    if attempt.state != AttemptState::Cancelled {
        return Err(err(
            "RETAINED_SOURCE_DRIFT",
            "original Native author history changed",
        ));
    }
    let retry = native_panel_retry_policy_in_transaction(
        tx,
        p,
        source_task,
        source["task_revision"].as_u64().unwrap_or(0),
    )
    .await?;
    Ok(retry["cancel_action_id"].is_null())
}
async fn put_document(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    c: &str,
    id: &str,
    expected: Option<u64>,
    value: Value,
) -> Result<Value> {
    validate_collection(c)?;
    if c == "agent_contexts" {
        crate::agent_contexts::validate(tx, p, id, &value).await?;
    }
    if c == "capsule_policies" {
        return Err(err(
            "CAPSULE_COMMAND_REQUIRED",
            "capsule policy requires validated registration",
        ));
    }
    if matches!(c, "planning_catalogs" | "planning_cards") {
        return Err(err(
            "COMMAND_REQUIRED",
            "planning registration requires RegisterPlanningCatalog",
        ));
    }
    if c == "native_panel_actions" {
        return Err(err(
            "COMMAND_REQUIRED",
            "native panel origin and outcomes require their typed service commands",
        ));
    }
    if c == "native_blueprint_reviews" {
        return Err(err(
            "COMMAND_REQUIRED",
            "native blueprint reviews and imports require their typed service commands",
        ));
    }
    if c == "native_configuration_drafts" {
        return Err(err(
            "COMMAND_REQUIRED",
            "native configuration requires typed review commands",
        ));
    }
    if matches!(c, "decisions" | "decision_history") {
        return Err(err(
            "DECISION_COMMAND_REQUIRED",
            "decision authority and history require typed Owner commands",
        ));
    }
    if matches!(
        c,
        "releases"
            | "release_history"
            | "release_acceptances"
            | "release_exports"
            | "release_archives"
            | "project_phases"
    ) {
        return Err(err(
            "RELEASE_COMMAND_REQUIRED",
            "release acceptance/export/phase authority requires typed Owner commands",
        ));
    }
    if c == "milestone_acceptances" {
        return Err(err(
            "COMMAND_REQUIRED",
            "milestone acceptance is an immutable server judgment; use AcceptMilestone",
        ));
    }
    if c == "operations" && expected.is_some() {
        let old:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='operations' AND document_id=$2").bind(p).bind(id).fetch_optional(&mut **tx).await?;
        if old.as_ref().is_some_and(|old| {
            matches!(
                old.get("kind").and_then(Value::as_str),
                Some(
                    "VERIFIER_PROCESS_ROOT"
                        | "VERIFIER_PROCESS_SETTLED"
                        | "RESOURCE_HANDOFF"
                        | "CONTRACT_SOURCE_FREEZE"
                        | "INTEGRATION_RECOVERY"
                )
            )
        }) || matches!(
            value.get("kind").and_then(Value::as_str),
            Some("VERIFIER_PROCESS_ROOT" | "VERIFIER_PROCESS_SETTLED")
        ) {
            return Err(err(
                "IMMUTABLE_VERIFIER_FACT",
                "registered verifier roots and final acknowledgments cannot be overwritten",
            ));
        }
    }

    if matches!(
        c,
        "executor_profiles" | "resource_profiles" | "model_routes" | "verification_plans"
    ) && expected.is_some()
    {
        return Err(err(
            "IMMUTABLE_PROFILE",
            "execution configuration versions are append only; use a new document ID",
        ));
    }
    if c == "contract_versions" {
        let frozen:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM contract_versions WHERE project_id=$1 AND contract_id||':'||version::text=$2 AND state='FROZEN')").bind(p).bind(id).fetch_one(&mut **tx).await?;
        if frozen {
            return Err(err(
                "CONTRACT_NOT_FROZEN",
                "frozen contract version is immutable",
            ));
        }
    }

    if matches!(
        c,
        "schedule_baselines" | "milestone_baselines" | "compiler_receipts"
    ) {
        return Err(err(
            "IMMUTABLE_BASELINE",
            "baseline history is derived only by schedule/milestone commands",
        ));
    }
    if !value.is_object() || id.is_empty() {
        return Err(err(
            "VALIDATION_ERROR",
            "document must be object with identity",
        ));
    }
    if c == "resource_profiles" {
        if let Some(limits) = value.get("physical_limits") {
            let limits: PhysicalLimitsPolicy = decode(limits.clone())?;
            limits.validate()?;
            if value.get("id").and_then(Value::as_str) != Some(id) {
                return Err(err(
                    "PHYSICAL_POLICY_INVALID",
                    "physical resource profile must bind document identity",
                ));
            }
        }
        if let Some(policy) = value.get("native_child_policy") {
            let policy: super::collaboration::NativeChildPolicy = decode(policy.clone())?;
            policy.validate()?;
        }
    }
    if c == "task_estimates" {
        let estimate: TaskEstimate = decode(value.clone())?;
        estimate.effort.validate()?;
        if estimate.project_id != p
            || estimate.estimate_id != id
            || estimate.estimate_version == 0
            || estimate
                .duration_hours
                .is_some_and(|v| !v.is_finite() || v <= 0.0 || v > 1_000_000.0)
        {
            return Err(err(
                "VALIDATION_ERROR",
                "task estimate identity, version or duration invalid",
            ));
        }
        if expected.is_some() {
            return Err(err("IMMUTABLE_BASELINE", "task estimates append only"));
        }
        let revision: Option<i64> = sqlx::query_scalar(
            "SELECT task_revision FROM tasks WHERE project_id=$1 AND task_id=$2",
        )
        .bind(p)
        .bind(&estimate.task_id)
        .fetch_optional(&mut **tx)
        .await?;
        if revision != Some(i64v(estimate.task_revision)?) {
            return Err(err(
                "CONTEXT_STALE",
                "estimate must bind current task revision",
            ));
        }
        let previous: Option<i64> = sqlx::query_scalar("SELECT max((data->>'estimate_version')::bigint) FROM documents WHERE project_id=$1 AND collection='task_estimates' AND data->>'task_id'=$2 AND (data->>'task_revision')::bigint=$3")
            .bind(p).bind(&estimate.task_id).bind(i64v(estimate.task_revision)?).fetch_one(&mut **tx).await?;
        if estimate.estimate_version != previous.unwrap_or(0) as u64 + 1 {
            return Err(err(
                "REVISION_CONFLICT",
                "estimate version must follow current history",
            ));
        }
    }
    if matches!(c, "contracts" | "contract_versions")
        && (value.get("state").and_then(Value::as_str) == Some("FROZEN")
            || value.get("frozen").and_then(Value::as_bool) == Some(true))
    {
        return Err(err(
            "CONTRACT_NOT_FROZEN",
            "contract freezing requires verified producer and consumer receipts; generic document write cannot grant freeze",
        ));
    }
    if c == "flow_contexts" {
        let committed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flow_revisions WHERE project_id=$1 AND flow_revision::text=$2 AND state IN('COMMITTED','SUPERSEDED'))").bind(p).bind(id).fetch_one(&mut **tx).await?;
        if committed {
            return Err(err(
                "REVISION_CONFLICT",
                "committed compile context is immutable",
            ));
        }
    }
    if c == "owners" {
        let owner: forgeflow_planner::OwnerTerritory = decode({
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove("revision");
            v
        })?;
        if owner.owner_id != id || owner.include.is_empty() {
            return Err(err(
                "OWNER_PATH_VIOLATION",
                "owner territory identity and includes required",
            ));
        }
        for path in owner.include.iter().chain(&owner.exclude) {
            validate_relative_path(path)?;
        }
        let existing:Vec<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='owners' AND document_id<>$2").bind(p).bind(id).fetch_all(&mut **tx).await?;
        for other in existing {
            let other: forgeflow_planner::OwnerTerritory = decode({
                let mut v = other;
                v.as_object_mut().unwrap().remove("revision");
                v
            })?;
            for a in &owner.include {
                for b in &other.include {
                    if paths_overlap(a, b) {
                        return Err(err(
                            "OWNER_PATH_VIOLATION",
                            "root owner territories overlap",
                        ));
                    }
                }
            }
        }
    }
    if c == "schedules" {
        let schedule: crate::Schedule = decode(value.clone())?;
        if let Some(estimate) = &schedule.effort_estimate {
            estimate.validate()?;
        }
        if schedule.project_id != p
            || schedule.schedule_id != id
            || schedule.baseline_version == 0
            || schedule.planned_end < schedule.planned_start
        {
            return Err(err(
                "VALIDATION_ERROR",
                "schedule identity/baseline/time interval invalid",
            ));
        }
        if expected.is_some() {
            return Err(err(
                "IMMUTABLE_BASELINE",
                "schedule versions append only; create a new schedule_id with incremented baseline_version",
            ));
        }
        let task: TaskCard = decode(
            sqlx::query_scalar("SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2")
                .bind(p)
                .bind(&schedule.task_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "scheduled task missing"))?,
        )?;
        let mut required = task.dependencies.clone();
        let mut declared = schedule.dependencies.clone();
        required.sort();
        declared.sort();
        if required != declared {
            return Err(err(
                "DEPENDENCY_UNSATISFIED",
                "schedule dependencies must match task graph",
            ));
        }
        for dependency in &schedule.dependencies {
            let end:Option<String>=sqlx::query_scalar("SELECT data->>'planned_end' FROM documents WHERE project_id=$1 AND collection='schedules' AND data->>'task_id'=$2 ORDER BY (data->>'baseline_version')::bigint DESC LIMIT 1").bind(p).bind(dependency).fetch_optional(&mut **tx).await?;
            let end = end.ok_or_else(|| {
                err(
                    "DEPENDENCY_UNSATISFIED",
                    "predecessor schedule must exist before dependent schedule",
                )
            })?;
            let end = DateTime::parse_from_rfc3339(&end)
                .map_err(|_| err("VALIDATION_ERROR", "predecessor date invalid"))?
                .with_timezone(&Utc);
            if schedule.planned_start < end {
                return Err(err(
                    "DEPENDENCY_UNSATISFIED",
                    "dependent starts before predecessor finish",
                ));
            }
        }
        let successors:Vec<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='schedules' AND data->'dependencies' ? $2").bind(p).bind(&schedule.task_id).fetch_all(&mut **tx).await?;
        for successor in successors {
            let successor: Schedule = decode(successor)?;
            let latest:Option<i64>=sqlx::query_scalar("SELECT max((data->>'baseline_version')::bigint) FROM documents WHERE project_id=$1 AND collection='schedules' AND data->>'task_id'=$2").bind(p).bind(&successor.task_id).fetch_one(&mut **tx).await?;
            if latest == Some(i64v(successor.baseline_version)?)
                && successor.planned_start < schedule.planned_end
            {
                return Err(err(
                    "DEPENDENCY_UNSATISFIED",
                    "upstream finish would invalidate saved successor start",
                ));
            }
        }
        sqlx::query("INSERT INTO schedule_baselines VALUES($1,$2,$3,$4)")
            .bind(p)
            .bind(i64v(schedule.baseline_version)?)
            .bind(id)
            .bind(&value)
            .execute(&mut **tx)
            .await?;
        sqlx::query("INSERT INTO documents VALUES($1,'schedule_baselines',$2,1,$3)")
            .bind(p)
            .bind(format!("{}:{}", id, schedule.baseline_version))
            .bind(&value)
            .execute(&mut **tx)
            .await?;
    }
    if c == "milestones" {
        // Preserve earliest retained authoritative event per declared baseline;
        // never invent an original date from a later current row.
        let history=sqlx::query("SELECT payload->'document' AS data,project_seq FROM events WHERE project_id=$1 AND object_id=$2 AND kind='document.updated' AND payload->>'collection'='milestones' ORDER BY project_seq").bind(p).bind(id).fetch_all(&mut **tx).await?;
        let mut versions = std::collections::BTreeSet::new();
        for row in history {
            let mut data: Value = row.try_get("data")?;
            let Some(version) = data
                .get("baseline_version")
                .and_then(Value::as_u64)
                .filter(|v| *v > 0)
            else {
                continue;
            };
            if !versions.insert(version) {
                continue;
            }
            if data.get("milestone_id").and_then(Value::as_str) != Some(id)
                || data.get("project_id").and_then(Value::as_str) != Some(p)
            {
                continue;
            }
            data["history_source_event_seq"] = row.try_get::<i64, _>("project_seq")?.into();
            data["history_source"] = "RETAINED_AUTHORITATIVE_EVENT".into();
            sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'milestone_baselines',$2,1,$3) ON CONFLICT DO NOTHING").bind(p).bind(format!("{id}:{version}")).bind(data).execute(&mut **tx).await?;
        }
    }
    if c == "milestones" {
        let milestone: crate::Milestone = decode(value.clone())?;
        if milestone.project_id != p
            || milestone.milestone_id != id
            || milestone.baseline_version == 0
        {
            return Err(err(
                "VALIDATION_ERROR",
                "milestone identity/baseline invalid",
            ));
        }
        let old:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='milestones' AND document_id=$2").bind(p).bind(id).fetch_optional(&mut **tx).await?;
        if let Some(old) = old {
            let old: Milestone = decode(old)?;
            if milestone.due_at != old.due_at
                && milestone
                    .change_reason
                    .as_ref()
                    .is_none_or(|r| r.trim().is_empty())
            {
                return Err(err(
                    "CHANGE_REASON_REQUIRED",
                    "milestone date change requires reason",
                ));
            }
            if milestone.baseline_version <= old.baseline_version {
                return Err(err(
                    "IMMUTABLE_BASELINE",
                    "milestone change requires new baseline version",
                ));
            }
        }
        sqlx::query("INSERT INTO documents VALUES($1,'milestone_baselines',$2,1,$3)")
            .bind(p)
            .bind(format!("{}:{}", id, milestone.baseline_version))
            .bind(&value)
            .execute(&mut **tx)
            .await?;
    }
    let previous = sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3 FOR UPDATE").bind(p).bind(c).bind(id).fetch_optional(&mut **tx).await?;
    let old = previous
        .as_ref()
        .map(|row| row.try_get::<i64, _>("revision"))
        .transpose()?;
    if old.map(|v| v as u64) != expected {
        return Err(err("REVISION_CONFLICT", "document revision mismatch"));
    }
    // A scheduler observation alone is not a document change. Check the exact
    // revision first, then preserve the prior revision and genuine observation
    // time when its decision is unchanged.
    if c == "operations" && id == "scheduler-state" {
        if let Some(previous) = previous {
            let prior: Value = previous.try_get("data")?;
            if scheduler_state_semantics(prior.clone()) == scheduler_state_semantics(value.clone())
            {
                return Ok(prior);
            }
        }
    }
    let revision = old.unwrap_or(0) + 1;
    let mut value = match c {
        "schedules" => json(&decode::<Schedule>(value)?)?,
        "milestones" => json(&decode::<Milestone>(value)?)?,
        "task_estimates" => json(&decode::<TaskEstimate>(value)?)?,
        _ => value,
    };
    value["revision"] = revision.into();
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,$2,$3,$4,$5) ON CONFLICT(project_id,collection,document_id) DO UPDATE SET revision=EXCLUDED.revision,data=EXCLUDED.data").bind(p).bind(c).bind(id).bind(revision).bind(&value).execute(&mut **tx).await?;
    event(
        tx,
        p,
        id,
        revision as u64,
        "document.updated",
        document_event_payload(p, c, id, &value)?,
    )
    .await?;
    Ok(value)
}

fn scheduler_state_semantics(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("revision");
        object.remove("observed_at");
    }
    value
}

/// Events invalidate catalog reads; the full scheduler matrix stays in the
/// canonical document instead of being copied into every SSE frame and outbox.
pub(crate) fn document_event_payload(p: &str, c: &str, id: &str, value: &Value) -> Result<Value> {
    if c != "operations" || id != "scheduler-state" {
        return Ok(serde_json::json!({"collection":c,"document":value}));
    }
    let content_sha256 = forgeflow_planner::sha256(&serde_json::to_vec(value)?);
    Ok(serde_json::json!({
        "collection": c,
        "document_ref": {
            "project_id": p,
            "collection": c,
            "document_id": id,
            "revision": value.get("revision").and_then(Value::as_u64),
            "content_sha256": content_sha256,
        },
        "summary": {
            "scanned": value.get("scanned").and_then(Value::as_u64),
            "skipped": value.get("skipped").and_then(Value::as_u64),
            "window_exhausted": value.get("window_exhausted").and_then(Value::as_bool),
            "blocked_count": value.get("blocked").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "admission_rejected_count": value.get("admission_rejected").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
        },
    }))
}

#[cfg(test)]
mod scheduler_event_tests {
    use super::*;

    #[test]
    fn scheduler_matrix_event_is_bounded_and_timestamp_is_not_a_decision_change() {
        let state = serde_json::json!({
            "revision": 11,
            "observed_at": "2026-10-10T00:00:00Z",
            "cursor": {"project_index": 1},
            "scanned": 192,
            "skipped": 192,
            "window_exhausted": false,
            "blocked": vec![serde_json::json!({"task_id":"queued","code":"RESOURCE_LIMIT","detail":"x".repeat(1024)}); 4032],
            "admission_rejected": [],
        });
        let original_bytes = serde_json::to_vec(&state).unwrap();
        assert!(original_bytes.len() > 1_048_576);
        let payload = document_event_payload("p", "operations", "scheduler-state", &state).unwrap();
        assert!(serde_json::to_vec(&payload).unwrap().len() < 1024);
        assert!(payload.get("document").is_none());
        assert_eq!(payload["document_ref"]["revision"], 11);
        assert_eq!(payload["document_ref"]["document_id"], "scheduler-state");
        assert_eq!(
            payload["document_ref"]["content_sha256"],
            forgeflow_planner::sha256(&original_bytes)
        );
        assert_eq!(payload["summary"]["blocked_count"], 4032);
        assert_eq!(serde_json::to_vec(&state).unwrap(), original_bytes);

        let mut observation = state.clone();
        observation["revision"] = 12.into();
        observation["observed_at"] = "2026-10-10T00:00:01Z".into();
        assert_eq!(
            scheduler_state_semantics(state.clone()),
            scheduler_state_semantics(observation.clone())
        );
        observation["cursor"]["project_index"] = 2.into();
        assert_ne!(
            scheduler_state_semantics(state.clone()),
            scheduler_state_semantics(observation)
        );

        let ordinary =
            document_event_payload("p", "operations", "other-operation", &state).unwrap();
        assert_eq!(ordinary["document"], state);
    }
}
pub(crate) async fn apply_catalog(
    tx: &mut Transaction<'_, Postgres>,
    command: CatalogCommand,
    actor: &str,
) -> Result<Value> {
    match command {
        CatalogCommand::NativeConfiguration {
            project_id,
            command,
        } => crate::native_configuration::apply(tx, &project_id, command, actor).await,
        CatalogCommand::AuthorizeRetainedCandidateReview {
            project_id,
            binding,
        } => {
            if actor != "native-candidate-review-service" {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "retained candidate authorization requires the Native panel service",
                ));
            }
            authorize_retained_candidate_review_tx(tx, &project_id, binding).await
        }
        CatalogCommand::Decision(command) => {
            crate::decisions::apply_in_transaction(tx, command, actor).await
        }
        CatalogCommand::Release(command) => {
            crate::releases::apply_in_transaction(tx, command, actor).await
        }
        CatalogCommand::AcceptMilestone {
            project_id,
            milestone_id,
            expected_revision,
            baseline_version,
        } => {
            crate::milestone_acceptance::accept_in_transaction(
                tx,
                &project_id,
                &milestone_id,
                expected_revision,
                baseline_version,
                actor,
            )
            .await
        }
        CatalogCommand::CreateProject(mut p) => {
            if p.project_id.is_empty()
                || p.name.trim().is_empty()
                || !std::path::Path::new(&p.root_path).is_absolute()
            {
                return Err(err(
                    "VALIDATION_ERROR",
                    "project identity, name and absolute root required",
                ));
            }
            if p.authority_mode == AuthorityMode::Managed && !p.archived {
                p.root_path = canonical_repository_identity(&p.root_path)?;
                assert_managed_repository_unique(tx, &p.project_id, &p.root_path).await?;
            }
            p.revision = 1;
            sqlx::query("INSERT INTO projects(project_id,revision,paused,archived,authority_mode,data) VALUES($1,1,$2,$3,$4,$5)").bind(&p.project_id).bind(p.paused).bind(p.archived).bind(p.authority_mode.as_str()).bind(json(&p)?).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO project_revisions VALUES($1,1,$2)")
                .bind(&p.project_id)
                .bind(json(&p)?)
                .execute(&mut **tx)
                .await?;
            event(
                tx,
                &p.project_id,
                &p.project_id,
                1,
                "project.created",
                json(&p)?,
            )
            .await?;
            json(&p)
        }
        CatalogCommand::UpdateProject {
            mut project,
            expected_revision,
        } => {
            let old = project_lock(tx, &project.project_id).await?;
            if old.revision != expected_revision {
                return Err(err("REVISION_CONFLICT", "project changed"));
            }
            if old.authority_mode != project.authority_mode || old.root_path != project.root_path {
                return Err(err(
                    "AUTHORITY_HANDOFF_REQUIRED",
                    "repository authority cannot change through ordinary edit",
                ));
            }
            if old.archived != project.archived && actor != "release-service" {
                let phased: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='project_phases')")
                    .bind(&project.project_id).fetch_one(&mut **tx).await?;
                if phased {
                    return Err(err(
                        "RELEASE_COMMAND_REQUIRED",
                        "phase-managed project archival/reopening requires typed release authority",
                    ));
                }
            }
            if project.archived && !old.archived {
                let open:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND terminal_at IS NULL) OR EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND state IN('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED')) OR EXISTS(SELECT 1 FROM model_request_permit m JOIN attempts a ON a.attempt_id=m.attempt_id WHERE a.project_id=$1 AND m.status IN('ADMITTED','QUARANTINED')) OR EXISTS(SELECT 1 FROM resource_allocations WHERE project_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_child_lifecycles WHERE project_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_child_allocations WHERE project_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_model_requests WHERE project_id=$1 AND status IN('ADMITTED','QUARANTINED')) OR EXISTS(SELECT 1 FROM gateway_scope_budget g JOIN attempts a ON a.attempt_id=g.attempt_id WHERE a.project_id=$1 AND g.inflight>0)").bind(&project.project_id).fetch_one(&mut **tx).await?;
                if open {
                    return Err(err(
                        "ARCHIVE_BLOCKED",
                        "archive requires confirmed quiescence of all attempts, integration and model effects",
                    ));
                }
            }
            if project.authority_mode == AuthorityMode::Managed && !project.archived {
                assert_managed_repository_unique(tx, &project.project_id, &project.root_path)
                    .await?;
            }
            project.revision = old.revision + 1;
            sqlx::query(
                "UPDATE projects SET revision=$2,paused=$3,archived=$4,data=$5 WHERE project_id=$1",
            )
            .bind(&project.project_id)
            .bind(i64v(project.revision)?)
            .bind(project.paused)
            .bind(project.archived)
            .bind(json(&project)?)
            .execute(&mut **tx)
            .await?;
            sqlx::query("INSERT INTO project_revisions VALUES($1,$2,$3)")
                .bind(&project.project_id)
                .bind(i64v(project.revision)?)
                .bind(json(&project)?)
                .execute(&mut **tx)
                .await?;
            event(
                tx,
                &project.project_id,
                &project.project_id,
                project.revision,
                "project.updated",
                json(&project)?,
            )
            .await?;
            json(&project)
        }
        CatalogCommand::ImportRequirements {
            project_id,
            source_id,
            source,
            requirements,
        } => {
            project_lock(tx, &project_id).await?;
            if requirements.is_empty() {
                return Err(err("VALIDATION_ERROR", "import must contain requirements"));
            }
            let source = put_document(tx, &project_id, "sources", &source_id, None, source).await?;
            let mut ids = std::collections::BTreeSet::new();
            for mut r in requirements {
                if r.project_id != project_id
                    || !ids.insert(r.requirement_id.clone())
                    || r.acceptance.is_empty()
                    || r.weight == 0
                {
                    return Err(err("VALIDATION_ERROR", "invalid imported requirement"));
                }
                r.revision = 1;
                sqlx::query("INSERT INTO requirements VALUES($1,$2,1,$3)")
                    .bind(&project_id)
                    .bind(&r.requirement_id)
                    .bind(json(&r)?)
                    .execute(&mut **tx)
                    .await?;
            }
            event(
                tx,
                &project_id,
                &source_id,
                1,
                "requirements.imported",
                source.clone(),
            )
            .await?;
            Ok(source)
        }
        CatalogCommand::CreateRequirement(mut r) => {
            project_lock(tx, &r.project_id).await?;
            if r.requirement_id.is_empty() || r.acceptance.is_empty() || r.weight == 0 {
                return Err(err(
                    "VALIDATION_ERROR",
                    "requirement identity, acceptance and positive weight required",
                ));
            }
            r.revision = 1;
            sqlx::query("INSERT INTO requirements VALUES($1,$2,1,$3)")
                .bind(&r.project_id)
                .bind(&r.requirement_id)
                .bind(json(&r)?)
                .execute(&mut **tx)
                .await?;
            event(
                tx,
                &r.project_id,
                &r.requirement_id,
                1,
                "requirement.created",
                json(&r)?,
            )
            .await?;
            json(&r)
        }
        CatalogCommand::UpdateRequirement {
            mut requirement,
            expected_revision,
        } => {
            project_lock(tx, &requirement.project_id).await?;
            let old:Option<i64>=sqlx::query_scalar("SELECT revision FROM requirements WHERE project_id=$1 AND requirement_id=$2 FOR UPDATE").bind(&requirement.project_id).bind(&requirement.requirement_id).fetch_optional(&mut **tx).await?;
            if old.map(|v| v as u64) != Some(expected_revision) {
                return Err(err("REVISION_CONFLICT", "requirement changed"));
            }
            requirement.revision = expected_revision + 1;
            sqlx::query("UPDATE requirements SET revision=$3,data=$4 WHERE project_id=$1 AND requirement_id=$2").bind(&requirement.project_id).bind(&requirement.requirement_id).bind(i64v(requirement.revision)?).bind(json(&requirement)?).execute(&mut **tx).await?;
            event(
                tx,
                &requirement.project_id,
                &requirement.requirement_id,
                requirement.revision,
                "requirement.updated",
                json(&requirement)?,
            )
            .await?;
            json(&requirement)
        }
        CatalogCommand::CreateTeam(mut t) => {
            project_lock(tx, &t.project_id).await?;
            t.revision = 1;
            sqlx::query("INSERT INTO owner_nodes(project_id,owner_id,parent_id,paused,data) VALUES($1,$2,$3,$4,$5)").bind(&t.project_id).bind(&t.team_id).bind(&t.parent_team_id).bind(t.paused).bind(json(&t)?).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO owner_closure VALUES($1,$2,$2,0)")
                .bind(&t.project_id)
                .bind(&t.team_id)
                .execute(&mut **tx)
                .await?;
            if let Some(parent) = &t.parent_team_id {
                sqlx::query("INSERT INTO owner_closure SELECT project_id,ancestor_id,$3,depth+1 FROM owner_closure WHERE project_id=$1 AND descendant_id=$2").bind(&t.project_id).bind(parent).bind(&t.team_id).execute(&mut **tx).await?;
            }
            event(tx, &t.project_id, &t.team_id, 1, "team.created", json(&t)?).await?;
            json(&t)
        }
        CatalogCommand::UpdateTeam {
            mut team,
            expected_revision,
        } => {
            project_lock(tx, &team.project_id).await?;
            let old: Team = decode(
                sqlx::query_scalar(
                    "SELECT data FROM owner_nodes WHERE project_id=$1 AND owner_id=$2 FOR UPDATE",
                )
                .bind(&team.project_id)
                .bind(&team.team_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "team missing"))?,
            )?;
            if old.revision != expected_revision || team.parent_team_id != old.parent_team_id {
                return Err(err("REVISION_CONFLICT", "team revision/ancestry changed"));
            }
            team.revision = old.revision + 1;
            sqlx::query(
                "UPDATE owner_nodes SET paused=$3,data=$4 WHERE project_id=$1 AND owner_id=$2",
            )
            .bind(&team.project_id)
            .bind(&team.team_id)
            .bind(team.paused)
            .bind(json(&team)?)
            .execute(&mut **tx)
            .await?;
            event(
                tx,
                &team.project_id,
                &team.team_id,
                team.revision,
                "team.updated",
                json(&team)?,
            )
            .await?;
            json(&team)
        }
        CatalogCommand::ChangeQueuePriority {
            project_id,
            task_id,
            priority,
            expected_revision,
        } => {
            project_lock(tx, &project_id).await?;
            let row=sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='queue_entries' AND document_id=$2 FOR UPDATE").bind(&project_id).bind(&task_id).fetch_optional(&mut **tx).await?.ok_or_else(||err("NOT_FOUND","queue entry missing"))?;
            if row.get::<i64, _>("revision") as u64 != expected_revision {
                return Err(err("REVISION_CONFLICT", "queue entry changed"));
            }
            let mut value: Value = row.try_get("data")?;
            if value.get("status").and_then(Value::as_str) != Some("QUEUED") {
                return Err(err(
                    "REVISION_CONFLICT",
                    "only queued entries can change priority",
                ));
            }
            value["priority"] = priority.into();
            put_document(
                tx,
                &project_id,
                "queue_entries",
                &task_id,
                Some(expected_revision),
                value,
            )
            .await
        }
        CatalogCommand::EnqueueTask {
            project_id,
            task_id,
            expected_revision,
            worker_id,
            priority,
            lease_seconds,
            worker_scope_id,
            scope_ids,
        } => {
            project_lock(tx, &project_id).await?;
            let task: TaskCard = decode(
                sqlx::query_scalar(
                    "SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2 FOR UPDATE",
                )
                .bind(&project_id)
                .bind(&task_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "task missing"))?,
            )?;
            if task.revision != expected_revision
                || task.state != TaskPlanningState::ReadyForAdmission
            {
                return Err(err("REVISION_CONFLICT", "task changed or not ready"));
            }
            validate_native_panel_enqueue(tx, &task).await?;
            let occupied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND task_id=$2 AND task_revision=$3 AND (terminal_at IS NULL OR state='SUCCEEDED'))").bind(&project_id).bind(&task_id).bind(i64v(task.task_revision)?).fetch_one(&mut **tx).await?;
            if occupied {
                return Err(err(
                    "ATTEMPT_ALREADY_ACTIVE",
                    "task current revision already active or fulfilled",
                ));
            }
            let envelope = task
                .envelope
                .ok_or_else(|| err("EXECUTOR_UNQUALIFIED", "frozen envelope missing"))?;
            if lease_seconds == 0 || lease_seconds > 3600 {
                return Err(err("VALIDATION_ERROR", "invalid lease TTL"));
            }
            let now = db_now(tx).await?;
            let seq: i64 = sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                .bind(&project_id)
                .fetch_one(&mut **tx)
                .await?;
            let value = serde_json::json!({"project_id":project_id,"task_id":task_id,"task_revision":task.task_revision,"flow_revision":task.flow_revision,"priority":priority,"enqueued_at_ms":now.timestamp_millis(),"enqueue_sequence":seq+1,"worker_id":worker_id,"worker_scope_id":worker_scope_id,"scope_ids":scope_ids,"lease_seconds":lease_seconds,"envelope":envelope,"status":"QUEUED","retry_not_before_ms":null});
            let old:Option<i64>=sqlx::query_scalar("SELECT revision FROM documents WHERE project_id=$1 AND collection='queue_entries' AND document_id=$2").bind(&project_id).bind(&task_id).fetch_optional(&mut **tx).await?;
            put_document(
                tx,
                &project_id,
                "queue_entries",
                &task_id,
                old.map(|v| v as u64),
                value,
            )
            .await
        }
        CatalogCommand::PutArtifact {
            project_id,
            id,
            path,
            sha256,
            kind,
            bytes,
        } => {
            project_lock(tx, &project_id).await?;
            if !valid_digest(&sha256) || !std::path::Path::new(&path).is_absolute() {
                return Err(err(
                    "VALIDATION_ERROR",
                    "artifact absolute path/hash required",
                ));
            }
            let value = serde_json::json!({"artifact_id":id,"path":path,"sha256":sha256,"kind":kind,"bytes":bytes});
            let old:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2").bind(&project_id).bind(&id).fetch_optional(&mut **tx).await?;
            if let Some(mut old) = old {
                old.as_object_mut().unwrap().remove("revision");
                if old != value {
                    return Err(err(
                        "IDEMPOTENCY_CONFLICT",
                        "artifact immutable identity reused",
                    ));
                }
                Ok(old)
            } else {
                put_document(tx, &project_id, "artifacts", &id, None, value).await
            }
        }
        CatalogCommand::RegisterInputSnapshots {
            project_id,
            snapshots,
        } => {
            project_lock(tx, &project_id).await?;
            let mut result = Vec::new();
            for snapshot in snapshots {
                let path = snapshot
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("VALIDATION_ERROR", "input snapshot path required"))?;
                validate_relative_path(path)?;
                if !snapshot
                    .get("sha256")
                    .and_then(Value::as_str)
                    .is_some_and(|hash| valid_digest(hash) && hash.bytes().any(|b| b != b'0'))
                {
                    return Err(err("VALIDATION_ERROR", "input snapshot digest required"));
                }
                let old:Option<i64>=sqlx::query_scalar("SELECT revision FROM documents WHERE project_id=$1 AND collection='input_snapshots' AND document_id=$2").bind(&project_id).bind(path).fetch_optional(&mut **tx).await?;
                result.push(
                    put_document(
                        tx,
                        &project_id,
                        "input_snapshots",
                        path,
                        old.map(|v| v as u64),
                        snapshot.clone(),
                    )
                    .await?,
                );
            }
            Ok(Value::Array(result))
        }
        CatalogCommand::RegisterPlanningCatalog {
            project_id,
            expected_revision,
            catalog,
        } => register_planning_catalog(tx, &project_id, expected_revision, catalog, true).await,
        CatalogCommand::PreviewNativeBlueprint {
            project_id,
            requested_by,
            request,
        } => {
            if actor != "native-blueprint-service" {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "native blueprint previews are service-owned",
                ));
            }
            preview_native_blueprint(tx, &project_id, &requested_by, request).await
        }
        CatalogCommand::ImportNativeBlueprint {
            project_id,
            preview_id,
            expected_revision,
            review_sha256,
            approved_by,
        } => {
            if actor != "native-blueprint-service" {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "native blueprint imports are service-owned",
                ));
            }
            import_native_blueprint(
                tx,
                &project_id,
                &preview_id,
                expected_revision,
                &review_sha256,
                &approved_by,
            )
            .await
        }
        CatalogCommand::RegisterNativePanelAction {
            project_id,
            requested_by,
            request_id,
            expected_model,
            catalog_id,
            expected_card_count,
            request,
        } => {
            if actor != "native-panel-service" {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "native panel origin is service-owned",
                ));
            }
            project_lock(tx, &project_id).await?;
            if requested_by.is_empty()
                || request_id.is_empty()
                || expected_model.is_empty()
                || catalog_id.is_empty()
                || expected_card_count == 0
                || expected_card_count > 10_000
                || !valid_digest(&request.config_sha256)
                || !valid_digest(&request.alignment_sha256)
                || request.reason.len() > 4096
                || request
                    .attempt_id
                    .as_ref()
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_err())
            {
                return Err(err(
                    "VALIDATION_ERROR",
                    "native panel request identity and immutable pins invalid",
                ));
            }
            let action_id = id();
            let value = serde_json::json!({"schema_version":"forgeflow.native-panel.action.v1",
                "project_id":project_id,"action_id":action_id,"entry_source":"DSH_NATIVE_PANEL",
                "action":request.action,"config_sha256":request.config_sha256,"alignment_sha256":request.alignment_sha256,
                "reason":request.reason,"attempt_id":request.attempt_id,"requested_by":requested_by,
                "expected_provider_model_id":expected_model,"planning_catalog_id":catalog_id,
                "expected_card_count":expected_card_count,
                "request_id":request_id,"requested_at":db_now(tx).await?.to_rfc3339(),
                "status":"ACCEPTED","revision":1,"delivery_completion_claimed":false});
            sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'native_panel_actions',$2,1,$3)")
                .bind(&project_id).bind(&action_id).bind(&value).execute(&mut **tx).await?;
            event(
                tx,
                &project_id,
                &action_id,
                1,
                "native.panel_action_requested",
                value.clone(),
            )
            .await?;
            Ok(value)
        }
        CatalogCommand::SettleNativePanelAction {
            project_id,
            action_id,
            expected_revision,
            status,
            result,
        } => {
            if actor != "native-panel-service" {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "native panel outcomes are service-owned",
                ));
            }
            project_lock(tx, &project_id).await?;
            let row = sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='native_panel_actions' AND document_id=$2 FOR UPDATE")
                .bind(&project_id).bind(&action_id).fetch_optional(&mut **tx).await?
                .ok_or_else(||err("NOT_FOUND", "native panel action not found"))?;
            if row.get::<i64, _>("revision") as u64 != expected_revision {
                return Err(err("REVISION_CONFLICT", "native panel action changed"));
            }
            let mut value: Value = row.get("data");
            if !matches!(value["status"].as_str(), Some("ACCEPTED" | "RUNNING"))
                || !matches!(status.as_str(), "RUNNING" | "SUCCEEDED" | "FAILED")
                || !result.is_object()
                || serde_json::to_vec(&result)?.len() > 65_536
            {
                return Err(err(
                    "VALIDATION_ERROR",
                    "native panel action outcome transition invalid",
                ));
            }
            let revision = expected_revision + 1;
            value["revision"] = revision.into();
            value["status"] = status.clone().into();
            value["result"] = result;
            value["updated_at"] = db_now(tx).await?.to_rfc3339().into();
            sqlx::query("UPDATE documents SET revision=$3,data=$4 WHERE project_id=$1 AND collection='native_panel_actions' AND document_id=$2")
                .bind(&project_id).bind(&action_id).bind(i64v(revision)?).bind(&value).execute(&mut **tx).await?;
            event(
                tx,
                &project_id,
                &action_id,
                revision,
                "native.panel_action_observed",
                value.clone(),
            )
            .await?;
            Ok(value)
        }
        CatalogCommand::PutDocument {
            project_id,
            collection,
            id,
            expected_revision,
            value,
        } => {
            if collection == "operations"
                && (id.starts_with("retained-candidate-review:")
                    || id.starts_with("retained-candidate-acceptance:"))
            {
                return Err(err(
                    "COMMAND_REQUIRED",
                    "retained candidate authority is derived only by typed Native review/integration commands",
                ));
            }
            if collection == "operations"
                && id.starts_with("verification-recovery:")
                && !matches!(
                    actor,
                    "verification-recovery-service" | "verification-service"
                )
            {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "verification recovery operations are trusted service-owned",
                ));
            }
            if collection == "operations"
                && matches!(
                    value.get("kind").and_then(Value::as_str),
                    Some("RESOURCE_HANDOFF" | "CONTRACT_SOURCE_FREEZE" | "INTEGRATION_RECOVERY")
                )
            {
                return Err(err(
                    "COMMAND_REQUIRED",
                    "handoff and contract source facts require their authoritative transactional command",
                ));
            }
            if collection == "operations"
                && matches!(
                    value.get("kind").and_then(Value::as_str),
                    Some("VERIFIER_PROCESS_ROOT" | "VERIFIER_PROCESS_SETTLED")
                )
                && !matches!(
                    actor,
                    "verification-service" | "recovery-service" | "internal"
                )
            {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "verifier process facts are trusted service-owned",
                ));
            }
            if collection == "queue_entries" && !matches!(actor, "scheduler-service" | "internal") {
                return Err(err(
                    "COMMAND_REQUIRED",
                    "queue mutations require typed enqueue/priority commands",
                ));
            }

            project_lock(tx, &project_id).await?;
            if collection == "operations"
                && id.starts_with("verification-recovery:")
                && actor == "verification-recovery-service"
                && (expected_revision.is_none()
                    || (expected_revision == Some(2)
                        && value["verification_recovery_authorization"]["resume_never_launched"]
                            == true))
            {
                let authorization = &value["verification_recovery_authorization"];
                if expected_revision == Some(2) {
                    let old:Value=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='operations' AND document_id=$2 FOR UPDATE").bind(&project_id).bind(&id).fetch_one(&mut **tx).await?;
                    let failure:Value=sqlx::query_scalar("SELECT response->'value' FROM idempotency_records WHERE actor_id='verification-service' AND operation='catalog' AND idempotency_key=$1").bind(format!("{id}:settled")).fetch_optional(&mut **tx).await?.ok_or_else(||err("VERIFICATION_RECOVERY_INVALID","never-launched failure receipt missing"))?;
                    let registered:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='VERIFIER_PROCESS_ROOT' AND (data->>'operation_id'=$2 OR data->>'ledger_operation_id'=$2))").bind(&project_id).bind(&id).fetch_one(&mut **tx).await?;
                    if old["revision"] != 2
                        || old["status"] != "FAILED"
                        || value["previous_failure_snapshot"] != old
                        || failure["operation_id"] != id
                        || failure["attempt_id"] != value["attempt_id"]
                        || failure["error"]["code"] != "PHYSICAL_BINDING_MISMATCH"
                        || failure["error"]["message"] != "VERIFIER_INVALID: unsafe identity"
                        || registered
                    {
                        return Err(err(
                            "VERIFICATION_RECOVERY_INVALID",
                            "only the exact unregistered never-launched operation may resume once",
                        ));
                    }
                }
                let attempt_id = value["attempt_id"].as_str().ok_or_else(|| {
                    err(
                        "VERIFICATION_RECOVERY_INVALID",
                        "recovery attempt identity is missing",
                    )
                })?;
                let attempt: Value = sqlx::query_scalar(
                    "SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2 FOR UPDATE",
                )
                .bind(&project_id)
                .bind(attempt_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "recovery attempt not found"))?;
                let prior = authorization["prior_operation_id"]
                    .as_str()
                    .ok_or_else(|| {
                        err(
                            "VERIFICATION_RECOVERY_INVALID",
                            "original failed operation is missing",
                        )
                    })?;
                let receipt:Value = sqlx::query_scalar("SELECT jsonb_build_object('request',request,'response',response) FROM idempotency_records WHERE actor_id='verification-service' AND operation='catalog' AND idempotency_key=$1")
                    .bind(format!("{prior}:settled")).fetch_optional(&mut **tx).await?.ok_or_else(||err("VERIFICATION_RECOVERY_INVALID","original verification-service failure receipt is missing"))?;
                let original = &receipt["response"]["value"];
                let action_id = authorization["native_panel_action_id"]
                    .as_str()
                    .ok_or_else(|| {
                        err(
                            "VERIFICATION_RECOVERY_INVALID",
                            "protected Native START authority is missing",
                        )
                    })?;
                let action:Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='native_panel_actions' AND document_id=$2 FOR SHARE")
                    .bind(&project_id).bind(action_id).fetch_optional(&mut **tx).await?.ok_or_else(||err("VERIFICATION_RECOVERY_INVALID","protected Native START action not found"))?;
                let quiet:bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM native_model_requests WHERE attempt_id=$1 AND status<>'SETTLED') AND NOT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND state<>'RELEASED' AND disposed_at IS NULL AND process_stopped_at IS NULL)")
                    .bind(attempt_id).fetch_one(&mut **tx).await?;
                if value["status"] != "ACCEPTED"
                    || attempt["state"] != "VERIFYING"
                    || attempt["generation"] != authorization["generation"]
                    || attempt["task_revision"] != authorization["task_revision"]
                    || receipt["request"]["kind"] != "PUT_DOCUMENT"
                    || receipt["request"]["payload"]["project_id"] != project_id
                    || receipt["request"]["payload"]["collection"] != "operations"
                    || receipt["request"]["payload"]["id"] != prior
                    || original["operation_id"] != prior
                    || original["project_id"] != project_id
                    || original["attempt_id"] != attempt_id
                    || original["status"] != "FAILED"
                    || original["error"]["code"] != "VERIFICATION_FAILED"
                    || original["error"]["message"]
                        != "VERIFIER_INVALID: independent verifier input is inside candidate write tree"
                    || action["entry_source"] != "DSH_NATIVE_PANEL"
                    || action["action"] != "START"
                    || !matches!(action["status"].as_str(), Some("RUNNING" | "SUCCEEDED"))
                    || action["config_sha256"] != authorization["config_sha256"]
                    || action["alignment_sha256"] != authorization["alignment_sha256"]
                    || !quiet
                {
                    return Err(err(
                        "VERIFICATION_RECOVERY_INVALID",
                        "Native recovery requires the exact stopped attempt and original service preflight failure",
                    ));
                }
            }
            if collection == "operations"
                && matches!(
                    value.get("kind").and_then(Value::as_str),
                    Some("VERIFIER_PROCESS_ROOT" | "VERIFIER_PROCESS_SETTLED")
                )
            {
                super::collaboration::validate_verifier_document(tx, &project_id, &id, &value)
                    .await?;
            }
            if collection == "channel_pools" {
                Store::validate_channel_pool_command_in_transaction(
                    tx,
                    &project_id,
                    &id,
                    actor,
                    expected_revision,
                    &value,
                )
                .await?;
            }
            put_document(tx, &project_id, &collection, &id, expected_revision, value).await
        }
        CatalogCommand::PutResourcePolicy {
            mut policy,
            expected_revision,
        } => {
            if policy.parent_scope_id.as_deref() == Some(&policy.scope_id)
                || policy.team_id.is_some() && policy.project_id.is_none()
                || policy.worker_id.is_some()
                    && (policy.project_id.is_some() || policy.team_id.is_some())
            {
                return Err(err(
                    "VALIDATION_ERROR",
                    "resource scope must be global, project, team or worker with acyclic ancestry",
                ));
            }
            if let Some(parent) = &policy.parent_scope_id {
                let parent_project: Option<String> =
                    sqlx::query_scalar("SELECT project_id FROM resource_scopes WHERE scope_id=$1")
                        .bind(parent)
                        .fetch_optional(&mut **tx)
                        .await?
                        .ok_or_else(|| err("NOT_FOUND", "resource parent missing"))?;
                if parent_project.is_some() && parent_project != policy.project_id {
                    return Err(err(
                        "AUTHORITY_SCOPE_VIOLATION",
                        "resource ancestor must be global or same project",
                    ));
                }
            }

            if let Some(p) = &policy.project_id {
                project_lock(tx, p).await?;
            }
            let old: Option<i64> = sqlx::query_scalar(
                "SELECT revision FROM resource_scopes WHERE scope_id=$1 FOR UPDATE",
            )
            .bind(&policy.scope_id)
            .fetch_optional(&mut **tx)
            .await?;
            if old.map(|v| v as u64) != expected_revision {
                return Err(err("REVISION_CONFLICT", "resource policy changed"));
            }
            if old.is_some() {
                let before: ResourcePolicy = decode(
                    sqlx::query_scalar("SELECT data FROM resource_scopes WHERE scope_id=$1")
                        .bind(&policy.scope_id)
                        .fetch_one(&mut **tx)
                        .await?,
                )?;
                if before.project_id != policy.project_id
                    || before.team_id != policy.team_id
                    || before.worker_id != policy.worker_id
                    || before.parent_scope_id != policy.parent_scope_id
                {
                    return Err(err(
                        "REVISION_CONFLICT",
                        "resource scope identity and ancestry immutable; create new scope",
                    ));
                }
            }
            if let Some(parent) = &policy.parent_scope_id {
                let cycle:bool=sqlx::query_scalar("WITH RECURSIVE ancestors AS (SELECT scope_id,parent_scope_id FROM resource_scopes WHERE scope_id=$1 UNION ALL SELECT s.scope_id,s.parent_scope_id FROM resource_scopes s JOIN ancestors a ON s.scope_id=a.parent_scope_id) SELECT EXISTS(SELECT 1 FROM ancestors WHERE scope_id=$2)").bind(parent).bind(&policy.scope_id).fetch_one(&mut **tx).await?;
                if cycle {
                    return Err(err("VALIDATION_ERROR", "resource hierarchy cycle"));
                }
            }
            policy.revision = old.unwrap_or(0) as u64 + 1;
            sqlx::query("INSERT INTO resource_scopes(scope_id,parent_scope_id,project_id,team_id,revision,paused,data,worker_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scope_id) DO UPDATE SET parent_scope_id=EXCLUDED.parent_scope_id,revision=EXCLUDED.revision,paused=EXCLUDED.paused,data=EXCLUDED.data").bind(&policy.scope_id).bind(&policy.parent_scope_id).bind(&policy.project_id).bind(&policy.team_id).bind(i64v(policy.revision)?).bind(policy.paused).bind(json(&policy)?).bind(&policy.worker_id).execute(&mut **tx).await?;
            for (d, n) in policy.limits.dimensions() {
                sqlx::query("INSERT INTO resource_limits(scope_id,dimension,hard_limit) VALUES($1,$2,$3) ON CONFLICT(scope_id,dimension) DO UPDATE SET hard_limit=EXCLUDED.hard_limit").bind(&policy.scope_id).bind(d).bind(i64v(n)?).execute(&mut **tx).await?;
            }
            if let Some(p) = &policy.project_id {
                event(
                    tx,
                    p,
                    &policy.scope_id,
                    policy.revision,
                    "resource_policy.updated",
                    json(&policy)?,
                )
                .await?;
            }
            json(&policy)
        }
        CatalogCommand::CommitFlow {
            project_id,
            flow_revision,
            expected_revision,
            approved_by,
        } => {
            project_lock(tx, &project_id).await?;
            let flow:FlowRevision=decode(sqlx::query_scalar("SELECT data FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2 FOR UPDATE").bind(&project_id).bind(i64v(flow_revision)?).fetch_optional(&mut **tx).await?.ok_or_else(||err("NOT_FOUND","flow not found"))?)?;
            let context:Value=sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2 FOR UPDATE").bind(&project_id).bind(flow_revision.to_string()).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","flow context missing"))?;
            let context_t: forgeflow_planner::CompileContext = decode(context.clone())?;
            validate_authoritative_context(tx, &project_id, &context_t).await?;
            let compiled =
                forgeflow_planner::freeze(flow, &context_t, &approved_by, expected_revision)
                    .map_err(|r| {
                        err(
                            "FLOW_CHECK_FAILED",
                            serde_json::to_string(&r).unwrap_or_default(),
                        )
                    })?;
            put_flow(tx, compiled.flow, Some(expected_revision), Some(context)).await
        }
        CatalogCommand::PutFlow {
            flow,
            expected_revision,
            context,
        } => put_flow(tx, flow, expected_revision, context).await,
        CatalogCommand::PutFlowFromParent {
            flow,
            expected_revision,
            context,
            parent_flow_revision,
            parent_expected_revision,
            expected_source_revision,
        } => {
            project_lock(tx, &flow.project_id).await?;
            let parent: FlowRevision = decode(sqlx::query_scalar(
                "SELECT data FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2 FOR SHARE"
            ).bind(&flow.project_id).bind(i64v(parent_flow_revision)?).fetch_optional(&mut **tx).await?
                .ok_or_else(|| err("REVISION_CONFLICT", "parent flow no longer exists"))?)?;
            if parent.revision != parent_expected_revision
                || flow.parent_revision != Some(parent_flow_revision)
                || flow.flow_revision <= parent_flow_revision
                || flow.state != FlowState::Draft
                || expected_revision.is_some()
            {
                return Err(err(
                    "REVISION_CONFLICT",
                    "reviewed parent identity changed or proposal is not a new draft",
                ));
            }
            let ctx: forgeflow_planner::CompileContext = decode(context.clone())?;
            if ctx.source_revision != expected_source_revision {
                return Err(err("CONTEXT_STALE", "reviewed requirement source changed"));
            }
            validate_authoritative_context(tx, &flow.project_id, &ctx).await?;
            for task in &flow.tasks {
                if parent
                    .tasks
                    .iter()
                    .find(|t| t.task_id == task.task_id)
                    .is_some_and(|old| old.owner_id != task.owner_id || old.team_id != task.team_id)
                {
                    let previous = parent
                        .tasks
                        .iter()
                        .find(|t| t.task_id == task.task_id)
                        .expect("reviewed parent task");
                    if task.task_revision != previous.task_revision + 1
                        || task.envelope.is_some()
                        || task.state != TaskPlanningState::NeedsReview
                    {
                        return Err(err(
                            "REVISION_CONFLICT",
                            "assignment must invalidate execution template and advance reviewed task definition once",
                        ));
                    }
                    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND task_id=$2 AND terminal_at IS NULL)")
                        .bind(&flow.project_id).bind(&task.task_id).fetch_one(&mut **tx).await?;
                    if active {
                        return Err(err(
                            "ACTIVE_ATTEMPT",
                            "assignment changed while an attempt is active",
                        ));
                    }
                }
            }
            put_flow(tx, flow, expected_revision, Some(context)).await
        }
    }
}
pub(crate) async fn validate_native_panel_enqueue(
    tx: &mut Transaction<'_, Postgres>,
    task: &TaskCard,
) -> Result<()> {
    let Some(envelope) = &task.envelope else {
        return Ok(());
    };
    let profile: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='executor_profiles' AND document_id=$2")
        .bind(&task.project_id).bind(&envelope.executor_profile_id).fetch_optional(&mut **tx).await?;
    let policies: Vec<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='planning_catalogs' AND data#>>'{metadata,development_entrypoint}'='DSH_NATIVE_OPERATION_PANEL'")
        .bind(&task.project_id).fetch_all(&mut **tx).await?;
    let restricted = !policies.is_empty();
    if profile.as_ref().is_none_or(|v| v["kind"] != "DSH_MANAGED") {
        if restricted
            && retained_candidate_task_binding_tx(tx, task)
                .await?
                .is_some()
        {
            let gate = native_panel_scheduling_in_transaction(tx, &task.project_id).await?;
            if gate["paused"] == true {
                return Err(err(
                    "NATIVE_SCHEDULING_PAUSED",
                    "Native panel has paused new controlled candidate verification",
                ));
            }
            return Ok(());
        }
        if restricted {
            return Err(err(
                "NATIVE_EXECUTOR_REQUIRED",
                "this project's reviewed development policy requires an actual registered managed DSH executor",
            ));
        }
        return Ok(());
    }
    let gate = native_panel_scheduling_in_transaction(tx, &task.project_id).await?;
    if gate["paused"] == true {
        return Err(err(
            "NATIVE_SCHEDULING_PAUSED",
            "native panel has paused new Root attempts; existing leases, models and child lifecycles remain governed by their original authority",
        ));
    }
    let retry = native_panel_retry_policy_in_transaction(
        tx,
        &task.project_id,
        &task.task_id,
        task.task_revision,
    )
    .await?;
    if retry["blocked"] == true {
        return Err(err(
            "NATIVE_RETRY_REQUIRED",
            "the Native UI cancelled this semantic task revision; a newer explicit retry of its latest terminal attempt is required",
        ));
    }
    if !restricted {
        return Ok(());
    }
    let context: Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2")
        .bind(&task.project_id).bind(task.flow_revision.to_string()).fetch_optional(&mut **tx).await?
        .ok_or_else(||err("NATIVE_PANEL_ORIGIN_REQUIRED", "committed task context is missing"))?;
    let spec: forgeflow_planner::TaskSpec = decode(context["task_specs"][&task.task_id].clone())?;
    let actions: Vec<&str> = spec
        .design_anchors
        .iter()
        .filter_map(|a| a.strip_prefix("forgeflow:native-panel-action:"))
        .collect();
    if actions.len() != 1 || uuid::Uuid::parse_str(actions[0]).is_err() {
        return Err(err(
            "NATIVE_PANEL_ORIGIN_REQUIRED",
            "native delivery must bind one actual DSH panel action in its reviewed task inputs",
        ));
    }
    let action: Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='native_panel_actions' AND document_id=$2 FOR SHARE")
        .bind(&task.project_id).bind(actions[0]).fetch_optional(&mut **tx).await?
        .ok_or_else(||err("NATIVE_PANEL_ORIGIN_REQUIRED", "native panel action is not registered"))?;
    // Stopping an incomplete delivery supervisor marks its START failed; it
    // does not revoke the frozen tasks that START actually authorized. Require
    // immutable service evidence of its confirmed startup, while the current
    // scheduling gate above still requires a separately active Native START.
    let confirmed_prior_start = if action["action"] == "START"
        && action["status"] == "FAILED"
        && action["result"]["source"] == "ACTUAL_SYSTEMD_UNIT_AND_POSTGRESQL"
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM events WHERE project_id=$1 AND object_id=$2 AND kind='native.panel_action_observed' AND payload->>'entry_source'='DSH_NATIVE_PANEL' AND payload->>'action'='START' AND payload->>'status'='RUNNING' AND payload->>'config_sha256'=$3 AND payload->>'alignment_sha256'=$4 AND payload->'result'->>'helper_exit_confirmed'='true' AND (payload->'result'->>'actual_service_main_pid') ~ '^[1-9][0-9]*$')")
            .bind(&task.project_id).bind(actions[0])
            .bind(action["config_sha256"].as_str().unwrap_or(""))
            .bind(action["alignment_sha256"].as_str().unwrap_or(""))
            .fetch_one(&mut **tx).await?
    } else {
        false
    };
    if action["entry_source"] != "DSH_NATIVE_PANEL"
        || !matches!(
            action["action"].as_str(),
            Some("START" | "PREPARE" | "REPLAN" | "RETRY")
        )
        || !(confirmed_prior_start
            || matches!(
                action["status"].as_str(),
                Some("ACCEPTED" | "RUNNING" | "SUCCEEDED")
            ))
        || action["project_id"].as_str() != Some(&task.project_id)
        || !action["config_sha256"].as_str().is_some_and(valid_digest)
        || !action["alignment_sha256"]
            .as_str()
            .is_some_and(valid_digest)
    {
        return Err(err(
            "NATIVE_PANEL_ORIGIN_REQUIRED",
            "native panel action is not an eligible frozen delivery origin",
        ));
    }
    for (prefix, key) in [
        ("forgeflow:native-panel-config:", "config_sha256"),
        ("forgeflow:native-panel-alignment:", "alignment_sha256"),
    ] {
        for hash in spec
            .design_anchors
            .iter()
            .filter_map(|a| a.strip_prefix(prefix))
        {
            if action[key].as_str() != Some(hash) {
                return Err(err(
                    "NATIVE_PANEL_CONFIG_STALE",
                    "reviewed task pins differ from the frozen native panel action",
                ));
            }
        }
    }
    Ok(())
}

const NATIVE_PANEL_SCHEDULING_QUERY: &str = "SELECT d.data || jsonb_build_object('requested_sequence',e.project_seq) FROM documents d JOIN events e ON e.project_id=d.project_id AND e.object_id=d.document_id AND e.kind='native.panel_action_requested' WHERE d.project_id=$1 AND d.collection='native_panel_actions' AND d.data->>'entry_source'='DSH_NATIVE_PANEL' AND d.data->>'action' IN ('PAUSE','START') ORDER BY e.project_seq DESC LIMIT 1";

fn native_panel_scheduling_projection(project: &str, action: Option<Value>) -> Value {
    let action = action.unwrap_or(Value::Null);
    let start = action["action"] == "START";
    let opened = start && matches!(action["status"].as_str(), Some("RUNNING" | "SUCCEEDED"));
    let paused = !action.is_null() && !opened;
    serde_json::json!({"project_id":project,"paused":paused,"action_id":action["action_id"],
        "action":action["action"],"action_status":action["status"],"requested_sequence":action["requested_sequence"],
        "start_pending":start&&action["status"]=="ACCEPTED","source":"POSTGRESQL_NATIVE_PANEL_ACTION"})
}

async fn native_panel_scheduling_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
) -> Result<Value> {
    let action: Option<Value> = sqlx::query_scalar(NATIVE_PANEL_SCHEDULING_QUERY)
        .bind(project)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(native_panel_scheduling_projection(project, action))
}

impl Store {
    /// Pause intent is ordered by the request's committed event sequence, not
    /// clock time or a later asynchronous settlement of an older START.
    pub async fn native_panel_scheduling(&self, project: &str) -> Result<Value> {
        let action: Option<Value> = sqlx::query_scalar(NATIVE_PANEL_SCHEDULING_QUERY)
            .bind(project)
            .fetch_optional(&self.pool)
            .await?;
        Ok(native_panel_scheduling_projection(project, action))
    }
}

const NATIVE_PANEL_RETRY_QUERY: &str = r#"
WITH actions AS (
    SELECT d.data,e.project_seq FROM documents d JOIN events e
      ON e.project_id=d.project_id AND e.object_id=d.document_id AND e.kind='native.panel_action_requested'
    WHERE d.project_id=$1 AND d.collection='native_panel_actions'
      AND d.data->>'entry_source'='DSH_NATIVE_PANEL' AND d.data->>'action' IN ('CANCEL','RETRY')
), latest_cancel AS (
    SELECT a.data,a.project_seq,t.attempt_id FROM actions a JOIN attempts t
      ON t.project_id=$1 AND t.task_id=$2 AND t.task_revision=$3
      AND (a.data->>'attempt_id'=t.attempt_id OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(a.data#>'{result,cancellations}')='array'
              THEN a.data#>'{result,cancellations}' ELSE '[]'::jsonb END) c WHERE c->>'attempt_id'=t.attempt_id))
    WHERE a.data->>'action'='CANCEL' AND (a.data->>'status'<>'FAILED' OR t.state='CANCELLED')
    ORDER BY a.project_seq DESC,t.generation DESC LIMIT 1
), latest_attempt AS (
    SELECT attempt_id,state FROM attempts WHERE project_id=$1 AND task_id=$2 AND task_revision=$3
    ORDER BY generation DESC LIMIT 1
), latest_retry AS (
    SELECT a.data,a.project_seq,t.attempt_id FROM actions a JOIN attempts t
      ON t.project_id=$1 AND t.task_id=$2 AND t.task_revision=$3 AND a.data->>'attempt_id'=t.attempt_id
    WHERE a.data->>'action'='RETRY' AND a.data->>'status' IN ('ACCEPTED','RUNNING','SUCCEEDED')
      AND a.project_seq>COALESCE((SELECT project_seq FROM latest_cancel),0)
    ORDER BY a.project_seq DESC LIMIT 1
)
SELECT jsonb_build_object(
    'project_id',$1::text,'task_id',$2::text,'task_revision',$3::bigint,
    'cancel_action_id',(SELECT data->'action_id' FROM latest_cancel),
    'cancel_attempt_id',(SELECT attempt_id FROM latest_cancel),
    'cancel_sequence',(SELECT project_seq FROM latest_cancel),
    'retry_action_id',(SELECT data->'action_id' FROM latest_retry),
    'retry_attempt_id',(SELECT attempt_id FROM latest_retry),
    'retry_sequence',(SELECT project_seq FROM latest_retry),
    'retry_target_current',EXISTS(SELECT 1 FROM latest_retry r JOIN latest_attempt t ON t.attempt_id=r.attempt_id WHERE t.state IN ('FAILED','CANCELLED')),
    'retry_consumed',EXISTS(SELECT 1 FROM attempts t WHERE t.project_id=$1 AND t.task_id=$2 AND t.task_revision=$3
        AND t.execution_bindings#>>'{native_retry_authorization,action_id}'=(SELECT data->>'action_id' FROM latest_retry)))
"#;

fn native_panel_retry_projection(mut value: Value) -> Value {
    let authorized = !value["retry_action_id"].is_null()
        && value["retry_target_current"] == true
        && value["retry_consumed"] != true;
    value["explicit_retry_authorized"] = authorized.into();
    value["blocked"] = (!value["cancel_action_id"].is_null() && !authorized).into();
    value["source"] = "POSTGRESQL_NATIVE_PANEL_ACTIONS".into();
    value
        .as_object_mut()
        .unwrap()
        .remove("retry_target_current");
    value
}

pub(crate) async fn native_panel_retry_policy_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    task: &str,
    revision: u64,
) -> Result<Value> {
    let value: Value = sqlx::query_scalar(NATIVE_PANEL_RETRY_QUERY)
        .bind(project)
        .bind(task)
        .bind(i64v(revision)?)
        .fetch_one(&mut **tx)
        .await?;
    Ok(native_panel_retry_projection(value))
}

impl Store {
    pub async fn native_panel_retry_policy(
        &self,
        project: &str,
        task: &str,
        revision: u64,
    ) -> Result<Value> {
        let value: Value = sqlx::query_scalar(NATIVE_PANEL_RETRY_QUERY)
            .bind(project)
            .bind(task)
            .bind(i64v(revision)?)
            .fetch_one(&self.pool)
            .await?;
        Ok(native_panel_retry_projection(value))
    }
}
/// Import the complete reviewed planning denominator without making unbound
/// cards executable or replacing the current committed execution Flow.
async fn register_planning_catalog(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    expected: Option<u64>,
    mut catalog: PlanningCatalogRegistration,
    persist: bool,
) -> Result<Value> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    project_lock(tx, p).await?;
    if catalog.schema_version != "forgeflow.planning.catalog.v1"
        || catalog.catalog_id.is_empty()
        || catalog.cards.is_empty()
        || catalog.cards.len() > 10_000
        || catalog.roster.len() > 10_000
        || catalog.expected_card_count != catalog.cards.len() as u64
        || catalog.expected_role_count != catalog.roster.len() as u64
        || !(catalog.metadata.is_object() || catalog.metadata.is_null())
    {
        return Err(err(
            "PLANNING_CATALOG_INVALID",
            "schema, identities, bounded denominator and metadata must agree",
        ));
    }
    let old_catalog: Option<Value> = sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='planning_catalogs' AND document_id=$2 FOR UPDATE")
        .bind(p).bind(&catalog.catalog_id).fetch_optional(&mut **tx).await?;
    if old_catalog.as_ref().and_then(|v| v["revision"].as_u64()) != expected {
        return Err(err(
            "REVISION_CONFLICT",
            "planning catalog revision changed",
        ));
    }
    let requirements: Vec<Requirement> = sqlx::query_scalar(
        "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id FOR SHARE",
    )
    .bind(p)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(decode)
    .collect::<Result<_>>()?;
    let source_revision = forgeflow_planner::sha256(&serde_json::to_vec(&requirements)?);
    if requirements.is_empty() || catalog.source_revision != source_revision {
        return Err(err(
            "REQUIREMENT_COVERAGE_STALE",
            "planning source revision must bind the complete current requirement authority",
        ));
    }
    let requirement_hashes: BTreeMap<String, String> = requirements
        .iter()
        .map(|r| {
            (
                r.requirement_id.clone(),
                forgeflow_planner::requirement_semantic_digest(r),
            )
        })
        .collect();
    let teams: BTreeMap<String, Team> = sqlx::query_scalar(
        "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id FOR SHARE",
    )
    .bind(p)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(decode::<Team>)
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .map(|team| (team.team_id.clone(), team))
    .collect();
    let owners: BTreeMap<String, forgeflow_planner::OwnerTerritory> = sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='owners' ORDER BY document_id FOR SHARE")
        .bind(p).fetch_all(&mut **tx).await?.into_iter().map(decode::<forgeflow_planner::OwnerTerritory>).collect::<Result<Vec<_>>>()?
        .into_iter().map(|owner| (owner.owner_id.clone(), owner)).collect();
    let input_rows: Vec<Value> = sqlx::query_scalar(
        "SELECT data FROM documents WHERE project_id=$1 AND collection='input_snapshots'",
    )
    .bind(p)
    .fetch_all(&mut **tx)
    .await?;
    let input_hashes: BTreeMap<String, String> = input_rows
        .iter()
        .filter_map(|v| {
            Some((
                v.get("path")
                    .or_else(|| v.get("relative_path"))?
                    .as_str()?
                    .to_owned(),
                v["sha256"].as_str()?.to_owned(),
            ))
        })
        .collect();
    let profile_rows: Vec<(String, String)> = sqlx::query_as("SELECT collection,document_id FROM documents WHERE project_id=$1 AND collection IN ('executor_profiles','verification_plans')")
        .bind(p).fetch_all(&mut **tx).await?;
    let profiles: BTreeSet<_> = profile_rows.into_iter().collect();
    let previous_rows: Vec<Value> = sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='planning_cards' FOR UPDATE")
        .bind(p).fetch_all(&mut **tx).await?;
    let previous: BTreeMap<String, Value> = previous_rows
        .into_iter()
        .filter_map(|v| Some((v["task_id"].as_str()?.to_owned(), v)))
        .collect();
    let ids: BTreeSet<String> = catalog
        .cards
        .iter()
        .map(|c| c.task.task_id.clone())
        .collect();
    if ids.len() != catalog.cards.len() || ids.iter().any(String::is_empty) {
        return Err(err(
            "PLANNING_CATALOG_INVALID",
            "planning task identities must be unique and nonempty",
        ));
    }
    if let Some(old) = &old_catalog {
        let prior: BTreeSet<String> = old["task_ids"]
            .as_array()
            .ok_or_else(|| {
                err(
                    "EVIDENCE_INCOMPLETE",
                    "prior catalog task identities missing",
                )
            })?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if prior != ids {
            return Err(err(
                "PLANNING_DENOMINATOR_CHANGED",
                "catalog updates preserve the full registered denominator; use an explicit new catalog for a changed scope",
            ));
        }
    }
    let mut indegree: BTreeMap<String, usize> = ids.iter().map(|id| (id.clone(), 0)).collect();
    let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut covered = BTreeSet::new();
    let mut edge_count = 0_u64;
    let mut rows = Vec::with_capacity(catalog.cards.len());
    let mut blocker_counts = BTreeMap::<String, u64>::new();
    let contains = |scope: &str, path: &str| {
        if scope.ends_with('/') {
            path.starts_with(scope)
        } else {
            scope == path
        }
    };
    for card in &mut catalog.cards {
        let task = &mut card.task;
        if task.project_id != p
            || task.task_revision == 0
            || task.flow_revision == 0
            || task.title.trim().is_empty()
            || task.state != TaskPlanningState::NeedsReview
            || task.envelope.is_some()
            || task.requirement_ids.is_empty()
            || !(card.metadata.is_object() || card.metadata.is_null())
            || task
                .resource_request
                .dimensions()
                .iter()
                .any(|(_, v)| *v > i64::MAX as u64)
        {
            return Err(err(
                "PLANNING_CATALOG_INVALID",
                format!(
                    "{} must be a non-executable, bounded, scoped planning card",
                    task.task_id
                ),
            ));
        }
        let owner = owners.get(&task.owner_id).ok_or_else(|| {
            err(
                "OWNER_PATH_VIOLATION",
                format!("{} owner is unregistered", task.task_id),
            )
        })?;
        if !teams.contains_key(&task.team_id) {
            return Err(err(
                "TEAM_NOT_FOUND",
                format!("{} execution team is unregistered", task.task_id),
            ));
        }
        if let Some(root) = &owner.root_team_id {
            let mut ancestor = Some(task.team_id.clone());
            let mut seen = BTreeSet::new();
            while let Some(id) = ancestor {
                if !seen.insert(id.clone()) {
                    return Err(err("TEAM_CYCLE", "execution team ancestry is cyclic"));
                }
                if &id == root {
                    break;
                }
                ancestor = teams.get(&id).and_then(|t| t.parent_team_id.clone());
            }
            if !seen.contains(root) {
                return Err(err(
                    "OWNER_PATH_VIOLATION",
                    "execution team is outside the owner root team",
                ));
            }
        }
        for path in task.read_set.iter().chain(&task.write_set) {
            validate_relative_path(path)?;
        }
        for path in &task.write_set {
            if !owner.include.iter().any(|scope| contains(scope, path))
                || owner.exclude.iter().any(|scope| contains(scope, path))
            {
                return Err(err(
                    "OWNER_PATH_VIOLATION",
                    format!(
                        "{} write path is outside its registered territory: {path}",
                        task.task_id
                    ),
                ));
            }
        }
        let requirement_ids: BTreeSet<_> = task.requirement_ids.iter().collect();
        if requirement_ids.len() != task.requirement_ids.len()
            || requirement_ids
                .iter()
                .any(|id| !requirement_hashes.contains_key(*id))
        {
            return Err(err(
                "REQUIREMENT_NOT_FOUND",
                format!(
                    "{} requirement references are missing or repeated",
                    task.task_id
                ),
            ));
        }
        covered.extend(task.requirement_ids.iter().cloned());
        let mut spec: forgeflow_planner::TaskSpec = decode(card.spec.clone())?;
        if spec.outcome.trim().is_empty()
            || spec.rollback_plan.trim().is_empty()
            || spec.design_anchors.is_empty()
        {
            return Err(err(
                "PLANNING_CATALOG_INVALID",
                "outcome, design anchors and rollback must be explicit",
            ));
        }
        spec.requirement_digest_refs = task
            .requirement_ids
            .iter()
            .map(|id| (id.clone(), requirement_hashes[id].clone()))
            .collect();
        let dependencies: BTreeSet<_> = task.dependencies.iter().collect();
        if dependencies.len() != task.dependencies.len()
            || dependencies
                .iter()
                .any(|id| *id == &task.task_id || !ids.contains(*id))
        {
            return Err(err(
                "DEPENDENCY_UNSATISFIED",
                "planning dependencies must be unique references to the same catalog",
            ));
        }
        let spec_dependencies: BTreeSet<_> = spec
            .dependency_refs
            .iter()
            .map(|d| d.task_id.clone())
            .collect();
        if spec_dependencies != task.dependencies.iter().cloned().collect()
            || spec.dependency_refs.len() != task.dependencies.len()
            || spec
                .dependency_refs
                .iter()
                .any(|d| d.project_id != p || d.binding_id.is_empty())
        {
            return Err(err(
                "DEPENDENCY_UNSATISFIED",
                "planning task and typed dependency meanings differ",
            ));
        }
        *indegree.get_mut(&task.task_id).unwrap() = task.dependencies.len();
        for dep in &task.dependencies {
            dependents
                .entry(dep.clone())
                .or_default()
                .push(task.task_id.clone());
        }
        edge_count += task.dependencies.len() as u64;
        let mut bound_paths = BTreeSet::new();
        for input in &spec.inputs {
            validate_relative_path(&input.path)?;
            if !valid_digest(&input.sha256)
                || input.sha256.bytes().all(|b| b == b'0')
                || input_hashes.get(&input.path) != Some(&input.sha256)
                || !bound_paths.insert(input.path.clone())
            {
                return Err(err(
                    "INPUT_HASH_MISMATCH",
                    format!(
                        "{} input must match a real registered snapshot: {}",
                        task.task_id, input.path
                    ),
                ));
            }
        }
        for path in &spec.mandatory_paths {
            validate_relative_path(path)?;
        }
        let unbound_inputs: Vec<_> = task
            .read_set
            .iter()
            .chain(&spec.mandatory_paths)
            .filter(|p| !bound_paths.contains(*p))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut blockers = BTreeSet::new();
        if !unbound_inputs.is_empty() {
            blockers.insert("CONTEXT_INPUTS_UNBOUND".to_owned());
        }
        if !profiles.contains(&(
            "executor_profiles".to_owned(),
            spec.execution_profile.clone(),
        )) {
            blockers.insert("EXECUTOR_PROFILE_UNBOUND".to_owned());
        }
        if spec.verification_plan.is_empty()
            || spec.verification_case_count == 0
            || !profiles.contains(&(
                "verification_plans".to_owned(),
                spec.verification_plan.clone(),
            ))
        {
            blockers.insert("VERIFICATION_PLAN_UNBOUND".to_owned());
        }
        // Planning has no execution envelope, even when all recipe inputs exist.
        blockers.insert("EXECUTION_ENVELOPE_UNBOUND".to_owned());
        if let Some(extra) = card.metadata.get("admission_blockers") {
            let extra = extra.as_array().ok_or_else(|| {
                err(
                    "PLANNING_CATALOG_INVALID",
                    "admission_blockers must be a string array",
                )
            })?;
            for blocker in extra {
                blockers.insert(
                    blocker
                        .as_str()
                        .ok_or_else(|| {
                            err(
                                "PLANNING_CATALOG_INVALID",
                                "admission blocker must be a string",
                            )
                        })?
                        .to_owned(),
                );
            }
        }
        task.input_digest = forgeflow_planner::canonical_task_input_digest(task, &spec);
        task.revision = 1;
        let mut revision = 1_u64;
        if let Some(old) = previous.get(&task.task_id) {
            if old["catalog_id"].as_str() != Some(&catalog.catalog_id) {
                return Err(err(
                    "PLANNING_CATALOG_CONFLICT",
                    "task identity already belongs to another planning catalog",
                ));
            }
            if old["task"]["input_digest"].as_str() != Some(&task.input_digest)
                && task.task_revision <= old["task"]["task_revision"].as_u64().unwrap_or(0)
            {
                return Err(err(
                    "REVISION_CONFLICT",
                    "changed planning task meaning requires a new task revision",
                ));
            }
            revision = old["revision"].as_u64().ok_or_else(|| {
                err(
                    "EVIDENCE_INCOMPLETE",
                    "registered planning card revision missing",
                )
            })? + 1;
        }
        for blocker in &blockers {
            *blocker_counts.entry(blocker.clone()).or_default() += 1;
        }
        rows.push(serde_json::json!({"document_id":task.task_id,"revision":revision,"data":{
            "schema_version":"forgeflow.planning.card.v1","project_id":p,"catalog_id":catalog.catalog_id,
            "task_id":task.task_id,"task":task,"spec":spec,"metadata":card.metadata,
            "source_revision":source_revision,"planning_only":true,"admission_blockers":blockers,
            "unbound_input_paths":unbound_inputs,"revision":revision}}));
    }
    if catalog
        .expected_edge_count
        .is_some_and(|count| count != edge_count)
    {
        return Err(err(
            "PLANNING_CATALOG_INVALID",
            "dependency edge denominator differs",
        ));
    }
    let mut frontier: VecDeque<_> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut visited = 0;
    while let Some(id) = frontier.pop_front() {
        visited += 1;
        for child in dependents.get(&id).into_iter().flatten() {
            let degree = indegree.get_mut(child).unwrap();
            *degree -= 1;
            if *degree == 0 {
                frontier.push_back(child.clone());
            }
        }
    }
    if visited != ids.len() {
        return Err(err(
            "FLOW_CYCLE",
            "registered planning dependency graph must be acyclic",
        ));
    }
    let mut role_ids = BTreeSet::new();
    for role in &catalog.roster {
        let id = role["agent_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| err("PLANNING_CATALOG_INVALID", "planned role identity required"))?;
        if !role_ids.insert(id.to_owned())
            || role["state"].as_str() != Some("PLANNED")
            || !role["runtime_pid"].is_null()
            || !role["lease_id"].is_null()
            || role["owner_id"]
                .as_str()
                .is_none_or(|owner| !owners.contains_key(owner))
            || role["team_id"]
                .as_str()
                .is_none_or(|team| !teams.contains_key(team))
        {
            return Err(err(
                "PLANNING_CATALOG_INVALID",
                "roster roles must be unique registered planning identities without runtime claims",
            ));
        }
    }
    for role in &catalog.roster {
        if role["parent_agent_id"].as_str().is_some_and(|parent| {
            !role_ids.contains(parent) || role["agent_id"].as_str() == Some(parent)
        }) {
            return Err(err(
                "PLANNING_CATALOG_INVALID",
                "role parent must be a distinct registered roster identity",
            ));
        }
        let mut cursor = role["parent_agent_id"].as_str();
        let mut seen = BTreeSet::new();
        while let Some(parent) = cursor {
            if !seen.insert(parent) {
                return Err(err("TEAM_CYCLE", "planned role ancestry must be acyclic"));
            }
            cursor = catalog
                .roster
                .iter()
                .find(|r| r["agent_id"].as_str() == Some(parent))
                .and_then(|r| r["parent_agent_id"].as_str());
        }
    }
    let revision = expected.unwrap_or(0) + 1;
    let cards_sha256 = forgeflow_planner::sha256(&serde_json::to_vec(&rows)?);
    let summary = serde_json::json!({"schema_version":"forgeflow.planning.catalog.v1","project_id":p,
        "catalog_id":catalog.catalog_id,"revision":revision,"source_revision":source_revision,
        "planning_only":true,"card_count":ids.len(),"role_count":role_ids.len(),"edge_count":edge_count,
        "parent_count":catalog.parents.len(),"task_ids":ids,"parents":catalog.parents,"roster":catalog.roster,
        "metadata":catalog.metadata,"cards_sha256":cards_sha256,"digest_algorithm":"forgeflow.planning.registered-rows.v1",
        "blocker_counts":blocker_counts,"requirement_count":requirement_hashes.len(),"covered_requirement_count":covered.len(),
        "uncovered_requirement_ids":requirement_hashes.keys().filter(|id| !covered.contains(*id)).collect::<Vec<_>>(),
        "execution_ready_cards":0,"observed_at":db_now(tx).await?.to_rfc3339()});
    if !persist {
        return Ok(summary);
    }
    // One bounded JSONB insert keeps the full import in one transaction without
    // one network round trip or one large SSE payload per card.
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) SELECT $1,'planning_cards',r.document_id,r.revision,r.data FROM jsonb_to_recordset($2::jsonb) AS r(document_id text,revision bigint,data jsonb) ON CONFLICT(project_id,collection,document_id) DO UPDATE SET revision=EXCLUDED.revision,data=EXCLUDED.data")
        .bind(p).bind(Value::Array(rows)).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'planning_catalogs',$2,$3,$4) ON CONFLICT(project_id,collection,document_id) DO UPDATE SET revision=EXCLUDED.revision,data=EXCLUDED.data")
        .bind(p).bind(&catalog.catalog_id).bind(i64v(revision)?).bind(&summary).execute(&mut **tx).await?;
    event(
        tx,
        p,
        &catalog.catalog_id,
        revision,
        "planning.catalog_registered",
        serde_json::json!({
        "catalog_id":catalog.catalog_id,"card_count":ids.len(),"role_count":role_ids.len(),
        "edge_count":edge_count,"cards_sha256":cards_sha256,"planning_only":true}),
    )
    .await?;
    Ok(summary)
}
async fn put_flow(
    tx: &mut Transaction<'_, Postgres>,
    mut f: FlowRevision,
    expected: Option<u64>,
    mut context: Option<Value>,
) -> Result<Value> {
    project_lock(tx, &f.project_id).await?;
    if f.flow_revision == 0 || !valid_digest(&f.input_digest) {
        return Err(err(
            "VALIDATION_ERROR",
            "flow identity and input hash required",
        ));
    }
    let old=sqlx::query("SELECT revision,state FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2 FOR UPDATE").bind(&f.project_id).bind(i64v(f.flow_revision)?).fetch_optional(&mut **tx).await?;
    if old.as_ref().map(|r| r.get::<i64, _>("revision") as u64) != expected {
        return Err(err("REVISION_CONFLICT", "flow revision changed"));
    }
    if old.as_ref().is_some_and(|r| {
        matches!(
            r.get::<String, _>("state").as_str(),
            "COMMITTED" | "SUPERSEDED"
        )
    }) {
        return Err(err(
            "REVISION_CONFLICT",
            "committed flow is immutable; create new flow revision",
        ));
    }
    if f.state == FlowState::Committed
        && (f.approved_by.as_ref().is_none_or(String::is_empty) || context.is_none())
    {
        return Err(err(
            "EVIDENCE_INCOMPLETE",
            "commit requires approved identity and compile context",
        ));
    }
    let mut typed_context = None;
    if f.state == FlowState::Committed {
        let supplied: forgeflow_planner::CompileContext = decode(
            context
                .clone()
                .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "compile context required"))?,
        )?;
        validate_authoritative_context(tx, &f.project_id, &supplied).await?;
        let report = forgeflow_planner::compile(&f, &supplied);
        if !report.passed || f.input_digest != report.input_digest {
            return Err(err(
                "FLOW_CHECK_FAILED",
                "committed flow lacks passing compiler check bound to semantic digest",
            ));
        }
        typed_context = Some(supplied);
    }
    let ids: std::collections::BTreeSet<_> = f.tasks.iter().map(|t| t.task_id.as_str()).collect();
    if ids.len() != f.tasks.len() {
        return Err(err("VALIDATION_ERROR", "duplicate task identity"));
    }
    for t in &f.tasks {
        if t.project_id != f.project_id
            || t.flow_revision != f.flow_revision
            || t.task_revision == 0
            || !valid_digest(&t.input_digest)
        {
            return Err(err(
                "VALIDATION_ERROR",
                "task project/revision/input invalid",
            ));
        }
        for p in t.read_set.iter().chain(&t.write_set) {
            validate_relative_path(p)?;
        }
        if t.dependencies
            .iter()
            .any(|d| !ids.contains(d.as_str()) || d == &t.task_id)
        {
            return Err(err(
                "DEPENDENCY_UNSATISFIED",
                "dependency must reference same flow",
            ));
        }
    }
    let mut ready = std::collections::BTreeSet::new();
    loop {
        let before = ready.len();
        for t in &f.tasks {
            if t.dependencies.iter().all(|d| ready.contains(d)) {
                ready.insert(t.task_id.clone());
            }
        }
        if ready.len() == f.tasks.len() {
            break;
        }
        if ready.len() == before {
            return Err(err("FLOW_CYCLE", "dependency graph must be acyclic"));
        }
    }
    if let Some(ctx) = context.as_mut() {
        let observed_at = db_now(tx).await?.to_rfc3339();
        ctx["observed_at"] = observed_at.clone().into();
        if let Some(supplied) = typed_context.as_mut() {
            supplied.observed_at = observed_at;
        }
    }
    if let Some(ctx) = &context {
        let old:Option<i64>=sqlx::query_scalar("SELECT revision FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(&f.project_id).bind(f.flow_revision.to_string()).fetch_optional(&mut **tx).await?;
        put_document(
            tx,
            &f.project_id,
            "flow_contexts",
            &f.flow_revision.to_string(),
            old.map(|x| x as u64),
            ctx.clone(),
        )
        .await?;
    }
    f.revision = expected.unwrap_or(0) + 1;
    sqlx::query("INSERT INTO flow_revisions VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(project_id,flow_revision) DO UPDATE SET revision=EXCLUDED.revision,state=EXCLUDED.state,input_digest=EXCLUDED.input_digest,data=EXCLUDED.data").bind(&f.project_id).bind(i64v(f.flow_revision)?).bind(i64v(f.revision)?).bind(f.state.as_str()).bind(&f.input_digest).bind(json(&f)?).execute(&mut **tx).await?;
    // Only this locked transaction shares these immutable source snapshots.
    // Every task and recursive dependency still undergoes its original checks.
    let mut original_bindings: std::collections::BTreeMap<
        u64,
        (forgeflow_planner::CompileContext, FlowRevision),
    > = std::collections::BTreeMap::new();
    for t in &f.tasks {
        let previous: Option<Value> = sqlx::query_scalar(
            "SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2 FOR UPDATE",
        )
        .bind(&f.project_id)
        .bind(&t.task_id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(previous) = previous {
            let old: TaskCard = decode(previous)?;
            let open:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND task_id=$2 AND terminal_at IS NULL)").bind(&f.project_id).bind(&t.task_id).fetch_one(&mut **tx).await?;
            if f.state != FlowState::Committed {
                continue;
            }
            if open || t.task_revision == old.task_revision {
                if !original_bindings.contains_key(&old.flow_revision) {
                    let old_context:Value=sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(&f.project_id).bind(old.flow_revision.to_string()).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","active task original context missing"))?;
                    let old_context: forgeflow_planner::CompileContext = decode(old_context)?;
                    let old_flow: FlowRevision = decode(
                        sqlx::query_scalar(
                            "SELECT data FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2",
                        )
                        .bind(&f.project_id)
                        .bind(i64v(old.flow_revision)?)
                        .fetch_one(&mut **tx)
                        .await?,
                    )?;
                    original_bindings.insert(old.flow_revision, (old_context, old_flow));
                }
                let (old_context, old_flow) =
                    original_bindings.get(&old.flow_revision).ok_or_else(|| {
                        err(
                            "EVIDENCE_INCOMPLETE",
                            "active task original context missing",
                        )
                    })?;
                let new_context = typed_context
                    .as_ref()
                    .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "active rebind context missing"))?;
                let mut frontier = old.dependencies.clone();
                let mut seen = std::collections::BTreeSet::new();
                while let Some(dep) = frontier.pop() {
                    if !seen.insert(dep.clone()) {
                        continue;
                    }
                    let old_dep = old_flow
                        .tasks
                        .iter()
                        .find(|card| card.task_id == dep)
                        .ok_or_else(|| {
                            err("DEPENDENCY_UNSATISFIED", "original dependency card missing")
                        })?;
                    let new_dep =
                        f.tasks
                            .iter()
                            .find(|card| card.task_id == dep)
                            .ok_or_else(|| {
                                err(
                                    "DEPENDENCY_UNSATISFIED",
                                    "active dependency missing from new flow",
                                )
                            })?;
                    if !forgeflow_planner::task_binding_equivalent(
                        old_dep,
                        old_context,
                        new_dep,
                        new_context,
                    ) {
                        return Err(err(
                            "REVISION_CONFLICT",
                            "reused task dependency authority changed behind same task ID",
                        ));
                    }
                    frontier.extend(old_dep.dependencies.clone());
                }
                if !forgeflow_planner::task_binding_equivalent(&old, old_context, t, new_context) {
                    return Err(err(
                        "REVISION_CONFLICT",
                        "reused task revision binding changed; create a new revision and stop/finish any open attempt",
                    ));
                }
            }
            if t.task_revision < old.task_revision
                || (t.task_revision == old.task_revision
                    && (t.write_set != old.write_set
                        || t.read_set != old.read_set
                        || t.owner_id != old.owner_id
                        || t.team_id != old.team_id
                        || t.dependencies != old.dependencies
                        || t.requirement_ids != old.requirement_ids
                        || t.envelope != old.envelope
                        || t.input_digest != old.input_digest
                        || t.resource_request != old.resource_request))
            {
                return Err(err(
                    "REVISION_CONFLICT",
                    "task semantic change requires new task revision",
                ));
            }
        }
        sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,revision,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(project_id,task_id) DO UPDATE SET task_revision=EXCLUDED.task_revision,flow_revision=EXCLUDED.flow_revision,team_id=EXCLUDED.team_id,owner_id=EXCLUDED.owner_id,state=EXCLUDED.state,input_digest=EXCLUDED.input_digest,revision=EXCLUDED.revision,data=EXCLUDED.data").bind(&t.project_id).bind(&t.task_id).bind(i64v(t.task_revision)?).bind(i64v(t.flow_revision)?).bind(&t.team_id).bind(&t.owner_id).bind(t.state.as_str()).bind(&t.input_digest).bind(i64v(t.revision.max(1))?).bind(json(t)?).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO task_revisions VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(&t.project_id)
            .bind(&t.task_id)
            .bind(i64v(t.task_revision)?)
            .bind(json(t)?)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("DELETE FROM task_dependencies WHERE project_id=$1 AND flow_revision=$2")
        .bind(&f.project_id)
        .bind(i64v(f.flow_revision)?)
        .execute(&mut **tx)
        .await?;
    for t in &f.tasks {
        for d in &t.dependencies {
            sqlx::query("INSERT INTO task_dependencies VALUES($1,$2,$3,$4)")
                .bind(&f.project_id)
                .bind(i64v(f.flow_revision)?)
                .bind(&t.task_id)
                .bind(d)
                .execute(&mut **tx)
                .await?;
        }
    }

    if f.state == FlowState::Committed {
        let removed:Vec<Value>=sqlx::query_scalar("SELECT data FROM tasks WHERE project_id=$1 AND task_id<>ALL($2) ORDER BY task_id FOR UPDATE").bind(&f.project_id).bind(f.tasks.iter().map(|t|t.task_id.clone()).collect::<Vec<_>>()).fetch_all(&mut **tx).await?;
        for value in removed {
            let mut task: TaskCard = decode(value)?;
            if task.state == TaskPlanningState::RemovedFromPlan {
                continue;
            }
            task.state = TaskPlanningState::RemovedFromPlan;
            task.revision += 1;
            sqlx::query("UPDATE tasks SET state='REMOVED_FROM_PLAN',revision=$3,data=$4 WHERE project_id=$1 AND task_id=$2").bind(&task.project_id).bind(&task.task_id).bind(i64v(task.revision)?).bind(json(&task)?).execute(&mut **tx).await?;
            event(
                tx,
                &task.project_id,
                &task.task_id,
                task.revision,
                "task.removed_from_plan",
                json(&task)?,
            )
            .await?;
        }
        let previous:Vec<Value>=sqlx::query_scalar("SELECT data FROM flow_revisions WHERE project_id=$1 AND flow_revision<>$2 AND state='COMMITTED' ORDER BY flow_revision FOR UPDATE").bind(&f.project_id).bind(i64v(f.flow_revision)?).fetch_all(&mut **tx).await?;
        for value in previous {
            let mut old: FlowRevision = decode(value)?;
            old.state = FlowState::Superseded;
            old.revision += 1;
            sqlx::query("UPDATE flow_revisions SET state='SUPERSEDED',data=$3,revision=$4 WHERE project_id=$1 AND flow_revision=$2").bind(&old.project_id).bind(i64v(old.flow_revision)?).bind(json(&old)?).bind(i64v(old.revision)?).execute(&mut **tx).await?;
            event(
                tx,
                &old.project_id,
                &old.flow_revision.to_string(),
                old.revision,
                "flow.superseded",
                json(&old)?,
            )
            .await?;
        }
    }
    if f.state == FlowState::Committed {
        let mut normalized = context
            .clone()
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "committed compiler context missing"))?;
        normalized["observed_at"] = String::new().into();
        let context_hash = forgeflow_planner::sha256(&serde_json::to_vec(&normalized)?);
        let receipt = serde_json::json!({"passed":true,"project_id":f.project_id,"flow_revision":f.flow_revision,"object_revision":f.revision,"digest_algorithm":forgeflow_planner::FLOW_APPROVAL_DIGEST_ALGORITHM,"task_input_digest_algorithm":forgeflow_planner::TASK_INPUT_DIGEST_ALGORITHM,"flow_digest":f.input_digest,"context_digest":context_hash,"static_template_digests":f.tasks.iter().filter_map(|t|t.envelope.as_ref().map(|e|(t.task_id.clone(),forgeflow_planner::static_execution_template_digest(e)))).collect::<std::collections::BTreeMap<_,_>>(),"approved_by":f.approved_by});
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'compiler_receipts',$2,1,$3)").bind(&f.project_id).bind(f.flow_revision.to_string()).bind(receipt).execute(&mut **tx).await?;
    }
    event(
        tx,
        &f.project_id,
        &f.flow_revision.to_string(),
        f.revision,
        "flow.updated",
        json(&f)?,
    )
    .await?;
    json(&f)
}

pub(crate) async fn validate_authoritative_context(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    context: &forgeflow_planner::CompileContext,
) -> Result<()> {
    let requirement_values: Vec<Value> = sqlx::query_scalar(
        "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id FOR SHARE",
    )
    .bind(p)
    .fetch_all(&mut **tx)
    .await?;
    let requirements: Vec<Requirement> = requirement_values
        .into_iter()
        .map(decode)
        .collect::<Result<_>>()?;
    let expected: Vec<forgeflow_planner::Requirement> = requirements
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
    let semantic_digests: std::collections::BTreeMap<String, String> = requirements
        .iter()
        .map(|r| {
            (
                r.requirement_id.clone(),
                forgeflow_planner::requirement_semantic_digest(r),
            )
        })
        .collect();
    if context.requirement_semantic_digests != semantic_digests {
        return Err(err(
            "REQUIREMENT_COVERAGE_STALE",
            "requirement outcome/scope/weight semantics differ from complete current authority",
        ));
    }
    let source_revision = forgeflow_planner::sha256(&serde_json::to_vec(&requirements)?);
    if expected.is_empty()
        || json(&expected)? != json(&context.requirements)?
        || context.source_revision != source_revision
    {
        return Err(err(
            "REQUIREMENT_COVERAGE_STALE",
            "compiler requirements must equal the complete current authority denominator",
        ));
    }
    let owners:Vec<Value>=sqlx::query_scalar("SELECT data - 'revision' FROM documents WHERE project_id=$1 AND collection='owners' ORDER BY document_id FOR UPDATE").bind(p).fetch_all(&mut **tx).await?;
    if owners.is_empty() {
        return Err(err(
            "OWNER_PATH_VIOLATION",
            "registered authoritative owner territories required",
        ));
    }
    let actual: Vec<forgeflow_planner::OwnerTerritory> =
        owners.into_iter().map(decode).collect::<Result<_>>()?;
    if json(&actual)? != json(&context.owners)? {
        return Err(err(
            "OWNER_PATH_VIOLATION",
            "compiler owner snapshot differs from authoritative territories",
        ));
    }
    for (path, digest) in &context.current_inputs {
        validate_relative_path(path)?;
        let snapshot:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='input_snapshots' AND document_id=$2 FOR UPDATE").bind(p).bind(path).fetch_optional(&mut **tx).await?;
        if snapshot
            .as_ref()
            .and_then(|s| s.get("sha256"))
            .and_then(Value::as_str)
            != Some(digest)
        {
            return Err(err(
                "CONTEXT_STALE",
                "compiler input snapshot is not registered authoritative hash",
            ));
        }
    }
    for contract in &context.contracts {
        let frozen:Option<Value>=sqlx::query_scalar("SELECT data FROM contract_versions WHERE project_id=$1 AND contract_id=$2 AND version=$3 AND state='FROZEN'").bind(p).bind(&contract.contract_id).bind(i64v(contract.version)?).fetch_optional(&mut **tx).await?;
        if contract.frozen && frozen.is_none() {
            return Err(err(
                "CONTRACT_NOT_FROZEN",
                "compiler contract freeze is not authoritative",
            ));
        }
        if let Some(frozen) = frozen {
            if frozen.get("spec_sha256").and_then(Value::as_str) != Some(&contract.spec_sha256)
                || frozen.get("source_sha256").and_then(Value::as_str)
                    != Some(&contract.source_sha256)
            {
                return Err(err(
                    "CONTRACT_NOT_FROZEN",
                    "contract digest differs from frozen authority",
                ));
            }
            if contract.frozen
                && (frozen.get("frozen").and_then(Value::as_bool) != Some(true)
                    || frozen.get("required_consumers")
                        != Some(&serde_json::to_value(&contract.required_consumers)?)
                    || frozen.get("passing_consumers")
                        != Some(&serde_json::to_value(&contract.passing_consumers)?)
                    || frozen.get("independent_receipt_id").and_then(Value::as_str)
                        != contract.independent_receipt_id.as_deref()
                    || frozen.get("integration_receipt_id").and_then(Value::as_str)
                        != contract.integration_receipt_id.as_deref())
            {
                return Err(err(
                    "CONTRACT_NOT_FROZEN",
                    "frozen contract consumer and receipt proof differs from canonical authority",
                ));
            }
        }
    }
    Ok(())
}
impl Store {
    pub async fn project_cursor(&self, p: &str) -> Result<u64> {
        let cursor: Option<i64> =
            sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                .bind(p)
                .fetch_optional(&self.pool)
                .await?;
        Ok(cursor.ok_or_else(|| err("NOT_FOUND", "project not found"))? as u64)
    }
    /// Planning inputs share one MVCC observation; no execution result bytes are projected.
    pub async fn planning_snapshot(&self, p: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let project: Value = sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
            .bind(p)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "project missing"))?;
        let revision: i64 =
            sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                .bind(p)
                .fetch_one(&mut *tx)
                .await?;
        let tasks: Vec<Value> = sqlx::query_scalar("SELECT data FROM tasks WHERE project_id=$1 AND state<>'REMOVED_FROM_PLAN' ORDER BY task_id")
            .bind(p).fetch_all(&mut *tx).await?;
        let teams: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let documents: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('collection',collection,'value',data) FROM documents WHERE project_id=$1 AND collection IN ('owners','task_estimates','schedules','queue_entries','planning_catalogs') ORDER BY collection,document_id")
            .bind(p).fetch_all(&mut *tx).await?;
        let policies: Vec<Value> = sqlx::query_scalar("SELECT data FROM resource_scopes WHERE project_id=$1 OR project_id IS NULL ORDER BY scope_id")
            .bind(p).fetch_all(&mut *tx).await?;
        let limits: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(l) FROM resource_limits l JOIN resource_scopes s USING(scope_id) WHERE s.project_id=$1 OR s.project_id IS NULL ORDER BY scope_id,dimension")
            .bind(p).fetch_all(&mut *tx).await?;
        let completed: Vec<String> = sqlx::query_scalar("SELECT t.task_id FROM tasks t WHERE t.project_id=$1 AND (EXISTS (SELECT 1 FROM attempts a WHERE a.project_id=t.project_id AND a.task_id=t.task_id AND a.task_revision=t.task_revision AND a.state='SUCCEEDED') OR EXISTS(SELECT 1 FROM documents d JOIN attempts r ON r.project_id=d.project_id AND r.attempt_id=d.data->'review'->>'attempt_id' AND r.state='SUCCEEDED' JOIN merge_intents m ON m.project_id=d.project_id AND m.intent_id=d.data->'integration'->>'intent_id' AND m.state='FINALIZED' WHERE d.project_id=t.project_id AND d.collection='operations' AND d.document_id LIKE 'retained-candidate-acceptance:%' AND d.data->'source'->>'task_id'=t.task_id AND (d.data->'source'->>'task_revision')::bigint=t.task_revision AND d.data->'source'->>'input_digest'=t.input_digest)) ORDER BY t.task_id")
            .bind(p).fetch_all(&mut *tx).await?;
        let active_task_ids: Vec<String> = sqlx::query_scalar("SELECT DISTINCT task_id FROM attempts WHERE project_id=$1 AND terminal_at IS NULL ORDER BY task_id")
            .bind(p).fetch_all(&mut *tx).await?;
        let as_of = db_now(&mut tx).await?;
        tx.commit().await?;
        let mut planning_tasks = tasks.clone();
        for task in &mut planning_tasks {
            if let Some(object) = task.as_object_mut() {
                object.remove("fence_epoch");
                object.remove("revision");
            }
        }
        let planning_documents:Vec<Value>=documents.iter().map(|document|{
            if document["collection"]=="queue_entries"{
                serde_json::json!({"collection":"queue_entries","task_id":document["value"]["task_id"],"priority":document["value"]["priority"]})
            }else{document.clone()}
        }).collect();
        let digest_material = serde_json::json!({"algorithm":"forgeflow.planning.inputs.v1","tasks":planning_tasks,
            "teams":teams,"documents":planning_documents,"resource_policies":policies,"completed_task_ids":completed});
        let planning_input_digest =
            forgeflow_planner::sha256(&serde_json::to_vec(&digest_material)?);
        Ok(
            serde_json::json!({"project":project,"tasks":tasks,"teams":teams,"documents":documents,
            "resource_policies":policies,"resource_limits":limits,"completed_task_ids":completed,
            "active_task_ids":active_task_ids,
            "revision":revision,"planning_input_digest":planning_input_digest,"as_of":as_of,"source":"POSTGRESQL_REPEATABLE_READ"}),
        )
    }
    pub async fn snapshot(&self, p: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let project: Option<Value> =
            sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
                .bind(p)
                .fetch_optional(&mut *tx)
                .await?;
        let project = project.ok_or_else(|| err("NOT_FOUND", "project not found"))?;
        let revision: i64 =
            sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                .bind(p)
                .fetch_one(&mut *tx)
                .await?;
        let tasks: Vec<Value> =
            sqlx::query_scalar("SELECT data FROM tasks WHERE project_id=$1 ORDER BY task_id")
                .bind(p)
                .fetch_all(&mut *tx)
                .await?;
        let attempts: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM attempts WHERE project_id=$1 ORDER BY created_at,attempt_id",
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let leases: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(l)-'token_digest' FROM leases l WHERE project_id=$1 ORDER BY lease_id",
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let allocations:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(a) FROM resource_allocations a WHERE project_id=$1 ORDER BY allocation_id").bind(p).fetch_all(&mut *tx).await?;
        // Project only lifecycle and accounting facts. Admission/RPC bodies,
        // model request grants and arbitrary settlement payloads remain private.
        let native_child_lifecycles: Vec<Value> = sqlx::query_scalar(
            r#"SELECT to_jsonb(l) FROM (
                SELECT allocation_id,project_id,task_id,attempt_id,generation,worker_id,
                       native_session_id,parent_session_id,parent_allocation_id,root_session_id,
                       delegation_depth,lifecycle_number,source,borrowed_parent_reservation,
                       provider,model,max_output_tokens,state,revoked,disposed_at,process_stopped_at,
                       acquired_at,released_at,release_reason
                FROM native_child_lifecycles WHERE project_id=$1
                ORDER BY acquired_at,allocation_id
            ) l"#,
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let native_child_allocations: Vec<Value> = sqlx::query_scalar(
            r#"SELECT to_jsonb(a) FROM (
                SELECT resource_allocation_id,allocation_id,project_id,attempt_id,scope_id,
                       dimension,amount,state,acquired_at,released_at,release_reason
                FROM native_child_allocations WHERE project_id=$1
                ORDER BY acquired_at,resource_allocation_id
            ) a"#,
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let native_model_requests: Vec<Value> = sqlx::query_scalar(
            r#"SELECT to_jsonb(m) FROM (
                SELECT request_id,project_id,attempt_id,generation,worker_id,allocation_id,
                       native_session_id,provider,model,max_output_tokens,purpose,status,
                       usage_complete,cost_status,admitted_at,settled_at,dispatched_at,
                       CASE WHEN dispatch_transport_settlement IS NULL THEN NULL ELSE
                           jsonb_build_object('outcome',dispatch_transport_settlement->'outcome',
                               'upstream_status',dispatch_transport_settlement->'upstream_status',
                               'received_bytes',dispatch_transport_settlement->'received_bytes',
                               'usage_complete',dispatch_transport_settlement->'usage_complete')
                       END AS transport,
                       CASE WHEN usage IS NULL THEN NULL ELSE (
                           SELECT COALESCE(jsonb_object_agg(key,value),'{}'::jsonb)
                           FROM jsonb_each(CASE WHEN jsonb_typeof(usage)='object'
                                               THEN usage ELSE '{}'::jsonb END)
                           WHERE key IN ('inputTokens','outputTokens','cacheReadTokens',
                                         'cacheWriteTokens','reasoningTokens','totalTokens')
                             AND jsonb_typeof(value)='number'
                       ) END AS usage
                FROM native_model_requests WHERE project_id=$1
                ORDER BY admitted_at,request_id
            ) m"#,
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        // Snapshot consumers need only public mode/accounting facts. Project
        // those keys in PostgreSQL instead of transferring and decoding every
        // frozen command, executor configuration and verification plan.
        let frozen_profiles: Vec<Value> = sqlx::query_scalar(r#"
            WITH profile_projection AS MATERIALIZED (
                SELECT p.project_id,p.sha256,jsonb_build_object(
                    'kind', p.data->'kind',
                    'native_mode', jsonb_build_object(
                        'mode_id', p.data#>'{native_mode,mode_id}',
                        'preset_patch', jsonb_build_object('sha256', p.data#>'{native_mode,preset_patch,sha256}'),
                        'enabled_capabilities', p.data#>'{native_mode,enabled_capabilities}')) AS profile
                FROM frozen_executor_profiles p WHERE p.project_id=$1
                  AND EXISTS (SELECT 1 FROM attempts a WHERE a.project_id=p.project_id
                              AND a.executor_profile_sha256=p.sha256)
            ), selected_profiles AS (
                SELECT a.attempt_id,a.created_at,a.execution_bindings,a.envelope,
                       CASE WHEN a.executor_profile_sha256 IS NULL
                            THEN a.execution_bindings->'executor_profile'
                            ELSE p.profile END AS frozen_executor_profile
                FROM attempts a LEFT JOIN profile_projection p
                  ON p.project_id=a.project_id AND p.sha256=a.executor_profile_sha256
                WHERE a.project_id=$1
            )
            SELECT jsonb_build_object(
                'attempt_id', attempt_id,
                'native_root_binding', CASE
                    WHEN jsonb_typeof(execution_bindings->'native_root_binding') = 'object'
                    THEN jsonb_build_object(
                        'schema_version', execution_bindings#>'{native_root_binding,schema_version}',
                        'project_id', execution_bindings#>'{native_root_binding,project_id}',
                        'task_id', execution_bindings#>'{native_root_binding,task_id}',
                        'task_revision', execution_bindings#>'{native_root_binding,task_revision}',
                        'input_digest', execution_bindings#>'{native_root_binding,input_digest}',
                        'owner_id', execution_bindings#>'{native_root_binding,owner_id}',
                        'team_id', execution_bindings#>'{native_root_binding,team_id}',
                        'position_id', execution_bindings#>'{native_root_binding,position_id}',
                        'preset_id', execution_bindings#>'{native_root_binding,preset_id}',
                        'catalog_sha256', execution_bindings#>'{native_root_binding,catalog_sha256}',
                        'planning_card_id', execution_bindings#>'{native_root_binding,planning_card_id}')
                    ELSE NULL END,
                'envelope', jsonb_build_object(
                    'executor_profile_id', envelope->'executor_profile_id',
                    'resource_profile_id', envelope->'resource_profile_id',
                    'model_route_id', envelope->'model_route_id'),
                'bindings', jsonb_build_object(
                    'executor_profile', jsonb_build_object(
                        'kind', frozen_executor_profile->'kind',
                        'native_mode', jsonb_build_object(
                            'mode_id', frozen_executor_profile#>'{native_mode,mode_id}',
                            'preset_patch', jsonb_build_object('sha256', frozen_executor_profile#>'{native_mode,preset_patch,sha256}'),
                            'enabled_capabilities', frozen_executor_profile#>'{native_mode,enabled_capabilities}')),
                    'resource_profile', jsonb_build_object(
                        'native_child_policy', CASE
                            WHEN jsonb_typeof(execution_bindings#>'{resource_profile,native_child_policy}') = 'object'
                            THEN jsonb_build_object(
                                'enabled', execution_bindings#>'{resource_profile,native_child_policy,enabled}',
                                'max_live_agents', execution_bindings#>'{resource_profile,native_child_policy,max_live_agents}',
                                'max_lifecycles', execution_bindings#>'{resource_profile,native_child_policy,max_lifecycles}',
                                'max_delegation_depth', execution_bindings#>'{resource_profile,native_child_policy,max_delegation_depth}',
                                'model_inflight_limit', execution_bindings#>'{resource_profile,native_child_policy,model_inflight_limit}',
                                'child_resources', jsonb_build_object(
                                    'active_slot', execution_bindings#>'{resource_profile,native_child_policy,child_resources,active_slot}',
                                    'coding_slot', execution_bindings#>'{resource_profile,native_child_policy,child_resources,coding_slot}',
                                    'cpu_units', execution_bindings#>'{resource_profile,native_child_policy,child_resources,cpu_units}',
                                    'memory_bytes', execution_bindings#>'{resource_profile,native_child_policy,child_resources,memory_bytes}',
                                    'build_permit', execution_bindings#>'{resource_profile,native_child_policy,child_resources,build_permit}',
                                    'gpu_permit', execution_bindings#>'{resource_profile,native_child_policy,child_resources,gpu_permit}',
                                    'provider_inflight', execution_bindings#>'{resource_profile,native_child_policy,child_resources,provider_inflight}'))
                            ELSE execution_bindings#>'{resource_profile,native_child_policy}' END)))
            FROM selected_profiles ORDER BY created_at,attempt_id
        "#).bind(p).fetch_all(&mut *tx).await?;
        let attempt_native_profiles: Vec<Value> = frozen_profiles.iter().map(|row| {
            let envelope = &row["envelope"];
            let executor = &row["bindings"]["executor_profile"];
            let native_mode = &executor["native_mode"];
            let policy = &row["bindings"]["resource_profile"]["native_child_policy"];
            let projected_policy = if policy.is_object() {
                let mut fields = serde_json::Map::new();
                for key in ["enabled", "max_live_agents", "max_lifecycles", "max_delegation_depth", "model_inflight_limit"] {
                    fields.insert(key.into(), policy[key].clone());
                }
                let mut resources = serde_json::Map::new();
                for dimension in ["active_slot", "coding_slot", "cpu_units", "memory_bytes", "build_permit", "gpu_permit", "provider_inflight"] {
                    resources.insert(dimension.into(), policy["child_resources"][dimension].clone());
                }
                fields.insert("child_resources".into(), Value::Object(resources));
                Value::Object(fields)
            } else { Value::Null };
            let capabilities = native_mode.get("enabled_capabilities").and_then(Value::as_array)
                .map(|items| Value::Array(items.iter().filter(|v| v.as_str().is_some_and(|s| s.len() <= 128)).cloned().collect()))
                .unwrap_or(Value::Null);
            serde_json::json!({"attempt_id":row["attempt_id"],
                "executor_profile_id":envelope["executor_profile_id"], "resource_profile_id":envelope["resource_profile_id"],
                "model_route_id":envelope["model_route_id"], "executor_kind":executor["kind"],
                "mode_id":native_mode["mode_id"], "preset_sha256":native_mode["preset_patch"]["sha256"],
                "capabilities":capabilities, "native_child_policy":projected_policy,
                "native_root_binding":row["native_root_binding"]})
        }).collect();
        let scopes:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(l) FROM resource_limits l JOIN resource_scopes s USING(scope_id) WHERE s.project_id=$1 OR s.project_id IS NULL ORDER BY l.scope_id,l.dimension").bind(p).fetch_all(&mut *tx).await?;
        let teams: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let requirements: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id",
        )
        .bind(p)
        .fetch_all(&mut *tx)
        .await?;
        let as_of = db_now(&mut tx).await?;
        tx.commit().await?;
        Ok(
            serde_json::json!({"project":project,"teams":teams,"requirements":requirements,"tasks":tasks,"attempts":attempts,"leases":leases,"allocations":allocations,"native_child_lifecycles":native_child_lifecycles,"native_child_allocations":native_child_allocations,"native_model_requests":native_model_requests,"attempt_native_profiles":attempt_native_profiles,"resource_limits":scopes,"revision":revision,"as_of":as_of,"source":"POSTGRESQL_AUTHORITY"}),
        )
    }
    pub async fn restore_reconcile(&self) -> Result<()> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM attempts WHERE terminal_at IS NULL")
                .fetch_one(&mut *tx)
                .await?;
        if active != 0 {
            return Err(err(
                "RECOVERY_REQUIRED",
                "restore has open attempts: preserve allocations and reconcile before resuming",
            ));
        }
        sqlx::query("UPDATE workers SET heartbeat_at='epoch'::timestamptz")
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE leases SET revoked_at=COALESCE(revoked_at,clock_timestamp())")
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE gateway_scope_budget SET revoked=true")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
impl Store {
    pub async fn attempt_task(&self, a: &Attempt) -> Result<TaskCard> {
        let v:Value=sqlx::query_scalar("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3").bind(&a.project_id).bind(&a.task_id).bind(i64v(a.task_revision)?).fetch_one(&self.pool).await?;
        decode(v)
    }
}
impl Store {
    /// Bounded stable-key reads; collection names select fixed SQL only.
    pub async fn paginated_catalog(
        &self,
        project: Option<&str>,
        collection: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Page<Value>> {
        let limit = limit.clamp(1, 500);
        if collection != "projects" && project.is_none() {
            return Err(err("AUTHORITY_SCOPE_VIOLATION", "project scope required"));
        }
        let (table, key) = match collection {
            "projects" => ("projects", "project_id"),
            "tasks" => ("tasks", "task_id"),
            "attempts" => ("attempts", "attempt_id"),
            "requirements" => ("requirements", "requirement_id"),
            "teams" => ("owner_nodes", "owner_id"),
            "flows" | "flow_summaries" => ("flow_revisions", "flow_revision"),
            "evidence" => ("evidence_receipts", "receipt_id"),
            _ => {
                let collection = collection.strip_prefix("documents:").unwrap_or(collection);
                validate_collection(collection)?;
                let rows=sqlx::query("SELECT (CASE WHEN collection='sources' THEN data-'content'-'requirements' WHEN collection='planning_cards' THEN data || jsonb_build_object('metadata',(data->'metadata')-'source_card') ELSE data END)||jsonb_build_object('revision',revision) AS data,document_id AS cursor_key FROM documents WHERE project_id=$1 AND ($2::text IS NULL OR document_id>$2) AND collection=$4 ORDER BY document_id LIMIT $3").bind(project).bind(after).bind(i64::from(limit)+1).bind(collection).fetch_all(&self.pool).await?;
                return page_rows(rows, limit);
            }
        };
        if collection == "flows" || collection == "flow_summaries" {
            if let Some(cursor) = after {
                let revision = cursor
                    .parse::<u64>()
                    .map_err(|_| err("VALIDATION_ERROR", "flow cursor must be integer"))?;
                i64v(revision)?;
            }
            let projection = if collection == "flow_summaries" {
                "jsonb_build_object('project_id',project_id,'flow_revision',flow_revision,'revision',revision,'state',state,'input_digest',input_digest)"
            } else {
                "data"
            };
            let rows=sqlx::query(&format!("SELECT {projection} AS data,flow_revision::text AS cursor_key FROM flow_revisions WHERE project_id=$1 AND ($2::text IS NULL OR flow_revision>$2::text::bigint) ORDER BY flow_revision LIMIT $3")).bind(project).bind(after).bind(i64::from(limit)+1).fetch_all(&self.pool).await?;
            return page_rows(rows, limit);
        }
        let q = format!(
            "SELECT data,{key} AS cursor_key FROM {table} WHERE ($1::text IS NULL OR project_id=$1) AND ($2::text IS NULL OR {key}>$2) ORDER BY {key} LIMIT $3"
        );
        let rows = sqlx::query(&q)
            .bind(project)
            .bind(after)
            .bind(i64::from(limit) + 1)
            .fetch_all(&self.pool)
            .await?;
        page_rows(rows, limit)
    }
}
fn page_rows(mut rows: Vec<sqlx::postgres::PgRow>, limit: u32) -> Result<Page<Value>> {
    let more = rows.len() > limit as usize;
    if more {
        rows.pop();
    }
    let next_cursor = if more {
        rows.last().map(|r| r.get::<String, _>("cursor_key"))
    } else {
        None
    };
    let items = rows
        .into_iter()
        .map(|r| r.try_get("data").map_err(StoreError::from))
        .collect::<Result<Vec<_>>>()?;
    Ok(Page { items, next_cursor })
}

struct BlueprintTarget {
    project: Project,
    requirements: Vec<Requirement>,
    teams: Vec<Team>,
    owners: Vec<Value>,
    profiles: std::collections::BTreeMap<(String, String), Value>,
    authority: NativeBlueprintAuthority,
    digest: String,
    flow_revision: u64,
}

async fn blueprint_target(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    mapping: &NativeBlueprintMapping,
) -> Result<BlueprintTarget> {
    use std::collections::BTreeMap;
    let p: Project = decode(
        sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
            .bind(project)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "blueprint target project not found"))?,
    )?;
    let requirements: Vec<Requirement> = sqlx::query_scalar(
        "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id",
    )
    .bind(project)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(decode)
    .collect::<Result<_>>()?;
    let teams: Vec<Team> =
        sqlx::query_scalar("SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id")
            .bind(project)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .map(decode)
            .collect::<Result<_>>()?;
    let owners:Vec<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='owners' ORDER BY document_id").bind(project).fetch_all(&mut **tx).await?;
    let catalog:Option<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='planning_catalogs' AND document_id=$2").bind(project).bind(&mapping.target_catalog_id).fetch_optional(&mut **tx).await?;
    let mut profiles = BTreeMap::new();
    for (collection, ids) in [
        ("executor_profiles", &mapping.executor_profile_ids),
        ("resource_profiles", &mapping.resource_profile_ids),
        ("model_routes", &mapping.model_route_ids),
    ] {
        for id in ids.values().collect::<std::collections::BTreeSet<_>>() {
            let value:Option<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3")
                .bind(project).bind(collection).bind(id).fetch_optional(&mut **tx).await?;
            profiles.insert(
                (collection.into(), id.clone()),
                value.unwrap_or(Value::Null),
            );
        }
    }
    let authority = NativeBlueprintAuthority {
        project_revision: p.revision,
        requirement_revisions: requirements
            .iter()
            .map(|r| (r.requirement_id.clone(), r.revision))
            .collect(),
        team_revisions: teams
            .iter()
            .map(|t| (t.team_id.clone(), t.revision))
            .collect(),
        owner_revisions: owners
            .iter()
            .filter_map(|o| Some((o["owner_id"].as_str()?.into(), o["revision"].as_u64()?)))
            .collect(),
        catalog_revision: catalog.as_ref().and_then(|c| c["revision"].as_u64()),
    };
    let profile_hashes: BTreeMap<String, String> = profiles
        .iter()
        .map(|((collection, id), value)| {
            Ok((
                format!("{collection}/{id}"),
                forgeflow_planner::sha256(&serde_json::to_vec(value)?),
            ))
        })
        .collect::<Result<_>>()?;
    let digest = forgeflow_planner::sha256(&serde_json::to_vec(
        &serde_json::json!({"algorithm":"forgeflow.native-blueprint.target-authority.v1",
        "project":p,"requirements":requirements,"teams":teams,"owners":owners,"catalog":catalog,"profiles":profile_hashes}),
    )?);
    let flow: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(flow_revision),0)+1 FROM flow_revisions WHERE project_id=$1",
    )
    .bind(project)
    .fetch_one(&mut **tx)
    .await?;
    Ok(BlueprintTarget {
        project: p,
        requirements,
        teams,
        owners,
        profiles,
        authority,
        digest,
        flow_revision: flow as u64,
    })
}

fn blueprint_findings(findings: &mut Vec<Value>, code: &str, subject: &str, detail: &str) {
    findings.push(serde_json::json!({"code":code,"subject":subject,"detail":detail}));
}
fn blueprint_id_map(
    mapping: &std::collections::BTreeMap<String, String>,
    declared: std::collections::BTreeSet<String>,
    injective: bool,
    field: &str,
) -> Result<()> {
    if mapping
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != declared
        || mapping.values().any(|id| {
            id.is_empty()
                || id.len() > 512
                || id.chars().any(|c| c.is_control() || c.is_whitespace())
        })
        || (injective
            && mapping
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != mapping.len())
    {
        let missing = declared.iter().find(|id| !mapping.contains_key(*id));
        let invalid = mapping.iter().find(|(_, id)| {
            id.is_empty()
                || id.len() > 512
                || id.chars().any(|c| c.is_control() || c.is_whitespace())
        });
        let reason = if missing.is_some() {
            "LOGICAL_ID_UNMAPPED"
        } else if mapping.keys().any(|id| !declared.contains(id)) {
            "UNDECLARED_LOGICAL_ID"
        } else if invalid.is_some() {
            "TARGET_ID_EMPTY_OR_INVALID"
        } else {
            "TARGET_ID_COLLISION"
        };
        let subject = missing
            .map(String::as_str)
            .or_else(|| invalid.map(|(id, _)| id.as_str()))
            .unwrap_or("");
        let mut error = DomainError::new(
            "BLUEPRINT_MAPPING_INVALID",
            format!("{field}: {reason}; complete the explicit target mapping before preview"),
        );
        error.details = serde_json::json!({"field":field,"subject":subject.chars().take(256).collect::<String>(),"reason":reason});
        return Err(error.into());
    }
    Ok(())
}
fn blueprint_path(path: &str, rules: &[NativeBlueprintPathRule]) -> Result<String> {
    validate_relative_path(path)?;
    let rule = rules
        .iter()
        .filter(|rule| {
            rule.source_prefix.is_empty()
                || rule.source_prefix == path
                || (rule.source_prefix.ends_with('/') && path.starts_with(&rule.source_prefix))
        })
        .max_by_key(|rule| rule.source_prefix.len())
        .ok_or_else(|| {
            err(
                "BLUEPRINT_PATH_UNMAPPED",
                "every logical path requires an explicit matching path rule",
            )
        })?;
    let mapped = format!(
        "{}{}",
        rule.target_prefix,
        &path[rule.source_prefix.len()..]
    );
    validate_relative_path(&mapped)?;
    Ok(mapped)
}
fn blueprint_design_anchor(
    anchor: &str,
    rules: &[NativeBlueprintPathRule],
) -> Result<Option<String>> {
    if anchor.starts_with("forgeflow:") {
        return Ok(None);
    }
    if let Some((path, section)) = anchor.split_once('#') {
        if validate_relative_path(path).is_ok() {
            return Ok(Some(format!("{}#{section}", blueprint_path(path, rules)?)));
        }
    }
    Ok(Some(anchor.into()))
}
fn blueprint_provenance(value: Value) -> Value {
    blueprint_provenance_inner(value, false)
}

fn blueprint_profile_roles(profile: &Value) -> Result<Option<Value>> {
    use std::io::Read;
    let Some(mode) = profile["native_mode"]["mode_manifest"].as_str() else {
        return Ok(None);
    };
    let path = std::path::Path::new(mode)
        .parent()
        .ok_or_else(|| err("BLUEPRINT_PROFILE_INVALID", "native mode location missing"))?
        .join("agent-roles.json");
    let pins: Vec<_> = profile["artifact_pins"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|pin| {
            pin["path"]
                .as_str()
                .is_some_and(|value| std::path::Path::new(value) == path)
        })
        .collect();
    if pins.is_empty() {
        return Ok(None);
    }
    if pins.len() != 1 || !path.is_absolute() {
        return Err(err(
            "BLUEPRINT_PROFILE_INVALID",
            "target role catalog pin must be singular and absolute",
        ));
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|_| {
        err(
            "BLUEPRINT_PROFILE_INVALID",
            "target role catalog unavailable",
        )
    })?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1_048_576 {
        return Err(err(
            "BLUEPRINT_PROFILE_INVALID",
            "target role catalog must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(1_048_577).read_to_end(&mut bytes))
        .map_err(|_| {
            err(
                "BLUEPRINT_PROFILE_INVALID",
                "target role catalog could not be read",
            )
        })?;
    if bytes.len() > 1_048_576
        || pins[0]["sha256"].as_str() != Some(forgeflow_planner::sha256(&bytes).as_str())
    {
        return Err(err(
            "BLUEPRINT_PROFILE_INVALID",
            "target role catalog bytes differ from frozen profile pin",
        ));
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn blueprint_provenance_inner(mut value: Value, fixture: bool) -> Value {
    match &mut value {
        Value::Object(object) => {
            object.retain(|key, _| {
                if fixture
                    && matches!(
                        key.to_ascii_lowercase().as_str(),
                        "status" | "state" | "frozen" | "accepted"
                    )
                {
                    return true;
                }
                !matches!(
                    key.to_ascii_lowercase().as_str(),
                    "status"
                        | "state"
                        | "attempt_id"
                        | "lease_id"
                        | "worker_id"
                        | "native_session_id"
                        | "pid"
                        | "generation"
                        | "operation_id"
                        | "input_digest"
                        | "input_hashes"
                        | "artifact_pins"
                        | "verification_binding"
                        | "verification_receipts"
                        | "evidence"
                        | "evidence_refs"
                        | "candidate_sha"
                        | "integrated_sha"
                        | "base_sha"
                        | "frozen"
                        | "accepted"
                        | "qualified"
                        | "qualification"
                        | "api_key"
                        | "apikey"
                        | "password"
                        | "token"
                        | "secret"
                        | "secret_ref"
                        | "secret_refs"
                        | "workspace_root"
                        | "private_path"
                        | "runtime_path"
                )
            });
            for (key, child) in object.iter_mut() {
                let definition = fixture
                    || matches!(
                        key.to_ascii_lowercase().as_str(),
                        "positive_cases"
                            | "negative_cases"
                            | "test_cases"
                            | "cases"
                            | "input"
                            | "expected"
                            | "definition_of_ready"
                            | "definition_of_done"
                    );
                *child = blueprint_provenance_inner(std::mem::take(child), definition);
            }
        }
        Value::Array(array) => {
            for child in array {
                *child = blueprint_provenance_inner(std::mem::take(child), fixture);
            }
        }
        _ => {}
    }
    value
}

async fn blueprint_catalog(
    tx: &mut Transaction<'_, Postgres>,
    target: &BlueprintTarget,
    request: &NativeBlueprintPreviewRequest,
) -> Result<(PlanningCatalogRegistration, Vec<Value>, Vec<Value>)> {
    use std::collections::{BTreeMap, BTreeSet};
    let b = &request.blueprint;
    let m = &request.mapping;
    let mapping_hash = forgeflow_planner::sha256(&serde_json::to_vec(
        &serde_json::json!({"algorithm":"forgeflow.native-blueprint.mapping.v1","mapping":m}),
    )?);
    if b.schema_version != "forgeflow.native-project-blueprint.v2"
        || b.blueprint_id.is_empty()
        || b.title.is_empty()
        || b.execution_rights_granted
        || b.runtime_bindings_exported
        || b.cards.is_empty()
        || b.cards.len() > 10_000
        || b.roles.is_empty()
        || b.roles.len() > 10_000
        || m.target_catalog_id.is_empty()
        || m.path_rules.is_empty()
    {
        return Err(err(
            "BLUEPRINT_INVALID",
            "only a bounded v2 logical blueprint without inherited execution rights can be reviewed",
        ));
    }
    for (map, ids, unique, field) in [
        (
            &m.requirement_ids,
            b.requirements
                .iter()
                .map(|r| r.requirement_id.clone())
                .collect::<BTreeSet<_>>(),
            false,
            "mapping.requirement_ids",
        ),
        (
            &m.team_ids,
            b.teams.iter().map(|t| t.team_id.clone()).collect(),
            false,
            "mapping.team_ids",
        ),
        (
            &m.owner_ids,
            b.owner_territories
                .iter()
                .map(|o| o.owner_id.clone())
                .collect(),
            false,
            "mapping.owner_ids",
        ),
        (
            &m.task_ids,
            b.cards.iter().map(|c| c.task_id.clone()).collect(),
            true,
            "mapping.task_ids",
        ),
        (
            &m.role_ids,
            b.roles.iter().map(|r| r.role_id.clone()).collect(),
            true,
            "mapping.role_ids",
        ),
        (
            &m.preset_ids,
            b.roles.iter().map(|r| r.preset_id.clone()).collect(),
            false,
            "mapping.preset_ids",
        ),
        (
            &m.executor_profile_ids,
            b.cards
                .iter()
                .map(|c| c.execution_profile_ref.clone())
                .collect(),
            false,
            "mapping.executor_profile_ids",
        ),
        (
            &m.resource_profile_ids,
            b.cards
                .iter()
                .map(|c| c.resource_profile_ref.clone())
                .collect(),
            false,
            "mapping.resource_profile_ids",
        ),
        (
            &m.model_route_ids,
            b.cards.iter().map(|c| c.model_route_ref.clone()).collect(),
            false,
            "mapping.model_route_ids",
        ),
    ] {
        blueprint_id_map(map, ids, unique, field)?;
    }
    if b.cards
        .iter()
        .map(|c| &c.task_id)
        .collect::<BTreeSet<_>>()
        .len()
        != b.cards.len()
        || b.roles
            .iter()
            .map(|r| &r.role_id)
            .collect::<BTreeSet<_>>()
            .len()
            != b.roles.len()
        || b.requirements
            .iter()
            .map(|r| &r.requirement_id)
            .collect::<BTreeSet<_>>()
            .len()
            != b.requirements.len()
        || b.teams
            .iter()
            .map(|t| &t.team_id)
            .collect::<BTreeSet<_>>()
            .len()
            != b.teams.len()
        || b.owner_territories
            .iter()
            .map(|t| &t.owner_id)
            .collect::<BTreeSet<_>>()
            .len()
            != b.owner_territories.len()
    {
        return Err(err(
            "BLUEPRINT_INVALID",
            "logical declarations must be unique",
        ));
    }
    let mut rule_ids = BTreeSet::new();
    for rule in &m.path_rules {
        if !rule.source_prefix.is_empty() {
            validate_relative_path(&rule.source_prefix)?;
        }
        if !rule.target_prefix.is_empty() {
            validate_relative_path(&rule.target_prefix)?;
        }
        if !rule_ids.insert(&rule.source_prefix) {
            return Err(err(
                "BLUEPRINT_MAPPING_INVALID",
                "path prefixes must be unique",
            ));
        }
    }
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let teams: BTreeMap<_, _> = target
        .teams
        .iter()
        .map(|t| (t.team_id.clone(), t))
        .collect();
    let owners: BTreeMap<_, _> = target
        .owners
        .iter()
        .filter_map(|o| Some((o["owner_id"].as_str()?.to_owned(), o)))
        .collect();
    for id in m.requirement_ids.values() {
        if !target.requirements.iter().any(|r| &r.requirement_id == id) {
            blueprint_findings(
                &mut findings,
                "REQUIREMENT_NOT_FOUND",
                id,
                "mapped requirement must already exist in target authority",
            );
        }
    }
    for id in m.team_ids.values() {
        if !teams.contains_key(id) {
            blueprint_findings(
                &mut findings,
                "TEAM_NOT_FOUND",
                id,
                "mapped team must already be registered",
            );
        }
    }
    for id in m.owner_ids.values() {
        if !owners.contains_key(id) || !teams.contains_key(id) {
            blueprint_findings(
                &mut findings,
                "OWNER_NOT_REGISTERED",
                id,
                "target CodeOwner requires both territory and OwnerNode registration",
            );
        }
    }
    for team in &b.teams {
        if let Some(actual) = teams.get(&m.team_ids[&team.team_id]) {
            let parent = team
                .parent_team_id
                .as_ref()
                .map(|p| {
                    m.team_ids.get(p).cloned().ok_or_else(|| {
                        err("BLUEPRINT_REFERENCE_INVALID", "logical parent team missing")
                    })
                })
                .transpose()?;
            if actual.parent_team_id != parent {
                blueprint_findings(
                    &mut findings,
                    "TEAM_ANCESTRY_MISMATCH",
                    &actual.team_id,
                    "target parent differs from the explicitly mapped logical hierarchy",
                );
            }
        }
    }
    for owner in &b.owner_territories {
        if m.team_ids
            .get(&owner.owner_id)
            .is_some_and(|node| node != &m.owner_ids[&owner.owner_id])
        {
            blueprint_findings(
                &mut findings,
                "OWNER_NODE_MAPPING_MISMATCH",
                &owner.owner_id,
                "one logical OwnerNode cannot map to two different target identities",
            );
        }
        for path in owner.include.iter().chain(&owner.exclude) {
            blueprint_path(path, &m.path_rules)?;
        }
        if let Some(actual) = owners.get(&m.owner_ids[&owner.owner_id]) {
            let expected_root = owner
                .root_team_id
                .as_ref()
                .map(|root| {
                    m.team_ids.get(root).cloned().ok_or_else(|| {
                        err(
                            "BLUEPRINT_REFERENCE_INVALID",
                            "logical territory root team missing",
                        )
                    })
                })
                .transpose()?;
            if actual["root_team_id"].as_str() != expected_root.as_deref()
                || expected_root.is_none()
            {
                blueprint_findings(
                    &mut findings,
                    "OWNER_ROOT_UNBOUND",
                    &m.owner_ids[&owner.owner_id],
                    "target territory root must match the explicitly mapped registered root team",
                );
            }
        }
    }
    for ((collection, id), profile) in &target.profiles {
        if profile.is_null() {
            blueprint_findings(
                &mut findings,
                "PROFILE_NOT_REGISTERED",
                id,
                "target execution/resource/model profile must already be registered",
            );
        }
        if collection == "executor_profiles"
            && !profile.is_null()
            && profile["kind"] != "DSH_MANAGED"
        {
            blueprint_findings(
                &mut findings,
                "NATIVE_EXECUTOR_REQUIRED",
                id,
                "native blueprint execution recipes require a registered managed DSH profile",
            );
        }
    }
    let mut target_role_catalogs = BTreeMap::new();
    for ((collection, id), profile) in &target.profiles {
        if collection == "executor_profiles" && !profile.is_null() {
            match blueprint_profile_roles(profile) {
                Ok(Some(catalog)) => {
                    target_role_catalogs.insert(id.clone(), catalog);
                }
                Ok(None) => blueprint_findings(
                    &mut warnings,
                    "NATIVE_ROLE_CATALOG_UNBOUND",
                    id,
                    "target specialized presets remain unbound; planning import grants no Native execution readiness",
                ),
                Err(StoreError::Domain(domain)) => {
                    blueprint_findings(&mut findings, &domain.code, id, &domain.message)
                }
                Err(error) => return Err(error),
            }
        }
    }
    let tasks: BTreeSet<_> = b.cards.iter().map(|c| c.task_id.as_str()).collect();
    let roles: BTreeMap<_, _> = b.roles.iter().map(|r| (r.role_id.as_str(), r)).collect();
    let mut roster = Vec::new();
    for role in &b.roles {
        let owner = m
            .owner_ids
            .get(&role.owner_id)
            .ok_or_else(|| err("BLUEPRINT_REFERENCE_INVALID", "logical role Owner missing"))?;
        let team = m
            .team_ids
            .get(&role.team_id)
            .ok_or_else(|| err("BLUEPRINT_REFERENCE_INVALID", "logical role team missing"))?;
        let parent = role
            .parent_role_id
            .as_ref()
            .map(|r| {
                m.role_ids.get(r).cloned().ok_or_else(|| {
                    err("BLUEPRINT_REFERENCE_INVALID", "logical role parent missing")
                })
            })
            .transpose()?;
        roster.push(serde_json::json!({"agent_id":m.role_ids[&role.role_id],"owner_id":owner,"team_id":team,
            "parent_agent_id":parent,"preset_id":m.preset_ids[&role.preset_id],"state":"PLANNED","runtime_pid":null,"lease_id":null}));
    }
    let source_revision = forgeflow_planner::sha256(&serde_json::to_vec(&target.requirements)?);
    let target_ids: Vec<String> = m.task_ids.values().cloned().collect();
    let runtime_ids: BTreeSet<String> =
        sqlx::query_scalar("SELECT task_id FROM tasks WHERE project_id=$1 AND task_id=ANY($2)")
            .bind(&target.project.project_id)
            .bind(&target_ids)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    let existing_cards:BTreeMap<String,Value>=sqlx::query_scalar::<_,Value>("SELECT data FROM documents WHERE project_id=$1 AND collection='planning_cards' AND document_id=ANY($2)")
        .bind(&target.project.project_id).bind(&target_ids).fetch_all(&mut **tx).await?.into_iter()
        .filter_map(|value|Some((value["task_id"].as_str()?.to_owned(),value))).collect();
    let mut cards = Vec::new();
    let mut paths = BTreeMap::new();
    for card in &b.cards {
        let task_id = &m.task_ids[&card.task_id];
        let owner = m
            .owner_ids
            .get(&card.owner_id)
            .ok_or_else(|| err("BLUEPRINT_REFERENCE_INVALID", "logical task Owner missing"))?;
        let team = m
            .team_ids
            .get(&card.team_id)
            .ok_or_else(|| err("BLUEPRINT_REFERENCE_INVALID", "logical task team missing"))?;
        let role = roles
            .get(card.role_id.as_str())
            .ok_or_else(|| err("BLUEPRINT_REFERENCE_INVALID", "logical card role missing"))?;
        if role.owner_id != card.owner_id || role.team_id != card.team_id {
            return Err(err(
                "BLUEPRINT_REFERENCE_INVALID",
                "logical card role and Owner/team differ",
            ));
        }
        let mapped_paths = |items: &Vec<String>| -> Result<Vec<String>> {
            items
                .iter()
                .map(|p| blueprint_path(p, &m.path_rules))
                .collect()
        };
        let reads = mapped_paths(&card.read_set)?;
        let writes = mapped_paths(&card.write_set)?;
        let mandatory = mapped_paths(&card.spec.mandatory_paths)?;
        for path in card
            .read_set
            .iter()
            .chain(&card.write_set)
            .chain(&card.spec.mandatory_paths)
            .chain(card.spec.input_refs.iter().map(|i| &i.path))
        {
            let mapped = blueprint_path(path, &m.path_rules)?;
            if paths.get(&mapped).is_some_and(|old| old != path) {
                blueprint_findings(
                    &mut findings,
                    "PATH_MAPPING_COLLISION",
                    &mapped,
                    "different logical paths collapse onto one target path",
                );
            } else {
                paths.insert(mapped, path.clone());
            }
        }
        let dependencies: Vec<String> =
            card.dependencies
                .iter()
                .map(|d| {
                    m.task_ids.get(d).cloned().ok_or_else(|| {
                        err("BLUEPRINT_REFERENCE_INVALID", "logical dependency missing")
                    })
                })
                .collect::<Result<_>>()?;
        let declared: BTreeSet<_> = card
            .spec
            .dependency_refs
            .iter()
            .map(|d| d.task_id.as_str())
            .collect();
        if declared != card.dependencies.iter().map(String::as_str).collect()
            || declared.len() != card.spec.dependency_refs.len()
        {
            return Err(err(
                "BLUEPRINT_REFERENCE_INVALID",
                "logical DAG and dependency meanings differ",
            ));
        }
        for input in &card.spec.input_refs {
            if input
                .producer_task_id
                .as_ref()
                .is_some_and(|id| !tasks.contains(id.as_str()))
            {
                return Err(err(
                    "BLUEPRINT_REFERENCE_INVALID",
                    "logical producer task missing",
                ));
            }
        }
        let profile = &target.profiles[&(
            "executor_profiles".into(),
            m.executor_profile_ids[&card.execution_profile_ref].clone(),
        )];
        let executor_id = &m.executor_profile_ids[&card.execution_profile_ref];
        if let Some(catalog) = target_role_catalogs.get(executor_id) {
            let position = &m.role_ids[&card.role_id];
            let preset = &m.preset_ids[&role.preset_id];
            if catalog["project_id"].as_str() != Some(&target.project.project_id)
                || !catalog["roster"].as_array().is_some_and(|rows| {
                    rows.iter().any(|r| {
                        r["position_id"].as_str() == Some(position)
                            && r["preset_id"].as_str() == Some(preset)
                            && r["owner_id"].as_str() == Some(owner)
                            && r["owner_team_id"].as_str() == Some(team)
                    })
                })
            {
                blueprint_findings(
                    &mut findings,
                    "TARGET_PRESET_ROLE_MISMATCH",
                    task_id,
                    "mapped role/preset/Owner/team does not exist in the target profile's immutable project catalog",
                );
            }
        }
        let model_id = &m.model_route_ids[&card.model_route_ref];
        if !profile.is_null() && profile["model_route_id"].as_str() != Some(model_id) {
            blueprint_findings(
                &mut findings,
                "MODEL_ROUTE_MISMATCH",
                task_id,
                "target model route differs from the registered executor",
            );
        }
        if runtime_ids.contains(task_id) {
            blueprint_findings(
                &mut findings,
                "TASK_RUNTIME_ID_COLLISION",
                task_id,
                "planning import must not reuse an existing execution task identity",
            );
        }
        let previous = existing_cards.get(task_id);
        let task_revision = previous
            .and_then(|p| p["task"]["task_revision"].as_u64())
            .unwrap_or(0)
            + 1;
        if previous.is_some_and(|p| p["catalog_id"].as_str() != Some(&m.target_catalog_id)) {
            blueprint_findings(
                &mut findings,
                "TASK_CATALOG_ID_COLLISION",
                task_id,
                "task identity belongs to another planning catalog",
            );
        }
        let mut anchors: Vec<String> = card
            .spec
            .design_anchors
            .iter()
            .filter_map(|a| blueprint_design_anchor(a, &m.path_rules).transpose())
            .collect::<Result<_>>()?;
        let logical_hash = forgeflow_planner::sha256(&serde_json::to_vec(
            &serde_json::json!({"algorithm":"forgeflow.native-blueprint.logical-card.v3","card":card,"mapping_sha256":mapping_hash}),
        )?);
        anchors.push(format!("blueprint:logical-card:v3:{logical_hash}"));
        let mut unknowns = card.spec.known_unknowns.clone();
        unknowns.extend([
            "BLUEPRINT_INPUTS_UNBOUND".into(),
            "BLUEPRINT_VERIFICATION_UNBOUND".into(),
            "BLUEPRINT_EXECUTION_ENVELOPE_UNBOUND".into(),
        ]);
        if !card.spec.contract_produces.is_empty() || !card.spec.contract_consumes.is_empty() {
            unknowns.push("BLUEPRINT_CONTRACTS_UNBOUND".into());
        }
        let dependency_refs:Vec<Value>=card.spec.dependency_refs.iter().map(|d|serde_json::json!({"project_id":target.project.project_id,
            "task_id":m.task_ids[&d.task_id],"kind":d.kind,"binding_id":format!("PLANNING_ONLY:{}",m.task_ids[&d.task_id])})).collect();
        let source_card = blueprint_provenance(card.source_card.clone());
        let source_hash = forgeflow_planner::sha256(&serde_json::to_vec(&source_card)?);
        let metadata = serde_json::json!({"role_id":m.role_ids[&card.role_id],"parent_task":card.parent_task,"phase":card.phase,
            "source_card":source_card,"source_card_sha256":source_hash,"source_original_card_sha256":card.source_original_card_sha256,
            "source_blueprint_card_sha256":card.source_card_sha256,"blueprint_id":b.blueprint_id,"provenance_only":true,
            "admission_blockers":unknowns,"logical_input_refs":card.spec.input_refs,
            "logical_contract_produces":card.spec.contract_produces,"logical_contract_consumes":card.spec.contract_consumes,
            "execution_targets":{"preset_id":m.preset_ids[&role.preset_id],"resource_profile_id":m.resource_profile_ids[&card.resource_profile_ref],"model_route_id":model_id},
            "runtime_qualifications_inherited":false});
        let spec = serde_json::json!({"outcome":card.spec.outcome,"design_anchors":anchors,"inputs":[],"producer_inputs":[],"mandatory_paths":mandatory,
            "dependency_refs":dependency_refs,"contract_produces":[],"contract_consumes":[],"execution_profile":m.executor_profile_ids[&card.execution_profile_ref],
            "verification_plan":"","verification_case_count":0,"rollback_plan":card.spec.rollback_plan,"known_unknowns":unknowns,
            "not_proven":["Blueprint registration is planning only; no source input, contract freeze, runtime qualification or product acceptance transfers"],"isolated_contract_probe":false});
        let task = TaskCard {
            project_id: target.project.project_id.clone(),
            task_id: task_id.clone(),
            task_revision,
            flow_revision: target.flow_revision,
            title: card.title.clone(),
            owner_id: owner.clone(),
            team_id: team.clone(),
            requirement_ids: card
                .requirement_ids
                .iter()
                .map(|id| {
                    m.requirement_ids.get(id).cloned().ok_or_else(|| {
                        err("BLUEPRINT_REFERENCE_INVALID", "logical requirement missing")
                    })
                })
                .collect::<Result<_>>()?,
            read_set: reads,
            write_set: writes,
            dependencies,
            state: TaskPlanningState::NeedsReview,
            input_digest: String::new(),
            resource_request: card.resource_request.clone(),
            envelope: None,
            revision: 1,
        };
        cards.push(PlanningCardRegistration {
            task,
            spec,
            metadata,
        });
    }
    warnings.push(serde_json::json!({"code":"PLANNING_ONLY","detail":"Target inputs, contracts, verification and Native execution permission remain unbound; no source qualification is inherited"}));
    let parents = b
        .parents
        .iter()
        .cloned()
        .map(blueprint_provenance)
        .collect();
    let catalog = PlanningCatalogRegistration {
        schema_version: "forgeflow.planning.catalog.v1".into(),
        catalog_id: m.target_catalog_id.clone(),
        source_revision,
        expected_card_count: cards.len() as u64,
        expected_role_count: roster.len() as u64,
        expected_edge_count: Some(cards.iter().map(|c| c.task.dependencies.len() as u64).sum()),
        cards,
        parents,
        roster,
        metadata: serde_json::json!({"development_entrypoint":"DSH_NATIVE_OPERATION_PANEL","source_blueprint":b.source,
            "source_metadata":blueprint_provenance(b.metadata.clone()),"execution_rights_granted":false,"runtime_qualifications_inherited":false}),
    };
    if findings.is_empty() {
        match register_planning_catalog(
            tx,
            &target.project.project_id,
            target.authority.catalog_revision,
            catalog.clone(),
            false,
        )
        .await
        {
            Ok(_) => {}
            Err(StoreError::Domain(domain)) => blueprint_findings(
                &mut findings,
                &domain.code,
                &m.target_catalog_id,
                &domain.message,
            ),
            Err(error) => return Err(error),
        }
    }
    Ok((catalog, findings, warnings))
}

async fn preview_native_blueprint(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    requested_by: &str,
    request: NativeBlueprintPreviewRequest,
) -> Result<Value> {
    project_lock(tx, project).await?;
    let target = blueprint_target(tx, project, &request.mapping).await?;
    if json(&target.authority)? != json(&request.expected_authority)? {
        return Err(err(
            "BLUEPRINT_TARGET_STALE",
            "reload full target authority revisions before previewing",
        ));
    }
    let (catalog, findings, warnings) = blueprint_catalog(tx, &target, &request).await?;
    let blueprint_hash = forgeflow_planner::sha256(&serde_json::to_vec(&request.blueprint)?);
    let review_hash = forgeflow_planner::sha256(&serde_json::to_vec(
        &serde_json::json!({"algorithm":"forgeflow.native-blueprint.review.v2","materialization_algorithm":"forgeflow.native-blueprint.materialization.v2",
        "target_project_id":project,"request":request,"catalog":catalog,"target_authority_sha256":target.digest,"blocking_findings":findings}),
    )?);
    let preview = id();
    let can_import = findings.is_empty();
    let counts = serde_json::json!({"cards":catalog.cards.len(),"roles":catalog.roster.len(),"edges":catalog.expected_edge_count,"parents":catalog.parents.len()});
    let value = serde_json::json!({"schema_version":"forgeflow.native-blueprint-review.v1","preview_id":preview,"project_id":project,
        "entry_source":"DSH_NATIVE_PANEL","requested_by":requested_by,"revision":1,"state":"REVIEW_REQUIRED","review_sha256":review_hash,
        "review_digest_algorithm":"forgeflow.native-blueprint.review.v2","materialization_algorithm":"forgeflow.native-blueprint.materialization.v2",
        "blueprint_sha256":blueprint_hash,"target_authority_sha256":target.digest,"counts":counts,"blocking_findings":findings,"warnings":warnings,
        "can_import":can_import,"execution_rights_granted":false,"request":request,"catalog":catalog,"created_at":db_now(tx).await?.to_rfc3339()});
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'native_blueprint_reviews',$2,1,$3)").bind(project).bind(&preview).bind(&value).execute(&mut **tx).await?;
    event(tx,project,&preview,1,"native.blueprint_previewed",serde_json::json!({"preview_id":preview,"review_sha256":review_hash,"counts":counts,"can_import":can_import,"execution_rights_granted":false})).await?;
    Ok(
        serde_json::json!({"preview_id":preview,"revision":1,"review_sha256":review_hash,"blueprint_sha256":blueprint_hash,
        "review_digest_algorithm":"forgeflow.native-blueprint.review.v2","materialization_algorithm":"forgeflow.native-blueprint.materialization.v2",
        "target_authority_sha256":target.digest,"counts":counts,"blocking_findings":findings,"warnings":warnings,"can_import":can_import,"execution_rights_granted":false}),
    )
}

async fn import_native_blueprint(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    preview: &str,
    expected: u64,
    review_hash: &str,
    approved_by: &str,
) -> Result<Value> {
    project_lock(tx, project).await?;
    let old:Value=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='native_blueprint_reviews' AND document_id=$2 FOR UPDATE")
        .bind(project).bind(preview).fetch_optional(&mut **tx).await?.ok_or_else(||err("NOT_FOUND","Native blueprint review not found"))?;
    if old["review_digest_algorithm"] != "forgeflow.native-blueprint.review.v2"
        || old["materialization_algorithm"] != "forgeflow.native-blueprint.materialization.v2"
    {
        return Err(err(
            "BLUEPRINT_REVIEW_VERSION_UNSUPPORTED",
            "request a fresh Native blueprint preview with the current digest and materialization algorithms",
        ));
    }
    if old["revision"].as_u64() != Some(expected)
        || old["state"] != "REVIEW_REQUIRED"
        || old["review_sha256"].as_str() != Some(review_hash)
        || old["can_import"] != true
        || old["entry_source"] != "DSH_NATIVE_PANEL"
    {
        return Err(err(
            "BLUEPRINT_REVIEW_CONFLICT",
            "review revision/hash/state changed or contains blocking findings",
        ));
    }
    let request: NativeBlueprintPreviewRequest = decode(old["request"].clone())?;
    let target = blueprint_target(tx, project, &request.mapping).await?;
    if target.digest != old["target_authority_sha256"].as_str().unwrap_or("")
        || json(&target.authority)? != json(&request.expected_authority)?
    {
        return Err(err(
            "BLUEPRINT_TARGET_STALE",
            "target authority changed after preview; no planning cards were imported",
        ));
    }
    let (catalog, findings, _) = blueprint_catalog(tx, &target, &request).await?;
    if !findings.is_empty() || json(&catalog)? != old["catalog"] {
        return Err(err(
            "BLUEPRINT_REVIEW_CONFLICT",
            "materialized review no longer matches the approved planning import",
        ));
    }
    let summary = register_planning_catalog(
        tx,
        project,
        target.authority.catalog_revision,
        catalog,
        true,
    )
    .await?;
    let result = serde_json::json!({"preview_id":preview,"catalog_id":summary["catalog_id"],"catalog_revision":summary["revision"],
        "card_count":summary["card_count"],"role_count":summary["role_count"],"state":"NEEDS_REVIEW","execution_rights_granted":false});
    let mut updated = old;
    updated["revision"] = (expected + 1).into();
    updated["state"] = "IMPORTED".into();
    updated["approved_by"] = approved_by.into();
    updated["result"] = result.clone();
    sqlx::query("UPDATE documents SET revision=$3,data=$4 WHERE project_id=$1 AND collection='native_blueprint_reviews' AND document_id=$2").bind(project).bind(preview).bind(i64v(expected+1)?).bind(&updated).execute(&mut **tx).await?;
    event(
        tx,
        project,
        preview,
        expected + 1,
        "native.blueprint_imported",
        result.clone(),
    )
    .await?;
    Ok(result)
}

impl Store {
    pub async fn native_blueprint_context(&self, project: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let p: Project = decode(
            sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
                .bind(project)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "project not found"))?,
        )?;
        let requirements: Vec<Requirement> = sqlx::query_scalar(
            "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id",
        )
        .bind(project)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(decode)
        .collect::<Result<_>>()?;
        let teams: Vec<Team> = sqlx::query_scalar(
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
        )
        .bind(project)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(decode)
        .collect::<Result<_>>()?;
        let owners:Vec<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='owners' ORDER BY document_id").bind(project).fetch_all(&mut *tx).await?;
        let profiles:Vec<(String,Value)>=sqlx::query_as("SELECT collection,data FROM documents WHERE project_id=$1 AND collection IN ('executor_profiles','resource_profiles','model_routes') ORDER BY collection,document_id").bind(project).fetch_all(&mut *tx).await?;
        let catalogs:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('catalog_id',document_id,'revision',revision,'card_count',data->'card_count','role_count',data->'role_count','edge_count',data->'edge_count') FROM documents WHERE project_id=$1 AND collection='planning_catalogs' ORDER BY document_id").bind(project).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let choices = |collection: &str| -> Result<Vec<Value>> {
            profiles.iter().filter(|(c,_)|c==collection).map(|(_,value)|{
                let mut choice=serde_json::json!({"id":value["id"],"kind":value["kind"],"model_route_id":value["model_route_id"],"provider":value["provider"],"model":value["model"],"sha256":forgeflow_planner::sha256(&serde_json::to_vec(value)?)});
                if collection=="executor_profiles" {
                    choice["preset_ids"]=serde_json::json!([]);choice["positions"]=serde_json::json!([]);choice["preset_catalog_status"]="UNBOUND".into();
                    if value["kind"]=="DSH_MANAGED" {
                        match blueprint_profile_roles(value) {
                            Ok(Some(catalog)) if catalog["schema_version"]=="forgeflow.agent-roles.v1"&&catalog["project_id"].as_str()==Some(project)=>{
                                let positions:Vec<Value>=catalog["roster"].as_array().into_iter().flatten().filter_map(|role|{
                                    let position=role["position_id"].as_str()?.to_owned();let preset=role["preset_id"].as_str()?.to_owned();
                                    let owner=role["owner_id"].as_str()?.to_owned();let team=role["owner_team_id"].as_str()?.to_owned();
                                    Some(serde_json::json!({"position_id":position,"preset_id":preset,"owner_id":owner,"team_id":team}))
                                }).collect();
                                let ids:std::collections::BTreeSet<String>=positions.iter().filter_map(|row|row["preset_id"].as_str().map(str::to_owned)).collect();
                                choice["preset_ids"]=serde_json::to_value(ids)?;choice["positions"]=serde_json::to_value(positions)?;
                                choice["preset_catalog_status"]="PIN_VERIFIED_TARGET_PROJECT".into();
                            },
                            Ok(Some(_))=>choice["preset_catalog_status"]="TARGET_PROJECT_MISMATCH".into(),
                            Ok(None)=>{},
                            Err(_)=>choice["preset_catalog_status"]="PIN_UNAVAILABLE_OR_INVALID".into(),
                        }
                    }
                }
                Ok(choice)
            }).collect()
        };
        Ok(
            serde_json::json!({"project":{"project_id":p.project_id,"name":p.name,"goal":p.goal,"authority_mode":p.authority_mode,"paused":p.paused,"archived":p.archived,"revision":p.revision},
            "requirements":requirements,"teams":teams,"owner_territories":owners,"executor_profiles":choices("executor_profiles")?,"resource_profiles":choices("resource_profiles")?,"model_routes":choices("model_routes")?,"catalogs":catalogs,
            "expected_authority":{"project_revision":p.revision,"requirement_revisions":requirements.iter().map(|r|(r.requirement_id.clone(),r.revision)).collect::<std::collections::BTreeMap<_,_>>(),
                "team_revisions":teams.iter().map(|t|(t.team_id.clone(),t.revision)).collect::<std::collections::BTreeMap<_,_>>(),
                "owner_revisions":owners.iter().filter_map(|o|Some((o["owner_id"].as_str()?.to_owned(),o["revision"].as_u64()?))).collect::<std::collections::BTreeMap<_,_>>(),"catalog_revision":null},
            "execution_rights_granted":false,"source":"POSTGRESQL_REPEATABLE_READ"}),
        )
    }
    pub async fn native_blueprint_source(
        &self,
        project: &str,
        catalog_id: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Value> {
        let limit = limit.clamp(1, 100);
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let catalog:Value=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='planning_catalogs' AND ($2::text IS NULL OR document_id=$2) ORDER BY (data->>'card_count')::bigint DESC,revision DESC,document_id LIMIT 1")
            .bind(project).bind(catalog_id).fetch_optional(&mut *tx).await?.ok_or_else(||err("NOT_FOUND","planning blueprint source catalog not found"))?;
        let id = catalog["catalog_id"]
            .as_str()
            .ok_or_else(|| err("BLUEPRINT_SOURCE_INVALID", "catalog identity missing"))?;
        let rows=sqlx::query("SELECT document_id AS cursor_key,jsonb_build_object('task',data->'task','spec',data->'spec','metadata',jsonb_build_object('source_card',data#>'{metadata,source_card}','source_card_sha256',data#>'{metadata,source_card_sha256}','role_id',data#>'{metadata,role_id}','parent_task',data#>'{metadata,parent_task}','phase',data#>'{metadata,phase}')) AS data FROM documents WHERE project_id=$1 AND collection='planning_cards' AND data->>'catalog_id'=$2 AND ($3::text IS NULL OR document_id>$3) ORDER BY document_id LIMIT $4")
            .bind(project).bind(id).bind(after).bind(i64::from(limit)+1).fetch_all(&mut *tx).await?;
        let requirements: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM requirements WHERE project_id=$1 ORDER BY requirement_id",
        )
        .bind(project)
        .fetch_all(&mut *tx)
        .await?;
        let teams: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
        )
        .bind(project)
        .fetch_all(&mut *tx)
        .await?;
        let owners:Vec<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='owners' ORDER BY document_id").bind(project).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let page = page_rows(rows, limit)?;
        Ok(
            serde_json::json!({"data":{"catalog":{"catalog_id":catalog["catalog_id"],"revision":catalog["revision"],"source_revision":catalog["source_revision"],"cards_sha256":catalog["cards_sha256"],
                "card_count":catalog["card_count"],"role_count":catalog["role_count"],"edge_count":catalog["edge_count"],"parents":catalog["parents"],"roster":catalog["roster"]},
            "requirements":requirements,"teams":teams,"owner_territories":owners,"cards":page.items,"execution_rights_granted":false},"next_cursor":page.next_cursor,
            "source":"postgres","observed_at":Utc::now()}),
        )
    }
}
impl Store {
    /// The immutable execution contract admitted for this exact Attempt.
    /// Do not reconstruct it from a task whose planning revision may have changed.
    pub async fn attempt_envelope(&self, p: &str, id: &str) -> Result<ExecutionEnvelope> {
        let value: Value = sqlx::query_scalar(
            "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
        )
        .bind(p)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "attempt envelope not found"))?;
        decode(value)
    }
    pub async fn attempt_bindings(&self, p: &str, id: &str) -> Result<Value> {
        let mut connection = self.control_pool.acquire().await?;
        crate::execution_bindings::load(&mut connection, p, id).await
    }
}
impl Store {
    /// Read-only in business effect; transient shared locks protect authority identity.
    pub async fn validate_current_flow_context(&self, p: &str, revision: u64) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2",
        )
        .bind(p)
        .bind(i64v(revision)?)
        .fetch_optional(&mut *tx)
        .await?;
        if state.as_deref() != Some("COMMITTED") {
            return Err(err(
                "FLOW_NOT_COMMITTED",
                "current committed planning revision required",
            ));
        }
        let context:forgeflow_planner::CompileContext=decode(sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(p).bind(revision.to_string()).fetch_optional(&mut *tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","committed context missing"))?)?;
        validate_authoritative_context(&mut tx, p, &context).await?;
        tx.commit().await?;
        Ok(())
    }
}
impl Store {
    /// Exact persisted compiler proof, never a runtime event cursor or legacy backfill.
    pub async fn latest_verified_flow(
        &self,
        p: &str,
    ) -> Result<Option<(FlowRevision, forgeflow_planner::CompileContext)>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let flow:Option<Value>=sqlx::query_scalar("SELECT data FROM flow_revisions WHERE project_id=$1 AND state='COMMITTED' ORDER BY flow_revision DESC LIMIT 1").bind(p).fetch_optional(&mut *tx).await?;
        let Some(flow) = flow else {
            tx.commit().await?;
            return Ok(None);
        };
        let flow: FlowRevision = decode(flow)?;
        let context:Value=sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(p).bind(flow.flow_revision.to_string()).fetch_optional(&mut *tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","compiler context missing"))?;
        let receipt:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='compiler_receipts' AND document_id=$2").bind(p).bind(flow.flow_revision.to_string()).fetch_optional(&mut *tx).await?.ok_or_else(||err("COMPILER_RECEIPT_MISSING","legacy approval has no current exact compiler stamp; explicit new review required"))?;
        let context_t: forgeflow_planner::CompileContext = decode(context.clone())?;
        let mut normalized = context;
        normalized["observed_at"] = String::new().into();
        let context_hash = forgeflow_planner::sha256(&serde_json::to_vec(&normalized)?);
        let templates = flow
            .tasks
            .iter()
            .filter_map(|t| {
                t.envelope.as_ref().map(|e| {
                    (
                        t.task_id.clone(),
                        forgeflow_planner::static_execution_template_digest(e),
                    )
                })
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        if receipt.get("passed").and_then(Value::as_bool) != Some(true)
            || receipt.get("digest_algorithm").and_then(Value::as_str)
                != Some(forgeflow_planner::FLOW_APPROVAL_DIGEST_ALGORITHM)
            || receipt
                .get("task_input_digest_algorithm")
                .and_then(Value::as_str)
                != Some(forgeflow_planner::TASK_INPUT_DIGEST_ALGORITHM)
            || receipt.get("flow_revision").and_then(Value::as_u64) != Some(flow.flow_revision)
            || receipt.get("object_revision").and_then(Value::as_u64) != Some(flow.revision)
            || receipt.get("flow_digest").and_then(Value::as_str) != Some(&flow.input_digest)
            || receipt.get("context_digest").and_then(Value::as_str) != Some(&context_hash)
            || receipt.get("static_template_digests") != Some(&json(&templates)?)
            || receipt.get("approved_by") != Some(&json(&flow.approved_by)?)
            || forgeflow_planner::semantic_digest(&flow, &context_t) != flow.input_digest
        {
            return Err(err(
                "COMPILER_RECEIPT_STALE",
                "immutable Flow/context/template identity differs from approved compiler stamp",
            ));
        }
        tx.commit().await?;
        Ok(Some((flow, context_t)))
    }
}
fn canonical_repository_identity(path: &str) -> Result<String> {
    match std::fs::canonicalize(path) {
        Ok(real) => Ok(real.to_string_lossy().into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !std::path::Path::new(path).is_absolute()
                || std::path::Path::new(path).components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(err(
                    "AUTHORITY_SCOPE_VIOLATION",
                    "repository root must be absolute and normalized",
                ));
            }
            Ok(path.into())
        }
        Err(e) => Err(err("REPOSITORY_IDENTITY_UNVERIFIED", e.to_string())),
    }
}
pub(crate) async fn assert_managed_repository_unique(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    root: &str,
) -> Result<()> {
    let root = canonical_repository_identity(root)?;
    let rows:Vec<Value>=sqlx::query_scalar("SELECT data FROM projects WHERE authority_mode='MANAGED' AND archived=false AND project_id<>$1 ORDER BY project_id FOR SHARE").bind(project).fetch_all(&mut **tx).await?;
    for data in rows {
        let other: Project = decode(data)?;
        if canonical_repository_identity(&other.root_path)? == root {
            return Err(err(
                "REPOSITORY_ALREADY_MANAGED",
                format!(
                    "canonical repository authority already belongs to {}",
                    other.project_id
                ),
            ));
        }
    }
    Ok(())
}
