use super::*;

/// A read-only auxiliary attempt may review a retained native author's bytes only
/// through the immutable admission binding. The controller's integration scope is
/// never a write capability granted to that auxiliary author.
async fn git_evidence_authority_tx(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<Option<Value>> {
    let retained = crate::catalog::validate_retained_native_candidate_binding_tx(tx, a).await?;
    let row = sqlx::query(
        "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2 FOR SHARE",
    )
    .bind(&a.project_id)
    .bind(&a.attempt_id)
    .fetch_one(&mut **tx)
    .await?;
    let envelope: ExecutionEnvelope = decode(row.try_get("envelope")?)?;
    let frozen = crate::execution_bindings::load(&mut **tx, &a.project_id, &a.attempt_id).await?;
    let Some(binding) = retained else {
        if matches!(
            envelope.session_purpose,
            SessionPurpose::Planning | SessionPurpose::Review
        ) {
            return Err(err(
                "RETAINED_CANDIDATE_AUTHORITY_REQUIRED",
                "ordinary read-only work accepts structured artifact evidence only",
            ));
        }
        return Ok(None);
    };
    let task: TaskCard = decode(sqlx::query_scalar("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3")
        .bind(&a.project_id).bind(&a.task_id).bind(i64v(a.task_revision)?).fetch_one(&mut **tx).await?)?;
    let plan: forgeflow_evidence::VerificationPlan = decode(frozen["verification_plan"].clone())?;
    let target = &binding["target"];
    if binding["schema_version"] != "forgeflow.retained-native-candidate.v1"
        || envelope.session_purpose != SessionPurpose::Review
        || !envelope.write_set.is_empty()
        || !task.write_set.is_empty()
        || envelope.command.is_none()
        || envelope.max_model_requests != 0
        || envelope.allowed_effects.iter().any(|effect| {
            matches!(
                effect,
                AllowedEffect::WriteDeclaredPaths | AllowedEffect::RequestApprovedModel
            )
        })
        || frozen["executor_profile"]["kind"] != "CONTROLLED_LIGHTWEIGHT"
        || envelope.executor_profile_id != "controlled-lightweight.v1"
        || task.resource_request.coding_slot != 0
        || task.resource_request.provider_inflight != 0
        || target["project_id"].as_str() != Some(a.project_id.as_str())
        || target["task_id"].as_str() != Some(a.task_id.as_str())
        || target["task_revision"].as_u64() != Some(a.task_revision)
        || target["input_digest"].as_str() != Some(task.input_digest.as_str())
        || target["verification_plan_id"].as_str() != Some(plan.plan_id.as_str())
        || target["verification_plan_hash"].as_str() != Some(plan.digest().as_str())
        || plan.plan_id != envelope.verification_plan_id
        || plan.task_revision != a.task_revision
        || plan.input_hash != task.input_digest
        || plan
            .commands
            .iter()
            .map(|command| command.expected_cases.len())
            .sum::<usize>()
            != 8
        || plan
            .commands
            .iter()
            .filter(|command| command.role == forgeflow_evidence::VerificationRole::Author)
            .map(|command| command.expected_cases.len())
            .sum::<usize>()
            != 2
        || plan
            .commands
            .iter()
            .filter(|command| command.role == forgeflow_evidence::VerificationRole::Consumer)
            .map(|command| command.expected_cases.len())
            .sum::<usize>()
            != 2
        || plan
            .commands
            .iter()
            .filter(|command| command.role == forgeflow_evidence::VerificationRole::Independent)
            .map(|command| command.expected_cases.len())
            .sum::<usize>()
            != 4
    {
        return Err(err(
            "RETAINED_CANDIDATE_SCOPE_MISMATCH",
            "retained candidate requires the exact zero-write, zero-model auxiliary review and frozen eight-case plan",
        ));
    }
    let has_models: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_model_requests WHERE project_id=$1 AND attempt_id=$2) OR EXISTS(SELECT 1 FROM model_request_permit WHERE attempt_id=$2)")
        .bind(&a.project_id).bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if has_models {
        return Err(err(
            "RETAINED_CANDIDATE_SCOPE_MISMATCH",
            "verification-only attempt cannot acquire or inherit model requests",
        ));
    }
    let candidate = retained_candidate(&binding)?;
    if candidate.base_sha != a.base_sha {
        return Err(err(
            "EVIDENCE_BINDING_MISMATCH",
            "fresh review base differs from the retained candidate's original base",
        ));
    }
    Ok(Some(binding))
}

fn retained_candidate(binding: &Value) -> Result<forgeflow_git::Candidate> {
    let source = &binding["source"];
    let candidate: forgeflow_git::Candidate = decode(source["candidate"].clone())?;
    let scope = forgeflow_git::PathScope {
        owner_paths: decode(source["owner_paths"].clone())?,
        write_set: decode(source["write_set"].clone())?,
    };
    if scope.owner_paths.is_empty()
        || scope.write_set.is_empty()
        || source["base_sha"].as_str() != Some(candidate.base_sha.as_str())
        || !valid_sha(&candidate.base_sha)
        || !valid_sha(&candidate.candidate_sha)
        || !valid_sha(&candidate.source_hash)
        || !valid_digest(&candidate.diff_manifest_hash)
        || candidate.manifest.base_sha != candidate.base_sha
        || candidate.manifest.head_sha != candidate.candidate_sha
        || candidate.manifest.hash != candidate.diff_manifest_hash
        || candidate.manifest.changes.is_empty()
        || !candidate.manifest.untracked.is_empty()
        || candidate.manifest.changes.iter().any(|change| {
            change.layer != "committed"
                || !scope.permits(&change.path)
                || change
                    .old_path
                    .as_ref()
                    .is_some_and(|path| !scope.permits(path))
        })
    {
        return Err(err(
            "RETAINED_CANDIDATE_SCOPE_MISMATCH",
            "retained candidate manifest differs from its original frozen owner and write scope",
        ));
    }
    for path in scope.owner_paths.iter().chain(&scope.write_set) {
        validate_relative_path(path)?;
    }
    Ok(candidate)
}

fn validate_retained_receipt(
    binding: &Value,
    plan: &forgeflow_evidence::VerificationPlan,
    receipt: &forgeflow_evidence::VerificationReceipt,
    integrated: bool,
) -> Result<()> {
    let candidate = retained_candidate(binding)?;
    let commands: Vec<String> = plan
        .commands
        .iter()
        .flat_map(|command| {
            std::iter::once(command.program.to_string_lossy().into_owned())
                .chain(command.args.clone())
        })
        .collect();
    if receipt.binding.candidate_sha != candidate.candidate_sha
        || receipt.binding.base_sha != candidate.base_sha
        || (!integrated && receipt.binding.source_hash != candidate.source_hash)
        || receipt.binding.integrated_sha.is_some() != integrated
        || receipt.total != 8
        || receipt.failed != 0
        || receipt.skipped != 0
        || receipt.command != commands
        || receipt.environment_profile != plan.environment_profile
        || receipt.oracle_id != plan.oracle_id
        || receipt.verifier_id != plan.verifier_id
        || receipt.author_id != plan.author_id
    {
        return Err(err(
            "RETAINED_CANDIDATE_RECEIPT_MISMATCH",
            "actual candidate/main verification differs from the frozen eight-case review plan",
        ));
    }
    Ok(())
}

fn validate_retained_merge(
    binding: &Value,
    plan: &forgeflow_evidence::VerificationPlan,
    a: &Attempt,
    intent: &MergeIntent,
) -> Result<()> {
    let candidate = retained_candidate(binding)?;
    let receipt: forgeflow_evidence::VerificationReceipt = decode(
        intent
            .receipt
            .as_ref()
            .and_then(|value| value.get("verification"))
            .cloned()
            .ok_or_else(|| {
                err(
                    "EVIDENCE_INCOMPLETE",
                    "retained candidate merge requires actual integrated-main verification",
                )
            })?,
    )?;
    validate_retained_receipt(binding, plan, &receipt, true)?;
    let integrated = intent.integrated_sha.as_deref().ok_or_else(|| {
        err(
            "EVIDENCE_INCOMPLETE",
            "retained candidate merge has no integrated SHA",
        )
    })?;
    let mut expected = receipt.binding.clone();
    expected.task_revision = a.task_revision;
    expected.attempt_id = a.attempt_id.clone();
    expected.generation = a.generation;
    expected.base_sha = candidate.base_sha;
    expected.candidate_sha = candidate.candidate_sha.clone();
    expected.integrated_sha = Some(integrated.into());
    expected.input_hash = plan.input_hash.clone();
    expected.verification_plan_id = plan.plan_id.clone();
    expected.verification_plan_hash = plan.digest();
    expected.contract_version = plan.contract_version.clone();
    receipt
        .validate(&expected, true)
        .map_err(|error| err("VERIFIER_INVALID", error.to_string()))?;
    if intent.project_id != a.project_id
        || intent.attempt_id != a.attempt_id
        || intent.generation != a.generation
        || intent.target_ref != "refs/heads/main"
        || intent.candidate_sha != candidate.candidate_sha
        || !valid_sha(integrated)
        || intent
            .receipt
            .as_ref()
            .and_then(|value| value["new_sha"].as_str())
            != Some(integrated)
        || intent
            .receipt
            .as_ref()
            .and_then(|value| value["verification_receipt_hash"].as_str())
            != Some(receipt.digest().as_str())
    {
        return Err(err(
            "RETAINED_CANDIDATE_RECEIPT_MISMATCH",
            "retained candidate merge identity or original eight-case receipt differs",
        ));
    }
    Ok(())
}

async fn retained_plan_tx(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<forgeflow_evidence::VerificationPlan> {
    decode(sqlx::query_scalar("SELECT execution_bindings->'verification_plan' FROM attempts WHERE project_id=$1 AND attempt_id=$2")
        .bind(&a.project_id).bind(&a.attempt_id).fetch_one(&mut **tx).await?)
}

impl Store {
    /// Return only an immutable retained-candidate binding validated against the
    /// real auxiliary attempt. Generic planning metadata cannot opt into this path.
    pub async fn retained_native_candidate_binding(
        &self,
        project: &str,
        attempt: &str,
    ) -> Result<Option<Value>> {
        let mut tx = self.pool.begin().await?;
        let stored: Option<Value> = sqlx::query_scalar("SELECT execution_bindings->'retained_native_candidate' FROM attempts WHERE project_id=$1 AND attempt_id=$2")
            .bind(project).bind(attempt).fetch_optional(&mut *tx).await?.flatten();
        if stored.as_ref().is_none_or(Value::is_null) {
            tx.commit().await?;
            return Ok(None);
        }
        project_lock(&mut tx, project).await?;
        let a = attempt_lock(&mut tx, project, attempt).await?;
        let result = git_evidence_authority_tx(&mut tx, &a).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn record_evidence(&self, r: EvidenceReceipt) -> Result<()> {
        if r.kind == "STRUCTURED_ARTIFACT" {
            return self.record_artifact_evidence(r).await;
        }
        if r.total == 0
            || r.failed > r.total
            || r.skipped > r.total
            || r.failed.checked_add(r.skipped).is_none_or(|v| v > r.total)
            || r.verifier_id == r.author_id
            || !valid_digest(&r.artifact.sha256)
        {
            return Err(err(
                "VERIFIER_INVALID",
                "independent evidence denominator or artifact invalid",
            ));
        }
        let verification: forgeflow_evidence::VerificationReceipt = decode(r.details.clone())?;
        // Filesystem/Git work remains outside the authoritative mutation transaction.
        let pre_a = self.get_attempt(&r.project_id, &r.attempt_id).await?;
        let pre_task = self.attempt_task(&pre_a).await?;
        let pre_envelope: ExecutionEnvelope = decode(
            sqlx::query_scalar(
                "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
            )
            .bind(&r.project_id)
            .bind(&r.attempt_id)
            .fetch_one(&self.pool)
            .await?,
        )?;
        let retained = self
            .retained_native_candidate_binding(&r.project_id, &r.attempt_id)
            .await?;
        if retained.is_none()
            && matches!(
                pre_envelope.session_purpose,
                SessionPurpose::Planning | SessionPurpose::Review
            )
        {
            return Err(err(
                "RETAINED_CANDIDATE_AUTHORITY_REQUIRED",
                "ordinary read-only evidence cannot adopt a Git candidate",
            ));
        }
        let plan_doc = self
            .get_document(
                &r.project_id,
                "verification_plans",
                &pre_envelope.verification_plan_id,
            )
            .await?;
        let mut plan_value = plan_doc.clone();
        plan_value
            .as_object_mut()
            .ok_or_else(|| err("VERIFIER_INVALID", "invalid plan document"))?
            .remove("revision");
        let plan: forgeflow_evidence::VerificationPlan = decode(plan_value)?;
        if plan.task_revision != pre_a.task_revision
            || plan.input_hash != pre_task.input_digest
            || verification.binding.integrated_sha.is_some()
            || r.integrated_sha.is_some()
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "registered plan must bind original task inputs; author candidate is not integrated",
            ));
        }
        if verification.binding.verification_plan_id != pre_envelope.verification_plan_id
            || verification.binding.verification_plan_hash != plan.digest()
            || verification.environment_profile != plan.environment_profile
            || verification.oracle_id != plan.oracle_id
            || verification.verifier_id != plan.verifier_id
            || verification.author_id != plan.author_id
        {
            return Err(err(
                "VERIFIER_INVALID",
                "receipt does not bind registered plan and independent verifier",
            ));
        }
        let descriptor_pre = self
            .get_document(&r.project_id, "artifacts", &r.artifact.artifact_id)
            .await?;
        let artifact_path_pre = descriptor_pre
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "artifact lacks path"))?;
        let root = std::fs::canonicalize(&pre_envelope.artifact_prefix)
            .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        let path = std::fs::canonicalize(artifact_path_pre)
            .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        if !path.starts_with(&root) {
            return Err(err(
                "OWNER_PATH_VIOLATION",
                "raw verification artifact escapes frozen artifact root",
            ));
        }
        verification
            .validate_log(
                path.parent()
                    .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "artifact log parent missing"))?,
            )
            .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        let receipt_log =
            std::fs::canonicalize(path.parent().unwrap().join(&verification.log_path))
                .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        if receipt_log != path {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "registered log descriptor differs from receipt raw log",
            ));
        }
        let disk: Value = serde_json::from_slice(
            &std::fs::read(path.parent().unwrap().join("verification-receipt.json"))
                .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?,
        )?;
        if disk != r.details {
            return Err(err(
                "VERIFIER_INVALID",
                "submitted counts/provenance differ from trusted runner's durable receipt",
            ));
        }
        let expected_total: u64 = plan
            .commands
            .iter()
            .map(|c| c.expected_cases.len() as u64)
            .sum();
        if verification.total != expected_total {
            return Err(err(
                "VERIFIER_INVALID",
                "receipt denominator differs from registered exact cases",
            ));
        }
        let mut expected = verification.binding.clone();
        expected.task_revision = pre_a.task_revision;
        expected.attempt_id = pre_a.attempt_id.clone();
        expected.generation = pre_a.generation;
        expected.base_sha = pre_a.base_sha.clone();
        expected.input_hash = pre_task.input_digest.clone();
        expected.verification_plan_id = plan.plan_id.clone();
        expected.verification_plan_hash = plan.digest();
        if retained.is_some()
            || matches!(
                pre_envelope.session_purpose,
                SessionPurpose::Execution | SessionPurpose::MainAgentModelSession
            )
        {
            let project = self.get_project(&r.project_id).await?;
            expected.source_hash = forgeflow_git::source_hash(
                std::path::Path::new(&project.root_path),
                &verification.binding.candidate_sha,
            )
            .map_err(|e| err("EVIDENCE_BINDING_MISMATCH", e.to_string()))?;
        }
        if let Some(retained) = &retained {
            validate_retained_receipt(retained, &plan, &verification, false)?;
        }
        let context = self
            .get_document(
                &r.project_id,
                "flow_contexts",
                &pre_task.flow_revision.to_string(),
            )
            .await?;
        let mut context = context;
        context.as_object_mut().unwrap().remove("revision");
        let context: forgeflow_planner::CompileContext = decode(context)?;
        let spec = context
            .task_specs
            .get(&pre_task.task_id)
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "frozen task specification missing"))?;
        expected.contract_version = spec
            .contract_produces
            .first()
            .or_else(|| spec.contract_consumes.first())
            .map(|c| format!("{}:{}", c.contract_id, c.version))
            .unwrap_or_else(|| plan.contract_version.clone());
        let expected_commands: Vec<String> = plan
            .commands
            .iter()
            .flat_map(|c| {
                std::iter::once(c.program.to_string_lossy().into_owned()).chain(c.args.clone())
            })
            .collect();
        if verification.command != expected_commands {
            return Err(err(
                "VERIFIER_INVALID",
                "receipt executed argv differs from registered plan",
            ));
        }
        verification
            .validate(&expected, true)
            .map_err(|e| err("VERIFIER_INVALID", e.to_string()))?;
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        let a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        valid_lease(&mut tx, &a, r.generation, &a.worker_id).await?;
        let current_retained = git_evidence_authority_tx(&mut tx, &a).await?;
        if current_retained != retained {
            return Err(err(
                "CONTEXT_STALE",
                "retained candidate authority changed after verification",
            ));
        }
        let current_plan:Value=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='verification_plans' AND document_id=$2 FOR UPDATE").bind(&r.project_id).bind(&pre_envelope.verification_plan_id).fetch_one(&mut *tx).await?;
        if current_plan != plan_doc
            || a.task_revision != pre_a.task_revision
            || a.generation != pre_a.generation
        {
            return Err(err(
                "CONTEXT_STALE",
                "evidence preflight identities changed",
            ));
        }
        let task:TaskCard=decode(sqlx::query_scalar("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3").bind(&a.project_id).bind(&a.task_id).bind(i64v(a.task_revision)?).fetch_one(&mut *tx).await?)?;
        if verification.binding.attempt_id != a.attempt_id
            || verification.binding.generation != a.generation
            || verification.binding.task_revision != a.task_revision
            || verification.binding.base_sha != a.base_sha
            || verification.binding.input_hash != task.input_digest
            || r.input_digest != task.input_digest
            || r.candidate_sha.as_deref() != Some(&verification.binding.candidate_sha)
            || r.verifier_id != verification.verifier_id
            || r.author_id != verification.author_id
            || r.total != verification.total
            || r.failed != verification.failed
            || r.skipped != verification.skipped
            || r.artifact.sha256 != verification.log_hash
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "receipt differs from immutable attempt and verifier identities",
            ));
        }

        let descriptor:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2").bind(&r.project_id).bind(&r.artifact.artifact_id).fetch_optional(&mut *tx).await?;
        let descriptor = descriptor
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "registered raw artifact required"))?;
        if descriptor.get("path") != descriptor_pre.get("path")
            || descriptor.get("sha256") != descriptor_pre.get("sha256")
        {
            return Err(err(
                "CONTEXT_STALE",
                "raw artifact descriptor changed after verification",
            ));
        }
        let value = json(&r)?;
        let old: Option<Value> =
            sqlx::query_scalar("SELECT data FROM evidence_receipts WHERE receipt_id=$1")
                .bind(&r.receipt_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(old) = old {
            if old != value {
                return Err(err("IDEMPOTENCY_CONFLICT", "evidence identity immutable"));
            }
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("INSERT INTO evidence_receipts VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&r.project_id)
            .bind(&r.receipt_id)
            .bind(&r.attempt_id)
            .bind(r.generation)
            .bind(&r.kind)
            .bind(&value)
            .bind(r.created_at)
            .execute(&mut *tx)
            .await?;
        event(
            &mut tx,
            &r.project_id,
            &r.receipt_id,
            1,
            "evidence.recorded",
            value,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn get_merge_intent(&self, p: &str, id: &str) -> Result<MergeIntent> {
        let v: Option<Value> = sqlx::query_scalar(
            "SELECT data FROM merge_intents WHERE project_id=$1 AND intent_id=$2",
        )
        .bind(p)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        decode(v.ok_or_else(|| err("NOT_FOUND", "merge intent not found"))?)
    }
    pub async fn pending_merges(&self, p: &str, target: &str) -> Result<Vec<MergeIntent>> {
        let v:Vec<Value>=sqlx::query_scalar("SELECT data FROM merge_intents WHERE project_id=$1 AND target_ref=$2 AND state IN('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED') ORDER BY intent_id").bind(p).bind(target).fetch_all(&self.pool).await?;
        v.into_iter().map(decode).collect()
    }
    pub async fn prepare_merge(&self, mut intent: MergeIntent) -> Result<MergeIntent> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &intent.project_id).await?;
        let mut a = attempt_lock(&mut tx, &intent.project_id, &intent.attempt_id).await?;
        valid_lease(&mut tx, &a, intent.generation, &a.worker_id).await?;
        super::collaboration::require_verifier_roots_settled(&mut tx, &a).await?;
        let retained = git_evidence_authority_tx(&mut tx, &a).await?;
        if let Some(binding) = &retained {
            let plan = retained_plan_tx(&mut tx, &a).await?;
            validate_retained_merge(binding, &plan, &a, &intent)?;
        }
        if let Some(old) =
            sqlx::query_scalar::<_, Value>("SELECT data FROM merge_intents WHERE intent_id=$1")
                .bind(&intent.intent_id)
                .fetch_optional(&mut *tx)
                .await?
        {
            let old: MergeIntent = decode(old)?;
            if old.attempt_id != intent.attempt_id
                || old.project_id != intent.project_id
                || old.candidate_sha != intent.candidate_sha
                || old.expected_sha != intent.expected_sha
            {
                return Err(err("IDEMPOTENCY_CONFLICT", "merge identity reused"));
            }
            tx.commit().await?;
            return Ok(old);
        }
        if !matches!(
            a.state,
            AttemptState::ReviewReady | AttemptState::MergeQueued
        ) {
            return Err(err(
                "ILLEGAL_TRANSITION",
                "candidate must be reviewed before integration",
            ));
        }
        if !valid_sha(&intent.candidate_sha)
            || !valid_sha(&intent.expected_sha)
            || !intent.target_ref.starts_with("refs/heads/")
        {
            return Err(err("VALIDATION_ERROR", "merge SHA/ref invalid"));
        }
        let receipts:Vec<Value>=sqlx::query_scalar("SELECT data FROM evidence_receipts WHERE project_id=$1 AND attempt_id=$2 AND generation=$3").bind(&a.project_id).bind(&a.attempt_id).bind(a.generation).fetch_all(&mut *tx).await?;
        if !receipts.iter().any(|v| {
            v.get("candidate_sha").and_then(Value::as_str) == Some(&intent.candidate_sha)
                && v.get("failed").and_then(Value::as_u64) == Some(0)
                && v.get("skipped").and_then(Value::as_u64) == Some(0)
        }) {
            return Err(err(
                "EVIDENCE_INCOMPLETE",
                "candidate lacks bound independent passing receipt",
            ));
        }
        if let Some(binding) = &retained {
            let plan = retained_plan_tx(&mut tx, &a).await?;
            let matching: Vec<_> = receipts
                .iter()
                .filter(|receipt| {
                    receipt["kind"] == "INDEPENDENT_VERIFICATION"
                        && receipt["candidate_sha"].as_str() == Some(intent.candidate_sha.as_str())
                })
                .collect();
            if matching.len() != 1 {
                return Err(err(
                    "EVIDENCE_INCOMPLETE",
                    "retained candidate requires one independently recorded candidate receipt",
                ));
            }
            let receipt: forgeflow_evidence::VerificationReceipt =
                decode(matching[0]["details"].clone())?;
            validate_retained_receipt(binding, &plan, &receipt, false)?;
        }
        if intent
            .receipt
            .as_ref()
            .and_then(|v| v.get("commit_decided"))
            .is_some()
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "caller cannot supply commit decision marker",
            ));
        }
        intent.state = MergeIntentState::Prepared;
        intent.revision = 1;
        sqlx::query("INSERT INTO merge_intents VALUES($1,$2,$3,$4,$5,$6,1,$7)")
            .bind(&intent.intent_id)
            .bind(&intent.project_id)
            .bind(&intent.attempt_id)
            .bind(intent.generation)
            .bind(&intent.target_ref)
            .bind(intent.state.as_str())
            .bind(json(&intent)?)
            .execute(&mut *tx)
            .await?;
        a.state = AttemptState::MergeQueued;
        a.revision += 1;
        persist_attempt(&mut tx, &a).await?;
        event(
            &mut tx,
            &a.project_id,
            &intent.intent_id,
            1,
            "merge.prepared",
            json(&intent)?,
        )
        .await?;
        tx.commit().await?;
        Ok(intent)
    }
    pub async fn decide_merge(&self, p: &str, id: &str, expected: u64) -> Result<MergeIntent> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, p).await?;
        let mut intent = lock_intent(&mut tx, p, id).await?;
        if intent.state == MergeIntentState::CommitDecided {
            tx.commit().await?;
            return Ok(intent);
        }
        if intent.revision != expected || intent.state != MergeIntentState::Prepared {
            return Err(err("REVISION_CONFLICT", "merge intent changed"));
        }
        let mut a = attempt_lock(&mut tx, p, &intent.attempt_id).await?;
        valid_lease(&mut tx, &a, intent.generation, &a.worker_id).await?;
        super::collaboration::require_verifier_roots_settled(&mut tx, &a).await?;
        if let Some(binding) = git_evidence_authority_tx(&mut tx, &a).await? {
            let plan = retained_plan_tx(&mut tx, &a).await?;
            validate_retained_merge(&binding, &plan, &a, &intent)?;
        }
        if a.state != AttemptState::MergeQueued {
            return Err(err("ILLEGAL_TRANSITION", "merge not queued"));
        }
        if intent.receipt.is_none() {
            return Err(err(
                "EVIDENCE_INCOMPLETE",
                "write-ahead merge intent requires frozen verification receipt",
            ));
        }
        if intent
            .receipt
            .as_ref()
            .and_then(|v| v.get("commit_decided"))
            .is_some()
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "commit decision marker is authority owned",
            ));
        }
        intent.state = MergeIntentState::CommitDecided;
        intent.receipt.as_mut().unwrap()["commit_decided"] = true.into();
        intent.revision += 1;
        save_intent(&mut tx, &intent).await?;
        a.state = AttemptState::Merging;
        a.revision += 1;
        persist_attempt(&mut tx, &a).await?;
        event(
            &mut tx,
            p,
            id,
            intent.revision,
            "merge.commit_decided",
            json(&intent)?,
        )
        .await?;
        tx.commit().await?;
        Ok(intent)
    }
    pub async fn mark_ref_updated(
        &self,
        p: &str,
        id: &str,
        sha: &str,
        receipt: Value,
    ) -> Result<MergeIntent> {
        let pre_intent = self.get_merge_intent(p, id).await?;
        if !matches!(
            pre_intent.state,
            MergeIntentState::Committed | MergeIntentState::Finalized
        ) {
            let project = self.get_project(p).await?;
            let repo = std::path::Path::new(&project.root_path);
            let head = forgeflow_git::resolve(repo, &pre_intent.target_ref)
                .map_err(|e| err("GIT_INTEGRATION_CONFLICT", e.to_string()))?;
            if !forgeflow_git::is_ancestor(repo, sha, &head)
                .map_err(|e| err("GIT_INTEGRATION_CONFLICT", e.to_string()))?
            {
                return Err(err(
                    "EVIDENCE_INCOMPLETE",
                    "integrated SHA is not reachable from authoritative target ref",
                ));
            }
            let verification: forgeflow_evidence::VerificationReceipt =
                decode(receipt.get("verification").cloned().ok_or_else(|| {
                    err("EVIDENCE_INCOMPLETE", "merge verification receipt missing")
                })?)?;
            let pre_attempt = self.get_attempt(p, &pre_intent.attempt_id).await?;
            let pre_task = self.attempt_task(&pre_attempt).await?;
            let retained = self
                .retained_native_candidate_binding(p, &pre_attempt.attempt_id)
                .await?;
            let envelope: ExecutionEnvelope = decode(
                sqlx::query_scalar(
                    "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
                )
                .bind(p)
                .bind(&pre_attempt.attempt_id)
                .fetch_one(&self.pool)
                .await?,
            )?;
            let mut plan_doc = self
                .get_document(p, "verification_plans", &envelope.verification_plan_id)
                .await?;
            plan_doc.as_object_mut().unwrap().remove("revision");
            let plan: forgeflow_evidence::VerificationPlan = decode(plan_doc)?;
            if let Some(binding) = &retained {
                validate_retained_receipt(binding, &plan, &verification, true)?;
            }
            let mut binding = verification.binding.clone();
            binding.task_revision = pre_attempt.task_revision;
            binding.attempt_id = pre_attempt.attempt_id.clone();
            binding.generation = pre_attempt.generation;
            binding.base_sha = pre_attempt.base_sha.clone();
            binding.candidate_sha = pre_intent.candidate_sha.clone();
            binding.integrated_sha = Some(sha.into());
            binding.input_hash = pre_task.input_digest;
            binding.source_hash = forgeflow_git::source_hash(repo, sha)
                .map_err(|e| err("EVIDENCE_BINDING_MISMATCH", e.to_string()))?;
            binding.verification_plan_id = plan.plan_id.clone();
            binding.verification_plan_hash = plan.digest();
            binding.contract_version = plan.contract_version;
            verification
                .validate(&binding, true)
                .map_err(|e| err("VERIFIER_INVALID", e.to_string()))?;
            if receipt
                .get("verification_receipt_hash")
                .and_then(Value::as_str)
                != Some(&verification.digest())
            {
                return Err(err(
                    "EVIDENCE_BINDING_MISMATCH",
                    "merge verification receipt digest mismatch",
                ));
            }
            let artifact_root = receipt
                .get("artifact_root")
                .and_then(Value::as_str)
                .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "merge raw log root missing"))?;
            let artifact_root = std::fs::canonicalize(artifact_root)
                .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
            let repo_root = std::fs::canonicalize(repo)
                .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
            if !artifact_root.starts_with(&repo_root) {
                return Err(err(
                    "OWNER_PATH_VIOLATION",
                    "merge raw evidence must remain in managed repository metadata",
                ));
            }
            verification
                .validate_log(&artifact_root)
                .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        }
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, p).await?;
        let mut intent = lock_intent(&mut tx, p, id).await?;
        if matches!(
            intent.state,
            MergeIntentState::Committed
                | MergeIntentState::Finalized
                | MergeIntentState::RefUpdated
        ) {
            if intent.integrated_sha.as_deref() != Some(sha) {
                return Err(err("IDEMPOTENCY_CONFLICT", "committed SHA mismatch"));
            }
            tx.commit().await?;
            return Ok(intent);
        }
        // COMMIT_DECIDED is irreversible: expired author lease does not turn a real ref CAS into cancellation.
        if !(intent.state == MergeIntentState::CommitDecided
            || (intent.state == MergeIntentState::RecoveryRequired
                && intent
                    .receipt
                    .as_ref()
                    .and_then(|v| v.get("commit_decided"))
                    .and_then(Value::as_bool)
                    == Some(true)))
            || !valid_sha(sha)
        {
            return Err(err(
                "ILLEGAL_TRANSITION",
                "merge confirmation requires decided intent",
            ));
        }
        let expected_new = intent
            .receipt
            .as_ref()
            .and_then(|v| v.get("new_sha"))
            .and_then(Value::as_str)
            .unwrap_or(&intent.candidate_sha);
        if sha != expected_new || receipt.get("new_sha").and_then(Value::as_str) != Some(sha) {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "confirmation SHA differs from write-ahead intent",
            ));
        }
        let mut a = attempt_lock(&mut tx, p, &intent.attempt_id).await?;
        if a.generation != intent.generation
            || !matches!(
                a.state,
                AttemptState::Merging | AttemptState::RecoveryRequired
            )
        {
            return Err(err("LEASE_STALE", "merge identity/state mismatch"));
        }
        if let Some(binding) = git_evidence_authority_tx(&mut tx, &a).await? {
            let plan = retained_plan_tx(&mut tx, &a).await?;
            let mut confirmed = intent.clone();
            confirmed.integrated_sha = Some(sha.into());
            confirmed.receipt = Some(receipt.clone());
            validate_retained_merge(&binding, &plan, &a, &confirmed)?;
        }
        intent.state = MergeIntentState::RefUpdated;
        intent.integrated_sha = Some(sha.into());
        intent.receipt = Some(receipt);
        intent.receipt.as_mut().unwrap()["commit_decided"] = true.into();
        intent.receipt.as_mut().unwrap()["ref_updated"] = true.into();
        intent.revision += 1;
        save_intent(&mut tx, &intent).await?;
        event(
            &mut tx,
            p,
            id,
            intent.revision,
            "merge.ref_updated",
            json(&intent)?,
        )
        .await?;
        tx.commit().await?;
        Ok(intent)
    }
    pub async fn finalize_merge(&self, p: &str, id: &str) -> Result<MergeIntent> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let result = finalize_merge_tx(&mut tx, p, id).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn confirm_merge(
        &self,
        p: &str,
        id: &str,
        sha: &str,
        receipt: Value,
    ) -> Result<MergeIntent> {
        self.mark_ref_updated(p, id, sha, receipt).await?;
        self.finalize_merge(p, id).await
    }
    pub async fn abort_merge(&self, p: &str, id: &str, reason: &str) -> Result<MergeIntent> {
        self.merge_recovery(p, id, reason, true).await
    }
    pub async fn mark_merge_recovery_required(
        &self,
        p: &str,
        id: &str,
        reason: &str,
    ) -> Result<MergeIntent> {
        self.merge_recovery(p, id, reason, false).await
    }
    async fn merge_recovery(
        &self,
        p: &str,
        id: &str,
        reason: &str,
        abort: bool,
    ) -> Result<MergeIntent> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, p).await?;
        let mut intent = lock_intent(&mut tx, p, id).await?;
        if abort && intent.state != MergeIntentState::Prepared {
            return Err(err(
                "COMMIT_IN_PROGRESS",
                "decided intent cannot be aborted",
            ));
        }
        if matches!(
            intent.state,
            MergeIntentState::Committed | MergeIntentState::Finalized
        ) {
            return Err(err("ALREADY_COMMITTED", "merge already committed"));
        }
        intent.state = if abort {
            MergeIntentState::Aborted
        } else {
            MergeIntentState::RecoveryRequired
        };
        intent.revision += 1;
        save_intent(&mut tx, &intent).await?;
        if !abort {
            let mut a = attempt_lock(&mut tx, p, &intent.attempt_id).await?;
            a.state = AttemptState::RecoveryRequired;
            a.revision += 1;
            revoke(&mut tx, &a).await?;
            sqlx::query("UPDATE resource_allocations SET state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'").bind(&a.attempt_id).execute(&mut *tx).await?;
            persist_attempt(&mut tx, &a).await?;
        }
        event(
            &mut tx,
            p,
            id,
            intent.revision,
            "merge.recovery",
            serde_json::json!({"intent":intent,"reason":reason}),
        )
        .await?;
        tx.commit().await?;
        Ok(intent)
    }
}
async fn lock_intent(tx: &mut Transaction<'_, Postgres>, p: &str, id: &str) -> Result<MergeIntent> {
    let v: Option<Value> = sqlx::query_scalar(
        "SELECT data FROM merge_intents WHERE project_id=$1 AND intent_id=$2 FOR UPDATE",
    )
    .bind(p)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    decode(v.ok_or_else(|| err("NOT_FOUND", "merge intent not found"))?)
}
async fn save_intent(tx: &mut Transaction<'_, Postgres>, i: &MergeIntent) -> Result<()> {
    sqlx::query("UPDATE merge_intents SET state=$3,revision=$4,data=$5 WHERE project_id=$1 AND intent_id=$2").bind(&i.project_id).bind(&i.intent_id).bind(i.state.as_str()).bind(i64v(i.revision)?).bind(json(i)?).execute(&mut **tx).await?;
    Ok(())
}
#[async_trait::async_trait]
impl forgeflow_git::IntegrationStore for Store {
    async fn prepare_merge(&self, intent: MergeIntent) -> std::result::Result<MergeIntent, String> {
        Store::prepare_merge(self, intent)
            .await
            .map_err(|e| e.to_string())
    }
    async fn decide_merge(
        &self,
        p: &str,
        i: &str,
        r: u64,
    ) -> std::result::Result<MergeIntent, String> {
        Store::decide_merge(self, p, i, r)
            .await
            .map_err(|e| e.to_string())
    }
    async fn confirm_merge(
        &self,
        p: &str,
        i: &str,
        sha: &str,
        r: Value,
    ) -> std::result::Result<MergeIntent, String> {
        Store::confirm_merge(self, p, i, sha, r)
            .await
            .map_err(|e| e.to_string())
    }
    async fn get_merge_intent(&self, p: &str, i: &str) -> std::result::Result<MergeIntent, String> {
        Store::get_merge_intent(self, p, i)
            .await
            .map_err(|e| e.to_string())
    }
    async fn pending_merges(
        &self,
        p: &str,
        target: &str,
    ) -> std::result::Result<Vec<MergeIntent>, String> {
        Store::pending_merges(self, p, target)
            .await
            .map_err(|e| e.to_string())
    }
    async fn abort_merge(
        &self,
        p: &str,
        i: &str,
        r: &str,
    ) -> std::result::Result<MergeIntent, String> {
        Store::abort_merge(self, p, i, r)
            .await
            .map_err(|e| e.to_string())
    }
    async fn mark_merge_recovery_required(
        &self,
        p: &str,
        i: &str,
        r: &str,
    ) -> std::result::Result<MergeIntent, String> {
        Store::mark_merge_recovery_required(self, p, i, r)
            .await
            .map_err(|e| e.to_string())
    }
}
impl Store {
    pub async fn freeze_contract(&self, r: FreezeContractRequest) -> Result<ContractVersion> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let request = json(&r)?;
        if let Some(value) = replay(
            &mut tx,
            &r.actor_id,
            "freeze_contract",
            &r.idempotency_key,
            &request,
        )
        .await?
        {
            let c = decode(value)?;
            tx.commit().await?;
            return Ok(c);
        }
        project_lock(&mut tx, &r.project_id).await?;
        let doc_id = format!("{}:{}", r.contract_id, r.version);
        let row=sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='contract_versions' AND document_id=$2 FOR UPDATE").bind(&r.project_id).bind(&doc_id).fetch_optional(&mut *tx).await?.ok_or_else(||err("NOT_FOUND","contract version draft missing"))?;
        if row.get::<i64, _>("revision") as u64 != r.expected_revision {
            return Err(err("REVISION_CONFLICT", "contract draft changed"));
        }
        let mut c: ContractVersion = decode(row.try_get("data")?)?;
        if c.project_id != r.project_id
            || c.contract_id != r.contract_id
            || c.version != r.version
            || !valid_digest(&c.spec_sha256)
            || !valid_digest(&c.source_sha256)
        {
            return Err(err("VALIDATION_ERROR", "contract identity/digest invalid"));
        }
        let producer: EvidenceReceipt = decode(
            sqlx::query_scalar(
                "SELECT data FROM evidence_receipts WHERE project_id=$1 AND receipt_id=$2",
            )
            .bind(&r.project_id)
            .bind(&r.producer_receipt_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                err(
                    "EVIDENCE_INCOMPLETE",
                    "producer verification receipt missing",
                )
            })?,
        )?;
        let task:String=sqlx::query_scalar("SELECT task_id FROM attempts WHERE project_id=$1 AND attempt_id=$2 AND state='SUCCEEDED'").bind(&r.project_id).bind(&producer.attempt_id).fetch_optional(&mut *tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","producer not integrated"))?;
        if task != c.producer_task_id {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "producer receipt belongs to another task",
            ));
        }
        let producer_task:TaskCard=decode(sqlx::query_scalar("SELECT t.data FROM task_revisions t JOIN attempts a ON a.project_id=t.project_id AND a.task_id=t.task_id AND a.task_revision=t.task_revision WHERE a.project_id=$1 AND a.attempt_id=$2").bind(&r.project_id).bind(&producer.attempt_id).fetch_one(&mut *tx).await?)?;
        let context:forgeflow_planner::CompileContext=decode(sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2").bind(&r.project_id).bind(producer_task.flow_revision.to_string()).fetch_one(&mut *tx).await?)?;
        let binding = context
            .task_specs
            .get(&producer_task.task_id)
            .and_then(|s| {
                s.contract_produces
                    .iter()
                    .find(|b| b.contract_id == c.contract_id && b.version == c.version)
            })
            .ok_or_else(|| {
                err(
                    "EVIDENCE_BINDING_MISMATCH",
                    "producer did not own this exact contract output",
                )
            })?;
        if binding.spec_sha256 != c.spec_sha256
            || !c.schema.is_object()
            || forgeflow_planner::sha256(&serde_json::to_vec(&c.schema)?) != c.spec_sha256
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "actual contract schema/hash differs from frozen producer contract",
            ));
        }
        let producer_verification: forgeflow_evidence::VerificationReceipt =
            decode(producer.details.clone())?;
        if producer_verification.binding.contract_version != doc_id
            || producer.failed != 0
            || producer.skipped != 0
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "producer receipt must verify exact contract version",
            ));
        }
        let integration:MergeIntent=decode(sqlx::query_scalar("SELECT data FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 AND state='FINALIZED'").bind(&r.project_id).bind(&producer.attempt_id).fetch_optional(&mut *tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","producer final integration receipt missing"))?)?;
        let integrated_sha = integration.integrated_sha.as_deref().ok_or_else(|| {
            err(
                "EVIDENCE_INCOMPLETE",
                "final integration lacks frozen commit",
            )
        })?;
        let integrated_verification: forgeflow_evidence::VerificationReceipt = decode(
            integration
                .receipt
                .as_ref()
                .and_then(|v| v.get("verification"))
                .cloned()
                .ok_or_else(|| {
                    err(
                        "EVIDENCE_INCOMPLETE",
                        "final integration lacks verification",
                    )
                })?,
        )?;
        let project: Project = decode(
            sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1")
                .bind(&r.project_id)
                .fetch_one(&mut *tx)
                .await?,
        )?;
        // source_hash keeps its historical Git tree OID meaning. The contract's
        // SHA256 is computed from actual tracked objects, never from report JSON.
        let source_content = forgeflow_git::source_content_manifest(
            std::path::Path::new(&project.root_path),
            integrated_sha,
        )
        .map_err(|e| err("EVIDENCE_BINDING_MISMATCH", e.to_string()))?;
        if source_content.commit_sha != integrated_sha
            || integrated_verification.binding.attempt_id != producer.attempt_id
            || integrated_verification.binding.generation != integration.generation
            || integrated_verification.binding.contract_version != doc_id
            || integrated_verification.binding.integrated_sha.as_deref() != Some(integrated_sha)
            || integrated_verification.binding.source_hash != source_content.tree_oid
            || source_content.source_sha256 != c.source_sha256
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "contract content SHA256 or verified Git tree differs from actual integrated commit",
            ));
        }
        let source_freeze_proof = serde_json::json!({
            "kind":"CONTRACT_SOURCE_FREEZE",
            "project_id":r.project_id,
            "contract_id":r.contract_id,
            "contract_version":r.version,
            "producer_attempt_id":producer.attempt_id,
            "integration_intent_id":integration.intent_id,
            "integrated_sha":source_content.commit_sha,
            "source_tree_oid":source_content.tree_oid,
            "source_content_algorithm":source_content.algorithm,
            "source_content_sha256":source_content.source_sha256,
            "tracked_entries":source_content.tracked_entries,
            "total_blob_bytes":source_content.total_blob_bytes
        });
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'operations',$2,1,$3)")
            .bind(&r.project_id)
            .bind(format!("contract-source-freeze:{}:{}", r.contract_id, r.version))
            .bind(source_freeze_proof)
            .execute(&mut *tx).await?;
        let mut consumer_receipts = std::collections::BTreeMap::new();
        let mut passing = std::collections::BTreeSet::new();
        for receipt_id in &r.consumer_receipt_ids {
            let receipt: EvidenceReceipt = decode(
                sqlx::query_scalar(
                    "SELECT data FROM evidence_receipts WHERE project_id=$1 AND receipt_id=$2",
                )
                .bind(&r.project_id)
                .bind(receipt_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "consumer receipt missing"))?,
            )?;
            let task: String = sqlx::query_scalar(
                "SELECT task_id FROM attempts WHERE project_id=$1 AND attempt_id=$2",
            )
            .bind(&r.project_id)
            .bind(&receipt.attempt_id)
            .fetch_one(&mut *tx)
            .await?;
            let verification: forgeflow_evidence::VerificationReceipt = decode(receipt.details)?;
            if receipt.failed != 0
                || receipt.skipped != 0
                || verification.binding.contract_version != doc_id
            {
                return Err(err(
                    "EVIDENCE_INCOMPLETE",
                    "consumer receipt must pass exact contract version",
                ));
            }
            consumer_receipts.insert(task.clone(), receipt.receipt_id.clone());
            passing.insert(task);
        }
        if c.required_consumers.iter().any(|t| !passing.contains(t)) {
            return Err(err(
                "CONTRACT_NOT_FROZEN",
                "required consumer probe receipts incomplete",
            ));
        }
        c.passing_consumers = passing.into_iter().collect();
        c.independent_receipt_id = Some(producer.receipt_id);
        c.integration_receipt_id = Some(integration.intent_id);
        c.frozen = true;
        c.revision = r.expected_revision + 1;
        sqlx::query("INSERT INTO contract_versions VALUES($1,$2,$3,'FROZEN',$4)")
            .bind(&c.project_id)
            .bind(&c.contract_id)
            .bind(i64v(c.version)?)
            .bind(json(&c)?)
            .execute(&mut *tx)
            .await?;
        for task in &c.required_consumers {
            sqlx::query("INSERT INTO contract_consumers(project_id,contract_id,version,task_id,receipt_id,data) VALUES($1,$2,$3,$4,$5,$6)").bind(&c.project_id).bind(&c.contract_id).bind(i64v(c.version)?).bind(task).bind(&consumer_receipts[task]).bind(serde_json::json!({"spec_sha256":c.spec_sha256,"source_sha256":c.source_sha256})).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE documents SET revision=$3,data=$4 WHERE project_id=$1 AND collection='contract_versions' AND document_id=$2").bind(&c.project_id).bind(&doc_id).bind(i64v(c.revision)?).bind(json(&c)?).execute(&mut *tx).await?;
        event(
            &mut tx,
            &c.project_id,
            &doc_id,
            c.revision,
            "contract.frozen",
            json(&c)?,
        )
        .await?;
        save_replay(
            &mut tx,
            &r.actor_id,
            "freeze_contract",
            &r.idempotency_key,
            &id(),
            &request,
            &json(&c)?,
        )
        .await?;
        tx.commit().await?;
        Ok(c)
    }
    pub async fn complete_read_only(
        &self,
        p: &str,
        id: &str,
        generation: i64,
        worker: &str,
        receipt_id: &str,
    ) -> Result<Attempt> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let result = complete_read_only_tx(&mut tx, p, id, generation, worker, receipt_id).await?;
        tx.commit().await?;
        Ok(result)
    }
}
impl Store {
    pub async fn record_artifact_evidence(&self, r: EvidenceReceipt) -> Result<()> {
        if r.candidate_sha.is_some()
            || r.integrated_sha.is_some()
            || r.kind != "STRUCTURED_ARTIFACT"
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "read-only receipt cannot fabricate Git identities",
            ));
        }
        let verification: forgeflow_evidence::ArtifactVerificationReceipt =
            decode(r.details.clone())?;
        let a = self.get_attempt(&r.project_id, &r.attempt_id).await?;
        if self
            .retained_native_candidate_binding(&r.project_id, &r.attempt_id)
            .await?
            .is_some()
        {
            return Err(err(
                "RETAINED_CANDIDATE_AUTHORITY_REQUIRED",
                "retained candidate review requires Git-bound candidate and integrated-main evidence",
            ));
        }
        let task = self.attempt_task(&a).await?;
        let envelope: ExecutionEnvelope = decode(
            sqlx::query_scalar(
                "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
            )
            .bind(&r.project_id)
            .bind(&r.attempt_id)
            .fetch_one(&self.pool)
            .await?,
        )?;
        if !matches!(
            envelope.session_purpose,
            SessionPurpose::Planning | SessionPurpose::Review
        ) || !envelope.write_set.is_empty()
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "artifact-only receipt requires planning/review attempt",
            ));
        }
        let plan_doc = self
            .get_document(
                &r.project_id,
                "verification_plans",
                &envelope.verification_plan_id,
            )
            .await?;
        let mut plan_value = plan_doc.clone();
        plan_value.as_object_mut().unwrap().remove("revision");
        let plan: forgeflow_evidence::VerificationPlan = decode(plan_value)?;
        if plan.task_revision != a.task_revision || plan.input_hash != task.input_digest {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "artifact verification plan must bind original task inputs",
            ));
        }
        let expected = forgeflow_evidence::ArtifactBinding {
            task_revision: a.task_revision,
            attempt_id: a.attempt_id.clone(),
            generation: a.generation,
            verification_plan_id: plan.plan_id.clone(),
            verification_plan_hash: plan.digest(),
            contract_version: plan.contract_version.clone(),
            input_hash: task.input_digest.clone(),
            context_hash: envelope.context_manifest.sha256.clone(),
            prompt_hash: envelope.prompt_artifact.sha256.clone(),
            artifact_hash: r.artifact.sha256.clone(),
        };
        let expected_commands: Vec<String> = plan
            .commands
            .iter()
            .flat_map(|c| {
                std::iter::once(c.program.to_string_lossy().into_owned()).chain(c.args.clone())
            })
            .collect();
        if verification.command != expected_commands {
            return Err(err(
                "VERIFIER_INVALID",
                "receipt executed argv differs from registered plan",
            ));
        }
        verification
            .validate(&expected, true)
            .map_err(|e| err("VERIFIER_INVALID", e.to_string()))?;
        if r.input_digest != task.input_digest
            || r.generation != a.generation
            || r.verifier_id != plan.verifier_id
            || r.author_id != plan.author_id
            || verification.verifier_id != plan.verifier_id
            || verification.author_id != plan.author_id
            || verification.environment_profile != plan.environment_profile
            || verification.oracle_id != plan.oracle_id
            || r.total != verification.total
            || r.failed != verification.failed
            || r.skipped != verification.skipped
        {
            return Err(err(
                "VERIFIER_INVALID",
                "artifact receipt differs from registered independent plan",
            ));
        }
        let descriptor = self
            .get_document(&r.project_id, "artifacts", &r.artifact.artifact_id)
            .await?;
        let path = descriptor
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "artifact path missing"))?;
        let path =
            std::fs::canonicalize(path).map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        let root = std::fs::canonicalize(&envelope.artifact_prefix)
            .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        if !path.starts_with(&root) {
            return Err(err(
                "OWNER_PATH_VIOLATION",
                "read-only artifact escapes frozen artifact root",
            ));
        }
        verification
            .validate_artifact(&path)
            .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        verification
            .validate_log(
                path.parent()
                    .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "artifact output parent missing"))?,
            )
            .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?;
        let disk: Value = serde_json::from_slice(
            &std::fs::read(path.parent().unwrap().join("verification-receipt.json"))
                .map_err(|e| err("EVIDENCE_INCOMPLETE", e.to_string()))?,
        )?;
        if disk != r.details {
            return Err(err(
                "VERIFIER_INVALID",
                "artifact receipt counts differ from trusted runner's durable output",
            ));
        }
        let expected_total: u64 = plan
            .commands
            .iter()
            .map(|c| c.expected_cases.len() as u64)
            .sum();
        if verification.total != expected_total {
            return Err(err(
                "VERIFIER_INVALID",
                "artifact denominator differs from registered exact case set",
            ));
        }
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        let current = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        valid_lease(&mut tx, &current, r.generation, &current.worker_id).await?;
        let current_plan:Value=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='verification_plans' AND document_id=$2 FOR UPDATE").bind(&r.project_id).bind(&envelope.verification_plan_id).fetch_one(&mut *tx).await?;
        if current_plan != plan_doc {
            return Err(err(
                "CONTEXT_STALE",
                "registered artifact verification plan changed",
            ));
        }
        let old: Option<Value> =
            sqlx::query_scalar("SELECT data FROM evidence_receipts WHERE receipt_id=$1")
                .bind(&r.receipt_id)
                .fetch_optional(&mut *tx)
                .await?;
        let value = json(&r)?;
        if let Some(old) = old {
            if old != value {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "artifact receipt identity immutable",
                ));
            }
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("INSERT INTO evidence_receipts VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&r.project_id)
            .bind(&r.receipt_id)
            .bind(&r.attempt_id)
            .bind(r.generation)
            .bind(&r.kind)
            .bind(&value)
            .bind(r.created_at)
            .execute(&mut *tx)
            .await?;
        event(
            &mut tx,
            &r.project_id,
            &r.receipt_id,
            1,
            "evidence.artifact_verified",
            value,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

pub(crate) async fn complete_read_only_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    id: &str,
    generation: i64,
    worker: &str,
    receipt_id: &str,
) -> Result<Attempt> {
    project_lock(tx, p).await?;
    let mut a = attempt_lock(tx, p, id).await?;
    valid_lease(tx, &a, generation, worker).await?;
    let retained: Option<Value> = sqlx::query_scalar("SELECT execution_bindings->'retained_native_candidate' FROM attempts WHERE project_id=$1 AND attempt_id=$2")
        .bind(p).bind(id).fetch_one(&mut **tx).await?;
    if retained.as_ref().is_some_and(|value| !value.is_null()) {
        return Err(err(
            "RETAINED_CANDIDATE_AUTHORITY_REQUIRED",
            "retained candidate acceptance cannot finish as artifact-only read-only work",
        ));
    }
    let e: ExecutionEnvelope = decode(
        sqlx::query_scalar("SELECT envelope FROM attempts WHERE attempt_id=$1")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    if !matches!(
        e.session_purpose,
        SessionPurpose::Planning | SessionPurpose::Review
    ) || !e.write_set.is_empty()
        || a.state != AttemptState::ReviewReady
    {
        return Err(err(
            "ILLEGAL_TRANSITION",
            "read-only completion requires reviewed planning/review artifact",
        ));
    }
    let evidence:EvidenceReceipt=decode(sqlx::query_scalar("SELECT data FROM evidence_receipts WHERE project_id=$1 AND receipt_id=$2 AND attempt_id=$3 AND generation=$4").bind(p).bind(receipt_id).bind(id).bind(generation).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","bound artifact verification missing"))?)?;
    if evidence.failed != 0 || evidence.skipped != 0 || evidence.kind != "STRUCTURED_ARTIFACT" {
        return Err(err(
            "EVIDENCE_INCOMPLETE",
            "read-only artifact verification not passing",
        ));
    }
    crate::handoff::strict_release_guard(tx, &a).await?;
    a.state = AttemptState::Succeeded;
    a.revision += 1;
    a.terminal_at = Some(db_now(tx).await?);
    a.result = Some(json(&evidence)?);
    revoke(tx, &a).await?;
    release(tx, &a, "read-only artifact accepted").await?;
    persist_attempt(tx, &a).await?;
    event(tx, p, id, a.revision, "attempt.succeeded", json(&a)?).await?;
    Ok(a)
}

pub(crate) async fn finalize_merge_tx(
    tx: &mut Transaction<'_, Postgres>,
    p: &str,
    id: &str,
) -> Result<MergeIntent> {
    project_lock(tx, p).await?;
    let mut intent = lock_intent(tx, p, id).await?;
    if matches!(
        intent.state,
        MergeIntentState::Finalized | MergeIntentState::Committed
    ) {
        return Ok(intent);
    }
    if intent.state != MergeIntentState::RefUpdated || intent.integrated_sha.is_none() {
        return Err(err(
            "ILLEGAL_TRANSITION",
            "finalization requires durable REF_UPDATED proof",
        ));
    }
    let mut a = attempt_lock(tx, p, &intent.attempt_id).await?;
    if a.generation != intent.generation
        || !matches!(
            a.state,
            AttemptState::Merging | AttemptState::RecoveryRequired
        )
    {
        return Err(err("LEASE_STALE", "finalization attempt identity mismatch"));
    }
    let retained = git_evidence_authority_tx(tx, &a).await?;
    if let Some(binding) = &retained {
        let plan = retained_plan_tx(tx, &a).await?;
        validate_retained_merge(binding, &plan, &a, &intent)?;
        super::collaboration::require_verifier_roots_settled(tx, &a).await?;
    }
    crate::handoff::strict_release_guard(tx, &a).await?;
    intent.state = MergeIntentState::Finalized;
    intent.revision += 1;
    if let Some(binding) = &retained {
        // Credit is committed with the final Git intent. The original cancelled
        // author, its model rows and the auxiliary task's product denominator stay unchanged.
        crate::catalog::finalize_retained_candidate_acceptance_tx(tx, &a, &intent, binding).await?;
    }
    save_intent(tx, &intent).await?;
    a.state = AttemptState::Succeeded;
    a.revision += 1;
    a.terminal_at = Some(db_now(tx).await?);
    a.result = Some(json(&intent)?);
    revoke(tx, &a).await?;
    release(tx, &a, "integration finalized").await?;
    persist_attempt(tx, &a).await?;
    event(
        tx,
        p,
        id,
        intent.revision,
        "merge.finalized",
        json(&intent)?,
    )
    .await?;
    event(
        tx,
        p,
        &a.attempt_id,
        a.revision,
        "attempt.succeeded",
        json(&a)?,
    )
    .await?;
    Ok(intent)
}
