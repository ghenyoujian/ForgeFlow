//! Milestone judgments reuse persisted independent verification and integration
//! authority. Planning dates and caller-supplied success flags grant no acceptance.
use super::*;
use forgeflow_evidence::{VerificationPlan, VerificationReceipt};
use std::collections::BTreeSet;

fn identities(values: &[String], label: &str, required: bool) -> Result<()> {
    let unique: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    if (required && values.is_empty())
        || unique.len() != values.len()
        || values
            .iter()
            .any(|value| value.trim().is_empty() || value != value.trim())
    {
        return Err(err(
            "VALIDATION_ERROR",
            format!("{label} must contain distinct nonempty identities"),
        ));
    }
    Ok(())
}

fn without_revision(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("revision");
    }
    value
}

fn verify_receipt(
    verification: &VerificationReceipt,
    task: &TaskCard,
    attempt: &Attempt,
    plan: &VerificationPlan,
    candidate_sha: &str,
    integrated_sha: Option<&str>,
) -> Result<()> {
    let mut expected = verification.binding.clone();
    expected.task_revision = task.task_revision;
    expected.attempt_id = attempt.attempt_id.clone();
    expected.generation = attempt.generation;
    expected.base_sha = attempt.base_sha.clone();
    expected.candidate_sha = candidate_sha.into();
    expected.integrated_sha = integrated_sha.map(str::to_owned);
    expected.contract_version = plan.contract_version.clone();
    expected.verification_plan_id = plan.plan_id.clone();
    expected.verification_plan_hash = plan.digest();
    expected.input_hash = task.input_digest.clone();
    verification
        .validate(&expected, true)
        .map_err(|error| err("VERIFIER_INVALID", error.to_string()))?;
    let total = plan
        .commands
        .iter()
        .try_fold(0_u64, |total, command| {
            total.checked_add(command.expected_cases.len() as u64)
        })
        .ok_or_else(|| {
            err(
                "VERIFIER_INVALID",
                "registered verification denominator overflow",
            )
        })?;
    let command: Vec<String> = plan
        .commands
        .iter()
        .flat_map(|command| {
            std::iter::once(command.program.to_string_lossy().into_owned())
                .chain(command.args.clone())
        })
        .collect();
    if verification.skipped != 0
        || verification.total != total
        || verification.command != command
        || verification.environment_profile != plan.environment_profile
        || verification.oracle_id != plan.oracle_id
        || verification.verifier_id != plan.verifier_id
        || verification.author_id != plan.author_id
        || !valid_sha(&verification.binding.source_hash)
    {
        return Err(err(
            "VERIFIER_INVALID",
            "milestone evidence differs from the current independent verification plan",
        ));
    }
    Ok(())
}

pub(crate) async fn accept_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    project_id: &str,
    milestone_id: &str,
    expected_revision: u64,
    baseline_version: u64,
    actor: &str,
) -> Result<Value> {
    let project = project_lock(tx, project_id).await?;
    if project.authority_mode != AuthorityMode::Managed || project.archived {
        return Err(err(
            "AUTHORITY_SCOPE_VIOLATION",
            "milestone acceptance requires an active managed project",
        ));
    }
    let row = sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='milestones' AND document_id=$2 FOR UPDATE")
        .bind(project_id).bind(milestone_id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("NOT_FOUND", "milestone not found"))?;
    let revision: i64 = row.try_get("revision")?;
    let milestone: Milestone = decode(row.try_get("data")?)?;
    if revision != i64v(expected_revision)? || milestone.revision != expected_revision {
        return Err(err(
            "REVISION_CONFLICT",
            "milestone revision changed before acceptance",
        ));
    }
    if milestone.project_id != project_id
        || milestone.milestone_id != milestone_id
        || baseline_version == 0
        || milestone.baseline_version != baseline_version
    {
        return Err(err(
            "CONTEXT_STALE",
            "milestone acceptance must bind its exact current baseline",
        ));
    }
    identities(
        &milestone.required_work_packages,
        "required task/work-unit IDs",
        true,
    )?;
    identities(
        &milestone.required_gate_ids,
        "required independent verification-plan IDs",
        true,
    )?;
    identities(
        &milestone.requirement_ids,
        "required requirement IDs",
        false,
    )?;

    let document_id = format!("{milestone_id}:{baseline_version}");
    let old: Option<Value> = sqlx::query_scalar(
        "SELECT data FROM documents WHERE project_id=$1 AND collection='milestone_acceptances' AND document_id=$2 FOR UPDATE",
    ).bind(project_id).bind(&document_id).fetch_optional(&mut **tx).await?;
    let judgment: Result<Value> = async {

    let mut requirement_refs = Vec::new();
    for requirement_id in &milestone.requirement_ids {
        let requirement: Requirement = decode(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM requirements WHERE project_id=$1 AND requirement_id=$2 FOR SHARE",
        ).bind(project_id).bind(requirement_id).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("REQUIREMENT_COVERAGE_STALE", "milestone requirement is not registered in this project"))?)?;
        if requirement.project_id != project_id || requirement.requirement_id != *requirement_id
            || requirement.deferred_reason.is_some()
        {
            return Err(err("REQUIREMENT_COVERAGE_STALE", "milestone requirement is deferred or has a different authority identity"));
        }
        requirement_refs.push(serde_json::json!({
            "requirement_id":requirement_id,"revision":requirement.revision,
            "semantic_sha256":forgeflow_planner::requirement_semantic_digest(&requirement),
        }));
    }

    let mut task_refs = Vec::new();
    let mut evidence_refs = Vec::new();
    let mut covered_requirements = BTreeSet::new();
    let mut covered_plans = BTreeSet::new();
    for task_id in &milestone.required_work_packages {
        let task: TaskCard = decode(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM tasks WHERE project_id=$1 AND task_id=$2 FOR SHARE",
        ).bind(project_id).bind(task_id).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "required work-unit identity must reference an existing current task_id"))?)?;
        if task.project_id != project_id || task.task_id != *task_id
            || matches!(task.state, TaskPlanningState::RemovedFromPlan | TaskPlanningState::NeedsReview)
        {
            return Err(err("CONTEXT_STALE", "required task is removed, needs review, or has another identity"));
        }
        let attempt: Attempt = decode(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM attempts WHERE project_id=$1 AND task_id=$2 AND task_revision=$3 AND state='SUCCEEDED' ORDER BY generation DESC,attempt_id LIMIT 1 FOR SHARE",
        ).bind(project_id).bind(task_id).bind(i64v(task.task_revision)?).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "required current task has no verified integrated successful attempt"))?)?;
        if attempt.project_id != project_id || attempt.task_id != *task_id
            || attempt.task_revision != task.task_revision || attempt.state != AttemptState::Succeeded
            || attempt.generation <= 0 || attempt.terminal_at.is_none()
        {
            return Err(err("CONTEXT_STALE", "successful attempt does not bind the current task revision"));
        }
        let envelope: ExecutionEnvelope = decode(sqlx::query_scalar::<_, Value>(
            "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
        ).bind(project_id).bind(&attempt.attempt_id).fetch_one(&mut **tx).await?)?;
        let frozen_task: TaskCard = decode(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3 FOR SHARE",
        ).bind(project_id).bind(task_id).bind(i64v(attempt.task_revision)?).fetch_one(&mut **tx).await?)?;
        if frozen_task.input_digest != task.input_digest || frozen_task.requirement_ids != task.requirement_ids
            || envelope.project_id != project_id || envelope.task_id != *task_id
            || envelope.task_revision != task.task_revision || envelope.attempt_id != attempt.attempt_id
            || envelope.generation != attempt.generation
        {
            return Err(err("CONTEXT_STALE", "current task inputs or frozen execution identity differ from the verified attempt"));
        }
        let context: forgeflow_planner::CompileContext = decode(without_revision(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2 FOR SHARE",
        ).bind(project_id).bind(frozen_task.flow_revision.to_string()).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "verified task's frozen requirement context is missing"))?))?;
        let spec = context.task_specs.get(task_id)
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "verified task's frozen specification is missing"))?;
        if spec.requirement_digest_refs.len() != task.requirement_ids.len() {
            return Err(err("REQUIREMENT_COVERAGE_STALE", "frozen task requirement digest denominator differs from its current scope"));
        }
        for requirement_id in &task.requirement_ids {
            let requirement: Requirement = decode(sqlx::query_scalar::<_, Value>(
                "SELECT data FROM requirements WHERE project_id=$1 AND requirement_id=$2 FOR SHARE",
            ).bind(project_id).bind(requirement_id).fetch_optional(&mut **tx).await?
                .ok_or_else(|| err("REQUIREMENT_COVERAGE_STALE", "verified task's required authority requirement is missing"))?)?;
            let digest = forgeflow_planner::requirement_semantic_digest(&requirement);
            if spec.requirement_digest_refs.get(requirement_id) != Some(&digest)
                || context.requirement_semantic_digests.get(requirement_id) != Some(&digest)
                || requirement.deferred_reason.is_some()
            {
                return Err(err("REQUIREMENT_COVERAGE_STALE", "requirement outcome or scope changed after the independently verified task was approved"));
            }
        }
        if task.envelope.as_ref().is_none_or(|current| current.verification_plan_id != envelope.verification_plan_id) {
            return Err(err("CONTEXT_STALE", "successful attempt verification plan differs from the current task"));
        }
        let plan: VerificationPlan = decode(without_revision(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM documents WHERE project_id=$1 AND collection='verification_plans' AND document_id=$2 FOR SHARE",
        ).bind(project_id).bind(&envelope.verification_plan_id).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "registered independent verification plan is missing"))?))?;
        if plan.plan_id != envelope.verification_plan_id || plan.task_revision != task.task_revision
            || plan.input_hash != task.input_digest || plan.commands.is_empty()
        {
            return Err(err("CONTEXT_STALE", "verification plan binds an obsolete task revision or input digest"));
        }
        let integration: MergeIntent = decode(sqlx::query_scalar::<_, Value>(
            "SELECT data FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 AND state='FINALIZED' ORDER BY intent_id LIMIT 1 FOR SHARE",
        ).bind(project_id).bind(&attempt.attempt_id).bind(attempt.generation).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "required task lacks finalized verified main integration"))?)?;
        let integrated_sha = integration.integrated_sha.as_deref()
            .filter(|sha| valid_sha(sha)).ok_or_else(|| err("EVIDENCE_INCOMPLETE", "finalized integration commit identity is missing"))?;
        if integration.project_id != project_id || integration.attempt_id != attempt.attempt_id
            || integration.generation != attempt.generation || integration.state != MergeIntentState::Finalized
            || integration.target_ref != "refs/heads/main" || !valid_sha(&integration.candidate_sha)
        {
            return Err(err("EVIDENCE_BINDING_MISMATCH", "integration identity must bind the successful task and authoritative main ref"));
        }
        let integrated_receipt = integration.receipt.as_ref()
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "finalized integration verification receipt is missing"))?;
        let integrated: VerificationReceipt = decode(integrated_receipt.get("verification").cloned()
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "latest-main integration lacks independent verification"))?)?;
        verify_receipt(&integrated, &task, &attempt, &plan, &integration.candidate_sha, Some(integrated_sha))?;
        if integrated_receipt.get("verification_receipt_hash").and_then(Value::as_str) != Some(integrated.digest().as_str()) {
            return Err(err("EVIDENCE_BINDING_MISMATCH", "integrated verification receipt hash differs from its immutable contents"));
        }

        let candidate_rows: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM evidence_receipts WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 ORDER BY receipt_id FOR SHARE",
        ).bind(project_id).bind(&attempt.attempt_id).bind(attempt.generation).fetch_all(&mut **tx).await?;
        let mut candidate = None;
        for row in candidate_rows {
            let receipt: EvidenceReceipt = decode(row)?;
            if receipt.kind == "STRUCTURED_ARTIFACT"
                || receipt.candidate_sha.as_deref() != Some(&integration.candidate_sha)
                || receipt.integrated_sha.is_some()
            {
                continue;
            }
            let verification: VerificationReceipt = decode(receipt.details.clone())?;
            verify_receipt(&verification, &task, &attempt, &plan, &integration.candidate_sha, None)?;
            if receipt.project_id != project_id || receipt.attempt_id != attempt.attempt_id
                || receipt.generation != attempt.generation || receipt.input_digest != task.input_digest
                || receipt.total != verification.total || receipt.failed != 0 || receipt.skipped != 0
                || receipt.verifier_id != verification.verifier_id || receipt.author_id != verification.author_id
                || receipt.artifact.sha256 != verification.log_hash || !valid_digest(&receipt.artifact.sha256)
                || receipt.receipt_id.trim().is_empty()
            {
                return Err(err("EVIDENCE_BINDING_MISMATCH", "candidate evidence identity, artifact or denominator is stale"));
            }
            candidate = Some(receipt);
            break;
        }
        let candidate = candidate.ok_or_else(|| err("EVIDENCE_INCOMPLETE", "required task lacks bound independent candidate evidence"))?;
        let artifact: Value = sqlx::query_scalar(
            "SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE",
        ).bind(project_id).bind(&candidate.artifact.artifact_id).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "candidate raw artifact is no longer registered"))?;
        // Independent verification registers {path, sha256} under an
        // authoritative documents.document_id. PutArtifact additionally stores
        // the ID inside its descriptor; validate it when present, not as a
        // mandatory field that the verifier's production schema does not have.
        if artifact.get("artifact_id").is_some_and(|id| id.as_str() != Some(&candidate.artifact.artifact_id))
            || artifact.get("sha256").and_then(Value::as_str) != Some(&candidate.artifact.sha256)
            || artifact.get("path").and_then(Value::as_str).is_none_or(|path| !std::path::Path::new(path).is_absolute())
        {
            return Err(err("EVIDENCE_BINDING_MISMATCH", "candidate raw artifact descriptor differs from the verified receipt"));
        }
        covered_requirements.extend(task.requirement_ids.iter().cloned());
        covered_plans.insert(plan.plan_id.clone());
        task_refs.push(serde_json::json!({
            "task_id":task_id,"task_revision":task.task_revision,"input_digest":task.input_digest,
            "verification_plan_id":plan.plan_id,"verification_plan_hash":plan.digest(),
        }));
        evidence_refs.push(serde_json::json!({
            "task_id":task_id,"task_revision":task.task_revision,"attempt_id":attempt.attempt_id,"generation":attempt.generation,
            "candidate_receipt_id":candidate.receipt_id,"candidate_receipt_sha256":forgeflow_planner::sha256(&serde_json::to_vec(&candidate)?),
            "candidate_artifact":candidate.artifact,"verification_plan_id":plan.plan_id,"verification_plan_hash":plan.digest(),
            "integration_intent_id":integration.intent_id,"integration_revision":integration.revision,
            "integrated_sha":integrated_sha,"target_ref":integration.target_ref,
            "integrated_verification_sha256":integrated.digest(),"integrated_log_sha256":integrated.log_hash,
            "source_tree_oid":integrated.binding.source_hash,
            "source_content_sha256":integrated_receipt.get("source_content_sha256"),
        }));
    }
    if milestone.requirement_ids.iter().any(|id| !covered_requirements.contains(id)) {
        return Err(err("REQUIREMENT_COVERAGE_STALE", "milestone requirements are not covered by its required current tasks"));
    }
    if milestone.required_gate_ids.iter().any(|id| !covered_plans.contains(id)) {
        return Err(err("EVIDENCE_INCOMPLETE", "required Gate identity must be a verified independent verification_plan_id bound to a required current task"));
    }
    let conditions = serde_json::json!({
        "requirement_ids":milestone.requirement_ids,"required_work_packages":milestone.required_work_packages,
        "required_gate_ids":milestone.required_gate_ids,"requirement_refs":requirement_refs,"task_refs":task_refs,
    });
    if let Some(old) = old.as_ref() {
        if old["milestone_revision"] != expected_revision || old["baseline_version"] != baseline_version
            || old["conditions"] != conditions || old["evidence_refs"] != serde_json::json!(evidence_refs)
        {
            return Err(err("ACCEPTANCE_STALE", "the original judgment is immutable; create a new milestone baseline for changed requirements or evidence"));
        }
        return Ok(old.clone());
    }
    let accepted = serde_json::json!({
        "schema_version":"forgeflow.milestone-acceptance.v1","project_id":project_id,"milestone_id":milestone_id,
        "baseline_version":baseline_version,"milestone_revision":expected_revision,"status":"ACCEPTED",
        "accepted_at":db_now(tx).await?,"accepted_by":actor,"conditions":conditions,"evidence_refs":evidence_refs,"revision":1,
    });
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'milestone_acceptances',$2,1,$3)")
        .bind(project_id).bind(&document_id).bind(&accepted).execute(&mut **tx).await?;
    event(tx, project_id, &document_id, 1, "document.updated", serde_json::json!({"collection":"milestone_acceptances","document":accepted})).await?;
    Ok(accepted)
    }.await;
    match judgment {
        Err(StoreError::Domain(error)) if old.is_some() => Err(err(
            "ACCEPTANCE_STALE",
            format!(
                "the original judgment is immutable; create a new milestone baseline; current conditions: {error}",
            ),
        )),
        result => result,
    }
}
