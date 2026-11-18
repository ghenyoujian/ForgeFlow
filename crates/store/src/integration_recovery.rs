//! Typed authorization and settlement of a retained irreversible Git intent.
use super::*;

impl Store {
    pub async fn authorize_integration_recovery(
        &self,
        identity: CommandIdentity,
        project: &str,
        attempt: &str,
        intent_id: &str,
        expected: u64,
        reason: &str,
        operation_id: &str,
    ) -> Result<CommandResult> {
        if !matches!(identity.actor_id.as_str(), "owner" | "owner-service") {
            return Err(err(
                "AUTHORITY_SCOPE_VIOLATION",
                "integration recovery requires Owner authorization",
            ));
        }
        if reason.trim().is_empty()
            || reason.len() > 2000
            || expected == 0
            || uuid::Uuid::parse_str(attempt).is_err()
            || uuid::Uuid::parse_str(intent_id).is_err()
            || operation_id.len() != 32
            || !operation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(err(
                "VALIDATION_ERROR",
                "invalid recovery identity, revision or reason",
            ));
        }
        let request = serde_json::json!({"project_id":project,"attempt_id":attempt,"intent_id":intent_id,"expected_intent_revision":expected,"reason":reason,"operation_id":operation_id});
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        if let Some(response) = replay(
            &mut tx,
            &identity.actor_id,
            "authorize_integration_recovery",
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            let mut result: CommandResult = decode(response)?;
            result.replayed = true;
            tx.commit().await?;
            return Ok(result);
        }
        project_lock(&mut tx, project).await?;
        let p: Project = decode(
            sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1 FOR UPDATE")
                .bind(project)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "recovery project missing"))?,
        )?;
        if p.authority_mode != AuthorityMode::Managed {
            return Err(err(
                "AUTHORITY_SCOPE_VIOLATION",
                "recovery requires the registered managed repository",
            ));
        }
        let mut intent: MergeIntent = decode(
            sqlx::query_scalar(
                "SELECT data FROM merge_intents WHERE project_id=$1 AND intent_id=$2 FOR UPDATE",
            )
            .bind(project)
            .bind(intent_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "recovery intent missing"))?,
        )?;
        if intent.revision != expected {
            return Err(err(
                "REVISION_CONFLICT",
                "integration intent changed since Owner review",
            ));
        }
        let a = attempt_lock(&mut tx, project, attempt).await?;
        if intent.project_id != project
            || intent.attempt_id != attempt
            || intent.generation != a.generation
            || !matches!(
                a.state,
                AttemptState::Merging | AttemptState::RecoveryRequired
            )
            || !matches!(
                intent.state,
                MergeIntentState::CommitDecided
                    | MergeIntentState::RefUpdated
                    | MergeIntentState::RecoveryRequired
            )
            || intent.integrated_sha.is_none()
            || intent
                .receipt
                .as_ref()
                .and_then(|value| value.get("commit_decided"))
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(err(
                "RECOVERY_SCOPE_CONFLICT",
                "recovery requires this attempt's irreversible durable commit decision",
            ));
        }
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='INTEGRATION_RECOVERY' AND data->>'intent_id'=$2 AND data->>'status'='ACCEPTED')")
            .bind(project).bind(intent_id).fetch_one(&mut *tx).await?;
        if pending {
            return Err(err(
                "RECOVERY_CONFLICT",
                "an accepted recovery already owns this intent; replay its original authorization",
            ));
        }
        let before = intent.clone();
        intent.revision = intent
            .revision
            .checked_add(1)
            .ok_or_else(|| err("VALIDATION_ERROR", "intent revision overflow"))?;
        // A real CAS consumes the reviewed revision; state and original receipt
        // remain byte-equivalent JSON. No ref, attempt, lease or allocation moves.
        sqlx::query(
            "UPDATE merge_intents SET revision=$3,data=$4 WHERE project_id=$1 AND intent_id=$2",
        )
        .bind(project)
        .bind(intent_id)
        .bind(i64v(intent.revision)?)
        .bind(json(&intent)?)
        .execute(&mut *tx)
        .await?;
        let value = serde_json::json!({"operation_id":operation_id,"kind":"INTEGRATION_RECOVERY","project_id":project,"attempt_id":attempt,"intent_id":intent_id,"status":"ACCEPTED","actor_id":identity.actor_id,"authorization_identity":identity,"request":request,"intent_before":before,"authorized_intent_revision":intent.revision,"accepted_at":db_now(&mut tx).await?});
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'operations',$2,1,$3)")
            .bind(project).bind(operation_id).bind(&value).execute(&mut *tx).await?;
        event(&mut tx, project, intent_id, intent.revision, "merge.recovery_authorized", serde_json::json!({"operation_id":operation_id,"actor_id":identity.actor_id,"reason":reason,"before_revision":expected,"authorized_revision":intent.revision})).await?;
        let result = CommandResult {
            operation_id: operation_id.into(),
            value,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &identity.actor_id,
            "authorize_integration_recovery",
            &identity.idempotency_key,
            operation_id,
            &request,
            &json(&result)?,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    /// The API recovery service submits only outcome fields. Original reviewed
    /// identities, authorization, request, and intent evidence cannot be replaced.
    pub async fn settle_integration_recovery(
        &self,
        identity: CommandIdentity,
        project: &str,
        operation: &str,
        expected_revision: u64,
        outcome: Value,
    ) -> Result<CommandResult> {
        if identity.actor_id != "recovery-service" {
            return Err(err(
                "AUTHORITY_SCOPE_VIOLATION",
                "only the recovery service may settle recovery",
            ));
        }
        let status = outcome.get("status").and_then(Value::as_str).unwrap_or("");
        let object = outcome
            .as_object()
            .ok_or_else(|| err("VALIDATION_ERROR", "recovery outcome must be an object"))?;
        if !matches!(status, "SUCCEEDED" | "RECOVERY_REQUIRED")
            || object.len() != 2
            || (status == "SUCCEEDED" && !object.contains_key("result"))
            || (status == "RECOVERY_REQUIRED" && !object.contains_key("error"))
        {
            return Err(err(
                "VALIDATION_ERROR",
                "recovery settlement may supply only status and result or error",
            ));
        }
        let request = serde_json::json!({"project_id":project,"operation_id":operation,"expected_revision":expected_revision,"outcome":outcome});
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        if let Some(response) = replay(
            &mut tx,
            &identity.actor_id,
            "settle_integration_recovery",
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            let mut result: CommandResult = decode(response)?;
            result.replayed = true;
            tx.commit().await?;
            return Ok(result);
        }
        project_lock(&mut tx, project).await?;
        let row = sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='operations' AND document_id=$2 FOR UPDATE")
            .bind(project).bind(operation).fetch_optional(&mut *tx).await?.ok_or_else(|| err("NOT_FOUND", "recovery operation missing"))?;
        let revision = row.get::<i64, _>("revision") as u64;
        let mut value: Value = row.try_get("data")?;
        if revision != expected_revision
            || value.get("status").and_then(Value::as_str) != Some("ACCEPTED")
        {
            return Err(err(
                "REVISION_CONFLICT",
                "recovery operation already settled or changed",
            ));
        }
        if value.get("kind").and_then(Value::as_str) != Some("INTEGRATION_RECOVERY")
            || value.get("project_id").and_then(Value::as_str) != Some(project)
            || value.get("operation_id").and_then(Value::as_str) != Some(operation)
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "operation is not this typed recovery authorization",
            ));
        }
        let before: MergeIntent =
            decode(value.get("intent_before").cloned().ok_or_else(|| {
                err(
                    "EVIDENCE_BINDING_MISMATCH",
                    "recovery authorization lacks original intent",
                )
            })?)?;
        let current: MergeIntent = decode(
            sqlx::query_scalar(
                "SELECT data FROM merge_intents WHERE project_id=$1 AND intent_id=$2 FOR UPDATE",
            )
            .bind(project)
            .bind(&before.intent_id)
            .fetch_one(&mut *tx)
            .await?,
        )?;
        if current.project_id != before.project_id
            || current.attempt_id != before.attempt_id
            || current.generation != before.generation
            || current.target_ref != before.target_ref
            || current.expected_sha != before.expected_sha
            || current.candidate_sha != before.candidate_sha
            || current.integrated_sha != before.integrated_sha
        {
            return Err(err(
                "EVIDENCE_BINDING_MISMATCH",
                "settlement changes frozen integration identity",
            ));
        }
        for key in [
            "new_sha",
            "verification",
            "verification_receipt_hash",
            "artifact_root",
        ] {
            if current
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.get(key))
                != before.receipt.as_ref().and_then(|receipt| receipt.get(key))
            {
                return Err(err(
                    "EVIDENCE_BINDING_MISMATCH",
                    "settlement changes original Git evidence",
                ));
            }
        }
        if status == "SUCCEEDED" {
            let a = attempt_lock(&mut tx, project, &before.attempt_id).await?;
            if current.state != MergeIntentState::Finalized
                || a.state != AttemptState::Succeeded
                || a.generation != before.generation
                || outcome["result"]["integration"] != json(&current)?
            {
                return Err(err(
                    "EVIDENCE_INCOMPLETE",
                    "success requires the actual finalized intent and succeeded attempt",
                ));
            }
            let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_allocations WHERE project_id=$1 AND attempt_id=$2 AND state!='RELEASED')")
                .bind(project).bind(&before.attempt_id).fetch_one(&mut *tx).await?;
            if occupied {
                return Err(err(
                    "EVIDENCE_INCOMPLETE",
                    "successful recovery still has retained allocation",
                ));
            }
            value["result"] = outcome["result"].clone();
        } else {
            let error: DomainError = decode(outcome["error"].clone())?;
            value["error"] = json(&error)?;
        }
        value["status"] = json(&status)?;
        value["settled_at"] = json(&db_now(&mut tx).await?)?;
        let next = revision
            .checked_add(1)
            .ok_or_else(|| err("VALIDATION_ERROR", "operation revision overflow"))?;
        sqlx::query("UPDATE documents SET revision=$3,data=$4 WHERE project_id=$1 AND collection='operations' AND document_id=$2")
            .bind(project).bind(operation).bind(i64v(next)?).bind(&value).execute(&mut *tx).await?;
        event(
            &mut tx,
            project,
            operation,
            next,
            "merge.recovery_settled",
            value.clone(),
        )
        .await?;
        let result = CommandResult {
            operation_id: operation.into(),
            value,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &identity.actor_id,
            "settle_integration_recovery",
            &identity.idempotency_key,
            &id(),
            &request,
            &json(&result)?,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
}
