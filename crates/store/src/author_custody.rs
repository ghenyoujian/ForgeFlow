//! Author termination and unresolved provider custody are separate facts.
//! Physical recovery is separate from author closure and never settles providers.
use crate::*;
use serde_json::json;

const OBSERVATION_KIND: &str = "AUTHOR_STOP_OBSERVED";
const COMMAND: &str = "close_author_retain_custody";

async fn validate_stop(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    r: &WorkerResult,
) -> Result<()> {
    if r.project_id != a.project_id
        || r.attempt_id != a.attempt_id
        || r.worker_id != a.worker_id
        || r.generation != a.generation
        || r.lease_id != a.lease_id
        || r.evidence["process_exit_confirmed"] != true
        || r.evidence["stop"]["process_exit_confirmed"] != true
        || r.outcome.execution_id.is_empty()
    {
        return Err(err(
            "PROCESS_EXIT_UNCONFIRMED",
            "exact assigned Worker and stopped author identity required",
        ));
    }
    if !crate::collaboration::validate_physical_stop(
        tx,
        a,
        &r.evidence,
        Some(&r.outcome.execution_id),
    )
    .await?
    {
        return Err(err(
            "PROCESS_EXIT_UNCONFIRMED",
            "custody retention requires the complete frozen physical pool stop",
        ));
    }
    Ok(())
}

async fn observation(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    event_id: &str,
) -> Result<WorkerResult> {
    let payload: Option<Value> = sqlx::query_scalar("SELECT payload FROM worker_event_ids WHERE event_id=$1 AND project_id=$2 AND attempt_id=$3")
        .bind(event_id).bind(&a.project_id).bind(&a.attempt_id).fetch_optional(&mut **tx).await?;
    let payload = payload.ok_or_else(|| {
        err(
            "AUTHOR_STOP_OBSERVATION_MISSING",
            "trusted Worker stop observation has not been recorded",
        )
    })?;
    if payload["kind"] != OBSERVATION_KIND || payload["source"] != "SCOPED_WORKER" {
        return Err(err(
            "AUTHOR_STOP_OBSERVATION_MISSING",
            "observation is not a scoped Worker physical stop",
        ));
    }
    let r: WorkerResult = decode(payload["worker_result"].clone())?;
    if payload["worker_result_sha256"] != forgeflow_evidence::sha256(&serde_json::to_vec(&r)?) {
        return Err(err(
            "PROCESS_EXIT_UNCONFIRMED",
            "trusted stop observation digest changed",
        ));
    }
    validate_stop(tx, a, &r).await?;
    Ok(r)
}

async fn close_preconditions(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    event_id: &str,
) -> Result<()> {
    if !matches!(
        a.state,
        AttemptState::Stopping | AttemptState::RecoveryRequired
    ) {
        return Err(err(
            "AUTHOR_CLOSE_STATE_INVALID",
            "only a stopped or quarantined cancellation can close its author",
        ));
    }
    stopped_custody_preconditions(tx, a, event_id).await
}

async fn stopped_custody_preconditions(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    event_id: &str,
) -> Result<()> {
    observation(tx, a, event_id).await?;
    let fenced: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM leases l JOIN tasks t ON t.project_id=l.project_id AND t.task_id=$2 WHERE l.attempt_id=$1 AND l.generation=$3 AND l.revoked_at IS NOT NULL AND t.fence_epoch>$3)")
        .bind(&a.attempt_id).bind(&a.task_id).bind(a.generation).fetch_one(&mut **tx).await?;
    if !fenced {
        return Err(err(
            "LEASE_STALE",
            "original write lease must be revoked and its task fence advanced",
        ));
    }
    let merge: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 AND state<>'ABORTED')")
        .bind(&a.project_id).bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if merge {
        return Err(err(
            "MERGE_EFFECT_UNCONFIRMED",
            "integration must be resolved through its own recovery authority",
        ));
    }
    crate::collaboration::require_verifier_roots_settled(tx, a).await?;
    // This command is not a workaround for a qualified strict channel handoff.
    crate::handoff::strict_release_guard(tx, a).await?;
    let unknown: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_model_requests WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED'))")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if !unknown {
        return Err(err(
            "NO_UNKNOWN_NATIVE_CUSTODY",
            "ordinary cancellation must use ordinary verified settlement",
        ));
    }
    Ok(())
}

async fn physical_recovery_preconditions(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    event_id: &str,
) -> Result<()> {
    if a.state != AttemptState::Cancelled || a.terminal_at.is_none() {
        return Err(err(
            "AUTHOR_CLOSE_STATE_INVALID",
            "physical recovery requires an already closed author",
        ));
    }
    stopped_custody_preconditions(tx, a, event_id).await?;
    let closure: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='AUTHOR_CLOSED_CUSTODY_RETAINED' AND data->>'attempt_id'=$2 AND data->>'generation'=$3 AND data->>'observation_event_id'=$4 AND data->>'author_state'='CANCELLED' AND data->>'resources_released'='false' AND data->>'financial_custody_settled'='false')")
        .bind(&a.project_id).bind(&a.attempt_id).bind(a.generation.to_string()).bind(event_id).fetch_one(&mut **tx).await?;
    if !closure {
        return Err(err(
            "AUTHOR_CLOSURE_REQUIRED",
            "exact retained-custody author closure required before physical recovery",
        ));
    }
    let inflight: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_model_requests WHERE attempt_id=$1 AND status='ADMITTED')")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if inflight {
        return Err(err(
            "NATIVE_EFFECT_UNCONFIRMED",
            "admitted model transport must finish before local capacity recovery",
        ));
    }
    Ok(())
}

impl Store {
    pub async fn release_stopped_physical_resources(
        &self,
        identity: CommandIdentity,
        r: ReleaseStoppedPhysicalResourcesRequest,
    ) -> Result<CommandReceipt> {
        const RELEASE: &str = "release_stopped_physical_resources";
        if !matches!(identity.actor_id.as_str(), "owner" | "owner-service") {
            return Err(err(
                "OWNER_AUTHORIZATION_REQUIRED",
                "physical custody recovery requires Owner authorization",
            ));
        }
        if r.reason.trim().is_empty() || r.reason.len() > 2048 || r.observation_event_id.is_empty()
        {
            return Err(err(
                "VALIDATION_ERROR",
                "explicit bounded recovery reason and scoped stop observation required",
            ));
        }
        let request = json(&r)?;
        let _guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        if let Some(old) = replay(
            &mut tx,
            &identity.actor_id,
            RELEASE,
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            let mut receipt: CommandReceipt = decode(old)?;
            receipt.replayed = true;
            tx.commit().await?;
            return Ok(receipt);
        }
        let a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        if a.revision != r.expected_revision {
            return Err(err(
                "REVISION_CONFLICT",
                "author changed before physical resource recovery",
            ));
        }
        physical_recovery_preconditions(&mut tx, &a, &r.observation_event_id).await?;
        // Ledger rows are already separated by dimension. Use existing RELEASED
        // semantics only for proven local capacity; never edit provider rows,
        // native lifecycle custody, model requests, permits, usage or grants.
        let reason = "trusted_stopped_physical_custody";
        let mut rows = sqlx::query("UPDATE resource_allocations SET state='RELEASED',released_at=clock_timestamp(),release_reason=$2 WHERE attempt_id=$1 AND state<>'RELEASED' AND dimension IN('active_slot','coding_slot','cpu_units','memory_bytes','build_permit','gpu_permit') RETURNING allocation_id AS row_id,scope_id,dimension,amount")
            .bind(&a.attempt_id).bind(reason).fetch_all(&mut *tx).await?;
        rows.extend(sqlx::query("UPDATE native_child_allocations SET state='RELEASED',released_at=clock_timestamp(),release_reason=$2 WHERE attempt_id=$1 AND state<>'RELEASED' AND dimension IN('active_slot','coding_slot','cpu_units','memory_bytes','build_permit','gpu_permit') RETURNING resource_allocation_id AS row_id,scope_id,dimension,amount")
            .bind(&a.attempt_id).bind(reason).fetch_all(&mut *tx).await?);
        let mut released = Vec::new();
        for row in rows {
            let scope: String = row.get("scope_id");
            let dimension: String = row.get("dimension");
            let amount: i64 = row.get("amount");
            let changed = sqlx::query("UPDATE resource_limits SET allocated=allocated-$3 WHERE scope_id=$1 AND dimension=$2 AND allocated>=$3")
                .bind(&scope).bind(&dimension).bind(amount).execute(&mut *tx).await?.rows_affected();
            if changed != 1 {
                return Err(err(
                    "RESOURCE_LEDGER_CORRUPT",
                    "physical recovery exceeds actual charged capacity",
                ));
            }
            released.push(json!({"allocation_row_id":row.get::<String,_>("row_id"),"scope_id":scope,"dimension":dimension,"amount":amount}));
        }
        let operation_id = id();
        let value = json!({"kind":"STOPPED_PHYSICAL_RESOURCES_RECOVERED","operation_id":operation_id,
            "project_id":a.project_id,"attempt_id":a.attempt_id,"task_id":a.task_id,"generation":a.generation,
            "observation_event_id":r.observation_event_id,"reason":r.reason,"authorized_by":identity.actor_id,
            "released_physical_rows":released,"provider_reservations_released":false,
            "financial_custody_settled":false,"model_usage_changed":false,"author_state_changed":false});
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'operations',$2,1,$3)")
            .bind(&a.project_id).bind(&operation_id).bind(&value).execute(&mut *tx).await?;
        event(
            &mut tx,
            &a.project_id,
            &a.attempt_id,
            a.revision,
            "attempt.stopped_physical_resources_recovered",
            value,
        )
        .await?;
        let receipt = CommandReceipt {
            operation_id,
            status: "STOPPED_PHYSICAL_RESOURCES_RECOVERED".into(),
            object_id: a.attempt_id,
            revision: a.revision,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &identity.actor_id,
            RELEASE,
            &identity.idempotency_key,
            &receipt.operation_id,
            &request,
            &json(&receipt)?,
        )
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }
    /// Scoped Worker observation can survive revoked lease cleanup. It never
    /// closes an author by itself, releases a loan, or asserts known model usage.
    pub async fn record_author_stop_observation(&self, r: WorkerResult) -> Result<Value> {
        if r.event_id.is_empty() || r.event_id.len() > 512 {
            return Err(err(
                "VALIDATION_ERROR",
                "bounded original result identity required",
            ));
        }
        let event_id = format!("{}:author-stop-observation", r.event_id);
        let payload = json!({"kind":OBSERVATION_KIND,"source":"SCOPED_WORKER",
            "worker_result_sha256":forgeflow_evidence::sha256(&serde_json::to_vec(&r)?),"worker_result":r});
        let _guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        let a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        let old: Option<Value> =
            sqlx::query_scalar("SELECT payload FROM worker_event_ids WHERE event_id=$1")
                .bind(&event_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(old) = old {
            if old != payload {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "stop observation identity cannot change",
                ));
            }
            tx.commit().await?;
            return Ok(
                json!({"event_id":event_id,"attempt_id":a.attempt_id,"author_stop_confirmed":true,"replayed":true}),
            );
        }
        if !matches!(
            a.state,
            AttemptState::Stopping | AttemptState::RecoveryRequired
        ) {
            return Err(err(
                "AUTHOR_CLOSE_STATE_INVALID",
                "stop observation records only an existing cancellation",
            ));
        }
        validate_stop(&mut tx, &a, &r).await?;
        sqlx::query("INSERT INTO worker_event_ids(event_id,project_id,attempt_id,payload) VALUES($1,$2,$3,$4)")
            .bind(&event_id).bind(&a.project_id).bind(&a.attempt_id).bind(&payload).execute(&mut *tx).await?;
        event(&mut tx, &a.project_id, &a.attempt_id, a.revision, "attempt.author_stop_observed",
            json!({"attempt_id":a.attempt_id,"generation":a.generation,"worker_id":a.worker_id,
                "observation_event_id":event_id,"author_stop_confirmed":true,"resources_released":false,"financial_custody_settled":false})).await?;
        tx.commit().await?;
        Ok(
            json!({"event_id":event_id,"attempt_id":a.attempt_id,"author_stop_confirmed":true,"replayed":false}),
        )
    }

    pub async fn close_author_retain_custody(
        &self,
        identity: CommandIdentity,
        r: CloseAuthorRetainCustodyRequest,
    ) -> Result<CommandReceipt> {
        if !matches!(identity.actor_id.as_str(), "owner" | "owner-service") {
            return Err(err(
                "OWNER_AUTHORIZATION_REQUIRED",
                "author closure with unknown custody requires Owner authorization",
            ));
        }
        if r.reason.trim().is_empty() || r.reason.len() > 2048 || r.observation_event_id.is_empty()
        {
            return Err(err(
                "VALIDATION_ERROR",
                "bounded explicit reason and trusted stop observation required",
            ));
        }
        let request = json(&r)?;
        let _guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        if let Some(old) = replay(
            &mut tx,
            &identity.actor_id,
            COMMAND,
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            let mut receipt: CommandReceipt = decode(old)?;
            receipt.replayed = true;
            tx.commit().await?;
            return Ok(receipt);
        }
        let mut a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        if a.revision != r.expected_revision {
            return Err(err(
                "REVISION_CONFLICT",
                "attempt changed before author closure",
            ));
        }
        close_preconditions(&mut tx, &a, &r.observation_event_id).await?;
        let operation_id = id();
        let custody: Value = sqlx::query_scalar("SELECT jsonb_build_object('native_requests',COALESCE((SELECT jsonb_agg(jsonb_build_object('request_id',request_id,'request_grant_id',request_grant_id,'status',status,'usage_complete',usage_complete) ORDER BY request_id) FROM native_model_requests WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED')),'[]'::jsonb),'resource_allocations',COALESCE((SELECT jsonb_agg(jsonb_build_object('allocation_id',allocation_id,'scope_id',scope_id,'dimension',dimension,'amount',amount,'state',state) ORDER BY allocation_id) FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED'),'[]'::jsonb),'native_allocations',COALESCE((SELECT jsonb_agg(jsonb_build_object('resource_allocation_id',resource_allocation_id,'allocation_id',allocation_id,'scope_id',scope_id,'dimension',dimension,'amount',amount,'state',state) ORDER BY resource_allocation_id) FROM native_child_allocations WHERE attempt_id=$1 AND state<>'RELEASED'),'[]'::jsonb))")
            .bind(&a.attempt_id).fetch_one(&mut *tx).await?;
        // No finalize_disposed/release/handoff call: all original allocation
        // states, counters and model settlements retain their exact preimage.
        sqlx::query("UPDATE native_child_lifecycles SET process_stopped_at=COALESCE(process_stopped_at,clock_timestamp()) WHERE attempt_id=$1 AND generation=$2 AND worker_id=$3")
            .bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).execute(&mut *tx).await?;
        a.state = AttemptState::Cancelled;
        a.terminal_at = Some(db_now(&mut tx).await?);
        a.revision += 1;
        persist_attempt(&mut tx, &a).await?;
        let receipt_value = json!({"kind":"AUTHOR_CLOSED_CUSTODY_RETAINED","operation_id":operation_id,
            "project_id":a.project_id,"attempt_id":a.attempt_id,"task_id":a.task_id,"generation":a.generation,
            "observation_event_id":r.observation_event_id,"reason":r.reason,"authorized_by":identity.actor_id,
            "author_state":"CANCELLED","resources_released":false,"financial_custody_settled":false,
            "retained_custody":custody});
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'operations',$2,1,$3)")
            .bind(&a.project_id).bind(&operation_id).bind(&receipt_value).execute(&mut *tx).await?;
        event(
            &mut tx,
            &a.project_id,
            &a.attempt_id,
            a.revision,
            "attempt.author_closed_custody_retained",
            receipt_value,
        )
        .await?;
        let receipt = CommandReceipt {
            operation_id,
            status: "AUTHOR_CLOSED_CUSTODY_RETAINED".into(),
            object_id: a.attempt_id,
            revision: a.revision,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &identity.actor_id,
            COMMAND,
            &identity.idempotency_key,
            &receipt.operation_id,
            &request,
            &json(&receipt)?,
        )
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }

    pub async fn author_custody_status(&self, project: &str, attempt: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let a: Attempt = decode(
            sqlx::query_scalar::<_, Value>(
                "SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2",
            )
            .bind(project)
            .bind(attempt)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "attempt not found"))?,
        )?;
        let observation_id: Option<String> = sqlx::query_scalar("SELECT event_id FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 AND payload->>'kind'=$3 ORDER BY event_id LIMIT 1")
            .bind(project).bind(attempt).bind(OBSERVATION_KIND).fetch_optional(&mut *tx).await?;
        let check = if let Some(id) = &observation_id {
            close_preconditions(&mut tx, &a, id).await
        } else {
            Err(err(
                "AUTHOR_STOP_OBSERVATION_MISSING",
                "trusted stop observation is not yet recorded",
            ))
        };
        let blocked_code = match &check {
            Ok(()) => None,
            Err(StoreError::Domain(e)) => Some(e.code.clone()),
            Err(_) => return check.map(|_| Value::Null),
        };
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM native_model_requests WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED')")
            .bind(attempt).fetch_one(&mut *tx).await?;
        let held: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED')+(SELECT count(*) FROM native_child_allocations WHERE attempt_id=$1 AND state<>'RELEASED')")
            .bind(attempt).fetch_one(&mut *tx).await?;
        let closure: Option<String> = sqlx::query_scalar("SELECT document_id FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='AUTHOR_CLOSED_CUSTODY_RETAINED' AND data->>'attempt_id'=$2 ORDER BY document_id LIMIT 1")
            .bind(project).bind(attempt).fetch_optional(&mut *tx).await?;
        let held_physical: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED' AND dimension IN('active_slot','coding_slot','cpu_units','memory_bytes','build_permit','gpu_permit'))+(SELECT count(*) FROM native_child_allocations WHERE attempt_id=$1 AND state<>'RELEASED' AND dimension IN('active_slot','coding_slot','cpu_units','memory_bytes','build_permit','gpu_permit'))")
            .bind(attempt).fetch_one(&mut *tx).await?;
        let physical_check = if let Some(id) = &observation_id {
            physical_recovery_preconditions(&mut tx, &a, id).await
        } else {
            Err(err(
                "AUTHOR_STOP_OBSERVATION_MISSING",
                "trusted stop observation required",
            ))
        };
        let physical_blocked_code = match &physical_check {
            Ok(()) => None,
            Err(StoreError::Domain(e)) => Some(e.code.clone()),
            Err(_) => return physical_check.map(|_| Value::Null),
        };
        let value = json!({"project_id":project,"attempt_id":attempt,"state":a.state,"revision":a.revision,"generation":a.generation,
            "trusted_stop_observation_event_id":observation_id,"author_close_eligible":check.is_ok(),"blocked_code":blocked_code,
            "pending_native_model_request_count":pending,"held_allocation_count":held,"custody_pending":pending>0||held>0,
            "retained_author_closure_operation_id":closure,"held_physical_allocation_count":held_physical,
            "physical_recovery_eligible":held_physical>0 && physical_check.is_ok(),"physical_recovery_blocked_code":physical_blocked_code});
        tx.commit().await?;
        Ok(value)
    }
}
