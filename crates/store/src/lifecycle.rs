use super::*;
impl Store {
    pub async fn transition(&self, r: TransitionRequest) -> Result<Attempt> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let result = transition_tx(&mut tx, r).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn heartbeat(&self, r: HeartbeatRequest) -> Result<Lease> {
        if r.lease_seconds == 0 || r.lease_seconds > 3600 {
            return Err(err("VALIDATION_ERROR", "invalid lease TTL"));
        }
        let mut tx = self.control_pool.begin().await?;
        // Renewal changes no resource or business authority. Its own Attempt then
        // Lease locks serialize with cancel/expiry without the global/project lane.
        let a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        let mut l = valid_lease(&mut tx, &a, r.generation, &r.worker_id).await?;
        let envelope: ExecutionEnvelope = decode(
            sqlx::query_scalar("SELECT envelope FROM attempts WHERE attempt_id=$1")
                .bind(&a.attempt_id)
                .fetch_one(&mut *tx)
                .await?,
        )?;
        let deadline = DateTime::parse_from_rfc3339(&envelope.deadline_at)
            .map_err(|_| err("VALIDATION_ERROR", "invalid deadline"))?
            .with_timezone(&Utc);
        let now = db_now(&mut tx).await?;
        if deadline <= now {
            return Err(err(
                "LEASE_STALE",
                "attempt deadline elapsed; renewal denied",
            ));
        }
        l.expires_at = (now + chrono::Duration::seconds(i64::from(r.lease_seconds))).min(deadline);
        sqlx::query("UPDATE leases SET expires_at=$2 WHERE lease_id=$1")
            .bind(&l.lease_id)
            .bind(l.expires_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(l)
    }
    pub async fn cancel(&self, r: CancelRequest) -> Result<CommandReceipt> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let request = json(&r)?;
        if let Some(v) =
            replay(&mut tx, &r.actor_id, "cancel", &r.idempotency_key, &request).await?
        {
            let mut receipt: CommandReceipt = decode(v)?;
            receipt.replayed = true;
            tx.commit().await?;
            return Ok(receipt);
        }
        project_lock(&mut tx, &r.project_id).await?;
        let mut a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        if a.revision != r.expected_revision {
            return Err(err("REVISION_CONFLICT", "attempt changed"));
        }
        let commit = irreversible_merge_decision(&mut tx, &a).await?;
        let operation_id = id();
        let status = if a.state == AttemptState::Succeeded {
            "ALREADY_COMMITTED"
        } else if commit {
            "COMMIT_IN_PROGRESS"
        } else if a.state.is_terminal() {
            "ALREADY_TERMINAL"
        } else {
            let never_dispatched = if matches!(
                a.state,
                AttemptState::Leased | AttemptState::RecoveryRequired
            ) {
                never_dispatched_proof(&mut tx, &a).await?
            } else {
                None
            };
            revoke(&mut tx, &a).await?;
            if let Some(proof) = never_dispatched {
                // The persisted start command was never handed out. Revocation and
                // terminalization share claim's transaction lock, so it cannot launch
                // after this proof, even if lease expiry erased the LEASED state.
                a.result = Some(serde_json::json!({
                    "schema_version":"forgeflow.never-dispatched.v1",
                    "kind":"NEVER_DISPATCHED",
                    "receipt_id":operation_id,
                    "project_id":a.project_id,
                    "attempt_id":a.attempt_id,
                    "operation_id":a.operation_id,
                    "lease_id":a.lease_id,
                    "generation":a.generation,
                    "worker_id":a.worker_id,
                    "dispatch_contract":"CLAIM_BEFORE_EFFECTS_V1",
                    "attempt_revision_before":a.revision,
                    "state_before":a.state,
                    "actor_id":r.actor_id,
                    "reason":r.reason,
                    "start_outbox":proof,
                    "observed_at":db_now(&mut tx).await?,
                    "dispatch_evidence_absent":true
                }));
                a.state = AttemptState::Cancelled;
                a.terminal_at = Some(db_now(&mut tx).await?);
                release(&mut tx, &a, &r.reason).await?;
            } else if a.state != AttemptState::RecoveryRequired {
                a.state = AttemptState::Stopping;
            }
            a.revision += 1;
            persist_attempt(&mut tx, &a).await?;
            if a.state == AttemptState::Cancelled {
                event(
                    &mut tx,
                    &a.project_id,
                    &a.attempt_id,
                    a.revision,
                    "attempt.never_dispatched",
                    json(&a.result)?,
                )
                .await?;
            }
            event(
                &mut tx,
                &a.project_id,
                &a.attempt_id,
                a.revision,
                "attempt.cancel_requested",
                serde_json::json!({"attempt":a,"reason":r.reason}),
            )
            .await?;
            if a.state != AttemptState::Cancelled {
                outbox(&mut tx,&a.project_id,&operation_id,"attempt.stop",serde_json::json!({"attempt_id":a.attempt_id,"generation":a.generation,"worker_id":a.worker_id,"reason":r.reason})).await?;
            }
            "ACCEPTED"
        };
        let receipt = CommandReceipt {
            operation_id,
            status: status.into(),
            object_id: a.attempt_id,
            revision: a.revision,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &r.actor_id,
            "cancel",
            &r.idempotency_key,
            &receipt.operation_id,
            &request,
            &json(&receipt)?,
        )
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }
    pub async fn confirm_stop(&self, r: StopReceipt) -> Result<Attempt> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let result = confirm_stop_tx(&mut tx, r).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn expire_leases(&self) -> Result<Vec<Attempt>> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let ids:Vec<(String,String)>=sqlx::query_as("SELECT a.project_id,a.attempt_id FROM attempts a JOIN leases l ON l.attempt_id=a.attempt_id WHERE a.terminal_at IS NULL AND l.revoked_at IS NULL AND l.expires_at<=clock_timestamp() ORDER BY a.project_id,a.attempt_id").fetch_all(&mut *tx).await?;
        let mut changed = Vec::new();
        for (p, id) in ids {
            project_lock(&mut tx, &p).await?;
            let mut a = attempt_lock(&mut tx, &p, &id).await?;
            // Renewal now has its own lane and may have committed while this
            // scan waited for the Attempt lock. Recheck the current locked lease;
            // a stale candidate list never authorizes revoking a renewed lease.
            let lease = sqlx::query("SELECT revoked_at,expires_at FROM leases WHERE project_id=$1 AND attempt_id=$2 AND lease_id=$3 FOR UPDATE")
                .bind(&p).bind(&id).bind(&a.lease_id).fetch_one(&mut *tx).await?;
            if a.state.is_terminal()
                || lease
                    .get::<Option<DateTime<Utc>>, _>("revoked_at")
                    .is_some()
                || lease.get::<DateTime<Utc>, _>("expires_at") > db_now(&mut tx).await?
            {
                continue;
            }
            let deciding:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 AND state='COMMIT_DECIDED')").bind(&p).bind(&id).fetch_one(&mut *tx).await?;
            revoke(&mut tx, &a).await?;
            a.state = AttemptState::RecoveryRequired;
            a.revision += 1;
            sqlx::query("UPDATE resource_allocations SET state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'").bind(&id).execute(&mut *tx).await?;
            persist_attempt(&mut tx, &a).await?;
            event(
                &mut tx,
                &p,
                &id,
                a.revision,
                "attempt.lease_expired",
                serde_json::json!({"attempt":a,"commit_decided":deciding}),
            )
            .await?;
            changed.push(a);
        }
        tx.commit().await?;
        Ok(changed)
    }
    pub async fn register_worker(&self, r: WorkerRegisterRequest) -> Result<()> {
        if r.worker_id.is_empty() || r.boot_id.is_empty() {
            return Err(err("VALIDATION_ERROR", "worker and boot identity required"));
        }
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let old: Option<String> =
            sqlx::query_scalar("SELECT boot_id FROM workers WHERE worker_id=$1 FOR UPDATE")
                .bind(&r.worker_id)
                .fetch_optional(&mut *tx)
                .await?;
        if old.is_some() {
            let previous = sqlx::query(
                "SELECT project_id,executor_profile_ids FROM workers WHERE worker_id=$1",
            )
            .bind(&r.worker_id)
            .fetch_one(&mut *tx)
            .await?;
            let old_project: Option<String> = previous.try_get("project_id")?;
            let old_profiles: Vec<String> = decode(previous.try_get("executor_profile_ids")?)?;
            let mut before = old_profiles.clone();
            let mut after = r.executor_profile_ids.clone();
            before.sort();
            after.sort();
            if old_project != r.project_id || before != after {
                let active:Vec<(String,String)>=sqlx::query_as("SELECT project_id,envelope->>'executor_profile_id' FROM attempts WHERE worker_id=$1 AND terminal_at IS NULL").bind(&r.worker_id).fetch_all(&mut *tx).await?;
                if !active.is_empty()
                    && (!(old_project.is_none() && old_profiles.is_empty())
                        || active.iter().any(|(p, profile)| {
                            Some(p) != r.project_id.as_ref()
                                || !r.executor_profile_ids.contains(profile)
                        }))
                {
                    return Err(err(
                        "WORKER_SCOPE_MISMATCH",
                        "worker association cannot retarget open attempts",
                    ));
                }
            }
        }
        if old.as_ref().is_some_and(|old| old != &r.boot_id) {
            let rows:Vec<(String,String)>=sqlx::query_as("SELECT project_id,attempt_id FROM attempts WHERE worker_id=$1 AND terminal_at IS NULL ORDER BY project_id,attempt_id").bind(&r.worker_id).fetch_all(&mut *tx).await?;
            for (p, id) in rows {
                project_lock(&mut tx, &p).await?;
                let mut a = attempt_lock(&mut tx, &p, &id).await?;
                a.state = AttemptState::RecoveryRequired;
                a.revision += 1;
                revoke(&mut tx, &a).await?;
                sqlx::query("UPDATE resource_allocations SET state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'").bind(&id).execute(&mut *tx).await?;
                persist_attempt(&mut tx, &a).await?;
                event(
                    &mut tx,
                    &p,
                    &id,
                    a.revision,
                    "worker.reboot_quarantined",
                    json(&a)?,
                )
                .await?;
            }
        }
        sqlx::query("INSERT INTO workers(worker_id,boot_id,capabilities,project_id,executor_profile_ids) VALUES($1,$2,$3,$4,$5) ON CONFLICT(worker_id) DO UPDATE SET boot_id=EXCLUDED.boot_id,capabilities=EXCLUDED.capabilities,project_id=EXCLUDED.project_id,executor_profile_ids=EXCLUDED.executor_profile_ids,heartbeat_at=clock_timestamp()").bind(r.worker_id).bind(r.boot_id).bind(json(&r.capabilities)?).bind(&r.project_id).bind(json(&r.executor_profile_ids)?).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn heartbeat_worker(&self, r: WorkerHeartbeatRequest) -> Result<()> {
        let n=sqlx::query("UPDATE workers SET heartbeat_at=clock_timestamp(),active_attempt_ids=$3 WHERE worker_id=$1 AND boot_id=$2").bind(r.worker_id).bind(r.boot_id).bind(json(&r.active_attempt_ids)?).execute(&self.control_pool).await?.rows_affected();
        if n == 0 {
            return Err(err("WORKER_STALE", "worker boot identity does not match"));
        }
        Ok(())
    }
    pub async fn claim(&self, worker: &str, project: &str) -> Result<Option<ExecutionEnvelope>> {
        self.claim_with_known_attempts(worker, project, &[]).await
    }
    /// Redeliver unseen STARTING claims while allowing a Worker to receive more work.
    /// Known IDs only suppress redelivery; their leases and allocations remain occupied.
    pub async fn claim_with_known_attempts(
        &self,
        worker: &str,
        project: &str,
        known_attempt_ids: &[String],
    ) -> Result<Option<ExecutionEnvelope>> {
        if known_attempt_ids.len() > 4096 {
            return Err(err(
                "VALIDATION_ERROR",
                "known claim inventory exceeds budget",
            ));
        }
        // Delivery consumes an existing reservation; it does not mutate resource
        // accounting. Keep it off the writer FIFO and global resource coordinator.
        let mut tx = self.dispatch_pool.begin().await?;
        // register_worker locks Worker before Project. Acquire the same order,
        // including the FK lock later taken by outbox.claimed_by. KEY SHARE still
        // permits heartbeat's non-key update while preventing reboot/retarget.
        let registered:Option<i32>=sqlx::query_scalar("SELECT 1 FROM workers WHERE worker_id=$1 AND project_id=$2 AND heartbeat_at>clock_timestamp()-interval '2 minutes' FOR KEY SHARE").bind(worker).bind(project).fetch_optional(&mut *tx).await?;
        if registered.is_none() {
            return Err(err(
                "WORKER_STALE",
                "worker must register and heartbeat before claim",
            ));
        }
        project_lock(&mut tx, project).await?;
        // Project contention may outlast the registration's liveness window.
        // Resample after that wait, as the original serialized claim did.
        let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workers WHERE worker_id=$1 AND project_id=$2 AND heartbeat_at>clock_timestamp()-interval '2 minutes')").bind(worker).bind(project).fetch_one(&mut *tx).await?;
        if !live {
            return Err(err(
                "WORKER_STALE",
                "worker must register and heartbeat before claim",
            ));
        }
        // Both replay and first delivery lock the command before Attempt/Lease.
        // Project serialization preserves cancel/replan/handoff ordering.
        let outstanding:Option<Value>=sqlx::query_scalar("SELECT a.envelope FROM attempts a JOIN outbox o ON o.operation_id=a.operation_id WHERE a.project_id=$1 AND a.worker_id=$2 AND a.state='STARTING' AND o.claimed_by=$2 AND o.kind='attempt.start' AND NOT(a.attempt_id=ANY($3::text[])) ORDER BY a.created_at,a.attempt_id FOR UPDATE OF o SKIP LOCKED LIMIT 1").bind(project).bind(worker).bind(known_attempt_ids).fetch_optional(&mut *tx).await?;
        if let Some(envelope) = outstanding {
            let e: ExecutionEnvelope = decode(envelope)?;
            let a = attempt_lock(&mut tx, project, &e.attempt_id).await?;
            valid_lease(&mut tx, &a, e.generation, worker).await?;
            tx.commit().await?;
            return Ok(Some(e));
        }
        let row=sqlx::query("SELECT o.outbox_id,a.attempt_id,a.envelope FROM outbox o JOIN attempts a ON a.operation_id=o.operation_id WHERE o.project_id=$1 AND o.kind='attempt.start' AND o.delivered_at IS NULL AND o.claimed_by IS NULL AND a.worker_id=$2 AND a.state='LEASED' ORDER BY o.created_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT 1").bind(project).bind(worker).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let mut a = attempt_lock(&mut tx, project, &row.get::<String, _>("attempt_id")).await?;
        valid_lease(&mut tx, &a, a.generation, worker).await?;
        let envelope: ExecutionEnvelope = decode(row.try_get("envelope")?)?;
        a.state = AttemptState::Starting;
        a.revision += 1;
        persist_attempt(&mut tx, &a).await?;
        sqlx::query(
            "UPDATE outbox SET claimed_by=$2,delivered_at=clock_timestamp() WHERE outbox_id=$1",
        )
        .bind(row.get::<String, _>("outbox_id"))
        .bind(worker)
        .execute(&mut *tx)
        .await?;
        event(
            &mut tx,
            project,
            &a.attempt_id,
            a.revision,
            "attempt.starting",
            json(&a)?,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(envelope))
    }
    pub async fn attempt_control(
        &self,
        p: &str,
        id: &str,
        generation: i64,
        worker: &str,
    ) -> Result<AttemptControl> {
        let row=sqlx::query(
            "SELECT a.state,a.generation,a.worker_id,l.expires_at,l.revoked_at,t.fence_epoch, \
             l.generation AS lease_generation,l.worker_id AS lease_worker_id, \
             a.envelope->>'deadline_at' AS deadline_at,clock_timestamp() AS observed_now, \
             EXISTS(SELECT 1 FROM outbox o WHERE o.project_id=a.project_id AND o.operation_id=a.operation_id \
                 AND o.kind='attempt.start' AND o.claimed_by=a.worker_id AND o.delivered_at IS NOT NULL \
                 AND o.payload->>'project_id'=a.project_id AND o.payload->>'attempt_id'=a.attempt_id \
                 AND o.payload->>'operation_id'=a.operation_id AND o.payload->>'lease_id'=a.lease_id \
                 AND o.payload->>'worker_id'=a.worker_id AND o.payload->'generation'=to_jsonb(a.generation)) \
             AS dispatch_confirmed FROM attempts a JOIN leases l ON l.attempt_id=a.attempt_id \
                 AND l.project_id=a.project_id AND l.lease_id=a.lease_id \
             JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id \
             WHERE a.project_id=$1 AND a.attempt_id=$2",
        ).bind(p).bind(id).fetch_optional(&self.control_pool).await?;
        let Some(r) = row else {
            return Ok(AttemptControl {
                valid: false,
                cancel_requested: false,
                lease_expires_at: None,
            });
        };
        let now: DateTime<Utc> = r.get("observed_now");
        let deadline = DateTime::parse_from_rfc3339(&r.get::<String, _>("deadline_at"))
            .map_err(|_| err("VALIDATION_ERROR", "invalid attempt deadline"))?
            .with_timezone(&Utc);
        let expires: DateTime<Utc> = r.get("expires_at");
        let revoked: Option<DateTime<Utc>> = r.get("revoked_at");
        let state: String = r.get("state");
        // Admission's envelope is a reservation, not launch authority. Only the
        // canonical transactional claim can authorize execution and its effects.
        let valid = r.get::<i64, _>("generation") == generation
            && r.get::<i64, _>("lease_generation") == generation
            && r.get::<i64, _>("fence_epoch") == generation
            && r.get::<String, _>("worker_id") == worker
            && r.get::<String, _>("lease_worker_id") == worker
            && revoked.is_none()
            && expires > now
            && deadline > now
            && r.get::<bool, _>("dispatch_confirmed")
            && matches!(
                state.as_str(),
                "STARTING" | "RUNNING" | "VERIFYING" | "REVIEW_READY" | "MERGE_QUEUED" | "MERGING"
            );
        Ok(AttemptControl {
            valid,
            cancel_requested: revoked.is_some()
                || matches!(state.as_str(), "STOPPING" | "RECOVERY_REQUIRED"),
            lease_expires_at: Some(expires.to_rfc3339()),
        })
    }
    pub async fn record_worker_event(&self, r: WorkerEvent) -> Result<()> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        let mut a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        let payload = json(&r)?;
        if let Some(old) =
            sqlx::query_scalar::<_, Value>("SELECT payload FROM worker_event_ids WHERE event_id=$1")
                .bind(&r.event_id)
                .fetch_optional(&mut *tx)
                .await?
        {
            if old != payload {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "worker event reused with different payload",
                ));
            }
            tx.commit().await?;
            return Ok(());
        }
        if a.lease_id != r.lease_id {
            return Err(err("LEASE_STALE", "lease identity mismatch"));
        }
        if r.kind == "RECOVERY_REQUIRED" {
            if a.generation != r.generation || a.worker_id != r.worker_id || a.state.is_terminal() {
                return Err(err("LEASE_STALE", "recovery event identity mismatch"));
            }
            a.state = AttemptState::RecoveryRequired;
            a.revision += 1;
            revoke(&mut tx, &a).await?;
            sqlx::query("UPDATE resource_allocations SET state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'").bind(&a.attempt_id).execute(&mut *tx).await?;
            persist_attempt(&mut tx, &a).await?;
        } else {
            valid_lease(&mut tx, &a, r.generation, &r.worker_id).await?;
        }
        if matches!(
            r.kind.as_str(),
            "process.started"
                | "execution.started"
                | "session.started"
                | "attempt.running"
                | "RUNNING"
        ) && a.state == AttemptState::Starting
        {
            a.state = AttemptState::Running;
            a.revision += 1;
            persist_attempt(&mut tx, &a).await?;
            sqlx::query("UPDATE resource_allocations SET state='HELD' WHERE attempt_id=$1 AND state='RESERVED'").bind(&a.attempt_id).execute(&mut *tx).await?;
        }
        if native_root_profile_needed(&r) {
            // Reads the original same-project frozen object (or exact legacy
            // inline binding), never a mutable current profile document.
            let bindings =
                crate::execution_bindings::load(&mut *tx, &a.project_id, &a.attempt_id).await?;
            if let Some(session) =
                native_root_session_candidate(&r, &bindings["executor_profile"], &a.operation_id)?
            {
                bind_native_root_session(&mut tx, &a, session).await?;
            }
        }
        sqlx::query("INSERT INTO worker_event_ids VALUES($1,$2,$3,$4)")
            .bind(&r.event_id)
            .bind(&r.project_id)
            .bind(&r.attempt_id)
            .bind(&payload)
            .execute(&mut *tx)
            .await?;
        event(
            &mut tx,
            &r.project_id,
            &r.attempt_id,
            a.revision,
            &r.kind,
            r.payload,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn worker_result(&self, r: WorkerResult) -> Result<Attempt> {
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let result = worker_result_tx(&mut tx, r).await?;
        tx.commit().await?;
        Ok(result)
    }
}

// Only root-shaped frames need the frozen profile lookup. Ordinary events do
// not repeatedly load the potentially large executor profile.
fn native_root_profile_needed(event: &WorkerEvent) -> bool {
    event.kind == "EXECUTOR_EVENT"
        && (event.payload["native_type"] == "session"
            || (event.payload["native_type"] == "system"
                && event.payload["payload"]["subtype"] == "init")
            || (event.payload["payload"]["type"] == "system"
                && event.payload["payload"]["subtype"] == "init"))
}

/// Protocol selection is derived from the frozen profile. The Claude branch is
/// explicitly PARTIAL: raw bytes remain in a scoped Worker's private journal,
/// not a registered v1 CAS artifact or independently verified Store observation.
fn native_root_session_candidate<'a>(
    event: &'a WorkerEvent,
    frozen_profile: &Value,
    operation_id: &str,
) -> Result<Option<&'a str>> {
    if !native_root_profile_needed(event) {
        return Ok(None);
    }
    let projection = &event.payload;
    let claude_profile = frozen_profile["kind"] == "CLAUDE_CODE_LEAF";
    let claude_marker = projection["source"] == "claude_code_leaf"
        || projection["driver_id"] == "CLAUDE_CODE"
        || projection["executor_kind"] == "CLAUDE_CODE_LEAF";
    if projection["native_type"] == "session" {
        if claude_profile || claude_marker {
            return Err(err(
                "EXECUTOR_PROTOCOL_ERROR",
                "Claude cannot bind through a DSH session event",
            ));
        }
        // Historical DSH event shape is deliberately retained.
        return Ok(projection["payload"]["sessionId"].as_str());
    }
    if !claude_profile {
        if claude_marker {
            return Err(err(
                "EXECUTOR_PROTOCOL_ERROR",
                "Claude root event differs from frozen executor kind",
            ));
        }
        return Ok(None);
    }
    let raw = &projection["payload"];
    if projection["source"] != "claude_code_leaf"
        || projection["driver_id"] != "CLAUDE_CODE"
        || projection["executor_kind"] != "CLAUDE_CODE_LEAF"
        || projection["native_event_contract"] != "PARTIAL_RESTRICTED_RAW_PROJECTION"
        || projection["native_type"] != "system"
        || projection["event_type"] != "system"
        || raw["type"] != "system"
        || raw["subtype"] != "init"
        || projection.get("parse_error") != Some(&Value::Null)
        || projection["payload_in_artifact"] != true
        || projection["completeness"] != "UPSTREAM_COMMITTED_PROJECTION"
        || projection["source_sequence_kind"] != "WORKER_RECEIVE_ORDER"
    {
        return Err(err(
            "EXECUTOR_PROTOCOL_ERROR",
            "inconsistent or malformed Claude root projection",
        ));
    }
    let sequence = projection["sequence"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
        .ok_or_else(|| {
            err(
                "EXECUTOR_PROTOCOL_ERROR",
                "bounded Claude receive sequence required",
            )
        })?;
    if projection["source_sequence"].as_u64() != Some(sequence)
        || projection["event_id"].as_str() != Some(event.event_id.as_str())
        || event.event_id != format!("{operation_id}:native-{sequence:020}")
        || projection["project_id"].as_str() != Some(event.project_id.as_str())
        || projection["attempt_id"].as_str() != Some(event.attempt_id.as_str())
    {
        return Err(err(
            "EXECUTOR_PROTOCOL_ERROR",
            "Claude projection differs from outer event identity",
        ));
    }
    let execution = projection["execution_id"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 512 && !v.contains('\0'));
    if execution.is_none()
        || projection["received_at"]
            .as_str()
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .is_none()
    {
        return Err(err(
            "EXECUTOR_PROTOCOL_ERROR",
            "Claude execution and receive time required",
        ));
    }
    // Validate a bounded internal reference only. Never open a caller-supplied
    // Worker path on the server or pretend it has been registered as ArtifactRef.
    let reference = &projection["raw_artifact_ref"];
    let raw_digest = projection["raw_sha256"]
        .as_str()
        .filter(|v| forgeflow_domain::valid_digest(v));
    let raw_bytes = projection["raw_bytes"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= i64::MAX as u64);
    let raw_path = reference["path"]
        .as_str()
        .filter(|v| v.len() <= 4096 && !v.contains('\0') && std::path::Path::new(v).is_absolute());
    if reference["storage"] != "WORKER_LOCAL_FILE"
        || raw_digest.is_none()
        || raw_bytes.is_none()
        || raw_path.is_none()
        || reference["sha256"].as_str() != raw_digest
        || reference["bytes"].as_u64() != raw_bytes
    {
        return Err(err(
            "EXECUTOR_PROTOCOL_ERROR",
            "Claude raw reference is absent or inconsistent",
        ));
    }
    match raw.get("parent_tool_use_id") {
        None | Some(Value::Null) => {}
        Some(Value::String(parent))
            if !parent.is_empty() && parent.len() <= 512 && !parent.contains('\0') =>
        {
            return Ok(None); // A forwarded child remains an observation, not a root grant.
        }
        _ => {
            return Err(err(
                "EXECUTOR_PROTOCOL_ERROR",
                "invalid Claude parent identity",
            ));
        }
    }
    let session = raw["session_id"]
        .as_str()
        .filter(|v| !v.trim().is_empty() && v.chars().count() <= 256 && !v.contains('\0'))
        .ok_or_else(|| {
            err(
                "EXECUTOR_PROTOCOL_ERROR",
                "bounded Claude root session identity required",
            )
        })?;
    Ok(Some(session))
}

fn validate_native_root_owner(
    attempt: &Attempt,
    proposed_session: &str,
    project: &str,
    attempt_id: &str,
    generation: i64,
    worker: &str,
    existing_session: &str,
) -> Result<()> {
    if project != attempt.project_id
        || attempt_id != attempt.attempt_id
        || generation != attempt.generation
        || worker != attempt.worker_id
        || existing_session != proposed_session
    {
        return Err(err(
            "EXECUTOR_PROTOCOL_ERROR",
            "native root session namespace conflicts with frozen attempt",
        ));
    }
    Ok(())
}

// Caller retains existing coordination/project/Attempt locks and valid lease.
// The old global session PK is preserved; collisions are never namespaced away.
async fn bind_native_root_session(
    tx: &mut Transaction<'_, Postgres>,
    attempt: &Attempt,
    session: &str,
) -> Result<()> {
    for row in sqlx::query("SELECT upstream_session_id,project_id,attempt_id,generation,worker_id FROM native_sessions WHERE attempt_id=$1 OR upstream_session_id=$2 ORDER BY upstream_session_id FOR UPDATE")
        .bind(&attempt.attempt_id).bind(session).fetch_all(&mut **tx).await? {
        validate_native_root_owner(attempt, session, row.get::<&str,_>("project_id"), row.get::<&str,_>("attempt_id"),
            row.get("generation"), row.get::<&str,_>("worker_id"), row.get::<&str,_>("upstream_session_id"))?;
    }
    sqlx::query("INSERT INTO native_sessions(upstream_session_id,project_id,attempt_id,generation,worker_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(upstream_session_id) DO NOTHING")
        .bind(session).bind(&attempt.project_id).bind(&attempt.attempt_id).bind(attempt.generation).bind(&attempt.worker_id).execute(&mut **tx).await?;
    // Do not interpret ON CONFLICT as successful ownership. Even an external
    // writer racing outside our coordination lane cannot turn a collision into ACK.
    let stored = sqlx::query("SELECT upstream_session_id,project_id,attempt_id,generation,worker_id FROM native_sessions WHERE upstream_session_id=$1 FOR UPDATE")
        .bind(session).fetch_one(&mut **tx).await?;
    validate_native_root_owner(
        attempt,
        session,
        stored.get::<&str, _>("project_id"),
        stored.get::<&str, _>("attempt_id"),
        stored.get("generation"),
        stored.get::<&str, _>("worker_id"),
        stored.get::<&str, _>("upstream_session_id"),
    )?;
    Ok(())
}

/// Positive authority proof only; missing local journals or PIDs are irrelevant.
/// Caller holds coordination, project and attempt locks until revocation and release.
async fn never_dispatched_proof(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<Option<Value>> {
    if a.result.is_some() {
        return Ok(None);
    }
    let dispatch_contract: Option<String> = sqlx::query_scalar(
        "SELECT execution_bindings->>'dispatch_contract' FROM attempts WHERE project_id=$1 AND attempt_id=$2",
    )
    .bind(&a.project_id)
    .bind(&a.attempt_id)
    .fetch_one(&mut **tx)
    .await?;
    if dispatch_contract.as_deref() != Some("CLAIM_BEFORE_EFFECTS_V1") {
        // An old reservation may predate claim-gated execution. The newer launch
        // checks cannot retroactively establish its absence of external effects.
        return Ok(None);
    }
    // ack_outbox does not take coordination, so lock the actual command row too.
    let row = sqlx::query(
        "SELECT outbox_id,payload,created_at,delivered_at,claimed_by FROM outbox \
         WHERE project_id=$1 AND operation_id=$2 AND kind='attempt.start' FOR UPDATE",
    )
    .bind(&a.project_id)
    .bind(&a.operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let delivered_at: Option<DateTime<Utc>> = row.try_get("delivered_at")?;
    let claimed_by: Option<String> = row.try_get("claimed_by")?;
    let payload: Value = row.try_get("payload")?;
    if delivered_at.is_some()
        || claimed_by.is_some()
        || payload.get("project_id").and_then(Value::as_str) != Some(a.project_id.as_str())
        || payload.get("operation_id").and_then(Value::as_str) != Some(a.operation_id.as_str())
        || payload.get("attempt_id").and_then(Value::as_str) != Some(a.attempt_id.as_str())
        || payload.get("lease_id").and_then(Value::as_str) != Some(a.lease_id.as_str())
        || payload.get("worker_id").and_then(Value::as_str) != Some(a.worker_id.as_str())
        || payload.get("generation").and_then(Value::as_i64) != Some(a.generation)
    {
        return Ok(None);
    }
    let outbox_id: String = row.try_get("outbox_id")?;
    // An undispatched marker cannot override contradictory execution authority.
    // Generic transitions can enter STARTING without changing the outbox, and
    // worker events may carry launch receipts under arbitrary executor event kinds.
    let dispatched: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
         SELECT 1 FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 \
         UNION ALL SELECT 1 FROM native_sessions WHERE project_id=$1 AND attempt_id=$2 \
         UNION ALL SELECT 1 FROM model_request_permit WHERE attempt_id=$2 \
         UNION ALL SELECT 1 FROM provider_requests WHERE project_id=$1 AND attempt_id=$2 \
         UNION ALL SELECT 1 FROM gateway_scope_budget WHERE attempt_id=$2 \
             AND (requests_used>0 OR inflight>0) \
         UNION ALL SELECT 1 FROM evidence_receipts WHERE project_id=$1 AND attempt_id=$2 \
         UNION ALL SELECT 1 FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 \
         UNION ALL SELECT 1 FROM worktrees WHERE project_id=$1 AND attempt_id=$2 \
         UNION ALL SELECT 1 FROM documents WHERE project_id=$1 AND collection='operations' \
             AND data->>'kind'='VERIFIER_PROCESS_ROOT' AND data->>'attempt_id'=$2 \
         UNION ALL SELECT 1 FROM outbox WHERE project_id=$1 AND kind='attempt.start' \
             AND outbox_id<>$4 AND (operation_id=$3 OR payload->>'attempt_id'=$2) \
         UNION ALL SELECT 1 FROM events WHERE project_id=$1 AND object_id=$2 AND ( \
             kind IN('attempt.starting','STARTING','process.started','execution.started','session.started', \
                      'attempt.running','RUNNING','EXECUTOR_EVENT','attempt.execution_returned') \
             OR payload->>'state' IN('STARTING','RUNNING','VERIFYING','REVIEW_READY','MERGE_QUEUED','MERGING') \
             OR payload->'attempt'->>'state' IN('STARTING','RUNNING','VERIFYING','REVIEW_READY','MERGE_QUEUED','MERGING')))",
    )
    .bind(&a.project_id)
    .bind(&a.attempt_id)
    .bind(&a.operation_id)
    .bind(&outbox_id)
    .fetch_one(&mut **tx)
    .await?;
    if dispatched {
        return Ok(None);
    }
    Ok(Some(serde_json::json!({
        "outbox_id":outbox_id,
        "kind":"attempt.start",
        "operation_id":a.operation_id,
        "dispatch_contract":dispatch_contract,
        "created_at":row.try_get::<DateTime<Utc>,_>("created_at")?,
        "delivered_at":delivered_at,
        "claimed_by":claimed_by,
        "payload":payload
    })))
}

pub(crate) async fn transition_tx(
    tx: &mut Transaction<'_, Postgres>,
    r: TransitionRequest,
) -> Result<Attempt> {
    project_lock(tx, &r.project_id).await?;
    let mut a = attempt_lock(tx, &r.project_id, &r.attempt_id).await?;
    if a.state != r.expected_state {
        return Err(err("REVISION_CONFLICT", "attempt state changed"));
    }
    valid_lease(tx, &a, r.generation, &r.worker_id).await?;
    if !a.state.can_transition(r.next_state)
        || r.next_state == AttemptState::Succeeded
        || r.next_state == AttemptState::Merging
        || r.next_state == AttemptState::Cancelled
    {
        return Err(err(
            "ILLEGAL_TRANSITION",
            "transition forbidden or reserved for cancellation/evidence/integration authority",
        ));
    }
    if r.next_state == AttemptState::Failed
        && !r
            .receipt
            .as_ref()
            .and_then(|v| v.get("process_exit_confirmed"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(err(
            "PROCESS_EXIT_UNCONFIRMED",
            "failure cannot release resources without confirmed stop",
        ));
    }
    if r.next_state == AttemptState::ReviewReady {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM evidence_receipts WHERE project_id=$1 AND attempt_id=$2 AND generation=$3").bind(&a.project_id).bind(&a.attempt_id).bind(a.generation).fetch_one(&mut **tx).await?;
        if count == 0 {
            return Err(err(
                "EVIDENCE_INCOMPLETE",
                "review readiness requires evidence receipt",
            ));
        }
    }
    if r.next_state.is_terminal() {
        crate::handoff::strict_release_guard(tx, &a).await?;
    }
    a.state = r.next_state;
    a.revision += 1;
    a.result = r.receipt.clone();
    if a.state == AttemptState::Stopping {
        revoke(tx, &a).await?;
        outbox(tx,&a.project_id,&id(),"attempt.stop",serde_json::json!({"attempt_id":a.attempt_id,"generation":a.generation,"reason":r.reason})).await?;
    }
    if a.state == AttemptState::RecoveryRequired {
        revoke(tx, &a).await?;
        sqlx::query("UPDATE resource_allocations SET state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'").bind(&a.attempt_id).execute(&mut **tx).await?;
    }
    if a.state.is_terminal() {
        a.terminal_at = Some(db_now(tx).await?);
        revoke(tx, &a).await?;
        release(tx, &a, &r.reason).await?;
    }
    if a.state == AttemptState::Running {
        sqlx::query(
            "UPDATE resource_allocations SET state='HELD' WHERE attempt_id=$1 AND state='RESERVED'",
        )
        .bind(&a.attempt_id)
        .execute(&mut **tx)
        .await?;
    }
    persist_attempt(tx, &a).await?;
    event(
        tx,
        &a.project_id,
        &a.attempt_id,
        a.revision,
        "attempt.transitioned",
        serde_json::json!({"attempt":a,"reason":r.reason}),
    )
    .await?;
    Ok(a)
}

#[cfg(test)]
mod next_root_session_tests {
    // Pure extraction/namespace counterexamples. No PostgreSQL, raw-file
    // verification, API authentication or real CLI qualification is asserted.
    use super::*;
    use serde_json::json;

    fn profile() -> Value {
        json!({"id":"claude-profile","kind":"CLAUDE_CODE_LEAF"})
    }
    fn claude_event() -> WorkerEvent {
        let id = "operation-1:native-00000000000000000001";
        WorkerEvent {
            event_id: id.into(),
            project_id: "project-1".into(),
            attempt_id: "attempt-1".into(),
            lease_id: "lease-1".into(),
            generation: 1,
            worker_id: "worker-1".into(),
            kind: "EXECUTOR_EVENT".into(),
            payload: json!({"sequence":1,"native_type":"system","payload":{"type":"system","subtype":"init","session_id":"root-1"},
                "parse_error":null,"driver_id":"CLAUDE_CODE","executor_kind":"CLAUDE_CODE_LEAF",
                "native_event_contract":"PARTIAL_RESTRICTED_RAW_PROJECTION","raw_sha256":"a".repeat(64),"raw_bytes":64,
                "payload_in_artifact":true,"event_id":id,"project_id":"project-1","attempt_id":"attempt-1",
                "execution_id":"execution-1","source":"claude_code_leaf","source_sequence":1,
                "source_sequence_kind":"WORKER_RECEIVE_ORDER","received_at":"2026-10-15T00:00:00Z",
                "event_type":"system","completeness":"UPSTREAM_COMMITTED_PROJECTION",
                "raw_artifact_ref":{"storage":"WORKER_LOCAL_FILE","path":"/nonexistent/worker-private/raw.ndjson","sha256":"a".repeat(64),"bytes":64}}),
        }
    }
    fn candidate(event: &WorkerEvent, frozen: &Value) -> Result<Option<String>> {
        native_root_session_candidate(event, frozen, "operation-1").map(|id| id.map(str::to_owned))
    }
    fn protocol_error(result: Result<Option<String>>) {
        match result {
            Err(StoreError::Domain(error)) => assert_eq!(error.code, "EXECUTOR_PROTOCOL_ERROR"),
            other => panic!("expected protocol rejection, got {other:?}"),
        }
    }
    fn attempt() -> Attempt {
        Attempt {
            project_id: "project-1".into(),
            task_id: "task-1".into(),
            task_revision: 1,
            attempt_id: "attempt-1".into(),
            lease_id: "lease-1".into(),
            generation: 1,
            worker_id: "worker-1".into(),
            operation_id: "operation-1".into(),
            base_sha: "b".repeat(40),
            state: AttemptState::Running,
            revision: 1,
            created_at: Utc::now(),
            terminal_at: None,
            result: None,
        }
    }

    #[test]
    fn root_init_allows_absent_or_null_parent_without_reading_worker_file() {
        let mut event = claude_event();
        assert_eq!(
            candidate(&event, &profile()).unwrap().as_deref(),
            Some("root-1")
        );
        event.payload["payload"]["parent_tool_use_id"] = Value::Null;
        assert_eq!(
            candidate(&event, &profile()).unwrap().as_deref(),
            Some("root-1")
        );
        // The deliberately nonexistent path above must never be opened by Store.
    }
    #[test]
    fn child_init_is_observation_and_cannot_become_root() {
        let mut event = claude_event();
        event.payload["payload"]["parent_tool_use_id"] = json!("parent-tool-1");
        event.payload["payload"]["session_id"] = json!("child-session");
        assert_eq!(candidate(&event, &profile()).unwrap(), None);
        for parent in [json!(""), json!(false), json!(1), json!({})] {
            event.payload["payload"]["parent_tool_use_id"] = parent;
            protocol_error(candidate(&event, &profile()));
        }
    }
    #[test]
    fn mutable_or_wrong_profile_does_not_enable_claude_root() {
        let event = claude_event();
        for frozen in [
            Value::Null,
            json!({"kind":"DSH_MANAGED"}),
            json!({"kind":"DSH_HEADLESS"}),
        ] {
            protocol_error(candidate(&event, &frozen));
        }
    }
    #[test]
    fn dsh_session_shape_is_preserved_and_cannot_impersonate_claude() {
        let mut event = claude_event();
        event.payload = json!({"native_type":"session","payload":{"sessionId":"dsh-session"}});
        assert_eq!(
            candidate(&event, &json!({"kind":"DSH_HEADLESS"}))
                .unwrap()
                .as_deref(),
            Some("dsh-session")
        );
        assert_eq!(
            candidate(&event, &Value::Null).unwrap().as_deref(),
            Some("dsh-session")
        );
        protocol_error(candidate(&event, &profile()));
        event.payload["source"] = json!("claude_code_leaf");
        protocol_error(candidate(&event, &json!({"kind":"DSH_HEADLESS"})));
    }
    #[test]
    fn only_root_shaped_executor_frames_load_profile_or_bind() {
        let mut event = claude_event();
        event.kind = "LOG".into();
        assert!(!native_root_profile_needed(&event));
        assert_eq!(candidate(&event, &profile()).unwrap(), None);
        for kind in ["assistant", "user", "stream_event", "result"] {
            event = claude_event();
            event.payload["native_type"] = json!(kind);
            event.payload["payload"] = json!({"type":kind,"session_id":"root-1"});
            assert!(!native_root_profile_needed(&event));
            assert_eq!(candidate(&event, &profile()).unwrap(), None);
        }
    }
    #[test]
    fn root_markers_must_agree_with_real_native_system_init() {
        for field in [
            "source",
            "driver_id",
            "executor_kind",
            "native_event_contract",
            "native_type",
            "event_type",
            "completeness",
            "source_sequence_kind",
        ] {
            let mut event = claude_event();
            event.payload[field] = json!("wrong");
            protocol_error(candidate(&event, &profile()));
        }
        let mut event = claude_event();
        event.payload["payload"]["type"] = json!("assistant");
        protocol_error(candidate(&event, &profile()));
        event = claude_event();
        event.payload["parse_error"] = json!("CLAUDE_INVALID_INIT");
        protocol_error(candidate(&event, &profile()));
        event = claude_event();
        event.payload["payload_in_artifact"] = json!(false);
        protocol_error(candidate(&event, &profile()));
    }
    #[test]
    fn duplicate_outer_project_attempt_or_event_identity_must_match() {
        for field in ["project_id", "attempt_id", "event_id"] {
            let mut event = claude_event();
            event.payload[field] = json!("different");
            protocol_error(candidate(&event, &profile()));
        }
        let mut event = claude_event();
        event.event_id = "operation-other:native-00000000000000000001".into();
        event.payload["event_id"] = json!(event.event_id);
        protocol_error(candidate(&event, &profile()));
    }
    #[test]
    fn malformed_sequence_execution_or_receive_time_cannot_bind() {
        for value in [json!(0), json!(u64::MAX), json!("1")] {
            let mut event = claude_event();
            event.payload["sequence"] = value;
            protocol_error(candidate(&event, &profile()));
        }
        for (field, value) in [
            ("source_sequence", json!(2)),
            ("execution_id", json!("")),
            ("received_at", json!("bad")),
        ] {
            let mut event = claude_event();
            event.payload[field] = value;
            protocol_error(candidate(&event, &profile()));
        }
    }
    #[test]
    fn raw_reference_is_internal_metadata_not_server_file_or_cas_authority() {
        for (field, value) in [
            ("storage", json!("CAS")),
            ("path", json!("relative/path")),
            ("sha256", json!("b".repeat(64))),
            ("bytes", json!(65)),
        ] {
            let mut event = claude_event();
            event.payload["raw_artifact_ref"][field] = value;
            protocol_error(candidate(&event, &profile()));
        }
        for (field, value) in [("raw_bytes", json!(0)), ("raw_sha256", json!("not-a-sha"))] {
            let mut event = claude_event();
            event.payload[field] = value;
            protocol_error(candidate(&event, &profile()));
        }
    }
    #[test]
    fn malformed_root_session_is_rejected_without_normalizing_opaque_identity() {
        for session in [
            json!(""),
            json!(" "),
            json!("x".repeat(257)),
            json!("bad\u{0}id"),
            json!(1),
        ] {
            let mut event = claude_event();
            event.payload["payload"]["session_id"] = session;
            protocol_error(candidate(&event, &profile()));
        }
        let mut event = claude_event();
        event.payload["payload"]["session_id"] = json!("opaque:1/raw");
        assert_eq!(
            candidate(&event, &profile()).unwrap().as_deref(),
            Some("opaque:1/raw")
        );
    }
    #[test]
    fn namespace_policy_refuses_root_replacement_and_other_project_attempt_worker_generation() {
        let a = attempt();
        assert!(
            validate_native_root_owner(
                &a,
                "root-1",
                "project-1",
                "attempt-1",
                1,
                "worker-1",
                "root-1"
            )
            .is_ok()
        );
        for (project, attempt_id, generation, worker, session) in [
            ("project-2", "attempt-1", 1, "worker-1", "root-1"),
            ("project-1", "attempt-2", 1, "worker-1", "root-1"),
            ("project-1", "attempt-1", 2, "worker-1", "root-1"),
            ("project-1", "attempt-1", 1, "worker-2", "root-1"),
            ("project-1", "attempt-1", 1, "worker-1", "old-root"),
        ] {
            let error = validate_native_root_owner(
                &a, "root-1", project, attempt_id, generation, worker, session,
            )
            .unwrap_err();
            assert!(
                matches!(error,StoreError::Domain(domain) if domain.code=="EXECUTOR_PROTOCOL_ERROR")
            );
        }
    }
}

pub(crate) async fn confirm_stop_tx(
    tx: &mut Transaction<'_, Postgres>,
    r: StopReceipt,
) -> Result<Attempt> {
    project_lock(tx, &r.project_id).await?;
    let mut a = attempt_lock(tx, &r.project_id, &r.attempt_id).await?;
    if a.generation != r.generation || a.worker_id != r.worker_id {
        return Err(err("LEASE_STALE", "stop receipt identity mismatch"));
    }
    if a.state == AttemptState::Cancelled {
        return Ok(a);
    }
    if !matches!(
        a.state,
        AttemptState::Stopping | AttemptState::RecoveryRequired
    ) || !r.process_exit_confirmed
    {
        return Err(err(
            "PROCESS_EXIT_UNCONFIRMED",
            "reliable stop proof required",
        ));
    }
    Store::collaboration_process_stopped_with_evidence_in_transaction(tx, &a, &r.evidence, None)
        .await?;
    crate::handoff::strict_release_guard(tx, &a).await?;
    a.state = AttemptState::Cancelled;
    a.revision += 1;
    a.result = Some(r.evidence);
    a.terminal_at = Some(db_now(tx).await?);
    revoke(tx, &a).await?;
    release(tx, &a, "confirmed stop").await?;
    persist_attempt(tx, &a).await?;
    event(
        tx,
        &a.project_id,
        &a.attempt_id,
        a.revision,
        "attempt.stopped",
        json(&a)?,
    )
    .await?;
    Ok(a)
}

// The durable receipt survives an intent entering RECOVERY_REQUIRED. Callers
// hold the coordination/project/Attempt locks shared with merge decisions.
async fn irreversible_merge_decision(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 AND (state IN('COMMIT_DECIDED','REF_UPDATED','FINALIZED','COMMITTED') OR data->'receipt'->>'commit_decided'='true'))")
        .bind(&a.project_id).bind(&a.attempt_id).fetch_one(&mut **tx).await?)
}

pub(crate) async fn worker_result_tx(
    tx: &mut Transaction<'_, Postgres>,
    r: WorkerResult,
) -> Result<Attempt> {
    project_lock(tx, &r.project_id).await?;
    let mut a = attempt_lock(tx, &r.project_id, &r.attempt_id).await?;
    let payload = json(&r)?;
    if let Some(old) =
        sqlx::query_scalar::<_, Value>("SELECT payload FROM worker_event_ids WHERE event_id=$1")
            .bind(&r.event_id)
            .fetch_optional(&mut **tx)
            .await?
    {
        if old != payload {
            return Err(err("IDEMPOTENCY_CONFLICT", "result event reused"));
        }
        return Ok(a);
    }
    if a.lease_id != r.lease_id || a.worker_id != r.worker_id || a.generation != r.generation {
        return Err(err("LEASE_STALE", "result identity mismatch"));
    }
    if matches!(
        a.state,
        AttemptState::Stopping | AttemptState::RecoveryRequired
    ) {
        if !r
            .evidence
            .get("process_exit_confirmed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(err(
                "PROCESS_EXIT_UNCONFIRMED",
                "stop result must confirm process exit",
            ));
        }
        if irreversible_merge_decision(tx, &a).await? {
            // Author termination does not undo the durable Git decision. Keep
            // custody, including native loans and lease state, for Owner recovery;
            // validate the same exact stop facts without running release helpers.
            super::collaboration::validate_physical_stop(
                tx,
                &a,
                &r.evidence,
                Some(&r.outcome.execution_id),
            )
            .await?;
            a.state = AttemptState::RecoveryRequired;
            a.terminal_at = None;
        } else {
            Store::collaboration_process_stopped_with_evidence_in_transaction(
                tx,
                &a,
                &r.evidence,
                Some(&r.outcome.execution_id),
            )
            .await?;
            crate::handoff::strict_release_guard(tx, &a).await?;
            a.state = AttemptState::Cancelled;
            a.terminal_at = Some(db_now(tx).await?);
            release(tx, &a, "worker confirmed stop").await?;
        }
    } else {
        valid_lease(tx, &a, r.generation, &r.worker_id).await?;
        if !matches!(a.state, AttemptState::Starting | AttemptState::Running) {
            return Err(err(
                "ILLEGAL_TRANSITION",
                "execution result only from started attempt",
            ));
        }
        if !r
            .evidence
            .get("process_exit_confirmed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(err(
                "PROCESS_EXIT_UNCONFIRMED",
                "execution result requires reliable exit proof",
            ));
        }
        Store::collaboration_process_stopped_with_evidence_in_transaction(
            tx,
            &a,
            &r.evidence,
            Some(&r.outcome.execution_id),
        )
        .await?;
        if r.outcome.completion_reason == "EXECUTOR_COMPLETED"
            && r.outcome.exit_code == Some(0)
            && r.evidence.get("log_error").is_none_or(Value::is_null)
        {
            a.state = AttemptState::Verifying;
        } else {
            crate::handoff::strict_release_guard(tx, &a).await?;
            a.state = AttemptState::Failed;
            a.terminal_at = Some(db_now(tx).await?);
            revoke(tx, &a).await?;
            release(tx, &a, "execution failed and process stop confirmed").await?;
        }
    }
    a.revision += 1;
    a.result = Some(payload.clone());
    persist_attempt(tx, &a).await?;
    sqlx::query("INSERT INTO worker_event_ids VALUES($1,$2,$3,$4)")
        .bind(&r.event_id)
        .bind(&r.project_id)
        .bind(&r.attempt_id)
        .bind(&payload)
        .execute(&mut **tx)
        .await?;
    event(
        tx,
        &a.project_id,
        &a.attempt_id,
        a.revision,
        "attempt.execution_returned",
        payload,
    )
    .await?;
    Ok(a)
}
