//! Trusted Gateway consumption of an existing native model budget grant.
//! A committed consumption is deliberately never replayable as connection rights.
use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModelDispatchRequest {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub native_session_id: String,
    pub allocation_id: String,
    pub request_id: String,
    pub request_grant_id: String,
    pub route_id: String,
    pub provider: String,
    pub model: String,
    pub max_output_tokens: u64,
    /// SHA256 of the exact body bytes the trusted Gateway will forward.
    pub body_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeModelDispatchReceipt {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub native_session_id: String,
    pub allocation_id: String,
    pub request_id: String,
    pub request_grant_id: String,
    pub route_id: String,
    pub provider: String,
    pub model: String,
    pub max_output_tokens: u64,
    pub body_sha256: String,
    pub lease_id: String,
    pub operation_id: String,
    pub dispatched_at: DateTime<Utc>,
    /// Immutable registered route snapshot, never a caller-supplied upstream URL.
    pub route: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModelTransportObservation {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub native_session_id: String,
    pub allocation_id: String,
    pub request_id: String,
    pub request_grant_id: String,
    pub body_sha256: String,
    /// RESPONSE_BODY_COMPLETED only after actual EOF; all uncertain paths interrupt.
    pub outcome: String,
    pub upstream_status: Option<u16>,
    pub received_bytes: u64,
    /// Trusted proxy-observed normalized numeric usage, not native caller claims.
    #[serde(default)]
    pub usage: Option<Value>,
    #[serde(default)]
    pub usage_complete: bool,
}

impl Store {
    /// Trusted server callback AFTER dropping/draining the upstream transport.
    /// Lease revocation does not invalidate cleanup observations. It never itself
    /// releases a grant or treats EOF as proof of known financial usage.
    pub async fn record_native_transport_observation(
        &self,
        observation: NativeModelTransportObservation,
    ) -> Result<()> {
        let r = &observation;
        if !matches!(
            r.outcome.as_str(),
            "RESPONSE_BODY_COMPLETED" | "RESPONSE_INTERRUPTED"
        ) || r.upstream_status.is_some_and(|s| !(100..=599).contains(&s))
            || r.usage.as_ref().is_some_and(|v| !v.is_object())
            || serde_json::to_vec(&r.usage)?.len() > 16384
            || (r.usage_complete && r.usage.is_none())
        {
            return Err(err(
                "NATIVE_DISPATCH_INVALID",
                "bounded trusted transport observation required",
            ));
        }
        i64v(r.received_bytes)?;
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        project_lock(&mut tx, &r.project_id).await?;
        let a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        if a.generation != r.generation || a.worker_id != r.worker_id {
            return Err(err(
                "NATIVE_IDENTITY_STALE",
                "original dispatch Worker/generation required for cleanup",
            ));
        }
        let grant = sqlx::query("SELECT dispatch_transport_settlement FROM native_model_requests WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 AND worker_id=$4 AND allocation_id=$5 AND native_session_id=$6 AND request_id=$7 AND request_grant_id=$8 AND dispatched_at IS NOT NULL AND dispatch_body_sha256=$9 FOR UPDATE")
            .bind(&r.project_id).bind(&r.attempt_id).bind(r.generation).bind(&r.worker_id)
            .bind(&r.allocation_id).bind(&r.native_session_id).bind(&r.request_id).bind(&r.request_grant_id).bind(&r.body_sha256)
            .fetch_optional(&mut *tx).await?.ok_or_else(|| err("NATIVE_IDENTITY_STALE", "exact consumed dispatch and body digest required"))?;
        let value = serde_json::to_value(r)?;
        if let Some(old) = grant.get::<Option<Value>, _>("dispatch_transport_settlement") {
            if old != value {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "trusted transport closure is immutable",
                ));
            }
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query(
            "UPDATE native_model_requests SET dispatch_transport_settlement=$2 WHERE request_id=$1",
        )
        .bind(&r.request_id)
        .bind(&value)
        .execute(&mut *tx)
        .await?;
        if r.outcome == "RESPONSE_INTERRUPTED" {
            sqlx::query("UPDATE native_model_requests SET status='QUARANTINED' WHERE request_id=$1 AND status='ADMITTED'")
                .bind(&r.request_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE native_child_lifecycles SET state='QUARANTINED',revoked=true WHERE allocation_id=$1 AND state<>'RELEASED'")
                .bind(&r.allocation_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE native_child_allocations SET state='QUARANTINED' WHERE allocation_id=$1 AND state<>'RELEASED'")
                .bind(&r.allocation_id).execute(&mut *tx).await?;
        }
        event(&mut tx, &r.project_id, &r.request_id, 2, "native_model.transport_observed", serde_json::json!({
            "attempt_id":r.attempt_id,"generation":r.generation,"allocation_id":r.allocation_id,
            "request_grant_id":r.request_grant_id,"body_sha256":r.body_sha256,
            "outcome":r.outcome,"upstream_status":r.upstream_status,"received_bytes":r.received_bytes,
            "usage_complete":r.usage_complete,"source":"TRUSTED_GATEWAY"
        })).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Call before ANY upstream DNS/socket/HTTP operation. Authenticated caller
    /// identity and the body hash must be supplied by the trusted server. This
    /// neither admits another request nor inserts a model_request_permit.
    /// Even identical retries fail: a response lost after commit is uncertain,
    /// not permission for a second external effect. Existing settlement remains
    /// keyed by the original request_id/request_grant_id and retains its budget.
    pub async fn consume_native_dispatch(
        &self,
        r: NativeModelDispatchRequest,
    ) -> Result<NativeModelDispatchReceipt> {
        for value in [
            &r.project_id,
            &r.attempt_id,
            &r.worker_id,
            &r.native_session_id,
            &r.route_id,
            &r.provider,
            &r.model,
        ] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(err(
                    "NATIVE_DISPATCH_INVALID",
                    "bounded nonempty dispatch identities required",
                ));
            }
        }
        for value in [&r.allocation_id, &r.request_id, &r.request_grant_id] {
            if Uuid::parse_str(value).is_err() {
                return Err(err(
                    "NATIVE_DISPATCH_INVALID",
                    "canonical native grant UUID required",
                ));
            }
        }
        if r.generation <= 0
            || r.max_output_tokens == 0
            || r.body_sha256.len() != 64
            || !r
                .body_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(err(
                "NATIVE_DISPATCH_INVALID",
                "positive generation/output cap and lowercase SHA256 required",
            ));
        }
        let cap = i64v(r.max_output_tokens)?;
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let p = project_lock(&mut tx, &r.project_id).await?;
        let a = attempt_lock(&mut tx, &r.project_id, &r.attempt_id).await?;
        valid_lease(&mut tx, &a, r.generation, &r.worker_id).await?;
        if p.authority_mode != AuthorityMode::Managed
            || p.paused
            || p.archived
            || !matches!(a.state, AttemptState::Starting | AttemptState::Running)
        {
            return Err(err(
                "NATIVE_ADMISSION_BLOCKED",
                "active managed parent required for model dispatch",
            ));
        }
        let claimed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbox o JOIN attempts a ON a.project_id=o.project_id AND a.operation_id=o.operation_id JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id WHERE o.project_id=$1 AND o.operation_id=$2 AND o.kind='attempt.start' AND o.claimed_by=$3 AND o.delivered_at IS NOT NULL AND o.payload->>'project_id'=a.project_id AND o.payload->>'task_id'=a.task_id AND o.payload->>'attempt_id'=a.attempt_id AND o.payload->>'operation_id'=a.operation_id AND o.payload->>'lease_id'=a.lease_id AND o.payload->>'worker_id'=a.worker_id AND o.payload->'generation'=to_jsonb(a.generation) AND t.task_revision=a.task_revision)")
            .bind(&r.project_id).bind(&a.operation_id).bind(&r.worker_id).fetch_one(&mut *tx).await?;
        let paused: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks t JOIN owner_closure c ON c.project_id=t.project_id AND c.descendant_id=t.team_id JOIN owner_nodes n ON n.project_id=c.project_id AND n.owner_id=c.ancestor_id WHERE t.project_id=$1 AND t.task_id=$2 AND n.paused)")
            .bind(&r.project_id).bind(&a.task_id).fetch_one(&mut *tx).await?;
        if !claimed || paused {
            return Err(err(
                "NATIVE_ADMISSION_BLOCKED",
                "claimed start and unpaused team ancestors required",
            ));
        }
        let row = sqlx::query("SELECT execution_bindings,envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2")
            .bind(&r.project_id).bind(&r.attempt_id).fetch_one(&mut *tx).await?;
        let bindings: Value = row.get("execution_bindings");
        let envelope: ExecutionEnvelope = decode(row.get("envelope"))?;
        envelope.validate()?;
        if envelope.project_id != a.project_id
            || envelope.task_id != a.task_id
            || envelope.task_revision != a.task_revision
            || envelope.attempt_id != a.attempt_id
            || envelope.lease_id != a.lease_id
            || envelope.worker_id != a.worker_id
            || envelope.generation != a.generation
            || envelope.operation_id != a.operation_id
            || !envelope
                .allowed_effects
                .contains(&AllowedEffect::RequestApprovedModel)
        {
            return Err(err(
                "NATIVE_MODEL_EFFECT_DENIED",
                "exact frozen model effect binding required",
            ));
        }
        let deadline = DateTime::parse_from_rfc3339(&envelope.deadline_at)
            .map_err(|_| err("NATIVE_POLICY_INVALID", "frozen deadline invalid"))?;
        if deadline.with_timezone(&Utc) <= db_now(&mut tx).await? {
            return Err(err("LEASE_STALE", "parent execution deadline expired"));
        }
        let route = bindings
            .get("model_route")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or_else(|| {
                err(
                    "NATIVE_ROUTE_INVALID",
                    "immutable registered model route required",
                )
            })?;
        if envelope.model_route_id != r.route_id
            || route.get("provider").and_then(Value::as_str) != Some(r.provider.as_str())
            || route.get("model").and_then(Value::as_str) != Some(r.model.as_str())
            || route.get("max_output_tokens").and_then(Value::as_u64) != Some(r.max_output_tokens)
        {
            return Err(err(
                "NATIVE_ROUTE_INVALID",
                "dispatch differs from exact frozen route/provider/model/cap",
            ));
        }
        let lifecycle = sqlx::query("SELECT * FROM native_child_lifecycles WHERE allocation_id=$1 AND project_id=$2 AND attempt_id=$3 AND generation=$4 AND worker_id=$5 AND native_session_id=$6 FOR UPDATE")
            .bind(&r.allocation_id).bind(&r.project_id).bind(&r.attempt_id).bind(r.generation).bind(&r.worker_id).bind(&r.native_session_id)
            .fetch_optional(&mut *tx).await?.ok_or_else(|| err("NATIVE_IDENTITY_STALE", "exact native allocation identity required"))?;
        let lineage_live: bool = sqlx::query_scalar("WITH RECURSIVE ancestry AS (SELECT allocation_id,parent_allocation_id,state,revoked,disposed_at,process_stopped_at FROM native_child_lifecycles WHERE allocation_id=$1 UNION SELECT p.allocation_id,p.parent_allocation_id,p.state,p.revoked,p.disposed_at,p.process_stopped_at FROM native_child_lifecycles p JOIN ancestry c ON p.allocation_id=c.parent_allocation_id) SELECT EXISTS(SELECT 1 FROM ancestry) AND NOT EXISTS(SELECT 1 FROM ancestry WHERE state<>'HELD' OR revoked OR disposed_at IS NOT NULL OR process_stopped_at IS NOT NULL)")
            .bind(&r.allocation_id).fetch_one(&mut *tx).await?;
        let revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND revoked AND state<>'RELEASED')")
            .bind(&r.attempt_id).fetch_one(&mut *tx).await?;
        if !lineage_live || revoked {
            return Err(err(
                "NATIVE_IDENTITY_STALE",
                "native grant and every ancestor must remain held/live",
            ));
        }
        if lifecycle.get::<String, _>("provider") != r.provider
            || lifecycle.get::<String, _>("model") != r.model
            || lifecycle.get::<i64, _>("max_output_tokens") != cap
        {
            return Err(err(
                "NATIVE_ROUTE_INVALID",
                "dispatch differs from native lifecycle route",
            ));
        }
        let grant = sqlx::query("SELECT status,dispatched_at,provider,model,max_output_tokens FROM native_model_requests WHERE request_id=$1 AND request_grant_id=$2 AND project_id=$3 AND attempt_id=$4 AND generation=$5 AND worker_id=$6 AND allocation_id=$7 AND native_session_id=$8 FOR UPDATE")
            .bind(&r.request_id).bind(&r.request_grant_id).bind(&r.project_id).bind(&r.attempt_id).bind(r.generation).bind(&r.worker_id).bind(&r.allocation_id).bind(&r.native_session_id)
            .fetch_optional(&mut *tx).await?.ok_or_else(|| err("NATIVE_IDENTITY_STALE", "exact previously admitted native model grant required"))?;
        if grant.get::<String, _>("status") != "ADMITTED" {
            return Err(err(
                "NATIVE_IDENTITY_STALE",
                "settled/quarantined request cannot dispatch",
            ));
        }
        if grant
            .get::<Option<DateTime<Utc>>, _>("dispatched_at")
            .is_some()
        {
            return Err(err(
                "NATIVE_DISPATCH_ALREADY_CONSUMED",
                "grant already consumed; uncertain dispatch cannot reconnect",
            ));
        }
        if grant.get::<String, _>("provider") != r.provider
            || grant.get::<String, _>("model") != r.model
            || grant.get::<i64, _>("max_output_tokens") != cap
        {
            return Err(err(
                "NATIVE_ROUTE_INVALID",
                "dispatch differs from admitted request route",
            ));
        }
        let dispatched_at: DateTime<Utc> = sqlx::query_scalar("UPDATE native_model_requests SET dispatched_at=clock_timestamp(),dispatch_body_sha256=$2 WHERE request_id=$1 AND status='ADMITTED' AND dispatched_at IS NULL RETURNING dispatched_at")
            .bind(&r.request_id).bind(&r.body_sha256).fetch_optional(&mut *tx).await?
            .ok_or_else(|| err("NATIVE_DISPATCH_ALREADY_CONSUMED", "dispatch compare-and-set lost"))?;
        event(
            &mut tx,
            &r.project_id,
            &r.request_id,
            1,
            "native_model.dispatched",
            serde_json::json!({
                "attempt_id":r.attempt_id,"generation":r.generation,"worker_id":r.worker_id,
                "allocation_id":r.allocation_id,"native_session_id":r.native_session_id,
                "request_grant_id":r.request_grant_id,"route_id":r.route_id,
                "provider":r.provider,"model":r.model,"max_output_tokens":r.max_output_tokens,
                "body_sha256":r.body_sha256,"dispatched_at":dispatched_at,
                "budget_admission":"EXISTING_NATIVE_GRANT","upstream_connection_count_allowed":1
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(NativeModelDispatchReceipt {
            project_id: r.project_id,
            attempt_id: r.attempt_id,
            generation: r.generation,
            worker_id: r.worker_id,
            native_session_id: r.native_session_id,
            allocation_id: r.allocation_id,
            request_id: r.request_id,
            request_grant_id: r.request_grant_id,
            route_id: r.route_id,
            provider: r.provider,
            model: r.model,
            max_output_tokens: r.max_output_tokens,
            body_sha256: r.body_sha256,
            lease_id: a.lease_id,
            operation_id: a.operation_id,
            dispatched_at,
            route,
        })
    }
}
