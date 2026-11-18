//! PostgreSQL request permits. Lease/token expiry never silently releases inflight work.
use crate::{AdmissionDenied, ModelRequestPermit, RequestAuthority, RequestSettlement};
use async_trait::async_trait;
use axum::http::StatusCode;
use forgeflow_domain::{ExecutionEnvelope, ModelBudgetMode};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayBudgetLimits {
    pub per_attempt_inflight: i64,
    pub global_inflight: i64,
    pub project_inflight: i64,
    pub global_window_requests: i64,
    pub project_window_requests: i64,
    pub route_window_requests: i64,
    pub window_seconds: i64,
}
impl GatewayBudgetLimits {
    fn valid(&self) -> bool {
        [
            self.per_attempt_inflight,
            self.global_inflight,
            self.project_inflight,
            self.global_window_requests,
            self.project_window_requests,
            self.route_window_requests,
            self.window_seconds,
        ]
        .iter()
        .all(|n| *n > 0)
    }
}

#[derive(Clone)]
pub struct PgRequestAuthority {
    pool: PgPool,
    limits: GatewayBudgetLimits,
    /// Freeze at gateway construction; Worker cannot choose a model through natural language.
    route_models: BTreeMap<String, String>,
    issuer_seed: Option<Arc<String>>,
}
fn token_digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
fn denied(code: &str, status: StatusCode) -> AdmissionDenied {
    AdmissionDenied {
        code: code.into(),
        status,
    }
}
fn unavailable(_: sqlx::Error) -> AdmissionDenied {
    denied(
        "MODEL_BUDGET_AUTHORITY_UNAVAILABLE",
        StatusCode::SERVICE_UNAVAILABLE,
    )
}

async fn lock_global(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(46001337)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn lock_project(
    tx: &mut Transaction<'_, Postgres>,
    project_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT project_id FROM projects WHERE project_id=$1 FOR UPDATE")
        .bind(project_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(())
}

async fn request_event(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    request_id: &str,
    kind: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let sequence: i64 = sqlx::query_scalar(
        "UPDATE projects SET event_seq=event_seq+1 WHERE project_id=$1 RETURNING event_seq",
    )
    .bind(project)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO events(event_id,project_id,project_seq,object_id,object_revision,schema_version,kind,payload) VALUES($1,$2,$3,$4,1,'forgeflow.event.v1',$5,$6)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(project).bind(sequence).bind(request_id).bind(kind).bind(payload).execute(&mut **tx).await?;
    Ok(())
}

impl PgRequestAuthority {
    pub fn new(
        pool: PgPool,
        limits: GatewayBudgetLimits,
        route_models: BTreeMap<String, String>,
    ) -> Result<Self, String> {
        if !limits.valid() || route_models.is_empty() || route_models.values().any(|m| m.is_empty())
        {
            return Err("positive request limits and frozen route-model mapping required".into());
        }
        Ok(Self {
            pool,
            limits,
            route_models,
            issuer_seed: None,
        })
    }
    /// Stable owner-only server secret, persisted independently from public receipts/config.
    /// A changed seed cannot reset an existing attempt's budget or reissue a different scope.
    pub fn with_issuer_seed(mut self, seed: String) -> Result<Self, String> {
        if seed.len() < 32 || seed.len() > 4096 {
            return Err("gateway issuer seed must contain 32..4096 bytes".into());
        }
        self.issuer_seed = Some(Arc::new(seed));
        Ok(self)
    }
    /// Trusted control-plane issuance requires a persisted claimed start command.
    /// Max requests and deadline derive from the admitted envelope.
    /// Every request rechecks the current renewable lease, so heartbeat extends no task deadline.
    /// Existing active scopes are immutable. The returned secret is never persisted in plaintext.
    pub async fn issue_scope(
        &self,
        project_id: &str,
        attempt_id: &str,
    ) -> Result<String, AdmissionDenied> {
        let issuer = self.issuer_seed.as_ref().ok_or_else(|| {
            denied(
                "GATEWAY_SCOPE_ISSUER_UNCONFIGURED",
                StatusCode::SERVICE_UNAVAILABLE,
            )
        })?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_global(&mut tx).await.map_err(unavailable)?;
        lock_project(&mut tx, project_id)
            .await
            .map_err(unavailable)?;
        let row=sqlx::query(
            "SELECT a.envelope,a.generation,a.lease_id,a.worker_id,a.task_revision,a.task_id,l.expires_at,clock_timestamp() AS db_now \
             FROM attempts a JOIN leases l ON l.attempt_id=a.attempt_id AND l.lease_id=a.lease_id \
             JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id \
             JOIN outbox o ON o.project_id=a.project_id AND o.operation_id=a.operation_id \
                 AND o.kind='attempt.start' AND o.claimed_by=a.worker_id AND o.delivered_at IS NOT NULL \
                 AND o.payload->>'project_id'=a.project_id AND o.payload->>'attempt_id'=a.attempt_id \
                 AND o.payload->>'operation_id'=a.operation_id AND o.payload->>'lease_id'=a.lease_id \
                 AND o.payload->>'worker_id'=a.worker_id AND o.payload->'generation'=to_jsonb(a.generation) \
             WHERE a.project_id=$1 AND a.attempt_id=$2 AND a.state IN ('STARTING','RUNNING') \
                 AND l.revoked_at IS NULL AND l.expires_at>clock_timestamp() \
                 AND l.generation=a.generation AND l.worker_id=a.worker_id \
                 AND t.fence_epoch=a.generation AND t.task_revision=a.task_revision \
             FOR UPDATE OF a,l,t,o",
        )
            .bind(project_id).bind(attempt_id).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or_else(||denied("STALE_EXECUTION_AUTHORITY",StatusCode::FORBIDDEN))?;
        let envelope: ExecutionEnvelope = serde_json::from_value(row.get("envelope"))
            .map_err(|_| denied("INVALID_FROZEN_ENVELOPE", StatusCode::CONFLICT))?;
        envelope
            .validate()
            .map_err(|_| denied("INVALID_FROZEN_ENVELOPE", StatusCode::CONFLICT))?;
        if envelope.project_id != project_id
            || envelope.attempt_id != attempt_id
            || envelope.generation != row.get::<i64, _>("generation")
            || envelope.lease_id != row.get::<String, _>("lease_id")
            || envelope.worker_id != row.get::<String, _>("worker_id")
            || envelope.task_revision != row.get::<i64, _>("task_revision") as u64
            || envelope.task_id != row.get::<String, _>("task_id")
        {
            return Err(denied("INVALID_FROZEN_ENVELOPE", StatusCode::CONFLICT));
        }
        if envelope.enforcement.model_budget_mode != ModelBudgetMode::GatewayEnforced
            || envelope.max_model_requests == 0
            || !envelope
                .allowed_effects
                .contains(&forgeflow_domain::AllowedEffect::RequestApprovedModel)
        {
            return Err(denied(
                "GATEWAY_ENFORCEMENT_NOT_ADMITTED",
                StatusCode::FORBIDDEN,
            ));
        }
        let route = &envelope.model_route_id;
        let model = self
            .route_models
            .get(route)
            .ok_or_else(|| denied("FROZEN_MODEL_ROUTE_MISSING", StatusCode::CONFLICT))?;
        let framed = serde_json::to_vec(&(
            "forgeflow.gateway.scope.v1",
            project_id,
            attempt_id,
            &envelope.lease_id,
            envelope.generation,
            route,
            model,
        ))
        .map_err(|_| denied("INVALID_FROZEN_ENVELOPE", StatusCode::CONFLICT))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(issuer.as_bytes()).map_err(|_| {
            denied(
                "GATEWAY_SCOPE_ISSUER_UNCONFIGURED",
                StatusCode::SERVICE_UNAVAILABLE,
            )
        })?;
        mac.update(&framed);
        let token = format!("ffgw-{:x}", mac.finalize().into_bytes());
        let scope_deadline = chrono::DateTime::parse_from_rfc3339(&envelope.deadline_at)
            .map_err(|_| denied("INVALID_FROZEN_ENVELOPE", StatusCode::CONFLICT))?
            .with_timezone(&chrono::Utc);
        let scope_deadline = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(
            scope_deadline.timestamp_micros(),
        )
        .ok_or_else(|| denied("INVALID_FROZEN_ENVELOPE", StatusCode::CONFLICT))?;
        if scope_deadline <= row.get::<chrono::DateTime<chrono::Utc>, _>("db_now") {
            return Err(denied("STALE_EXECUTION_AUTHORITY", StatusCode::FORBIDDEN));
        }
        let existing=sqlx::query("SELECT token_sha256,model,generation,max_requests,inflight_limit,expires_at,revoked,expires_at<=clock_timestamp() AS expired FROM gateway_scope_budget WHERE attempt_id=$1 AND route_id=$2 FOR UPDATE")
            .bind(attempt_id).bind(route).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        if let Some(existing) = existing {
            if existing.get::<bool, _>("revoked") || existing.get::<bool, _>("expired") {
                return Err(denied("STALE_GATEWAY_SCOPE", StatusCode::FORBIDDEN));
            }
            if existing.get::<String, _>("token_sha256") != token_digest(&token)
                || existing.get::<String, _>("model") != *model
                || existing.get::<i64, _>("generation") != envelope.generation
                || existing.get::<i64, _>("max_requests") != i64::from(envelope.max_model_requests)
                || existing.get::<i64, _>("inflight_limit") != self.limits.per_attempt_inflight
                || existing.get::<chrono::DateTime<chrono::Utc>, _>("expires_at") != scope_deadline
            {
                return Err(denied(
                    "FROZEN_GATEWAY_SCOPE_MISMATCH",
                    StatusCode::CONFLICT,
                ));
            }
            tx.commit().await.map_err(unavailable)?;
            return Ok(token);
        }
        sqlx::query("INSERT INTO gateway_scope_budget(token_sha256,project_id,attempt_id,generation,route_id,model,max_requests,inflight_limit,requests_used,inflight,expires_at,revoked) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,0,$9,false)")
            .bind(token_digest(&token)).bind(project_id).bind(attempt_id).bind(row.get::<i64,_>("generation")).bind(route).bind(model).bind(i64::from(envelope.max_model_requests)).bind(self.limits.per_attempt_inflight).bind(scope_deadline).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(token)
    }
    pub async fn revoke_scope(
        &self,
        project_id: &str,
        attempt_id: &str,
    ) -> Result<(), AdmissionDenied> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_global(&mut tx).await.map_err(unavailable)?;
        lock_project(&mut tx, project_id)
            .await
            .map_err(unavailable)?;
        sqlx::query(
            "UPDATE gateway_scope_budget SET revoked=true WHERE project_id=$1 AND attempt_id=$2",
        )
        .bind(project_id)
        .bind(attempt_id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        // Existing permit inflight reservations remain held until actual stream settlement.
        tx.commit().await.map_err(unavailable)?;
        Ok(())
    }
}

#[async_trait]
impl RequestAuthority for PgRequestAuthority {
    async fn admit(
        &self,
        token: &str,
        route_id: &str,
        model: &str,
    ) -> Result<ModelRequestPermit, AdmissionDenied> {
        if token.len() > 256 || !token.starts_with("ffgw-") {
            return Err(denied("INVALID_GATEWAY_SCOPE", StatusCode::UNAUTHORIZED));
        }
        let hash = token_digest(token);
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_global(&mut tx).await.map_err(unavailable)?;
        let project: Option<String> =
            sqlx::query_scalar("SELECT project_id FROM gateway_scope_budget WHERE token_sha256=$1")
                .bind(&hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
        let project =
            project.ok_or_else(|| denied("INVALID_GATEWAY_SCOPE", StatusCode::UNAUTHORIZED))?;
        lock_project(&mut tx, &project).await.map_err(unavailable)?;
        let row=sqlx::query(
            "SELECT b.attempt_id,b.route_id,b.model,b.generation,b.max_requests,b.requests_used,b.inflight,b.inflight_limit \
             FROM gateway_scope_budget b JOIN attempts a ON a.attempt_id=b.attempt_id AND a.project_id=b.project_id \
             JOIN leases l ON l.lease_id=a.lease_id AND l.attempt_id=a.attempt_id \
             JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id \
             JOIN outbox o ON o.project_id=a.project_id AND o.operation_id=a.operation_id \
                 AND o.kind='attempt.start' AND o.claimed_by=a.worker_id AND o.delivered_at IS NOT NULL \
                 AND o.payload->>'project_id'=a.project_id AND o.payload->>'attempt_id'=a.attempt_id \
                 AND o.payload->>'operation_id'=a.operation_id AND o.payload->>'lease_id'=a.lease_id \
                 AND o.payload->>'worker_id'=a.worker_id AND o.payload->'generation'=to_jsonb(a.generation) \
             WHERE b.token_sha256=$1 AND NOT b.revoked AND b.expires_at>clock_timestamp() \
                 AND a.state IN ('STARTING','RUNNING') AND l.revoked_at IS NULL AND l.expires_at>clock_timestamp() \
                 AND b.generation=a.generation AND l.generation=a.generation AND l.worker_id=a.worker_id \
                 AND t.fence_epoch=a.generation AND t.task_revision=a.task_revision \
             FOR UPDATE OF b,a,l,t,o",
        )
            .bind(&hash).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or_else(||denied("STALE_EXECUTION_AUTHORITY",StatusCode::FORBIDDEN))?;
        if row.get::<String, _>("route_id") != route_id
            || row.get::<String, _>("model") != model
            || self.route_models.get(route_id).map(String::as_str) != Some(model)
        {
            return Err(denied("FROZEN_MODEL_ROUTE_MISMATCH", StatusCode::FORBIDDEN));
        }
        if row.get::<i64, _>("requests_used") >= row.get::<i64, _>("max_requests")
            || row.get::<i64, _>("inflight") >= row.get::<i64, _>("inflight_limit")
        {
            return Err(denied(
                "WAITING_MODEL_BUDGET",
                StatusCode::TOO_MANY_REQUESTS,
            ));
        }
        let counts=sqlx::query("SELECT COUNT(*) FILTER(WHERE p.status IN ('ADMITTED','QUARANTINED')) AS global_inflight,COUNT(*) FILTER(WHERE p.status IN ('ADMITTED','QUARANTINED') AND b.project_id=$1) AS project_inflight,COUNT(*) FILTER(WHERE p.admitted_at>clock_timestamp()-make_interval(secs=>$2::double precision)) AS global_requests,COUNT(*) FILTER(WHERE p.admitted_at>clock_timestamp()-make_interval(secs=>$2::double precision) AND b.project_id=$1) AS project_requests,COUNT(*) FILTER(WHERE p.admitted_at>clock_timestamp()-make_interval(secs=>$2::double precision) AND p.route_id=$3) AS route_requests FROM model_request_permit p JOIN gateway_scope_budget b ON b.token_sha256=p.scope_token_digest")
            .bind(&project).bind(self.limits.window_seconds as f64).bind(route_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
        for (field, limit) in [
            ("global_inflight", self.limits.global_inflight),
            ("project_inflight", self.limits.project_inflight),
            ("global_requests", self.limits.global_window_requests),
            ("project_requests", self.limits.project_window_requests),
            ("route_requests", self.limits.route_window_requests),
        ] {
            if counts.get::<i64, _>(field) >= limit {
                return Err(denied(
                    "WAITING_MODEL_BUDGET",
                    StatusCode::TOO_MANY_REQUESTS,
                ));
            }
        }
        let permit = ModelRequestPermit {
            request_id: uuid::Uuid::new_v4().to_string(),
            attempt_id: row.get("attempt_id"),
            route_id: route_id.into(),
            model: model.into(),
            generation: row.get("generation"),
        };
        sqlx::query("UPDATE gateway_scope_budget SET requests_used=requests_used+1,inflight=inflight+1 WHERE token_sha256=$1").bind(&hash).execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO model_request_permit(request_id,scope_token_digest,attempt_id,route_id,model,generation,admitted_at,status) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp(),'ADMITTED')")
            .bind(&permit.request_id).bind(&hash).bind(&permit.attempt_id).bind(route_id).bind(model).bind(permit.generation).execute(&mut *tx).await.map_err(unavailable)?;
        let observed = serde_json::json!({"request_id":permit.request_id,"attempt_id":permit.attempt_id,"route_id":permit.route_id,"model":permit.model,"generation":permit.generation,"outcome":"ADMITTED","usage":null,"usage_completeness":"UNKNOWN"});
        sqlx::query("INSERT INTO provider_requests(project_id,request_id,attempt_id,data) VALUES($1,$2,$3,$4)").bind(&project).bind(&permit.request_id).bind(&permit.attempt_id).bind(&observed).execute(&mut *tx).await.map_err(unavailable)?;
        request_event(
            &mut tx,
            &project,
            &permit.request_id,
            "ModelRequestAdmitted",
            observed,
        )
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(permit)
    }
    async fn settle(&self, settlement: RequestSettlement) -> Result<(), String> {
        if settlement.outcome.is_empty()
            || matches!(
                settlement.outcome.as_str(),
                "ADMITTED" | "STREAMING" | "CONNECTING"
            )
        {
            return Err("nonterminal model settlement rejected".into());
        }
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        lock_global(&mut tx).await.map_err(|e| e.to_string())?;
        let row=sqlx::query("SELECT p.scope_token_digest,b.project_id FROM model_request_permit p JOIN gateway_scope_budget b ON b.token_sha256=p.scope_token_digest WHERE p.request_id=$1").bind(&settlement.request_id).fetch_optional(&mut *tx).await.map_err(|e|e.to_string())?.ok_or("request permit not found")?;
        lock_project(&mut tx, row.get::<&str, _>("project_id"))
            .await
            .map_err(|e| e.to_string())?;
        let confirmed_closed = matches!(
            settlement.outcome.as_str(),
            "RESPONSE_BODY_COMPLETED"
                | "AUTHORITY_CONTRACT_MISMATCH"
                | "RECOVERY_CONFIRMED_REQUEST_CLOSED"
        );
        let next_status = if confirmed_closed {
            settlement.outcome.as_str()
        } else {
            "QUARANTINED"
        };
        let changed=sqlx::query("UPDATE model_request_permit SET status=$2,settlement=$3 WHERE request_id=$1 AND (status='ADMITTED' OR (status='QUARANTINED' AND $4))").bind(&settlement.request_id).bind(next_status).bind(serde_json::to_value(&settlement).map_err(|e|e.to_string())?).bind(confirmed_closed).execute(&mut *tx).await.map_err(|e|e.to_string())?.rows_affected();
        if changed == 1 && confirmed_closed {
            let released=sqlx::query("UPDATE gateway_scope_budget SET inflight=inflight-1 WHERE token_sha256=$1 AND inflight>0").bind(row.get::<&str,_>("scope_token_digest")).execute(&mut *tx).await.map_err(|e|e.to_string())?.rows_affected();
            if released != 1 {
                return Err("model permit inflight ledger inconsistency".into());
            }
        }
        if changed == 1 {
            let payload = serde_json::to_value(&settlement).map_err(|e| e.to_string())?;
            sqlx::query("UPDATE provider_requests SET data=data || $2::jsonb WHERE request_id=$1")
                .bind(&settlement.request_id)
                .bind(&payload)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
            request_event(
                &mut tx,
                row.get::<&str, _>("project_id"),
                &settlement.request_id,
                "ModelRequestSettled",
                payload,
            )
            .await
            .map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
