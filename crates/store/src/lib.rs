mod admission;
mod agent_contexts;
mod agent_network;
mod author_custody;
mod catalog;
pub mod ecp_collaboration;
pub mod ecp_delivery_claim;
pub mod ecp_identity;
pub mod ecp_membership;
pub mod ecp_messaging;
pub mod ecp_profile_admission;
pub mod ecp_registry;
pub mod ecp_resources;
pub mod ecp_sessions;
mod role_catalog;
mod workspaces;
pub use agent_network::NetworkMessageInput;
mod planning_views;
pub use planning_views::TaskListFilter;
pub mod capsules;
pub mod collaboration;
pub mod core_authority;
mod decisions;
pub mod event_retention;
mod execution_bindings;
mod handoff;
mod integration;
mod integration_recovery;
mod lifecycle;
mod maintenance;
mod materialization;
mod milestone_acceptance;
mod native_configuration;
pub mod native_model_dispatch;
mod releases;
mod restore;
mod template_receipt;
mod worker_dispatch;
use chrono::{DateTime, Utc};
use forgeflow_domain::*;
pub use handoff::{
    HandoffReceipt, HandoffRequest, HandoffScheduler, QueuedReplacement, TerminalAcknowledgement,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
pub use template_receipt::{
    TEMPLATE_ASSEMBLY_RESULT_V2, TemplateAssemblyReferences, TemplateBindingReceiptReference,
    TemplateFlowReference,
};
use uuid::Uuid;
pub use worker_dispatch::{WorkerDispatchFact, WorkerDispatchKind};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
}
pub type Result<T> = std::result::Result<T, StoreError>;
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    control_pool: PgPool,
    dispatch_pool: PgPool,
    write_slots: std::sync::Arc<tokio::sync::Semaphore>,
    handoff_slots: std::sync::Arc<tokio::sync::Semaphore>,
}

fn authority_pool_options(max_connections: u32) -> sqlx::postgres::PgPoolOptions {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .after_release(|connection, _| {
            Box::pin(async move {
                // A cancelled SQLx 0.8 BEGIN may leave PostgreSQL in a transaction
                // before the driver's transaction_depth is incremented. Ping only
                // checks protocol readiness and cannot clear that server state.
                // A released connection has no remaining transaction owner. One
                // simple-query batch starts an empty transaction when idle, avoiding
                // a "no transaction in progress" warning on every pool release.
                // In an orphan transaction BEGIN only warns; ROLLBACK still discards
                // its uncommitted work. An already-aborted orphan rejects BEGIN, so
                // this hook returns an error and SQLx closes that connection instead.
                // Driver transaction_depth alone cannot identify these orphans.
                sqlx::Executor::execute(connection, "BEGIN; ROLLBACK").await?;
                Ok(true)
            })
        })
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with_options(url.parse()?).await
    }
    /// All lanes always use one connection identity and session configuration.
    /// Callers can set search_path in these options for isolated-schema deployments
    /// without a second URL or a differently configured authority database.
    pub async fn connect_with_options(options: sqlx::postgres::PgConnectOptions) -> Result<Self> {
        let (pool, control_pool, dispatch_pool) = tokio::try_join!(
            authority_pool_options(16).connect_with(options.clone()),
            authority_pool_options(4).connect_with(options.clone()),
            authority_pool_options(4).connect_with(options),
        )?;
        Ok(Self {
            pool,
            control_pool,
            dispatch_pool,
            write_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            handoff_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(3)),
        })
    }
    pub fn from_pool(pool: PgPool) -> Self {
        // Preserve existing caller-owned pool hooks, including after_connect
        // schema isolation. Production connect uses independent control and dispatch lanes.
        Self {
            control_pool: pool.clone(),
            dispatch_pool: pool.clone(),
            pool,
            write_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            handoff_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(3)),
        }
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    pub fn control_pool(&self) -> &PgPool {
        &self.control_pool
    }
    /// Committed start delivery has its own bounded connections, independent of
    /// ordinary writes and the four connections reserved for lease renewal.
    pub fn dispatch_pool(&self) -> &PgPool {
        &self.dispatch_pool
    }
    /// Wait before occupying a PostgreSQL connection. All clones share the same
    /// four writer slots; PostgreSQL locks remain the cross-process authority.
    pub(crate) async fn write_guard(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.write_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| err("STORE_WRITE_LANE_CLOSED", "writer backpressure lane closed"))
    }
    /// A pump may already own the PostgreSQL leader while admitting ordinary
    /// work. Limit leader-waiting handoffs to three writers, leaving its slot free.
    pub(crate) async fn handoff_guard(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.handoff_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                err(
                    "STORE_WRITE_LANE_CLOSED",
                    "handoff backpressure lane closed",
                )
            })
    }
    /// Scheduler authority reads must see the uncommitted terminal result in a
    /// handoff. These bridges reuse the ordinary admission validation helpers.
    pub async fn dependency_ready_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        project: &str,
        flow: u64,
        task: &str,
        dependency: &str,
    ) -> Result<bool> {
        admission::dependency_ready_tx(tx, project, flow, task, dependency).await
    }
    pub async fn validate_flow_context_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        project: &str,
        revision: u64,
    ) -> Result<()> {
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM flow_revisions WHERE project_id=$1 AND flow_revision=$2",
        )
        .bind(project)
        .bind(i64v(revision)?)
        .fetch_optional(&mut **tx)
        .await?;
        if state.as_deref() != Some("COMMITTED") {
            return Err(err(
                "FLOW_NOT_COMMITTED",
                "current committed planning revision required",
            ));
        }
        let context: forgeflow_planner::CompileContext = decode(sqlx::query_scalar(
            "SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2",
        ).bind(project).bind(revision.to_string()).fetch_optional(&mut **tx).await?
            .ok_or_else(||err("EVIDENCE_INCOMPLETE", "committed context missing"))?)?;
        catalog::validate_authoritative_context(tx, project, &context).await
    }
    pub async fn migrate(&self) -> Result<()> {
        // SQLx migration locks are session-scoped and its error/cancellation paths
        // need not unlock. Discard this session on every exit, including cancellation.
        let mut connection = self.pool.acquire().await?;
        connection.close_on_drop();
        sqlx::migrate!("../../migrations")
            .run_direct(&mut *connection)
            .await?;
        Ok(())
    }
    pub async fn events(
        &self,
        project_id: &str,
        after: u64,
        limit: u32,
    ) -> Result<Vec<DomainEvent>> {
        let rows=sqlx::query("SELECT * FROM events WHERE project_id=$1 AND project_seq>$2 ORDER BY project_seq LIMIT $3").bind(project_id).bind(i64v(after)?).bind(i64::from(limit.clamp(1,1000))).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(DomainEvent {
                    event_id: r.try_get("event_id")?,
                    project_id: r.try_get("project_id")?,
                    project_seq: r.try_get::<i64, _>("project_seq")? as u64,
                    object_id: r.try_get("object_id")?,
                    object_revision: r.try_get::<i64, _>("object_revision")? as u64,
                    schema_version: r.try_get("schema_version")?,
                    kind: r.try_get("kind")?,
                    payload: r.try_get("payload")?,
                    occurred_at: r.try_get("occurred_at")?,
                })
            })
            .collect()
    }
    pub async fn pending_outbox(&self, limit: u32) -> Result<Vec<OutboxMessage>> {
        let rows=sqlx::query("SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY created_at,outbox_id LIMIT $1").bind(i64::from(limit.clamp(1,1000))).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(OutboxMessage {
                    outbox_id: r.try_get("outbox_id")?,
                    project_id: r.try_get("project_id")?,
                    operation_id: r.try_get("operation_id")?,
                    kind: r.try_get("kind")?,
                    payload: r.try_get("payload")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect()
    }
    pub async fn ack_outbox(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE outbox SET delivered_at=clock_timestamp() WHERE outbox_id=$1 AND delivered_at IS NULL").bind(id).execute(&self.pool).await?;
        Ok(())
    }
}
fn err(code: &str, msg: impl Into<String>) -> StoreError {
    DomainError::new(code, msg).into()
}
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn i64v(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| err("VALIDATION_ERROR", "integer exceeds PostgreSQL bigint"))
}
fn decode<T: DeserializeOwned>(v: Value) -> Result<T> {
    Ok(serde_json::from_value(v)?)
}
fn json<T: Serialize>(v: &T) -> Result<Value> {
    Ok(serde_json::to_value(v)?)
}
async fn coordination(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(46001337)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn db_now(tx: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
async fn project_lock(tx: &mut Transaction<'_, Postgres>, project: &str) -> Result<Project> {
    let v: Option<Value> =
        sqlx::query_scalar("SELECT data FROM projects WHERE project_id=$1 FOR UPDATE")
            .bind(project)
            .fetch_optional(&mut **tx)
            .await?;
    decode(v.ok_or_else(|| err("NOT_FOUND", "project not found"))?)
}
async fn event(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    object: &str,
    revision: u64,
    kind: &str,
    payload: Value,
) -> Result<()> {
    let seq: i64 = sqlx::query_scalar(
        "UPDATE projects SET event_seq=event_seq+1 WHERE project_id=$1 RETURNING event_seq",
    )
    .bind(project)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO events(event_id,project_id,project_seq,object_id,object_revision,schema_version,kind,payload) VALUES($1,$2,$3,$4,$5,'forgeflow.event.v1',$6,$7)").bind(id()).bind(project).bind(seq).bind(object).bind(i64v(revision)?).bind(kind).bind(payload).execute(&mut **tx).await?;
    Ok(())
}
async fn outbox(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    operation: &str,
    kind: &str,
    payload: Value,
) -> Result<()> {
    sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_id,kind) DO NOTHING").bind(id()).bind(project).bind(operation).bind(kind).bind(payload).execute(&mut **tx).await?;
    Ok(())
}
async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    actor: &str,
    operation: &str,
    key: &str,
    request: &Value,
) -> Result<Option<Value>> {
    if actor.is_empty() || key.is_empty() || key.len() > 512 {
        return Err(err(
            "VALIDATION_ERROR",
            "actor and idempotency key required",
        ));
    }
    // Serializes all identical command keys even before their record exists.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{actor}\x1f{operation}\x1f{key}"))
        .execute(&mut **tx)
        .await?;
    let row=sqlx::query("SELECT request,response FROM idempotency_records WHERE actor_id=$1 AND operation=$2 AND idempotency_key=$3").bind(actor).bind(operation).bind(key).fetch_optional(&mut **tx).await?;
    match row {
        Some(r) => {
            if r.try_get::<Value, _>("request")? != *request {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "key already used for a different request",
                ));
            }
            Ok(Some(r.try_get("response")?))
        }
        None => Ok(None),
    }
}
async fn save_replay(
    tx: &mut Transaction<'_, Postgres>,
    actor: &str,
    operation: &str,
    key: &str,
    operation_id: &str,
    request: &Value,
    response: &Value,
) -> Result<()> {
    sqlx::query("INSERT INTO idempotency_records(actor_id,operation,idempotency_key,operation_id,request,response) VALUES($1,$2,$3,$4,$5,$6)").bind(actor).bind(operation).bind(key).bind(operation_id).bind(request).bind(response).execute(&mut **tx).await?;
    Ok(())
}
async fn attempt_lock(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    attempt: &str,
) -> Result<Attempt> {
    let v: Option<Value> = sqlx::query_scalar(
        "SELECT data FROM attempts WHERE project_id=$1 AND attempt_id=$2 FOR UPDATE",
    )
    .bind(project)
    .bind(attempt)
    .fetch_optional(&mut **tx)
    .await?;
    decode(v.ok_or_else(|| err("NOT_FOUND", "attempt not found"))?)
}
async fn persist_attempt(tx: &mut Transaction<'_, Postgres>, a: &Attempt) -> Result<()> {
    sqlx::query("UPDATE attempts SET state=$3,revision=$4,terminal_at=$5,data=$6 WHERE project_id=$1 AND attempt_id=$2").bind(&a.project_id).bind(&a.attempt_id).bind(a.state.as_str()).bind(i64v(a.revision)?).bind(a.terminal_at).bind(json(a)?).execute(&mut **tx).await?;
    Ok(())
}
async fn valid_lease(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    generation: i64,
    worker: &str,
) -> Result<Lease> {
    let row = sqlx::query("SELECT * FROM leases WHERE project_id=$1 AND attempt_id=$2 FOR UPDATE")
        .bind(&a.project_id)
        .bind(&a.attempt_id)
        .fetch_one(&mut **tx)
        .await?;
    let lease = lease_row(&row)?;
    let fence: i64 =
        sqlx::query_scalar("SELECT fence_epoch FROM tasks WHERE project_id=$1 AND task_id=$2")
            .bind(&a.project_id)
            .bind(&a.task_id)
            .fetch_one(&mut **tx)
            .await?;
    if a.generation != generation
        || generation != fence
        || a.worker_id != worker
        || lease.generation != generation
        || lease.worker_id != worker
        || lease.revoked_at.is_some()
        || lease.expires_at <= db_now(tx).await?
        || a.state.is_terminal()
        || matches!(
            a.state,
            AttemptState::Stopping | AttemptState::RecoveryRequired
        )
    {
        return Err(err(
            "LEASE_STALE",
            "lease expired, revoked or generation/worker mismatched",
        ));
    }
    Ok(lease)
}
fn lease_row(r: &sqlx::postgres::PgRow) -> Result<Lease> {
    Ok(Lease {
        project_id: r.try_get("project_id")?,
        lease_id: r.try_get("lease_id")?,
        attempt_id: r.try_get("attempt_id")?,
        generation: r.try_get("generation")?,
        worker_id: r.try_get("worker_id")?,
        capability_scope: decode(r.try_get("capability_scope")?)?,
        issued_at: r.try_get("issued_at")?,
        expires_at: r.try_get("expires_at")?,
        revoked_at: r.try_get("revoked_at")?,
    })
}
async fn release(tx: &mut Transaction<'_, Postgres>, a: &Attempt, reason: &str) -> Result<()> {
    crate::handoff::strict_release_guard(tx, a).await?;
    crate::collaboration::require_verifier_roots_settled(tx, a).await?;

    if Store::collaboration_pending_in_transaction(tx, &a.attempt_id).await? {
        return Err(err(
            "NATIVE_EFFECT_UNCONFIRMED",
            "native children or model requests remain active/unknown; keep occupied until reconciled",
        ));
    }
    let inflight:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM model_request_permit WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED'))").bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if inflight {
        return Err(err(
            "MODEL_EFFECT_UNCONFIRMED",
            "model requests remain active/unknown; keep occupied until reconciled",
        ));
    }
    let rows=sqlx::query("UPDATE resource_allocations SET state='RELEASED',released_at=clock_timestamp(),release_reason=$2 WHERE attempt_id=$1 AND state<>'RELEASED' RETURNING scope_id,dimension,amount").bind(&a.attempt_id).bind(reason).fetch_all(&mut **tx).await?;
    for r in rows {
        let n=sqlx::query("UPDATE resource_limits SET allocated=allocated-$3 WHERE scope_id=$1 AND dimension=$2 AND allocated>=$3").bind(r.try_get::<String,_>("scope_id")?).bind(r.try_get::<String,_>("dimension")?).bind(r.try_get::<i64,_>("amount")?).execute(&mut **tx).await?.rows_affected();
        if n != 1 {
            return Err(err(
                "RESOURCE_LEDGER_CORRUPT",
                "allocation release exceeds recorded occupied capacity",
            ));
        }
    }
    sqlx::query("UPDATE outbox SET delivered_at=COALESCE(delivered_at,clock_timestamp()) WHERE project_id=$1 AND (operation_id=$2 OR payload->>'attempt_id'=$3) AND kind IN('attempt.start','attempt.stop')").bind(&a.project_id).bind(&a.operation_id).bind(&a.attempt_id).execute(&mut **tx).await?;
    Ok(())
}
async fn revoke(tx: &mut Transaction<'_, Postgres>, a: &Attempt) -> Result<()> {
    Store::collaboration_revoke_in_transaction(tx, &a.attempt_id).await?;
    sqlx::query(
        "UPDATE leases SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE attempt_id=$1",
    )
    .bind(&a.attempt_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE gateway_scope_budget SET revoked=true WHERE attempt_id=$1")
        .bind(&a.attempt_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE tasks SET fence_epoch=fence_epoch+1 WHERE project_id=$1 AND task_id=$2 AND fence_epoch=$3").bind(&a.project_id).bind(&a.task_id).bind(a.generation).execute(&mut **tx).await?;
    Ok(())
}
