use crate::*;
use async_trait::async_trait;
use forgeflow_domain::{
    AdmissionReceipt, AdmissionRequest, AuthorityMode, CatalogCommand, CommandIdentity,
    ExecutionEnvelope, FlowState,
};
use forgeflow_planner::{CompileContext, compile};
use forgeflow_store::{Store, StoreError};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
#[path = "frontier.rs"]
mod frontier;

/// Persistent authorized queue proposal. Dynamic Attempt/Lease identities are assigned by Store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueEntry {
    pub project_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub flow_revision: u64,
    pub priority: i32,
    pub enqueued_at_ms: u64,
    pub enqueue_sequence: u64,
    pub worker_id: String,
    pub worker_scope_id: String,
    pub scope_ids: Vec<String>,
    pub lease_seconds: u32,
    pub envelope: ExecutionEnvelope,
    pub status: String,
    pub retry_not_before_ms: Option<u64>,
}
#[derive(Debug, Clone)]
pub struct PumpConfig {
    pub actor_id: String,
    pub candidate_window: usize,
    pub maximum_selections: usize,
    pub aging_interval_ms: u64,
    pub worker_heartbeat_max_age_seconds: u32,
}
impl Default for PumpConfig {
    fn default() -> Self {
        Self {
            actor_id: "scheduler-service".into(),
            candidate_window: 256,
            maximum_selections: 16,
            aging_interval_ms: 60_000,
            worker_heartbeat_max_age_seconds: 30,
        }
    }
}

/// Ordinary scheduling policy evaluated inside Store's atomic terminal handoff.
/// It never opens a connection, commits, or writes a queue projection itself.
#[derive(Debug, Clone, Default)]
pub struct StoreHandoffScheduler {
    config: PumpConfig,
    strict_project_id: Option<String>,
}
impl StoreHandoffScheduler {
    pub fn new(config: PumpConfig) -> Result<Self, PumpError> {
        if !matches!(config.actor_id.as_str(), "scheduler-service" | "internal")
            || config.candidate_window == 0
            || config.maximum_selections == 0
        {
            return Err(PumpError::Invalid(
                "handoff requires scheduler authority and positive scan/selection limits".into(),
            ));
        }
        Ok(Self {
            config,
            strict_project_id: None,
        })
    }
    /// Restrict the ordinary ready frontier to an explicitly authorized strict
    /// controlled pool. Missing, inactive or stale policy never falls back.
    pub fn for_strict_pool(config: PumpConfig, project_id: String) -> Result<Self, PumpError> {
        if project_id.trim().is_empty() {
            return Err(PumpError::Invalid("strict pool project required".into()));
        }
        let mut scheduler = Self::new(config)?;
        scheduler.strict_project_id = Some(project_id);
        Ok(scheduler)
    }
}
#[async_trait]
impl forgeflow_store::HandoffScheduler for StoreHandoffScheduler {
    async fn select(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        terminal: &forgeflow_domain::Attempt,
    ) -> forgeflow_store::Result<Option<forgeflow_store::QueuedReplacement>> {
        select_replacement_in_transaction(
            transaction,
            &self.config,
            self.strict_project_id.as_deref(),
            terminal,
        )
        .await
        .map_err(|error| match error {
            PumpError::Store(error) => error,
            PumpError::Database(error) => StoreError::Database(error),
            PumpError::Json(error) => StoreError::Json(error),
            PumpError::Invalid(message) => StoreError::Domain(forgeflow_domain::DomainError::new(
                "INVALID_SCHEDULER_SNAPSHOT",
                message,
            )),
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PumpResult {
    pub leadership_acquired: bool,
    pub decision: SchedulerDecision,
    pub admitted: Vec<AdmissionReceipt>,
    pub admission_rejected: Vec<BlockReason>,
}
#[derive(Debug, thiserror::Error)]
pub enum PumpError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("invalid scheduler snapshot: {0}")]
    Invalid(String),
}
fn without_revision(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("revision");
    }
    value
}
fn scheduler_state_semantics(value: Value) -> Value {
    let mut value = without_revision(value);
    if let Some(object) = value.as_object_mut() {
        object.remove("observed_at");
    }
    value
}
fn empty_decision() -> SchedulerDecision {
    SchedulerDecision {
        selected_tasks: vec![],
        blocked: vec![],
        cursor: FairCursor::default(),
        scanned: 0,
        skipped: 0,
        window_exhausted: false,
    }
}
fn scoped_reason(project: &str, task: &str, code: &str, detail: impl Into<String>) -> BlockReason {
    let mut reason = blocker(task, code, detail);
    reason.project_id = Some(project.into());
    reason
}

fn set_dimension(
    vector: &mut ResourceVector,
    dimension: &str,
    amount: u64,
) -> Result<(), PumpError> {
    match dimension {
        "active_slot" => vector.active_slot = amount,
        "coding_slot" => vector.coding_slot = amount,
        "cpu_units" => vector.cpu_units = amount,
        "memory_bytes" => vector.memory_bytes = amount,
        "build_permit" => vector.build_permit = amount,
        "gpu_permit" => vector.gpu_permit = amount,
        "provider_inflight" => vector.provider_inflight = amount,
        _ => {
            return Err(PumpError::Invalid(format!(
                "unknown resource dimension {dimension}"
            )));
        }
    }
    Ok(())
}
fn admission_key(entry: &QueueEntry, revision: u64) -> String {
    format!(
        "schedule:{}:{}:{}:{}",
        entry.project_id, entry.task_id, entry.task_revision, revision
    )
}
async fn mark_dispatched(
    store: &Store,
    config: &PumpConfig,
    entry: &QueueEntry,
    revision: u64,
    receipt: &AdmissionReceipt,
) -> Result<(), PumpError> {
    let mut entry = entry.clone();
    entry.worker_id = receipt.attempt.worker_id.clone();
    if entry.worker_scope_id.is_empty() {
        entry.worker_scope_id = store
            .resource_policies(&entry.project_id)
            .await?
            .into_iter()
            .find(|policy| policy.worker_id.as_deref() == Some(entry.worker_id.as_str()))
            .map(|policy| policy.scope_id)
            .ok_or_else(|| {
                PumpError::Invalid("admitted worker has no authoritative resource scope".into())
            })?;
    }
    let mut value = serde_json::to_value(&entry)?;
    value["status"] = json!("DISPATCHED");
    value["admission_operation_id"] = json!(receipt.operation_id);
    value["attempt_id"] = json!(receipt.attempt.attempt_id);
    store
        .execute_command(
            CommandIdentity {
                actor_id: config.actor_id.clone(),
                idempotency_key: format!("{}:queue-dispatched", admission_key(&entry, revision)),
            },
            CatalogCommand::PutDocument {
                project_id: entry.project_id.clone(),
                collection: "queue_entries".into(),
                id: entry.task_id.clone(),
                expected_revision: Some(revision),
                value,
            },
        )
        .await?;
    Ok(())
}

#[derive(Debug, Clone)]
struct WorkerSnapshot {
    project_id: Option<String>,
    executor_profile_ids: Vec<String>,
    capabilities: Vec<String>,
}
fn supports(worker: &WorkerSnapshot, project: &str, envelope: &ExecutionEnvelope) -> bool {
    worker.project_id.as_deref() == Some(project)
        && worker
            .executor_profile_ids
            .contains(&envelope.executor_profile_id)
        && worker.capabilities.iter().any(|capability| {
            capability
                == if envelope.command.is_some() {
                    "CONTROLLED_LIGHTWEIGHT"
                } else {
                    "DSH_HEADLESS"
                }
        })
}
async fn load_workers(
    store: &Store,
    maximum_age_seconds: u32,
) -> Result<BTreeMap<String, WorkerSnapshot>, PumpError> {
    let rows = sqlx::query("SELECT worker_id, project_id, executor_profile_ids, capabilities FROM workers WHERE heartbeat_at>clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY worker_id")
        .bind(f64::from(maximum_age_seconds)).fetch_all(store.pool()).await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("worker_id")?,
                WorkerSnapshot {
                    project_id: row.try_get("project_id")?,
                    executor_profile_ids: serde_json::from_value(
                        row.try_get("executor_profile_ids")?,
                    )?,
                    capabilities: serde_json::from_value(row.try_get("capabilities")?)?,
                },
            ))
        })
        .collect()
}
async fn load_scopes(store: &Store) -> Result<Vec<ScopeSnapshot>, PumpError> {
    // One SQL statement gives policy and all allocated dimensions a coherent read snapshot.
    let rows = sqlx::query("SELECT s.data AS policy,COALESCE(jsonb_object_agg(l.dimension,l.allocated) FILTER(WHERE l.dimension IS NOT NULL),'{}'::jsonb) AS allocations FROM resource_scopes s LEFT JOIN resource_limits l USING(scope_id) GROUP BY s.scope_id,s.data ORDER BY s.scope_id")
        .fetch_all(store.pool()).await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let policy = serde_json::from_value(row.try_get("policy")?)?;
        let allocations: Value = row.try_get("allocations")?;
        let mut allocated = ResourceVector::default();
        for (dimension, amount) in allocations
            .as_object()
            .ok_or_else(|| PumpError::Invalid("resource allocations must be an object".into()))?
        {
            set_dimension(
                &mut allocated,
                dimension,
                amount.as_u64().ok_or_else(|| {
                    PumpError::Invalid("allocation is negative or noninteger".into())
                })?,
            )?;
        }
        result.push(ScopeSnapshot { policy, allocated });
    }
    Ok(result)
}
async fn context_current(store: &Store, project: &str, revision: u64) -> Result<bool, PumpError> {
    match store.validate_current_flow_context(project, revision).await {
        Ok(()) => Ok(true),
        Err(StoreError::Domain(_)) => Ok(false),
        Err(error) => Err(PumpError::Store(error)),
    }
}

async fn transaction_list<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    query: &str,
    project: Option<&str>,
) -> Result<Vec<T>, PumpError> {
    let query = sqlx::query_scalar::<_, Value>(query);
    let values = if let Some(project) = project {
        query.bind(project).fetch_all(&mut **tx).await?
    } else {
        query.fetch_all(&mut **tx).await?
    };
    values
        .into_iter()
        .map(|value| serde_json::from_value(value).map_err(PumpError::from))
        .collect()
}
async fn load_workers_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    maximum_age_seconds: u32,
) -> Result<BTreeMap<String, WorkerSnapshot>, PumpError> {
    let rows = sqlx::query("SELECT worker_id, project_id, executor_profile_ids, capabilities FROM workers WHERE heartbeat_at>clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY worker_id")
        .bind(f64::from(maximum_age_seconds)).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("worker_id")?,
                WorkerSnapshot {
                    project_id: row.try_get("project_id")?,
                    executor_profile_ids: serde_json::from_value(
                        row.try_get("executor_profile_ids")?,
                    )?,
                    capabilities: serde_json::from_value(row.try_get("capabilities")?)?,
                },
            ))
        })
        .collect()
}
async fn load_scopes_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ScopeSnapshot>, PumpError> {
    let rows = sqlx::query("SELECT s.data AS policy,COALESCE(jsonb_object_agg(l.dimension,l.allocated) FILTER(WHERE l.dimension IS NOT NULL),'{}'::jsonb) AS allocations FROM resource_scopes s LEFT JOIN resource_limits l USING(scope_id) GROUP BY s.scope_id,s.data ORDER BY s.scope_id")
        .fetch_all(&mut **tx).await?;
    let mut scopes = Vec::with_capacity(rows.len());
    for row in rows {
        let policy = serde_json::from_value(row.try_get("policy")?)?;
        let allocations: Value = row.try_get("allocations")?;
        let mut allocated = ResourceVector::default();
        for (dimension, amount) in allocations
            .as_object()
            .ok_or_else(|| PumpError::Invalid("resource allocations must be an object".into()))?
        {
            set_dimension(
                &mut allocated,
                dimension,
                amount.as_u64().ok_or_else(|| {
                    PumpError::Invalid("allocation is negative or noninteger".into())
                })?,
            )?;
        }
        scopes.push(ScopeSnapshot { policy, allocated });
    }
    Ok(scopes)
}
async fn context_current_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    revision: u64,
) -> Result<bool, PumpError> {
    match Store::validate_flow_context_in_transaction(tx, project, revision).await {
        Ok(()) => Ok(true),
        Err(StoreError::Domain(_)) => Ok(false),
        Err(error) => Err(PumpError::Store(error)),
    }
}

struct StrictPoolSelection {
    project_id: String,
    worker_id: String,
    resource_profile_id: String,
}
fn pool_error(code: &str, message: &str) -> PumpError {
    PumpError::Store(StoreError::Domain(forgeflow_domain::DomainError::new(
        code, message,
    )))
}
fn pool_controlled(envelope: &ExecutionEnvelope, resources: &ResourceVector) -> bool {
    envelope.command.is_some()
        && envelope.executor_profile_id == "controlled-lightweight.v1"
        && envelope.max_model_requests == 0
        && resources.provider_inflight == 0
        && !envelope
            .allowed_effects
            .contains(&forgeflow_domain::AllowedEffect::RequestApprovedModel)
}
async fn strict_pool_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    project_id: &str,
    terminal: &forgeflow_domain::Attempt,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<StrictPoolSelection, PumpError> {
    if terminal.project_id != project_id {
        return Err(pool_error(
            "CHANNEL_POOL_MEMBERSHIP",
            "strict selector project must match the terminal attempt",
        ));
    }
    let policy: Value = sqlx::query_scalar(
        "SELECT data FROM documents WHERE project_id=$1 AND collection='channel_pools' AND document_id='strict-controlled' FOR SHARE",
    ).bind(project_id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| pool_error("CHANNEL_POOL_MISSING", "explicit strict pool policy required"))?;
    if policy["schema_version"].as_str() != Some("forgeflow.channel_pool.v1")
        || policy["project_id"].as_str() != Some(project_id)
        || policy["controlled_only"].as_bool() != Some(true)
        || policy["launch_grace_ms"].as_u64() != Some(2000)
        || policy["executor_profile_id"].as_str() != Some("controlled-lightweight.v1")
    {
        return Err(pool_error(
            "CHANNEL_POOL_INVALID",
            "strict pool must bind the exact project and controlled execution profile",
        ));
    }
    match policy["status"].as_str() {
        Some("ACTIVE") => {}
        Some("DRAINING" | "ENDED") => {
            return Err(pool_error(
                "CHANNEL_POOL_DRAINING",
                "strict pool no longer accepts replacement admissions",
            ));
        }
        _ => {
            return Err(pool_error(
                "CHANNEL_POOL_INVALID",
                "unknown strict pool status",
            ));
        }
    }
    let parse_time = |field: &str| {
        policy[field]
            .as_str()
            .filter(|value| value.ends_with('Z') || value.ends_with("+00:00"))
            .and_then(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .ok()
                    .filter(|time| time.offset().local_minus_utc() == 0)
                    .map(|time| time.with_timezone(&chrono::Utc))
            })
            .ok_or_else(|| {
                pool_error(
                    "CHANNEL_POOL_INVALID",
                    "strict pool requires valid UTC timestamps",
                )
            })
    };
    let starts_at = parse_time("starts_at")?;
    let ends_at = parse_time("ends_at")?;
    if starts_at >= ends_at {
        return Err(pool_error(
            "CHANNEL_POOL_INVALID",
            "strict pool interval must be positive",
        ));
    }
    if now < starts_at || now >= ends_at {
        return Err(pool_error(
            "CHANNEL_POOL_WINDOW",
            "strict pool is outside its authorized active interval",
        ));
    }
    let worker_id = policy["worker_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| pool_error("CHANNEL_POOL_INVALID", "strict pool worker required"))?;
    let resource_profile_id = policy["resource_profile_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            pool_error(
                "CHANNEL_POOL_INVALID",
                "strict pool resource profile required",
            )
        })?;
    let baseline: Vec<String> = serde_json::from_value(
        policy["known_baseline_proof"]["attempt_ids"].clone(),
    )
    .map_err(|_| {
        pool_error(
            "CHANNEL_POOL_INVALID",
            "strict pool baseline identities required",
        )
    })?;
    let baseline_ids = baseline.iter().cloned().collect::<BTreeSet<_>>();
    if baseline.is_empty()
        || baseline_ids.len() != baseline.len()
        || baseline.iter().any(|id| id.is_empty())
        || policy["target_channels"].as_u64() != Some(baseline.len() as u64)
    {
        return Err(pool_error(
            "CHANNEL_POOL_INVALID",
            "strict pool baseline must match its declared channel count",
        ));
    }
    let lineage_root: Option<String> = sqlx::query_scalar(
        "SELECT data->>'lineage_root_attempt_id' FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='RESOURCE_HANDOFF' AND data->'successor'->>'attempt_id'=$2 ORDER BY document_id LIMIT 1",
    ).bind(project_id).bind(&terminal.attempt_id).fetch_optional(&mut **tx).await?;
    if !baseline_ids.contains(&terminal.attempt_id)
        && !lineage_root
            .as_ref()
            .is_some_and(|root| baseline_ids.contains(root))
    {
        return Err(pool_error(
            "CHANNEL_POOL_MEMBERSHIP",
            "terminal attempt is outside the strict pool baseline lineage",
        ));
    }
    let envelope: ExecutionEnvelope = serde_json::from_value(
        sqlx::query_scalar::<_, Value>(
            "SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2",
        )
        .bind(project_id)
        .bind(&terminal.attempt_id)
        .fetch_one(&mut **tx)
        .await?,
    )?;
    let resources: ResourceVector = serde_json::from_value(sqlx::query_scalar::<_, Value>(
        "SELECT data->'resource_request' FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3",
    ).bind(project_id).bind(&terminal.task_id)
        .bind(i64::try_from(terminal.task_revision).map_err(|_| pool_error("CHANNEL_POOL_INVALID", "terminal revision exceeds database range"))?)
        .fetch_one(&mut **tx).await?)?;
    if terminal.worker_id != worker_id
        || envelope.resource_profile_id != resource_profile_id
        || !pool_controlled(&envelope, &resources)
    {
        return Err(pool_error(
            "CHANNEL_POOL_MEMBERSHIP",
            "terminal execution identity does not match the strict controlled pool",
        ));
    }
    Ok(StrictPoolSelection {
        project_id: project_id.into(),
        worker_id: worker_id.into(),
        resource_profile_id: resource_profile_id.into(),
    })
}

async fn select_replacement_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    config: &PumpConfig,
    strict_project_id: Option<&str>,
    terminal: &forgeflow_domain::Attempt,
) -> Result<Option<forgeflow_store::QueuedReplacement>, PumpError> {
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let now_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| PumpError::Invalid("database clock precedes epoch".into()))?;
    let strict_pool = if let Some(project_id) = strict_project_id {
        Some(strict_pool_in_transaction(tx, project_id, terminal, now).await?)
    } else {
        None
    };
    let projects = transaction_list::<forgeflow_domain::Project>(
        tx,
        "SELECT data FROM projects ORDER BY project_id",
        None,
    )
    .await?
    .into_iter()
    .filter(|p| {
        p.authority_mode == AuthorityMode::Managed
            && !p.archived
            && !p.paused
            && strict_pool
                .as_ref()
                .is_none_or(|pool| p.project_id == pool.project_id)
    })
    .collect::<Vec<_>>();
    let Some(anchor) = projects.first() else {
        return Ok(None);
    };
    let project_ids = projects
        .iter()
        .map(|p| p.project_id.clone())
        .collect::<Vec<_>>();
    let mut queued_by_project = frontier::queued(&mut **tx, &project_ids).await?;
    if queued_by_project.is_empty() {
        return Ok(None);
    }
    let state:Option<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='operations' AND document_id='scheduler-state'").bind(&anchor.project_id).fetch_optional(&mut **tx).await?;
    let state_revision = state
        .as_ref()
        .and_then(|v| v.get("revision"))
        .and_then(Value::as_u64);
    let cursor = state
        .as_ref()
        .and_then(|v| v.get("cursor"))
        .cloned()
        .map(serde_json::from_value::<FairCursor>)
        .transpose()?
        .unwrap_or_default();
    let workers = load_workers_in_transaction(tx, config.worker_heartbeat_max_age_seconds).await?;
    let scopes = load_scopes_in_transaction(tx).await?;
    let mut input = SchedulerInput {
        tasks: vec![],
        teams: vec![],
        scopes,
        candidates: vec![],
        dependency_receipts: vec![],
        active_writes: frontier::active_writes(&mut **tx, &project_ids).await?,
        committed_flows: BTreeMap::new(),
        project_weights: BTreeMap::new(),
        cursor,
        now_ms,
        aging_interval_ms: config.aging_interval_ms,
        candidate_window: config.candidate_window,
        // A handoff transfers exactly one occupied channel; advance fairness once.
        maximum_selections: 1,
    };
    let mut entries = BTreeMap::<TaskRef, (QueueEntry, u64)>::new();
    let mut admission_rejected = vec![];
    let mut policies = BTreeMap::new();
    for project in &projects {
        let Some(queued) = queued_by_project.remove(&project.project_id) else {
            continue;
        };
        let task_ids = frontier::task_ids(&queued);
        let tasks = frontier::tasks(&mut **tx, &project.project_id, &task_ids).await?;
        let attempts = frontier::attempts(&mut **tx, &project.project_id, &task_ids).await?;
        let (latest_committed, flows) =
            frontier::flows(&mut **tx, &project.project_id, &tasks).await?;
        if let Some(revision) = latest_committed {
            input
                .committed_flows
                .insert(project.project_id.clone(), revision);
        }
        input.teams.extend(
            transaction_list::<forgeflow_domain::Team>(
                tx,
                "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
                Some(&project.project_id),
            )
            .await?,
        );
        let policy = input
            .scopes
            .iter()
            .find(|s| {
                s.policy.project_id.as_deref() == Some(&project.project_id)
                    && s.policy.team_id.is_none()
                    && s.policy.worker_id.is_none()
            })
            .map(|s| s.policy.revision);
        if let Some(revision) = policy {
            policies.insert(project.project_id.clone(), revision);
        }
        let mut contexts = BTreeMap::new();
        for flow in &flows {
            if flow.state == FlowState::Committed {
                let value: Value = sqlx::query_scalar(
                    "SELECT data FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2",
                ).bind(&project.project_id).bind(flow.flow_revision.to_string())
                    .fetch_optional(&mut **tx).await?
                    .ok_or_else(|| PumpError::Invalid("committed flow context missing".into()))?;
                let context: CompileContext = serde_json::from_value(without_revision(value))?;
                contexts.insert(
                    flow.flow_revision,
                    (
                        compile(flow, &context).passed
                            && context_current_in_transaction(
                                tx,
                                &project.project_id,
                                flow.flow_revision,
                            )
                            .await?,
                        context,
                    ),
                );
            }
        }
        let replay_keys = queued
            .iter()
            .map(|(entry, revision)| admission_key(entry, *revision))
            .collect::<Vec<_>>();
        let replay_keys: BTreeSet<String> = sqlx::query_scalar(
            "SELECT idempotency_key FROM idempotency_records WHERE actor_id=$1 AND operation='admit' AND idempotency_key=ANY($2::text[])",
        ).bind(&config.actor_id).bind(&replay_keys).fetch_all(&mut **tx).await?.into_iter().collect();
        for (mut entry, entry_revision) in queued {
            let Some(task) = tasks.iter().find(|t| t.task_id == entry.task_id) else {
                admission_rejected.push(scoped_reason(
                    &project.project_id,
                    &entry.task_id,
                    "TASK_MISSING",
                    "queue proposal references absent task",
                ));
                continue;
            };
            if entry.project_id != project.project_id
                || entry.task_revision != task.task_revision
                || entry.flow_revision != task.flow_revision
            {
                admission_rejected.push(scoped_reason(
                    &project.project_id,
                    &entry.task_id,
                    "REVISION_CONFLICT",
                    "queue entry must be rebased explicitly to current task revision",
                ));
                continue;
            }
            if let Some(pool) = &strict_pool {
                if !pool_controlled(&entry.envelope, &task.resource_request)
                    || entry.envelope.resource_profile_id != pool.resource_profile_id
                    || (!entry.worker_id.is_empty() && entry.worker_id != pool.worker_id)
                {
                    admission_rejected.push(scoped_reason(
                        &project.project_id,
                        &entry.task_id,
                        "CHANNEL_POOL_CANDIDATE",
                        "queue proposal is outside the strict controlled worker and profile pool",
                    ));
                    continue;
                }
                if entry.worker_id.is_empty() {
                    entry.worker_id = pool.worker_id.clone();
                }
            }
            // An ordinary pump may still need to repair a dispatched projection.
            // Handoff must never reuse that receipt as a fresh successor.
            if replay_keys.contains(&admission_key(&entry, entry_revision)) {
                continue;
            }
            if attempts.iter().any(|a| {
                a.task_id == task.task_id
                    && a.task_revision == task.task_revision
                    && a.state == forgeflow_domain::AttemptState::Succeeded
            }) {
                continue;
            }
            if entry.worker_id.is_empty() {
                if let Some((worker, _)) = workers
                    .iter()
                    .find(|(_, worker)| supports(worker, &entry.project_id, &entry.envelope))
                {
                    entry.worker_id = worker.clone();
                }
            }
            if entry.worker_scope_id.is_empty() {
                entry.worker_scope_id = input
                    .scopes
                    .iter()
                    .find(|scope| {
                        scope.policy.worker_id.as_deref() == Some(entry.worker_id.as_str())
                    })
                    .map(|scope| scope.policy.scope_id.clone())
                    .unwrap_or_default();
            }
            let capable = workers
                .get(&entry.worker_id)
                .is_some_and(|worker| supports(worker, &entry.project_id, &entry.envelope));
            let context_valid = contexts
                .get(&task.flow_revision)
                .is_some_and(|(passed, _)| *passed)
                && task.envelope.as_ref() == Some(&entry.envelope);
            for dependency in &task.dependencies {
                let valid = Store::dependency_ready_in_transaction(
                    tx,
                    &project.project_id,
                    task.flow_revision,
                    &task.task_id,
                    dependency,
                )
                .await?;
                let binding_id = contexts
                    .get(&task.flow_revision)
                    .and_then(|(_, ctx)| ctx.task_specs.get(&task.task_id))
                    .and_then(|spec| {
                        spec.dependency_refs
                            .iter()
                            .find(|d| d.task_id == *dependency)
                    })
                    .map(|d| d.binding_id.clone())
                    .unwrap_or_default();
                input.dependency_receipts.push(DependencyReceipt {
                    project_id: project.project_id.clone(),
                    task_id: task.task_id.clone(),
                    dependency_id: dependency.clone(),
                    binding_id,
                    valid,
                });
            }
            let root_team_id = contexts
                .get(&task.flow_revision)
                .and_then(|(_, context)| {
                    context
                        .owners
                        .iter()
                        .find(|owner| owner.owner_id == task.owner_id)
                })
                .and_then(|owner| owner.root_team_id.clone());
            input.candidates.push(QueueCandidate {
                root_team_id,
                project_id: project.project_id.clone(),
                task_id: task.task_id.clone(),
                priority: entry.priority,
                enqueued_at_ms: entry.enqueued_at_ms,
                enqueue_sequence: entry.enqueue_sequence,
                scope_ids: entry.scope_ids.clone(),
                worker_scope_id: entry.worker_scope_id.clone(),
                worker_id: entry.worker_id.clone(),
                has_open_attempt: attempts
                    .iter()
                    .any(|a| a.task_id == task.task_id && !a.state.is_terminal()),
                immutable_inputs_valid: context_valid,
                executor_capable: capable,
                retry_not_before_ms: entry.retry_not_before_ms,
            });
            if entries
                .insert(
                    task_ref(&task.project_id, &task.task_id),
                    (entry, entry_revision),
                )
                .is_some()
            {
                input.candidates.retain(|candidate| {
                    candidate.project_id != task.project_id || candidate.task_id != task.task_id
                });
                let mut reason = blocker(
                    &task.task_id,
                    "DUPLICATE_QUEUE_ENTRY",
                    "multiple queue proposals target the same project-scoped task",
                );
                reason.project_id = Some(task.project_id.clone());
                admission_rejected.push(reason);
            }
        }
        input.tasks.extend(tasks);
    }
    let tasks = input
        .tasks
        .iter()
        .map(|task| (task_ref(&task.project_id, &task.task_id), task))
        .collect::<BTreeMap<_, _>>();
    // Clone the chosen immutable card before moving the full snapshot into the
    // same ready frontier used by ordinary dispatch.
    let tasks = tasks
        .into_iter()
        .map(|(key, task)| (key, task.clone()))
        .collect::<BTreeMap<_, _>>();
    let decision = ready_frontier(input);
    let Some(selected) = decision.selected_tasks.first() else {
        return Ok(None);
    };
    let task = &tasks[selected];
    let (entry, queue_revision) = &entries[selected];
    let policy_revision = policies
        .get(&task.project_id)
        .ok_or_else(|| PumpError::Invalid("selected project policy missing".into()))?;
    Ok(Some(forgeflow_store::QueuedReplacement {
        admission: AdmissionRequest {
            actor_id: config.actor_id.clone(),
            idempotency_key: admission_key(entry, *queue_revision),
            project_id: task.project_id.clone(),
            task_id: task.task_id.clone(),
            task_revision: task.task_revision,
            flow_revision: task.flow_revision,
            policy_revision: *policy_revision,
            input_digest: task.input_digest.clone(),
            worker_id: entry.worker_id.clone(),
            lease_seconds: entry.lease_seconds,
            envelope: entry.envelope.clone(),
        },
        queue_revision: *queue_revision,
        scheduler_anchor_project_id: anchor.project_id.clone(),
        scheduler_state_revision: state_revision,
        scheduler_state: json!({
            "cursor": decision.cursor,
            "observed_at": now.to_rfc3339(),
            "scanned": decision.scanned,
            "skipped": decision.skipped,
            "window_exhausted": decision.window_exhausted,
            "blocked": decision.blocked,
            "admission_rejected": admission_rejected,
        }),
    }))
}

pub async fn pump_once(store: &Store) -> Result<PumpResult, PumpError> {
    pump_once_with_config(store, &PumpConfig::default()).await
}
/// One bounded pump. Advisory transaction leadership survives until this pump returns;
/// no external model/process/Git operation occurs while the lock is held.
pub async fn pump_once_with_config(
    store: &Store,
    config: &PumpConfig,
) -> Result<PumpResult, PumpError> {
    if config.actor_id.trim().is_empty()
        || config.candidate_window == 0
        || config.maximum_selections == 0
    {
        return Err(PumpError::Invalid(
            "actor and positive scan/selection limits required".into(),
        ));
    }
    let mut leadership = store.pool().begin().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(46001338)")
        .fetch_one(&mut *leadership)
        .await?;
    if !acquired {
        leadership.rollback().await?;
        return Ok(PumpResult {
            leadership_acquired: false,
            decision: empty_decision(),
            admitted: vec![],
            admission_rejected: vec![],
        });
    }
    let result = pump_under_leadership(store, config).await;
    leadership.commit().await?;
    result
}
async fn pump_under_leadership(
    store: &Store,
    config: &PumpConfig,
) -> Result<PumpResult, PumpError> {
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(store.pool())
        .await?;
    let now_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| PumpError::Invalid("database clock precedes epoch".into()))?;
    let projects = store
        .list_projects()
        .await?
        .into_iter()
        .filter(|p| p.authority_mode == AuthorityMode::Managed && !p.archived && !p.paused)
        .collect::<Vec<_>>();
    let Some(anchor) = projects.first() else {
        return Ok(PumpResult {
            leadership_acquired: true,
            decision: empty_decision(),
            admitted: vec![],
            admission_rejected: vec![],
        });
    };
    let project_ids = projects
        .iter()
        .map(|p| p.project_id.clone())
        .collect::<Vec<_>>();
    let mut queued_by_project = frontier::queued(store.pool(), &project_ids).await?;
    let state:Option<Value>=sqlx::query_scalar("SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='operations' AND document_id='scheduler-state'").bind(&anchor.project_id).fetch_optional(store.pool()).await?;
    let state_revision = state
        .as_ref()
        .and_then(|v| v.get("revision"))
        .and_then(Value::as_u64);
    let cursor = state
        .as_ref()
        .and_then(|v| v.get("cursor"))
        .cloned()
        .map(serde_json::from_value::<FairCursor>)
        .transpose()?
        .unwrap_or_default();
    // Even an empty queue reconciles the persisted fairness/blocked projection,
    // but it need not deserialize Worker/resource/immutable execution payloads.
    let (workers, scopes, active_writes) = if queued_by_project.is_empty() {
        (BTreeMap::new(), vec![], vec![])
    } else {
        (
            load_workers(store, config.worker_heartbeat_max_age_seconds).await?,
            load_scopes(store).await?,
            frontier::active_writes(store.pool(), &project_ids).await?,
        )
    };
    let mut input = SchedulerInput {
        tasks: vec![],
        teams: vec![],
        scopes,
        candidates: vec![],
        dependency_receipts: vec![],
        active_writes,
        committed_flows: BTreeMap::new(),
        project_weights: BTreeMap::new(),
        cursor,
        now_ms,
        aging_interval_ms: config.aging_interval_ms,
        candidate_window: config.candidate_window,
        maximum_selections: config.maximum_selections,
    };
    let mut entries = BTreeMap::<TaskRef, (QueueEntry, u64)>::new();
    let mut admission_rejected = vec![];
    let mut policies = BTreeMap::new();
    for project in &projects {
        let Some(queued) = queued_by_project.remove(&project.project_id) else {
            continue;
        };
        let task_ids = frontier::task_ids(&queued);
        let tasks = frontier::tasks(store.pool(), &project.project_id, &task_ids).await?;
        let attempts = frontier::attempts(store.pool(), &project.project_id, &task_ids).await?;
        let (latest_committed, flows) =
            frontier::flows(store.pool(), &project.project_id, &tasks).await?;
        if let Some(revision) = latest_committed {
            input
                .committed_flows
                .insert(project.project_id.clone(), revision);
        }
        input
            .teams
            .extend(store.list_teams(&project.project_id).await?);
        let policy = input
            .scopes
            .iter()
            .find(|s| {
                s.policy.project_id.as_deref() == Some(&project.project_id)
                    && s.policy.team_id.is_none()
                    && s.policy.worker_id.is_none()
            })
            .map(|s| s.policy.revision);
        if let Some(revision) = policy {
            policies.insert(project.project_id.clone(), revision);
        }
        let mut contexts = BTreeMap::new();
        for flow in &flows {
            if flow.state == FlowState::Committed {
                let value = store
                    .get_document(
                        &project.project_id,
                        "flow_contexts",
                        &flow.flow_revision.to_string(),
                    )
                    .await?;
                let context: CompileContext = serde_json::from_value(without_revision(value))?;
                contexts.insert(
                    flow.flow_revision,
                    (
                        compile(flow, &context).passed
                            && context_current(store, &project.project_id, flow.flow_revision)
                                .await?,
                        context,
                    ),
                );
            }
        }
        // The scheduler leader also serializes terminal handoffs. Read only
        // current queue proposals and batch exact admission replay identities,
        // rather than holding that leader across one SQL roundtrip per task.
        // Store::admit still checks idempotency and authority transactionally.
        let replay_keys = queued
            .iter()
            .map(|(entry, revision)| admission_key(entry, *revision))
            .collect::<Vec<_>>();
        let replay_rows = sqlx::query(
            "SELECT idempotency_key,response FROM idempotency_records WHERE actor_id=$1 AND operation='admit' AND idempotency_key=ANY($2::text[])",
        ).bind(&config.actor_id).bind(&replay_keys).fetch_all(store.pool()).await?;
        let replay_receipts = replay_rows
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("idempotency_key")?,
                    row.try_get::<Value, _>("response")?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, PumpError>>()?;
        for (mut entry, entry_revision) in queued {
            let Some(task) = tasks.iter().find(|t| t.task_id == entry.task_id) else {
                admission_rejected.push(scoped_reason(
                    &project.project_id,
                    &entry.task_id,
                    "TASK_MISSING",
                    "queue proposal references absent task",
                ));
                continue;
            };
            if entry.project_id != project.project_id
                || entry.task_revision != task.task_revision
                || entry.flow_revision != task.flow_revision
            {
                admission_rejected.push(scoped_reason(
                    &project.project_id,
                    &entry.task_id,
                    "REVISION_CONFLICT",
                    "queue entry must be rebased explicitly to current task revision",
                ));
                continue;
            }
            // Recover a crash after atomic admission but before queue projection persistence.
            // Read the exact idempotency receipt instead of recreating a request with changed policies.
            if let Some(value) = replay_receipts.get(&admission_key(&entry, entry_revision)) {
                let receipt: AdmissionReceipt = serde_json::from_value(value.clone())?;
                mark_dispatched(store, config, &entry, entry_revision, &receipt).await?;
                continue;
            }
            if attempts.iter().any(|a| {
                a.task_id == task.task_id
                    && a.task_revision == task.task_revision
                    && a.state == forgeflow_domain::AttemptState::Succeeded
            }) {
                continue;
            }
            if entry.worker_id.is_empty() {
                if let Some((worker, _)) = workers
                    .iter()
                    .find(|(_, worker)| supports(worker, &entry.project_id, &entry.envelope))
                {
                    entry.worker_id = worker.clone();
                }
            }
            if entry.worker_scope_id.is_empty() {
                entry.worker_scope_id = input
                    .scopes
                    .iter()
                    .find(|scope| {
                        scope.policy.worker_id.as_deref() == Some(entry.worker_id.as_str())
                    })
                    .map(|scope| scope.policy.scope_id.clone())
                    .unwrap_or_default();
            }
            let capable = workers
                .get(&entry.worker_id)
                .is_some_and(|worker| supports(worker, &entry.project_id, &entry.envelope));
            let context_valid = contexts
                .get(&task.flow_revision)
                .is_some_and(|(passed, _)| *passed)
                && task.envelope.as_ref() == Some(&entry.envelope);
            for dependency in &task.dependencies {
                let valid = store
                    .dependency_ready(
                        &project.project_id,
                        task.flow_revision,
                        &task.task_id,
                        dependency,
                    )
                    .await?;
                let binding_id = contexts
                    .get(&task.flow_revision)
                    .and_then(|(_, ctx)| ctx.task_specs.get(&task.task_id))
                    .and_then(|spec| {
                        spec.dependency_refs
                            .iter()
                            .find(|d| d.task_id == *dependency)
                    })
                    .map(|d| d.binding_id.clone())
                    .unwrap_or_default();
                input.dependency_receipts.push(DependencyReceipt {
                    project_id: project.project_id.clone(),
                    task_id: task.task_id.clone(),
                    dependency_id: dependency.clone(),
                    binding_id,
                    valid,
                });
            }
            let root_team_id = contexts
                .get(&task.flow_revision)
                .and_then(|(_, context)| {
                    context
                        .owners
                        .iter()
                        .find(|owner| owner.owner_id == task.owner_id)
                })
                .and_then(|owner| owner.root_team_id.clone());
            input.candidates.push(QueueCandidate {
                root_team_id,
                project_id: project.project_id.clone(),
                task_id: task.task_id.clone(),
                priority: entry.priority,
                enqueued_at_ms: entry.enqueued_at_ms,
                enqueue_sequence: entry.enqueue_sequence,
                scope_ids: entry.scope_ids.clone(),
                worker_scope_id: entry.worker_scope_id.clone(),
                worker_id: entry.worker_id.clone(),
                has_open_attempt: attempts
                    .iter()
                    .any(|a| a.task_id == task.task_id && !a.state.is_terminal()),
                immutable_inputs_valid: context_valid,
                executor_capable: capable,
                retry_not_before_ms: entry.retry_not_before_ms,
            });
            if entries
                .insert(
                    task_ref(&task.project_id, &task.task_id),
                    (entry, entry_revision),
                )
                .is_some()
            {
                input.candidates.retain(|candidate| {
                    candidate.project_id != task.project_id || candidate.task_id != task.task_id
                });
                let mut reason = blocker(
                    &task.task_id,
                    "DUPLICATE_QUEUE_ENTRY",
                    "multiple queue proposals target the same project-scoped task",
                );
                reason.project_id = Some(task.project_id.clone());
                admission_rejected.push(reason);
            }
        }
        input.tasks.extend(tasks);
    }
    let tasks = input
        .tasks
        .iter()
        .map(|task| (task_ref(&task.project_id, &task.task_id), task.clone()))
        .collect::<BTreeMap<_, _>>();
    let decision = ready_frontier(input);
    let mut admitted = vec![];
    for selected in &decision.selected_tasks {
        let task_id = &selected.task_id;
        let task = &tasks[selected];
        let (entry, entry_revision) = &entries[selected];
        let Some(policy_revision) = policies.get(&task.project_id) else {
            admission_rejected.push(scoped_reason(
                &task.project_id,
                task_id,
                "RESOURCE_SCOPE_MISSING",
                "project policy missing",
            ));
            continue;
        };
        let idempotency_key = admission_key(entry, *entry_revision);
        let request = AdmissionRequest {
            actor_id: config.actor_id.clone(),
            idempotency_key: idempotency_key.clone(),
            project_id: task.project_id.clone(),
            task_id: task.task_id.clone(),
            task_revision: task.task_revision,
            flow_revision: task.flow_revision,
            policy_revision: *policy_revision,
            input_digest: task.input_digest.clone(),
            worker_id: entry.worker_id.clone(),
            lease_seconds: entry.lease_seconds,
            envelope: entry.envelope.clone(),
        };
        match store.admit(request).await {
            Ok(receipt) => {
                // A crash here replays the same admission key, never issues a second lease.
                mark_dispatched(store, config, entry, *entry_revision, &receipt).await?;
                admitted.push(receipt);
            }
            Err(StoreError::Domain(error)) => admission_rejected.push(scoped_reason(
                &task.project_id,
                task_id,
                &error.code,
                error.message,
            )),
            Err(error) => return Err(PumpError::Store(error)),
        }
    }
    let scheduler_state = json!({"cursor":decision.cursor,"observed_at":now.to_rfc3339(),"scanned":decision.scanned,"skipped":decision.skipped,"window_exhausted":decision.window_exhausted,"blocked":decision.blocked,"admission_rejected":admission_rejected});
    if state.as_ref().is_none_or(|prior| {
        scheduler_state_semantics(prior.clone())
            != scheduler_state_semantics(scheduler_state.clone())
    }) {
        let operation_key = format!(
            "scheduler-state:{}:{}",
            anchor.project_id,
            state_revision.unwrap_or(0)
        );
        store
            .execute_command(
                CommandIdentity {
                    actor_id: config.actor_id.clone(),
                    idempotency_key: operation_key,
                },
                CatalogCommand::PutDocument {
                    project_id: anchor.project_id.clone(),
                    collection: "operations".into(),
                    id: "scheduler-state".into(),
                    expected_revision: state_revision,
                    value: scheduler_state,
                },
            )
            .await?;
    }
    Ok(PumpResult {
        leadership_acquired: true,
        decision,
        admitted,
        admission_rejected,
    })
}

/// Current admission projection for one task. It reserves nothing and does not persist
/// a fairness cursor, queue entry, Attempt, Lease, allocation, event or dispatch Outbox.
pub async fn preview_task(
    store: &Store,
    project_id: &str,
    task_id: &str,
) -> Result<SchedulerDecision, PumpError> {
    let project = store.get_project(project_id).await?;
    if project.authority_mode != AuthorityMode::Managed || project.paused || project.archived {
        let mut decision = empty_decision();
        decision.blocked.push(scoped_reason(
            project_id,
            task_id,
            "PROJECT_NOT_ADMISSIBLE",
            "project must be managed, active and unpaused",
        ));
        return Ok(decision);
    }
    let task = store.get_task(project_id, task_id).await?;
    let attempts = frontier::attempts(store.pool(), project_id, &[task_id.into()]).await?;
    if attempts.iter().any(|attempt| {
        attempt.task_id == task_id
            && attempt.task_revision == task.task_revision
            && attempt.state == forgeflow_domain::AttemptState::Succeeded
    }) {
        let mut decision = empty_decision();
        decision.blocked.push(scoped_reason(
            project_id,
            task_id,
            "ALREADY_SUCCEEDED",
            "current task revision already has verified success; no automatic rerun",
        ));
        return Ok(decision);
    }
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(store.pool())
        .await?;
    let now_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| PumpError::Invalid("database clock precedes epoch".into()))?;
    let scopes = load_scopes(store).await?;
    let workers = load_workers(
        store,
        PumpConfig::default().worker_heartbeat_max_age_seconds,
    )
    .await?;
    let worker_id = task
        .envelope
        .as_ref()
        .and_then(|envelope| {
            workers
                .iter()
                .find(|(_, worker)| supports(worker, project_id, envelope))
                .map(|(id, _)| id.clone())
        })
        .unwrap_or_default();
    let worker_scope_id = scopes
        .iter()
        .find(|scope| scope.policy.worker_id.as_deref() == Some(&worker_id))
        .map(|scope| scope.policy.scope_id.clone())
        .unwrap_or_default();
    let (committed, flows) =
        frontier::flows(store.pool(), project_id, std::slice::from_ref(&task)).await?;
    let mut dependency_receipts = vec![];
    let mut valid = false;
    let mut root_team_id = None;
    if let Some(flow) = flows
        .iter()
        .find(|flow| flow.flow_revision == task.flow_revision && flow.state == FlowState::Committed)
    {
        let context: CompileContext = serde_json::from_value(without_revision(
            store
                .get_document(project_id, "flow_contexts", &flow.flow_revision.to_string())
                .await?,
        ))?;
        root_team_id = context
            .owners
            .iter()
            .find(|owner| owner.owner_id == task.owner_id)
            .and_then(|owner| owner.root_team_id.clone());
        valid = compile(flow, &context).passed
            && context_current(store, project_id, flow.flow_revision).await?;
        for dependency in &task.dependencies {
            let binding_id = context
                .task_specs
                .get(task_id)
                .and_then(|spec| {
                    spec.dependency_refs
                        .iter()
                        .find(|edge| edge.task_id == *dependency)
                })
                .map(|edge| edge.binding_id.clone())
                .unwrap_or_default();
            dependency_receipts.push(DependencyReceipt {
                project_id: project_id.into(),
                task_id: task_id.into(),
                dependency_id: dependency.clone(),
                binding_id,
                valid: store
                    .dependency_ready(project_id, task.flow_revision, task_id, dependency)
                    .await?,
            });
        }
    }
    let active_writes = frontier::active_writes(store.pool(), &[project_id.into()]).await?;
    let candidate = QueueCandidate {
        root_team_id,
        project_id: project_id.into(),
        task_id: task_id.into(),
        priority: 0,
        enqueued_at_ms: now_ms,
        enqueue_sequence: 0,
        scope_ids: vec![],
        worker_scope_id,
        worker_id: worker_id.clone(),
        has_open_attempt: attempts
            .iter()
            .any(|attempt| attempt.task_id == task_id && !attempt.state.is_terminal()),
        immutable_inputs_valid: valid && task.envelope.is_some(),
        executor_capable: !worker_id.is_empty(),
        retry_not_before_ms: None,
    };
    Ok(ready_frontier(SchedulerInput {
        tasks: vec![task],
        teams: store.list_teams(project_id).await?,
        scopes,
        candidates: vec![candidate],
        dependency_receipts,
        active_writes,
        committed_flows: committed
            .map(|revision| BTreeMap::from([(project_id.into(), revision)]))
            .unwrap_or_default(),
        project_weights: BTreeMap::new(),
        cursor: FairCursor::default(),
        now_ms,
        aging_interval_ms: 60_000,
        candidate_window: 1,
        maximum_selections: 1,
    }))
}

#[cfg(test)]
mod association_tests {
    use super::*;
    fn envelope() -> ExecutionEnvelope {
        serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":"op","project_id":"p","task_id":"task","task_revision":1,"attempt_id":"attempt","lease_id":"lease","generation":1,"worker_id":"worker","workspace_root":"/tmp/root","base_sha":"1111111111111111111111111111111111111111","context_manifest":{"artifact_id":"context","sha256":"1111111111111111111111111111111111111111111111111111111111111111","mandatory_paths":[],"rendered_utf8_bytes":1,"token_estimate":null,"tokenizer_id":null},"write_set":[],"prompt_artifact":{"artifact_id":"prompt","sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"model_route_id":"route","executor_profile_id":"native.v1","resource_profile_id":"resources","verification_plan_id":"plan","allowed_effects":[],"issued_at":"2026-10-09T00:00:00Z","expires_at":"2026-10-09T01:00:00Z","deadline_at":"2026-10-10T00:00:00Z","artifact_prefix":"artifacts","secret_refs":[],"idempotency_key":"key","trace_id":"trace","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null,"command":null})).unwrap()
    }
    #[test]
    fn wildcard_capability_text_cannot_replace_structured_project_and_profile_identity() {
        let native = envelope();
        let registered = WorkerSnapshot {
            project_id: Some("p".into()),
            executor_profile_ids: vec!["native.v1".into()],
            capabilities: vec!["DSH_HEADLESS".into()],
        };
        assert!(supports(&registered, "p", &native));
        assert!(!supports(&registered, "q", &native));
        let legacy = WorkerSnapshot {
            project_id: None,
            executor_profile_ids: vec![],
            capabilities: vec![
                "DSH_HEADLESS".into(),
                "PROJECT:p".into(),
                "EXECUTOR_PROFILE:native.v1".into(),
            ],
        };
        assert!(!supports(&legacy, "p", &native));
        let wrong_profile = WorkerSnapshot {
            executor_profile_ids: vec!["other.v1".into()],
            ..registered
        };
        assert!(!supports(&wrong_profile, "p", &native));
    }
    #[test]
    fn native_and_controlled_caps_cannot_be_used_as_each_others_qualification() {
        let mut native = envelope();
        let controlled = WorkerSnapshot {
            project_id: Some("p".into()),
            executor_profile_ids: vec!["native.v1".into(), "controlled-lightweight.v1".into()],
            capabilities: vec!["CONTROLLED_LIGHTWEIGHT".into()],
        };
        assert!(!supports(&controlled, "p", &native));
        native.executor_profile_id = "controlled-lightweight.v1".into();
        native.command = Some(forgeflow_domain::CommandSpec {
            program: "/tmp/approved-probe".into(),
            args: vec![],
        });
        assert!(supports(&controlled, "p", &native));
        let false_native = WorkerSnapshot {
            capabilities: vec!["DSH_HEADLESS".into()],
            ..controlled
        };
        assert!(!supports(&false_native, "p", &native));
    }
}
