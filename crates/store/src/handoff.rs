//! One commit transfers a launched, settled allocation to a lawful queued successor.
//!
//! The replacement is RESERVED until the real Worker claims and launches it. This
//! preserves allocated channel lineage; it does not assert a live replacement PID.
use super::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const POOL_ID: &str = "strict-controlled";
const POOL_AUTH: &str = "forgeflow.strict_handoff_authority";

#[derive(Clone)]
struct StrictPool {
    value: Value,
    project: String,
    worker: String,
    resource_profile: String,
    status: String,
    starts: DateTime<Utc>,
    ends: DateTime<Utc>,
    target: u64,
    revision: u64,
    baseline: BTreeSet<String>,
}

fn pool_string(value: &Value, field: &str) -> Result<String> {
    value[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err("CHANNEL_POOL_INVALID", format!("pool {field} is required")))
}
fn pool_utc(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    let text = pool_string(value, field)?;
    let parsed = DateTime::parse_from_rfc3339(&text).map_err(|_| {
        err(
            "CHANNEL_POOL_INVALID",
            format!("pool {field} must be explicit UTC"),
        )
    })?;
    if parsed.offset().local_minus_utc() != 0 || !(text.ends_with('Z') || text.ends_with("+00:00"))
    {
        return Err(err(
            "CHANNEL_POOL_INVALID",
            "pool time must use explicit UTC",
        ));
    }
    Ok(parsed.with_timezone(&Utc))
}
fn digest_valid(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
fn owner_identity(
    value: &Value,
    by: &str,
    identity: &str,
    at: &str,
    reason: Option<&str>,
    hash: &str,
) -> Result<()> {
    let owner = pool_string(value, by)?;
    if !matches!(owner.as_str(), "owner" | "owner-service")
        || value[identity]["actor_id"].as_str() != Some(owner.as_str())
        || value[identity]["idempotency_key"]
            .as_str()
            .is_none_or(|key| key.is_empty() || key.len() > 512)
        || !digest_valid(&value[hash])
        || reason.is_some_and(|field| {
            value[field]
                .as_str()
                .is_none_or(|reason| reason.trim().is_empty())
        })
    {
        return Err(err(
            "OWNER_AUTHORIZATION_REQUIRED",
            "pool lifecycle requires a recorded Owner identity, request digest and reason",
        ));
    }
    pool_utc(value, at)?;
    Ok(())
}
fn parse_pool(project: &str, mut value: Value, revision: u64) -> Result<StrictPool> {
    if value["schema_version"] != "forgeflow.channel_pool.v1"
        || value["project_id"].as_str() != Some(project)
        || value["executor_profile_id"] != "controlled-lightweight.v1"
        || value["controlled_only"] != true
        || value["launch_grace_ms"] != 2000
    {
        return Err(err(
            "CHANNEL_POOL_INVALID",
            "pool schema, project and controlled scope are invalid",
        ));
    }
    let status = pool_string(&value, "status")?;
    if !matches!(status.as_str(), "ACTIVE" | "DRAINING" | "ENDED") {
        return Err(err("CHANNEL_POOL_INVALID", "unknown pool lifecycle state"));
    }
    let starts = pool_utc(&value, "starts_at")?;
    let ends = pool_utc(&value, "ends_at")?;
    let target = value["target_channels"]
        .as_u64()
        .filter(|target| *target > 0)
        .ok_or_else(|| err("CHANNEL_POOL_INVALID", "positive channel target required"))?;
    let ids = value["known_baseline_proof"]["attempt_ids"]
        .as_array()
        .ok_or_else(|| err("CHANNEL_POOL_INVALID", "pool baseline IDs required"))?;
    let baseline: BTreeSet<String> = ids
        .iter()
        .map(|id| {
            id.as_str()
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| err("CHANNEL_POOL_INVALID", "baseline attempt identity invalid"))
        })
        .collect::<Result<_>>()?;
    let proof = &value["known_baseline_proof"];
    if starts >= ends
        || baseline.len() != ids.len()
        || baseline.len() as u64 != target
        || proof["snapshot_revision"].as_u64().is_none()
        || !digest_valid(&proof["snapshot_sha256"])
    {
        return Err(err(
            "CHANNEL_POOL_INVALID",
            "pool baseline count, original window or snapshot identity invalid",
        ));
    }
    pool_utc(proof, "observed_at")?;
    owner_identity(
        &value,
        "authorized_by",
        "activation_identity",
        "authorized_at",
        None,
        "activation_request_sha256",
    )?;
    if status != "ACTIVE" {
        owner_identity(
            &value,
            "drain_authorized_by",
            "drain_identity",
            "drain_authorized_at",
            Some("drain_reason"),
            "drain_request_sha256",
        )?;
        if pool_utc(&value, "drain_authorized_at")? < ends && value["qualification_aborted"] != true
        {
            return Err(err(
                "CHANNEL_POOL_INVALID",
                "recorded drain precedes the original end",
            ));
        }
    }
    if status == "ENDED" {
        owner_identity(
            &value,
            "ended_by",
            "end_identity",
            "ended_at",
            Some("end_reason"),
            "end_request_sha256",
        )?;
        if pool_utc(&value, "ended_at")? < pool_utc(&value, "drain_authorized_at")? {
            return Err(err(
                "CHANNEL_POOL_INVALID",
                "end precedes its authorized drain",
            ));
        }
    }
    let worker = pool_string(&value, "worker_id")?;
    let resource_profile = pool_string(&value, "resource_profile_id")?;
    value["revision"] = revision.into();
    Ok(StrictPool {
        value,
        project: project.into(),
        worker,
        resource_profile,
        status,
        starts,
        ends,
        target,
        revision,
        baseline,
    })
}
async fn load_pool(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
) -> Result<Option<StrictPool>> {
    let row=sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='channel_pools' AND document_id=$2 FOR UPDATE")
        .bind(project).bind(POOL_ID).fetch_optional(&mut **tx).await?;
    row.map(|row| {
        parse_pool(
            project,
            row.try_get("data")?,
            row.try_get::<i64, _>("revision")? as u64,
        )
    })
    .transpose()
}
fn matches_pool(pool: &StrictPool, envelope: &ExecutionEnvelope, worker: &str) -> bool {
    envelope.project_id == pool.project
        && worker == pool.worker
        && envelope.executor_profile_id == "controlled-lightweight.v1"
        && envelope.resource_profile_id == pool.resource_profile
        && envelope.command.is_some()
}
fn controlled_without_models(envelope: &ExecutionEnvelope, task: &TaskCard) -> bool {
    envelope.max_model_requests == 0
        && task.resource_request.provider_inflight == 0
        && task.resource_request.active_slot == 1
        && !envelope
            .allowed_effects
            .contains(&AllowedEffect::RequestApprovedModel)
}
async fn frozen_attempt(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<(ExecutionEnvelope, TaskCard)> {
    let envelope = decode(
        sqlx::query_scalar("SELECT envelope FROM attempts WHERE project_id=$1 AND attempt_id=$2")
            .bind(&a.project_id)
            .bind(&a.attempt_id)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    let task=decode(sqlx::query_scalar("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3")
        .bind(&a.project_id).bind(&a.task_id).bind(i64v(a.task_revision)?).fetch_one(&mut **tx).await?)?;
    Ok((envelope, task))
}
async fn canonical_lineage(
    tx: &mut Transaction<'_, Postgres>,
    pool: &StrictPool,
    a: &Attempt,
) -> Result<Option<Value>> {
    Ok(sqlx::query_scalar("SELECT response->'evidence' FROM idempotency_records WHERE operation='terminal_handoff' AND response->'replacement'->'attempt'->>'attempt_id'=$1 AND response->'evidence'->>'strict_pool_id'=$2 AND response->'evidence'->>'strict_pool_activation_sha256'=$3 ORDER BY operation_id LIMIT 1")
        .bind(&a.attempt_id).bind(POOL_ID).bind(pool.value["activation_request_sha256"].as_str().unwrap())
        .fetch_optional(&mut **tx).await?)
}
async fn pool_root(
    tx: &mut Transaction<'_, Postgres>,
    pool: &StrictPool,
    a: &Attempt,
) -> Result<String> {
    if pool.baseline.contains(&a.attempt_id) {
        return Ok(a.attempt_id.clone());
    }
    let evidence = canonical_lineage(tx, pool, a).await?.ok_or_else(|| {
        err(
            "CHANNEL_POOL_LINEAGE_INVALID",
            "attempt has no canonical pool handoff lineage",
        )
    })?;
    let root = pool_string(&evidence, "lineage_root_attempt_id")?;
    if !pool.baseline.contains(&root)
        || evidence["successor"]["project_id"].as_str() != Some(pool.project.as_str())
        || evidence["successor"]["worker_id"].as_str() != Some(pool.worker.as_str())
    {
        return Err(err(
            "CHANNEL_POOL_LINEAGE_INVALID",
            "handoff root or successor scope differs from the authorized baseline",
        ));
    }
    Ok(root)
}
async fn scoped_allocations(
    tx: &mut Transaction<'_, Postgres>,
    pool: &StrictPool,
) -> Result<Vec<Attempt>> {
    let rows:Vec<Value>=sqlx::query_scalar("SELECT DISTINCT a.data FROM attempts a JOIN resource_allocations r USING(attempt_id) WHERE a.project_id=$1 AND a.worker_id=$2 AND a.envelope->>'executor_profile_id'='controlled-lightweight.v1' AND a.envelope->>'resource_profile_id'=$3 AND a.envelope->'command' IS NOT NULL AND a.envelope->'command'<>'null'::jsonb AND r.state<>'RELEASED' ORDER BY a.data")
        .bind(&pool.project).bind(&pool.worker).bind(&pool.resource_profile).fetch_all(&mut **tx).await?;
    rows.into_iter().map(decode).collect()
}
async fn exact_vector(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    task: &TaskCard,
) -> Result<()> {
    let rows=sqlx::query("SELECT scope_id,dimension,amount FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED' ORDER BY scope_id,dimension FOR SHARE")
        .bind(&a.attempt_id).fetch_all(&mut **tx).await?;
    let mut vectors = BTreeMap::<String, BTreeMap<String, i64>>::new();
    for row in rows {
        vectors
            .entry(row.try_get("scope_id")?)
            .or_default()
            .insert(row.try_get("dimension")?, row.try_get("amount")?);
    }
    let expected: BTreeMap<String, i64> = task
        .resource_request
        .dimensions()
        .into_iter()
        .filter(|(_, amount)| *amount > 0)
        .map(|(dimension, amount)| Ok((dimension.to_owned(), i64v(amount)?)))
        .collect::<Result<_>>()?;
    let scopes:BTreeSet<String>=sqlx::query_scalar("WITH RECURSIVE selected AS (SELECT scope_id,parent_scope_id FROM resource_scopes WHERE (project_id IS NULL AND worker_id IS NULL) OR worker_id=$3 OR (project_id=$1 AND (team_id IS NULL OR team_id IN(SELECT ancestor_id FROM owner_closure WHERE project_id=$1 AND descendant_id=$2))) UNION SELECT s.scope_id,s.parent_scope_id FROM resource_scopes s JOIN selected c ON s.scope_id=c.parent_scope_id) SELECT DISTINCT scope_id FROM selected ORDER BY scope_id")
        .bind(&a.project_id).bind(&task.team_id).bind(&a.worker_id).fetch_all(&mut **tx).await?.into_iter().collect();
    if scopes.is_empty()
        || scopes != vectors.keys().cloned().collect()
        || vectors.values().any(|vector| vector != &expected)
    {
        return Err(err(
            "CHANNEL_POOL_VECTOR_INVALID",
            "pool attempt must retain its exact full resource vector at every required scope",
        ));
    }
    Ok(())
}
async fn validate_current_pool(
    tx: &mut Transaction<'_, Postgres>,
    pool: &StrictPool,
    override_launch: Option<(&Attempt, &Value)>,
    fresh: Option<&Attempt>,
) -> Result<()> {
    let attempts = scoped_allocations(tx, pool).await?;
    if attempts.len() as u64 != pool.target {
        return Err(err(
            "CHANNEL_POOL_DENOMINATOR_CHANGED",
            "scoped occupied channel count differs from the authorized target",
        ));
    }
    let mut roots = BTreeSet::new();
    let now = db_now(tx).await?;
    for a in attempts {
        let (envelope, task) = frozen_attempt(tx, &a).await?;
        if a.state.is_terminal()
            || !matches_pool(pool, &envelope, &a.worker_id)
            || !controlled_without_models(&envelope, &task)
        {
            return Err(err(
                "CHANNEL_POOL_SCOPE_MISMATCH",
                "pool lineage requires open controlled, one-slot, zero-model attempts on the authorized worker and profiles",
            ));
        }
        exact_vector(tx, &a, &task).await?;
        let root = if fresh.is_some_and(|fresh| fresh.attempt_id == a.attempt_id) {
            let marker: Value = decode(
                sqlx::query_scalar(
                    "SELECT current_setting('forgeflow.strict_handoff_authority',true)::jsonb",
                )
                .fetch_one(&mut **tx)
                .await?,
            )?;
            pool_string(&marker, "lineage_root_attempt_id")?
        } else {
            pool_root(tx, pool, &a).await?
        };
        if !roots.insert(root) {
            return Err(err(
                "CHANNEL_POOL_LINEAGE_INVALID",
                "two occupied attempts cannot share one baseline channel root",
            ));
        }
        let launch = if let Some((author, launch)) =
            override_launch.filter(|(author, _)| author.attempt_id == a.attempt_id)
        {
            let _ = author;
            Some(launch.clone())
        } else {
            launch_proof(
                tx,
                &a,
                &TerminalAcknowledgement::FinalizeMerge {
                    project_id: a.project_id.clone(),
                    intent_id: String::new(),
                },
            )
            .await
            .ok()
        };
        if pool.baseline.contains(&a.attempt_id) {
            let launch = launch.ok_or_else(|| {
                err(
                    "CHANNEL_POOL_BASELINE_INVALID",
                    "unused reservation cannot seed a controlled pool",
                )
            })?;
            let at = pool_utc(&launch, "launched_at")?;
            if at > pool.starts {
                return Err(err(
                    "CHANNEL_POOL_BASELINE_INVALID",
                    "baseline process must actually launch before the declared interval begins",
                ));
            }
        }
        // Successor launch latency is observed separately. A slow, legally
        // fenced successor must not prevent unrelated confirmed-stop handoffs.
        // Reservation, exact vector, live lease and unique lineage checks above
        // remain authoritative; every activated baseline still needs real launch.
    }
    if roots != pool.baseline {
        return Err(err(
            "CHANNEL_POOL_LINEAGE_INVALID",
            "occupied roots must form an exact bijection with the activated baseline",
        ));
    }
    Ok(())
}

/// Called by the service-owned catalog command before the canonical document
/// write. Definition and lifecycle authorization are checked under the same lock.
impl Store {
    pub async fn validate_channel_pool_command_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        project: &str,
        document: &str,
        actor: &str,
        expected: Option<u64>,
        value: &Value,
    ) -> Result<()> {
        if actor != "channel-pool-service" || document != POOL_ID {
            return Err(err(
                "OWNER_AUTHORIZATION_REQUIRED",
                "channel pool writes require the Owner-authorized pool service command",
            ));
        }
        project_lock(tx, project).await?;
        let old = load_pool(tx, project).await?;
        let next = parse_pool(project, value.clone(), expected.unwrap_or(0) + 1)?;
        let now = db_now(tx).await?;
        match old {
            None => {
                if expected.is_some()
                    || next.status != "ACTIVE"
                    || value["qualification_aborted"] == true
                    || now < next.starts
                    || now >= next.ends
                    || pool_utc(value, "authorized_at")? > now
                    || pool_utc(value, "authorized_at")? < next.starts
                {
                    return Err(err(
                        "CHANNEL_POOL_WINDOW_CLOSED",
                        "activation requires an active original interval and current Owner authorization",
                    ));
                }
                if [
                    "drain_authorized_by",
                    "drain_authorized_at",
                    "drain_reason",
                    "drain_identity",
                    "drain_request_sha256",
                    "ended_by",
                    "ended_at",
                    "end_reason",
                    "end_identity",
                    "end_request_sha256",
                ]
                .iter()
                .any(|key| !value[*key].is_null())
                {
                    return Err(err(
                        "CHANNEL_POOL_LIFECYCLE_CONFLICT",
                        "activation cannot contain drain or end authorization",
                    ));
                }
                let seq: i64 =
                    sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                        .bind(project)
                        .fetch_one(&mut **tx)
                        .await?;
                if value["known_baseline_proof"]["snapshot_revision"]
                    .as_u64()
                    .unwrap()
                    > seq as u64
                    || pool_utc(&value["known_baseline_proof"], "observed_at")? > now
                {
                    return Err(err(
                        "CHANNEL_POOL_BASELINE_INVALID",
                        "baseline snapshot cannot refer to future authority",
                    ));
                }
                validate_current_pool(tx, &next, None, None).await?;
            }
            Some(old) => {
                if expected != Some(old.revision) {
                    return Err(err("REVISION_CONFLICT", "pool revision changed"));
                }
                for key in [
                    "schema_version",
                    "project_id",
                    "starts_at",
                    "ends_at",
                    "target_channels",
                    "worker_id",
                    "resource_profile_id",
                    "executor_profile_id",
                    "controlled_only",
                    "launch_grace_ms",
                    "known_baseline_proof",
                    "authorized_by",
                    "authorized_at",
                    "activation_identity",
                    "activation_request_sha256",
                ] {
                    if old.value[key] != value[key] {
                        return Err(err(
                            "IMMUTABLE_CHANNEL_POOL",
                            "authorized pool definition and original baseline cannot change",
                        ));
                    }
                }
                if now < old.ends && value["qualification_aborted"] != true {
                    return Err(err(
                        "CHANNEL_POOL_WINDOW_CLOSED",
                        "Owner may drain only after the original interval has elapsed",
                    ));
                }
                if old.status == "ACTIVE" && next.status == "DRAINING" {
                    owner_identity(
                        value,
                        "drain_authorized_by",
                        "drain_identity",
                        "drain_authorized_at",
                        Some("drain_reason"),
                        "drain_request_sha256",
                    )?;
                    let at = pool_utc(value, "drain_authorized_at")?;
                    if (at < old.ends && value["qualification_aborted"] != true)
                        || at < old.starts
                        || at > now
                        || [
                            "ended_by",
                            "ended_at",
                            "end_reason",
                            "end_identity",
                            "end_request_sha256",
                        ]
                        .iter()
                        .any(|key| !value[*key].is_null())
                    {
                        return Err(err(
                            "CHANNEL_POOL_LIFECYCLE_CONFLICT",
                            "drain must retain the elapsed original window and its Owner authorization",
                        ));
                    }
                } else if old.status == "DRAINING" && next.status == "ENDED" {
                    for key in [
                        "drain_authorized_by",
                        "drain_authorized_at",
                        "drain_reason",
                        "drain_identity",
                        "drain_request_sha256",
                        "qualification_aborted",
                    ] {
                        if old.value[key] != value[key] {
                            return Err(err(
                                "IMMUTABLE_CHANNEL_POOL",
                                "end cannot change the recorded drain authorization",
                            ));
                        }
                    }
                    owner_identity(
                        value,
                        "ended_by",
                        "end_identity",
                        "ended_at",
                        Some("end_reason"),
                        "end_request_sha256",
                    )?;
                    let at = pool_utc(value, "ended_at")?;
                    if (at < old.ends && old.value["qualification_aborted"] != true)
                        || at > now
                        || !scoped_allocations(tx, &old).await?.is_empty()
                    {
                        return Err(err(
                            "CHANNEL_POOL_NOT_DRAINED",
                            "end requires zero scoped allocations and elapsed original interval",
                        ));
                    }
                } else {
                    return Err(err(
                        "CHANNEL_POOL_LIFECYCLE_CONFLICT",
                        "only Owner-authorized ACTIVE to DRAINING to ENDED transitions are allowed",
                    ));
                }
            }
        }
        Ok(())
    }
}

async fn marker_matches(
    tx: &mut Transaction<'_, Postgres>,
    pool: &StrictPool,
    a: Option<&Attempt>,
) -> Result<bool> {
    let marker: Option<String> =
        sqlx::query_scalar("SELECT current_setting('forgeflow.strict_handoff_authority',true)")
            .fetch_one(&mut **tx)
            .await?;
    let Some(marker) = marker.filter(|marker| !marker.is_empty()) else {
        return Ok(false);
    };
    let marker: Value = decode(serde_json::from_str(&marker)?)?;
    let xid: String = sqlx::query_scalar("SELECT pg_current_xact_id()::text")
        .fetch_one(&mut **tx)
        .await?;
    Ok(marker["transaction_id"].as_str() == Some(xid.as_str())
        && marker["project_id"].as_str() == Some(pool.project.as_str())
        && marker["pool_id"] == POOL_ID
        && marker["pool_revision"].as_u64() == Some(pool.revision)
        && marker["lineage_root_attempt_id"]
            .as_str()
            .is_some_and(|root| pool.baseline.contains(root))
        && a.is_none_or(|a| {
            marker["attempt_id"].as_str() == Some(a.attempt_id.as_str())
                && marker["generation"].as_i64() == Some(a.generation)
        }))
}
pub(crate) async fn strict_release_guard(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<()> {
    let Some(pool) = load_pool(tx, &a.project_id).await? else {
        return Ok(());
    };
    let (envelope, _) = frozen_attempt(tx, a).await?;
    if !matches_pool(&pool, &envelope, &a.worker_id) || pool.status == "ENDED" {
        return Ok(());
    }
    if pool.status == "DRAINING" {
        if db_now(tx).await? < pool.ends && pool.value["qualification_aborted"] != true {
            return Err(err(
                "CHANNEL_POOL_WINDOW_CLOSED",
                "draining cannot precede the original end",
            ));
        }
        return Ok(());
    }
    if !marker_matches(tx, &pool, Some(a)).await? {
        return Err(err(
            "CHANNEL_POOL_HANDOFF_REQUIRED",
            "ACTIVE controlled allocations may release only through the same-transaction lawful handoff",
        ));
    }
    let now = db_now(tx).await?;
    if now < pool.starts || now >= pool.ends {
        return Err(err(
            "CHANNEL_POOL_WINDOW_CLOSED",
            "ACTIVE retains allocations until explicit elapsed Owner drain",
        ));
    }
    Ok(())
}
pub(crate) async fn strict_admission_guard(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    task: &TaskCard,
    envelope: &ExecutionEnvelope,
    worker: &str,
) -> Result<()> {
    let Some(pool) = load_pool(tx, project).await? else {
        return Ok(());
    };
    if !matches_pool(&pool, envelope, worker) || pool.status == "ENDED" {
        return Ok(());
    }
    if pool.status == "DRAINING" {
        return Err(err(
            "CHANNEL_POOL_DRAINING",
            "Owner-authorized draining forbids new scoped admissions",
        ));
    }
    let now = db_now(tx).await?;
    if now < pool.starts || now >= pool.ends {
        return Err(err(
            "CHANNEL_POOL_WINDOW_CLOSED",
            "ACTIVE original pool window is closed; explicit Owner drain required",
        ));
    }
    if !controlled_without_models(envelope, task) || !marker_matches(tx, &pool, None).await? {
        return Err(err(
            "CHANNEL_POOL_HANDOFF_REQUIRED",
            "ACTIVE permits only one scoped zero-model successor inside an authorized atomic handoff",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalAcknowledgement {
    WorkerResult {
        result: WorkerResult,
    },
    ConfirmStop {
        receipt: StopReceipt,
    },
    FailedTransition {
        request: TransitionRequest,
    },
    CompleteReadOnly {
        project_id: String,
        attempt_id: String,
        generation: i64,
        worker_id: String,
        receipt_id: String,
    },
    FinalizeMerge {
        project_id: String,
        intent_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffRequest {
    pub identity: CommandIdentity,
    pub terminal: TerminalAcknowledgement,
}

/// A scheduler decision made from the post-terminal snapshot in this transaction.
/// The Store still validates and consumes the exact existing QUEUED proposal.
#[derive(Debug, Clone)]
pub struct QueuedReplacement {
    pub admission: AdmissionRequest,
    pub queue_revision: u64,
    pub scheduler_anchor_project_id: String,
    pub scheduler_state_revision: Option<u64>,
    pub scheduler_state: Value,
}

/// Implementations must use the ordinary bounded priority/aging/fairness policy
/// and only this transaction for authority reads. External effects are forbidden.
#[async_trait]
pub trait HandoffScheduler: Send + Sync {
    async fn select(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        terminal: &Attempt,
    ) -> Result<Option<QueuedReplacement>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffReceipt {
    pub operation_id: String,
    pub terminal: Attempt,
    pub replacement: AdmissionReceipt,
    pub transaction_id: String,
    pub evidence: Value,
    pub replayed: bool,
}

impl Store {
    /// Fails closed when no independently legal successor exists. In that case
    /// the terminal acknowledgement and release both roll back; callers retain
    /// their durable acknowledgement and retry after authorized queue work exists.
    pub async fn terminal_handoff(
        &self,
        request: HandoffRequest,
        scheduler: &dyn HandoffScheduler,
    ) -> Result<HandoffReceipt> {
        let _handoff_guard = self.handoff_guard().await?;
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        // The ordinary pump holds this lock while obtaining coordination for
        // admissions. Match that order, including across different projects.
        sqlx::query("SELECT pg_advisory_xact_lock(46001338)")
            .execute(&mut *tx)
            .await?;
        coordination(&mut tx).await?;
        let request_json = json(&request)?;
        if let Some(value) = replay(
            &mut tx,
            &request.identity.actor_id,
            "terminal_handoff",
            &request.identity.idempotency_key,
            &request_json,
        )
        .await?
        {
            let mut receipt: HandoffReceipt = decode(value)?;
            receipt.replayed = true;
            tx.commit().await?;
            return Ok(receipt);
        }
        let predecessor = predecessor(&mut tx, &request.terminal).await?;
        let strict_pool = match load_pool(&mut tx, &predecessor.project_id).await? {
            Some(pool) => {
                let (envelope, _) = frozen_attempt(&mut tx, &predecessor).await?;
                if matches_pool(&pool, &envelope, &predecessor.worker_id) {
                    if pool.status != "ACTIVE" {
                        return Err(err(
                            "CHANNEL_POOL_DRAINING",
                            "Owner authorized ordinary settlement after the original pool interval",
                        ));
                    }
                    Some(pool)
                } else {
                    None
                }
            }
            None => None,
        };
        if predecessor.state.is_terminal() || predecessor.terminal_at.is_some() {
            return Err(err(
                "HANDOFF_ALREADY_TERMINAL",
                "a new handoff requires an occupied nonterminal predecessor",
            ));
        }
        let launch = launch_proof(&mut tx, &predecessor, &request.terminal).await?;
        let author_stop =
            author_stop_proof(&mut tx, &predecessor, &launch, &request.terminal).await?;
        let strict_root = if let Some(pool) = &strict_pool {
            let now = db_now(&mut tx).await?;
            if now < pool.starts || now >= pool.ends {
                return Err(err(
                    "CHANNEL_POOL_WINDOW_CLOSED",
                    "ACTIVE pool retains allocation until explicit elapsed Owner drain",
                ));
            }
            validate_current_pool(&mut tx, pool, Some((&predecessor, &launch)), None).await?;
            let root = pool_root(&mut tx, pool, &predecessor).await?;
            let xid: String = sqlx::query_scalar("SELECT pg_current_xact_id()::text")
                .fetch_one(&mut *tx)
                .await?;
            let marker = serde_json::json!({"transaction_id":xid,"pool_id":POOL_ID,"pool_revision":pool.revision,
                "project_id":pool.project,"attempt_id":predecessor.attempt_id,"generation":predecessor.generation,
                "lineage_root_attempt_id":root});
            sqlx::query("SELECT set_config('forgeflow.strict_handoff_authority',$1,true)")
                .bind(marker.to_string())
                .execute(&mut *tx)
                .await?;
            Some(root)
        } else {
            None
        };
        if !matches!(
            &request.terminal,
            TerminalAcknowledgement::FinalizeMerge { .. }
        ) && predecessor.result.as_ref().is_some_and(|value| {
            value
                .pointer("/receipt/commit_decided")
                .and_then(Value::as_bool)
                == Some(true)
                || value.get("commit_decided").and_then(Value::as_bool) == Some(true)
        }) {
            return Err(err(
                "MERGE_EFFECT_UNCONFIRMED",
                "decided integration requires merge finalization",
            ));
        }
        let predecessor_allocations = allocation_evidence(&mut tx, &predecessor).await?;
        if !predecessor_allocations
            .iter()
            .any(|value| value["dimension"] == "active_slot" && value["state"] != "RELEASED")
        {
            return Err(err(
                "HANDOFF_ALLOCATION_MISSING",
                "launched predecessor must still own an active allocation",
            ));
        }
        let counts_before = allocated_counts(&mut tx).await?;
        let lineage: Option<Value> = sqlx::query_scalar(
            "SELECT data FROM documents WHERE collection='operations' \
             AND data->>'kind'='RESOURCE_HANDOFF' \
             AND data->'successor'->>'attempt_id'=$1 ORDER BY document_id LIMIT 1",
        )
        .bind(&predecessor.attempt_id)
        .fetch_optional(&mut *tx)
        .await?;
        let terminal = acknowledge_terminal(&mut tx, request.terminal.clone()).await?;
        if !terminal.state.is_terminal() || terminal.terminal_at.is_none() {
            return Err(err(
                "HANDOFF_NOT_TERMINAL",
                "author execution success still requires independent verification and integration",
            ));
        }
        assert_effects_settled(&mut tx, &terminal).await?;
        let released_allocations = allocation_evidence(&mut tx, &terminal).await?;
        // Selection observes this very transaction's lawful release and terminal
        // dependency outcome, while other sessions still observe the predecessor.
        let selected = scheduler.select(&mut tx, &terminal).await?.ok_or_else(|| {
            err(
                "HANDOFF_UNAVAILABLE",
                "no independently lawful authorized queue successor; retain allocation",
            )
        })?;
        let queued = queued_proposal(&mut tx, &selected).await?;
        let replacement = crate::admission::admit_tx(&mut tx, selected.admission.clone()).await?;
        if replacement.replayed || replacement.attempt.attempt_id == predecessor.attempt_id {
            return Err(err(
                "HANDOFF_REPLACEMENT_REPLAYED",
                "new handoff requires a fresh attempt, lease, allocations and start command",
            ));
        }
        if let Some(pool) = &strict_pool {
            let (envelope, task) = frozen_attempt(&mut tx, &replacement.attempt).await?;
            if !matches_pool(pool, &envelope, &replacement.attempt.worker_id)
                || !controlled_without_models(&envelope, &task)
            {
                return Err(err(
                    "CHANNEL_POOL_SCOPE_MISMATCH",
                    "atomic successor must remain in the activated project, worker, controlled executor and resource profile",
                ));
            }
            let now = db_now(&mut tx).await?;
            if now < pool.starts || now >= pool.ends {
                return Err(err(
                    "CHANNEL_POOL_WINDOW_CLOSED",
                    "handoff cannot commit outside the original ACTIVE window",
                ));
            }
            validate_current_pool(&mut tx, pool, None, Some(&replacement.attempt)).await?;
        }
        let counts_after = allocated_counts(&mut tx).await?;
        if counts_before != counts_after {
            return Err(err(
                "HANDOFF_DENOMINATOR_CHANGED",
                "terminal and successor must preserve allocated channel count and global active slots",
            ));
        }
        let mut dispatched = queued;
        dispatched["status"] = Value::String("DISPATCHED".into());
        dispatched["worker_id"] = Value::String(replacement.attempt.worker_id.clone());
        if dispatched["worker_scope_id"]
            .as_str()
            .is_none_or(str::is_empty)
        {
            dispatched["worker_scope_id"] =
                Value::String(format!("worker:{}", replacement.attempt.worker_id));
        }
        dispatched["admission_operation_id"] = Value::String(replacement.operation_id.clone());
        dispatched["attempt_id"] = Value::String(replacement.attempt.attempt_id.clone());
        persist_document(
            &mut tx,
            &replacement.attempt.project_id,
            "queue_entries",
            &replacement.attempt.task_id,
            Some(selected.queue_revision),
            dispatched,
        )
        .await?;
        persist_document(
            &mut tx,
            &selected.scheduler_anchor_project_id,
            "operations",
            "scheduler-state",
            selected.scheduler_state_revision,
            selected.scheduler_state,
        )
        .await?;
        let operation_id = id();
        let transaction_id: String = sqlx::query_scalar("SELECT pg_current_xact_id()::text")
            .fetch_one(&mut *tx)
            .await?;
        let successor_allocations = allocation_evidence(&mut tx, &replacement.attempt).await?;
        let evidence = serde_json::json!({
            "kind":"RESOURCE_HANDOFF",
            "schema_version":"forgeflow.resource_handoff.v1",
            "operation_id":operation_id,
            "transaction_id":transaction_id,
            "lineage_root_attempt_id":strict_root.as_ref().map(|root|Value::String(root.clone())).unwrap_or_else(||lineage.as_ref()
                .and_then(|value|value.get("lineage_root_attempt_id"))
                .cloned().unwrap_or_else(||Value::String(predecessor.attempt_id.clone()))),
            "strict_pool_id":strict_pool.as_ref().map(|_|POOL_ID),
            "strict_pool_revision":strict_pool.as_ref().map(|pool|pool.revision),
            "strict_pool_activation_sha256":strict_pool.as_ref().map(|pool|pool.value["activation_request_sha256"].clone()),
            "predecessor_handoff_operation_id":lineage.as_ref()
                .and_then(|value|value.get("operation_id")).cloned(),
            "predecessor":predecessor,
            "terminal":terminal,
            "author_launch":launch,
            "author_stop":author_stop,
            "predecessor_allocations_before":predecessor_allocations,
            "released_allocations":released_allocations,
            "successor":replacement.attempt,
            "acquired_allocations":successor_allocations,
            "allocated_before":counts_before,
            "allocated_after":counts_after,
            "successor_state_at_commit":"RESERVED",
            "successor_author_pid_at_commit":null,
            "maximum_replacement_dispatch_gap_ms":2000,
            "dispatch_gap_verdict":"REQUIRES_ACTUAL_WORKER_OBSERVATION"
        });
        persist_document(
            &mut tx,
            &terminal.project_id,
            "operations",
            &format!("handoff:{operation_id}"),
            None,
            evidence.clone(),
        )
        .await?;
        event(
            &mut tx,
            &terminal.project_id,
            &terminal.attempt_id,
            terminal.revision,
            "resource.handoff",
            evidence.clone(),
        )
        .await?;
        if replacement.attempt.project_id != terminal.project_id {
            event(
                &mut tx,
                &replacement.attempt.project_id,
                &replacement.attempt.attempt_id,
                replacement.attempt.revision,
                "resource.handoff",
                evidence.clone(),
            )
            .await?;
        }
        let receipt = HandoffReceipt {
            operation_id,
            terminal,
            replacement,
            transaction_id,
            evidence,
            replayed: false,
        };
        save_replay(
            &mut tx,
            &request.identity.actor_id,
            "terminal_handoff",
            &request.identity.idempotency_key,
            &receipt.operation_id,
            &request_json,
            &json(&receipt)?,
        )
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }
}

async fn predecessor(
    tx: &mut Transaction<'_, Postgres>,
    terminal: &TerminalAcknowledgement,
) -> Result<Attempt> {
    let (project, attempt) = match terminal {
        TerminalAcknowledgement::WorkerResult { result } => {
            (result.project_id.as_str(), result.attempt_id.clone())
        }
        TerminalAcknowledgement::ConfirmStop { receipt } => {
            (receipt.project_id.as_str(), receipt.attempt_id.clone())
        }
        TerminalAcknowledgement::FailedTransition { request } => {
            if request.next_state != AttemptState::Failed {
                return Err(err(
                    "ILLEGAL_TRANSITION",
                    "handoff transition must be FAILED",
                ));
            }
            (request.project_id.as_str(), request.attempt_id.clone())
        }
        TerminalAcknowledgement::CompleteReadOnly {
            project_id,
            attempt_id,
            ..
        } => (project_id.as_str(), attempt_id.clone()),
        TerminalAcknowledgement::FinalizeMerge {
            project_id,
            intent_id,
        } => {
            let attempt: String = sqlx::query_scalar(
                "SELECT attempt_id FROM merge_intents WHERE project_id=$1 AND intent_id=$2 FOR UPDATE",
            ).bind(project_id).bind(intent_id).fetch_optional(&mut **tx).await?
                .ok_or_else(||err("NOT_FOUND", "merge intent missing"))?;
            (project_id.as_str(), attempt)
        }
    };
    project_lock(tx, project).await?;
    attempt_lock(tx, project, &attempt).await
}

async fn acknowledge_terminal(
    tx: &mut Transaction<'_, Postgres>,
    terminal: TerminalAcknowledgement,
) -> Result<Attempt> {
    match terminal {
        TerminalAcknowledgement::WorkerResult { result } => {
            crate::lifecycle::worker_result_tx(tx, result).await
        }
        TerminalAcknowledgement::ConfirmStop { receipt } => {
            crate::lifecycle::confirm_stop_tx(tx, receipt).await
        }
        TerminalAcknowledgement::FailedTransition { request } => {
            crate::lifecycle::transition_tx(tx, request).await
        }
        TerminalAcknowledgement::CompleteReadOnly {
            project_id,
            attempt_id,
            generation,
            worker_id,
            receipt_id,
        } => {
            crate::integration::complete_read_only_tx(
                tx,
                &project_id,
                &attempt_id,
                generation,
                &worker_id,
                &receipt_id,
            )
            .await
        }
        TerminalAcknowledgement::FinalizeMerge {
            project_id,
            intent_id,
        } => {
            let intent = crate::integration::finalize_merge_tx(tx, &project_id, &intent_id).await?;
            attempt_lock(tx, &project_id, &intent.attempt_id).await
        }
    }
}

fn report_scope_matches(value: &Value, a: &Attempt) -> bool {
    value["project_id"].as_str() == Some(a.project_id.as_str())
        && value["attempt_id"].as_str() == Some(a.attempt_id.as_str())
        && value["generation"].as_i64() == Some(a.generation)
        && value["worker_id"].as_str() == Some(a.worker_id.as_str())
        && value["lease_id"].as_str() == Some(a.lease_id.as_str())
}

fn valid_launch(launch: &Value, a: &Attempt) -> bool {
    let process = &launch["process"];
    let intent = &launch["intent"];
    intent["attempt_id"].as_str() == Some(a.attempt_id.as_str())
        && intent["operation_id"].as_str() == Some(a.operation_id.as_str())
        && intent["generation"].as_i64() == Some(a.generation)
        && intent["worker_id"].as_str() == Some(a.worker_id.as_str())
        && process["attempt_id"].as_str() == Some(a.attempt_id.as_str())
        && process["pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0 && pid <= i32::MAX as u64)
        && process["pgid"]
            .as_i64()
            .is_some_and(|pgid| pgid > 0 && Some(pgid as u64) == process["pid"].as_u64())
        && process["start_ticks"]
            .as_u64()
            .is_some_and(|ticks| ticks > 0)
        && process["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
        && process["boot_id"] == intent["boot_id"]
        && launch["execution_id"].as_str().is_some_and(|execution| {
            Uuid::parse_str(execution).is_ok() && execution != a.operation_id
        })
        && launch["execution_id"] == intent["execution_id"]
        && launch["launched_at"]
            .as_str()
            .is_some_and(|at| DateTime::parse_from_rfc3339(at).is_ok())
}

async fn launch_proof(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    terminal: &TerminalAcknowledgement,
) -> Result<Value> {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 ORDER BY event_id",
    ).bind(&a.project_id).bind(&a.attempt_id).fetch_all(&mut **tx).await?;
    for value in rows {
        if !report_scope_matches(&value, a) {
            continue;
        }
        if matches!(
            value["kind"].as_str(),
            Some("RUNNING" | "process.started" | "execution.started" | "attempt.running")
        ) && let Some(launch) = value
            .get("payload")
            .filter(|launch| valid_launch(launch, a))
        {
            return Ok(launch.clone());
        }
        // Recovery can lose RUNNING publication after the durable journal was
        // written. An accepted bound result retains that exact positive receipt.
        if value.get("outcome").is_some()
            && let Some(launch) = value
                .pointer("/evidence/launch_receipt")
                .filter(|launch| valid_launch(launch, a))
        {
            return Ok(launch.clone());
        }
    }
    let evidence = match terminal {
        TerminalAcknowledgement::WorkerResult { result }
            if result.project_id == a.project_id
                && result.attempt_id == a.attempt_id
                && result.lease_id == a.lease_id
                && result.generation == a.generation
                && result.worker_id == a.worker_id =>
        {
            Some(&result.evidence)
        }
        TerminalAcknowledgement::ConfirmStop { receipt }
            if receipt.project_id == a.project_id
                && receipt.attempt_id == a.attempt_id
                && receipt.generation == a.generation
                && receipt.worker_id == a.worker_id =>
        {
            Some(&receipt.evidence)
        }
        _ => None,
    };
    if let Some(launch) = evidence
        .and_then(|evidence| evidence.get("launch_receipt"))
        .filter(|launch| valid_launch(launch, a))
    {
        return Ok(launch.clone());
    }
    Err(err(
        "HANDOFF_PREDECESSOR_UNLAUNCHED",
        "positive bound process launch receipt required; unused reservations do not establish channel lineage",
    ))
}

fn stop_from_evidence(value: &Value) -> Option<Value> {
    let stop = value.get("stop")?;
    (value["process_exit_confirmed"].as_bool() == Some(true)
        && stop["process_exit_confirmed"].as_bool() == Some(true)
        && stop["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
        && stop["stdout_bytes"].as_u64().is_some()
        && stop["stderr_bytes"].as_u64().is_some()
        && stop["notification_overflow"].as_u64().is_some())
    .then(|| stop.clone())
}

async fn author_stop_proof(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    launch: &Value,
    terminal: &TerminalAcknowledgement,
) -> Result<Value> {
    let immediate = match terminal {
        TerminalAcknowledgement::WorkerResult { result }
            if result.project_id == a.project_id
                && result.attempt_id == a.attempt_id
                && result.lease_id == a.lease_id
                && result.generation == a.generation
                && result.worker_id == a.worker_id
                && Some(result.outcome.execution_id.as_str())
                    == launch["execution_id"].as_str() =>
        {
            stop_from_evidence(&result.evidence)
        }
        TerminalAcknowledgement::ConfirmStop { receipt }
            if receipt.project_id == a.project_id
                && receipt.attempt_id == a.attempt_id
                && receipt.generation == a.generation
                && receipt.worker_id == a.worker_id
                && receipt.process_exit_confirmed
                && receipt.evidence["execution_id"] == launch["execution_id"] =>
        {
            stop_from_evidence(&receipt.evidence)
        }
        _ => None,
    };
    if let Some(stop) = immediate {
        return Ok(stop);
    }
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 \
         AND payload->>'lease_id'=$3 AND payload->>'worker_id'=$4 \
         AND payload->>'generation'=$5 AND payload ? 'outcome' ORDER BY event_id",
    )
    .bind(&a.project_id)
    .bind(&a.attempt_id)
    .bind(&a.lease_id)
    .bind(&a.worker_id)
    .bind(a.generation.to_string())
    .fetch_all(&mut **tx)
    .await?;
    for value in rows {
        if value["outcome"]["execution_id"] == launch["execution_id"]
            && let Some(stop) = value.get("evidence").and_then(stop_from_evidence)
        {
            return Ok(stop);
        }
    }
    Err(err(
        "PROCESS_EXIT_UNCONFIRMED",
        "handoff requires bound positive author stop evidence; allocation remains occupied",
    ))
}

async fn assert_effects_settled(tx: &mut Transaction<'_, Postgres>, a: &Attempt) -> Result<()> {
    let unresolved: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 \
         AND state NOT IN('ABORTED','FINALIZED','COMMITTED'))",
    )
    .bind(&a.project_id)
    .bind(&a.attempt_id)
    .fetch_one(&mut **tx)
    .await?;
    if unresolved {
        return Err(err(
            "MERGE_EFFECT_UNCONFIRMED",
            "all merge effects must be finalized or lawfully aborted before handoff",
        ));
    }
    let model_unknown: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM model_request_permit WHERE attempt_id=$1 \
         AND status IN('ADMITTED','QUARANTINED') UNION ALL \
         SELECT 1 FROM gateway_scope_budget WHERE attempt_id=$1 AND inflight>0)",
    )
    .bind(&a.attempt_id)
    .fetch_one(&mut **tx)
    .await?;
    if model_unknown {
        return Err(err(
            "MODEL_EFFECT_UNCONFIRMED",
            "model request accounting remains inflight or unknown",
        ));
    }
    let fenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM leases l JOIN tasks t ON t.project_id=l.project_id \
         AND t.task_id=$2 WHERE l.attempt_id=$1 AND l.generation=$3 \
         AND l.revoked_at IS NOT NULL AND t.fence_epoch>$3)",
    )
    .bind(&a.attempt_id)
    .bind(&a.task_id)
    .bind(a.generation)
    .fetch_one(&mut **tx)
    .await?;
    if !fenced {
        return Err(err(
            "LEASE_STALE",
            "terminal handoff requires revoked predecessor lease and advanced task fence",
        ));
    }
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED')",
    ).bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if held {
        return Err(err(
            "RESOURCE_LEDGER_CORRUPT",
            "terminal handoff did not release full resource vector",
        ));
    }
    Ok(())
}

async fn allocation_evidence(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<Vec<Value>> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object('allocation_id',allocation_id,'project_id',project_id, \
         'attempt_id',attempt_id,'scope_id',scope_id,'dimension',dimension,'amount',amount, \
         'state',state,'acquired_at',acquired_at,'released_at',released_at,'release_reason',release_reason) \
         FROM resource_allocations WHERE attempt_id=$1 ORDER BY scope_id,dimension",
    ).bind(&a.attempt_id).fetch_all(&mut **tx).await?)
}

async fn allocated_counts(tx: &mut Transaction<'_, Postgres>) -> Result<Value> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object( \
         'all_allocated_attempts',(SELECT count(DISTINCT r.attempt_id) FROM resource_allocations r \
             WHERE r.dimension='active_slot' AND r.state<>'RELEASED'), \
         'controlled_allocated_attempts',(SELECT count(DISTINCT r.attempt_id) \
             FROM resource_allocations r JOIN attempts a USING(attempt_id) \
             WHERE r.dimension='active_slot' AND r.state<>'RELEASED' AND a.envelope->'command' IS NOT NULL \
             AND a.envelope->'command'<>'null'::jsonb), \
         'global_active_slots',(SELECT COALESCE(jsonb_object_agg(s.scope_id,l.allocated),'{}'::jsonb) \
             FROM resource_scopes s JOIN resource_limits l USING(scope_id) \
             WHERE s.project_id IS NULL AND s.worker_id IS NULL AND l.dimension='active_slot'))",
    ).fetch_one(&mut **tx).await?)
}

async fn queued_proposal(
    tx: &mut Transaction<'_, Postgres>,
    selected: &QueuedReplacement,
) -> Result<Value> {
    let request = &selected.admission;
    if !matches!(request.actor_id.as_str(), "scheduler-service" | "internal") {
        return Err(err(
            "AUTHORITY_SCOPE_VIOLATION",
            "queue consumption belongs to scheduler authority",
        ));
    }
    let row = sqlx::query(
        "SELECT revision,data FROM documents WHERE project_id=$1 AND collection='queue_entries' \
         AND document_id=$2 FOR UPDATE",
    )
    .bind(&request.project_id)
    .bind(&request.task_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        err(
            "HANDOFF_QUEUE_UNAUTHORIZED",
            "replacement requires an existing authorized queue proposal",
        )
    })?;
    let queued: Value = row.try_get("data")?;
    if row.try_get::<i64, _>("revision")? != i64v(selected.queue_revision)?
        || queued["status"].as_str() != Some("QUEUED")
        || queued["project_id"].as_str() != Some(request.project_id.as_str())
        || queued["task_id"].as_str() != Some(request.task_id.as_str())
        || queued["task_revision"].as_u64() != Some(request.task_revision)
        || queued["flow_revision"].as_u64() != Some(request.flow_revision)
        || queued["lease_seconds"].as_u64() != Some(u64::from(request.lease_seconds))
        || queued["envelope"] != json(&request.envelope)?
        || queued["worker_id"]
            .as_str()
            .is_none_or(|worker| !worker.is_empty() && worker != request.worker_id)
    {
        return Err(err(
            "REVISION_CONFLICT",
            "replacement must consume exact current immutable queue proposal",
        ));
    }
    if request.idempotency_key
        != format!(
            "schedule:{}:{}:{}:{}",
            request.project_id, request.task_id, request.task_revision, selected.queue_revision
        )
    {
        return Err(err(
            "HANDOFF_QUEUE_UNAUTHORIZED",
            "replacement must use canonical scheduler admission identity",
        ));
    }
    let now_ms = db_now(tx).await?.timestamp_millis();
    if queued["retry_not_before_ms"]
        .as_i64()
        .is_some_and(|at| at > now_ms)
    {
        return Err(err(
            "ADMISSION_BLOCKED",
            "queued retry delay remains active",
        ));
    }
    if !selected.scheduler_state.is_object() || selected.scheduler_state.get("cursor").is_none() {
        return Err(err(
            "VALIDATION_ERROR",
            "replacement requires persisted ordinary scheduler cursor",
        ));
    }
    Ok(queued)
}

async fn persist_document(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    collection: &str,
    document: &str,
    expected: Option<u64>,
    mut value: Value,
) -> Result<()> {
    project_lock(tx, project).await?;
    let actual: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3 FOR UPDATE",
    ).bind(project).bind(collection).bind(document).fetch_optional(&mut **tx).await?;
    if actual != expected.map(i64v).transpose()? {
        return Err(err(
            "REVISION_CONFLICT",
            "queue or scheduler cursor changed before handoff",
        ));
    }
    let revision = actual
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| err("REVISION_CONFLICT", "document revision exhausted"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| err("VALIDATION_ERROR", "handoff document must be an object"))?;
    object.insert("revision".into(), Value::from(revision));
    sqlx::query(
        "INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,$2,$3,$4,$5) \
         ON CONFLICT(project_id,collection,document_id) DO UPDATE SET revision=$4,data=$5",
    ).bind(project).bind(collection).bind(document).bind(revision).bind(&value)
        .execute(&mut **tx).await?;
    event(
        tx,
        project,
        document,
        revision as u64,
        "document.updated",
        crate::catalog::document_event_payload(project, collection, document, &value)?,
    )
    .await
}
