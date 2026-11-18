//! Owner-authorized, time-bounded controlled channel pools and terminal handoff.
use super::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use forgeflow_git::IntegrationStore;
use forgeflow_scheduler::{PumpConfig, StoreHandoffScheduler};
use forgeflow_store::{HandoffReceipt, HandoffRequest, TerminalAcknowledgement};
use std::collections::BTreeSet;

pub(crate) const COLLECTION: &str = "channel_pools";
pub(crate) const POLICY_ID: &str = "strict-controlled";
const SERVICE: &str = "channel-pool-service";
const CONTROLLED_EXECUTOR: &str = "controlled-lightweight.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PoolStatus {
    Active,
    Draining,
    Ended,
}

/// Definitions are immutable after activation. Lifecycle writes retain the full
/// original window and baseline; elapsed time alone never authorizes a release.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelPool {
    pub schema_version: String,
    pub project_id: String,
    pub status: PoolStatus,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub target_channels: u64,
    pub worker_id: String,
    pub resource_profile_id: String,
    pub executor_profile_id: String,
    pub controlled_only: bool,
    pub launch_grace_ms: u64,
    pub known_baseline_proof: BaselineProof,
    pub authorized_by: String,
    pub authorized_at: DateTime<Utc>,
    pub activation_identity: CommandIdentity,
    pub activation_request_sha256: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub qualification_aborted: bool,
    #[serde(default)]
    pub drain_authorized_by: Option<String>,
    #[serde(default)]
    pub drain_authorized_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub drain_reason: Option<String>,
    #[serde(default)]
    pub drain_identity: Option<CommandIdentity>,
    #[serde(default)]
    pub drain_request_sha256: Option<String>,
    #[serde(default)]
    pub ended_by: Option<String>,
    #[serde(default)]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end_reason: Option<String>,
    #[serde(default)]
    pub end_identity: Option<CommandIdentity>,
    #[serde(default)]
    pub end_request_sha256: Option<String>,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineProof {
    pub attempt_ids: Vec<String>,
    pub snapshot_revision: u64,
    pub observed_at: DateTime<Utc>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurePool {
    #[serde(deserialize_with = "explicit_utc")]
    pub starts_at: DateTime<Utc>,
    #[serde(deserialize_with = "explicit_utc")]
    pub ends_at: DateTime<Utc>,
    pub target_channels: u64,
    pub worker_id: String,
    pub resource_profile_id: String,
    pub controlled_only: bool,
    pub launch_grace_ms: u64,
    pub baseline_attempt_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub expected_revision: u64,
    pub reason: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub abort_before_end: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn explicit_utc<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let value = String::deserialize(d)?;
    let time = DateTime::parse_from_rfc3339(&value).map_err(serde::de::Error::custom)?;
    if time.offset().local_minus_utc() != 0 || !(value.ends_with('Z') || value.ends_with("+00:00"))
    {
        return Err(serde::de::Error::custom(
            "pool windows require explicit UTC",
        ));
    }
    Ok(time.with_timezone(&Utc))
}

fn owner(actor: &Principal) -> Result<(), ApiError> {
    if actor.worker || !matches!(actor.actor_id.as_str(), "owner" | "owner-service") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_AUTHORIZATION_REQUIRED",
            "channel pool lifecycle requires Owner authorization",
        ));
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<String, ApiError> {
    Ok(forgeflow_planner::sha256(
        &serde_json::to_vec(value).map_err(contract_error)?,
    ))
}

fn contract_error(error: serde_json::Error) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "CHANNEL_POOL_INVALID",
        error.to_string(),
    )
}

pub(crate) fn scheduler(project: &str) -> Result<StoreHandoffScheduler, ApiError> {
    StoreHandoffScheduler::for_strict_pool(PumpConfig::default(), project.to_owned()).map_err(
        |error| {
            ApiError::new(
                StatusCode::CONFLICT,
                "CHANNEL_POOL_SELECTOR_INVALID",
                error.to_string(),
            )
        },
    )
}

fn same_identity(left: &CommandIdentity, right: &CommandIdentity) -> bool {
    left.actor_id == right.actor_id && left.idempotency_key == right.idempotency_key
}

impl ConfigurePool {
    fn validate(&self, now: DateTime<Utc>) -> Result<(), ApiError> {
        let ids: BTreeSet<_> = self.baseline_attempt_ids.iter().collect();
        if self.starts_at >= self.ends_at
            || now < self.starts_at
            || now >= self.ends_at
            || self.target_channels == 0
            || self.worker_id.is_empty()
            || self.resource_profile_id.is_empty()
            || !self.controlled_only
            || self.launch_grace_ms != 2000
            || ids.len() != self.baseline_attempt_ids.len()
            || ids.iter().any(|id| id.is_empty())
            || ids.len() as u64 != self.target_channels
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "CHANNEL_POOL_INVALID",
                "activation requires a live UTC window, exact distinct baseline, controlled profile and 2000ms launch grace",
            ));
        }
        Ok(())
    }
}

pub(crate) async fn load(s: &App, project: &str) -> Result<Option<ChannelPool>, ApiError> {
    match s.store.get_document(project, COLLECTION, POLICY_ID).await {
        Ok(value) => {
            let pool: ChannelPool = serde_json::from_value(value).map_err(contract_error)?;
            if pool.schema_version != "forgeflow.channel_pool.v1"
                || pool.project_id != project
                || !pool.controlled_only
                || pool.executor_profile_id != CONTROLLED_EXECUTOR
                || pool.launch_grace_ms != 2000
                || pool.starts_at >= pool.ends_at
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "CHANNEL_POOL_INVALID",
                    "persisted pool policy is invalid; Owner intervention required",
                ));
            }
            Ok(Some(pool))
        }
        Err(forgeflow_store::StoreError::Domain(error)) if error.code == "NOT_FOUND" => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub async fn read_pool(State(s): State<App>, Path(project): Path<String>) -> ApiResult<Value> {
    s.store.get_project(&project).await?;
    Ok(view(load(&s, &project).await?))
}

pub async fn configure_pool(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ConfigurePool>,
) -> ApiResult<Value> {
    owner(&actor)?;
    let command_identity = identity(&headers, &actor)?;
    let request_digest = digest(&body)?;
    if let Some(pool) = load(&s, &project).await? {
        if same_identity(&pool.activation_identity, &command_identity) {
            if pool.activation_request_sha256 != request_digest {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "pool activation key reused with changed definition",
                ));
            }
            return Ok(Json(
                json!({"data":pool,"replayed":true,"source":"postgres"}),
            ));
        }
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "IMMUTABLE_CHANNEL_POOL",
            "pool definition already authorized; use explicit drain and end commands",
        ));
    }
    body.validate(Utc::now())?;
    let snapshot = s.store.snapshot(&project).await?;
    let baseline: BTreeSet<_> = body.baseline_attempt_ids.iter().cloned().collect();
    // These checks give precise API errors; the service-owned Store write repeats
    // authority and launch checks under its transaction lock.
    let allocations = snapshot["allocations"].as_array().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "CHANNEL_POOL_BASELINE_INVALID",
            "allocation snapshot missing",
        )
    })?;
    let occupied: BTreeSet<String> = allocations
        .iter()
        .filter(|a| a["dimension"] == "active_slot" && a["state"] != "RELEASED")
        .filter_map(|a| a["attempt_id"].as_str().map(str::to_owned))
        .collect();
    for attempt_id in &baseline {
        let attempt = s.store.get_attempt(&project, attempt_id).await?;
        let task = s.store.attempt_task(&attempt).await?;
        let envelope = s.store.attempt_envelope(&project, attempt_id).await?;
        if attempt.state.is_terminal()
            || attempt.worker_id != body.worker_id
            || !occupied.contains(attempt_id)
            || envelope.command.is_none()
            || envelope.executor_profile_id != CONTROLLED_EXECUTOR
            || envelope.resource_profile_id != body.resource_profile_id
            || task.resource_request.provider_inflight != 0
            || envelope.max_model_requests != 0
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "CHANNEL_POOL_BASELINE_INVALID",
                "baseline requires occupied controlled attempts on the authorized worker and frozen profile with zero model requests",
            ));
        }
    }
    let now = Utc::now();
    let pool = ChannelPool {
        schema_version: "forgeflow.channel_pool.v1".into(),
        project_id: project,
        status: PoolStatus::Active,
        starts_at: body.starts_at,
        ends_at: body.ends_at,
        target_channels: body.target_channels,
        worker_id: body.worker_id,
        resource_profile_id: body.resource_profile_id,
        executor_profile_id: CONTROLLED_EXECUTOR.into(),
        controlled_only: true,
        launch_grace_ms: 2000,
        known_baseline_proof: BaselineProof {
            attempt_ids: baseline.into_iter().collect(),
            snapshot_revision: snapshot["revision"].as_u64().ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "CHANNEL_POOL_BASELINE_INVALID",
                    "snapshot revision missing",
                )
            })?,
            observed_at: serde_json::from_value(snapshot["as_of"].clone())
                .map_err(contract_error)?,
            snapshot_sha256: digest(&snapshot)?,
        },
        authorized_by: actor.actor_id,
        authorized_at: now,
        activation_identity: command_identity.clone(),
        activation_request_sha256: request_digest,
        qualification_aborted: false,
        drain_authorized_by: None,
        drain_authorized_at: None,
        drain_reason: None,
        drain_identity: None,
        drain_request_sha256: None,
        ended_by: None,
        ended_at: None,
        end_reason: None,
        end_identity: None,
        end_request_sha256: None,
        revision: 0,
    };
    save(&s, command_identity, &pool, None).await
}

async fn save(
    s: &App,
    command_identity: CommandIdentity,
    pool: &ChannelPool,
    expected: Option<u64>,
) -> ApiResult<Value> {
    let mut value = serde_json::to_value(pool).map_err(contract_error)?;
    value
        .as_object_mut()
        .expect("pool object")
        .remove("revision");
    let receipt = s
        .store
        .execute_command(
            CommandIdentity {
                actor_id: SERVICE.into(),
                idempotency_key: digest(&command_identity)?,
            },
            CatalogCommand::PutDocument {
                project_id: pool.project_id.clone(),
                collection: COLLECTION.into(),
                id: POLICY_ID.into(),
                expected_revision: expected,
                value,
            },
        )
        .await?;
    Ok(Json(
        json!({"data":receipt.value,"operation_id":receipt.operation_id,"replayed":receipt.replayed}),
    ))
}

pub async fn drain_pool(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<LifecycleRequest>,
) -> ApiResult<Value> {
    lifecycle(s, project, actor, headers, body, false).await
}

pub async fn finish_pool(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<LifecycleRequest>,
) -> ApiResult<Value> {
    lifecycle(s, project, actor, headers, body, true).await
}

async fn lifecycle(
    s: App,
    project: String,
    actor: Principal,
    headers: HeaderMap,
    body: LifecycleRequest,
    end: bool,
) -> ApiResult<Value> {
    owner(&actor)?;
    let command_identity = identity(&headers, &actor)?;
    let request_digest = digest(&body)?;
    let mut pool = load(&s, &project).await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "CHANNEL_POOL_NOT_FOUND",
            "pool has no authorized policy",
        )
    })?;
    let replay_identity = if end {
        &pool.end_identity
    } else {
        &pool.drain_identity
    };
    let replay_digest = if end {
        &pool.end_request_sha256
    } else {
        &pool.drain_request_sha256
    };
    if replay_identity
        .as_ref()
        .is_some_and(|old| same_identity(old, &command_identity))
    {
        if replay_digest.as_deref() != Some(request_digest.as_str()) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "IDEMPOTENCY_CONFLICT",
                "pool lifecycle key reused with changed request",
            ));
        }
        return Ok(Json(
            json!({"data":pool,"replayed":true,"source":"postgres"}),
        ));
    }
    let now = Utc::now();
    if body.reason.trim().is_empty()
        || body.expected_revision != pool.revision
        || (now < pool.ends_at && !(pool.qualification_aborted || (!end && body.abort_before_end)))
        || (end && body.abort_before_end)
        || pool.status
            != if end {
                PoolStatus::Draining
            } else {
                PoolStatus::Active
            }
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "CHANNEL_POOL_LIFECYCLE_CONFLICT",
            "Owner lifecycle requires the current revision and a recorded reason; early drain must explicitly abort qualification",
        ));
    }
    if end {
        pool.status = PoolStatus::Ended;
        pool.ended_by = Some(actor.actor_id);
        pool.ended_at = Some(now);
        pool.end_reason = Some(body.reason);
        pool.end_identity = Some(command_identity.clone());
        pool.end_request_sha256 = Some(request_digest);
    } else {
        pool.status = PoolStatus::Draining;
        pool.qualification_aborted = body.abort_before_end;
        pool.drain_authorized_by = Some(actor.actor_id);
        pool.drain_authorized_at = Some(now);
        pool.drain_reason = Some(body.reason);
        pool.drain_identity = Some(command_identity.clone());
        pool.drain_request_sha256 = Some(request_digest);
    }
    save(&s, command_identity, &pool, Some(body.expected_revision)).await
}

/// Scope is read from authority, never from a verification request body. Store
/// independently checks the policy under the terminal transaction lock.
pub(crate) async fn strict_for_attempt(
    s: &App,
    project: &str,
    attempt: &Attempt,
) -> Result<bool, ApiError> {
    let Some(pool) = load(s, project).await? else {
        return Ok(false);
    };
    let envelope = s
        .store
        .attempt_envelope(project, &attempt.attempt_id)
        .await?;
    let scoped = attempt.worker_id == pool.worker_id
        && envelope.executor_profile_id == pool.executor_profile_id
        && envelope.resource_profile_id == pool.resource_profile_id
        && envelope.command.is_some();
    if !scoped {
        return Ok(false);
    }
    if pool.status == PoolStatus::Active {
        if Utc::now() < pool.starts_at || Utc::now() >= pool.ends_at {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "CHANNEL_POOL_WINDOW_CLOSED",
                "ACTIVE pool retains resources outside its original window; Owner must explicitly authorize draining",
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

pub async fn worker_result(
    State(s): State<App>,
    Path(attempt_id): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<WorkerResult>,
) -> ApiResult<Value> {
    if !actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_AUTH_REQUIRED",
            "handoff results require the scoped Worker service token",
        ));
    }
    s.auth
        .worker_scope(&actor, Some(&body.worker_id), Some(&body.project_id))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    let command_identity = identity(&headers, &actor)?;
    if body.attempt_id != attempt_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IDENTITY_MISMATCH",
            "attempt path/body differ",
        ));
    }
    let attempt =
        crate::workers::authorized_attempt(&s, &actor, &body.project_id, &attempt_id).await?;
    let pool = match load(&s, &body.project_id).await? {
        Some(pool) => pool,
        None if body
            .evidence
            .get("process_exit_confirmed")
            .and_then(Value::as_bool)
            == Some(true)
            && matches!(
                attempt.state,
                AttemptState::Stopping | AttemptState::RecoveryRequired | AttemptState::Cancelled
            ) =>
        {
            // The Worker freezes strict delivery before the Owner can activate
            // a fully observed fleet. A failed initialization still needs its
            // canonical stop acknowledgement. Store rechecks identity, stop
            // proof and any pool activated since this read under its transaction.
            let stopped = s.store.worker_result(body).await?;
            return Ok(Json(
                json!({"data":stopped,"handoff":null,"initialization_stop":true,"source":"postgres"}),
            ));
        }
        None => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "CHANNEL_POOL_NOT_ACTIVE",
                "handoff-result requires an Owner-authorized controlled channel pool",
            ));
        }
    };
    let envelope = s
        .store
        .attempt_envelope(&body.project_id, &attempt_id)
        .await?;
    if attempt.worker_id != pool.worker_id
        || envelope.executor_profile_id != pool.executor_profile_id
        || envelope.resource_profile_id != pool.resource_profile_id
        || envelope.command.is_none()
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "CHANNEL_POOL_SCOPE_DENIED",
            "attempt does not belong to the authorized controlled worker and profile",
        ));
    }
    let success = body.outcome.completion_reason == "EXECUTOR_COMPLETED"
        && body.outcome.exit_code == Some(0)
        && body.evidence.get("log_error").is_none_or(Value::is_null);
    if success
        && !matches!(
            attempt.state,
            AttemptState::Stopping | AttemptState::RecoveryRequired | AttemptState::Cancelled
        )
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "HANDOFF_REQUIRES_TERMINAL",
            "execution success enters VERIFYING through execution-result before independent verification",
        ));
    }
    let result = s
        .store
        .terminal_handoff(
            HandoffRequest {
                identity: command_identity,
                terminal: TerminalAcknowledgement::WorkerResult {
                    result: body.clone(),
                },
            },
            &scheduler(&body.project_id)?,
        )
        .await;
    match result {
        Ok(receipt) => Ok(Json(
            json!({"data":receipt,"operation_id":receipt.operation_id,"replayed":receipt.replayed}),
        )),
        // This single Store verdict means the Owner explicitly authorized
        // draining after the immutable window. Other errors retain allocation.
        Err(forgeflow_store::StoreError::Domain(error))
            if error.code == "CHANNEL_POOL_DRAINING" =>
        {
            let attempt = s.store.worker_result(body).await?;
            Ok(Json(
                json!({"data":attempt,"handoff":null,"draining":true,"source":"postgres"}),
            ))
        }
        Err(error) => Err(error.into()),
    }
}

/// The Git service keeps its actual CAS and evidence proof before this adapter
/// replaces only the final database acknowledgement.
pub(crate) struct PoolIntegrationStore {
    state: App,
    operation_id: String,
    receipt: tokio::sync::Mutex<Option<HandoffReceipt>>,
}

impl PoolIntegrationStore {
    pub(crate) fn new(state: App, operation_id: &str) -> Self {
        Self {
            state,
            operation_id: operation_id.into(),
            receipt: tokio::sync::Mutex::new(None),
        }
    }
    pub(crate) async fn handoff_receipt(&self) -> Option<HandoffReceipt> {
        self.receipt.lock().await.clone()
    }
}

#[async_trait]
impl IntegrationStore for PoolIntegrationStore {
    async fn prepare_merge(&self, intent: MergeIntent) -> Result<MergeIntent, String> {
        self.state
            .store
            .prepare_merge(intent)
            .await
            .map_err(|e| e.to_string())
    }
    async fn decide_merge(&self, p: &str, i: &str, r: u64) -> Result<MergeIntent, String> {
        self.state
            .store
            .decide_merge(p, i, r)
            .await
            .map_err(|e| e.to_string())
    }
    async fn confirm_merge(
        &self,
        p: &str,
        i: &str,
        sha: &str,
        receipt: Value,
    ) -> Result<MergeIntent, String> {
        // mark_ref_updated verifies the authoritative Git ref, frozen plan,
        // receipt binding and raw logs before persisting REF_UPDATED.
        let intent = self
            .state
            .store
            .mark_ref_updated(p, i, sha, receipt)
            .await
            .map_err(|e| e.to_string())?;
        let attempt = self
            .state
            .store
            .get_attempt(p, &intent.attempt_id)
            .await
            .map_err(|e| e.to_string())?;
        if strict_for_attempt(&self.state, p, &attempt)
            .await
            .map_err(|e| e.1.to_string())?
        {
            let receipt = self
                .state
                .store
                .terminal_handoff(
                    HandoffRequest {
                        identity: CommandIdentity {
                            actor_id: "verification-service".into(),
                            idempotency_key: format!("{}:finalize-handoff", self.operation_id),
                        },
                        terminal: TerminalAcknowledgement::FinalizeMerge {
                            project_id: p.into(),
                            intent_id: i.into(),
                        },
                    },
                    &scheduler(p).map_err(|e| e.1.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())?;
            *self.receipt.lock().await = Some(receipt);
            self.state
                .store
                .get_merge_intent(p, i)
                .await
                .map_err(|e| e.to_string())
        } else {
            self.state
                .store
                .finalize_merge(p, i)
                .await
                .map_err(|e| e.to_string())
        }
    }
    async fn get_merge_intent(&self, p: &str, i: &str) -> Result<MergeIntent, String> {
        self.state
            .store
            .get_merge_intent(p, i)
            .await
            .map_err(|e| e.to_string())
    }
    async fn pending_merges(&self, p: &str, target: &str) -> Result<Vec<MergeIntent>, String> {
        self.state
            .store
            .pending_merges(p, target)
            .await
            .map_err(|e| e.to_string())
    }
    async fn abort_merge(&self, p: &str, i: &str, reason: &str) -> Result<MergeIntent, String> {
        self.state
            .store
            .abort_merge(p, i, reason)
            .await
            .map_err(|e| e.to_string())
    }
    async fn mark_merge_recovery_required(
        &self,
        p: &str,
        i: &str,
        reason: &str,
    ) -> Result<MergeIntent, String> {
        self.state
            .store
            .mark_merge_recovery_required(p, i, reason)
            .await
            .map_err(|e| e.to_string())
    }
}
