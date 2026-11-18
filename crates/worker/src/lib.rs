//! Separate authenticated worker; server remains the sole business authority.
mod attempt_preparation;
mod claude_supervisor;
mod configuration;
pub mod ecp_child_authority;
pub mod ecp_registration;
pub mod ecp_resume;
mod executor_profile;
pub use configuration::load_configuration;
pub use executor_profile::WorkerExecutorProfile;
pub mod model_relay;
pub mod native_controller;
use anyhow::{Context, Result, bail};
use forgeflow_domain::{ExecutionEnvelope, ExecutorOutcome};
pub use forgeflow_domain::{
    WorkerEvent, WorkerHeartbeatRequest as WorkerHeartbeat,
    WorkerRegisterRequest as RegisterRequest, WorkerResult,
};
use forgeflow_executors::{HeadlessProfile, HeadlessStream, prepare_headless, sha256};
use forgeflow_runtime::{
    Journal, LaunchIntent, LogNotice, ProcessSpec, RecoveryDisposition, StopEvidence,
    SupervisionLimits, boot_id, durable_json, reconcile, safe_id, supervise,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{mpsc, watch},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub project_id: String,
    pub known_attempt_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub envelope: Option<ExecutionEnvelope>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub valid: bool,
    pub cancel_requested: bool,
    pub lease_expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretBinding {
    pub env_name: String,
    pub path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub control_url: String,
    pub worker_id: String,
    pub project_id: String,
    pub data_root: PathBuf,
    pub profile: WorkerExecutorProfile,
    pub model_route_id: String,
    #[serde(default)]
    pub secret_files: BTreeMap<String, SecretBinding>,
    #[serde(default = "default_poll")]
    pub poll_seconds: u64,
    #[serde(default = "default_logs")]
    pub max_log_bytes: u64,
    #[serde(default = "default_concurrency")]
    pub max_active_attempts: usize,
    #[serde(default)]
    pub controlled_workload_programs: BTreeMap<String, String>,
    #[serde(default)]
    pub sandbox: Option<forgeflow_runtime::SandboxProfile>,
    /// Terminal failures use the canonical atomic handoff transaction. Its refusal
    /// retains this attempt; the worker never retries through ordinary release.
    #[serde(default)]
    pub strict_resource_handoff: bool,
    #[serde(default)]
    pub managed_dsh: Option<ManagedDshConfig>,
    /// Discovered only by the dedicated delegated user-service bootstrap.
    #[serde(default)]
    pub cgroup_delegation: Option<forgeflow_runtime::CgroupDelegation>,
}

/// Immutable managed mode references. They are part of the flat frozen executor
/// registration together with the original HeadlessProfile and its file pins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedDshConfig {
    pub mode_id: String,
    pub mode_manifest: PathBuf,
    pub preset_patch: PathBuf,
    pub bridge_plugin: PathBuf,
    pub selected_model_config: PathBuf,
    pub credentials: PathBuf,
    pub doctor: PathBuf,
    #[serde(default = "default_native_rpc_timeout")]
    pub rpc_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_relay: Option<model_relay::ModelRelayConfig>,
}
fn default_native_rpc_timeout() -> u64 {
    2000
}

fn frozen_executor_profile(config: &WorkerConfig) -> Result<Value> {
    let mut value = serde_json::to_value(&config.profile)?;
    if let Some(managed) = &config.managed_dsh {
        if config.profile.dsh().is_none() {
            bail!("Claude profile cannot contain managed DSH configuration");
        }
        let fields = value
            .as_object_mut()
            .context("headless profile must be an object")?;
        fields.insert("kind".into(), json!("DSH_MANAGED"));
        fields.insert("native_mode".into(), serde_json::to_value(managed)?);
    }
    Ok(value)
}
fn profile_is_claude(config: &WorkerConfig) -> bool {
    config.profile.claude().is_some()
}
fn default_concurrency() -> usize {
    4
}
fn default_poll() -> u64 {
    2
}
fn default_logs() -> u64 {
    256 * 1024 * 1024
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalResourceProbe {
    schema_version: String,
    delegation: forgeflow_runtime::CgroupDelegation,
    program: PathBuf,
    program_sha256: String,
    args: Vec<String>,
    output_dir: PathBuf,
    limits: forgeflow_runtime::PhysicalCgroupLimits,
    timeout_seconds: u64,
}
/// A bounded trusted helper invokes the same actual supervisor used by required
/// profiles. It has no API client, Worker registration, model or ledger claims.
pub async fn physical_resource_probe(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != std::fs::metadata("/proc/self")?.uid()
    {
        bail!("physical probe configuration must be a private owned regular file");
    }
    let probe: PhysicalResourceProbe = serde_json::from_slice(&std::fs::read(path)?)?;
    probe.limits.validate()?;
    if probe.schema_version != "forgeflow.physical-resource-probe.v1"
        || !probe.program.is_absolute()
        || !probe.output_dir.is_absolute()
        || !(1..=30).contains(&probe.timeout_seconds)
        || sha256(&std::fs::read(&probe.program)?) != probe.program_sha256
    {
        bail!("invalid bounded physical helper specification or executable pin");
    }
    if probe.output_dir.exists() && std::fs::read_dir(&probe.output_dir)?.next().is_some() {
        bail!("physical proof output already exists; retain original evidence");
    }
    std::fs::create_dir_all(&probe.output_dir)?;
    std::fs::set_permissions(&probe.output_dir, std::fs::Permissions::from_mode(0o700))?;
    let journal = Journal {
        directory: probe.output_dir.clone(),
    };
    let execution_id = journal.execution_id()?;
    let intent = LaunchIntent {
        execution_id: execution_id.clone(),
        operation_id: format!("physical-probe-{}", uuid::Uuid::new_v4()),
        attempt_id: format!("physical-probe-{}", uuid::Uuid::new_v4()),
        generation: 1,
        worker_id: "local-physical-probe".into(),
        boot_id: boot_id()?,
        workspace: probe.output_dir.clone(),
        prompt_sha256: sha256(&[]),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let request = forgeflow_runtime::PhysicalFenceRequest {
        project_id: "local-physical-probe".into(),
        resource_binding_sha256: sha256(&serde_json::to_vec(
            &json!({"scope":"LOCAL_TRUSTED_HELPER_NOT_ADMISSION", "limits":probe.limits}),
        )?),
        delegation: probe.delegation.clone(),
        limits: probe.limits.clone(),
    };
    let spec = ProcessSpec {
        program: probe.program,
        args: probe.args,
        cwd: probe.output_dir.clone(),
        stdin: Vec::new(),
        env: BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]),
    };
    let supervisor_pid = std::process::id();
    let supervisor_membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let (_cancel, cancellation) = watch::channel(false);
    let (notices, mut notice_rx) = mpsc::channel(64);
    let drain_notices = tokio::spawn(async move { while notice_rx.recv().await.is_some() {} });
    let (launched, _launch_rx) = watch::channel(None);
    let stop = forgeflow_runtime::supervise_physical(
        spec,
        intent,
        journal.clone(),
        SupervisionLimits {
            timeout: Duration::from_secs(probe.timeout_seconds),
            max_log_bytes: 1024 * 1024,
            ..Default::default()
        },
        cancellation,
        notices,
        launched,
        request,
    )
    .await;
    let _ = drain_notices.await;
    let stop = stop?;
    let fence = forgeflow_runtime::PreparedCgroupFence::restore(&journal)?
        .context("actual physical fence was not prepared")?;
    let membership: Value =
        serde_json::from_slice(&std::fs::read(journal.path("cgroup-membership.json"))?)?;
    let limits_readback = fence.identity.limits_readback()?;
    let receipt = journal.receipt()?;
    let report = json!({"schema_version":"forgeflow.physical-resource-runtime-probe.v1","runtime_api":"supervise_physical",
        "qualification_scope":"LOCAL_TRUSTED_HELPER_ONLY_NOT_BUSINESS_ADMISSION_OR_REAL_DSH",
        "status":if stop.process_exit_confirmed{"STOP_CONFIRMED"}else{"STOP_UNCONFIRMED"},
        "delegation":probe.delegation,"attempt_cgroup":fence.identity.leaf_path,
        "supervisor_pid":supervisor_pid,"supervisor_membership":supervisor_membership,
        "supervisor_alive_after":std::process::id()==supervisor_pid,"limits_readback":limits_readback,
        "files_before":membership["snapshot"],"files_after":fence.snapshot(),
        "child_reaped":stop.process_exit_confirmed,"cgroup_empty":!fence.populated()?,
        "launch_receipt":receipt,"stop_receipt":stop,"physical_identity":fence.identity,
        "execution_id":execution_id,"models_started":0,"workers_registered":0});
    durable_json(&probe.output_dir.join("runtime-report.json"), &report)?;
    if !stop.process_exit_confirmed {
        bail!("physical helper stop unconfirmed; retain quarantine evidence");
    }
    Ok(())
}
#[derive(Clone)]
pub struct ControlClient {
    client: reqwest::Client,
    // Telemetry shares the database write lane. Bound it across every author,
    // while presence, lease renewal, control and settlement stay independent.
    telemetry_slots: std::sync::Arc<tokio::sync::Semaphore>,
    root: reqwest::Url,
    token: String,
    settlements: Option<mpsc::UnboundedSender<SettlementNotice>>,
    dispatch_connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
#[derive(Debug)]
struct SettlementNotice {
    attempt_id: String,
    terminal_confirmed: bool,
    canonical_result: bool,
    wake_only: bool,
}
impl ControlClient {
    pub fn new(root: &str, token: String) -> Result<Self> {
        let root = reqwest::Url::parse(&format!("{}/api/v1/", root.trim_end_matches('/')))?;
        if token.trim().is_empty() {
            bail!("worker authentication token missing");
        }
        if root.scheme() != "https"
            && !root
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]"))
        {
            bail!("remote worker control requires HTTPS");
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            telemetry_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            root,
            token,
            settlements: None,
            dispatch_connected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
    fn url(&self, segments: &[&str]) -> Result<reqwest::Url> {
        let mut url = self.root.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid control URL"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }
    async fn post<T: Serialize>(&self, segments: &[&str], key: &str, body: &T) -> Result<Value> {
        let response = self
            .client
            .post(self.url(segments)?)
            .bearer_auth(&self.token)
            .header("Idempotency-Key", key)
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            bail!("control request rejected with HTTP {status}");
        }
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
    pub async fn register(&self, value: &RegisterRequest) -> Result<()> {
        self.post(
            &["workers", "register"],
            &format!("{}:{}", value.worker_id, value.boot_id),
            value,
        )
        .await?;
        Ok(())
    }
    pub async fn heartbeat(&self, value: &WorkerHeartbeat) -> Result<()> {
        self.post(
            &["workers", &value.worker_id, "heartbeat"],
            &uuid::Uuid::new_v4().to_string(),
            value,
        )
        .await?;
        Ok(())
    }
    pub async fn renew(&self, envelope: &ExecutionEnvelope) -> Result<()> {
        let request = forgeflow_domain::HeartbeatRequest {
            project_id: envelope.project_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            lease_seconds: 30,
        };
        self.post(
            &["attempts", &envelope.attempt_id, "heartbeat"],
            &uuid::Uuid::new_v4().to_string(),
            &request,
        )
        .await?;
        Ok(())
    }
    pub async fn claim(
        &self,
        config: &WorkerConfig,
        known_attempt_ids: Vec<String>,
    ) -> Result<Option<ExecutionEnvelope>> {
        Ok(serde_json::from_value::<ClaimResponse>(
            self.post(
                &["workers", &config.worker_id, "claim"],
                &uuid::Uuid::new_v4().to_string(),
                &ClaimRequest {
                    project_id: config.project_id.clone(),
                    known_attempt_ids,
                },
            )
            .await?,
        )?
        .envelope)
    }
    pub async fn control(&self, envelope: &ExecutionEnvelope) -> Result<ControlResponse> {
        Ok(self
            .client
            .get(self.url(&["attempts", &envelope.attempt_id, "control"])?)
            .bearer_auth(&self.token)
            .query(&[
                ("project_id", envelope.project_id.clone()),
                ("generation", envelope.generation.to_string()),
                ("worker_id", envelope.worker_id.clone()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn attempt(&self, envelope: &ExecutionEnvelope) -> Result<forgeflow_domain::Attempt> {
        let response: Value = self
            .client
            .get(self.url(&["attempts", &envelope.attempt_id])?)
            .bearer_auth(&self.token)
            .query(&[
                ("project_id", &envelope.project_id),
                ("worker_id", &envelope.worker_id),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(serde_json::from_value(
            response.get("data").cloned().unwrap_or(response),
        )?)
    }
    pub async fn bindings(&self, envelope: &ExecutionEnvelope) -> Result<Value> {
        let response: Value = self
            .client
            .get(self.url(&["attempts", &envelope.attempt_id, "bindings"])?)
            .bearer_auth(&self.token)
            .query(&[
                ("project_id", envelope.project_id.clone()),
                ("worker_id", envelope.worker_id.clone()),
                ("generation", envelope.generation.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(response.get("data").cloned().unwrap_or(response))
    }
    pub async fn artifact(&self, project_id: &str, worker_id: &str, id: &str) -> Result<Vec<u8>> {
        use futures::StreamExt;
        let response = self
            .client
            .get(self.url(&["artifacts", id, "content"])?)
            .query(&[("project_id", project_id), ("worker_id", worker_id)])
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(60))
            .send()
            .await?
            .error_for_status()?;
        let mut body = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(part) = body.next().await {
            let part = part?;
            if bytes.len() + part.len() > 32 * 1024 * 1024 {
                bail!("input artifact exceeds bounded worker budget");
            }
            bytes.extend_from_slice(&part);
        }
        Ok(bytes)
    }
    pub async fn event(&self, event: &WorkerEvent) -> Result<()> {
        // The durable outbox is the queue. Do not turn 128 busy authors into
        // 128 additional requests waiting for the same controller write lock.
        let _permit = self
            .telemetry_slots
            .try_acquire()
            .context("worker telemetry lane busy; durable outbox retained")?;
        self.post(
            &["attempts", &event.attempt_id, "worker-events"],
            &event.event_id,
            event,
        )
        .await?;
        Ok(())
    }
    pub async fn result(&self, result: &WorkerResult) -> Result<()> {
        self.post(
            &["attempts", &result.attempt_id, "execution-result"],
            &result.event_id,
            result,
        )
        .await?;
        Ok(())
    }
    pub async fn handoff_result(&self, result: &WorkerResult) -> Result<()> {
        self.post(
            &["attempts", &result.attempt_id, "handoff-result"],
            &result.event_id,
            result,
        )
        .await?;
        Ok(())
    }
    /// Forward one native request with the worker token retained in this client.
    /// Neither native environment nor socket response receives credentials.
    pub async fn native_rpc(
        &self,
        envelope: &ExecutionEnvelope,
        rpc_id: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Value> {
        use futures::StreamExt;
        use native_controller::NativeRpcFailure;
        let transport_error = |error: reqwest::Error, phase| NativeRpcFailure {
            phase,
            code: if error.is_timeout() {
                "NATIVE_CONTROLLER_TIMEOUT"
            } else {
                "NATIVE_CONTROLLER_TRANSPORT"
            },
            http_status: None,
            canonical_code: None,
        };
        let schema_error = |phase| NativeRpcFailure {
            phase,
            code: "NATIVE_CONTROLLER_RESPONSE_INVALID",
            http_status: None,
            canonical_code: None,
        };
        if body.len() > native_controller::MAX_FRAME_BYTES
            || timeout < Duration::from_millis(1)
            || timeout > Duration::from_millis(native_controller::MAX_NATIVE_RPC_TIMEOUT_MS)
        {
            bail!("native request exceeds bounded transport policy");
        }
        let response = self
            .client
            .post(self.url(&["attempts", &envelope.attempt_id, "native-controller"])?)
            .bearer_auth(&self.token)
            .header("x-forgeflow-worker-id", &envelope.worker_id)
            .header("Idempotency-Key", rpc_id)
            .header("Content-Type", "application/json")
            .timeout(timeout)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| transport_error(error, "canonical_http"))?;
        let status = response.status();
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|error| transport_error(error, "canonical_response_body"))?;
            if bytes.len() + chunk.len() > crate::native_controller::MAX_FRAME_BYTES {
                return Err(schema_error("canonical_response_body").into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let canonical_code = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|value| value.get("code").and_then(Value::as_str).map(str::to_owned))
                .filter(|code| {
                    !code.is_empty()
                        && code.len() <= 80
                        && code.bytes().all(|byte| {
                            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                });
            return Err(NativeRpcFailure {
                phase: "canonical_http_status",
                code: "NATIVE_CONTROLLER_CANONICAL_REJECTED",
                http_status: Some(status.as_u16()),
                canonical_code,
            }
            .into());
        }
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|_| schema_error("canonical_response_json"))?;
        let response = response.get("data").cloned().unwrap_or(response);
        if response.get("ok").and_then(Value::as_bool).is_none()
            || response.get("generation").and_then(Value::as_i64) != Some(envelope.generation)
        {
            return Err(schema_error("canonical_response_identity").into());
        }
        Ok(response)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultDeliveryPolicy {
    project_id: String,
    task_id: String,
    attempt_id: String,
    generation: i64,
    worker_id: String,
    strict_resource_handoff: bool,
}

/// Freeze transport policy before any callback. Old journals without a policy
/// keep their previous endpoint, including an unacknowledged immutable callback.
fn result_delivery_policy(
    config: &WorkerConfig,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    admitting: bool,
) -> Result<ResultDeliveryPolicy> {
    if let Some(policy) = attempt_preparation::policy(journal, envelope)? {
        return Ok(policy);
    }
    let path = journal.path("result-delivery-policy.json");
    let policy = if path.exists() {
        serde_json::from_slice::<ResultDeliveryPolicy>(&std::fs::read(&path)?)?
    } else {
        let policy = ResultDeliveryPolicy {
            project_id: envelope.project_id.clone(),
            task_id: envelope.task_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            strict_resource_handoff: admitting && config.strict_resource_handoff,
        };
        durable_json(&path, &policy)?;
        policy
    };
    if policy.project_id != envelope.project_id
        || policy.task_id != envelope.task_id
        || policy.attempt_id != envelope.attempt_id
        || policy.generation != envelope.generation
        || policy.worker_id != envelope.worker_id
    {
        bail!("result delivery policy differs from immutable attempt identity");
    }
    Ok(policy)
}

async fn deliver_result(
    config: &WorkerConfig,
    client: &ControlClient,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    result: &WorkerResult,
) -> Result<()> {
    if result.attempt_id != envelope.attempt_id
        || result.project_id != envelope.project_id
        || result.worker_id != envelope.worker_id
        || result.generation != envelope.generation
        || result.lease_id != envelope.lease_id
    {
        bail!("result delivery identity differs from immutable attempt");
    }
    // A strict sandbox can reject preparation before the supervisor creates a
    // physical leaf. Preserve that original failure; settle only a genuinely
    // unused, identity-bound empty leaf, never an invented author process.
    let settlement_config = config.clone();
    let settlement_envelope = envelope.clone();
    let settlement_journal = journal.clone();
    let settlement_original = result.clone();
    let no_launch = tokio::task::spawn_blocking(move || {
        no_launch_physical_failure_result(
            &settlement_config,
            &settlement_envelope,
            &settlement_journal,
            &settlement_original,
        )
    })
    .await??;
    let result = no_launch.as_ref().unwrap_or(result);
    // Persist a trusted whole-pool author-stop observation independently of
    // the stricter result/financial settlement. Only an explicit Owner command
    // may subsequently close the author while preserving unknown custody.
    if result.evidence["process_exit_confirmed"] == true
        && result
            .evidence
            .get("physical_fence")
            .is_some_and(Value::is_object)
        && result
            .evidence
            .get("physical_stop")
            .is_some_and(Value::is_object)
    {
        let observation_key = format!("{}:author-stop-observation", result.event_id);
        match client
            .post(
                &["attempts", &result.attempt_id, "author-stop-observation"],
                &observation_key,
                result,
            )
            .await
        {
            Ok(observation) => {
                let response = observation.get("data").unwrap_or(&observation);
                if response["event_id"] != observation_key
                    || response["author_stop_confirmed"] != true
                {
                    tracing::warn!(attempt_id=%result.attempt_id,"author stop observation acknowledgement differs; no observation receipt persisted");
                } else {
                    let receipt_path = journal.path(&format!(
                        "author-stop-observation-{}.json",
                        sha256(result.event_id.as_bytes())
                    ));
                    let receipt = json!({"worker_result_sha256":sha256(&serde_json::to_vec(result)?),"response":response});
                    tokio::task::spawn_blocking(move || durable_json(&receipt_path, &receipt))
                        .await??;
                }
            }
            Err(error) => {
                tracing::debug!(attempt_id=%result.attempt_id,%error,"author stop observation unavailable; ordinary settlement remains strict")
            }
        }
    }
    // Stop settlement may follow a crash before the telemetry outbox was
    // materialized. Its original bytes must remain durable before any callback.
    ensure_deferred_starting(journal, None, true).await?;
    let policy = result_delivery_policy(config, envelope, journal, false)?;
    let passed = result.outcome.completion_reason == "EXECUTOR_COMPLETED"
        && result.outcome.exit_code == Some(0)
        && result.evidence.get("log_error").is_none_or(Value::is_null);
    let response = if policy.strict_resource_handoff && !passed {
        client
            .post(
                &["attempts", &result.attempt_id, "handoff-result"],
                &result.event_id,
                result,
            )
            .await?
    } else {
        client
            .post(
                &["attempts", &result.attempt_id, "execution-result"],
                &result.event_id,
                result,
            )
            .await?
    };
    let authority = response.get("data").unwrap_or(&response);
    let terminal = authority.get("terminal").unwrap_or(authority);
    let terminal_confirmed = if terminal.get("attempt_id").is_some() {
        let terminal: forgeflow_domain::Attempt = serde_json::from_value(terminal.clone())?;
        if terminal.project_id != envelope.project_id
            || terminal.task_id != envelope.task_id
            || terminal.task_revision != envelope.task_revision
            || terminal.attempt_id != envelope.attempt_id
            || terminal.lease_id != envelope.lease_id
            || terminal.worker_id != envelope.worker_id
            || terminal.generation != envelope.generation
            || terminal.operation_id != envelope.operation_id
            || terminal.base_sha != envelope.base_sha
        {
            bail!("result acknowledgement differs from immutable attempt identity");
        }
        terminal.state.is_terminal()
            && result
                .evidence
                .get("process_exit_confirmed")
                .and_then(Value::as_bool)
                == Some(true)
            && matches!(journal.disposition()?, RecoveryDisposition::Completed)
    } else {
        false
    };
    // Persist the ACK before waking admission. This is the controller's terminal
    // verdict plus actual local quiescence, never a RESERVED successor count.
    let canonical_result = match std::fs::read(journal.path("result.json")) {
        Ok(bytes) => serde_json::from_slice::<WorkerResult>(&bytes)?.event_id == result.event_id,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
    };
    let ack = if canonical_result {
        journal.path("result-ack.json")
    } else {
        journal.path(&format!(
            "result-{}-ack.json",
            sha256(result.event_id.as_bytes())
        ))
    };
    let value = json!({"event_id":result.event_id,"terminal_confirmed":terminal_confirmed,"controller_response":response});
    tokio::task::spawn_blocking(move || durable_json(&ack, &value)).await??;
    if let Some(settlements) = &client.settlements {
        let _ = settlements.send(SettlementNotice {
            attempt_id: envelope.attempt_id.clone(),
            terminal_confirmed,
            canonical_result,
            wake_only: false,
        });
    }
    Ok(())
}

fn no_launch_failure_has_launch_facts(journal: &Journal) -> Result<bool> {
    for name in [
        "launch.lock",
        "launch-intent.json",
        "launch-receipt.json",
        "cgroup-membership.json",
    ] {
        match std::fs::symlink_metadata(journal.path(name)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

/// Supplemental failure settlement, not launch authority. Original stop/result
/// files remain immutable and the ordinary Store physical-stop validator decides
/// whether the returned raw observation can release the admitted reservation.
fn no_launch_physical_failure_result(
    config: &WorkerConfig,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    original: &WorkerResult,
) -> Result<Option<WorkerResult>> {
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if original.outcome.completion_reason != "WORKER_PREPARATION_FAILED"
        || original.evidence.get("process_exit_confirmed") != Some(&json!(true))
        || original.evidence.get("physical_fence").is_some()
    {
        return Ok(None);
    }
    let bindings: Value = match std::fs::read(journal.path("execution-bindings.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bindings["resource_profile"]
        .get("physical_limits")
        .is_none()
    {
        return Ok(None);
    }
    if no_launch_failure_has_launch_facts(journal)? {
        return Ok(None);
    }
    let restored = attempt_preparation::restore(journal)?
        .context("no-launch physical failure needs immutable preparation authority")?;
    if restored != *envelope
        || envelope.worker_id != config.worker_id
        || envelope.project_id != config.project_id
        || original.outcome.execution_id != journal.execution_id()?
    {
        bail!("no-launch failure differs from frozen preparation identity");
    }
    let original_bytes = std::fs::read(journal.path("result.json"))?;
    let recorded: WorkerResult = serde_json::from_slice(&original_bytes)?;
    if serde_json::to_value(&recorded)? != serde_json::to_value(original)?
        || recorded.attempt_id != envelope.attempt_id
        || recorded.project_id != envelope.project_id
        || recorded.worker_id != envelope.worker_id
        || recorded.lease_id != envelope.lease_id
        || recorded.generation != envelope.generation
    {
        bail!("no-launch original result identity or bytes changed");
    }
    let stop_bytes = std::fs::read(journal.path("stop.json"))?;
    let original_stop: StopEvidence = serde_json::from_slice(&stop_bytes)?;
    if !original_stop.process_exit_confirmed
        || original_stop.exit_code.is_some()
        || original_stop.signal.is_some()
        || original_stop.stdout_bytes != 0
        || original_stop.stderr_bytes != 0
        || serde_json::to_value(&original_stop)? != original.evidence["stop"]
    {
        bail!("no-launch failure must retain the original unexecuted stop facts");
    }
    let pool: forgeflow_domain::PhysicalResourceBinding = serde_json::from_value(
        bindings
            .get("physical_resources")
            .cloned()
            .context("no-launch frozen physical reservation missing")?,
    )?;
    pool.verify()?;
    if pool.resource_profile_id != envelope.resource_profile_id
        || serde_json::to_value(&pool.physical_limits)?
            != bindings["resource_profile"]["physical_limits"]
        || config
            .sandbox
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            != bindings["resource_profile"].get("sandbox").cloned()
    {
        bail!("no-launch physical reservation or sandbox differs from frozen profile");
    }
    let boot = boot_id()?;
    let marker = json!({"schema_version":"forgeflow.no-launch-physical-failure.v1",
        "attempt_id":envelope.attempt_id,"generation":envelope.generation,
        "execution_id":original.outcome.execution_id,"boot_id":boot,
        "original_result_sha256":sha256(&original_bytes),"original_stop_sha256":sha256(&stop_bytes),
        "preparation_sha256":sha256(&std::fs::read(journal.path("attempt-preparation.json"))?),
        "reservation_sha256":pool.reservation_sha256});
    let lock_path = journal.path("no-launch-failure-settlement.lock");
    let (mut lock, fresh) = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock_path)
    {
        Ok(lock) => (lock, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&lock_path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("no-launch settlement lock is not a regular private file");
            }
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)?;
            if metadata.ino() != lock.metadata()?.ino() || metadata.dev() != lock.metadata()?.dev()
            {
                bail!("no-launch settlement lock changed");
            }
            (lock, false)
        }
        Err(error) => return Err(error.into()),
    };
    lock.try_lock()
        .context("no-launch settlement already has an active observer")?;
    if fresh {
        lock.write_all(&serde_json::to_vec(&marker)?)?;
        lock.sync_all()?;
        std::fs::File::open(&journal.directory)?.sync_all()?;
    } else {
        let mut bytes = Vec::new();
        lock.read_to_end(&mut bytes)?;
        if serde_json::from_slice::<Value>(&bytes)? != marker {
            bail!("no-launch settlement boot or original failure identity changed");
        }
    }
    if no_launch_failure_has_launch_facts(journal)? {
        bail!("launch facts appeared during no-launch settlement");
    }
    let result_path = journal.path("no-launch-failure-result.json");
    if result_path.exists() {
        let settled: WorkerResult = serde_json::from_slice(&std::fs::read(&result_path)?)?;
        let fence = journal
            .cgroup_fence()?
            .context("no-launch settlement physical fence missing")?;
        let intent: LaunchIntent = serde_json::from_slice(&std::fs::read(
            journal.path("no-launch-failure-intent.json"),
        )?)?;
        let physical_stop: Value =
            serde_json::from_slice(&std::fs::read(journal.path("cgroup-stop.json"))?)?;
        let mut expected = original.clone();
        expected.event_id = format!("{}:no-launch-physical-failure", envelope.operation_id);
        expected.evidence["never_launched"] = json!(true);
        expected.evidence["launch_intent"] = serde_json::to_value(&intent)?;
        expected.evidence["physical_fence"] = serde_json::to_value(&fence)?;
        expected.evidence["physical_stop"] = physical_stop.clone();
        expected.evidence["original_result_sha256"] = marker["original_result_sha256"].clone();
        expected.evidence["original_stop_sha256"] = marker["original_stop_sha256"].clone();
        if fence.boot_id != boot
            || fence.resource_binding_sha256 != pool.reservation_sha256
            || fence.attempt_id != envelope.attempt_id
            || fence.project_id != envelope.project_id
            || fence.generation != envelope.generation
            || fence.execution_id != original.outcome.execution_id
            || intent.boot_id != boot
            || intent.attempt_id != envelope.attempt_id
            || intent.worker_id != envelope.worker_id
            || intent.generation != envelope.generation
            || intent.operation_id != envelope.operation_id
            || intent.execution_id != original.outcome.execution_id
            || serde_json::to_value(&settled)? != serde_json::to_value(&expected)?
            || settled.evidence["physical_fence"] != serde_json::to_value(&fence)?
            || settled.evidence["launch_intent"] != serde_json::to_value(&intent)?
            || settled.evidence["original_result_sha256"] != marker["original_result_sha256"]
            || settled.evidence["original_stop_sha256"] != marker["original_stop_sha256"]
            || settled.evidence["physical_stop"] != physical_stop
            || settled.evidence["never_launched"] != true
            || settled.outcome.execution_id != original.outcome.execution_id
            || !matches!(journal.disposition()?, RecoveryDisposition::Completed)
        {
            bail!("no-launch settlement receipt changed or physical closure unconfirmed");
        }
        return Ok(Some(settled));
    }
    let intent = LaunchIntent {
        execution_id: original.outcome.execution_id.clone(),
        operation_id: envelope.operation_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        generation: envelope.generation,
        worker_id: envelope.worker_id.clone(),
        boot_id: boot.clone(),
        workspace: PathBuf::from(&envelope.workspace_root),
        prompt_sha256: envelope.prompt_artifact.sha256.clone(),
        created_at: envelope.issued_at.clone(),
    };
    attempt_preparation::durable_first_json(
        &journal.path("no-launch-failure-intent.json"),
        &serde_json::to_value(&intent)?,
    )?;
    if serde_json::from_slice::<Value>(&std::fs::read(
        journal.path("no-launch-failure-intent.json"),
    )?)? != serde_json::to_value(&intent)?
    {
        bail!("no-launch supplemental intent changed");
    }
    let fence = if journal.cgroup_fence()?.is_some() {
        forgeflow_runtime::PreparedCgroupFence::restore(journal)?
            .context("no-launch physical fence disappeared")?
    } else {
        forgeflow_runtime::PreparedCgroupFence::prepare(
            forgeflow_runtime::PhysicalFenceRequest {
                project_id: envelope.project_id.clone(),
                delegation: config
                    .cgroup_delegation
                    .clone()
                    .context("no-launch settlement requires its own delegated Worker")?,
                limits: forgeflow_runtime::PhysicalCgroupLimits {
                    cpu_quota_us: pool.cpu_quota_us,
                    cpu_period_us: pool.physical_limits.period_us,
                    memory_max_bytes: pool.memory_max_bytes,
                    memory_swap_max_bytes: pool.physical_limits.swap_max_bytes,
                    pids_max: pool.physical_limits.pids_max,
                    memory_oom_group: pool.physical_limits.memory_oom_group,
                },
                resource_binding_sha256: pool.reservation_sha256.clone(),
            },
            &intent,
            journal,
        )?
    };
    if fence.identity.attempt_id != envelope.attempt_id
        || fence.identity.generation != envelope.generation
        || fence.identity.execution_id != intent.execution_id
        || fence.identity.boot_id != boot
        || fence.identity.resource_binding_sha256 != pool.reservation_sha256
        || Some(&fence.identity.delegation) != config.cgroup_delegation.as_ref()
        || fence.populated()?
        || !fence.record_stop(journal)?
    {
        bail!("no-launch private fence is not the exact unpopulated admitted reservation");
    }
    let mut settled = original.clone();
    settled.event_id = format!("{}:no-launch-physical-failure", envelope.operation_id);
    settled.evidence["never_launched"] = json!(true);
    settled.evidence["launch_intent"] = serde_json::to_value(&intent)?;
    settled.evidence["physical_fence"] = serde_json::to_value(&fence.identity)?;
    settled.evidence["physical_stop"] =
        serde_json::from_slice(&std::fs::read(journal.path("cgroup-stop.json"))?)?;
    settled.evidence["original_result_sha256"] = marker["original_result_sha256"].clone();
    settled.evidence["original_stop_sha256"] = marker["original_stop_sha256"].clone();
    attempt_preparation::durable_first_json(&result_path, &serde_json::to_value(&settled)?)?;
    if serde_json::from_slice::<Value>(&std::fs::read(result_path)?)?
        != serde_json::to_value(&settled)?
    {
        bail!("no-launch supplemental result changed");
    }
    Ok(Some(settled))
}
fn event(envelope: &ExecutionEnvelope, kind: &str, payload: Value, suffix: &str) -> WorkerEvent {
    WorkerEvent {
        event_id: format!("{}:{suffix}", envelope.operation_id),
        project_id: envelope.project_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        lease_id: envelope.lease_id.clone(),
        generation: envelope.generation,
        worker_id: envelope.worker_id.clone(),
        kind: kind.into(),
        payload,
    }
}

/// The mandatory worktree checkpoint also owns the exact first telemetry event.
/// Only the separate outbox inode is deferred until physical launch or failure.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeferredStartingEvent {
    outbox_file: String,
    event: WorkerEvent,
}

#[derive(Debug)]
struct DeferredStartingDurabilityFailure(anyhow::Error);

impl std::fmt::Display for DeferredStartingDurabilityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "deferred STARTING durability failed: {}", self.0)
    }
}

impl std::error::Error for DeferredStartingDurabilityFailure {}

/// Network refusal may retain telemetry while a stop is settled; a local
/// checkpoint failure must instead stop publication and cancel a live author.
fn retain_deferred_starting_failure(result: Result<()>) -> Result<()> {
    match result {
        Err(error)
            if error
                .downcast_ref::<DeferredStartingDurabilityFailure>()
                .is_some() =>
        {
            Err(error)
        }
        _ => Ok(()),
    }
}

impl DeferredStartingEvent {
    fn new(event: WorkerEvent) -> Self {
        Self {
            outbox_file: format!(
                "event-{:020}-{}.json",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                sha256(event.event_id.as_bytes())
            ),
            event,
        }
    }

    fn validate(&self, journal: &Journal) -> Result<()> {
        safe_id(&self.outbox_file)?;
        let suffix = format!("-{}.json", sha256(self.event.event_id.as_bytes()));
        let timestamp = self
            .outbox_file
            .strip_prefix("event-")
            .and_then(|name| name.strip_suffix(&suffix))
            .context("deferred STARTING outbox basename differs from event")?;
        if timestamp.len() != 20 || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("invalid deferred STARTING outbox timestamp");
        }
        let envelope: ExecutionEnvelope =
            serde_json::from_slice(&std::fs::read(journal.path("envelope.json"))?)?;
        envelope.validate()?;
        if journal.directory.file_name().and_then(|name| name.to_str())
            != Some(envelope.attempt_id.as_str())
        {
            bail!("deferred STARTING journal scope differs from immutable attempt");
        }
        let workspace = self.event.payload["workspace"]
            .as_str()
            .context("deferred STARTING workspace missing")?;
        if !Path::new(workspace).is_absolute()
            || self.event.payload["base_sha"] != envelope.base_sha
            || self.event.payload["isolation"] != "LOCAL_TRUSTED_WORKTREE"
            || serde_json::to_value(&self.event)?
                != serde_json::to_value(event(
                    &envelope,
                    "STARTING",
                    json!({"workspace":workspace,
                    "base_sha":envelope.base_sha,"isolation":"LOCAL_TRUSTED_WORKTREE"}),
                    "starting",
                ))?
        {
            bail!("deferred STARTING differs from immutable attempt identity");
        }
        Ok(())
    }
}

fn read_deferred_starting(journal: &Journal) -> Result<Option<DeferredStartingEvent>> {
    let bytes = match std::fs::read(journal.path("worktree.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata: Value = serde_json::from_slice(&bytes)?;
    let Some(value) = metadata.get("deferred_starting") else {
        return Ok(None);
    };
    let pending: DeferredStartingEvent = serde_json::from_value(value.clone())?;
    pending.validate(journal)?;
    let envelope: ExecutionEnvelope =
        serde_json::from_slice(&std::fs::read(journal.path("envelope.json"))?)?;
    if metadata["project_id"] != pending.event.project_id
        || metadata["repository"] != envelope.workspace_root
        || metadata["state"] != "PREPARED"
        || metadata["worktree"]["absolute_path"] != pending.event.payload["workspace"]
        || metadata["worktree"]["base_sha"] != pending.event.payload["base_sha"]
    {
        bail!("deferred STARTING differs from durable worktree checkpoint");
    }
    Ok(Some(pending))
}

async fn ensure_deferred_starting(
    journal: &Journal,
    supplied: Option<&DeferredStartingEvent>,
    retry_checkpoint: bool,
) -> Result<Option<String>> {
    ensure_deferred_starting_with_directory_sync(
        journal,
        supplied,
        retry_checkpoint,
        sync_preparation_directory,
    )
    .await
}

async fn ensure_deferred_starting_with_directory_sync<F>(
    journal: &Journal,
    supplied: Option<&DeferredStartingEvent>,
    retry_checkpoint: bool,
    sync_directory: F,
) -> Result<Option<String>>
where
    F: Fn(PathBuf) -> Result<()> + Send + 'static,
{
    let journal = journal.clone();
    let supplied = supplied.cloned();
    let result = tokio::task::spawn_blocking(move || {
        let pending = match supplied {
            Some(pending) => Some(pending),
            None => read_deferred_starting(&journal)?,
        };
        let Some(pending) = pending else {
            return Ok(None);
        };
        pending.validate(&journal)?;
        let expected = serde_json::to_vec(&pending.event)?;
        let acknowledged = journal.path("starting-event-ack.json");
        let outbox = journal.path(&pending.outbox_file);
        let mut existing = false;
        for path in [&acknowledged, &outbox] {
            match std::fs::read(path) {
                Ok(bytes) => {
                    if bytes != expected {
                        bail!("deferred STARTING publication differs from original bytes");
                    }
                    // A failed directory checkpoint can leave an already-renamed
                    // file visible. Retry that barrier before the failure wrapper
                    // is allowed to submit a stop result.
                    if retry_checkpoint {
                        std::fs::File::open(path)?.sync_all()?;
                        sync_directory(journal.directory.clone())?;
                    }
                    existing = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if existing {
            return Ok(Some(pending.outbox_file));
        }
        let parent = publish_synced_bytes(&outbox, &expected)?;
        sync_directory(parent)?;
        Ok(Some(pending.outbox_file))
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    result.map_err(|error| DeferredStartingDurabilityFailure(error).into())
}

async fn acknowledge_deferred_starting(journal: &Journal, outbox: PathBuf) -> Result<()> {
    acknowledge_deferred_starting_with_directory_sync(journal, outbox, sync_preparation_directory)
        .await
}

async fn acknowledge_deferred_starting_with_directory_sync<F>(
    journal: &Journal,
    outbox: PathBuf,
    sync_directory: F,
) -> Result<()>
where
    F: Fn(PathBuf) -> Result<()> + Send + 'static,
{
    let journal = journal.clone();
    let result = tokio::task::spawn_blocking(move || {
        let pending = read_deferred_starting(&journal)?
            .context("deferred STARTING checkpoint disappeared before acknowledgement")?;
        if outbox != journal.path(&pending.outbox_file)
            || std::fs::read(&outbox)? != serde_json::to_vec(&pending.event)?
        {
            bail!("deferred STARTING acknowledgement differs from original outbox");
        }
        let acknowledged = journal.path("starting-event-ack.json");
        match std::fs::read(&acknowledged) {
            Ok(bytes) if bytes != serde_json::to_vec(&pending.event)? => {
                bail!("deferred STARTING acknowledgement changed original bytes")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::rename(outbox, acknowledged)?;
        sync_directory(journal.directory)
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    result.map_err(|error| DeferredStartingDurabilityFailure(error).into())
}

/// Preserve the actual immutable runtime receipt when a RUNNING publication was
/// lost. The resulting evidence can also back a canonical StopReceipt; no process
/// identity is synthesized for an attempt without a durable launch receipt.
fn bound_stop_evidence(
    mut evidence: Value,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    execution_id: &str,
) -> Result<Value> {
    let object = evidence
        .as_object_mut()
        .context("stop evidence must be an object")?;
    object.insert("execution_id".into(), json!(execution_id));
    if let Some(physical) = journal.cgroup_fence()? {
        let physical_stop: Value =
            serde_json::from_slice(&std::fs::read(journal.path("cgroup-stop.json"))?)?;
        if physical_stop["identity_sha256"] != physical.identity_sha256 {
            bail!("physical stop differs from the frozen launch fence");
        }
        object.insert("physical_fence".into(), serde_json::to_value(physical)?);
        object.insert("physical_stop".into(), physical_stop);
    }
    let bytes = match std::fs::read(journal.path("launch-receipt.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if object.contains_key("physical_fence") {
                let stop: StopEvidence =
                    serde_json::from_slice(&std::fs::read(journal.path("stop.json"))?)?;
                if stop.process_exit_confirmed
                    && (stop.reason == "cancelled_before_launch"
                        || stop.reason.starts_with("spawn_failed:"))
                {
                    let authority = journal
                        .launch_authority()?
                        .context("unlaunched physical stop needs its bound intent")?;
                    let intent = &authority.intent;
                    if intent.execution_id != execution_id
                        || intent.attempt_id != envelope.attempt_id
                        || intent.operation_id != envelope.operation_id
                        || intent.generation != envelope.generation
                        || intent.worker_id != envelope.worker_id
                        || intent.boot_id != boot_id()?
                    {
                        bail!("unlaunched physical stop intent differs from frozen attempt");
                    }
                    object.insert("launch_intent".into(), serde_json::to_value(intent)?);
                    object.insert("never_launched".into(), json!(true));
                }
            }
            return Ok(evidence);
        }
        Err(error) => return Err(error.into()),
    };
    let raw: Value = serde_json::from_slice(&bytes)?;
    let receipt: forgeflow_runtime::LaunchReceipt = serde_json::from_value(raw.clone())?;
    let saved_intent: Value =
        serde_json::from_slice(&std::fs::read(journal.path("launch-intent.json"))?)?;
    if receipt.execution_id != execution_id
        || receipt.intent.execution_id != execution_id
        || journal.execution_id()? != execution_id
        || receipt.execution_id == envelope.operation_id
        || receipt.intent.operation_id != envelope.operation_id
        || receipt.intent.attempt_id != envelope.attempt_id
        || receipt.intent.generation != envelope.generation
        || receipt.intent.worker_id != envelope.worker_id
        || receipt.process.attempt_id != envelope.attempt_id
        || receipt.process.boot_id != receipt.intent.boot_id
        || raw["intent"] != saved_intent
    {
        bail!(
            "durable launch receipt differs from attempt/execution identity; retained for recovery"
        );
    }
    object.insert("launch_receipt".into(), raw);
    Ok(evidence)
}
/// Durable local outbox: acknowledgement removes only the acknowledged event.
async fn queue_event(
    _client: &ControlClient,
    journal: &Journal,
    event: &WorkerEvent,
) -> Result<()> {
    let path = journal.path(&format!(
        "event-{:020}-{}.json",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        sha256(event.event_id.as_bytes())
    ));
    let event = event.clone();
    // Every live author's log notification used to fsync on a Tokio reactor
    // thread. Preserve complete file+directory durability without blocking the
    // manager, claim replies, dispatch stream or launch-control timers.
    tokio::task::spawn_blocking(move || durable_json(&path, &event)).await??;
    Ok(())
}
async fn replay_events(client: &ControlClient, journal: &Journal) -> Result<()> {
    let starting_file = ensure_deferred_starting(journal, None, false).await?;
    let mut entries =
        std::fs::read_dir(&journal.directory)?.collect::<std::io::Result<Vec<_>>>()?;
    // A wall-clock correction must not put later telemetry before STARTING.
    entries.sort_by_key(|entry| {
        (
            !starting_file
                .as_ref()
                .is_some_and(|name| entry.file_name() == name.as_str()),
            entry.file_name(),
        )
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    for entry in entries
        .into_iter()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("event-") && name.ends_with(".json")
        })
        .take(16)
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("event-") && name.ends_with(".json") {
            let event: WorkerEvent = serde_json::from_slice(&std::fs::read(entry.path())?)?;
            // Bound the batch between requests. Cancelling an issued POST
            // after 2 s left the API committing it while every author sent
            // another copy; this retry storm could starve lease renewal.
            // Await its ACK under the client's existing 10 s HTTP bound.
            // An unavailable lane or lost ACK keeps the exact outbox file.
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            client.event(&event).await?;
            if starting_file.as_deref() == Some(name.as_ref()) {
                acknowledge_deferred_starting(journal, entry.path()).await?;
            } else {
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    // Cancelled or lost ACKs leave their files intact for identity-stable redelivery.
    Ok(())
}
fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(value)?.with_timezone(&chrono::Utc))
}
fn remaining(value: &str) -> Result<Duration> {
    Ok((parse_time(value)? - chrono::Utc::now())
        .to_std()
        .context("lease or deadline already expired")?)
}
#[derive(Clone)]
struct LeaseAuthority {
    expires_at: chrono::DateTime<chrono::Utc>,
    revoked: bool,
}
/// Keep execution rights current independently of event projection and result upload.
/// Failures never extend the last observed deadline; the supervisor still fences locally.
struct LeaseKeeper {
    authority: watch::Receiver<LeaseAuthority>,
    authority_tx: watch::Sender<LeaseAuthority>,
    task: tokio::task::JoinHandle<()>,
    retained_until_settlement: bool,
}
impl Drop for LeaseKeeper {
    fn drop(&mut self) {
        if !self.retained_until_settlement {
            self.task.abort();
        }
    }
}
impl LeaseKeeper {
    fn retain_until_settlement(&mut self) {
        self.retained_until_settlement = true;
    }
    fn observe_launch_control(&self, control: &ControlResponse) -> Result<()> {
        if !control.valid || control.cancel_requested {
            bail!("lease revoked during preparation");
        }
        let expires_at = parse_time(&control.lease_expires_at)?;
        remaining(&control.lease_expires_at)?;
        let accepted = self.authority_tx.send_if_modified(|authority| {
            if authority.revoked {
                return false;
            }
            authority.expires_at = expires_at;
            true
        });
        if !accepted {
            bail!("lease keeper already fenced during preparation");
        }
        Ok(())
    }
    fn start(
        client: ControlClient,
        envelope: ExecutionEnvelope,
        expires_at: chrono::DateTime<chrono::Utc>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Self {
        let (tx, authority) = watch::channel(LeaseAuthority {
            expires_at,
            revoked: false,
        });
        let authority_tx = tx.clone();
        let mut updates = authority.clone();
        let task = tokio::spawn(async move {
            let deadline = match parse_time(&envelope.deadline_at) {
                Ok(deadline) => deadline,
                Err(_) => return,
            };
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let current = updates.borrow_and_update().clone();
                let fence = current.expires_at.min(deadline);
                if current.revoked || *shutdown.borrow() || chrono::Utc::now() >= fence {
                    tx.send_replace(LeaseAuthority {
                        expires_at: chrono::Utc::now(),
                        revoked: true,
                    });
                    return;
                }
                tokio::select! {
                    _=tick.tick()=>{},
                    _=tokio::time::sleep((fence-chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO))=>{
                        tx.send_replace(LeaseAuthority { expires_at: chrono::Utc::now(), revoked: true });
                        return;
                    }
                    _=updates.changed()=>continue,
                    _=shutdown.changed()=>{
                        tx.send_replace(LeaseAuthority { expires_at: chrono::Utc::now(), revoked: true });
                        return;
                    }
                }
                let refresh = async {
                    if let Err(error) = client.renew(&envelope).await {
                        tracing::warn!(attempt_id=%envelope.attempt_id,error=%error,"lease renewal unavailable; previous deadline retained");
                    }
                    client.control(&envelope).await
                };
                let control = tokio::select! {
                    result=refresh=>result,
                    _=updates.changed()=>continue,
                    _=shutdown.changed()=>{
                        tx.send_replace(LeaseAuthority { expires_at: chrono::Utc::now(), revoked: true });
                        return;
                    }
                    _=tokio::time::sleep((fence-chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO))=>{
                        tx.send_replace(LeaseAuthority { expires_at: chrono::Utc::now(), revoked: true });
                        return;
                    }
                };
                match control {
                    Ok(control) if control.valid && !control.cancel_requested => {
                        if let Ok(expires_at) = parse_time(&control.lease_expires_at) {
                            if expires_at <= chrono::Utc::now() {
                                tx.send_replace(LeaseAuthority {
                                    expires_at,
                                    revoked: true,
                                });
                                return;
                            }
                            tx.send_replace(LeaseAuthority {
                                expires_at: expires_at.min(deadline),
                                revoked: false,
                            });
                        }
                    }
                    Ok(_) => {
                        tx.send_replace(LeaseAuthority {
                            expires_at: chrono::Utc::now(),
                            revoked: true,
                        });
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(attempt_id=%envelope.attempt_id,error=%error,"lease authority unavailable; no local extension")
                    }
                }
            }
        });
        Self {
            authority,
            authority_tx,
            task,
            retained_until_settlement: false,
        }
    }
}

/// Presence has its own HTTP task; admission, replay and occupied-slot scans cannot starve it.
struct WorkerPresence {
    attempts: watch::Sender<Vec<String>>,
    acknowledged: watch::Receiver<Option<tokio::time::Instant>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for WorkerPresence {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl WorkerPresence {
    fn start(
        client: ControlClient,
        worker_id: String,
        boot_id: String,
        attempts: Vec<String>,
    ) -> Self {
        let (attempts, mut snapshot) = watch::channel(attempts);
        let (ack, acknowledged) = watch::channel(None);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let heartbeat = WorkerHeartbeat {
                    worker_id: worker_id.clone(),
                    boot_id: boot_id.clone(),
                    active_attempt_ids: snapshot.borrow_and_update().clone(),
                };
                match client.heartbeat(&heartbeat).await {
                    Ok(()) => {
                        ack.send_replace(Some(tokio::time::Instant::now()));
                    }
                    Err(error) => {
                        ack.send_replace(None);
                        tracing::warn!(error=%error,"worker presence unavailable; new admission suspended");
                    }
                }
            }
        });
        Self {
            attempts,
            acknowledged,
            task,
        }
    }
    fn admits(&self) -> bool {
        self.acknowledged
            .borrow()
            .is_some_and(|at| at.elapsed() < Duration::from_secs(15))
    }
    fn update(&self, occupied: &std::collections::BTreeSet<String>) {
        self.attempts
            .send_replace(occupied.iter().cloned().collect());
    }
}

fn fair_batch(
    ids: &std::collections::BTreeSet<String>,
    cursor: &mut Option<String>,
    limit: usize,
) -> Vec<String> {
    let mut ordered: Vec<_> = ids
        .iter()
        .filter(|id| cursor.as_ref().is_none_or(|last| *id > last))
        .cloned()
        .collect();
    ordered.extend(
        ids.iter()
            .filter(|id| cursor.as_ref().is_some_and(|last| *id <= last))
            .cloned(),
    );
    ordered.truncate(limit);
    if let Some(last) = ordered.last() {
        *cursor = Some(last.clone());
    }
    ordered
}
fn read_secrets(
    config: &WorkerConfig,
    envelope: &ExecutionEnvelope,
) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for reference in &envelope.secret_refs {
        let binding = config
            .secret_files
            .get(reference)
            .context("secret reference unavailable")?;
        if binding.env_name.is_empty()
            || !binding
                .env_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || binding.env_name.starts_with("FORGEFLOW_")
        {
            bail!("invalid secret environment binding");
        }
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(&binding.path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            bail!("secret must be a private regular file");
        }
        values.insert(
            binding.env_name.clone(),
            std::fs::read_to_string(&binding.path)?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        );
    }
    Ok(values)
}

async fn parse_persisted_stream(
    client: &ControlClient,
    journal: &Journal,
    envelope: &ExecutionEnvelope,
    stop: &StopEvidence,
    claude: bool,
) -> Result<ExecutorOutcome> {
    if claude {
        return claude_supervisor::parse_persisted_stream(client, journal, envelope, stop).await;
    }
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut digest = Sha256::new();
    let mut file = tokio::fs::File::open(journal.path("stdout.ndjson")).await?;
    let mut chunk = vec![0; 16384];
    loop {
        let count = file.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    let raw_digest = format!("{:x}", digest.finalize());
    let mut reader = BufReader::new(tokio::fs::File::open(journal.path("stdout.ndjson")).await?);
    let mut stream = HeadlessStream::new(journal.execution_id()?);
    let mut final_artifact = None;
    let mut line_index = 0u64;
    loop {
        line_index += 1;
        let Some(line) = read_native_line(&mut reader, journal, line_index).await? else {
            break;
        };
        let (parsed, projected) = match line {
            NativeLine::Buffered(raw) => {
                let parsed = stream.observe_line(&raw);
                let raw_path = native_raw_path(journal, parsed.sequence)?;
                persist_native_raw(&raw_path, &raw)?;
                if parsed.kind == "final" && parsed.parse_error.is_none() {
                    persist_bytes(&journal.path("final.json"), &raw)?;
                    final_artifact =
                        Some(journal.path("final.json").to_string_lossy().into_owned());
                }
                let projected = if raw.len() > 65536 {
                    json!({"sequence":parsed.sequence,"native_type":parsed.kind,"raw_sha256":sha256(&raw),"raw_bytes":raw.len(),"payload_in_artifact":true})
                } else {
                    json!({"sequence":parsed.sequence,"native_type":parsed.kind,"payload":parsed.payload,"parse_error":parsed.parse_error})
                };
                let projected = normalize_native(
                    journal,
                    envelope,
                    parsed.sequence,
                    &parsed.kind,
                    projected,
                    &raw_path,
                    &sha256(&raw),
                    raw.len() as u64,
                )?;
                (parsed, projected)
            }
            NativeLine::Spooled {
                path,
                raw_bytes,
                raw_sha256,
                prefix,
            } => {
                if !prefix.starts_with(br#"{"type":"final","text":""#) {
                    bail!(
                        "oversized non-final native event retained in {}",
                        path.display()
                    );
                }
                let validate = path.clone();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let mut deserializer =
                        serde_json::Deserializer::from_reader(std::fs::File::open(validate)?);
                    serde::de::IgnoredAny::deserialize(&mut deserializer)?;
                    deserializer.end()?;
                    Ok(())
                })
                .await??;
                let parsed = stream.observe_spooled_final(raw_sha256.clone(), raw_bytes);
                let raw_path = native_raw_path(journal, parsed.sequence)?;
                if raw_path.exists() {
                    if hash_file(&raw_path).await? != raw_sha256 {
                        bail!("native source replay changed bytes; original retained");
                    }
                    std::fs::remove_file(&path)?;
                } else {
                    std::fs::rename(&path, &raw_path)?;
                }
                link_final_artifact(journal, &raw_path)?;
                std::fs::File::open(&journal.directory)?.sync_all()?;
                final_artifact = Some(journal.path("final.json").to_string_lossy().into_owned());
                let projected = json!({"sequence":parsed.sequence,"native_type":"final","raw_sha256":raw_sha256,"raw_bytes":raw_bytes,"payload_in_artifact":true});
                let projected = normalize_native(
                    journal,
                    envelope,
                    parsed.sequence,
                    &parsed.kind,
                    projected,
                    &raw_path,
                    &raw_sha256,
                    raw_bytes,
                )?;
                (parsed, projected)
            }
        };
        queue_event(
            client,
            journal,
            &event(
                envelope,
                "EXECUTOR_EVENT",
                projected,
                &format!("native-{:020}", parsed.sequence),
            ),
        )
        .await?;
    }
    let cancelled = stop.process_exit_confirmed && stop.reason.starts_with("cancelled");
    let mut outcome = stream.finish(stop.exit_code, cancelled, raw_digest, final_artifact);
    if !stop.process_exit_confirmed {
        outcome.completion_reason = "RECOVERY_REQUIRED".into();
        outcome.error_class = Some("STOP_UNCONFIRMED".into());
    }
    if stop.log_error.is_some() {
        outcome.completion_reason = "EVIDENCE_STORAGE_FAILED".into();
        outcome.error_class = Some("EVIDENCE_STORAGE_FAILED".into());
    }
    Ok(outcome)
}

async fn execute_inner(
    config: &WorkerConfig,
    client: &ControlClient,
    envelope: ExecutionEnvelope,
    mut shutdown_rx: watch::Receiver<bool>,
    prepared_authority: Option<attempt_preparation::PreparedAuthority>,
    preparation_started: std::time::Instant,
    preparation_started_at: String,
    bundle_ready_ms: u64,
    pending_starting: &mut Option<DeferredStartingEvent>,
) -> Result<()> {
    envelope.validate()?;
    config.profile.verify_configuration(
        config.managed_dsh.is_some(),
        &config.model_route_id,
        config.sandbox.is_some(),
    )?;
    if *shutdown_rx.borrow() {
        bail!("worker shutdown before preparation");
    }
    safe_id(&envelope.attempt_id)?;
    if envelope.worker_id != config.worker_id
        || envelope.project_id != config.project_id
        || envelope.model_route_id != config.model_route_id
    {
        bail!("worker/project/model route differs from frozen configuration");
    }
    let journal = Journal::new(&config.data_root.join("attempts"), &envelope.attempt_id)?;
    match journal.disposition()? {
        RecoveryDisposition::Completed => {
            let stop: StopEvidence =
                serde_json::from_slice(&std::fs::read(journal.path("stop.json"))?)?;
            native_controller::reconcile_transport(&journal, stop.process_exit_confirmed)?;
            durable_json(
                &journal.path("lease-retention.json"),
                &json!({"attempt_id":envelope.attempt_id,
                "generation":envelope.generation,"state":"AWAITING_CONTROLLER_SETTLEMENT",
                "deadline_at":envelope.deadline_at}),
            )?;
            tokio::spawn(restore_lease(
                client.clone(),
                envelope.clone(),
                shutdown_rx.clone(),
            ));
            let _ = replay_events(client, &journal).await;
            if journal.path("result.json").exists() {
                let result: WorkerResult =
                    serde_json::from_slice(&std::fs::read(journal.path("result.json"))?)?;
                deliver_result(config, client, &envelope, &journal, &result).await?;
            }
            return Ok(());
        }
        RecoveryDisposition::RecoveryRequired(reason) => {
            queue_event(
                client,
                &journal,
                &event(
                    &envelope,
                    "RECOVERY_REQUIRED",
                    json!({"reason":reason}),
                    "recovery",
                ),
            )
            .await?;
            bail!("duplicate delivery quarantined; no relaunch");
        }
        RecoveryDisposition::NeverLaunched => {}
    }
    let sealed = prepared_authority.is_some();
    let authority = async {
        let identity = async {
            if let Some(prepared) = &prepared_authority {
                Ok::<_, anyhow::Error>(prepared.execution_id().to_owned())
            } else {
                let identity_journal = journal.clone();
                tokio::task::spawn_blocking(move || identity_journal.execution_id()).await?
            }
        };
        let (execution_id, control) = tokio::join!(identity, client.control(&envelope));
        let execution_id = execution_id?;
        let control = control?;
        if !control.valid || control.cancel_requested {
            bail!("launch lease rejected or revoked");
        }
        let lease_expiry =
            parse_time(&control.lease_expires_at)?.min(parse_time(&envelope.expires_at)?);
        remaining(&lease_expiry.to_rfc3339())?;
        let keeper = LeaseKeeper::start(
            client.clone(),
            envelope.clone(),
            lease_expiry,
            shutdown_rx.clone(),
        );
        Ok::<_, anyhow::Error>((execution_id, keeper, preparation_ms(preparation_started)))
    };
    let bindings = async {
        let bindings = client.bindings(&envelope).await?;
        let fetched_ms = preparation_ms(preparation_started);
        let registered = bindings
            .get("executor_profile")
            .context("frozen executor profile binding missing")?;
        if envelope.command.is_some() {
            if registered.get("id").and_then(Value::as_str) != Some("controlled-lightweight.v1")
                || registered.get("kind").and_then(Value::as_str) != Some("CONTROLLED_LIGHTWEIGHT")
                || registered.get("approved_programs")
                    != Some(&serde_json::to_value(&config.controlled_workload_programs)?)
            {
                bail!("controlled executable policy differs from frozen registration");
            }
        } else if registered != &frozen_executor_profile(config)? {
            bail!("loaded native profile differs from immutable admitted registration");
        }
        for key in ["resource_profile", "model_route", "verification_plan"] {
            if !bindings.get(key).is_some_and(Value::is_object) {
                bail!("frozen {key} binding missing");
            }
        }
        let claude_output_cap = config.profile.verify_route(&bindings)?;
        let native_root_binding = bindings
            .get("native_root_binding")
            .filter(|value| !value.is_null())
            .map(|value| {
                serde_json::from_value::<native_controller::NativeRootBinding>(value.clone())
            })
            .transpose()?;
        if let Some(binding) = &native_root_binding {
            if envelope.command.is_some() || config.managed_dsh.is_none() {
                bail!("task-selected native role requires the exact managed native executor");
            }
            binding.validate_identity(
                &envelope,
                bindings["verification_plan"]["input_hash"]
                    .as_str()
                    .context("native root binding needs the frozen verification input digest")?,
            )?;
        }
        let frozen_sandbox = bindings["resource_profile"]
            .get("sandbox")
            .filter(|v| !v.is_null());
        match (&config.sandbox, frozen_sandbox) {
            (Some(profile), Some(frozen)) if serde_json::to_value(profile)? == *frozen => {}
            (None, None) => {}
            _ => bail!(
                "sandbox configuration differs from admitted resource profile; no trusted fallback"
            ),
        }
        let physical = match bindings["resource_profile"]
            .get("physical_limits")
            .filter(|v| !v.is_null())
        {
            Some(policy) => {
                if config.sandbox.is_none() || config.cgroup_delegation.is_none() {
                    bail!(
                        "required physical fencing needs a frozen strong sandbox and delegated service; no fallback"
                    );
                }
                let binding: forgeflow_domain::PhysicalResourceBinding = serde_json::from_value(
                    bindings
                        .get("physical_resources")
                        .cloned()
                        .context("frozen physical reservation missing")?,
                )?;
                binding.verify()?;
                if binding.resource_profile_id != envelope.resource_profile_id
                    || serde_json::to_value(&binding.physical_limits)? != *policy
                {
                    bail!("physical reservation differs from the admitted profile policy");
                }
                let native = bindings["resource_profile"].get("native_child_policy");
                let children = if native
                    .and_then(|v| v.get("enabled"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    let max = native
                        .and_then(|v| v.get("max_live_agents"))
                        .and_then(Value::as_u64)
                        .context("frozen native pool count missing")?;
                    u32::try_from(
                        max.checked_sub(1)
                            .context("native pool must include its root")?,
                    )?
                } else {
                    0
                };
                let child: forgeflow_domain::ResourceVector = native
                    .and_then(|v| v.get("child_resources"))
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()?
                    .unwrap_or_default();
                if binding.max_concurrent_children != children
                    || binding.native_child_resources != child
                {
                    bail!("physical reservation differs from the frozen native child pool");
                }
                Some(binding)
            }
            None => {
                if bindings
                    .get("physical_resources")
                    .is_some_and(|v| !v.is_null())
                {
                    bail!("physical reservation supplied without required profile policy");
                }
                None
            }
        };
        persist_preparation(vec![(
            journal.path("execution-bindings.json"),
            serde_json::to_vec(&bindings)?,
        )])
        .await?;
        Ok::<_, anyhow::Error>((
            fetched_ms,
            preparation_ms(preparation_started),
            physical,
            native_root_binding,
            claude_output_cap,
        ))
    };
    std::fs::create_dir_all(&journal.directory)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&journal.directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let repository = PathBuf::from(&envelope.workspace_root);
    let target = config
        .data_root
        .join("worktrees")
        .join(&envelope.attempt_id);
    std::fs::create_dir_all(target.parent().context("worktree root missing")?)?;
    let base = envelope.base_sha.clone();
    let attempt = envelope.attempt_id.clone();
    let target_copy = target.clone();
    let inputs = async {
        let (prompt, manifest) = tokio::join!(
            client.artifact(
                &envelope.project_id,
                &envelope.worker_id,
                &envelope.prompt_artifact.artifact_id
            ),
            client.artifact(
                &envelope.project_id,
                &envelope.worker_id,
                &envelope.context_manifest.artifact_id
            ),
        );
        let prompt = prompt?;
        let manifest = manifest?;
        let fetched_ms = preparation_ms(preparation_started);
        if sha256(&prompt) != envelope.prompt_artifact.sha256
            || sha256(&manifest) != envelope.context_manifest.sha256
        {
            bail!("input artifact hash mismatch");
        }
        std::str::from_utf8(&prompt).context("prompt is not UTF-8")?;
        // Every independent file still syncs its bytes. The completed batch
        // syncs each parent directory once, before any preparation can launch.
        let mut files = vec![
            (journal.path("prompt.txt"), prompt.clone()),
            (journal.path("context-manifest.json"), manifest.clone()),
        ];
        if !sealed {
            files.push((
                journal.path("envelope.json"),
                serde_json::to_vec(&envelope)?,
            ));
        }
        persist_preparation(files).await?;
        Ok::<_, anyhow::Error>((
            prompt,
            manifest,
            fetched_ms,
            preparation_ms(preparation_started),
        ))
    };
    let private_worktree = async {
        let worktree = tokio::task::spawn_blocking(move || {
            forgeflow_git::prepare_isolated_repository(&repository, &base, &attempt, &target_copy)
        })
        .await??;
        let cloned_ms = preparation_ms(preparation_started);
        let path = journal.path("worktree.json");
        let starting = event(
            &envelope,
            "STARTING",
            json!({"workspace":worktree.absolute_path,"base_sha":worktree.base_sha,"isolation":"LOCAL_TRUSTED_WORKTREE"}),
            "starting",
        );
        // Retain raw pending even if the worktree checkpoint itself fails. The
        // outer failure path must persist it before any result acknowledgement.
        let deferred = DeferredStartingEvent::new(starting);
        *pending_starting = Some(deferred.clone());
        let metadata = json!({"project_id":envelope.project_id,"repository":envelope.workspace_root,"worktree":worktree,"state":"PREPARED","target_ref":"refs/heads/main","deferred_starting":deferred});
        persist_preparation(vec![(path, serde_json::to_vec(&metadata)?)]).await?;
        Ok::<_, anyhow::Error>((worktree, cloned_ms, preparation_ms(preparation_started)))
    };
    let executable_pin = async {
        if let Some(command) = &envelope.command {
            let program = PathBuf::from(&command.program);
            if !program.is_absolute() {
                bail!("controlled workload executable must be absolute");
            }
            let expected = config
                .controlled_workload_programs
                .get(&command.program)
                .context("controlled workload executable is not approved")?
                .clone();
            // Full content verification still occurs for every attempt. It is
            // independent of immutable input fetch and private Git creation.
            tokio::task::spawn_blocking(move || -> Result<()> {
                if sha256(&std::fs::read(program)?) != expected {
                    bail!("controlled workload executable pin changed");
                }
                Ok(())
            })
            .await??;
        }
        Ok::<_, anyhow::Error>(preparation_ms(preparation_started))
    };
    // All branches only prepare private state. Neither a completed clone nor
    // fetched inputs confer launch rights. Drain every branch on failure so a
    // late Git setup cannot outlive the failed preparation acknowledgement.
    let (authority, bindings, inputs, worktree, executable_pin) = tokio::join!(
        authority,
        bindings,
        inputs,
        private_worktree,
        executable_pin
    );
    let (execution_id, mut keeper, authority_ready_ms) = authority?;
    let (
        bindings_fetched_ms,
        bindings_ready_ms,
        physical_binding,
        native_root_binding,
        claude_output_cap,
    ) = bindings?;
    let executable_pin_ms = executable_pin?;
    let (prompt, manifest, inputs_fetched_ms, inputs_ready_ms) = inputs?;
    let (worktree, worktree_cloned_ms, worktree_ready_ms) = worktree?;
    verify_context_files(
        &manifest,
        &envelope,
        &worktree.absolute_path,
        client,
        &journal,
    )
    .await?;
    let context_ready_ms = preparation_ms(preparation_started);
    // The original signed envelope remains intact. Only adapter-local cwd becomes isolated.
    let mut local = envelope.clone();
    local.workspace_root = worktree.absolute_path.to_string_lossy().into_owned();
    let profile = config.profile.clone();
    if envelope.resume_session_id.is_some() {
        bail!(
            "UNSUPPORTED_WORKER_RESUME: prior native session cannot be adopted into a new per-attempt worktree"
        );
    }
    // The approved profile includes a dedicated persistent home and immutable configuration pins.
    // Retain that exact namespace: substituting a new home would discard model/config identity.
    let controlled = envelope.command.is_some();
    let prepared_managed = if !controlled {
        if let Some(managed) = &config.managed_dsh {
            if config.sandbox.is_none() {
                bail!("managed native mode requires the frozen strong sandbox profile");
            }
            Some(native_controller::prepare_managed_home(
                profile.dsh().context("managed DSH profile missing")?,
                managed,
                &envelope,
                &journal,
                config
                    .data_root
                    .join("executor-homes")
                    .join(&envelope.project_id)
                    .join(&envelope.attempt_id)
                    .join("managed"),
                true,
                native_root_binding.as_ref(),
                &worktree.absolute_path,
            )?)
        } else {
            None
        }
    } else {
        None
    };
    let managed_home = if let Some(prepared) = &prepared_managed {
        prepared.home.clone()
    } else if !controlled && profile.claude().is_some() {
        claude_supervisor::prepare_home(config, &envelope)?
    } else if controlled {
        config
            .data_root
            .join("executor-homes")
            .join("controlled")
            .join(&envelope.project_id)
    } else {
        profile.home().to_owned()
    };
    std::fs::create_dir_all(&managed_home)?;
    if !controlled {
        bind_project_home(&managed_home, &envelope.project_id, profile.id())?;
    }
    let mut launch = if let Some(command) = &envelope.command {
        if envelope.executor_profile_id != "controlled-lightweight.v1"
            || envelope.max_model_requests != 0
            || envelope
                .allowed_effects
                .contains(&forgeflow_domain::AllowedEffect::RequestApprovedModel)
        {
            bail!("controlled workload must have explicit profile and zero model access");
        }
        let program = PathBuf::from(&command.program);
        if !program.is_absolute() {
            bail!("controlled workload executable must be absolute");
        }
        forgeflow_executors::HeadlessLaunchSpec {
            program,
            args: command.args.clone(),
            env: BTreeMap::new(),
            stdin: prompt,
            cwd: worktree.absolute_path.clone(),
        }
    } else {
        // Native profile content pins can span thousands of files. Keep the
        // complete existing checks while freeing dispatch/renewal reactor threads.
        let native_envelope = local.clone();
        let native_profile = profile.clone();
        tokio::task::spawn_blocking(move || match &native_profile {
            WorkerExecutorProfile::Dsh(profile) => {
                prepare_headless(&native_envelope, prompt, profile)
            }
            WorkerExecutorProfile::ClaudeLeaf(profile) => {
                forgeflow_executors::prepare_claude_leaf(&native_envelope, prompt, profile)
            }
        })
        .await??
    };
    let native_controller =
        if let (Some(managed), Some(_prepared)) = (&config.managed_dsh, &prepared_managed) {
            let at = profile
                .dsh()
                .context("managed DSH profile missing")?
                .prefix_args
                .len()
                + 2;
            launch.args.splice(
                at..at,
                [
                    "--patch".into(),
                    native_controller::PRESET_ALIAS.into(),
                    "--patch".into(),
                    native_controller::PATCH_ALIAS.into(),
                ],
            );
            Some(
                native_controller::NativeController::start(
                    client.clone(),
                    envelope.clone(),
                    journal.clone(),
                    Duration::from_millis(managed.rpc_timeout_ms),
                )
                .await?,
            )
        } else {
            None
        };
    let model_relay = if let Some(relay) = config
        .managed_dsh
        .as_ref()
        .and_then(|managed| managed.model_relay.as_ref())
    {
        if controlled
            || config
                .sandbox
                .as_ref()
                .is_none_or(|sandbox| sandbox.network_allowed)
        {
            bail!("strict native model relay requires the frozen network-isolated sandbox");
        }
        if !envelope.secret_refs.is_empty() {
            bail!(
                "strict model profile cannot expose child secret references; provider key is gateway-only"
            );
        }
        launch
            .args
            .splice(0..0, ["--import".into(), model_relay::LOADER_ALIAS.into()]);
        Some(
            model_relay::ModelRelay::start(
                client.clone(),
                envelope.clone(),
                journal.clone(),
                relay.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut env = launch.env;
    env.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into());
    env.insert("LANG".into(), "C.UTF-8".into());
    env.insert("HOME".into(), managed_home.to_string_lossy().into_owned());
    if prepared_managed.is_some() {
        env.insert(
            "DSH_HOME".into(),
            managed_home.to_string_lossy().into_owned(),
        );
    }
    if !controlled && profile.claude().is_some() {
        env.insert(
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS".into(),
            claude_output_cap
                .context("Claude frozen output cap missing before launch")?
                .to_string(),
        );
        env.insert(
            "CLAUDE_CONFIG_DIR".into(),
            managed_home.to_string_lossy().into_owned(),
        );
        env.extend(claude_supervisor::read_credentials(config, &envelope)?);
    } else {
        env.extend(read_secrets(config, &envelope)?);
    }
    if model_relay.is_some() {
        env.insert(
            "FORGEFLOW_MODEL_RELAY_DUMMY".into(),
            "forgeflow-relay-no-provider-secret".into(),
        );
    }
    let launch_spec_ready_ms = preparation_ms(preparation_started);
    let intent = LaunchIntent {
        execution_id: execution_id.clone(),
        operation_id: envelope.operation_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        generation: envelope.generation,
        worker_id: envelope.worker_id.clone(),
        boot_id: boot_id()?,
        workspace: worktree.absolute_path.clone(),
        prompt_sha256: envelope.prompt_artifact.sha256.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    // Recheck immediately before starting: fetching artifacts and Git creation can consume lease time.
    let final_control_started_ms = preparation_ms(preparation_started);
    let control = client.control(&envelope).await?;
    keeper.observe_launch_control(&control)?;
    let final_control_ready_ms = preparation_ms(preparation_started);
    if *shutdown_rx.borrow() {
        bail!("worker shutdown during preparation");
    }
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (launched_tx, mut launched_rx) = watch::channel(None);
    let (notice_tx, mut notice_rx) = mpsc::channel::<LogNotice>(64);
    let limits = SupervisionLimits {
        timeout: remaining(&envelope.deadline_at)?,
        max_log_bytes: config.max_log_bytes,
        ..Default::default()
    };
    let mut spec = ProcessSpec {
        program: launch.program,
        args: launch.args,
        env,
        cwd: launch.cwd,
        stdin: launch.stdin,
    };
    if let Some(profile) = &config.sandbox {
        let mut effective_profile = profile.clone();
        let canonical_repo = std::fs::canonicalize(&envelope.workspace_root)?;
        let state_root = std::fs::canonicalize(&config.data_root)?;
        let approved_home = std::fs::canonicalize(&managed_home)?;
        if prepared_managed.is_some() || profile_is_claude(config) {
            let source_home = std::fs::canonicalize(config.profile.home())?;
            effective_profile
                .readonly_paths
                .retain(|path| std::fs::canonicalize(path).ok().as_ref() != Some(&source_home));
        }
        for readonly in &effective_profile.readonly_paths {
            let path = std::fs::canonicalize(readonly)?;
            if profile_is_claude(config) {
                claude_supervisor::validate_readonly_mount(config, &envelope, &path)?;
            }
            if model_relay.is_some() {
                let credential = std::fs::canonicalize(
                    &config
                        .managed_dsh
                        .as_ref()
                        .context("strict managed configuration missing")?
                        .credentials,
                )?;
                if credential.starts_with(&path) || path.starts_with(&credential) {
                    bail!("strict model sandbox cannot expose any provider credential mount");
                }
            }
            if physical_binding.is_some()
                && (path.starts_with("/sys/fs/cgroup")
                    || Path::new("/sys/fs/cgroup").starts_with(&path))
            {
                bail!("physically fenced author must not expose host cgroupfs");
            }
            if path.starts_with(&canonical_repo)
                || canonical_repo.starts_with(&path)
                || state_root.starts_with(&path)
                || (path.starts_with(&state_root) && !path.starts_with(&approved_home))
            {
                bail!(
                    "sandbox readonly mount exposes canonical repository or control state ancestor"
                );
            }
        }
        // Git and approved verifier programs also open the null device O_RDWR.
        // Grant the same checked discard inode to controlled and DSH processes;
        // this grants no workspace, credential or other device write access.
        let mut writable_mounts = vec![native_controller::native_null_output_mount()?];
        if !controlled {
            let home = std::fs::canonicalize(&managed_home)?;
            if profile_is_claude(config) {
                // The leaf sees only its own mutable configuration/cache directory.
                // Never mount or copy the personal/source profile home.
                let source_home = std::fs::canonicalize(config.profile.home())?;
                effective_profile
                    .readonly_paths
                    .retain(|path| std::fs::canonicalize(path).ok().as_ref() != Some(&source_home));
                writable_mounts.push(forgeflow_runtime::SandboxMount {
                    source: home.clone(),
                    target: home.clone(),
                });
            } else if let Some(prepared) = &prepared_managed {
                // The frozen source home supplies pinned inputs only. The native
                // process sees this attempt's selected model configuration.
                let source_home = std::fs::canonicalize(config.profile.home())?;
                effective_profile
                    .readonly_paths
                    .retain(|path| std::fs::canonicalize(path).ok().as_ref() != Some(&source_home));
                effective_profile.readonly_paths.push(home.clone());
                for name in ["sessions", "storages", "profiles/headless"] {
                    let source = prepared.home.join(name);
                    writable_mounts.push(forgeflow_runtime::SandboxMount {
                        source: source.clone(),
                        target: source,
                    });
                }
            } else if !profile
                .readonly_paths
                .iter()
                .any(|p| std::fs::canonicalize(p).ok().as_ref() == Some(&home))
            {
                bail!("sandbox must mount qualified DSH configuration home read-only");
            }
            if prepared_managed.is_none() && !profile_is_claude(config) {
                for name in ["sessions", "storages"] {
                    let source = config
                        .data_root
                        .join("executor-homes")
                        .join(&envelope.project_id)
                        .join(&envelope.attempt_id)
                        .join(name);
                    std::fs::create_dir_all(&source)?;
                    std::fs::create_dir_all(home.join(name))?;
                    writable_mounts.push(forgeflow_runtime::SandboxMount {
                        source,
                        target: home.join(name),
                    });
                }
            }
        }
        let instance = forgeflow_runtime::SandboxInstance {
            workspace: worktree.absolute_path.clone(),
            write_set: envelope.write_set.clone(),
            allow_git_metadata: true,
            writable_mounts,
        };
        spec = forgeflow_runtime::sandbox_command(spec, &effective_profile, &instance)?;
        if let (Some(prepared), Some(controller)) = (&prepared_managed, &native_controller) {
            native_controller::mount_native_aliases(
                &mut spec,
                prepared,
                &controller.socket_path,
                model_relay
                    .as_ref()
                    .map(|relay| relay.socket_path.as_path()),
            )?;
        }
        durable_json(
            &journal.path("sandbox.json"),
            &json!({"isolation_profile":"BWRAP_LANDLOCK_EXACT","landlock_abi":forgeflow_runtime::landlock_abi()?,"profile":profile,"effective_profile":effective_profile,"managed_native":prepared_managed.is_some(),"private_git":true,"network_allowed":profile.network_allowed,"cpu_memory_enforcement":if physical_binding.is_some(){"REQUIRED_CGROUP_V2_BEFORE_EXEC"}else{"UNVERIFIED"}}),
        )?;
    }
    // Sandbox preparation may also take time. Fence synchronously before spawning,
    // then keep the independent guard active through process/group settlement.
    let authority = keeper.authority.borrow().clone();
    if authority.revoked || authority.expires_at <= chrono::Utc::now() || *shutdown_rx.borrow() {
        bail!("lease or shutdown fenced before process launch");
    }
    // Persist diagnostics after the physical launch notification, so this one
    // same-attempt trace cannot add a checkpoint to the launch critical path.
    let mut preparation_timing = Some(json!({
        "schema_version":"forgeflow.worker-preparation-timing.v1",
        "project_id":envelope.project_id,"attempt_id":envelope.attempt_id,
        "generation":envelope.generation,"execution_id":execution_id,
        "started_at":preparation_started_at,"clock":"PROCESS_MONOTONIC_ELAPSED_MS",
        "bundle_ready_ms":bundle_ready_ms,"authority_ready_ms":authority_ready_ms,
        "bindings_fetched_ms":bindings_fetched_ms,"bindings_ready_ms":bindings_ready_ms,
        "inputs_fetched_ms":inputs_fetched_ms,"inputs_ready_ms":inputs_ready_ms,
        "executable_pin_ready_ms":executable_pin_ms,
        "worktree_cloned_ms":worktree_cloned_ms,"worktree_ready_ms":worktree_ready_ms,
        "private_git_duration_ms":worktree.clone_duration_ms,
        "context_ready_ms":context_ready_ms,"launch_spec_ready_ms":launch_spec_ready_ms,
        "final_control_started_ms":final_control_started_ms,
        "final_control_ready_ms":final_control_ready_ms,
        "supervisor_queued_ms":preparation_ms(preparation_started),
    }));
    let mut expiry_rx = keeper.authority.clone();
    let lease_cancel = cancel_tx.clone();
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let guard_shutdown = shutdown.clone();
    let mut guard_signal = shutdown_rx.clone();
    let lease_guard = tokio::spawn(async move {
        loop {
            let authority = expiry_rx.borrow().clone();
            if authority.revoked {
                let _ = lease_cancel.send(true);
                return;
            }
            let duration = (authority.expires_at - chrono::Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO);
            tokio::select! {
                _=tokio::time::sleep(duration)=>{let _=lease_cancel.send(true);return;},
                change=expiry_rx.changed()=>{if change.is_err(){let _=lease_cancel.send(true);return;}}
                change=guard_signal.changed()=>{if change.is_err()||*guard_signal.borrow(){guard_shutdown.store(true,std::sync::atomic::Ordering::Relaxed);let _=lease_cancel.send(true);return;}}
            }
        }
    });
    let launch_authority = keeper.authority.clone();
    let launch_shutdown = shutdown_rx.clone();
    let launch_cancel = cancel_tx.clone();
    let launch_journal = journal.clone();
    let physical_request =
        physical_binding.map(|binding| forgeflow_runtime::PhysicalFenceRequest {
            project_id: envelope.project_id.clone(),
            delegation: config
                .cgroup_delegation
                .clone()
                .expect("physical configuration checked before preparation"),
            limits: forgeflow_runtime::PhysicalCgroupLimits {
                cpu_quota_us: binding.cpu_quota_us,
                cpu_period_us: binding.physical_limits.period_us,
                memory_max_bytes: binding.memory_max_bytes,
                memory_swap_max_bytes: binding.physical_limits.swap_max_bytes,
                pids_max: binding.physical_limits.pids_max,
                memory_oom_group: binding.physical_limits.memory_oom_group,
            },
            resource_binding_sha256: binding.reservation_sha256,
        });
    let mut future = tokio::spawn(async move {
        // Recheck when the scheduled supervisor actually runs. A stalled executor
        // must not turn a previously accepted lease snapshot into launch rights.
        let authority = launch_authority.borrow().clone();
        if authority.revoked
            || authority.expires_at <= chrono::Utc::now()
            || *launch_shutdown.borrow()
        {
            let _ = launch_cancel.send(true);
        }
        if let Some(physical) = physical_request {
            forgeflow_runtime::supervise_physical(
                spec,
                intent,
                launch_journal,
                limits,
                cancel_rx,
                notice_tx,
                launched_tx,
                physical,
            )
            .await
        } else {
            supervise(
                spec,
                intent,
                launch_journal,
                limits,
                cancel_rx,
                notice_tx,
                launched_tx,
            )
            .await
        }
    });
    let mut heartbeat =
        tokio::time::interval(Duration::from_secs(config.poll_seconds.clamp(1, 10)));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut notices_open = true;
    let mut launched_open = true;
    let mut live = LiveProjection::for_profile(&execution_id, profile.claude().is_some());
    let mut starting_ready = false;
    let mut starting_failure = None;
    let supervision = loop {
        tokio::select! {
            result=&mut future => break result.map_err(anyhow::Error::from).and_then(|result|result),
            change=launched_rx.changed(),if launched_open && starting_failure.is_none() => {
                if change.is_err() {
                    launched_open=false;
                } else {
                    let receipt = launched_rx.borrow().clone();
                    if let Some(receipt) = receipt {
                        if let Some(physical) = journal.cgroup_fence()? {
                            let mut sandbox: Value = serde_json::from_slice(&std::fs::read(journal.path("sandbox.json"))?)?;
                            sandbox["cpu_memory_enforcement"] = json!("CGROUP_V2_ATTACH_AND_LIMITS_CONFIRMED");
                            sandbox["physical_enforcement_scope"] = json!("WORKER_AUTHOR_AND_INHERITED_NATIVE_DESCENDANTS_ONLY; API_VERIFIER_NOT_INCLUDED");
                            sandbox["physical_fence_sha256"] = json!(physical.identity_sha256);
                            durable_json(&journal.path("sandbox.json"), &sandbox)?;
                        }
                        if !starting_ready {
                            match ensure_deferred_starting(&journal, pending_starting.as_ref(), true).await {
                                Ok(_) => starting_ready = true,
                                Err(error) => {
                                    tracing::error!(error=%error,"starting receipt persistence failed");
                                    starting_failure.get_or_insert(error);
                                    let _=cancel_tx.send(true);
                                    continue;
                                }
                            }
                        }
                        persist_preparation_timing(&journal, &mut preparation_timing, preparation_started, &receipt).await;
                        if let Err(error)=queue_event(client,&journal,&event(&envelope,"RUNNING",serde_json::to_value(receipt)?,"running")).await {
                            tracing::error!(error=%error,"running receipt publication failed");
                            let _=cancel_tx.send(true);
                        }
                        if let Err(error)=retain_deferred_starting_failure(replay_events(client,&journal).await) {
                            starting_failure.get_or_insert(error);
                            let _=cancel_tx.send(true);
                        }
                    }
                }
            },
            notice=notice_rx.recv(),if notices_open && starting_failure.is_none() => {
                // Runtime publishes its durable receipt before sending notices.
                // The log branch may win select before the watch branch does.
                if notice.is_some() && !starting_ready {
                    match ensure_deferred_starting(&journal, pending_starting.as_ref(), true).await {
                        Ok(_) => starting_ready = true,
                        Err(error) => {
                            tracing::error!(error=%error,"starting receipt persistence failed");
                            starting_failure.get_or_insert(error);
                            let _=cancel_tx.send(true);
                            continue;
                        }
                    }
                }
                if let Some(notice)=notice {if let Err(error)=queue_event(client,&journal,&event(&envelope,"LOG_SEGMENT",serde_json::to_value(&notice)?,&format!("log-{}-{:020}",notice.stream,notice.offset))).await {tracing::error!(error=%error,"log notification persistence failed");let _=cancel_tx.send(true);}if !controlled&&notice.stream=="stdout" {if let Err(error)=live.poll(client,&journal,&envelope).await {tracing::error!(error=%error,"live event projection failed");if error.downcast_ref::<DeferredStartingDurabilityFailure>().is_some(){starting_failure.get_or_insert(error);}let _=cancel_tx.send(true);}}} else {notices_open=false;}
            },
            _=heartbeat.tick(),if starting_failure.is_none()=> {
                // interval's first tick is immediate. Do not recreate the
                // telemetry checkpoint on the physical launch critical path.
                if launched_rx.borrow().is_none() { continue; }
                if !starting_ready {
                    match ensure_deferred_starting(&journal, pending_starting.as_ref(), true).await {
                        Ok(_) => starting_ready = true,
                        Err(error) => {
                            tracing::error!(error=%error,"starting receipt persistence failed");
                            starting_failure.get_or_insert(error);
                            let _=cancel_tx.send(true);
                            continue;
                        }
                    }
                }
                if !controlled {if let Err(error)=live.poll(client,&journal,&envelope).await {tracing::error!(error=%error,"live event replay failed");if error.downcast_ref::<DeferredStartingDurabilityFailure>().is_some(){starting_failure.get_or_insert(error);}let _=cancel_tx.send(true);}}
                if starting_failure.is_some() { continue; }
                if let Err(error)=retain_deferred_starting_failure(replay_events(client,&journal).await) {
                            starting_failure.get_or_insert(error);
                            let _=cancel_tx.send(true);
                        }
            },
        }
    };
    lease_guard.abort();
    let _ = lease_guard.await;
    // The independent author supervisor has settled. Close and join every model
    // relay exchange before publishing whole-attempt stop evidence. Transport
    // closure never claims that an interrupted provider request stopped.
    let model_relay_stop = if let Some(relay) = model_relay {
        Some(relay.finish().await?)
    } else {
        None
    };
    drop(native_controller);
    // Fast exit, cancellation before spawn and supervisor errors can settle
    // before any receipt branch. The supervisor is already joined here.
    if !starting_ready {
        if let Err(error) =
            ensure_deferred_starting(&journal, pending_starting.as_ref(), true).await
        {
            starting_failure.get_or_insert(error);
        }
    }
    // A short process can settle before select observes the watch change.
    let last_launch = launched_rx.borrow().clone();
    if let Some(receipt) = last_launch {
        persist_preparation_timing(
            &journal,
            &mut preparation_timing,
            preparation_started,
            &receipt,
        )
        .await;
    }
    // Native access ends with independent supervisor settlement. The following
    // worker callback supplies its exact receipt and stop to canonical closure.
    // A zero exit racing cancellation must never erase a persistence failure.
    let stop = supervision?;
    let transport = native_controller::reconcile_transport(&journal, stop.process_exit_confirmed);
    if let Some(error) = starting_failure {
        if let Err(transport_error) = transport {
            tracing::error!(error=%transport_error,"native transport reconciliation after starting failure failed");
        }
        return Err(error);
    }
    transport?;
    if *shutdown_rx.borrow() {
        bail!("worker shutdown requested");
    }
    let mut outcome = if controlled {
        ExecutorOutcome {
            execution_id: journal.execution_id()?,
            upstream_session_id: None,
            exit_code: stop.exit_code,
            completion_reason: if !stop.process_exit_confirmed {
                "RECOVERY_REQUIRED"
            } else if stop.reason.starts_with("cancelled") {
                "CANCELLED"
            } else if stop.exit_code == Some(0) && stop.log_error.is_none() {
                "EXECUTOR_COMPLETED"
            } else {
                "PROCESS_FAILED"
            }
            .into(),
            raw_event_digest: hash_file(&journal.path("stdout.ndjson"))
                .await
                .unwrap_or_else(|_| sha256(&[])),
            transcript_completeness: "CONTROLLED_LIGHTWEIGHT_STDIO_NOT_DSH".into(),
            final_artifact: None,
            error_class: None,
        }
    } else {
        let parsed = tokio::select! {
            parsed=parse_persisted_stream(client, &journal, &envelope, &stop, profile.claude().is_some())=>parsed,
            _=shutdown_rx.changed()=>bail!("worker shutdown requested"),
        };
        match parsed {
            Ok(value) => value,
            Err(error) => ExecutorOutcome {
                execution_id: journal.execution_id()?,
                upstream_session_id: None,
                exit_code: stop.exit_code,
                completion_reason: if stop.process_exit_confirmed {
                    "PROTOCOL_OR_EVIDENCE_ERROR"
                } else {
                    "RECOVERY_REQUIRED"
                }
                .into(),
                raw_event_digest: String::new(),
                transcript_completeness: "INCOMPLETE".into(),
                final_artifact: None,
                error_class: Some(error.to_string()),
            },
        }
    };
    let audit = if stop.process_exit_confirmed {
        let path = worktree.absolute_path.clone();
        let base = envelope.base_sha.clone();
        let scope = forgeflow_git::PathScope {
            owner_paths: envelope.write_set.clone(),
            write_set: envelope.write_set.clone(),
        };
        match tokio::task::spawn_blocking(move || {
            forgeflow_git::audit_private_worktree(&path, &base, &scope)
        })
        .await?
        {
            Ok(manifest) => serde_json::to_value(manifest)?,
            Err(error) => {
                outcome.completion_reason = "WRITE_SCOPE_VIOLATION".into();
                outcome.error_class = Some(error.to_string());
                json!({"error":error.to_string()})
            }
        }
    } else {
        json!({"quarantined":true,"reason":"writer stop unconfirmed"})
    };
    let stderr_digest = hash_file(&journal.path("stderr.log")).await.ok();
    let result = WorkerResult {
        event_id: format!("{}:result", envelope.operation_id),
        project_id: envelope.project_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        lease_id: envelope.lease_id.clone(),
        generation: envelope.generation,
        worker_id: envelope.worker_id.clone(),
        evidence: bound_stop_evidence(
            json!({"process_exit_confirmed":stop.process_exit_confirmed,"stop":stop,"stderr_sha256":stderr_digest,"scope_audit":audit,"worktree":worktree.absolute_path,"base_sha":worktree.base_sha,"journal":journal.directory,"executor_kind":if controlled {"CONTROLLED_LIGHTWEIGHT"}else if profile.claude().is_some(){"CLAUDE_CODE_LEAF"}else if prepared_managed.is_some(){"DSH_MANAGED"}else{"DSH_HEADLESS"},"real_dsh":!controlled && profile.dsh().is_some(),"model_relay_stop":model_relay_stop}),
            &envelope,
            &journal,
            &outcome.execution_id,
        )?,
        outcome,
    };
    durable_json(&journal.path("result.json"), &result)?;
    // Publication and ACK can fail after the author has stopped. The durable result
    // still owns the exact generation until controller settlement, so retain first.
    durable_json(
        &journal.path("lease-retention.json"),
        &json!({"attempt_id":envelope.attempt_id,
        "generation":envelope.generation,"state":"AWAITING_CONTROLLER_SETTLEMENT",
        "deadline_at":envelope.deadline_at}),
    )?;
    keeper.retain_until_settlement();
    if *shutdown_rx.borrow() {
        bail!("worker shutdown requested");
    }
    let publication = tokio::select! {
        result=async {
        // Revocation can reject late execution events. Their retained outbox must never
        // prevent an identity-bound stop receipt from confirming quiescence.
        let _ = replay_events(client, &journal).await;
        deliver_result(config, client, &envelope, &journal, &result).await?;
        Ok::<_, anyhow::Error>(())
        }=>result,
        _=shutdown_rx.changed()=>bail!("worker shutdown requested"),
    };
    if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        bail!("worker shutdown requested");
    }
    publication?;
    Ok(())
}

async fn restore_lease(
    client: ControlClient,
    envelope: ExecutionEnvelope,
    shutdown: watch::Receiver<bool>,
) {
    let deadline = match remaining(&envelope.deadline_at) {
        Ok(value) => value,
        Err(_) => return,
    };
    let restore = async {
        loop {
            if *shutdown.borrow() {
                return;
            }
            match client.control(&envelope).await {
                Ok(control) if control.valid && !control.cancel_requested => {
                    if let Ok(expires_at) = parse_time(&control.lease_expires_at) {
                        let mut keeper = LeaseKeeper::start(
                            client.clone(),
                            envelope.clone(),
                            expires_at,
                            shutdown.clone(),
                        );
                        keeper.retain_until_settlement();
                    }
                    return;
                }
                Ok(_) => return,
                Err(error) => {
                    tracing::warn!(attempt_id=%envelope.attempt_id,error=%error,"restored lease authority unavailable")
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    };
    let mut stop = shutdown.clone();
    tokio::select! { _=restore=>{}, _=stop.changed()=>{}, _=tokio::time::sleep(deadline)=>{} }
}

fn terminal_identity_matches(authority: &Value, envelope: &ExecutionEnvelope) -> bool {
    authority["project_id"] == envelope.project_id
        && authority["task_id"] == envelope.task_id
        && authority["task_revision"].as_u64() == Some(envelope.task_revision)
        && authority["attempt_id"] == envelope.attempt_id
        && authority["lease_id"] == envelope.lease_id
        && authority["generation"].as_i64() == Some(envelope.generation)
        && authority["worker_id"] == envelope.worker_id
        && authority["operation_id"] == envelope.operation_id
        && authority["base_sha"] == envelope.base_sha
}

fn terminal_state(value: &Value) -> bool {
    matches!(
        value["state"].as_str(),
        Some("SUCCEEDED" | "FAILED" | "CANCELLED")
    )
}

/// Publish current observed authority, never a synthesized historical timestamp.
/// Completion and full immutable identity precede durable evidence and refill.
async fn publish_terminal_observation(
    client: &ControlClient,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    authority: Value,
    transport: &str,
    received_at: &str,
) -> Result<bool> {
    if !terminal_identity_matches(&authority, envelope) {
        bail!("controller terminal identity differs from frozen attempt");
    }
    if !terminal_state(&authority)
        || !matches!(journal.disposition()?, RecoveryDisposition::Completed)
    {
        return Ok(false);
    }
    let stop: StopEvidence = serde_json::from_slice(&std::fs::read(journal.path("stop.json"))?)?;
    if !stop.process_exit_confirmed {
        return Ok(false);
    }
    let receipt_path = journal.path("controller-terminal.json");
    let receipt = json!({
        "schema_version":"forgeflow.worker-controller-terminal.v1",
        "transport":transport,"received_at":received_at,"authority":authority,
        "local_stop_sha256":sha256(&std::fs::read(journal.path("stop.json"))?),
        "local_stop":stop,
    });
    let previous = match std::fs::read(&receipt_path) {
        Ok(bytes) => Some(serde_json::from_slice::<Value>(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(previous) = previous {
        if previous["schema_version"] != "forgeflow.worker-controller-terminal.v1"
            || !terminal_identity_matches(&previous["authority"], envelope)
            || previous["authority"]["state"] != receipt["authority"]["state"]
            || previous["local_stop_sha256"] != receipt["local_stop_sha256"]
        {
            bail!("durable terminal observation drift; original retained");
        }
    } else {
        let write_path = receipt_path.clone();
        let write_receipt = receipt.clone();
        tokio::task::spawn_blocking(move || {
            attempt_preparation::durable_first_json(&write_path, &write_receipt)
        })
        .await??;
        // A concurrent SSE/HTTP observer may have published first. Verify the
        // winning immutable receipt before trusting it; never rewrite its time.
        let saved: Value = serde_json::from_slice(&std::fs::read(&receipt_path)?)?;
        if saved["schema_version"] != "forgeflow.worker-controller-terminal.v1"
            || !terminal_identity_matches(&saved["authority"], envelope)
            || saved["authority"]["state"] != receipt["authority"]["state"]
            || saved["local_stop_sha256"] != receipt["local_stop_sha256"]
        {
            bail!("concurrent durable terminal observation differs; capacity retained");
        }
    }
    if let Some(settlements) = &client.settlements {
        let _ = settlements.send(SettlementNotice {
            attempt_id: envelope.attempt_id.clone(),
            terminal_confirmed: true,
            canonical_result: false,
            wake_only: false,
        });
    }
    Ok(true)
}

fn dispatch_scope_component(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

async fn consume_dispatch_frame(
    config: &WorkerConfig,
    client: &ControlClient,
    raw: &[u8],
    after: &mut u64,
) -> Result<()> {
    let text = std::str::from_utf8(raw).context("dispatch event is not UTF-8")?;
    let mut event_type = "";
    let mut event_id = "";
    let mut data = String::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_type = value.trim();
        }
        if let Some(value) = line.strip_prefix("id:") {
            event_id = value.trim();
        }
        if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.trim_start());
        }
    }
    if event_type != "worker-dispatch" || data.is_empty() {
        return Ok(());
    }
    let fact: Value = serde_json::from_str(&data)?;
    let prefix = format!(
        "{}:{}:",
        dispatch_scope_component(&config.project_id),
        dispatch_scope_component(&config.worker_id)
    );
    let sequence = event_id
        .strip_prefix(&prefix)
        .context("dispatch cursor scope differs")?
        .parse::<u64>()
        .context("dispatch cursor is not an integer")?;
    if fact["schema_version"] != "forgeflow.worker_dispatch.v1"
        || fact["project_id"] != config.project_id
        || fact["worker_id"] != config.worker_id
        || fact["project_seq"].as_u64() != Some(sequence)
    {
        bail!("dispatch event protocol or scope mismatch");
    }
    *after = (*after).max(sequence);
    match fact["kind"].as_str() {
        Some("CURSOR") => return Ok(()),
        Some("HANDOFF_WAKE") => {
            if let Some(settlements) = &client.settlements {
                let _ = settlements.send(SettlementNotice {
                    attempt_id: String::new(),
                    terminal_confirmed: false,
                    canonical_result: false,
                    wake_only: true,
                });
            }
            return Ok(());
        }
        Some("TERMINAL") => {}
        _ => bail!("unknown dispatch fact kind"),
    }
    let attempt_id = fact["attempt_id"]
        .as_str()
        .context("dispatch attempt missing")?;
    safe_id(attempt_id)?;
    let journal = Journal::new(&config.data_root.join("attempts"), attempt_id)?;
    let envelope: ExecutionEnvelope = match std::fs::read(journal.path("envelope.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    publish_terminal_observation(
        client,
        &envelope,
        &journal,
        fact,
        "WORKER_DISPATCH_SSE",
        &chrono::Utc::now().to_rfc3339(),
    )
    .await?;
    Ok(())
}

struct WorkerDispatchListener {
    task: tokio::task::JoinHandle<()>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for WorkerDispatchListener {
    fn drop(&mut self) {
        self.connected
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.task.abort();
    }
}
impl WorkerDispatchListener {
    fn start(
        config: WorkerConfig,
        client: ControlClient,
        mut shutdown: watch::Receiver<bool>,
    ) -> Self {
        let connected = client.dispatch_connected.clone();
        let task = tokio::spawn(async move {
            use futures::StreamExt;
            let mut after = 0u64; // Replay is safe; first accepted receipt is immutable.
            while !*shutdown.borrow() {
                let observe = async {
                    let response = client
                        .client
                        .get(client.url(&["workers", &config.worker_id, "dispatch-events"])?)
                        .bearer_auth(&client.token)
                        .header("Accept", "text/event-stream")
                        .header(
                            "Last-Event-ID",
                            format!(
                                "{}:{}:{after}",
                                dispatch_scope_component(&config.project_id),
                                dispatch_scope_component(&config.worker_id)
                            ),
                        )
                        .query(&[
                            ("project_id", config.project_id.clone()),
                            ("after", after.to_string()),
                        ])
                        .timeout(Duration::from_secs(60))
                        .send()
                        .await?
                        .error_for_status()?;
                    if !response
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.starts_with("text/event-stream"))
                    {
                        bail!("worker dispatch stream content type differs");
                    }
                    client
                        .dispatch_connected
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    let mut chunks = response.bytes_stream();
                    let mut buffer = Vec::new();
                    while let Some(chunk) = chunks.next().await {
                        buffer.extend_from_slice(&chunk?);
                        if buffer.len() > 1024 * 1024 {
                            bail!("dispatch stream buffered frame budget exceeded");
                        }
                        while let Some(end) = buffer.windows(2).position(|p| p == b"\n\n") {
                            let frame = buffer.drain(..end + 2).collect::<Vec<_>>();
                            if frame.len() > 64 * 1024 {
                                bail!("dispatch fact exceeds bounded frame budget");
                            }
                            if let Err(error) =
                                consume_dispatch_frame(&config, &client, &frame, &mut after).await
                            {
                                tracing::warn!(error=%error,"dispatch fact rejected; capacity retained");
                            }
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                };
                tokio::select! {
                    result=observe => { if let Err(error)=result {tracing::debug!(error=%error,"dispatch stream reconnect pending");} }
                    _=shutdown.changed()=>break,
                }
                client
                    .dispatch_connected
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Some(settlements) = &client.settlements {
                    let _ = settlements.send(SettlementNotice {
                        attempt_id: String::new(),
                        terminal_confirmed: false,
                        canonical_result: false,
                        wake_only: true,
                    });
                }
                tokio::select! { _=tokio::time::sleep(Duration::from_millis(250))=>{}, _=shutdown.changed()=>break }
            }
            client
                .dispatch_connected
                .store(false, std::sync::atomic::Ordering::Relaxed);
        });
        Self { task, connected }
    }
}

struct MaintenanceOutcome {
    release: bool,
    acknowledged: bool,
}
async fn maintain_attempt(
    config: &WorkerConfig,
    client: &ControlClient,
    attempt: &str,
    pending: bool,
) -> Result<MaintenanceOutcome> {
    let journal = Journal::new(&config.data_root.join("attempts"), attempt)?;
    let envelope: ExecutionEnvelope =
        serde_json::from_slice(&std::fs::read(journal.path("envelope.json"))?)?;
    let mut outcome = MaintenanceOutcome {
        release: false,
        acknowledged: false,
    };
    match client.attempt(&envelope).await {
        Ok(authority)
            if authority.generation == envelope.generation
                && authority.worker_id == config.worker_id =>
        {
            let stopped = matches!(journal.disposition()?, RecoveryDisposition::Completed);
            outcome.release = authority.state.is_terminal() && stopped;
            if outcome.release {
                // Do not wait for late log replay before returning this actual
                // terminal observation to admission. Its receive time is current.
                outcome.release = publish_terminal_observation(
                    client,
                    &envelope,
                    &journal,
                    serde_json::to_value(&authority)?,
                    "ATTEMPT_HTTP_FALLBACK",
                    &chrono::Utc::now().to_rfc3339(),
                )
                .await?;
            }
            if stopped
                && matches!(
                    authority.state,
                    forgeflow_domain::AttemptState::Stopping
                        | forgeflow_domain::AttemptState::RecoveryRequired
                )
            {
                let stop: StopEvidence =
                    serde_json::from_slice(&std::fs::read(journal.path("stop.json"))?)?;
                if stop.process_exit_confirmed {
                    let mut result = reconciled_author_stop(&envelope, &stop, &journal)?;
                    result.event_id =
                        format!("{}:post-author-stop-confirmation", envelope.operation_id);
                    result.evidence["author_stop_only"] = json!(true);
                    result.evidence["original_stop_sha256"] =
                        json!(hash_file(&journal.path("stop.json")).await?);
                    durable_json(&journal.path("post-author-stop-result.json"), &result)?;
                    let _ = deliver_result(config, client, &envelope, &journal, &result).await;
                }
            }
        }
        Ok(_) => tracing::warn!(attempt_id=%attempt,"attempt authority differs; capacity retained"),
        Err(error) => {
            tracing::warn!(attempt_id=%attempt,error=%error,"attempt observation unavailable; capacity retained")
        }
    }
    if pending {
        let result: WorkerResult =
            serde_json::from_slice(&std::fs::read(journal.path("result.json"))?)?;
        if deliver_result(config, client, &envelope, &journal, &result)
            .await
            .is_ok()
        {
            outcome.acknowledged = true;
        }
    }
    let _ = replay_events(client, &journal).await;
    Ok(outcome)
}

fn configuration_shape(config: &WorkerConfig) -> Result<()> {
    safe_id(&config.worker_id)?;
    safe_id(&config.project_id)?;
    config.profile.verify_configuration(
        config.managed_dsh.is_some(),
        &config.model_route_id,
        config.sandbox.is_some(),
    )?;
    if !config.data_root.is_absolute() || config.max_log_bytes == 0 {
        bail!("absolute data root and nonzero log budget required");
    }
    if !(1..=128).contains(&config.max_active_attempts) {
        bail!("worker concurrency must be 1..128");
    }
    Ok(())
}

/// This local Doctor uses the same frozen mode/profile checks as real startup.
/// It never registers a Worker, claims a task, or starts a native/model session.
pub fn check_configuration(config: &WorkerConfig) -> Result<Value> {
    configuration_shape(config)?;
    config.profile.verify_identity()?;
    if let Some(sandbox) = &config.sandbox {
        for (path, expected) in [
            (&sandbox.bwrap_program, &sandbox.bwrap_sha256),
            (&sandbox.guard_program, &sandbox.guard_sha256),
        ] {
            if !path.is_absolute() || sha256(&std::fs::read(path)?) != *expected {
                bail!("sandbox executable differs from the exact configuration pin");
            }
        }
    }
    if let Some(managed) = &config.managed_dsh {
        if config.sandbox.is_none()
            || (managed.model_relay.is_some()
                && config.sandbox.as_ref().is_some_and(|s| s.network_allowed))
        {
            bail!("managed mode requires a strong sandbox and relay-confined network");
        }
        native_controller::verify_managed(
            config
                .profile
                .dsh()
                .context("managed DSH profile required")?,
            managed,
        )?;
    }
    Ok(
        json!({"status":"PINNED_CONFIGURATION_VALID", "worker_id":config.worker_id,
        "project_id":config.project_id,"executor_profile_id":config.profile.id(),
        "max_active_attempts":config.max_active_attempts,"scope":"LOCAL_PINNED_CONFIGURATION_ONLY",
        "workers_registered":0,"native_sessions_started":0,"model_calls":0,"g20":"NOT_RUN"}),
    )
}

pub async fn run(config: WorkerConfig, token: String) -> Result<()> {
    configuration_shape(&config)?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    let _shutdown_signal = tokio::spawn(async move {
        let _ = wait_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    std::fs::create_dir_all(config.data_root.join("attempts"))?;
    let (settlement_tx, mut settlement_rx) = mpsc::unbounded_channel();
    let mut client = ControlClient::new(&config.control_url, token)?;
    client.settlements = Some(settlement_tx);
    let boot = boot_id()?;
    let native_configured = config.profile.id() != "controlled-lightweight.v1";
    let mut executor_profile_ids = Vec::new();
    if native_configured {
        config.profile.verify_identity()?;
        if let Some(managed) = &config.managed_dsh {
            if config.sandbox.is_none() {
                bail!("managed mode requires strong sandbox");
            }
            if managed.model_relay.is_some()
                && config
                    .sandbox
                    .as_ref()
                    .is_none_or(|sandbox| sandbox.network_allowed)
            {
                bail!(
                    "strict model relay registration requires network_allowed=false; no ambient egress fallback"
                );
            }
            native_controller::verify_managed(
                config
                    .profile
                    .dsh()
                    .context("managed DSH profile missing")?,
                managed,
            )?;
        }
        std::fs::create_dir_all(config.profile.home())?;
        if config.managed_dsh.is_none() && config.profile.dsh().is_some() {
            bind_project_home(
                config.profile.home(),
                &config.project_id,
                config.profile.id(),
            )?;
        }
        executor_profile_ids.push(config.profile.id().to_owned());
    }
    for (program, expected) in &config.controlled_workload_programs {
        if !Path::new(program).is_absolute() || hash_file(Path::new(program)).await? != *expected {
            bail!("controlled executable registration pin mismatch");
        }
    }
    if !config.controlled_workload_programs.is_empty()
        && !executor_profile_ids
            .iter()
            .any(|id| id == "controlled-lightweight.v1")
    {
        executor_profile_ids.push("controlled-lightweight.v1".into());
    }
    client
        .register(&RegisterRequest {
            worker_id: config.worker_id.clone(),
            boot_id: boot.clone(),
            project_id: Some(config.project_id.clone()),
            executor_profile_ids,
            capabilities: {
                let mut capabilities = vec![
                    "LINUX_PROCESS_GROUP".into(),
                    "DURABLE_LAUNCH_JOURNAL".into(),
                    "LOCAL_TRUSTED_WORKTREE".into(),
                ];
                if native_configured {
                    capabilities.push(
                        if profile_is_claude(&config) {
                            "CLAUDE_CODE_LEAF"
                        } else {
                            "DSH_HEADLESS"
                        }
                        .into(),
                    );
                    if config.managed_dsh.is_some() {
                        capabilities.push("CANONICAL_NATIVE_RPC_V2".into());
                    }
                }
                if !config.controlled_workload_programs.is_empty() {
                    capabilities.push("CONTROLLED_LIGHTWEIGHT".into());
                }
                capabilities
            },
        })
        .await?;
    // Conservatively reserve every durable owned attempt before slow recovery HTTP.
    // Presence and independent restored lease tasks start before serial publication.
    let mut occupied = std::collections::BTreeSet::new();
    let mut pending_reports = std::collections::BTreeSet::<String>::new();
    let mut recovered = Vec::new();
    for entry in std::fs::read_dir(config.data_root.join("attempts"))? {
        let journal = Journal {
            directory: entry?.path(),
        };
        if !journal.directory.is_dir() {
            continue;
        }
        let prepared = attempt_preparation::restore(&journal)?;
        let envelope: ExecutionEnvelope = if let Some(envelope) = prepared {
            envelope
        } else if journal.path("envelope.json").exists() {
            serde_json::from_slice(&std::fs::read(journal.path("envelope.json"))?)?
        } else {
            continue;
        };
        if envelope.worker_id != config.worker_id || envelope.project_id != config.project_id {
            continue;
        }
        occupied.insert(envelope.attempt_id.clone());
        recovered.push((journal, envelope));
    }
    let presence = WorkerPresence::start(
        client.clone(),
        config.worker_id.clone(),
        boot.clone(),
        occupied.iter().cloned().collect(),
    );
    let mut restorations = tokio::task::JoinSet::new();
    for (_, envelope) in &recovered {
        restorations.spawn(restore_lease(
            client.clone(),
            envelope.clone(),
            shutdown_rx.clone(),
        ));
    }
    // A missing receipt remains quarantined and can never justify a fresh launch.
    for (journal, envelope) in recovered {
        // A crash while observing an unused physical leaf must not replace the
        // original preparation failure with a synthetic author-stop result.
        if journal.path("no-launch-failure-settlement.lock").exists()
            && !no_launch_failure_has_launch_facts(&journal)?
            && journal.path("result.json").exists()
        {
            let original: WorkerResult =
                serde_json::from_slice(&std::fs::read(journal.path("result.json"))?)?;
            if original.outcome.completion_reason == "WORKER_PREPARATION_FAILED" {
                native_controller::reconcile_transport(&journal, true)?;
                if let Err(error) =
                    deliver_result(&config, &client, &envelope, &journal, &original).await
                {
                    tracing::warn!(attempt_id=%envelope.attempt_id,%error,"no-launch physical failure remains held");
                }
                continue;
            }
        }
        if let RecoveryDisposition::RecoveryRequired(reason) = journal.disposition()? {
            let reconciliation = reconcile(&journal, Duration::from_secs(3)).await;
            let payload = match reconciliation {
                Ok(stop) => {
                    native_controller::reconcile_transport(&journal, stop.process_exit_confirmed)?;
                    if stop.process_exit_confirmed {
                        let result = WorkerResult {
                            event_id: format!("{}:reconciled-stop", envelope.operation_id),
                            project_id: envelope.project_id.clone(),
                            attempt_id: envelope.attempt_id.clone(),
                            lease_id: envelope.lease_id.clone(),
                            generation: envelope.generation,
                            worker_id: envelope.worker_id.clone(),
                            evidence: bound_stop_evidence(
                                json!({"process_exit_confirmed":true,"stop":stop,"executor_kind":executor_profile::journal_executor_identity(&envelope, &journal)?.0,"real_dsh":executor_profile::journal_executor_identity(&envelope, &journal)?.1}),
                                &envelope,
                                &journal,
                                &journal.execution_id()?,
                            )?,
                            outcome: ExecutorOutcome {
                                execution_id: journal.execution_id()?,
                                upstream_session_id: None,
                                exit_code: None,
                                completion_reason: "CANCELLED".into(),
                                raw_event_digest: String::new(),
                                transcript_completeness: "RESTART_RECONCILIATION".into(),
                                final_artifact: None,
                                error_class: None,
                            },
                        };
                        durable_json(&journal.path("result.json"), &result)?;
                        let _ = std::fs::remove_file(journal.path("result-ack.json"));
                    }
                    json!({"reason":reason,"stop":stop})
                }
                Err(error) => json!({"reason":reason,"error":error.to_string(),"quarantined":true}),
            };
            queue_event(
                &client,
                &journal,
                &event(&envelope, "RECOVERY_REQUIRED", payload, "restart-recovery"),
            )
            .await?;
        }
        if matches!(journal.disposition()?, RecoveryDisposition::Completed) {
            let stop: StopEvidence =
                serde_json::from_slice(&std::fs::read(journal.path("stop.json"))?)?;
            native_controller::reconcile_transport(&journal, stop.process_exit_confirmed)?;
        }
        if matches!(journal.disposition()?, RecoveryDisposition::Completed)
            && !journal.path("result.json").exists()
        {
            if let Ok(authority) = client.attempt(&envelope).await {
                if matches!(
                    authority.state,
                    forgeflow_domain::AttemptState::Starting
                        | forgeflow_domain::AttemptState::Running
                ) && authority.generation == envelope.generation
                {
                    let stop: StopEvidence =
                        serde_json::from_slice(&std::fs::read(journal.path("stop.json"))?)?;
                    queue_event(&client,&journal,&event(&envelope,"RECOVERY_REQUIRED",json!({"reason":"worker stopped author before durable result settlement","stop":stop}),"unsettled-author-recovery")).await?;
                    let result = reconciled_author_stop(&envelope, &stop, &journal)?;
                    durable_json(&journal.path("result.json"), &result)?;
                }
            }
        }
        let _ = replay_events(&client, &journal).await;
        if journal.path("result.json").exists() {
            let result: WorkerResult =
                serde_json::from_slice(&std::fs::read(journal.path("result.json"))?)?;
            let _ = deliver_result(&config, &client, &envelope, &journal, &result).await;
        }
    }
    let _dispatch =
        WorkerDispatchListener::start(config.clone(), client.clone(), shutdown_rx.clone());
    let mut tasks: tokio::task::JoinSet<(String, Result<()>)> = tokio::task::JoinSet::new();
    let mut running_ids = std::collections::BTreeSet::<String>::new();
    for attempt in &occupied {
        let journal = Journal::new(&config.data_root.join("attempts"), attempt)?;
        if journal.path("result.json").exists() && !journal.path("result-ack.json").exists() {
            pending_reports.insert(attempt.clone());
        }
    }
    let mut claims = tokio::task::JoinSet::new();
    let mut maintenance: tokio::task::JoinSet<(String, Result<MaintenanceOutcome>)> =
        tokio::task::JoinSet::new();
    let mut maintenance_ids = std::collections::BTreeSet::new();
    let mut cursor = None;
    let mut poll = tokio::time::interval(Duration::from_secs(config.poll_seconds.clamp(1, 10)));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut dispatch_fallback = tokio::time::interval(Duration::from_millis(250));
    dispatch_fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutting_down = *shutdown_rx.borrow();
    let mut claim_budget = 0usize;
    let mut refill_epoch = 0u64;
    loop {
        if shutting_down && tasks.is_empty() && claims.is_empty() {
            return Ok(());
        }
        if !shutting_down
            && !*shutdown_rx.borrow()
            && claims.is_empty()
            && claim_budget > 0
            && occupied.len() < config.max_active_attempts
            && presence.admits()
        {
            claim_budget -= 1;
            let config = config.clone();
            let client = client.clone();
            let known = occupied.iter().cloned().collect();
            let epoch = refill_epoch;
            claims.spawn(async move { (epoch, client.claim(&config, known).await) });
        }
        tokio::select! {
            _=shutdown_rx.changed(), if !shutting_down => { shutting_down = true; },
            Some(settlement)=settlement_rx.recv() => {
                if settlement.wake_only { claim_budget = claim_budget.max(1); }
                if settlement.canonical_result { pending_reports.remove(&settlement.attempt_id); }
                if settlement.terminal_confirmed && occupied.remove(&settlement.attempt_id) {
                    presence.update(&occupied);
                    // A durable terminal ACK grants an immediate normal claim.
                    // Claim-before-effect and the independent launch fence remain
                    // mandatory; a handoff envelope alone never launches a process.
                    refill_epoch = refill_epoch.wrapping_add(1);
                    claim_budget = claim_budget.saturating_add(1).min(config.max_active_attempts);
                }
            },
            _=restorations.join_next(), if !restorations.is_empty() => {},
            completion=tasks.join_next(), if !tasks.is_empty() => {
                match completion {
                    Some(Ok((attempt, result))) => {
                        if let Err(error) = result { tracing::error!(attempt_id=%attempt,error=%error,"attempt stopped; durable evidence retained"); }
                        running_ids.remove(&attempt);
                        let journal = Journal::new(&config.data_root.join("attempts"), &attempt)?;
                        if journal.path("result.json").exists() && !journal.path("result-ack.json").exists() { pending_reports.insert(attempt.clone()); }
                        if occupied.contains(&attempt) && maintenance.len() < 4 && maintenance_ids.insert(attempt.clone()) {
                            let pending = pending_reports.contains(&attempt); let config = config.clone(); let client = client.clone();
                            maintenance.spawn(async move { let result = maintain_attempt(&config, &client, &attempt, pending).await; (attempt, result) });
                        }
                    }
                    Some(Err(error)) => tracing::error!(error=%error,"supervision task panicked; capacity retained for recovery"),
                    None => {}
                }
            },
            completion=maintenance.join_next(), if !maintenance.is_empty() => {
                match completion {
                    Some(Ok((attempt, outcome))) => {
                        maintenance_ids.remove(&attempt);
                        match outcome {
                            Ok(outcome) => {
                                if outcome.release && occupied.remove(&attempt) {
                                    presence.update(&occupied);
                                    refill_epoch = refill_epoch.wrapping_add(1);
                                    claim_budget = claim_budget.saturating_add(1).min(config.max_active_attempts);
                                }
                                if outcome.acknowledged { pending_reports.remove(&attempt); }
                            }
                            Err(error) => tracing::warn!(attempt_id=%attempt,error=%error,"attempt maintenance failed; durable capacity retained"),
                        }
                    }
                    Some(Err(error)) => tracing::error!(error=%error,"attempt maintenance panicked; capacity retained"),
                    None => {}
                }
            },
            completion=claims.join_next(), if !claims.is_empty() => {
                match completion {
                    Some(Ok((_, Ok(Some(envelope))))) => {
                        if occupied.len() >= config.max_active_attempts { bail!("claim exceeded reserved worker capacity"); }
                        if !occupied.insert(envelope.attempt_id.clone()) { tracing::error!(attempt_id=%envelope.attempt_id,"duplicate active claim ignored"); continue; }
                        presence.update(&occupied);
                        running_ids.insert(envelope.attempt_id.clone());
                        let config = config.clone(); let client = client.clone(); let shutdown = shutdown_rx.clone(); let attempt = envelope.attempt_id.clone();
                        // Even a claim received during shutdown is durably settled. execute
                        // observes shutdown before preparation and cannot launch a child.
                        tasks.spawn(async move { let result = execute_controlled(&config, &client, envelope, shutdown).await; (attempt, result) });
                    }
                    Some(Ok((epoch, Ok(None)))) => { if epoch == refill_epoch { claim_budget = 0; } },
                    Some(Ok((epoch, Err(error)))) => { if epoch == refill_epoch { claim_budget = 0; } tracing::warn!(error=%error,"claim unavailable"); },
                    Some(Err(error)) => tracing::error!(error=%error,"claim task panicked; admission suspended for this poll"),
                    None => {}
                }
            },
            _=poll.tick(), if !shutting_down => {
                // Four concurrent maintenance requests, one in-flight claim, and a
                // rotating cursor bound work per tick without privileging low IDs.
                let eligible = occupied.union(&pending_reports).filter(|id| !running_ids.contains(*id) && !maintenance_ids.contains(*id)).cloned().collect();
                for attempt in fair_batch(&eligible, &mut cursor, 4usize.saturating_sub(maintenance.len())) {
                    maintenance_ids.insert(attempt.clone());
                    let pending = pending_reports.contains(&attempt); let config = config.clone(); let client = client.clone();
                    maintenance.spawn(async move { let result = maintain_attempt(&config, &client, &attempt, pending).await; (attempt, result) });
                }
                claim_budget = 4;
            },
            _=dispatch_fallback.tick(), if !shutting_down && !client.dispatch_connected.load(std::sync::atomic::Ordering::Relaxed) => {
                // Bounded fallback only while the single scoped event stream is
                // unavailable. Live authors are never polled/released by this lane.
                let eligible = occupied.union(&pending_reports).filter(|id| !running_ids.contains(*id) && !maintenance_ids.contains(*id)).cloned().collect();
                for attempt in fair_batch(&eligible, &mut cursor, 4usize.saturating_sub(maintenance.len())) {
                    maintenance_ids.insert(attempt.clone());
                    let pending = pending_reports.contains(&attempt); let config = config.clone(); let client = client.clone();
                    maintenance.spawn(async move { let result = maintain_attempt(&config, &client, &attempt, pending).await; (attempt, result) });
                }
                claim_budget = claim_budget.max(1);
            },
        }
    }
}

async fn verify_context_files(
    bytes: &[u8],
    envelope: &ExecutionEnvelope,
    workspace: &Path,
    client: &ControlClient,
    journal: &Journal,
) -> Result<()> {
    let manifest: forgeflow_domain::ContextManifest = serde_json::from_slice(bytes)?;
    let root = std::fs::canonicalize(workspace)?;
    let mut seen = std::collections::BTreeSet::new();
    for file in &manifest.files {
        forgeflow_domain::validate_relative_path(&file.path)?;
        if !forgeflow_domain::valid_digest(&file.sha256) || !seen.insert(file.path.as_str()) {
            bail!("invalid or duplicate context file identity");
        }
        let mut path = root.clone();
        for component in Path::new(&file.path).components() {
            path.push(component);
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                bail!("context symlinks are unsupported");
            }
        }
        let canonical = std::fs::canonicalize(&path)?;
        if !canonical.starts_with(&root) || hash_file(&canonical).await? != file.sha256 {
            bail!("context file hash or path drift: {}", file.path);
        }
    }
    let mut artifact_bytes = 0usize;
    for input in &manifest.artifact_inputs {
        forgeflow_domain::validate_relative_path(&input.logical_path)?;
        if !forgeflow_domain::valid_digest(&input.artifact.sha256)
            || !seen.insert(input.logical_path.as_str())
        {
            bail!("invalid or duplicate artifact context identity");
        }
        let bytes = client
            .artifact(
                &envelope.project_id,
                &envelope.worker_id,
                &input.artifact.artifact_id,
            )
            .await?;
        artifact_bytes += bytes.len();
        if artifact_bytes > 32 * 1024 * 1024 || sha256(&bytes) != input.artifact.sha256 {
            bail!("artifact context byte budget or digest mismatch");
        }
        let root = journal.path("context-artifacts");
        std::fs::create_dir_all(&root)?;
        persist_bytes(&root.join(sha256(input.logical_path.as_bytes())), &bytes)?;
    }
    for required in envelope
        .context_manifest
        .mandatory_paths
        .iter()
        .chain(&manifest.mandatory_paths)
    {
        forgeflow_domain::validate_relative_path(required)?;
        if !seen.contains(required.as_str()) {
            bail!("mandatory context file missing from manifest: {required}");
        }
    }
    Ok(())
}

struct LiveProjection {
    offset: u64,
    pending: Vec<u8>,
    stream: claude_supervisor::NativeStream,
    deferred_large_line: bool,
}
impl LiveProjection {
    fn new(execution: &str) -> Self {
        Self::for_profile(execution, false)
    }
    fn for_profile(execution: &str, claude: bool) -> Self {
        Self {
            offset: 0,
            pending: Vec::new(),
            stream: claude_supervisor::NativeStream::new(execution, claude),
            deferred_large_line: false,
        }
    }
    async fn poll(
        &mut self,
        client: &ControlClient,
        journal: &Journal,
        envelope: &ExecutionEnvelope,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        if self.deferred_large_line {
            return Ok(());
        }
        let mut file = match tokio::fs::File::open(journal.path("stdout.ndjson")).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        file.seek(std::io::SeekFrom::Start(self.offset)).await?;
        let mut chunk = vec![0; 16384];
        let mut projected = 0usize;
        // Read a bounded batch per poll so heartbeat and cancellation remain responsive.
        for _ in 0..4 {
            let count = file.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            self.offset += count as u64;
            self.pending.extend_from_slice(&chunk[..count]);
            if self.pending.len() > 1024 * 1024 {
                self.pending.clear();
                self.deferred_large_line = true;
                return Ok(());
            }
            while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                let raw = self.pending.drain(..=end).collect::<Vec<_>>();
                let parsed = self.stream.observe_line(&raw);
                if self.stream.is_claude() && !claude_supervisor::should_project(&parsed) {
                    // Retain the physical sequence and complete supervisor log;
                    // token deltas need no per-frame file, metadata or outbox.
                    continue;
                }
                let raw_path = native_raw_path(journal, parsed.sequence)?;
                persist_native_raw(&raw_path, &raw)?;
                if self.stream.terminal(&parsed) {
                    persist_bytes(&journal.path("final.json"), &raw)?;
                }
                let payload = self.stream.projection(&parsed, &raw);
                let payload = normalize_native_for_source(
                    journal,
                    envelope,
                    parsed.sequence,
                    &parsed.kind,
                    payload,
                    &raw_path,
                    &sha256(&raw),
                    raw.len() as u64,
                    if self.stream.is_claude() {
                        "claude_code_leaf"
                    } else {
                        "dsh_headless"
                    },
                )?;
                queue_event(
                    client,
                    journal,
                    &event(
                        envelope,
                        "EXECUTOR_EVENT",
                        payload,
                        &format!("native-{:020}", parsed.sequence),
                    ),
                )
                .await?;
                projected += 1;
                if projected >= 16 {
                    self.offset -= self.pending.len() as u64;
                    self.pending.clear();
                    retain_deferred_starting_failure(replay_events(client, journal).await)?;
                    return Ok(());
                }
            }
        }
        retain_deferred_starting_failure(replay_events(client, journal).await)?;
        Ok(())
    }
}

/// Every failed preparation or uncertain launch leaves a durable result for server reconciliation.
async fn execute_controlled(
    config: &WorkerConfig,
    client: &ControlClient,
    envelope: ExecutionEnvelope,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let preparation_started = std::time::Instant::now();
    let preparation_started_at = chrono::Utc::now().to_rfc3339();
    envelope.validate()?;
    if envelope.worker_id != config.worker_id || envelope.project_id != config.project_id {
        bail!("envelope is assigned to another worker or project");
    }
    let existing = Journal::new(&config.data_root.join("attempts"), &envelope.attempt_id)?;
    if existing.path("envelope.json").exists() {
        let persisted: ExecutionEnvelope =
            serde_json::from_slice(&std::fs::read(existing.path("envelope.json"))?)?;
        if persisted != envelope {
            bail!("duplicate attempt changed its immutable envelope; retained original");
        }
    }
    std::fs::create_dir_all(&existing.directory)?;
    // A newly claimed attempt freezes the selected transaction before launch or
    // failure. A previous result keeps its prior callback policy and bytes.
    let new_attempt = !existing.path("envelope.json").exists()
        && !existing.path("execution-id.json").exists()
        && !existing.path("result-delivery-policy.json").exists()
        && !existing.path("launch-intent.json").exists()
        && !existing.path("launch.lock").exists()
        && !existing.path("result.json").exists();
    let prepare_config = config.clone();
    let prepare_envelope = envelope.clone();
    let prepare_journal = existing.clone();
    let prepared_authority = tokio::task::spawn_blocking(move || {
        attempt_preparation::prepare(
            &prepare_config,
            &prepare_envelope,
            &prepare_journal,
            new_attempt,
        )
    })
    .await??;
    if prepared_authority.is_none() {
        result_delivery_policy(config, &envelope, &existing, new_attempt)?;
    }
    // prepare already verified the immutable bundle and every compatibility
    // view. Carry that local result instead of rereading/restoring it twice.
    let bundle_ready_ms = preparation_ms(preparation_started);
    let mut pending_starting = None;
    let result = execute_inner(
        config,
        client,
        envelope.clone(),
        shutdown_rx.clone(),
        prepared_authority,
        preparation_started,
        preparation_started_at,
        bundle_ready_ms,
        &mut pending_starting,
    )
    .await;
    if let Err(error) = &result {
        let journal = Journal::new(&config.data_root.join("attempts"), &envelope.attempt_id)?;
        std::fs::create_dir_all(&journal.directory)?;
        // Legacy unlaunched journals can contain identity/policy without the
        // envelope view. Restore the already checked binding before validating
        // any clone-complete telemetry, including the existing-result branch.
        durable_json(&journal.path("envelope.json"), &envelope)?;
        ensure_deferred_starting(&journal, pending_starting.as_ref(), true).await?;
        if journal.path("result.json").exists() {
            return result;
        }
        let launched =
            journal.path("launch-intent.json").exists() || journal.path("launch.lock").exists();
        let stop = if journal.path("stop.json").exists() {
            serde_json::from_slice::<StopEvidence>(&std::fs::read(journal.path("stop.json"))?)?
        } else {
            StopEvidence {
                exit_code: None,
                signal: None,
                reason: error.to_string(),
                process_exit_confirmed: !launched,
                stdout_bytes: 0,
                stderr_bytes: 0,
                notification_overflow: 0,
                log_error: None,
            }
        };
        if !launched {
            journal.record_stop(&stop)?;
        }
        let outcome = ExecutorOutcome {
            execution_id: journal.execution_id()?,
            upstream_session_id: None,
            exit_code: stop.exit_code,
            completion_reason: if stop.process_exit_confirmed && *shutdown_rx.borrow() {
                "CANCELLED"
            } else if stop.process_exit_confirmed {
                "WORKER_PREPARATION_FAILED"
            } else {
                "RECOVERY_REQUIRED"
            }
            .into(),
            raw_event_digest: String::new(),
            transcript_completeness: "INCOMPLETE".into(),
            final_artifact: None,
            error_class: Some(error.to_string()),
        };
        let receipt = WorkerResult {
            event_id: format!("{}:result", envelope.operation_id),
            project_id: envelope.project_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            lease_id: envelope.lease_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            evidence: bound_stop_evidence(
                json!({"process_exit_confirmed":stop.process_exit_confirmed,"stop":stop,"journal":journal.directory}),
                &envelope,
                &journal,
                &outcome.execution_id,
            )?,
            outcome,
        };
        durable_json(&journal.path("result.json"), &receipt)?;
        durable_json(
            &journal.path("lease-retention.json"),
            &json!({"attempt_id":envelope.attempt_id,
            "generation":envelope.generation,"state":"AWAITING_CONTROLLER_SETTLEMENT",
            "deadline_at":envelope.deadline_at}),
        )?;
        let shutting_down = *shutdown_rx.borrow();
        tokio::spawn(restore_lease(client.clone(), envelope.clone(), shutdown_rx));
        if !stop.process_exit_confirmed {
            let _ = queue_event(
                client,
                &journal,
                &event(
                    &envelope,
                    "RECOVERY_REQUIRED",
                    json!({"reason":error.to_string()}),
                    "worker-error-recovery",
                ),
            )
            .await;
        }
        if !shutting_down {
            retain_deferred_starting_failure(replay_events(client, &journal).await)?;
            let _ = deliver_result(config, client, &envelope, &journal, &receipt).await;
        }
    }
    result
}

/// Single-attempt embedding entrypoint; standalone run supplies a shared shutdown signal.
pub async fn execute(
    config: &WorkerConfig,
    client: &ControlClient,
    envelope: ExecutionEnvelope,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let deadline = remaining(&envelope.deadline_at).unwrap_or(Duration::ZERO);
    let attempt_id = envelope.attempt_id.clone();
    let signal = tokio::spawn(async move {
        tokio::select! { _=wait_shutdown_signal()=>{}, _=tokio::time::sleep(deadline)=>{} }
        let _ = shutdown_tx.send(true);
    });
    let result = execute_controlled(config, client, envelope, shutdown_rx).await;
    let retained = Journal::new(&config.data_root.join("attempts"), &attempt_id)?
        .path("lease-retention.json")
        .exists();
    if !retained {
        signal.abort();
        let _ = signal.await;
    }
    result
}

async fn hash_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut digest = Sha256::new();
    let mut file = tokio::fs::File::open(path).await?;
    let mut bytes = vec![0; 16384];
    loop {
        let count = file.read(&mut bytes).await?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn preparation_ms(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

async fn persist_preparation_timing(
    journal: &Journal,
    timing: &mut Option<Value>,
    started: std::time::Instant,
    receipt: &forgeflow_runtime::LaunchReceipt,
) {
    let Some(mut timing) = timing.take() else {
        return;
    };
    timing["launch_observed_ms"] = json!(preparation_ms(started));
    timing["runtime_launched_at"] = json!(receipt.launched_at);
    let path = journal.path("preparation-timing.json");
    let persistence = tokio::task::spawn_blocking(move || durable_json(&path, &timing))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
    if let Err(error) = persistence {
        tracing::error!(error=%error,"preparation timing persistence failed");
    }
}

fn persist_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = publish_synced_bytes(path, bytes)?;
    sync_preparation_directory(parent)
}

/// Sync complete file bytes and atomically publish them. The caller must sync
/// the returned parent before treating this publication as durable.
fn publish_synced_bytes(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    let parent = path
        .parent()
        .context("artifact parent missing")?
        .to_path_buf();
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    Ok(parent)
}

fn sync_preparation_directory(parent: PathBuf) -> Result<()> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

async fn persist_preparation(files: Vec<(PathBuf, Vec<u8>)>) -> Result<()> {
    persist_preparation_with_directory_sync(files, sync_preparation_directory).await
}

async fn persist_preparation_with_directory_sync<F>(
    files: Vec<(PathBuf, Vec<u8>)>,
    sync_directory: F,
) -> Result<()>
where
    F: Fn(PathBuf) -> Result<()> + Clone + Send + 'static,
{
    let mut writes = tokio::task::JoinSet::new();
    for (path, bytes) in files {
        writes.spawn_blocking(move || publish_synced_bytes(&path, &bytes));
    }
    let mut failure = None;
    let mut parents = std::collections::BTreeSet::new();
    while let Some(result) = writes.join_next().await {
        let result = result
            .map_err(anyhow::Error::from)
            .and_then(|result| result);
        match result {
            Ok(parent) => {
                parents.insert(parent);
            }
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    // A single directory checkpoint covers every rename in that parent. Drain
    // it even when another file failed: successful publications must be durable
    // before either a physical launch or a failed preparation acknowledgement.
    let mut checkpoints = tokio::task::JoinSet::new();
    for parent in parents {
        let sync_directory = sync_directory.clone();
        checkpoints.spawn_blocking(move || sync_directory(parent));
    }
    while let Some(result) = checkpoints.join_next().await {
        let result = result
            .map_err(anyhow::Error::from)
            .and_then(|result| result);
        if let Err(error) = result {
            failure.get_or_insert(error);
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
enum NativeLine {
    Buffered(Vec<u8>),
    Spooled {
        path: PathBuf,
        raw_bytes: u64,
        raw_sha256: String,
        prefix: Vec<u8>,
    },
}
async fn read_native_line(
    reader: &mut BufReader<tokio::fs::File>,
    journal: &Journal,
    index: u64,
) -> Result<Option<NativeLine>> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;
    let mut bytes = Vec::new();
    let mut output: Option<tokio::fs::File> = None;
    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut prefix = Vec::new();
    let path = journal.path(&format!("native-line-{index:020}.spool"));
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map(|n| n + 1).unwrap_or(available.len());
        let chunk = &available[..take];
        digest.update(chunk);
        count += take as u64;
        if prefix.len() < 64 {
            prefix.extend_from_slice(&chunk[..chunk.len().min(64 - prefix.len())]);
        }
        if output.is_none() && bytes.len() + take > 1024 * 1024 {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .await?;
            file.write_all(&bytes).await?;
            bytes.clear();
            output = Some(file);
        }
        if let Some(file) = &mut output {
            file.write_all(chunk).await?;
        } else {
            bytes.extend_from_slice(chunk);
        }
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    if count == 0 {
        return Ok(None);
    }
    if let Some(mut file) = output {
        file.flush().await?;
        file.sync_all().await?;
        Ok(Some(NativeLine::Spooled {
            path,
            raw_bytes: count,
            raw_sha256: format!("{:x}", digest.finalize()),
            prefix,
        }))
    } else {
        Ok(Some(NativeLine::Buffered(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    #[test]
    fn no_launch_failure_denies_partial_and_symlinked_launch_facts() {
        use std::os::unix::fs::symlink;
        for name in [
            "launch.lock",
            "launch-intent.json",
            "launch-receipt.json",
            "cgroup-membership.json",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let journal = Journal::new(temp.path(), "unlaunched").unwrap();
            std::fs::create_dir_all(&journal.directory).unwrap();
            assert!(!no_launch_failure_has_launch_facts(&journal).unwrap());
            // Even an incomplete write or a dangling symlink is uncertainty,
            // never evidence that a prior launch can safely be ignored.
            std::fs::write(journal.path(name), []).unwrap();
            assert!(no_launch_failure_has_launch_facts(&journal).unwrap());
            std::fs::remove_file(journal.path(name)).unwrap();
            symlink(temp.path().join("absent"), journal.path(name)).unwrap();
            assert!(no_launch_failure_has_launch_facts(&journal).unwrap());
        }
    }

    #[test]
    fn no_launch_failure_preserves_original_bytes_and_rejects_drift_before_cgroup() {
        let temp = tempfile::tempdir().unwrap();
        let config = liveness_config("http://127.0.0.1:1", temp.path());
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        attempt_preparation::prepare(&config, &envelope, &journal, true).unwrap();
        let stop = StopEvidence {
            exit_code: None,
            signal: None,
            reason: "actual preparation rejected".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        journal.record_stop(&stop).unwrap();
        let original = WorkerResult {
            event_id: format!("{}:result", envelope.operation_id),
            project_id: envelope.project_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            lease_id: envelope.lease_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            evidence: json!({"process_exit_confirmed":true,"stop":stop}),
            outcome: ExecutorOutcome {
                execution_id: journal.execution_id().unwrap(),
                upstream_session_id: None,
                exit_code: None,
                completion_reason: "WORKER_PREPARATION_FAILED".into(),
                raw_event_digest: String::new(),
                transcript_completeness: "INCOMPLETE".into(),
                final_artifact: None,
                error_class: Some("preparation rejected".into()),
            },
        };
        durable_json(&journal.path("result.json"), &original).unwrap();
        let failure_bytes = std::fs::read(journal.path("result.json")).unwrap();
        let stop_bytes = std::fs::read(journal.path("stop.json")).unwrap();
        // Legacy profiles retain their existing failure publication behavior.
        durable_json(
            &journal.path("execution-bindings.json"),
            &json!({"resource_profile":{}}),
        )
        .unwrap();
        assert!(
            no_launch_physical_failure_result(&config, &envelope, &journal, &original)
                .unwrap()
                .is_none()
        );
        durable_json(
            &journal.path("execution-bindings.json"),
            &json!({"resource_profile":{"physical_limits":{"required":true}}}),
        )
        .unwrap();
        let mut changed = original.clone();
        changed.generation += 1;
        assert!(no_launch_physical_failure_result(&config, &envelope, &journal, &changed).is_err());
        let mut changed = original.clone();
        changed.outcome.execution_id = uuid::Uuid::new_v4().to_string();
        assert!(no_launch_physical_failure_result(&config, &envelope, &journal, &changed).is_err());
        assert_eq!(
            std::fs::read(journal.path("result.json")).unwrap(),
            failure_bytes
        );
        assert_eq!(
            std::fs::read(journal.path("stop.json")).unwrap(),
            stop_bytes
        );
        assert!(!journal.path("cgroup-fence.json").exists());
        assert!(!journal.path("no-launch-failure-settlement.lock").exists());
        assert!(!journal.path("launch.lock").exists());
    }

    struct FakeControl {
        url: String,
        requests: Arc<Mutex<Vec<(String, tokio::time::Instant, Value)>>>,
        payloads: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
        renew_delay_ms: Arc<AtomicU64>,
        event_delay_ms: Arc<AtomicU64>,
        reject_result: Arc<AtomicBool>,
        result_reply: Arc<Mutex<Value>>,
        attempt_reply: Arc<Mutex<Option<Value>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for FakeControl {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl FakeControl {
        async fn start() -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let payloads = Arc::new(Mutex::new(Vec::new()));
            let renew_delay_ms = Arc::new(AtomicU64::new(0));
            let event_delay_ms = Arc::new(AtomicU64::new(7000));
            let reject_result = Arc::new(AtomicBool::new(false));
            let result_reply = Arc::new(Mutex::new(Value::Null));
            let attempt_reply = Arc::new(Mutex::new(None));
            let recorded = requests.clone();
            let raw_recorded = payloads.clone();
            let delay = renew_delay_ms.clone();
            let event_delay = event_delay_ms.clone();
            let reject = reject_result.clone();
            let reply = result_reply.clone();
            let attempt = attempt_reply.clone();
            let task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted=listener.accept()=>{
                            let (mut socket, _) = accepted.unwrap();
                            let recorded = recorded.clone(); let raw_recorded=raw_recorded.clone(); let delay = delay.clone(); let event_delay = event_delay.clone(); let reject = reject.clone(); let reply = reply.clone(); let attempt = attempt.clone();
                            connections.spawn(async move {
                                let mut bytes = Vec::new(); let mut chunk = [0; 4096];
                                let header_end = loop {
                                    let count = socket.read(&mut chunk).await.unwrap();
                                    if count == 0 { return; }
                                    bytes.extend_from_slice(&chunk[..count]);
                                    if let Some(at) = bytes.windows(4).position(|b| b == b"\r\n\r\n") { break at + 4; }
                                    assert!(bytes.len() < 65536);
                                };
                                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                                let path = headers.lines().next().unwrap().split_whitespace().nth(1).unwrap().split('?').next().unwrap().to_owned();
                                let length = headers.lines().find_map(|line| {
                                    let (key, value) = line.split_once(':')?;
                                    key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                                }).unwrap_or(0);
                                while bytes.len() < header_end + length {
                                    let count = socket.read(&mut chunk).await.unwrap();
                                    if count == 0 { return; }
                                    bytes.extend_from_slice(&chunk[..count]);
                                }
                                let body = serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap_or(Value::Null);
                                raw_recorded.lock().unwrap().push((path.clone(),bytes[header_end..header_end+length].to_vec()));
                                recorded.lock().unwrap().push((path.clone(), tokio::time::Instant::now(), body));
                                let mut status = "200 OK";
                                let response = if path.ends_with("/control") {
                                    json!({"valid":true,"cancel_requested":false,"lease_expires_at":(chrono::Utc::now()+chrono::Duration::seconds(30)).to_rfc3339()})
                                } else if path.contains("/attempts/") && path.ends_with("/heartbeat") {
                                    tokio::time::sleep(Duration::from_millis(delay.load(Ordering::SeqCst))).await;
                                    Value::Null
                                } else if path.ends_with("/worker-events") {
                                    tokio::time::sleep(Duration::from_millis(event_delay.load(Ordering::SeqCst))).await;
                                    Value::Null
                                } else if path.ends_with("/claim") {
                                    tokio::time::sleep(Duration::from_secs(7)).await;
                                    json!({"envelope":null})
                                } else if path.ends_with("/attempt-live") {
                                    let custom = attempt.lock().unwrap().clone();
                                    if let Some(reply) = custom { reply } else {
                                        tokio::time::sleep(Duration::from_secs(7)).await;
                                        json!({"project_id":"project-live","task_id":"task-live","task_revision":1,"attempt_id":"attempt-live","lease_id":"lease-live","generation":1,"worker_id":"worker-live","operation_id":"operation-live","base_sha":"a".repeat(40),"state":"VERIFYING","revision":3,"created_at":chrono::Utc::now(),"terminal_at":null,"result":null})
                                    }
                                } else if (path.ends_with("/execution-result") || path.ends_with("/handoff-result")) && reject.swap(false, Ordering::SeqCst) {
                                    status = "503 Service Unavailable"; Value::Null
                                } else if path.ends_with("/execution-result") || path.ends_with("/handoff-result") {
                                    reply.lock().unwrap().clone()
                                } else { Value::Null };
                                let body = serde_json::to_vec(&response).unwrap();
                                let header = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                                let _ = socket.write_all(header.as_bytes()).await;
                                let _ = socket.write_all(&body).await;
                            });
                        }
                        _=connections.join_next(), if !connections.is_empty()=>{}
                    }
                }
            });
            Self {
                url,
                requests,
                payloads,
                renew_delay_ms,
                event_delay_ms,
                reject_result,
                result_reply,
                attempt_reply,
                task,
            }
        }
        fn count(&self, suffix: &str) -> usize {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(path, _, _)| path.ends_with(suffix))
                .count()
        }
    }
    pub(crate) fn liveness_envelope() -> ExecutionEnvelope {
        let now = chrono::Utc::now();
        serde_json::from_value(json!({
            "schema_version":"forgeflow.execution.v1","operation_id":"operation-live","project_id":"project-live","task_id":"task-live","task_revision":1,
            "attempt_id":"attempt-live","lease_id":"lease-live","generation":1,"worker_id":"worker-live","workspace_root":"/tmp/worker-live.git","base_sha":"a".repeat(40),
            "context_manifest":{"artifact_id":"context-live","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},
            "write_set":["result.txt"],"prompt_artifact":{"artifact_id":"prompt-live","sha256":"c".repeat(64)},"model_route_id":"route-live","executor_profile_id":"profile-live","resource_profile_id":"resource-live","verification_plan_id":"verify-live",
            "allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS","REQUEST_APPROVED_MODEL"],"issued_at":now.to_rfc3339(),"expires_at":(now+chrono::Duration::seconds(30)).to_rfc3339(),"deadline_at":(now+chrono::Duration::minutes(5)).to_rfc3339(),
            "artifact_prefix":"/tmp/artifacts/live","secret_refs":[],"idempotency_key":"key-live","trace_id":"trace-live",
            "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},
            "session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null
        })).unwrap()
    }
    pub(crate) fn liveness_config(url: &str, root: &Path) -> WorkerConfig {
        WorkerConfig {
            control_url: url.into(),
            worker_id: "worker-live".into(),
            project_id: "project-live".into(),
            data_root: root.into(),
            profile: HeadlessProfile {
                id: "profile-live".into(),
                program: "/bin/true".into(),
                prefix_args: vec![],
                home: root.join("home"),
                profile_name: "live".into(),
                artifact_pins: vec![],
                resume_verified: false,
                model_route_id: "route-live".into(),
                gateway_coverage_verified: false,
            }
            .into(),
            model_route_id: "route-live".into(),
            secret_files: BTreeMap::new(),
            poll_seconds: 1,
            max_log_bytes: 65536,
            max_active_attempts: 4,
            controlled_workload_programs: BTreeMap::new(),
            sandbox: None,
            strict_resource_handoff: false,
            managed_dsh: None,
            cgroup_delegation: None,
        }
    }

    fn starting_checkpoint(
        journal: &Journal,
        envelope: &ExecutionEnvelope,
    ) -> DeferredStartingEvent {
        durable_json(&journal.path("envelope.json"), envelope).unwrap();
        let workspace = journal.directory.join("private-worktree");
        let pending = DeferredStartingEvent::new(event(
            envelope,
            "STARTING",
            json!({"workspace":workspace,"base_sha":envelope.base_sha,
                "isolation":"LOCAL_TRUSTED_WORKTREE"}),
            "starting",
        ));
        durable_json(&journal.path("worktree.json"), &json!({
            "project_id":envelope.project_id,"repository":envelope.workspace_root,
            "state":"PREPARED","worktree":{"absolute_path":workspace,"base_sha":envelope.base_sha},
            "deferred_starting":pending,
        })).unwrap();
        pending
    }

    #[tokio::test]
    async fn deferred_starting_recovers_exact_original_event_before_launch_or_failed_preparation() {
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        let pending = starting_checkpoint(&journal, &envelope);
        let expected_file = pending.outbox_file.clone();
        let expected_bytes = serde_json::to_vec(&pending.event).unwrap();
        assert!(
            !journal.path(&expected_file).exists(),
            "worktree checkpoint must not allocate the separate telemetry inode before launch"
        );
        assert!(!journal.path("launch.lock").exists());
        drop(pending); // The crash loses all in-memory pending state.
        let recovered = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        assert_eq!(
            ensure_deferred_starting(&recovered, None, true)
                .await
                .unwrap(),
            Some(expected_file.clone())
        );
        assert_eq!(
            std::fs::read(recovered.path(&expected_file)).unwrap(),
            expected_bytes
        );
        assert!(
            !recovered.path("launch.lock").exists(),
            "preparation failure recovery must not synthesize launch authority"
        );

        // If the worktree checkpoint itself failed, the failure wrapper still
        // owns the originally allocated event and can preserve it before ACK.
        let other = Journal::new(temp.path(), "failed-worktree-checkpoint").unwrap();
        let mut other_envelope = envelope.clone();
        other_envelope.attempt_id = "failed-worktree-checkpoint".into();
        let pending = starting_checkpoint(&other, &other_envelope);
        std::fs::remove_file(other.path("worktree.json")).unwrap();
        ensure_deferred_starting(&other, Some(&pending), true)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(other.path(&pending.outbox_file)).unwrap(),
            serde_json::to_vec(&pending.event).unwrap()
        );
    }

    #[tokio::test]
    async fn deferred_starting_lost_http_ack_replays_identical_bytes_before_clock_regressed_running()
     {
        let server = FakeControl::start().await;
        // A 7 s ACK is slow but valid under the 10 s client bound. Exercise
        // an actual lost ACK here, rather than cancelling valid work at 2 s.
        server.event_delay_ms.store(11_000, Ordering::SeqCst);
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        let pending = starting_checkpoint(&journal, &envelope);
        let running = event(
            &envelope,
            "RUNNING",
            json!({"fixture":"later physical receipt"}),
            "running",
        );
        let regressed = journal.path(&format!(
            "event-{:020}-{}.json",
            1,
            sha256(running.event_id.as_bytes())
        ));
        durable_json(&regressed, &running).unwrap();
        assert!(replay_events(&client, &journal).await.is_err());
        assert!(journal.path(&pending.outbox_file).exists());
        assert!(!journal.path("starting-event-ack.json").exists());
        server.event_delay_ms.store(0, Ordering::SeqCst);
        replay_events(&client, &journal).await.unwrap();
        let published: Vec<_> = server
            .payloads
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.ends_with("/worker-events"))
            .map(|(_, bytes)| bytes.clone())
            .collect();
        assert_eq!(published.len(), 3);
        assert_eq!(
            published[0], published[1],
            "lost ACK changed original STARTING bytes"
        );
        assert_eq!(published[0], serde_json::to_vec(&pending.event).unwrap());
        assert_eq!(published[2], serde_json::to_vec(&running).unwrap());
        assert_eq!(
            std::fs::read(journal.path("starting-event-ack.json")).unwrap(),
            published[0]
        );
        assert!(!journal.path(&pending.outbox_file).exists());
        replay_events(&client, &journal).await.unwrap();
        assert_eq!(
            server.count("/worker-events"),
            3,
            "durable acknowledgement must not recreate the STARTING outbox"
        );
    }

    #[tokio::test]
    async fn bounded_telemetry_retains_backpressure_and_late_ack_without_starving_control() {
        let server = FakeControl::start().await;
        server.event_delay_ms.store(2_500, Ordering::SeqCst);
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let mut journals = Vec::new();
        let mut replay = tokio::task::JoinSet::new();
        for number in 0..8 {
            let journal = Journal::new(temp.path(), &format!("telemetry-{number}")).unwrap();
            let value = event(
                &envelope,
                "LOG_SEGMENT",
                json!({"offset":number}),
                &format!("telemetry-{number}"),
            );
            queue_event(&client, &journal, &value).await.unwrap();
            journals.push(journal);
        }
        for journal in journals.iter().cloned() {
            let client = client.clone();
            replay.spawn(async move { replay_events(&client, &journal).await });
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while server.count("/worker-events") < 4 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            server.count("/worker-events"),
            4,
            "all authors must share the telemetry bound"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            client.renew(&envelope).await.unwrap();
            assert!(client.control(&envelope).await.unwrap().valid);
        })
        .await
        .expect("telemetry must not occupy the lease/control lane");
        let mut acknowledged = 0;
        let mut deferred = 0;
        while let Some(result) = replay.join_next().await {
            if result.unwrap().is_ok() {
                acknowledged += 1;
            } else {
                deferred += 1;
            }
        }
        assert_eq!(
            (acknowledged, deferred),
            (4, 4),
            "a valid ACK after 2 s must settle once, while busy authors retain events"
        );
        server.event_delay_ms.store(0, Ordering::SeqCst);
        for journal in &journals {
            replay_events(&client, journal).await.unwrap();
            assert!(
                !std::fs::read_dir(&journal.directory)
                    .unwrap()
                    .any(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with("event-"))
            );
        }
        assert_eq!(
            server.count("/worker-events"),
            8,
            "backpressure must retain every event without duplicating late acknowledgements"
        );
    }

    #[tokio::test]
    async fn deferred_starting_partial_directory_failures_retry_original_publication_and_ack() {
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        let pending = starting_checkpoint(&journal, &envelope);
        let bytes = serde_json::to_vec(&pending.event).unwrap();
        let outbox = journal.path(&pending.outbox_file);
        let observed = outbox.clone();
        let expected = bytes.clone();
        let error = ensure_deferred_starting_with_directory_sync(&journal, None, true, move |_| {
            assert_eq!(
                std::fs::read(&observed).unwrap(),
                expected,
                "inject only after full file fsync and atomic rename"
            );
            bail!("injected STARTING directory checkpoint failure")
        })
        .await
        .unwrap_err();
        assert!(
            retain_deferred_starting_failure(Err(error)).is_err(),
            "local durability failure must not be suppressed as network refusal"
        );
        let checkpoints = Arc::new(AtomicU64::new(0));
        let counted = checkpoints.clone();
        ensure_deferred_starting_with_directory_sync(
            &journal,
            Some(&pending),
            true,
            move |parent| {
                counted.fetch_add(1, Ordering::SeqCst);
                sync_preparation_directory(parent)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            checkpoints.load(Ordering::SeqCst),
            1,
            "visible publication must retry its failed directory barrier"
        );
        let marker = journal.path("starting-event-ack.json");
        let observed = marker.clone();
        let expected = bytes.clone();
        let error = acknowledge_deferred_starting_with_directory_sync(
            &journal,
            outbox.clone(),
            move |_| {
                assert_eq!(std::fs::read(&observed).unwrap(), expected);
                bail!("injected ACK rename directory checkpoint failure")
            },
        )
        .await
        .unwrap_err();
        assert!(retain_deferred_starting_failure(Err(error)).is_err());
        let ack_checkpoints = Arc::new(AtomicU64::new(0));
        let counted = ack_checkpoints.clone();
        ensure_deferred_starting_with_directory_sync(&journal, None, true, move |parent| {
            counted.fetch_add(1, Ordering::SeqCst);
            sync_preparation_directory(parent)
        })
        .await
        .unwrap();
        assert_eq!(
            ack_checkpoints.load(Ordering::SeqCst),
            1,
            "visible ACK marker must retry its failed directory barrier before result delivery"
        );
        assert_eq!(std::fs::read(&marker).unwrap(), bytes);
        assert!(!outbox.exists());
        // Model the crash visibility where the uncheckpointed rename is lost.
        // The mandatory checkpoint still reconstructs the same idempotent event.
        std::fs::remove_file(marker).unwrap();
        ensure_deferred_starting(&journal, None, true)
            .await
            .unwrap();
        assert_eq!(std::fs::read(outbox).unwrap(), bytes);
        assert!(retain_deferred_starting_failure(Err(anyhow::anyhow!("HTTP refused"))).is_ok());
    }

    #[tokio::test]
    async fn deferred_starting_scope_drift_and_conflicting_ack_block_result_http() {
        let server = FakeControl::start().await;
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        let pending = starting_checkpoint(&journal, &envelope);
        let mut invalid = pending.clone();
        invalid.outbox_file = format!("../{}", pending.outbox_file);
        assert!(
            ensure_deferred_starting(&journal, Some(&invalid), true)
                .await
                .is_err()
        );
        invalid = pending.clone();
        invalid.event.generation += 1;
        assert!(
            ensure_deferred_starting(&journal, Some(&invalid), true)
                .await
                .is_err()
        );
        durable_json(&journal.path("starting-event-ack.json"), &invalid.event).unwrap();
        let result = WorkerResult {
            event_id: format!("{}:result", envelope.operation_id),
            project_id: envelope.project_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            lease_id: envelope.lease_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            evidence: json!({"process_exit_confirmed":true}),
            outcome: ExecutorOutcome {
                execution_id: journal.execution_id().unwrap(),
                upstream_session_id: None,
                exit_code: Some(0),
                completion_reason: "EXECUTOR_COMPLETED".into(),
                raw_event_digest: String::new(),
                transcript_completeness: "TEST_ONLY".into(),
                final_artifact: None,
                error_class: None,
            },
        };
        let config = liveness_config(&server.url, temp.path());
        assert!(
            deliver_result(&config, &client, &envelope, &journal, &result)
                .await
                .is_err()
        );
        assert_eq!(server.count("/execution-result"), 0);
        assert_eq!(server.count("/handoff-result"), 0);
        assert!(!journal.path("result-ack.json").exists());
    }

    #[test]
    fn maintenance_cursor_reaches_failed_low_ids_and_later_attempts() {
        let ids = (0..11).map(|n| format!("attempt-{n:02}")).collect();
        let mut cursor = None;
        let mut observed = std::collections::BTreeSet::new();
        for _ in 0..3 {
            observed.extend(fair_batch(&ids, &mut cursor, 4));
        }
        assert_eq!(observed, ids);
        assert_eq!(fair_batch(&ids, &mut cursor, 1), vec!["attempt-01"]);
    }

    #[tokio::test]
    async fn terminal_dispatch_requires_scoped_identity_actual_stop_and_durable_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let config = liveness_config("http://127.0.0.1:1", temp.path());
        let envelope = liveness_envelope();
        let journal =
            Journal::new(&config.data_root.join("attempts"), &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let mut client =
            ControlClient::new(&config.control_url, "private-test-token".into()).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        client.settlements = Some(tx);
        let mut fact = json!({
            "schema_version":"forgeflow.worker_dispatch.v1","kind":"TERMINAL","project_seq":7,
            "project_id":envelope.project_id,"worker_id":envelope.worker_id,"attempt_id":envelope.attempt_id,
            "lease_id":envelope.lease_id,"generation":envelope.generation,"state":"CANCELLED",
            "task_id":envelope.task_id,"task_revision":envelope.task_revision,
            "operation_id":envelope.operation_id,"base_sha":envelope.base_sha,
        });
        let frame = |fact: &Value| {
            format!("id: project-live:worker-live:7\nevent: worker-dispatch\ndata: {fact}\n\n")
                .into_bytes()
        };
        let mut after = 0;
        consume_dispatch_frame(&config, &client, &frame(&fact), &mut after)
            .await
            .unwrap();
        assert!(
            rx.try_recv().is_err(),
            "controller terminal alone cannot release a live/unsettled local author"
        );
        assert!(!journal.path("controller-terminal.json").exists());
        journal
            .record_stop(&StopEvidence {
                exit_code: Some(143),
                signal: None,
                reason: "fixture-confirmed-stop".into(),
                process_exit_confirmed: true,
                stdout_bytes: 0,
                stderr_bytes: 0,
                notification_overflow: 0,
                log_error: None,
            })
            .unwrap();
        fact["generation"] = json!(2);
        assert!(
            consume_dispatch_frame(&config, &client, &frame(&fact), &mut after)
                .await
                .is_err()
        );
        assert!(rx.try_recv().is_err());
        fact["generation"] = json!(1);
        let wrong_scope = frame(&fact).into_iter().collect::<Vec<_>>();
        let wrong_scope = String::from_utf8(wrong_scope)
            .unwrap()
            .replace("id: project-live:worker-live:7", "id: other:worker-live:7");
        assert!(
            consume_dispatch_frame(&config, &client, wrong_scope.as_bytes(), &mut after)
                .await
                .is_err()
        );
        consume_dispatch_frame(&config, &client, &frame(&fact), &mut after)
            .await
            .unwrap();
        let notice = rx.try_recv().unwrap();
        assert!(notice.terminal_confirmed && !notice.wake_only);
        assert_eq!(notice.attempt_id, envelope.attempt_id);
        let original = std::fs::read(journal.path("controller-terminal.json")).unwrap();
        let receipt: Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(receipt["authority"], fact);
        assert_eq!(receipt["transport"], "WORKER_DISPATCH_SSE");
        consume_dispatch_frame(&config, &client, &frame(&fact), &mut after)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(journal.path("controller-terminal.json")).unwrap(),
            original,
            "replay must not backfill or rewrite the first real receive time"
        );
        assert_eq!(
            dispatch_scope_component("project:中文\n"),
            "project%3A%E4%B8%AD%E6%96%87%0A"
        );
    }

    #[tokio::test]
    async fn terminal_dispatch_concurrent_observers_preserve_first_durable_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let config = liveness_config("http://127.0.0.1:1", temp.path());
        let envelope = liveness_envelope();
        let journal =
            Journal::new(&config.data_root.join("attempts"), &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        journal
            .record_stop(&StopEvidence {
                exit_code: Some(0),
                signal: None,
                reason: "fixture-confirmed-stop".into(),
                process_exit_confirmed: true,
                stdout_bytes: 0,
                stderr_bytes: 0,
                notification_overflow: 0,
                log_error: None,
            })
            .unwrap();
        let authority = json!({
            "project_id":envelope.project_id,"task_id":envelope.task_id,"task_revision":envelope.task_revision,
            "attempt_id":envelope.attempt_id,"lease_id":envelope.lease_id,"generation":envelope.generation,
            "worker_id":envelope.worker_id,"operation_id":envelope.operation_id,"base_sha":envelope.base_sha,
            "state":"CANCELLED",
        });
        let client = ControlClient::new(&config.control_url, "private-test-token".into()).unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut observations = tokio::task::JoinSet::new();
        for transport in ["WORKER_DISPATCH_SSE", "ATTEMPT_HTTP_FALLBACK"] {
            let (client, envelope, journal, authority, barrier) = (
                client.clone(),
                envelope.clone(),
                journal.clone(),
                authority.clone(),
                barrier.clone(),
            );
            observations.spawn(async move {
                barrier.wait().await;
                let received_at = chrono::Utc::now().to_rfc3339();
                assert!(
                    publish_terminal_observation(
                        &client,
                        &envelope,
                        &journal,
                        authority,
                        transport,
                        &received_at
                    )
                    .await
                    .unwrap()
                );
                (transport, received_at)
            });
        }
        barrier.wait().await;
        let mut actual = Vec::new();
        while let Some(result) = observations.join_next().await {
            actual.push(result.unwrap());
        }
        let original = std::fs::read(journal.path("controller-terminal.json")).unwrap();
        let saved: Value = serde_json::from_slice(&original).unwrap();
        assert!(
            actual
                .iter()
                .any(|(transport, time)| saved["transport"] == *transport
                    && saved["received_at"] == *time)
        );
        assert!(terminal_identity_matches(&saved["authority"], &envelope));
        // A later current observation must preserve the exact first publication,
        // including its genuinely observed timestamp and transport identity.
        assert!(
            publish_terminal_observation(
                &client,
                &envelope,
                &journal,
                authority,
                "LATER_OBSERVATION",
                &chrono::Utc::now().to_rfc3339()
            )
            .await
            .unwrap()
        );
        assert_eq!(
            std::fs::read(journal.path("controller-terminal.json")).unwrap(),
            original
        );
        assert!(
            !std::fs::read_dir(&journal.directory)
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".authority-"))
        );
    }

    #[tokio::test]
    async fn terminal_dispatch_http_refill_precedes_slow_late_log_replay() {
        let server = FakeControl::start().await;
        let temp = tempfile::tempdir().unwrap();
        let config = liveness_config(&server.url, temp.path());
        let envelope = liveness_envelope();
        let journal =
            Journal::new(&config.data_root.join("attempts"), &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        journal
            .record_stop(&StopEvidence {
                exit_code: Some(0),
                signal: None,
                reason: "fixture-confirmed-stop".into(),
                process_exit_confirmed: true,
                stdout_bytes: 0,
                stderr_bytes: 0,
                notification_overflow: 0,
                log_error: None,
            })
            .unwrap();
        *server.attempt_reply.lock().unwrap() = Some(json!({
            "project_id":envelope.project_id,"task_id":envelope.task_id,"task_revision":envelope.task_revision,
            "attempt_id":envelope.attempt_id,"lease_id":envelope.lease_id,"generation":envelope.generation,
            "worker_id":envelope.worker_id,"operation_id":envelope.operation_id,"base_sha":envelope.base_sha,
            "state":"CANCELLED","revision":4,"created_at":chrono::Utc::now(),
            "terminal_at":chrono::Utc::now(),"result":null,
        }));
        let mut client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        client.settlements = Some(tx);
        queue_event(
            &client,
            &journal,
            &event(&envelope, "LOG_SEGMENT", json!({"offset":0}), "late-log"),
        )
        .await
        .unwrap();
        let attempt = envelope.attempt_id.clone();
        let job =
            tokio::spawn(async move { maintain_attempt(&config, &client, &attempt, false).await });
        let notice = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(notice.terminal_confirmed);
        assert!(
            journal.path("controller-terminal.json").exists(),
            "actual observation must be durable before refill"
        );
        assert!(
            !job.is_finished(),
            "refill still waited for the deliberately delayed late event transport"
        );
        let outcome = job.await.unwrap().unwrap();
        assert!(outcome.release);
        assert_eq!(server.count("/worker-events"), 1);
    }

    #[tokio::test]
    async fn strict_handoff_retries_keep_callback_bytes_and_frozen_endpoint() {
        let server = FakeControl::start().await;
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let mut config = liveness_config(&server.url, temp.path());
        config.strict_resource_handoff = true;
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        result_delivery_policy(&config, &envelope, &journal, true).unwrap();
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "cancelled".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        let result = reconciled_author_stop(&envelope, &stop, &journal).unwrap();
        durable_json(&journal.path("result.json"), &result).unwrap();
        let original = std::fs::read(journal.path("result.json")).unwrap();
        server.reject_result.store(true, Ordering::SeqCst);
        assert!(
            deliver_result(&config, &client, &envelope, &journal, &result)
                .await
                .is_err()
        );
        assert!(!journal.path("result-ack.json").exists());
        config.strict_resource_handoff = false;
        deliver_result(&config, &client, &envelope, &journal, &result)
            .await
            .unwrap();
        assert_eq!(server.count("/handoff-result"), 2);
        assert_eq!(server.count("/execution-result"), 0);
        let requests = server.payloads.lock().unwrap();
        let callbacks: Vec<_> = requests
            .iter()
            .filter(|(path, _)| path.ends_with("/handoff-result"))
            .collect();
        assert!(callbacks.iter().all(|(_, bytes)| *bytes == original));
        assert_eq!(
            std::fs::read(journal.path("result.json")).unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn terminal_ack_wakes_refill_only_after_durable_identity_bound_settlement() {
        let server = FakeControl::start().await;
        let mut client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        client.settlements = Some(tx);
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let mut config = liveness_config(&server.url, temp.path());
        config.strict_resource_handoff = true;
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        result_delivery_policy(&config, &envelope, &journal, true).unwrap();
        let stop = StopEvidence {
            exit_code: Some(143),
            signal: None,
            reason: "cancelled".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        journal.record_stop(&stop).unwrap();
        let result = reconciled_author_stop(&envelope, &stop, &journal).unwrap();
        durable_json(&journal.path("result.json"), &result).unwrap();
        let terminal = json!({
            "project_id":envelope.project_id,"task_id":envelope.task_id,
            "task_revision":envelope.task_revision,"attempt_id":envelope.attempt_id,
            "lease_id":envelope.lease_id,"generation":envelope.generation,
            "worker_id":envelope.worker_id,"operation_id":envelope.operation_id,
            "base_sha":envelope.base_sha,"state":"CANCELLED","revision":4,
            "created_at":chrono::Utc::now(),"terminal_at":chrono::Utc::now(),"result":result,
        });
        *server.result_reply.lock().unwrap() = json!({"data":{"terminal":terminal}});
        server.reject_result.store(true, Ordering::SeqCst);
        assert!(
            deliver_result(&config, &client, &envelope, &journal, &result)
                .await
                .is_err()
        );
        assert!(rx.try_recv().is_err());
        assert!(!journal.path("result-ack.json").exists());
        server.result_reply.lock().unwrap()["data"]["terminal"]["generation"] =
            json!(envelope.generation + 1);
        assert!(
            deliver_result(&config, &client, &envelope, &journal, &result)
                .await
                .is_err()
        );
        assert!(rx.try_recv().is_err());
        assert!(!journal.path("result-ack.json").exists());
        server.result_reply.lock().unwrap()["data"]["terminal"]["generation"] =
            json!(envelope.generation);
        deliver_result(&config, &client, &envelope, &journal, &result)
            .await
            .unwrap();
        let notice = rx
            .try_recv()
            .expect("ACK should wake the control loop directly");
        assert_eq!(notice.attempt_id, envelope.attempt_id);
        assert!(notice.terminal_confirmed && notice.canonical_result);
        let ack: Value =
            serde_json::from_slice(&std::fs::read(journal.path("result-ack.json")).unwrap())
                .unwrap();
        assert_eq!(ack["event_id"], result.event_id);
        assert_eq!(ack["terminal_confirmed"], true);
        assert_eq!(
            server.count("/claim"),
            0,
            "settlement is a wakeup, not authority to bypass claim"
        );
    }

    #[tokio::test]
    async fn parallel_preparation_drains_all_writes_when_one_file_fails() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.json");
        let last = temp.path().join("last.json");
        let checkpoints = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = checkpoints.clone();
        let first_at_checkpoint = first.clone();
        let last_at_checkpoint = last.clone();
        assert!(
            persist_preparation_with_directory_sync(
                vec![
                    (first.clone(), b"first".to_vec()),
                    (
                        temp.path().join("missing-parent/fails.json"),
                        b"fail".to_vec()
                    ),
                    (last.clone(), b"last".to_vec()),
                ],
                move |parent| {
                    assert_eq!(std::fs::read(&first_at_checkpoint).unwrap(), b"first");
                    assert_eq!(std::fs::read(&last_at_checkpoint).unwrap(), b"last");
                    sync_preparation_directory(parent)?;
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }
            )
            .await
            .is_err()
        );
        assert_eq!(
            checkpoints.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "successful publications must share a completed directory fsync before failure returns"
        );
        assert_eq!(std::fs::read(first).unwrap(), b"first");
        assert_eq!(std::fs::read(last).unwrap(), b"last");
    }

    #[tokio::test]
    async fn parallel_preparation_syncs_each_parent_once_after_all_file_publications() {
        let temp = tempfile::tempdir().unwrap();
        let first_parent = temp.path().join("first");
        let second_parent = temp.path().join("second");
        std::fs::create_dir_all(&first_parent).unwrap();
        std::fs::create_dir_all(&second_parent).unwrap();
        let files = vec![
            (first_parent.join("prompt.txt"), b"prompt".to_vec()),
            (first_parent.join("manifest.json"), b"manifest".to_vec()),
            (second_parent.join("worktree.json"), b"worktree".to_vec()),
        ];
        let expected = std::sync::Arc::new(files.clone());
        let checkpoints = std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let observed = checkpoints.clone();
        persist_preparation_with_directory_sync(files, move |parent| {
            // This is the actual directory durability boundary. All successful
            // file fsyncs and atomic renames must have settled before it runs.
            for (path, bytes) in expected.iter() {
                assert_eq!(&std::fs::read(path).unwrap(), bytes);
            }
            sync_preparation_directory(parent.clone())?;
            *observed.lock().unwrap().entry(parent).or_insert(0) += 1;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            *checkpoints.lock().unwrap(),
            BTreeMap::from([(first_parent, 1), (second_parent, 1),])
        );
    }

    #[tokio::test]
    async fn parallel_preparation_drains_other_directory_checkpoints_after_failure() {
        let temp = tempfile::tempdir().unwrap();
        let failed_parent = temp.path().join("failed");
        let completed_parent = temp.path().join("completed");
        std::fs::create_dir_all(&failed_parent).unwrap();
        std::fs::create_dir_all(&completed_parent).unwrap();
        let checkpoints = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = checkpoints.clone();
        assert!(
            persist_preparation_with_directory_sync(
                vec![
                    (failed_parent.join("worktree.json"), b"worktree".to_vec()),
                    (completed_parent.join("starting.json"), b"starting".to_vec()),
                ],
                move |parent| {
                    if parent == failed_parent {
                        bail!("injected directory fsync failure");
                    }
                    sync_preparation_directory(parent)?;
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }
            )
            .await
            .is_err()
        );
        assert_eq!(
            checkpoints.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "another failed directory checkpoint cannot abandon remaining fsyncs"
        );
        assert_eq!(
            std::fs::read(completed_parent.join("starting.json")).unwrap(),
            b"starting"
        );
    }

    #[tokio::test]
    async fn strict_success_and_legacy_replay_use_execution_result() {
        let server = FakeControl::start().await;
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let mut config = liveness_config(&server.url, temp.path());
        config.strict_resource_handoff = true;
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        result_delivery_policy(&config, &envelope, &journal, true).unwrap();
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "exited".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        let mut result = reconciled_author_stop(&envelope, &stop, &journal).unwrap();
        result.outcome.completion_reason = "EXECUTOR_COMPLETED".into();
        deliver_result(&config, &client, &envelope, &journal, &result)
            .await
            .unwrap();
        let legacy = Journal::new(&temp.path().join("legacy"), &envelope.attempt_id).unwrap();
        result.outcome.completion_reason = "CANCELLED".into();
        durable_json(&legacy.path("result.json"), &result).unwrap();
        deliver_result(&config, &client, &envelope, &legacy, &result)
            .await
            .unwrap();
        assert_eq!(server.count("/execution-result"), 2);
        assert_eq!(server.count("/handoff-result"), 0);
    }

    #[tokio::test]
    async fn delayed_projection_claim_and_observation_preserve_presence_and_post_ack_lease() {
        let server = FakeControl::start().await;
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let config = liveness_config(&server.url, temp.path());
        let journal = Journal::new(&temp.path().join("attempts"), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        std::fs::write(
            journal.path("stdout.ndjson"),
            b"{\"type\":\"session\",\"sessionId\":\"native-live\"}\n",
        )
        .unwrap();
        let (shutdown, signal) = watch::channel(false);
        let mut keeper = LeaseKeeper::start(
            client.clone(),
            envelope.clone(),
            parse_time(&envelope.expires_at).unwrap(),
            signal,
        );
        let mut authority = keeper.authority.clone();
        let presence = WorkerPresence::start(
            client.clone(),
            envelope.worker_id.clone(),
            "boot-live".into(),
            vec![envelope.attempt_id.clone()],
        );
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "exited".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        let result = reconciled_author_stop(&envelope, &stop, &journal).unwrap();
        server.reject_result.store(true, Ordering::SeqCst);
        assert!(client.result(&result).await.is_err());
        keeper.retain_until_settlement();
        drop(keeper);
        client.result(&result).await.unwrap(); // Controller ACK has arrived; lease ownership continues.
        let start = tokio::time::Instant::now();
        let mut live = LiveProjection::new(&result.outcome.execution_id);
        let (projected, claimed, observed) = tokio::join!(
            live.poll(&client, &journal, &envelope),
            client.claim(&config, vec![envelope.attempt_id.clone()]),
            client.attempt(&envelope)
        );
        projected.unwrap();
        assert!(claimed.unwrap().is_none());
        assert_eq!(
            observed.unwrap().state,
            forgeflow_domain::AttemptState::Verifying
        );
        assert!(start.elapsed() >= Duration::from_secs(7));
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            server.count("/workers/worker-live/heartbeat") >= 3,
            "presence starved during slow HTTP"
        );
        assert!(
            server.count("/attempts/attempt-live/heartbeat") >= 3,
            "post-ACK keeper stopped or starved"
        );
        assert!(!authority.borrow().revoked);
        assert!(presence.admits());
        let events = server.requests.lock().unwrap();
        for (_, _, body) in events
            .iter()
            .filter(|(path, _, _)| path.ends_with("/workers/worker-live/heartbeat"))
        {
            assert_eq!(body["active_attempt_ids"], json!(["attempt-live"]));
        }
        drop(events);
        shutdown.send(true).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            authority.wait_for(|state| state.revoked),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn slow_renewal_is_fenced_at_observed_expiry_and_shutdown_interrupts_http() {
        let server = FakeControl::start().await;
        server.renew_delay_ms.store(7000, Ordering::SeqCst);
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let (shutdown, signal) = watch::channel(false);
        let keeper = LeaseKeeper::start(
            client.clone(),
            liveness_envelope(),
            chrono::Utc::now() + chrono::Duration::milliseconds(250),
            signal.clone(),
        );
        let mut authority = keeper.authority.clone();
        tokio::time::timeout(
            Duration::from_secs(1),
            authority.wait_for(|state| state.revoked),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(server.count("/attempts/attempt-live/heartbeat") >= 1);
        let second = LeaseKeeper::start(
            client,
            liveness_envelope(),
            chrono::Utc::now() + chrono::Duration::seconds(30),
            signal,
        );
        let mut second_authority = second.authority.clone();
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.send(true).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            second_authority.wait_for(|state| state.revoked),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn replay_budget_retains_lost_ack_events_and_live_batches_resume_at_eof() {
        let server = FakeControl::start().await;
        // A 7 s delayed ACK is valid under the client's 10 s HTTP bound.
        // Delay beyond that bound to exercise actual lost-ACK redelivery.
        server.event_delay_ms.store(11_000, Ordering::SeqCst);
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        let raw = "{\"type\":\"session\",\"sessionId\":\"live\"}\n".repeat(33);
        std::fs::write(journal.path("stdout.ndjson"), raw.as_bytes()).unwrap();
        let mut live = LiveProjection::new(&journal.execution_id().unwrap());
        for _ in 0..3 {
            let before = server.count("/worker-events");
            live.poll(&client, &journal, &envelope).await.unwrap();
            let requests = server.requests.lock().unwrap();
            let sent = requests
                .iter()
                .filter(|(path, _, _)| path.ends_with("/worker-events"))
                .nth(before)
                .unwrap();
            // The 2 s batch budget prevents starting another request; an
            // in-flight request retains its 10 s ACK deadline. Measure from
            // receipt here, excluding the earlier durable local append work.
            assert!(
                sent.1.elapsed() < Duration::from_secs(12),
                "in-flight replay exceeded its HTTP deadline envelope"
            );
        }
        assert_eq!(live.offset, raw.len() as u64);
        let pending = std::fs::read_dir(&journal.directory)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("event-")
                    .then_some(entry)
            })
            .count();
        assert_eq!(pending, 33, "lost ACK discarded durable events");
        let requests = server.requests.lock().unwrap();
        let delivered: Vec<_> = requests
            .iter()
            .filter(|(path, _, _)| path.ends_with("/worker-events"))
            .collect();
        assert_eq!(delivered.len(), 3);
        assert!(
            delivered
                .iter()
                .all(|(_, _, body)| body["event_id"] == delivered[0].2["event_id"]),
            "redelivery changed its identity"
        );
    }

    #[tokio::test]
    async fn shutdown_with_confirmed_author_stop_retains_durable_result_without_network_wait() {
        let server = FakeControl::start().await;
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let config = liveness_config(&server.url, temp.path());
        let journal = Journal::new(&temp.path().join("attempts"), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "executor_exited".into(),
            process_exit_confirmed: true,
            stdout_bytes: 33,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        journal.record_stop(&stop).unwrap();
        let (_shutdown, signal) = watch::channel(true);
        assert!(
            execute_controlled(&config, &client, envelope.clone(), signal)
                .await
                .is_err()
        );
        let result: WorkerResult =
            serde_json::from_slice(&std::fs::read(journal.path("result.json")).unwrap()).unwrap();
        assert_eq!(result.outcome.completion_reason, "CANCELLED");
        assert_eq!(result.evidence["process_exit_confirmed"], true);
        assert_eq!(result.event_id, format!("{}:result", envelope.operation_id));
        assert_eq!(result.project_id, envelope.project_id);
        assert_eq!(result.attempt_id, envelope.attempt_id);
        assert_eq!(result.lease_id, envelope.lease_id);
        assert_eq!(result.generation, envelope.generation);
        assert_eq!(result.worker_id, envelope.worker_id);
        assert_eq!(
            result.evidence["stop"],
            serde_json::to_value(&stop).unwrap()
        );
        let retention: Value =
            serde_json::from_slice(&std::fs::read(journal.path("lease-retention.json")).unwrap())
                .unwrap();
        assert_eq!(retention["attempt_id"], envelope.attempt_id);
        assert_eq!(retention["generation"], envelope.generation);
        let persisted: ExecutionEnvelope =
            serde_json::from_slice(&std::fs::read(journal.path("envelope.json")).unwrap()).unwrap();
        assert_eq!(persisted, envelope);
        assert!(!journal.path("launch-intent.json").exists());
        // Allow spawned restoration to observe shutdown. The oracle is zero HTTP
        // requests, not total journal fsync time on the qualification host.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            server.requests.lock().unwrap().is_empty(),
            "shutdown performed network work"
        );
    }
    #[tokio::test]
    #[ignore = "A00 must provide private FORGEFLOW_CLAUDE_CAPTURE_PATH and pinned FORGEFLOW_CLAUDE_CAPTURE_SHA256; no models are called"]
    async fn claude_captured_stream_replay_keeps_all_frames_and_sparse_identity() {
        let path = PathBuf::from(
            std::env::var("FORGEFLOW_CLAUDE_CAPTURE_PATH")
                .expect("explicit private captured stdout required"),
        );
        let expected_sha = std::env::var("FORGEFLOW_CLAUDE_CAPTURE_SHA256")
            .expect("explicit captured stdout SHA256 required");
        let raw = std::fs::read(path).unwrap();
        assert_eq!(sha256(&raw), expected_sha);
        assert_eq!(raw.len(), 701_140);
        let mut parser = forgeflow_executors::ClaudeStream::new("no-model-captured-replay");
        let mut selected = Vec::new();
        let mut frames = 0u64;
        for line in raw.split_inclusive(|byte| *byte == b'\n') {
            frames += 1;
            let parsed = parser.observe_line(line);
            assert!(
                parsed.parse_error.is_none(),
                "captured frame {} failed: {:?}",
                frames,
                parsed.parse_error
            );
            assert_eq!(parsed.sequence, frames);
            if claude_supervisor::should_project(&parsed) {
                selected.push(parsed.sequence);
            }
        }
        assert_eq!(frames, 2797);
        assert_eq!(selected.len(), 28);
        assert_eq!(selected.last(), Some(&2797));
        assert!(selected.windows(2).any(|pair| pair[1] > pair[0] + 1));
        let temp = tempfile::tempdir().unwrap();
        let mut envelope = liveness_envelope();
        envelope.max_model_requests = 0;
        envelope
            .allowed_effects
            .retain(|effect| *effect != forgeflow_domain::AllowedEffect::RequestApprovedModel);
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        persist_bytes(&journal.path("stdout.ndjson"), &raw).unwrap();
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "no-model-captured-parser-replay".into(),
            process_exit_confirmed: true,
            stdout_bytes: raw.len() as u64,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        let client =
            ControlClient::new("http://127.0.0.1:1", "NO_MODEL_REPLAY_NO_CREDENTIAL".into())
                .unwrap();
        let started = std::time::Instant::now();
        let outcome = parse_persisted_stream(&client, &journal, &envelope, &stop, true)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(outcome.completion_reason, "EXECUTOR_COMPLETED");
        assert_eq!(outcome.raw_event_digest, expected_sha);
        assert_eq!(
            hash_file(&journal.path("stdout.ndjson")).await.unwrap(),
            expected_sha
        );
        let originals = selected
            .iter()
            .map(|sequence| {
                let path = journal.path(&format!("native-events/{sequence:020}.meta.json"));
                let bytes = std::fs::read(&path).unwrap();
                let projection: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(projection["sequence"].as_u64(), Some(*sequence));
                assert_eq!(projection["source_sequence"].as_u64(), Some(*sequence));
                (path, bytes)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            std::fs::read_dir(journal.path("native-events"))
                .unwrap()
                .count(),
            56,
            "only 28 selected raw/meta pairs should exist"
        );
        let replay = parse_persisted_stream(&client, &journal, &envelope, &stop, true)
            .await
            .unwrap();
        assert_eq!(replay.raw_event_digest, outcome.raw_event_digest);
        assert_eq!(replay.completion_reason, outcome.completion_reason);
        for (path, bytes) in originals {
            assert!(
                std::fs::read(path).unwrap() == bytes,
                "replay changed immutable projection bytes"
            );
        }
        assert_eq!(
            std::fs::read_dir(journal.path("native-events"))
                .unwrap()
                .count(),
            56
        );
        println!(
            "{}",
            json!({"evidence_class":"NO_MODEL_CAPTURED_STREAM_REPLAY","raw_sha256":expected_sha,"source_bytes":raw.len(),"parsed_frames":frames,"selected_business_frames":selected.len(),"suppressed_frames":frames-selected.len() as u64,"first_complete_replay_seconds":elapsed.as_secs_f64(),"real_provider_calls":0,"not_proven":["physical author stop","new live native execution","business integration","all-log zero-copy"]})
        );
    }
    #[tokio::test]
    async fn claude_live_and_persisted_replay_keep_large_result_and_identity() {
        let server = FakeControl::start().await;
        server.event_delay_ms.store(0, Ordering::SeqCst);
        let client = ControlClient::new(&server.url, "private-test-token".into()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        let result_text = "complete-".repeat(262_144);
        let init = b"{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"claude-root\"}\n";
        let mut result = serde_json::to_vec(&json!({"type":"result","subtype":"success","session_id":"claude-root","is_error":false,"result":result_text})).unwrap();
        result.push(b'\n');
        let mut stdout = init.to_vec();
        stdout.extend_from_slice(&result);
        std::fs::write(journal.path("stdout.ndjson"), &stdout).unwrap();
        let mut live = LiveProjection::for_profile(&journal.execution_id().unwrap(), true);
        live.poll(&client, &journal, &envelope).await.unwrap();
        let initial_projection =
            std::fs::read(journal.path("native-events/00000000000000000001.meta.json")).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&initial_projection).unwrap()["source"],
            "claude_code_leaf"
        );
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "exited".into(),
            process_exit_confirmed: true,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        let outcome = parse_persisted_stream(&client, &journal, &envelope, &stop, true)
            .await
            .unwrap();
        assert_eq!(outcome.completion_reason, "EXECUTOR_COMPLETED");
        assert_eq!(outcome.upstream_session_id.as_deref(), Some("claude-root"));
        assert_eq!(outcome.raw_event_digest, sha256(&stdout));
        assert_eq!(std::fs::read(journal.path("final.json")).unwrap(), result);
        assert_eq!(
            std::fs::read(journal.path("native-events/00000000000000000001.meta.json")).unwrap(),
            initial_projection
        );
        assert_eq!(
            forgeflow_executors::extract_claude_result_text(
                &std::fs::read(journal.path("final.json")).unwrap()
            )
            .unwrap(),
            result_text
        );
        assert!(
            !std::fs::read_to_string(journal.path("native-events/00000000000000000002.meta.json"))
                .unwrap()
                .contains(&result_text)
        );
    }
    #[tokio::test]
    async fn claude_oversized_frame_fails_and_keeps_complete_original() {
        use std::io::Write;
        let temp = tempfile::tempdir().unwrap();
        let envelope = liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        let mut file = std::fs::File::create(journal.path("stdout.ndjson")).unwrap();
        file.write_all(br#"{"type":"result","result":""#).unwrap();
        for _ in 0..513 {
            file.write_all(&[b'x'; 65536]).unwrap();
        }
        file.write_all(b"\"}\n").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let original = hash_file(&journal.path("stdout.ndjson")).await.unwrap();
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "exited".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        let client = ControlClient::new("http://127.0.0.1:1", "no-model-fixture".into()).unwrap();
        let error = parse_persisted_stream(&client, &journal, &envelope, &stop, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("CLAUDE_FRAME_LIMIT_EXCEEDED"));
        assert_eq!(
            hash_file(&journal.path("native-line-00000000000000000001.spool"))
                .await
                .unwrap(),
            original
        );
        assert_eq!(
            hash_file(&journal.path("stdout.ndjson")).await.unwrap(),
            original
        );
        assert!(!journal.path("final.json").exists());
    }
    #[tokio::test]
    async fn oversized_native_final_is_spooled_losslessly_with_bounded_buffers() {
        use std::io::Write;
        let temp = tempfile::tempdir().unwrap();
        let journal = Journal::new(temp.path(), "final-spool").unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        let source = journal.path("stdout.ndjson");
        let mut output = std::fs::File::create(&source).unwrap();
        output.write_all(br#"{"type":"final","text":""#).unwrap();
        let chunk = vec![b'x'; 65536];
        for _ in 0..513 {
            output.write_all(&chunk).unwrap();
        }
        output.write_all(b"\"}\n").unwrap();
        output.sync_all().unwrap();
        let expected = hash_file(&source).await.unwrap();
        let mut reader = BufReader::new(tokio::fs::File::open(&source).await.unwrap());
        let line = read_native_line(&mut reader, &journal, 1)
            .await
            .unwrap()
            .unwrap();
        match line {
            NativeLine::Spooled {
                path,
                raw_bytes,
                raw_sha256,
                prefix,
            } => {
                assert_eq!(raw_sha256, expected);
                assert_eq!(raw_bytes, std::fs::metadata(&source).unwrap().len());
                assert!(prefix.starts_with(br#"{"type":"final","text":""#));
                assert_eq!(std::fs::metadata(path).unwrap().len(), raw_bytes);
            }
            NativeLine::Buffered(_) => panic!("large final buffered"),
        }
        assert!(
            read_native_line(&mut reader, &journal, 2)
                .await
                .unwrap()
                .is_none()
        );
    }
}

fn reconciled_author_stop(
    envelope: &ExecutionEnvelope,
    stop: &StopEvidence,
    journal: &Journal,
) -> Result<WorkerResult> {
    Ok(WorkerResult {
        event_id: format!("{}:reconciled-stop", envelope.operation_id),
        project_id: envelope.project_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        lease_id: envelope.lease_id.clone(),
        generation: envelope.generation,
        worker_id: envelope.worker_id.clone(),
        evidence: bound_stop_evidence(
            json!({"process_exit_confirmed":stop.process_exit_confirmed,"stop":stop,"executor_kind":executor_profile::journal_executor_identity(envelope, journal)?.0,"real_dsh":executor_profile::journal_executor_identity(envelope, journal)?.1}),
            envelope,
            journal,
            &journal.execution_id()?,
        )?,
        outcome: ExecutorOutcome {
            execution_id: journal.execution_id()?,
            upstream_session_id: None,
            exit_code: stop.exit_code,
            completion_reason: "CANCELLED".into(),
            raw_event_digest: String::new(),
            transcript_completeness: "RESTART_RECONCILIATION".into(),
            final_artifact: None,
            error_class: None,
        },
    })
}

fn native_raw_path(journal: &Journal, sequence: u64) -> Result<PathBuf> {
    let directory = journal.path("native-events");
    std::fs::create_dir_all(&directory)?;
    Ok(directory.join(format!("{sequence:020}.ndjson")))
}
fn link_final_artifact(journal: &Journal, source: &Path) -> Result<()> {
    let temporary = journal.path(&format!("final-{}.tmp", uuid::Uuid::new_v4()));
    std::fs::hard_link(source, &temporary)?;
    std::fs::rename(temporary, journal.path("final.json"))?;
    std::fs::File::open(&journal.directory)?.sync_all()?;
    Ok(())
}
fn normalize_native(
    journal: &Journal,
    envelope: &ExecutionEnvelope,
    sequence: u64,
    native_type: &str,
    projected: Value,
    raw_path: &Path,
    raw_sha256: &str,
    raw_bytes: u64,
) -> Result<Value> {
    normalize_native_for_source(
        journal,
        envelope,
        sequence,
        native_type,
        projected,
        raw_path,
        raw_sha256,
        raw_bytes,
        "dsh_headless",
    )
}
fn normalize_native_for_source(
    journal: &Journal,
    envelope: &ExecutionEnvelope,
    sequence: u64,
    native_type: &str,
    mut projected: Value,
    raw_path: &Path,
    raw_sha256: &str,
    raw_bytes: u64,
    source: &str,
) -> Result<Value> {
    let path = journal
        .path("native-events")
        .join(format!("{sequence:020}.meta.json"));
    if path.exists() {
        let previous: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        if previous
            .pointer("/raw_artifact_ref/sha256")
            .and_then(Value::as_str)
            != Some(raw_sha256)
            || previous.get("source").and_then(Value::as_str) != Some(source)
        {
            bail!("native event sequence replay changed original bytes");
        }
        return Ok(previous);
    }
    let completeness = if projected
        .pointer("/payload/truncated")
        .and_then(Value::as_bool)
        == Some(true)
    {
        "UPSTREAM_PROJECTION_TRUNCATED"
    } else {
        "UPSTREAM_COMMITTED_PROJECTION"
    };
    let fields = projected
        .as_object_mut()
        .context("native projection must be object")?;
    fields.insert(
        "event_id".into(),
        json!(format!("{}:native-{sequence:020}", envelope.operation_id)),
    );
    fields.insert("project_id".into(), json!(envelope.project_id));
    fields.insert("attempt_id".into(), json!(envelope.attempt_id));
    fields.insert("execution_id".into(), json!(journal.execution_id()?));
    fields.insert("source".into(), json!(source));
    fields.insert("source_sequence".into(), json!(sequence));
    fields.insert("source_sequence_kind".into(), json!("WORKER_RECEIVE_ORDER"));
    fields.insert("received_at".into(), json!(chrono::Utc::now().to_rfc3339()));
    fields.insert("event_type".into(), json!(native_type));
    fields.insert("completeness".into(), json!(completeness));
    fields.insert("raw_artifact_ref".into(),json!({"storage":"WORKER_LOCAL_FILE","path":raw_path,"sha256":raw_sha256,"bytes":raw_bytes}));
    durable_json(&path, &projected)?;
    Ok(projected)
}

fn bind_project_home(home: &Path, project_id: &str, profile_id: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = home.join(".forgeflow-project.json");
    let expected = json!({"project_id":project_id,"executor_profile_id":profile_id});
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&serde_json::to_vec(&expected)?)?;
            file.sync_all()?;
            std::fs::File::open(home)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual: Value = serde_json::from_slice(&std::fs::read(path)?)?;
            if actual != expected {
                bail!("DSH home belongs to another project or frozen profile");
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn persist_native_raw(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if std::fs::metadata(path)?.len() != bytes.len() as u64 {
            bail!("native raw artifact replay changed length");
        }
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let mut digest = Sha256::new();
        let mut chunk = [0u8; 16384];
        loop {
            let count = file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            digest.update(&chunk[..count]);
        }
        if format!("{:x}", digest.finalize()) != sha256(bytes) {
            bail!("native raw artifact replay changed bytes");
        }
        return Ok(());
    }
    persist_bytes(path, bytes)
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    fn envelope(root: &Path) -> ExecutionEnvelope {
        serde_json::from_value(json!({
            "schema_version":"forgeflow.execution.v1","operation_id":"dispatch-op","project_id":"project","task_id":"task","task_revision":1,"attempt_id":"attempt","lease_id":"lease","generation":1,"worker_id":"worker","workspace_root":root,"base_sha":"a".repeat(40),
            "context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"profile","resource_profile_id":"resource","verification_plan_id":"verify","allowed_effects":["READ_WORKSPACE"],"issued_at":"2026-10-09T00:00:00Z","expires_at":"2026-10-09T01:00:00Z","deadline_at":"2026-10-09T02:00:00Z","artifact_prefix":root,"secret_refs":[],"idempotency_key":"key","trace_id":"trace",
            "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"REVIEW","max_model_requests":1,"resume_session_id":null,"command":null
        })).unwrap()
    }
    #[test]
    fn terminal_evidence_preserves_full_journal_launch_receipt_and_rejects_scope_drift() {
        let temp = tempfile::tempdir().unwrap();
        let journal = Journal::new(temp.path(), "attempt").unwrap();
        let envelope = envelope(temp.path());
        let execution = journal.execution_id().unwrap();
        let intent = LaunchIntent {
            execution_id: execution.clone(),
            operation_id: envelope.operation_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            boot_id: "fixture-boot".into(),
            workspace: temp.path().join("worktree"),
            prompt_sha256: envelope.prompt_artifact.sha256.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        journal.record_intent(&intent).unwrap();
        let receipt = forgeflow_runtime::LaunchReceipt {
            execution_id: execution.clone(),
            intent,
            process: forgeflow_runtime::ProcessIdentity {
                pid: 1234,
                pgid: 1234,
                start_ticks: 98765,
                boot_id: "fixture-boot".into(),
                attempt_id: envelope.attempt_id.clone(),
            },
            launched_at: chrono::Utc::now().to_rfc3339(),
            command_program: "/bin/true".into(),
            command_args: vec!["opaque-argument".into()],
            environment_key_names: vec!["PATH".into()],
        };
        journal.record_receipt(&receipt).unwrap();
        let raw: Value =
            serde_json::from_slice(&std::fs::read(journal.path("launch-receipt.json")).unwrap())
                .unwrap();
        let stop = StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "fixture_confirmed_stop".into(),
            process_exit_confirmed: true,
            stdout_bytes: 1,
            stderr_bytes: 2,
            notification_overflow: 3,
            log_error: None,
        };
        let result = reconciled_author_stop(&envelope, &stop, &journal).unwrap();
        assert_eq!(result.evidence["launch_receipt"], raw);
        assert_eq!(result.evidence["execution_id"], result.outcome.execution_id);
        assert_eq!(
            result.evidence["stop"],
            serde_json::to_value(&stop).unwrap()
        );
        let confirm = forgeflow_domain::StopReceipt {
            project_id: envelope.project_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            generation: envelope.generation,
            worker_id: envelope.worker_id.clone(),
            process_exit_confirmed: stop.process_exit_confirmed,
            evidence: result.evidence.clone(),
        };
        assert_eq!(
            confirm.evidence["execution_id"],
            confirm.evidence["launch_receipt"]["execution_id"]
        );
        let before = std::fs::read(journal.path("launch-receipt.json")).unwrap();
        let mut drifted = envelope.clone();
        drifted.generation += 1;
        assert!(bound_stop_evidence(json!({}), &drifted, &journal, &execution).is_err());
        assert!(
            bound_stop_evidence(
                json!({}),
                &envelope,
                &journal,
                &uuid::Uuid::new_v4().to_string()
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(journal.path("launch-receipt.json")).unwrap(),
            before
        );
        let mut changed_intent = serde_json::to_value(&receipt.intent).unwrap();
        changed_intent["created_at"] = json!("2026-01-01T00:00:00Z");
        durable_json(&journal.path("launch-intent.json"), &changed_intent).unwrap();
        assert!(bound_stop_evidence(json!({}), &envelope, &journal, &execution).is_err());
    }
    #[test]
    fn terminal_evidence_does_not_invent_launch_receipt_before_launch() {
        let temp = tempfile::tempdir().unwrap();
        let journal = Journal::new(temp.path(), "attempt").unwrap();
        let envelope = envelope(temp.path());
        let execution = journal.execution_id().unwrap();
        let evidence = bound_stop_evidence(
            json!({"process_exit_confirmed":true}),
            &envelope,
            &journal,
            &execution,
        )
        .unwrap();
        assert_eq!(evidence["execution_id"], execution);
        assert!(evidence.get("launch_receipt").is_none());
        assert!(!journal.path("launch-receipt.json").exists());
        assert!(!journal.path("launch-intent.json").exists());
    }
    #[test]
    fn normalized_receive_identity_and_artifact_remain_stable_across_replay() {
        let temp = tempfile::tempdir().unwrap();
        let journal = Journal::new(temp.path(), "attempt").unwrap();
        let envelope = envelope(temp.path());
        let execution = journal.execution_id().unwrap();
        let bytes = br#"{"type":"session","sessionId":"upstream"}"#;
        let path = native_raw_path(&journal, 1).unwrap();
        persist_native_raw(&path, bytes).unwrap();
        let first = normalize_native(
            &journal,
            &envelope,
            1,
            "session",
            json!({"native_type":"session","payload":{"sessionId":"upstream"}}),
            &path,
            &sha256(bytes),
            bytes.len() as u64,
        )
        .unwrap();
        let replay = normalize_native(
            &journal,
            &envelope,
            1,
            "session",
            json!({"future":"must not overwrite original observation"}),
            &path,
            &sha256(bytes),
            bytes.len() as u64,
        )
        .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first["execution_id"], execution);
        assert_ne!(first["execution_id"], envelope.operation_id);
        assert_eq!(first["source_sequence_kind"], "WORKER_RECEIVE_ORDER");
        assert!(first["received_at"].as_str().is_some());
        assert_eq!(
            first["raw_artifact_ref"]["sha256"],
            sha256(&std::fs::read(&path).unwrap())
        );
        assert!(persist_native_raw(&path, b"changed").is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    #[test]
    fn dedicated_dsh_home_cannot_be_reassigned_to_another_project() {
        let temp = tempfile::tempdir().unwrap();
        bind_project_home(temp.path(), "first", "profile").unwrap();
        bind_project_home(temp.path(), "first", "profile").unwrap();
        assert!(bind_project_home(temp.path(), "second", "profile").is_err());
        assert!(bind_project_home(temp.path(), "first", "different-profile").is_err());
    }
}

async fn wait_shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
    Ok(())
}
