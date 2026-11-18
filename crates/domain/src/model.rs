use crate::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
macro_rules! states {
    ($name:ident { $($v:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $($v),+ }
        impl $name { pub fn as_str(self) -> String { serde_json::to_value(self).expect("enum serialization").as_str().unwrap().to_owned() } }
    };
}
states!(AttemptState {
    Leased,
    Starting,
    Running,
    Verifying,
    ReviewReady,
    MergeQueued,
    Merging,
    Stopping,
    RecoveryRequired,
    Succeeded,
    Failed,
    Cancelled
});
states!(TaskPlanningState {
    Planned,
    NeedsReview,
    ReadyForAdmission,
    Deferred,
    RemovedFromPlan
});
states!(FlowState {
    Draft,
    Checking,
    ReviewRequired,
    Committed,
    Superseded
});
states!(AuthorityMode {
    Managed,
    ObservedReadOnly
});
states!(DataOrigin {
    Native,
    Imported,
    Demo
});
states!(AllocationState {
    Reserved,
    Held,
    Quarantined,
    Released
});
states!(MergeIntentState {
    Prepared,
    CommitDecided,
    RefUpdated,
    Finalized,
    Committed,
    Aborted,
    RecoveryRequired
});
states!(GateStatus {
    NotRun,
    Blocked,
    Inconclusive,
    Fail,
    Pass,
    VerifierInvalid
});
impl AttemptState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
    pub fn can_transition(self, next: Self) -> bool {
        use AttemptState::*;
        matches!(
            (self, next),
            (Leased, Starting | Cancelled)
                | (Starting, Running | Failed | RecoveryRequired)
                | (Running, Verifying | Stopping | Failed)
                | (Verifying, ReviewReady | Failed | Stopping)
                | (ReviewReady, MergeQueued | Failed)
                | (MergeQueued, Merging | Stopping)
                | (Merging, Succeeded | Failed | RecoveryRequired)
                | (Stopping, Cancelled | RecoveryRequired)
                | (RecoveryRequired, Cancelled | Failed)
        )
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceVector {
    pub active_slot: u64,
    pub coding_slot: u64,
    pub cpu_units: u64,
    pub memory_bytes: u64,
    pub build_permit: u64,
    pub gpu_permit: u64,
    pub provider_inflight: u64,
}
impl ResourceVector {
    /// Checked authority arithmetic, independently of replicated ancestor rows.
    pub fn checked_pool(&self, child: &Self, count: u32) -> Result<Self, DomainError> {
        let calculate = |root: u64, each: u64| {
            each.checked_mul(u64::from(count))
                .and_then(|amount| root.checked_add(amount))
                .filter(|amount| *amount <= i64::MAX as u64)
                .ok_or_else(|| {
                    DomainError::new(
                        "PHYSICAL_POLICY_INVALID",
                        "whole-attempt resource vector overflow",
                    )
                })
        };
        Ok(Self {
            active_slot: calculate(self.active_slot, child.active_slot)?,
            coding_slot: calculate(self.coding_slot, child.coding_slot)?,
            cpu_units: calculate(self.cpu_units, child.cpu_units)?,
            memory_bytes: calculate(self.memory_bytes, child.memory_bytes)?,
            build_permit: calculate(self.build_permit, child.build_permit)?,
            gpu_permit: calculate(self.gpu_permit, child.gpu_permit)?,
            provider_inflight: calculate(self.provider_inflight, child.provider_inflight)?,
        })
    }
    pub fn dimensions(&self) -> [(&'static str, u64); 7] {
        [
            ("active_slot", self.active_slot),
            ("coding_slot", self.coding_slot),
            ("cpu_units", self.cpu_units),
            ("memory_bytes", self.memory_bytes),
            ("build_permit", self.build_permit),
            ("gpu_permit", self.gpu_permit),
            ("provider_inflight", self.provider_inflight),
        ]
    }
}

/// Presence on an immutable resource profile requires physical fencing; absence
/// preserves legacy logical accounting without asserting physical enforcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhysicalLimitsPolicy {
    pub schema_version: String,
    pub required: bool,
    pub cpu_units_per_cpu: u64,
    pub period_us: u64,
    pub pids_max: u64,
    pub swap_max_bytes: u64,
    pub memory_oom_group: bool,
}
impl PhysicalLimitsPolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != "forgeflow.physical-limits.v1"
            || !self.required
            || self.cpu_units_per_cpu == 0
            || self.cpu_units_per_cpu > i64::MAX as u64
            || !(1_000..=1_000_000).contains(&self.period_us)
            || !(1..=65_536).contains(&self.pids_max)
            || self.swap_max_bytes != 0
            || !self.memory_oom_group
        {
            return Err(DomainError::new(
                "PHYSICAL_POLICY_INVALID",
                "required versioned finite CPU/memory/pids policy with swap0 and OOMgroup required",
            ));
        }
        Ok(())
    }
    pub fn hash_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
    pub fn digest(&self) -> Result<String, DomainError> {
        use sha2::{Digest, Sha256};
        Ok(format!(
            "{:x}",
            Sha256::digest(self.hash_payload().map_err(|_| DomainError::new(
                "PHYSICAL_POLICY_INVALID",
                "physical policy serialization failed"
            ))?)
        ))
    }
}

/// Immutable reservation/launch rights; runtime never derives these from a
/// mutable current Task. One complete pool is held until trusted parent stop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhysicalResourceBinding {
    pub schema_version: String,
    pub accounting_mode: String,
    pub resource_profile_id: String,
    pub root_resources: ResourceVector,
    pub native_child_resources: ResourceVector,
    pub max_concurrent_children: u32,
    pub reserved_resources: ResourceVector,
    pub physical_limits: PhysicalLimitsPolicy,
    pub cpu_quota_us: u64,
    pub memory_max_bytes: u64,
    pub physical_limits_sha256: String,
    pub reservation_sha256: String,
}
impl PhysicalResourceBinding {
    pub fn new(
        resource_profile_id: String,
        root_resources: ResourceVector,
        native_child_resources: ResourceVector,
        max_concurrent_children: u32,
        physical_limits: PhysicalLimitsPolicy,
    ) -> Result<Self, DomainError> {
        physical_limits.validate()?;
        let reserved_resources =
            root_resources.checked_pool(&native_child_resources, max_concurrent_children)?;
        let numerator = reserved_resources
            .cpu_units
            .checked_mul(physical_limits.period_us)
            .ok_or_else(|| {
                DomainError::new(
                    "PHYSICAL_POLICY_INVALID",
                    "CPU quota multiplication overflow",
                )
            })?;
        if numerator % physical_limits.cpu_units_per_cpu != 0 {
            return Err(DomainError::new(
                "PHYSICAL_POLICY_INVALID",
                "CPU units mapping must divide exactly",
            ));
        }
        let cpu_quota_us = numerator / physical_limits.cpu_units_per_cpu;
        let mut binding = Self {
            schema_version: "forgeflow.physical-reservation.v1".into(),
            accounting_mode: "UPFRONT_NATIVE_POOL".into(),
            resource_profile_id,
            root_resources,
            native_child_resources,
            max_concurrent_children,
            memory_max_bytes: reserved_resources.memory_bytes,
            reserved_resources,
            physical_limits_sha256: physical_limits.digest()?,
            physical_limits,
            cpu_quota_us,
            reservation_sha256: String::new(),
        };
        binding.validate()?;
        binding.reservation_sha256 = binding.digest()?;
        Ok(binding)
    }
    /// Typed serialization becomes a lexicographically keyed compact JSON
    /// object; the self hash is omitted. Consumers call this, never guess order.
    pub fn hash_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("typed binding object")
            .remove("reservation_sha256");
        serde_json::to_vec(&value)
    }
    pub fn digest(&self) -> Result<String, DomainError> {
        use sha2::{Digest, Sha256};
        Ok(format!(
            "{:x}",
            Sha256::digest(self.hash_payload().map_err(|_| DomainError::new(
                "PHYSICAL_POLICY_INVALID",
                "physical binding serialization failed"
            ))?)
        ))
    }
    pub fn validate(&self) -> Result<(), DomainError> {
        self.physical_limits.validate()?;
        let expected = self
            .root_resources
            .checked_pool(&self.native_child_resources, self.max_concurrent_children)?;
        let product = expected
            .cpu_units
            .checked_mul(self.physical_limits.period_us)
            .ok_or_else(|| {
                DomainError::new(
                    "PHYSICAL_POLICY_INVALID",
                    "CPU quota multiplication overflow",
                )
            })?;
        if self.schema_version != "forgeflow.physical-reservation.v1"
            || self.accounting_mode != "UPFRONT_NATIVE_POOL"
            || self.resource_profile_id.is_empty()
            || self.reserved_resources != expected
            || self.root_resources.cpu_units == 0
            || self.root_resources.memory_bytes == 0
            || self.memory_max_bytes == 0
            || self.memory_max_bytes != expected.memory_bytes
            || product % self.physical_limits.cpu_units_per_cpu != 0
            || self.cpu_quota_us != product / self.physical_limits.cpu_units_per_cpu
            || !(1_000..=i64::MAX as u64).contains(&self.cpu_quota_us)
        {
            return Err(DomainError::new(
                "PHYSICAL_POLICY_INVALID",
                "physical reservation vectors and derived finite limits differ",
            ));
        }
        Ok(())
    }
    pub fn verify(&self) -> Result<(), DomainError> {
        self.validate()?;
        if self.physical_limits_sha256 != self.physical_limits.digest()?
            || self.reservation_sha256 != self.digest()?
        {
            return Err(DomainError::new(
                "PHYSICAL_BINDING_MISMATCH",
                "physical policy/reservation hash differs",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project_id: String,
    pub name: String,
    pub root_path: String,
    pub authority_mode: AuthorityMode,
    pub data_origin: DataOrigin,
    pub goal: String,
    pub technology_stack: Vec<String>,
    pub timezone: String,
    pub paused: bool,
    pub archived: bool,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub project_id: String,
    pub requirement_id: String,
    pub title: String,
    pub source_anchor: String,
    pub outcome: String,
    pub scope: String,
    pub acceptance: Vec<String>,
    pub priority: i32,
    pub weight: u64,
    pub deferred_reason: Option<String>,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Team {
    pub project_id: String,
    pub team_id: String,
    pub parent_team_id: Option<String>,
    pub name: String,
    pub paused: bool,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicy {
    #[serde(default)]
    pub worker_id: Option<String>,
    pub scope_id: String,
    pub parent_scope_id: Option<String>,
    pub project_id: Option<String>,
    pub team_id: Option<String>,
    pub limits: ResourceVector,
    pub revision: u64,
    pub paused: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCard {
    pub project_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub flow_revision: u64,
    pub title: String,
    pub owner_id: String,
    pub team_id: String,
    pub requirement_ids: Vec<String>,
    pub read_set: Vec<String>,
    pub write_set: Vec<String>,
    pub dependencies: Vec<String>,
    pub state: TaskPlanningState,
    pub input_digest: String,
    pub resource_request: ResourceVector,
    pub envelope: Option<ExecutionEnvelope>,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowRevision {
    pub project_id: String,
    pub flow_revision: u64,
    pub parent_revision: Option<u64>,
    pub state: FlowState,
    pub tasks: Vec<TaskCard>,
    pub input_digest: String,
    pub approved_by: Option<String>,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub project_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub attempt_id: String,
    pub lease_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub operation_id: String,
    pub base_sha: String,
    pub state: AttemptState,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub terminal_at: Option<DateTime<Utc>>,
    pub result: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub project_id: String,
    pub lease_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub capability_scope: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEvent {
    pub event_id: String,
    pub project_id: String,
    pub project_seq: u64,
    pub object_id: String,
    pub object_revision: u64,
    pub schema_version: String,
    pub kind: String,
    pub payload: Value,
    pub occurred_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReceipt {
    pub receipt_id: String,
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub kind: String,
    pub input_digest: String,
    pub candidate_sha: Option<String>,
    pub integrated_sha: Option<String>,
    pub verifier_id: String,
    pub author_id: String,
    pub total: u64,
    pub failed: u64,
    pub skipped: u64,
    pub artifact: ArtifactRef,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeIntent {
    pub intent_id: String,
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub target_ref: String,
    pub expected_sha: String,
    pub candidate_sha: String,
    pub integrated_sha: Option<String>,
    pub state: MergeIntentState,
    pub revision: u64,
    pub receipt: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHandle {
    pub execution_id: String,
    pub upstream_session_id: Option<String>,
    pub attempt_id: String,
    pub operation_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorEvent {
    pub execution_id: String,
    pub sequence: u64,
    pub kind: String,
    pub payload: Value,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxMessage {
    pub outbox_id: String,
    pub project_id: String,
    pub operation_id: String,
    pub kind: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub project_id: String,
    pub schedule_id: String,
    pub task_id: String,
    pub baseline_version: u64,
    pub planned_start: DateTime<Utc>,
    pub planned_end: DateTime<Utc>,
    pub dependencies: Vec<String>,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort_estimate: Option<EffortEstimate>,
}
/// Reviewed planning effort, distinct from elapsed schedule or actual process time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffortEstimate {
    pub optimistic_hours: f64,
    pub likely_hours: f64,
    pub pessimistic_hours: f64,
    pub rationale: String,
    pub source: String,
}
impl EffortEstimate {
    pub fn validate(&self) -> Result<(), DomainError> {
        let hours = [
            self.optimistic_hours,
            self.likely_hours,
            self.pessimistic_hours,
        ];
        if hours
            .iter()
            .any(|v| !v.is_finite() || *v < 0.0 || *v > 1_000_000.0)
            || hours[0] > hours[1]
            || hours[1] > hours[2]
            || self.rationale.trim().is_empty()
            || self.source != "USER_REVIEWED_THREE_POINT"
        {
            return Err(DomainError::new(
                "VALIDATION_ERROR",
                "reviewed effort requires ordered finite hours, source and rationale",
            ));
        }
        Ok(())
    }
}
/// Versioned planning estimate independent of scheduled dates and execution rights.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEstimate {
    pub project_id: String,
    pub estimate_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub estimate_version: u64,
    pub effort: EffortEstimate,
    pub duration_hours: Option<f64>,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Milestone {
    #[serde(default)]
    pub change_reason: Option<String>,
    pub project_id: String,
    pub milestone_id: String,
    pub title: String,
    pub due_at: DateTime<Utc>,
    pub baseline_version: u64,
    pub requirement_ids: Vec<String>,
    pub required_work_packages: Vec<String>,
    pub required_gate_ids: Vec<String>,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub project_id: String,
    pub decision_id: String,
    pub proposal: String,
    pub options: Vec<String>,
    pub affected_object_ids: Vec<String>,
    pub authorized_by: Option<String>,
    pub selected_option: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractVersion {
    #[serde(default)]
    pub schema: serde_json::Value,
    pub project_id: String,
    pub contract_id: String,
    pub version: u64,
    pub spec_sha256: String,
    pub source_sha256: String,
    pub producer_task_id: String,
    pub required_consumers: Vec<String>,
    pub passing_consumers: Vec<String>,
    pub independent_receipt_id: Option<String>,
    pub integration_receipt_id: Option<String>,
    pub frozen: bool,
    pub revision: u64,
}
