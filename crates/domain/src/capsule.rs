//! Frozen Next v1 transport projections. These types never grant a lease,
//! launch a process, settle usage, or change an Attempt state. Validation proves
//! structure and supplied identity only; Store must check current authority.
use crate::{
    AllowedEffect, ArtifactRef, DomainError, ExecutionEnvelope, ExecutorCapabilities, WorkerEvent,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CAPSULE_SCHEMA_V1: &str = "forgeflow.capsule.v1";
pub const NATIVE_OBSERVATION_BINDING_SCHEMA_V1: &str = "forgeflow.native-observation-binding.v1";
pub const NATIVE_EVENT_SCHEMA_V1: &str = "forgeflow.native-event.v1";
pub const DRIVER_PROBE_SCHEMA_V1: &str = "forgeflow.driver-probe.v1";
pub const WRITE_AUTHORIZATION_SCHEMA_V1: &str = "forgeflow.write-authorization.v1";
pub const NATIVE_EVENT_SUMMARY_MAX_BYTES: usize = 16 * 1024;
pub const CAPSULE_MAX_REQUESTED_PATHS: usize = 1024;
const MAX_EVIDENCE_REFS: usize = 16;
const MAX_CAPABILITY_CHECKS: usize = 32;

macro_rules! wire_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $($variant),+ }
    };
}
wire_enum!(ExecutorDriverId { Dsh, ClaudeCode });
wire_enum!(ExecutionKind {
    ManagedLeaf,
    NativeTeamCapsule,
    NativeWorkflowCapsule
});
wire_enum!(TeamWritePolicy {
    ReadOnly,
    AggregateWriteScope,
    DisjointAttested
});
wire_enum!(DriverMode {
    DshHeadless,
    DshManagedTeam,
    DshManagedWorkflow,
    ClaudeLeaf,
    ClaudeInteractiveTeam,
    ClaudeSavedWorkflow
});
wire_enum!(EvidenceClass {
    RealModel,
    LocalProcess,
    NoModelFixture,
    Imported,
    Unknown
});
wire_enum!(VerificationStatus {
    Verified,
    Partial,
    Failed,
    NotRun,
    Blocked,
    Inconclusive,
    NotImplemented,
    Unknown
});
wire_enum!(CapabilityId {
    ExecutableIdentity,
    VersionHelp,
    StartHeadless,
    StructuredEvents,
    SessionResume,
    SessionCancel,
    ProcessCancel,
    SessionClose,
    TranscriptReplay,
    NativeTeam,
    NativeWorkflow,
    NativeMessaging,
    SupervisedChildren,
    ModelEgressEnforced,
    VerifiedWriteIsolation,
    UsageAccounting,
    BusinessE2e
});
wire_enum!(NativeEventKind {
    SessionStarted,
    MemberStarted,
    MemberIdle,
    TaskObserved,
    MessageObserved,
    WorkflowPhase,
    ToolObserved,
    UsageObserved,
    AgentFinished,
    DriverFailure,
    StopObserved,
    Unknown
});
wire_enum!(CancelPhase {
    Requested,
    Acknowledged,
    ProcessExitProven,
    Unknown
});
wire_enum!(CancelFailure {
    Timeout,
    Rejected,
    TransportLost,
    InvalidReply
});
wire_enum!(AuthorizationDecisionKind {
    Allow,
    Deny,
    ReadOnly
});

impl DriverMode {
    pub fn driver_id(self) -> ExecutorDriverId {
        match self {
            Self::DshHeadless | Self::DshManagedTeam | Self::DshManagedWorkflow => {
                ExecutorDriverId::Dsh
            }
            Self::ClaudeLeaf | Self::ClaudeInteractiveTeam | Self::ClaudeSavedWorkflow => {
                ExecutorDriverId::ClaudeCode
            }
        }
    }

    pub fn execution_kind(self) -> ExecutionKind {
        match self {
            Self::DshHeadless | Self::ClaudeLeaf => ExecutionKind::ManagedLeaf,
            Self::DshManagedTeam | Self::ClaudeInteractiveTeam => ExecutionKind::NativeTeamCapsule,
            Self::DshManagedWorkflow | Self::ClaudeSavedWorkflow => {
                ExecutionKind::NativeWorkflowCapsule
            }
        }
    }
}

fn invalid(message: &str) -> DomainError {
    DomainError::new("CAPSULE_VALIDATION_ERROR", message)
}
fn identity(value: &str, limit: usize) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > limit || value.contains('\0') || value.trim().is_empty() {
        return Err(invalid("identity is empty, too large or contains NUL"));
    }
    Ok(())
}
fn digest(value: &str) -> Result<(), DomainError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("expected lowercase SHA256"));
    }
    Ok(())
}
fn positive(value: u64) -> Result<(), DomainError> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(invalid("positive database BIGINT required"));
    }
    Ok(())
}
fn artifact(value: &ArtifactRef) -> Result<(), DomainError> {
    identity(&value.artifact_id, 512)?;
    if value.artifact_id.starts_with('/')
        || value.artifact_id.starts_with('\\')
        || value.artifact_id.as_bytes().get(1) == Some(&b':')
    {
        return Err(invalid(
            "artifact reference cannot be an absolute runtime path",
        ));
    }
    digest(&value.sha256)
}
fn machine_code(value: &str) -> Result<(), DomainError> {
    identity(value, 128)?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(invalid("bounded uppercase machine reason code required"));
    }
    Ok(())
}
fn capsule_id(value: &str, attempt: &str) -> Result<(), DomainError> {
    identity(value, 520)?;
    if value.strip_prefix("capsule:") != Some(attempt) {
        return Err(invalid("capsule identity differs from original attempt"));
    }
    Ok(())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvelopeRef {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub sha256: String,
}
impl ExecutionEnvelopeRef {
    /// Identity reference only; this performs no lease lookup or admission.
    pub fn from_envelope(envelope: &ExecutionEnvelope) -> Result<Self, DomainError> {
        envelope.validate()?;
        let reference = Self {
            project_id: envelope.project_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            generation: envelope.generation,
            sha256: hash(
                &serde_json::to_vec(envelope)
                    .map_err(|_| invalid("envelope serialization failed"))?,
            ),
        };
        reference.validate()?;
        Ok(reference)
    }
    pub fn validate(&self) -> Result<(), DomainError> {
        identity(&self.project_id, 512)?;
        identity(&self.attempt_id, 512)?;
        if self.generation <= 0 {
            return Err(invalid("positive generation required"));
        }
        digest(&self.sha256)
    }
    /// Caller supplies the authoritative frozen envelope, never a client replacement.
    pub fn validate_against(&self, envelope: &ExecutionEnvelope) -> Result<(), DomainError> {
        self.validate()?;
        if self != &Self::from_envelope(envelope)? {
            return Err(invalid("frozen execution envelope identity differs"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleBinding {
    pub schema_version: String,
    pub capsule_id: String,
    pub envelope_ref: ExecutionEnvelopeRef,
    pub driver_id: ExecutorDriverId,
    pub execution_kind: ExecutionKind,
    pub executor_profile_sha256: String,
    pub qualification_ref: ArtifactRef,
    pub team_write_policy: TeamWritePolicy,
}
impl CapsuleBinding {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != CAPSULE_SCHEMA_V1 {
            return Err(invalid("unsupported capsule schema"));
        }
        self.envelope_ref.validate()?;
        capsule_id(&self.capsule_id, &self.envelope_ref.attempt_id)?;
        digest(&self.executor_profile_sha256)?;
        artifact(&self.qualification_ref)
    }
    /// Compares frozen inputs, not current authorization or external evidence truth.
    pub fn validate_against(
        &self,
        envelope: &ExecutionEnvelope,
        expected_profile_sha256: &str,
    ) -> Result<(), DomainError> {
        self.validate()?;
        self.envelope_ref.validate_against(envelope)?;
        digest(expected_profile_sha256)?;
        if self.executor_profile_sha256 != expected_profile_sha256 {
            return Err(invalid("executor profile digest differs"));
        }
        if self.team_write_policy == TeamWritePolicy::ReadOnly
            && (!envelope.write_set.is_empty()
                || envelope
                    .allowed_effects
                    .contains(&AllowedEffect::WriteDeclaredPaths))
        {
            return Err(invalid("read-only capsule cannot carry write authority"));
        }
        Ok(())
    }
    /// Compatibility of observation metadata; NOT a qualification/admission gate.
    pub fn validate_probe_binding(&self, probe: &DriverProbeResult) -> Result<(), DomainError> {
        self.validate()?;
        probe.validate()?;
        if self.driver_id != probe.driver_id
            || self.execution_kind != probe.mode.execution_kind()
            || probe.executor_profile_sha256.as_deref()
                != Some(self.executor_profile_sha256.as_str())
        {
            return Err(invalid("probe mode, driver or frozen profile differs"));
        }
        Ok(())
    }
}

/// An external session observation carries no Attempt, lease or launch permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveOnlyBinding {
    pub schema_version: String,
    pub observation_id: String,
    pub project_id: String,
    pub driver_id: ExecutorDriverId,
    pub executor_profile_sha256: Option<String>,
    pub native_session_id: String,
    pub registered_at: DateTime<Utc>,
}
impl ObserveOnlyBinding {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != NATIVE_OBSERVATION_BINDING_SCHEMA_V1 {
            return Err(invalid("unsupported observe-only binding schema"));
        }
        identity(&self.observation_id, 512)?;
        identity(&self.project_id, 512)?;
        native_session(&self.native_session_id)?;
        if let Some(profile) = &self.executor_profile_sha256 {
            digest(profile)?;
        }
        Ok(())
    }
}
fn native_session(value: &str) -> Result<(), DomainError> {
    // Existing PostgreSQL constraint uses character length, not UTF-8 bytes.
    if value.is_empty()
        || value.chars().count() > 256
        || value.contains('\0')
        || value.trim().is_empty()
    {
        return Err(invalid("bounded native session identity required"));
    }
    Ok(())
}

/// Projection of an existing lifecycle, not evidence that the row is live/HELD.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleRef {
    pub driver_id: ExecutorDriverId,
    pub executor_profile_sha256: String,
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub native_session_id: String,
    pub allocation_id: String,
    pub lifecycle_number: u64,
    pub parent_allocation_id: Option<String>,
}
impl NativeLifecycleRef {
    pub fn validate_against(
        &self,
        envelope: &ExecutionEnvelope,
        capsule: &CapsuleBinding,
    ) -> Result<(), DomainError> {
        capsule.validate_against(envelope, &self.executor_profile_sha256)?;
        native_session(&self.native_session_id)?;
        identity(&self.worker_id, 512)?;
        identity(&self.allocation_id, 512)?;
        positive(self.lifecycle_number)?;
        if self.driver_id != capsule.driver_id
            || self.project_id != envelope.project_id
            || self.attempt_id != envelope.attempt_id
            || self.generation != envelope.generation
            || self.worker_id != envelope.worker_id
        {
            return Err(invalid(
                "native lifecycle namespace differs from frozen attempt",
            ));
        }
        if let Some(parent) = &self.parent_allocation_id {
            identity(parent, 512)?;
            if parent == &self.allocation_id {
                return Err(invalid("native lifecycle cannot parent itself"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCheck {
    pub check_id: CapabilityId,
    pub status: VerificationStatus,
    pub scope: String,
    pub reason_code: Option<String>,
    pub evidence_refs: Vec<ArtifactRef>,
}
impl CapabilityCheck {
    pub fn validate(&self) -> Result<(), DomainError> {
        identity(&self.scope, 2048)?;
        if let Some(reason) = &self.reason_code {
            machine_code(reason)?;
        }
        if self.evidence_refs.len() > MAX_EVIDENCE_REFS
            || (self.status == VerificationStatus::Verified && self.evidence_refs.is_empty())
        {
            return Err(invalid("verified check needs bounded evidence references"));
        }
        let mut seen = BTreeSet::new();
        for reference in &self.evidence_refs {
            artifact(reference)?;
            if !seen.insert(&reference.artifact_id) {
                return Err(invalid("duplicate or conflicting check artifact identity"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverProbeResult {
    pub schema_version: String,
    pub probe_id: String,
    pub driver_id: ExecutorDriverId,
    pub mode: DriverMode,
    pub observed_at: DateTime<Utc>,
    pub executable_sha256: Option<String>,
    pub artifact_pins_ref: Option<ArtifactRef>,
    pub executor_profile_sha256: Option<String>,
    pub cli_version: Option<String>,
    pub capabilities: ExecutorCapabilities,
    pub checks: Vec<CapabilityCheck>,
    pub environment_ref: ArtifactRef,
    pub command_results_ref: ArtifactRef,
    pub evidence_class: EvidenceClass,
}
impl DriverProbeResult {
    /// Validates evidence metadata, not whether evidence proves a runtime claim.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != DRIVER_PROBE_SCHEMA_V1 || self.driver_id != self.mode.driver_id()
        {
            return Err(invalid(
                "unsupported probe schema or mismatched driver/mode",
            ));
        }
        identity(&self.probe_id, 512)?;
        if let Some(value) = &self.executable_sha256 {
            digest(value)?;
        }
        if let Some(value) = &self.executor_profile_sha256 {
            digest(value)?;
        }
        if let Some(value) = &self.artifact_pins_ref {
            artifact(value)?;
        }
        if let Some(value) = &self.cli_version {
            identity(value, 512)?;
        }
        identity(&self.capabilities.adapter_contract_version, 512)?;
        identity(&self.capabilities.protocol, 512)?;
        if let Some(value) = &self.capabilities.protocol_version {
            identity(value, 512)?;
        }
        identity(&self.capabilities.usage_accounting, 512)?;
        identity(&self.capabilities.nested_spawn_control, 512)?;
        artifact(&self.environment_ref)?;
        artifact(&self.command_results_ref)?;
        if self.checks.len() > MAX_CAPABILITY_CHECKS {
            return Err(invalid("too many probe checks"));
        }
        let mut seen = BTreeSet::new();
        for check in &self.checks {
            check.validate()?;
            if !seen.insert(check.check_id) {
                return Err(invalid("duplicate capability check"));
            }
            if check.status != VerificationStatus::Verified {
                continue;
            }
            if self.evidence_class == EvidenceClass::Unknown {
                return Err(invalid("unknown evidence cannot verify a capability"));
            }
            if matches!(
                check.check_id,
                CapabilityId::StartHeadless
                    | CapabilityId::NativeTeam
                    | CapabilityId::NativeWorkflow
                    | CapabilityId::BusinessE2e
            ) && self.evidence_class != EvidenceClass::RealModel
            {
                return Err(invalid(
                    "real runtime qualification cannot come from fixture or process-only evidence",
                ));
            }
            if self.evidence_class == EvidenceClass::NoModelFixture
                && !matches!(
                    check.check_id,
                    CapabilityId::ExecutableIdentity
                        | CapabilityId::VersionHelp
                        | CapabilityId::ProcessCancel
                        | CapabilityId::TranscriptReplay
                )
            {
                return Err(invalid(
                    "NoModel fixture cannot verify native runtime capabilities",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventObservation {
    pub schema_version: String,
    pub driver_id: ExecutorDriverId,
    pub capsule_id: String,
    pub executor_profile_sha256: String,
    pub stream_id: String,
    pub stream_seq: u64,
    pub native_seq: Option<String>,
    pub native_session_id: Option<String>,
    pub allocation_id: Option<String>,
    pub lifecycle_number: Option<u64>,
    pub native_member_id: Option<String>,
    pub native_task_id: Option<String>,
    pub occurred_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub kind: NativeEventKind,
    pub source_ref: ArtifactRef,
    pub frame_offset: u64,
    pub frame_length: u64,
    pub raw_sha256: String,
    pub payload_ref: Option<ArtifactRef>,
    pub summary: Value,
    pub parse_error: Option<String>,
    pub evidence_class: EvidenceClass,
}
impl NativeEventObservation {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != NATIVE_EVENT_SCHEMA_V1 {
            return Err(invalid("unsupported native event schema"));
        }
        identity(&self.capsule_id, 520)?;
        identity(&self.stream_id, 512)?;
        positive(self.stream_seq)?;
        digest(&self.executor_profile_sha256)?;
        if let Some(value) = &self.native_seq {
            identity(value, 512)?;
        }
        if let Some(value) = &self.native_session_id {
            native_session(value)?;
        }
        for value in [
            &self.native_member_id,
            &self.native_task_id,
            &self.allocation_id,
        ]
        .into_iter()
        .flatten()
        {
            identity(value, 512)?;
        }
        if self.allocation_id.is_some() != self.lifecycle_number.is_some()
            || (self.allocation_id.is_some() && self.native_session_id.is_none())
        {
            return Err(invalid(
                "native allocation needs exact session and lifecycle together",
            ));
        }
        if let Some(value) = self.lifecycle_number {
            positive(value)?;
        }
        artifact(&self.source_ref)?;
        if let Some(value) = &self.payload_ref {
            artifact(value)?;
        }
        digest(&self.raw_sha256)?;
        if self.frame_length == 0
            || self.frame_offset.checked_add(self.frame_length).is_none()
            || self.frame_offset + self.frame_length > i64::MAX as u64
        {
            return Err(invalid("invalid or overflowing raw frame range"));
        }
        let object = self
            .summary
            .as_object()
            .ok_or_else(|| invalid("event summary must be an object"))?;
        if serde_json::to_vec(&self.summary)
            .map_err(|_| invalid("summary serialization failed"))?
            .len()
            > NATIVE_EVENT_SUMMARY_MAX_BYTES
        {
            return Err(invalid(
                "event summary exceeds 16KiB; use an artifact reference",
            ));
        }
        if [
            "event_id",
            "project_id",
            "attempt_id",
            "lease_id",
            "generation",
            "worker_id",
        ]
        .iter()
        .any(|key| object.contains_key(*key))
        {
            return Err(invalid(
                "event summary cannot override outer WorkerEvent identity",
            ));
        }
        if let Some(value) = &self.parse_error {
            machine_code(value)?;
        }
        if self.kind == NativeEventKind::StopObserved {
            serde_json::from_value::<CancelObservation>(self.summary.clone())
                .map_err(|_| invalid("STOP_OBSERVED needs strict CancelObservation"))?
                .validate_shape()?;
        }
        Ok(())
    }
    /// Checks two observations from one known stream. The caller still owns
    /// durable cursors, duplicate ACKs and gap recovery; no cursor is mutated.
    pub fn validate_successor_of(&self, previous: &Self) -> Result<(), DomainError> {
        self.validate()?;
        previous.validate()?;
        if self.driver_id != previous.driver_id
            || self.capsule_id != previous.capsule_id
            || self.executor_profile_sha256 != previous.executor_profile_sha256
            || self.stream_id != previous.stream_id
            || previous.stream_seq.checked_add(1) != Some(self.stream_seq)
        {
            return Err(invalid(
                "native stream changed, repeated or has a sequence gap",
            ));
        }
        Ok(())
    }
    /// Metadata association only. This does not accept an event, grant a child,
    /// establish that its lifecycle is live, or advance canonical state.
    pub fn validate_binding(
        &self,
        outer: &WorkerEvent,
        envelope: &ExecutionEnvelope,
        capsule: &CapsuleBinding,
    ) -> Result<(), DomainError> {
        self.validate()?;
        capsule.validate_against(envelope, &self.executor_profile_sha256)?;
        identity(&outer.event_id, 512)?;
        if self.capsule_id != capsule.capsule_id
            || self.driver_id != capsule.driver_id
            || outer.project_id != envelope.project_id
            || outer.attempt_id != envelope.attempt_id
            || outer.lease_id != envelope.lease_id
            || outer.generation != envelope.generation
            || outer.worker_id != envelope.worker_id
        {
            return Err(invalid(
                "native event differs from outer frozen execution identity",
            ));
        }
        if outer.payload
            != serde_json::to_value(self)
                .map_err(|_| invalid("native projection serialization failed"))?
        {
            return Err(invalid("outer WorkerEvent payload differs from projection"));
        }
        Ok(())
    }
    /// Offline byte-identity verification; storage authorization and event truth
    /// remain the caller's responsibility. Raw bytes are never reserialized.
    pub fn validate_raw_frame(&self, source_bytes: &[u8]) -> Result<(), DomainError> {
        self.validate()?;
        if hash(source_bytes) != self.source_ref.sha256 {
            return Err(invalid("raw source artifact digest differs"));
        }
        let start = usize::try_from(self.frame_offset)
            .map_err(|_| invalid("raw frame offset exceeds host size"))?;
        let end = usize::try_from(self.frame_offset + self.frame_length)
            .map_err(|_| invalid("raw frame end exceeds host size"))?;
        let frame = source_bytes
            .get(start..end)
            .ok_or_else(|| invalid("raw frame is outside source artifact"))?;
        if hash(frame) != self.raw_sha256 {
            return Err(invalid("raw frame digest differs"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelObservation {
    pub request_id: String,
    pub phase: CancelPhase,
    pub failure: Option<CancelFailure>,
    pub evidence_ref: Option<ArtifactRef>,
}
impl CancelObservation {
    /// Shape only: PROCESS_EXIT_PROVEN is a claim until trusted Worker/Store
    /// verifies the referenced physical evidence. ACK never proves termination.
    pub fn validate_shape(&self) -> Result<(), DomainError> {
        identity(&self.request_id, 512)?;
        if let Some(value) = &self.evidence_ref {
            artifact(value)?;
        }
        if (self.phase == CancelPhase::ProcessExitProven && self.evidence_ref.is_none())
            || (self.failure.is_some() && self.phase != CancelPhase::Unknown)
        {
            return Err(invalid(
                "cancel phase contradicts failure or lacks stop evidence reference",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAuthorizationRequest {
    pub envelope_ref: ExecutionEnvelopeRef,
    pub capsule_id: String,
    pub requested_effect: AllowedEffect,
    pub requested_paths: Vec<String>,
    pub native_allocation_id: Option<String>,
}
impl WriteAuthorizationRequest {
    /// Static scope comparison only; success is NOT a write/launch permission.
    /// No filesystem, current lease, Owner or resource checks happen here.
    pub fn validate_against(&self, envelope: &ExecutionEnvelope) -> Result<(), DomainError> {
        self.envelope_ref.validate_against(envelope)?;
        capsule_id(&self.capsule_id, &envelope.attempt_id)?;
        if !envelope.allowed_effects.contains(&self.requested_effect)
            || self.requested_paths.len() > CAPSULE_MAX_REQUESTED_PATHS
        {
            return Err(invalid(
                "requested effect or path count exceeds frozen envelope",
            ));
        }
        if let Some(value) = &self.native_allocation_id {
            identity(value, 512)?;
        }
        let mut seen = BTreeSet::new();
        for path in &self.requested_paths {
            identity(path, 4096)?;
            crate::validate_relative_path(path)?;
            let normalized = path.trim_end_matches('/');
            if !seen.insert(normalized) {
                return Err(invalid("duplicate requested path"));
            }
            if self.requested_effect == AllowedEffect::WriteDeclaredPaths
                && !envelope.write_set.iter().any(|scope| {
                    let scope = scope.trim_end_matches('/');
                    normalized == scope
                        || normalized
                            .strip_prefix(scope)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
            {
                return Err(invalid(
                    "requested write is outside declared path components",
                ));
            }
        }
        if self.requested_effect == AllowedEffect::WriteDeclaredPaths
            && self.requested_paths.is_empty()
        {
            return Err(invalid("write request needs explicit paths"));
        }
        Ok(())
    }
}

/// Explanation supplied by a trusted service. Deserializing or validating an
/// ALLOW value never grants authority. No method here computes ALLOW.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAuthorizationDecision {
    pub schema_version: String,
    pub envelope_ref: ExecutionEnvelopeRef,
    pub attempt_revision: u64,
    pub decision: AuthorizationDecisionKind,
    pub reason_codes: Vec<String>,
    pub team_write_policy: TeamWritePolicy,
    pub guard_receipt_ref: Option<ArtifactRef>,
    pub checked_at: DateTime<Utc>,
    pub operation_id: String,
}
impl WriteAuthorizationDecision {
    /// Shape only; Store must re-check authority at action time, including a
    /// previously returned ALLOW. This DTO is not a replayable bearer ticket.
    pub fn validate_shape(&self) -> Result<(), DomainError> {
        if self.schema_version != WRITE_AUTHORIZATION_SCHEMA_V1 {
            return Err(invalid("unsupported authorization explanation schema"));
        }
        self.envelope_ref.validate()?;
        positive(self.attempt_revision)?;
        identity(&self.operation_id, 512)?;
        if self.reason_codes.is_empty() || self.reason_codes.len() > 32 {
            return Err(invalid("bounded authorization reason codes required"));
        }
        let mut seen = BTreeSet::new();
        for code in &self.reason_codes {
            machine_code(code)?;
            if !seen.insert(code) {
                return Err(invalid("duplicate authorization reason code"));
            }
        }
        if let Some(value) = &self.guard_receipt_ref {
            artifact(value)?;
        }
        Ok(())
    }
}
