//! Offline projection of bounded, caller-captured discovery. No process or model launches.
use crate::{ClaudeLeafProfile, ExecutorError, sha256};
use forgeflow_domain::{
    ArtifactRef, CapabilityCheck, CapabilityId, DriverMode, DriverProbeResult, EvidenceClass,
    ExecutorCapabilities, ExecutorDriverId, VerificationStatus,
};

/// The trusted caller captures version/help using its bounded process runner and
/// stores original commands/output before invoking this projection. These are
/// discovery observations, never an execution or qualification token.
#[derive(Debug)]
pub struct ClaudeDiscoveryEvidence {
    pub probe_id: String,
    pub version_stdout: Vec<u8>,
    pub version_exit_code: Option<i32>,
    pub help_stdout: Vec<u8>,
    pub help_exit_code: Option<i32>,
    pub artifact_pins_ref: Option<ArtifactRef>,
    pub environment_ref: ArtifactRef,
    pub command_results_ref: ArtifactRef,
}

pub fn claude_doctor(
    profile: &ClaudeLeafProfile,
    evidence: ClaudeDiscoveryEvidence,
) -> Result<DriverProbeResult, ExecutorError> {
    profile.verify_identity()?;
    if evidence.version_stdout.len() > 4096 || evidence.help_stdout.len() > 131072 {
        return Err(ExecutorError::Unsupported(
            "discovery output exceeds bounded receipt limit".into(),
        ));
    }
    let version = std::str::from_utf8(&evidence.version_stdout)
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 512 && !s.contains('\0'));
    let help = std::str::from_utf8(&evidence.help_stdout).ok();
    let help_matches = help.is_some_and(|help| {
        profile.help_verified_flags.iter().all(|flag| {
            help.split_whitespace()
                .any(|word| word.trim_matches(',') == flag)
        })
    });
    let discovery_ok = evidence.version_exit_code == Some(0)
        && evidence.help_exit_code == Some(0)
        && version.is_some()
        && help_matches;
    let all = [
        CapabilityId::ExecutableIdentity,
        CapabilityId::VersionHelp,
        CapabilityId::StartHeadless,
        CapabilityId::StructuredEvents,
        CapabilityId::SessionResume,
        CapabilityId::SessionCancel,
        CapabilityId::ProcessCancel,
        CapabilityId::SessionClose,
        CapabilityId::TranscriptReplay,
        CapabilityId::NativeTeam,
        CapabilityId::NativeWorkflow,
        CapabilityId::NativeMessaging,
        CapabilityId::SupervisedChildren,
        CapabilityId::ModelEgressEnforced,
        CapabilityId::VerifiedWriteIsolation,
        CapabilityId::UsageAccounting,
        CapabilityId::BusinessE2e,
    ];
    let checks = all.into_iter().map(|check_id| {
        let (status, scope, reason) = match check_id {
            CapabilityId::ExecutableIdentity => (VerificationStatus::Verified,
                "Exact executable/profile artifact pins readable and matched; no model launch", None),
            CapabilityId::VersionHelp if discovery_ok => (VerificationStatus::Verified,
                "Caller-captured bounded version/help receipts for pinned CLI; discovery only", None),
            CapabilityId::VersionHelp => (VerificationStatus::Failed,
                "Version/help receipt failed or does not cover profile flags", Some("DISCOVERY_RECEIPT_REJECTED")),
            _ => (VerificationStatus::NotRun, "No actual CLI session, model, isolation or business workload executed by offline Doctor",
                Some("RUNTIME_QUALIFICATION_NOT_RUN")),
        };
        CapabilityCheck { check_id, status, scope: scope.into(), reason_code: reason.map(str::to_owned),
            evidence_refs: if status == VerificationStatus::Verified { vec![evidence.command_results_ref.clone()] } else { Vec::new() } }
    }).collect();
    let result = DriverProbeResult {
        schema_version: "forgeflow.driver-probe.v1".into(),
        probe_id: evidence.probe_id,
        driver_id: ExecutorDriverId::ClaudeCode,
        mode: DriverMode::ClaudeLeaf,
        observed_at: chrono::Utc::now(),
        executable_sha256: Some(super::claude::hash_file(&profile.program)?),
        artifact_pins_ref: evidence.artifact_pins_ref,
        executor_profile_sha256: Some(sha256(
            &serde_json::to_vec(profile)
                .map_err(|_| ExecutorError::Identity("profile serialization failed".into()))?,
        )),
        cli_version: if evidence.version_exit_code == Some(0) {
            version.map(str::to_owned)
        } else {
            None
        },
        capabilities: ExecutorCapabilities {
            adapter_contract_version: "forgeflow.executor.claude-leaf.v1".into(),
            protocol: "CLAUDE_STREAM_JSON".into(),
            protocol_version: None,
            structured_events: false,
            session_resume: false,
            session_cancel: false,
            process_cancel: false,
            session_close: false,
            usage_accounting: "UNVERIFIED_PROVIDER_REPORTED".into(),
            transcript_replay: false,
            nested_spawn_control: "UNVERIFIED".into(),
        },
        checks,
        environment_ref: evidence.environment_ref,
        command_results_ref: evidence.command_results_ref,
        evidence_class: EvidenceClass::LocalProcess,
    };
    result
        .validate()
        .map_err(|e| ExecutorError::Identity(e.to_string()))?;
    Ok(result)
}
