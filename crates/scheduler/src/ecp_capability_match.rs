//! Fail-closed capability matching. A scheduler candidate may be selected
//! only when the frozen profile identity and current evidence satisfy the
//! requested mode; discovery-only rows never become executable capacity.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityMatchRequest {
    pub workspace_id: String,
    pub project_id: String,
    pub profile_id: String,
    pub profile_sha256: String,
    /// Optional digest observed by the worker immediately before launch. When
    /// present it must equal the frozen profile digest; omission is allowed
    /// for discovery-only planning and never upgrades evidence by itself.
    #[serde(default)]
    pub observed_profile_sha256: Option<String>,
    pub requested_mode: String,
    pub required_capabilities: Vec<String>,
    pub profile_support_status: String,
    pub profile_evidence_status: String,
    pub profile_workspace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityMatchStatus {
    Admitted,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityMatchDecision {
    pub status: CapabilityMatchStatus,
    pub reason_code: String,
    pub profile_id: String,
}

pub fn match_profile(
    input: &CapabilityMatchRequest,
    available: &[String],
) -> CapabilityMatchDecision {
    let mut decision = CapabilityMatchDecision {
        status: CapabilityMatchStatus::Blocked,
        reason_code: "PROFILE_NOT_ADMISSIBLE".into(),
        profile_id: input.profile_id.clone(),
    };
    if input.workspace_id != input.profile_workspace_id {
        decision.reason_code = "WORKSPACE_SCOPE_MISMATCH".into();
        return decision;
    }
    if input.profile_sha256.len() != 64
        || !input
            .profile_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        decision.reason_code = "PROFILE_DIGEST_INVALID".into();
        return decision;
    }
    if let Some(observed) = &input.observed_profile_sha256 {
        if observed.len() != 64
            || !observed
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            decision.reason_code = "OBSERVED_PROFILE_DIGEST_INVALID".into();
            return decision;
        }
        if observed != &input.profile_sha256 {
            decision.reason_code = "PROFILE_DRIFT".into();
            return decision;
        }
    }
    if input.profile_support_status == "UNKNOWN" || input.profile_evidence_status == "NOT_RUN" {
        decision.status = CapabilityMatchStatus::Unknown;
        decision.reason_code = "PROFILE_EVIDENCE_NOT_RUN".into();
        return decision;
    }
    if input.requested_mode.trim().is_empty() {
        decision.reason_code = "REQUESTED_MODE_INVALID".into();
        return decision;
    }
    if !available
        .iter()
        .any(|capability| capability == &input.requested_mode)
    {
        decision.reason_code = "REQUESTED_MODE_UNAVAILABLE".into();
        return decision;
    }
    if input.profile_support_status != "SUPPORTED" || input.profile_evidence_status != "VERIFIED" {
        decision.reason_code = "PROFILE_SUPPORT_NOT_VERIFIED".into();
        return decision;
    }
    if input
        .required_capabilities
        .iter()
        .any(|capability| !available.iter().any(|item| item == capability))
    {
        decision.reason_code = "CAPABILITY_MISSING".into();
        return decision;
    }
    decision.status = CapabilityMatchStatus::Admitted;
    decision.reason_code = "CURRENT_PROFILE_VERIFIED".into();
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> CapabilityMatchRequest {
        CapabilityMatchRequest {
            workspace_id: "w".into(),
            project_id: "p".into(),
            profile_id: "profile".into(),
            profile_sha256: "a".repeat(64),
            observed_profile_sha256: None,
            requested_mode: "managed_leaf".into(),
            required_capabilities: vec!["managed_leaf".into()],
            profile_support_status: "SUPPORTED".into(),
            profile_evidence_status: "VERIFIED".into(),
            profile_workspace_id: "w".into(),
        }
    }
    #[test]
    fn unknown_evidence_never_admits() {
        let mut value = input();
        value.profile_evidence_status = "NOT_RUN".into();
        assert_eq!(
            match_profile(&value, &["managed_leaf".into()]).status,
            CapabilityMatchStatus::Unknown
        );
        assert_eq!(
            match_profile(&value, &[]).status,
            CapabilityMatchStatus::Unknown
        );
    }
    #[test]
    fn verified_profile_admits_only_matching_scope_and_capabilities() {
        assert_eq!(
            match_profile(&input(), &["managed_leaf".into()]).status,
            CapabilityMatchStatus::Admitted
        );
    }
    #[test]
    fn requested_mode_is_an_explicit_capability_boundary() {
        let value = input();
        assert_eq!(
            match_profile(&value, &[]).reason_code,
            "REQUESTED_MODE_UNAVAILABLE"
        );
        let mut mismatched = input();
        mismatched.requested_mode = "native_team".into();
        assert_eq!(
            match_profile(&mismatched, &["managed_leaf".into()]).reason_code,
            "REQUESTED_MODE_UNAVAILABLE"
        );
    }
    #[test]
    fn observed_profile_drift_never_admits() {
        let mut value = input();
        value.observed_profile_sha256 = Some("b".repeat(64));
        let decision = match_profile(&value, &["managed_leaf".into()]);
        assert_eq!(decision.status, CapabilityMatchStatus::Blocked);
        assert_eq!(decision.reason_code, "PROFILE_DRIFT");
    }
    #[test]
    fn malformed_observed_digest_is_blocked_without_runtime_probe() {
        let mut value = input();
        value.observed_profile_sha256 = Some("unknown".into());
        let decision = match_profile(&value, &["managed_leaf".into()]);
        assert_eq!(decision.reason_code, "OBSERVED_PROFILE_DIGEST_INVALID");
    }
}
