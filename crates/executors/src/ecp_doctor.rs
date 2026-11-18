//! ECP executor Doctor projection. Discovery is evidence, never runtime
//! qualification. Provider execution stays owned by Worker.
use crate::ExecutorError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DoctorStatus {
    Verified,
    Failed,
    NotRun,
    Blocked,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcpDoctorCheck {
    pub capability: String,
    pub status: DoctorStatus,
    pub reason_code: Option<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcpDoctorReceipt {
    pub schema_version: String,
    pub profile_id: String,
    pub provider: String,
    pub profile_sha256: String,
    pub binary_sha256: Option<String>,
    pub evidence_class: String,
    pub checks: Vec<EcpDoctorCheck>,
    pub qualification: String,
}

impl EcpDoctorReceipt {
    /// Validate a receipt before it can influence executor admission.
    ///
    /// Discovery output is deliberately a data contract, not a capability
    /// grant.  A receipt claiming a verified capability must carry a real
    /// model evidence class and at least one safe, relative evidence ref;
    /// malformed or path-traversing refs are rejected before scheduling.
    pub fn validate_for_admission(&self) -> Result<(), ExecutorError> {
        const CAPABILITIES: [&str; 11] = [
            "managed_leaf",
            "subagent",
            "native_team",
            "workflow",
            "bot",
            "session_resume",
            "cancel",
            "structured_events",
            "child_supervision",
            "write_isolation",
            "cost_enforcement",
        ];
        if self.schema_version != "forgeflow.ecp-doctor.v1"
            || self.profile_id.trim().is_empty()
            || self.provider.trim().is_empty()
            || !is_sha256(&self.profile_sha256)
        {
            return Err(ExecutorError::Identity(
                "invalid ECP Doctor receipt identity".into(),
            ));
        }
        if self
            .binary_sha256
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(ExecutorError::Identity(
                "invalid ECP Doctor binary digest".into(),
            ));
        }
        if !matches!(
            self.evidence_class.as_str(),
            "OFFLINE_DISCOVERY" | "REAL_MODEL"
        ) {
            return Err(ExecutorError::Unsupported(
                "unknown ECP Doctor evidence class".into(),
            ));
        }
        if !matches!(
            self.qualification.as_str(),
            "NOT_RUN" | "VERIFIED" | "FAILED" | "INCONCLUSIVE" | "BLOCKED"
        ) {
            return Err(ExecutorError::Unsupported(
                "unknown ECP Doctor qualification".into(),
            ));
        }
        let names: Vec<&str> = self
            .checks
            .iter()
            .map(|check| check.capability.as_str())
            .collect();
        let expected: BTreeSet<&str> = CAPABILITIES.into_iter().collect();
        let actual: BTreeSet<&str> = names.iter().copied().collect();
        if names.len() != actual.len() || actual != expected {
            return Err(ExecutorError::Unsupported(
                "ECP Doctor capability matrix is incomplete or duplicated".into(),
            ));
        }
        let mut verified = 0usize;
        for check in &self.checks {
            let refs = &check.evidence_refs;
            let mut unique_refs = BTreeSet::new();
            for reference in refs {
                let path = std::path::Path::new(reference);
                if path.is_absolute()
                    || path
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir))
                    || !unique_refs.insert(reference)
                {
                    return Err(ExecutorError::Identity(
                        "unsafe or duplicate ECP Doctor evidence ref".into(),
                    ));
                }
            }
            match check.status {
                DoctorStatus::Verified => {
                    verified += 1;
                    if refs.is_empty() {
                        return Err(ExecutorError::Unsupported(
                            "verified ECP Doctor capability lacks evidence".into(),
                        ));
                    }
                }
                _ if check.reason_code.is_none() => {
                    return Err(ExecutorError::Unsupported(
                        "non-verified ECP Doctor capability lacks reason code".into(),
                    ));
                }
                _ => {}
            }
        }
        if self.qualification == "VERIFIED"
            && (self.evidence_class != "REAL_MODEL" || verified != self.checks.len())
        {
            return Err(ExecutorError::Unsupported(
                "verified ECP Doctor receipt is not backed by complete real-model evidence".into(),
            ));
        }
        if self.evidence_class == "OFFLINE_DISCOVERY" && verified > 0 {
            return Err(ExecutorError::Unsupported(
                "offline ECP Doctor discovery cannot verify capabilities".into(),
            ));
        }
        Ok(())
    }

    pub fn offline_unknown(
        profile_id: impl Into<String>,
        provider: impl Into<String>,
        profile_sha256: String,
    ) -> Self {
        let capabilities = [
            "managed_leaf",
            "subagent",
            "native_team",
            "workflow",
            "bot",
            "session_resume",
            "cancel",
            "structured_events",
            "child_supervision",
            "write_isolation",
            "cost_enforcement",
        ];
        Self {
            schema_version: "forgeflow.ecp-doctor.v1".into(),
            profile_id: profile_id.into(),
            provider: provider.into(),
            profile_sha256,
            binary_sha256: None,
            evidence_class: "OFFLINE_DISCOVERY".into(),
            checks: capabilities
                .into_iter()
                .map(|capability| EcpDoctorCheck {
                    capability: capability.into(),
                    status: if capability == "managed_leaf" {
                        DoctorStatus::NotRun
                    } else {
                        DoctorStatus::NotRun
                    },
                    reason_code: Some("RUNTIME_QUALIFICATION_NOT_RUN".into()),
                    evidence_refs: Vec::new(),
                })
                .collect(),
            qualification: "NOT_RUN".into(),
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> EcpDoctorReceipt {
        EcpDoctorReceipt::offline_unknown("profile", "dsh", "a".repeat(64))
    }

    #[test]
    fn offline_discovery_is_valid_but_cannot_verify_capabilities() {
        assert!(receipt().validate_for_admission().is_ok());
    }

    #[test]
    fn verified_receipt_requires_real_model_evidence_and_refs() {
        let mut value = receipt();
        value.qualification = "VERIFIED".into();
        value.evidence_class = "REAL_MODEL".into();
        for check in &mut value.checks {
            check.status = DoctorStatus::Verified;
            check.reason_code = None;
            check.evidence_refs = vec!["receipts/run.json".into()];
        }
        assert!(value.validate_for_admission().is_ok());
    }

    #[test]
    fn unsafe_evidence_ref_is_rejected() {
        let mut value = receipt();
        value.checks[0].evidence_refs = vec!["../outside.json".into()];
        assert!(value.validate_for_admission().is_err());
    }

    #[test]
    fn incomplete_or_duplicate_capability_matrix_is_rejected() {
        let mut value = receipt();
        value.checks.pop();
        assert!(value.validate_for_admission().is_err());
        let mut value = receipt();
        value.checks[1].capability = value.checks[0].capability.clone();
        assert!(value.validate_for_admission().is_err());
    }
}
