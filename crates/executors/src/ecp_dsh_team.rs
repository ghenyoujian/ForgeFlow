//! DSH Native Team boundary. Native lifecycle control is not inferred from
//! observed events; a current profile receipt is required before activation.
use crate::ExecutorError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DshTeamContract {
    pub profile_id: String,
    pub native_team_id: Option<String>,
    pub evidence_status: String,
    pub support_status: String,
}

impl DshTeamContract {
    pub fn require_qualified(&self) -> Result<(), ExecutorError> {
        if self.profile_id.trim().is_empty()
            || self
                .native_team_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(ExecutorError::Identity(
                "DSH Native Team receipt is missing immutable identity".into(),
            ));
        }
        if self.support_status != "SUPPORTED" || self.evidence_status != "VERIFIED" {
            return Err(ExecutorError::Unsupported(
                "DSH Native Team requires a current real-model qualification receipt".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> DshTeamContract {
        DshTeamContract {
            profile_id: "dsh-profile".into(),
            native_team_id: Some("team-1".into()),
            evidence_status: "NOT_RUN".into(),
            support_status: "UNKNOWN".into(),
        }
    }

    #[test]
    fn unqualified_team_receipt_is_unsupported() {
        assert!(contract().require_qualified().is_err());
    }

    #[test]
    fn missing_team_identity_is_rejected_before_qualification() {
        let mut value = contract();
        value.native_team_id = None;
        assert!(matches!(
            value.require_qualified(),
            Err(ExecutorError::Identity(_))
        ));
    }

    #[test]
    fn verified_team_requires_both_support_and_evidence() {
        let mut value = contract();
        value.evidence_status = "VERIFIED".into();
        value.support_status = "SUPPORTED".into();
        assert!(value.require_qualified().is_ok());
    }
}
