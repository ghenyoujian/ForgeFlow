//! Claude Native Team boundary. Claude leaf support never implies Team support.
use crate::ExecutorError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeTeamContract {
    pub profile_id: String,
    pub native_team_id: Option<String>,
    pub evidence_status: String,
    pub support_status: String,
}

impl ClaudeTeamContract {
    pub fn require_qualified(&self) -> Result<(), ExecutorError> {
        if self.profile_id.trim().is_empty()
            || self
                .native_team_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(ExecutorError::Identity(
                "Claude Native Team receipt is missing immutable identity".into(),
            ));
        }
        Err(ExecutorError::Unsupported(
            "Claude Native Team is not qualified for the current profile".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_team_identity_is_checked_before_unsupported_boundary() {
        let value = ClaudeTeamContract {
            profile_id: "claude-profile".into(),
            native_team_id: Some("team-1".into()),
            evidence_status: "NOT_RUN".into(),
            support_status: "UNKNOWN".into(),
        };
        assert!(matches!(
            value.require_qualified(),
            Err(ExecutorError::Unsupported(_))
        ));
        let invalid = ClaudeTeamContract {
            native_team_id: None,
            ..value
        };
        assert!(matches!(
            invalid.require_qualified(),
            Err(ExecutorError::Identity(_))
        ));
    }
}
