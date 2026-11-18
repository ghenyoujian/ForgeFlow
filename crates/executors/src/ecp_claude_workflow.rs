//! Claude Workflow boundary. A leaf CLI result is not a Workflow receipt.
use crate::ExecutorError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeWorkflowContract {
    pub profile_id: String,
    pub run_id: Option<String>,
    pub script_sha256: Option<String>,
    pub evidence_status: String,
}

impl ClaudeWorkflowContract {
    pub fn require_qualified(&self) -> Result<(), ExecutorError> {
        if self.profile_id.trim().is_empty()
            || self
                .run_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            || self
                .script_sha256
                .as_deref()
                .is_none_or(|value| !is_sha256(value))
        {
            return Err(ExecutorError::Identity(
                "Claude Workflow receipt is missing immutable script identity".into(),
            ));
        }
        Err(ExecutorError::Unsupported(
            "Claude Workflow is not qualified for the current profile".into(),
        ))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_identity_is_required_even_when_provider_is_unsupported() {
        let value = ClaudeWorkflowContract {
            profile_id: "claude-profile".into(),
            run_id: Some("run-1".into()),
            script_sha256: Some("b".repeat(64)),
            evidence_status: "NOT_RUN".into(),
        };
        assert!(matches!(
            value.require_qualified(),
            Err(ExecutorError::Unsupported(_))
        ));
        let invalid = ClaudeWorkflowContract {
            script_sha256: Some("bad".into()),
            ..value
        };
        assert!(matches!(
            invalid.require_qualified(),
            Err(ExecutorError::Identity(_))
        ));
    }
}
