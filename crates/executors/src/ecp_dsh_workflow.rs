//! DSH Workflow observation boundary. Workflow events do not create control
//! handles; cancellation/resume remain platform-authorized operations.
use crate::ExecutorError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DshWorkflowContract {
    pub profile_id: String,
    pub run_id: Option<String>,
    pub script_sha256: Option<String>,
    pub evidence_status: String,
}

impl DshWorkflowContract {
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
                "DSH Workflow receipt is missing immutable script identity".into(),
            ));
        }
        Err(ExecutorError::Unsupported(
            "DSH Workflow control requires a current provider receipt and script identity".into(),
        ))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> DshWorkflowContract {
        DshWorkflowContract {
            profile_id: "dsh-profile".into(),
            run_id: Some("run-1".into()),
            script_sha256: Some("a".repeat(64)),
            evidence_status: "NOT_RUN".into(),
        }
    }

    #[test]
    fn workflow_identity_is_validated_before_unsupported_boundary() {
        assert!(matches!(
            contract().require_qualified(),
            Err(ExecutorError::Unsupported(_))
        ));
        let mut value = contract();
        value.script_sha256 = Some("bad".into());
        assert!(matches!(
            value.require_qualified(),
            Err(ExecutorError::Identity(_))
        ));
    }
}
