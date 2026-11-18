mod capsule;
mod commands;
mod decisions;
mod execution;
mod model;
mod releases;
pub use capsule::*;
pub use commands::*;
pub use decisions::{
    DECISION_INBOX_SCHEMA, Decision, DecisionBlockedTask, DecisionCause, DecisionCommand,
    DecisionOutcome, DecisionState,
};
pub use execution::*;
pub use model::Decision as LegacyDecision;
pub use model::*;
pub use releases::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct DomainError {
    pub code: String,
    pub message: String,
    pub object_id: Option<String>,
    pub request_id: Option<String>,
    pub retryable: bool,
    pub remediation: Option<String>,
    pub details: serde_json::Value,
}
impl DomainError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            object_id: None,
            request_id: None,
            retryable: false,
            remediation: None,
            details: serde_json::Value::Null,
        }
    }
}
