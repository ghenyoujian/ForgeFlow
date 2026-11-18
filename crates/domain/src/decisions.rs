use crate::ResourcePolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const DECISION_INBOX_SCHEMA: &str = "forgeflow.decision-inbox.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionState {
    Open,
    Acknowledged,
    Deferred,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionCause {
    PausedResourcePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBlockedTask {
    pub task_id: String,
    pub task_revision: u64,
    pub queue_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub schema_version: String,
    pub decision_id: String,
    pub project_id: String,
    pub cause: DecisionCause,
    pub state: DecisionState,
    /// Original authoritative paused-policy snapshot; never rebound on resolve.
    pub policy: ResourcePolicy,
    pub blocked_tasks: Vec<DecisionBlockedTask>,
    pub note: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub revisit_at: Option<DateTime<Utc>>,
    pub resolution_reason: Option<String>,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum DecisionCommand {
    OpenPausedPolicy {
        project_id: String,
        scope_id: String,
        expected_policy_revision: u64,
        note: String,
    },
    Acknowledge {
        project_id: String,
        decision_id: String,
        expected_revision: u64,
        note: String,
    },
    Defer {
        project_id: String,
        decision_id: String,
        expected_revision: u64,
        revisit_at: DateTime<Utc>,
        reason: String,
    },
    Resolve {
        project_id: String,
        decision_id: String,
        expected_revision: u64,
        expected_policy_revision: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOutcome {
    pub decision: Decision,
    /// Current policy at this command's commit, distinct from original snapshot.
    pub policy: ResourcePolicy,
    pub created: bool,
    pub policy_changed: bool,
}
