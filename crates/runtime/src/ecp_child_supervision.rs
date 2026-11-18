//! Phase 5 child lifecycle primitives.
//!
//! This module is intentionally independent from the database and provider
//! adapters. It is the local fail-closed part of child admission: a child can
//! only receive an attenuation of its parent's action, project, write and
//! numeric budget scope. Lifecycle transitions are generation/epoch bound and
//! idempotent by request key.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChildLifecycleState {
    Pending,
    Running,
    StopRequested,
    Exited,
    Disposed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildScope {
    pub parent_id: String,
    pub child_id: String,
    pub project_id: String,
    pub generation: i64,
    pub epoch: i64,
    pub depth: u32,
    pub max_depth: u32,
    pub actions: BTreeSet<String>,
    pub write_set: BTreeSet<String>,
    /// Numeric units are deliberately generic. The control plane maps model,
    /// CPU, wall-time and storage units to their own ledger dimensions.
    pub budget: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRequest {
    pub child_id: String,
    pub project_id: String,
    pub parent_generation: i64,
    pub parent_epoch: i64,
    pub actions: BTreeSet<String>,
    pub write_set: BTreeSet<String>,
    pub budget: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildReceipt {
    pub child_id: String,
    pub parent_id: String,
    pub generation: i64,
    pub epoch: i64,
    pub revision: u64,
    pub state: ChildLifecycleState,
    pub request_key: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildAuthorityError {
    Invalid(String),
    ParentRevoked,
    GenerationMismatch,
    EpochMismatch,
    ProjectExpansion,
    ActionExpansion(String),
    WriteExpansion(String),
    BudgetExpansion(String),
    DepthExceeded,
    IdempotencyConflict,
    InvalidTransition {
        from: ChildLifecycleState,
        to: ChildLifecycleState,
    },
    StaleRevision,
}

impl ChildAuthorityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "CHILD_INVALID",
            Self::ParentRevoked => "CHILD_PARENT_REVOKED",
            Self::GenerationMismatch => "CHILD_GENERATION_MISMATCH",
            Self::EpochMismatch => "CHILD_EPOCH_MISMATCH",
            Self::ProjectExpansion => "CHILD_PROJECT_EXPANSION",
            Self::ActionExpansion(_) => "CHILD_ACTION_EXPANSION",
            Self::WriteExpansion(_) => "CHILD_WRITE_EXPANSION",
            Self::BudgetExpansion(_) => "CHILD_BUDGET_EXPANSION",
            Self::DepthExceeded => "CHILD_DEPTH_EXCEEDED",
            Self::IdempotencyConflict => "CHILD_IDEMPOTENCY_CONFLICT",
            Self::InvalidTransition { .. } => "CHILD_INVALID_TRANSITION",
            Self::StaleRevision => "CHILD_STALE_REVISION",
        }
    }
}

impl std::fmt::Display for ChildAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(msg) => write!(f, "{}: {msg}", self.code()),
            Self::ActionExpansion(action) => write!(f, "{}: {action}", self.code()),
            Self::WriteExpansion(path) => write!(f, "{}: {path}", self.code()),
            Self::BudgetExpansion(unit) => write!(f, "{}: {unit}", self.code()),
            Self::InvalidTransition { from, to } => write!(f, "{}: {from:?}->{to:?}", self.code()),
            other => f.write_str(other.code()),
        }
    }
}
impl std::error::Error for ChildAuthorityError {}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn valid_scope_path(value: &str) -> bool {
    let trimmed = value.trim_end_matches('/');
    !trimmed.is_empty()
        && value.len() <= 2048
        && !value.starts_with('/')
        && !trimmed
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

fn scope_contains(parent: &str, child: &str) -> bool {
    parent == child
        || (parent.ends_with('/') && child.starts_with(parent))
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn digest<T: Serialize>(value: &T) -> Result<String, ChildAuthorityError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ChildAuthorityError::Invalid(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl ChildScope {
    pub fn validate(&self) -> Result<(), ChildAuthorityError> {
        if !valid_identity(&self.parent_id)
            || !valid_identity(&self.child_id)
            || self.parent_id == self.child_id
            || !valid_identity(&self.project_id)
            || self.generation < 1
            || self.epoch < 1
            || self.depth > self.max_depth
            || self.max_depth > 64
        {
            return Err(ChildAuthorityError::Invalid(
                "invalid child identity or depth".into(),
            ));
        }
        if self.actions.iter().any(|value| !valid_identity(value)) {
            return Err(ChildAuthorityError::Invalid(
                "invalid action identifier".into(),
            ));
        }
        if self.write_set.iter().any(|value| !valid_scope_path(value)) {
            return Err(ChildAuthorityError::Invalid("invalid write scope".into()));
        }
        if self.budget.keys().any(|value| !valid_identity(value)) {
            return Err(ChildAuthorityError::Invalid(
                "invalid budget dimension".into(),
            ));
        }
        Ok(())
    }

    pub fn attenuate(&self, request: ChildRequest) -> Result<ChildScope, ChildAuthorityError> {
        self.validate()?;
        if request.child_id == self.parent_id || !valid_identity(&request.child_id) {
            return Err(ChildAuthorityError::Invalid(
                "invalid child identity".into(),
            ));
        }
        if request.project_id != self.project_id {
            return Err(ChildAuthorityError::ProjectExpansion);
        }
        if request.parent_generation != self.generation {
            return Err(ChildAuthorityError::GenerationMismatch);
        }
        if request.parent_epoch != self.epoch {
            return Err(ChildAuthorityError::EpochMismatch);
        }
        if self.depth >= self.max_depth {
            return Err(ChildAuthorityError::DepthExceeded);
        }
        for action in &request.actions {
            if !self.actions.contains(action) {
                return Err(ChildAuthorityError::ActionExpansion(action.clone()));
            }
        }
        for path in &request.write_set {
            if !request
                .write_set
                .iter()
                .all(|value| valid_scope_path(value))
                || !self
                    .write_set
                    .iter()
                    .any(|parent| scope_contains(parent, path))
            {
                return Err(ChildAuthorityError::WriteExpansion(path.clone()));
            }
        }
        for (unit, value) in &request.budget {
            if self.budget.get(unit).copied().unwrap_or(0) < *value {
                return Err(ChildAuthorityError::BudgetExpansion(unit.clone()));
            }
        }
        Ok(Self {
            parent_id: self.child_id.clone(),
            child_id: request.child_id,
            project_id: self.project_id.clone(),
            generation: self.generation,
            epoch: self.epoch,
            depth: self.depth + 1,
            max_depth: self.max_depth,
            actions: request.actions,
            write_set: request.write_set,
            budget: request.budget,
        })
    }
}

#[derive(Debug, Default)]
pub struct ChildSupervisor {
    records: BTreeMap<String, ChildReceipt>,
}

impl ChildSupervisor {
    pub fn admit(
        &mut self,
        parent: &ChildScope,
        request: ChildRequest,
        request_key: impl Into<String>,
    ) -> Result<ChildReceipt, ChildAuthorityError> {
        let request_key = request_key.into();
        if request_key.is_empty() || request_key.len() > 512 {
            return Err(ChildAuthorityError::Invalid("invalid request key".into()));
        }
        let scope = parent.attenuate(request)?;
        let request_digest = digest(&(scope.clone(), &request_key))?;
        if let Some(existing) = self.records.get(&scope.child_id) {
            if existing.request_key != request_key || existing.request_digest != request_digest {
                return Err(ChildAuthorityError::IdempotencyConflict);
            }
            return Ok(existing.clone());
        }
        let receipt = ChildReceipt {
            child_id: scope.child_id,
            parent_id: scope.parent_id,
            generation: scope.generation,
            epoch: scope.epoch,
            revision: 1,
            state: ChildLifecycleState::Pending,
            request_key,
            request_digest,
        };
        self.records
            .insert(receipt.child_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn transition(
        &mut self,
        child_id: &str,
        generation: i64,
        epoch: i64,
        expected_revision: u64,
        request_key: &str,
        next: ChildLifecycleState,
    ) -> Result<ChildReceipt, ChildAuthorityError> {
        let current = self
            .records
            .get_mut(child_id)
            .ok_or_else(|| ChildAuthorityError::Invalid("unknown child".into()))?;
        if current.generation != generation {
            return Err(ChildAuthorityError::GenerationMismatch);
        }
        if current.epoch != epoch {
            return Err(ChildAuthorityError::EpochMismatch);
        }
        // A replay of the exact transition is safe even when the caller still
        // carries the pre-commit revision. Generation and epoch are checked
        // above, so an old identity can never obtain a replay receipt.
        if current.request_key == request_key && current.state == next {
            return Ok(current.clone());
        }
        if current.request_key == request_key {
            return Err(ChildAuthorityError::IdempotencyConflict);
        }
        if current.revision != expected_revision {
            return Err(ChildAuthorityError::StaleRevision);
        }
        let allowed = matches!(
            (&current.state, &next),
            (ChildLifecycleState::Pending, ChildLifecycleState::Running)
                | (
                    ChildLifecycleState::Pending,
                    ChildLifecycleState::StopRequested
                )
                | (
                    ChildLifecycleState::Running,
                    ChildLifecycleState::StopRequested
                )
                | (ChildLifecycleState::Running, ChildLifecycleState::Exited)
                | (
                    ChildLifecycleState::StopRequested,
                    ChildLifecycleState::Exited
                )
                | (ChildLifecycleState::Exited, ChildLifecycleState::Disposed)
                | (
                    ChildLifecycleState::StopRequested,
                    ChildLifecycleState::Disposed
                )
        );
        if !allowed {
            return Err(ChildAuthorityError::InvalidTransition {
                from: current.state.clone(),
                to: next,
            });
        }
        current.revision += 1;
        current.state = next;
        current.request_key = request_key.to_owned();
        Ok(current.clone())
    }

    pub fn get(&self, child_id: &str) -> Option<&ChildReceipt> {
        self.records.get(child_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> ChildScope {
        ChildScope {
            parent_id: "root".into(),
            child_id: "root-session".into(),
            project_id: "project".into(),
            generation: 3,
            epoch: 7,
            depth: 0,
            max_depth: 2,
            actions: ["read", "write", "model"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            write_set: ["src/", "README.md"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            budget: [("model_tokens".into(), 1000), ("cpu_ms".into(), 5000)]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn attenuation_rejects_expansion_and_preserves_parent_generation() {
        let child = parent()
            .attenuate(ChildRequest {
                child_id: "child".into(),
                project_id: "project".into(),
                parent_generation: 3,
                parent_epoch: 7,
                actions: ["read".into()].into_iter().collect(),
                write_set: ["src/lib.rs".into()].into_iter().collect(),
                budget: [("model_tokens".into(), 100)].into_iter().collect(),
            })
            .unwrap();
        assert_eq!(child.parent_id, "root-session");
        assert_eq!(child.generation, 3);
        assert!(matches!(
            parent().attenuate(ChildRequest {
                child_id: "escape".into(),
                project_id: "other".into(),
                parent_generation: 3,
                parent_epoch: 7,
                actions: BTreeSet::new(),
                write_set: BTreeSet::new(),
                budget: BTreeMap::new()
            }),
            Err(ChildAuthorityError::ProjectExpansion)
        ));
    }

    #[test]
    fn lifecycle_is_idempotent_and_rejects_stale_generation() {
        let mut supervisor = ChildSupervisor::default();
        let request = ChildRequest {
            child_id: "child".into(),
            project_id: "project".into(),
            parent_generation: 3,
            parent_epoch: 7,
            actions: ["read".into()].into_iter().collect(),
            write_set: BTreeSet::new(),
            budget: BTreeMap::new(),
        };
        let first = supervisor.admit(&parent(), request.clone(), "key").unwrap();
        assert_eq!(first, supervisor.admit(&parent(), request, "key").unwrap());
        assert!(matches!(
            supervisor.transition("child", 2, 7, 1, "run", ChildLifecycleState::Running),
            Err(ChildAuthorityError::GenerationMismatch)
        ));
        let running = supervisor
            .transition("child", 3, 7, 1, "run", ChildLifecycleState::Running)
            .unwrap();
        assert_eq!(running.revision, 2);
        assert_eq!(
            supervisor
                .transition("child", 3, 7, 1, "run", ChildLifecycleState::Running)
                .unwrap(),
            running
        );
        assert!(matches!(
            supervisor.transition("child", 3, 7, 2, "run", ChildLifecycleState::StopRequested),
            Err(ChildAuthorityError::IdempotencyConflict)
        ));
        assert!(matches!(
            supervisor.transition("child", 3, 7, 2, "other", ChildLifecycleState::Pending),
            Err(ChildAuthorityError::InvalidTransition { .. })
        ));
    }
}
