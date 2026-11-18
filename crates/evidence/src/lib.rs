//! Binding and denominator validation for reproducible verification evidence.
//! Explicit server-classified subject projections accompany execution; ordinary
//! runner APIs retain strict independent-oracle placement and admitted plan hashes.
mod runner;
pub use runner::*;
mod artifact;
pub use artifact::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    pub task_revision: u64,
    pub attempt_id: String,
    pub generation: i64,
    pub base_sha: String,
    pub candidate_sha: String,
    pub integrated_sha: Option<String>,
    pub contract_version: String,
    pub verification_plan_id: String,
    pub verification_plan_hash: String,
    pub input_hash: String,
    pub source_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub binding: EvidenceBinding,
    pub environment_profile: String,
    pub command: Vec<String>,
    pub exit_code: i32,
    pub total: u64,
    pub failed: u64,
    pub skipped: u64,
    pub positive_cases: u64,
    pub negative_cases: u64,
    pub oracle_id: String,
    pub verifier_id: String,
    pub author_id: String,
    pub independent: bool,
    pub log_path: String,
    pub log_hash: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("VERIFIER_INVALID: {0}")]
    Invalid(String),
    #[error("EVIDENCE_BINDING_MISMATCH")]
    BindingMismatch,
    #[error("GATE_FAIL: test or command failed")]
    Failed,
}

impl VerificationReceipt {
    /// Read a raw log from an explicit artifact root and verify its immutable bytes.
    pub fn validate_log(&self, artifact_root: &std::path::Path) -> Result<(), EvidenceError> {
        let path = std::path::Path::new(&self.log_path);
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(EvidenceError::Invalid("unsafe log artifact path".into()));
        }
        let root = std::fs::canonicalize(artifact_root)
            .map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        let log = std::fs::canonicalize(root.join(path))
            .map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        if !log.starts_with(&root) {
            return Err(EvidenceError::Invalid("log escapes artifact root".into()));
        }
        let bytes = std::fs::read(log).map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        if bytes.is_empty() || sha256(&bytes) != self.log_hash {
            return Err(EvidenceError::Invalid(
                "missing or mismatched raw log bytes".into(),
            ));
        }
        Ok(())
    }

    /// Validate independently produced structured counts and immutable identities.
    /// This never treats arbitrary stdout containing PASS as verification.
    pub fn validate(
        &self,
        expected: &EvidenceBinding,
        require_independent: bool,
    ) -> Result<(), EvidenceError> {
        if &self.binding != expected {
            return Err(EvidenceError::BindingMismatch);
        }
        let required = [
            &self.binding.attempt_id,
            &self.binding.base_sha,
            &self.binding.candidate_sha,
            &self.binding.contract_version,
            &self.binding.verification_plan_id,
            &self.binding.verification_plan_hash,
            &self.binding.input_hash,
            &self.binding.source_hash,
            &self.environment_profile,
            &self.oracle_id,
            &self.verifier_id,
            &self.author_id,
            &self.log_path,
            &self.log_hash,
        ];
        if required.iter().any(|v| v.trim().is_empty())
            || self.command.is_empty()
            || self.command[0].trim().is_empty()
        {
            return Err(EvidenceError::Invalid("missing execution identity".into()));
        }
        if self.total == 0 || self.skipped >= self.total {
            return Err(EvidenceError::Invalid(
                "zero executed business cases".into(),
            ));
        }
        if self.positive_cases == 0 || self.negative_cases == 0 {
            return Err(EvidenceError::Invalid(
                "positive and negative executed cases are both required".into(),
            ));
        }
        if self.failed > self.total
            || self.skipped > self.total - self.failed
            || self.positive_cases.checked_add(self.negative_cases)
                != Some(self.total - self.skipped)
        {
            return Err(EvidenceError::Invalid(
                "inconsistent test denominator".into(),
            ));
        }
        if require_independent && (!self.independent || self.verifier_id == self.author_id) {
            return Err(EvidenceError::Invalid("independent oracle required".into()));
        }
        if self.exit_code != 0 || self.failed != 0 {
            return Err(EvidenceError::Failed);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("receipt has serializable fields"))
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
