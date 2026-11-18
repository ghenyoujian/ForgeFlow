use crate::{EvidenceError, sha256};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub task_revision: u64,
    pub attempt_id: String,
    pub generation: i64,
    pub verification_plan_id: String,
    pub verification_plan_hash: String,
    pub contract_version: String,
    pub input_hash: String,
    pub context_hash: String,
    pub prompt_hash: String,
    pub artifact_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVerificationReceipt {
    pub binding: ArtifactBinding,
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
impl ArtifactVerificationReceipt {
    pub fn validate(
        &self,
        expected: &ArtifactBinding,
        require_independent: bool,
    ) -> Result<(), EvidenceError> {
        if &self.binding != expected {
            return Err(EvidenceError::BindingMismatch);
        }
        let values = [
            &self.binding.attempt_id,
            &self.binding.verification_plan_id,
            &self.binding.verification_plan_hash,
            &self.binding.contract_version,
            &self.binding.input_hash,
            &self.binding.context_hash,
            &self.binding.prompt_hash,
            &self.binding.artifact_hash,
            &self.environment_profile,
            &self.oracle_id,
            &self.verifier_id,
            &self.author_id,
            &self.log_path,
            &self.log_hash,
        ];
        if values.iter().any(|v| v.trim().is_empty())
            || self.command.is_empty()
            || self.command[0].trim().is_empty()
        {
            return Err(EvidenceError::Invalid(
                "missing structured artifact execution identity".into(),
            ));
        }
        if self.total == 0
            || self.skipped >= self.total
            || self.positive_cases == 0
            || self.negative_cases == 0
        {
            return Err(EvidenceError::Invalid(
                "missing positive/negative executed artifact oracle cases".into(),
            ));
        }
        if self.failed > self.total
            || self.skipped > self.total - self.failed
            || self.positive_cases.checked_add(self.negative_cases)
                != Some(self.total - self.skipped)
        {
            return Err(EvidenceError::Invalid(
                "inconsistent artifact test denominator".into(),
            ));
        }
        if require_independent && (!self.independent || self.author_id == self.verifier_id) {
            return Err(EvidenceError::Invalid(
                "independent artifact oracle required".into(),
            ));
        }
        if self.exit_code != 0 || self.failed != 0 {
            return Err(EvidenceError::Failed);
        }
        Ok(())
    }
    pub fn digest(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("serializable artifact receipt"))
    }
    pub fn validate_log(&self, root: &std::path::Path) -> Result<(), EvidenceError> {
        let path = std::path::Path::new(&self.log_path);
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(EvidenceError::Invalid("unsafe artifact log path".into()));
        }
        let root =
            std::fs::canonicalize(root).map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        let path = std::fs::canonicalize(root.join(path))
            .map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        if !path.starts_with(&root) {
            return Err(EvidenceError::Invalid("artifact log escapes root".into()));
        }
        let bytes = std::fs::read(path).map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        if bytes.is_empty() || sha256(&bytes) != self.log_hash {
            return Err(EvidenceError::Invalid(
                "artifact raw log bytes mismatch".into(),
            ));
        }
        Ok(())
    }
    pub fn validate_artifact(&self, path: &std::path::Path) -> Result<(), EvidenceError> {
        let bytes = std::fs::read(path).map_err(|e| EvidenceError::Invalid(e.to_string()))?;
        if bytes.is_empty() || sha256(&bytes) != self.binding.artifact_hash {
            return Err(EvidenceError::BindingMismatch);
        }
        Ok(())
    }
}
