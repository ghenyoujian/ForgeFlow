use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextManifestRef {
    pub artifact_id: String,
    pub sha256: String,
    pub mandatory_paths: Vec<String>,
    pub rendered_utf8_bytes: u64,
    pub token_estimate: Option<u64>,
    pub tokenizer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelBudgetMode {
    GatewayEnforced,
    DirectObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StageResourceMode {
    ToolIntercepted,
    AttemptReservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedEffect {
    ReadWorkspace,
    WriteDeclaredPaths,
    RunApprovedCommands,
    RequestApprovedModel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionPurpose {
    Planning,
    Review,
    Execution,
    MainAgentModelSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub model_budget_mode: ModelBudgetMode,
    pub stage_resource_mode: StageResourceMode,
    pub build_capable: bool,
    pub gateway_coverage_receipt_id: Option<String>,
    pub tool_guard_receipt_id: Option<String>,
    pub attempt_reserved_build_permits: u32,
    pub all_model_routes_covered: bool,
    pub disabled_tool_entry_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvelope {
    pub schema_version: String,
    pub operation_id: String,
    pub project_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub attempt_id: String,
    pub lease_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub workspace_root: String,
    pub base_sha: String,
    pub context_manifest: ContextManifestRef,
    pub write_set: Vec<String>,
    pub prompt_artifact: ArtifactRef,
    pub model_route_id: String,
    pub executor_profile_id: String,
    pub resource_profile_id: String,
    pub verification_plan_id: String,
    pub allowed_effects: Vec<AllowedEffect>,
    pub issued_at: String,
    pub expires_at: String,
    pub deadline_at: String,
    pub artifact_prefix: String,
    pub secret_refs: Vec<String>,
    pub idempotency_key: String,
    pub trace_id: String,
    pub enforcement: Enforcement,
    pub session_purpose: SessionPurpose,
    pub max_model_requests: u32,
    pub resume_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorCapabilities {
    pub adapter_contract_version: String,
    pub protocol: String,
    pub protocol_version: Option<String>,
    pub structured_events: bool,
    pub session_resume: bool,
    pub session_cancel: bool,
    pub process_cancel: bool,
    pub session_close: bool,
    pub usage_accounting: String,
    pub transcript_replay: bool,
    pub nested_spawn_control: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorOutcome {
    pub execution_id: String,
    pub upstream_session_id: Option<String>,
    pub exit_code: Option<i32>,
    pub completion_reason: String,
    pub raw_event_digest: String,
    pub transcript_completeness: String,
    pub final_artifact: Option<String>,
    pub error_class: Option<String>,
}

impl ExecutionEnvelope {
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        use crate::DomainError;
        let invalid = |m: &str| DomainError::new("VALIDATION_ERROR", m);
        if self.schema_version != "forgeflow.execution.v1" {
            return Err(invalid("unsupported execution schema"));
        }
        for id in [
            &self.operation_id,
            &self.project_id,
            &self.task_id,
            &self.attempt_id,
            &self.lease_id,
            &self.worker_id,
            &self.model_route_id,
            &self.executor_profile_id,
            &self.resource_profile_id,
            &self.verification_plan_id,
            &self.idempotency_key,
            &self.trace_id,
        ] {
            if id.is_empty() || id.len() > 512 {
                return Err(invalid("identity must contain 1..512 characters"));
            }
        }
        if self.generation < 1 || self.task_revision < 1 {
            return Err(invalid("generation and task revision must be positive"));
        }
        if !valid_sha(&self.base_sha) {
            return Err(invalid("base_sha must be a Git object hash"));
        }
        if !valid_digest(&self.prompt_artifact.sha256)
            || !valid_digest(&self.context_manifest.sha256)
        {
            return Err(invalid("artifact sha256 must be 64 hexadecimal characters"));
        }
        if !std::path::Path::new(&self.workspace_root).is_absolute()
            || !std::path::Path::new(&self.artifact_prefix).is_absolute()
        {
            return Err(invalid(
                "workspace_root and artifact_prefix must be absolute",
            ));
        }
        for path in self
            .write_set
            .iter()
            .chain(self.context_manifest.mandatory_paths.iter())
        {
            validate_relative_path(path)?;
        }
        let issued = chrono::DateTime::parse_from_rfc3339(&self.issued_at)
            .map_err(|_| invalid("invalid issued_at"))?;
        let expires = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| invalid("invalid expires_at"))?;
        let deadline = chrono::DateTime::parse_from_rfc3339(&self.deadline_at)
            .map_err(|_| invalid("invalid deadline_at"))?;
        if issued >= expires || expires > deadline {
            return Err(invalid("require issued_at < expires_at <= deadline_at"));
        }
        if matches!(
            self.session_purpose,
            SessionPurpose::Planning | SessionPurpose::Review
        ) && (!self.write_set.is_empty()
            || self
                .allowed_effects
                .contains(&AllowedEffect::WriteDeclaredPaths))
        {
            return Err(invalid("read-only sessions cannot acquire write effects"));
        }
        if self
            .allowed_effects
            .contains(&AllowedEffect::WriteDeclaredPaths)
            && self.write_set.is_empty()
        {
            return Err(invalid("write effect requires declared paths"));
        }
        if self.enforcement.model_budget_mode == ModelBudgetMode::GatewayEnforced
            && (!self.enforcement.all_model_routes_covered
                || self.enforcement.gateway_coverage_receipt_id.is_none())
        {
            return Err(invalid("gateway enforcement requires coverage receipt"));
        }
        if self.enforcement.stage_resource_mode == StageResourceMode::ToolIntercepted
            && self.enforcement.tool_guard_receipt_id.is_none()
        {
            return Err(invalid("tool interception requires guard receipt"));
        }
        if self.enforcement.build_capable
            && self.enforcement.stage_resource_mode == StageResourceMode::AttemptReservation
            && self.enforcement.attempt_reserved_build_permits == 0
        {
            return Err(invalid("build-capable attempt must reserve build permit"));
        }
        if let Some(command) = &self.command {
            if command.program.is_empty()
                || command.program.contains('\0')
                || command.args.iter().any(|a| a.contains('\0'))
            {
                return Err(invalid("invalid command argument"));
            }
        }
        Ok(())
    }
}
pub fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn valid_sha(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn validate_relative_path(path: &str) -> Result<(), crate::DomainError> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains('\0')
        || path.contains(':')
        || path
            .trim_end_matches('/')
            .split('/')
            .any(|p| p == ".." || p == "." || p.is_empty())
        || std::path::Path::new(path).is_absolute()
    {
        return Err(crate::DomainError::new(
            "OWNER_PATH_VIOLATION",
            "path must be normalized repository relative path",
        ));
    }
    Ok(())
}
pub fn paths_overlap(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('/');
    let b = b.trim_end_matches('/');
    a == b
        || a.strip_prefix(b).is_some_and(|p| p.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|p| p.starts_with('/'))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFile {
    pub path: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextManifest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_inputs: Vec<ContextArtifactInput>,
    pub files: Vec<ContextFile>,
    pub mandatory_paths: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextArtifactInput {
    pub logical_path: String,
    pub artifact: ArtifactRef,
}
