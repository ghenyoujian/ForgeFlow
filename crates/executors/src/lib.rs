//! Version-pinned DSH Headless projection. Process supervision belongs to Worker.
pub mod claude;
pub mod doctor;
pub mod ecp_bot_session;
pub mod ecp_claude_leaf;
pub mod ecp_claude_team;
pub mod ecp_claude_workflow;
pub mod ecp_doctor;
pub mod ecp_dsh_leaf;
pub mod ecp_dsh_team;
pub mod ecp_dsh_workflow;
pub use claude::{
    ClaudeCredentialEnv, ClaudeLeafProfile, ClaudeStream, extract_claude_result_text,
    prepare_claude_leaf,
};
pub use doctor::{ClaudeDiscoveryEvidence, claude_doctor};
use forgeflow_domain::{ExecutionEnvelope, ExecutorCapabilities, ExecutorOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("INVALID_EXECUTION_ENVELOPE: {0}")]
    InvalidEnvelope(String),
    #[error("EXECUTOR_IDENTITY_MISMATCH: {0}")]
    Identity(String),
    #[error("UNSUPPORTED_CAPABILITY: {0}")]
    Unsupported(String),
    #[error("INVALID_FINAL_ARTIFACT: {0}")]
    FinalArtifact(String),
    #[error("executor I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Extract only the pinned native terminal `{type:"final",text:string}` answer.
/// Worker artifacts are complete JSON events (normal pretty JSON or lossless NDJSON spool),
/// never a concatenation of tool/user text. Artifact identity is checked by the caller.
pub fn extract_final_text(raw: &[u8]) -> Result<String, ExecutorError> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|e| ExecutorError::FinalArtifact(e.to_string()))?;
    let Value::Object(mut object) = value else {
        return Err(ExecutorError::FinalArtifact(
            "final event must be an object".into(),
        ));
    };
    if object.get("type").and_then(Value::as_str) != Some("final") {
        return Err(ExecutorError::FinalArtifact(
            "artifact is not a native final event".into(),
        ));
    }
    match object.remove("text") {
        Some(Value::String(text)) => Ok(text),
        _ => Err(ExecutorError::FinalArtifact(
            "native final text must be a string".into(),
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPin {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessProfile {
    pub id: String,
    /// Approved executable, usually an absolute Node binary; never the personal dsh.sh wrapper.
    pub program: PathBuf,
    /// Frozen entrypoint arguments, e.g. /.../apps/cli/lib/bin.js.
    pub prefix_args: Vec<String>,
    pub home: PathBuf,
    pub profile_name: String,
    pub artifact_pins: Vec<ArtifactPin>,
    pub resume_verified: bool,
    pub model_route_id: String,
    /// Hard budget coverage requires a separate real egress receipt; not a prompt assertion.
    pub gateway_coverage_verified: bool,
}

#[derive(Debug, Clone)]
pub struct HeadlessLaunchSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub stdin: Vec<u8>,
    pub cwd: PathBuf,
}

impl HeadlessProfile {
    pub fn verify_identity(&self) -> Result<(), ExecutorError> {
        if !self.program.is_absolute() || !self.home.is_absolute() || self.artifact_pins.is_empty()
        {
            return Err(ExecutorError::Identity(
                "absolute program/home and nonempty artifact pins required".into(),
            ));
        }
        let program = fs::canonicalize(&self.program)?;
        if !self
            .artifact_pins
            .iter()
            .any(|p| fs::canonicalize(&p.path).ok().as_ref() == Some(&program))
        {
            return Err(ExecutorError::Identity("executable is not pinned".into()));
        }
        for pin in &self.artifact_pins {
            if sha256(&fs::read(&pin.path)?) != pin.sha256 {
                return Err(ExecutorError::Identity(format!(
                    "artifact changed: {}",
                    pin.path.display()
                )));
            }
        }
        Ok(())
    }
}

pub fn prepare_headless(
    envelope: &ExecutionEnvelope,
    prompt: Vec<u8>,
    profile: &HeadlessProfile,
) -> Result<HeadlessLaunchSpec, ExecutorError> {
    envelope
        .validate()
        .map_err(|e| ExecutorError::InvalidEnvelope(e.to_string()))?;
    if !envelope
        .allowed_effects
        .contains(&forgeflow_domain::AllowedEffect::RequestApprovedModel)
        || envelope.max_model_requests == 0
    {
        return Err(ExecutorError::InvalidEnvelope(
            "Headless requires approved model-request effect and a positive request budget".into(),
        ));
    }
    profile.verify_identity()?;
    if envelope.executor_profile_id != profile.id {
        return Err(ExecutorError::Identity(
            "profile ID differs from admission".into(),
        ));
    }
    if envelope.model_route_id != profile.model_route_id {
        return Err(ExecutorError::Identity(
            "model route differs from frozen executor profile".into(),
        ));
    }
    if envelope.enforcement.model_budget_mode == forgeflow_domain::ModelBudgetMode::GatewayEnforced
        && !profile.gateway_coverage_verified
    {
        return Err(ExecutorError::Unsupported(
            "gateway budget coverage has not been qualified for this profile".into(),
        ));
    }
    if envelope.command.is_some() {
        return Err(ExecutorError::Unsupported(
            "caller command overrides are not allowed for Headless".into(),
        ));
    }
    let text = std::str::from_utf8(&prompt)
        .map_err(|_| ExecutorError::InvalidEnvelope("prompt is not UTF-8".into()))?;
    if text.trim().is_empty() || sha256(&prompt) != envelope.prompt_artifact.sha256 {
        return Err(ExecutorError::InvalidEnvelope(
            "prompt artifact digest or content mismatch".into(),
        ));
    }
    let mut args = profile.prefix_args.clone();
    args.extend([
        "--profile".into(),
        profile.profile_name.clone(),
        "--json".into(),
    ]);
    if let Some(session) = &envelope.resume_session_id {
        if !profile.resume_verified {
            return Err(ExecutorError::Unsupported(
                "session resume has not been qualified for this profile".into(),
            ));
        }
        if session.trim().is_empty() {
            return Err(ExecutorError::InvalidEnvelope(
                "empty opaque session ID".into(),
            ));
        }
        args.extend(["--session-id".into(), session.clone()]);
    }
    // Explicit '-' preserves arbitrary multiline Unicode input through stdin.
    args.push("-".into());
    Ok(HeadlessLaunchSpec {
        program: profile.program.clone(),
        args,
        env: BTreeMap::from([(
            "DSH_HOME".into(),
            profile.home.to_string_lossy().into_owned(),
        )]),
        stdin: prompt,
        cwd: fs::canonicalize(&envelope.workspace_root)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEvent {
    pub sequence: u64,
    pub kind: String,
    pub payload: Value,
    /// Exact NDJSON bytes, including any unknown fields; callers persist these before publication.
    pub raw: Vec<u8>,
    pub parse_error: Option<String>,
}

#[derive(Debug)]
pub struct HeadlessStream {
    execution_id: String,
    sequence: u64,
    session_id: Option<String>,
    reason: Option<String>,
    upstream_error_code: Option<String>,
    final_count: u32,
    error_seen: bool,
    malformed: bool,
    truncated: bool,
}

impl HeadlessStream {
    pub fn new(execution_id: impl Into<String>) -> Self {
        Self {
            execution_id: execution_id.into(),
            sequence: 0,
            session_id: None,
            reason: None,
            upstream_error_code: None,
            final_count: 0,
            error_seen: false,
            malformed: false,
            truncated: false,
        }
    }
    /// Worker supplies one persisted complete line. Finals are never capped as intermediate events.
    pub fn observe_line(&mut self, raw: &[u8]) -> ParsedEvent {
        self.sequence += 1;
        let parsed: Result<Value, _> = serde_json::from_slice(raw);
        let (payload, parse_error) = match parsed {
            Ok(v) if v.is_object() => (v, None),
            Ok(v) => {
                self.malformed = true;
                (v, Some("NDJSON event must be an object".into()))
            }
            Err(e) => {
                self.malformed = true;
                (Value::Null, Some(e.to_string()))
            }
        };
        let kind = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        self.truncated |= payload.get("truncated").and_then(Value::as_bool) == Some(true);
        match kind.as_str() {
            "session" => {
                if let Some(id) = payload
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    if self.session_id.as_deref().is_some_and(|old| old != id) {
                        self.malformed = true;
                    }
                    self.session_id = Some(id.to_owned());
                } else {
                    self.malformed = true;
                }
            }
            "status" if payload.get("phase").and_then(Value::as_str) == Some("turn_end") => {
                self.reason = payload
                    .pointer("/reason/kind")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                self.upstream_error_code = payload
                    .pointer("/reason/error/code")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            "final" => {
                self.final_count += 1;
                if !payload.get("text").is_some_and(Value::is_string) {
                    self.malformed = true;
                }
            }
            "error" => self.error_seen = true,
            _ => {}
        }
        ParsedEvent {
            sequence: self.sequence,
            kind,
            payload,
            raw: raw.to_vec(),
            parse_error,
        }
    }
    pub fn upstream_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
    /// For a lossless final already persisted and validated by the Worker without buffering
    /// its text. Caller verifies the pinned native `{"type":"final","text":"` prefix and
    /// validates the complete spooled JSON with a streaming IgnoredAny deserializer.
    /// The raw artifact remains the authority; this bounded metadata never replaces it.
    pub fn observe_spooled_final(&mut self, raw_sha256: String, raw_bytes: u64) -> ParsedEvent {
        self.sequence += 1;
        self.final_count += 1;
        ParsedEvent {
            sequence: self.sequence,
            kind: "final".into(),
            payload: serde_json::json!({"type":"final","payload_in_artifact":true,"raw_sha256":raw_sha256,"raw_bytes":raw_bytes}),
            raw: Vec::new(),
            parse_error: None,
        }
    }
    pub fn finish(
        self,
        exit_code: Option<i32>,
        confirmed_cancelled: bool,
        raw_digest: String,
        final_artifact: Option<String>,
    ) -> ExecutorOutcome {
        let (reason, error) = if confirmed_cancelled {
            ("CANCELLED", None)
        } else if self.malformed || self.final_count > 1 {
            ("PROTOCOL_ERROR", Some("MALFORMED_EVENT_STREAM"))
        } else if self.error_seen {
            ("EXECUTOR_ERROR", Some("UPSTREAM_RUNTIME_ERROR"))
        } else if exit_code != Some(0) {
            ("PROCESS_FAILED", Some("PROCESS_EXIT_FAILURE"))
        } else if self.final_count != 1
            || self.reason.as_deref() != Some("completed")
            || self.session_id.is_none()
        {
            ("INCOMPLETE", Some("INCOMPLETE_EVENT_STREAM"))
        } else if final_artifact.is_none() {
            ("EVIDENCE_STORAGE_FAILED", Some("EVIDENCE_STORAGE_FAILED"))
        } else {
            ("EXECUTOR_COMPLETED", None)
        };
        ExecutorOutcome {
            execution_id: self.execution_id,
            upstream_session_id: self.session_id,
            exit_code,
            completion_reason: reason.into(),
            raw_event_digest: raw_digest,
            transcript_completeness: if self.truncated {
                "UPSTREAM_PROJECTION_TRUNCATED"
            } else {
                "UPSTREAM_COMMITTED_PROJECTION"
            }
            .into(),
            final_artifact,
            error_class: if matches!(reason, "PROCESS_FAILED" | "EXECUTOR_ERROR" | "INCOMPLETE") {
                self.upstream_error_code
                    .or_else(|| error.map(str::to_owned))
            } else {
                error.map(str::to_owned)
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub executor_profile_id: String,
    pub executable_real_path: PathBuf,
    pub artifact_pins: Vec<ArtifactPin>,
    pub platform: String,
    pub architecture: String,
    pub workspace_real_path: PathBuf,
    pub managed_home: PathBuf,
    pub stdin_protocol: String,
    pub stdout_protocol: String,
    pub credential_resolution: String,
    pub model_route_resolution: String,
    pub sandbox_boundary: String,
    pub session_persistence: String,
    pub capabilities: ExecutorCapabilities,
}

pub fn doctor(profile: &HeadlessProfile, cwd: &Path) -> Result<DoctorReport, ExecutorError> {
    profile.verify_identity()?;
    Ok(DoctorReport {
        executor_profile_id: profile.id.clone(),
        executable_real_path: fs::canonicalize(&profile.program)?,
        artifact_pins: profile.artifact_pins.clone(),
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        workspace_real_path: fs::canonicalize(cwd)?,
        managed_home: profile.home.clone(),
        stdin_protocol: "UTF8_PROMPT_EOF".into(),
        stdout_protocol: "NDJSON_COMMITTED_PROJECTION".into(),
        credential_resolution: "UNVERIFIED".into(),
        model_route_resolution: "UNVERIFIED".into(),
        sandbox_boundary: "WORKER_ENFORCED_OR_UNVERIFIED".into(),
        session_persistence: "DSH_PROFILE_OWNED_UNVERIFIED".into(),
        capabilities: ExecutorCapabilities {
            adapter_contract_version: "forgeflow.executor.headless.v1".into(),
            protocol: "DSH_HEADLESS_NDJSON".into(),
            protocol_version: None,
            structured_events: true,
            session_resume: profile.resume_verified,
            session_cancel: false,
            process_cancel: false,
            session_close: false,
            usage_accounting: "OPTIONAL_PROVIDER_REPORTED_STEP_USAGE".into(),
            transcript_replay: false,
            nested_spawn_control: "UNVERIFIED".into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_text_extraction_never_uses_tool_or_user_text() {
        assert_eq!(
            extract_final_text(br#"{"type":"final","text":"{\"unicode\":\"\u6587\u4ef6\"}\n"}"#)
                .unwrap(),
            "{\"unicode\":\"文件\"}\n"
        );
        assert!(
            extract_final_text(br#"{"type":"tool_result","text":"pretend model output"}"#).is_err()
        );
        assert!(extract_final_text(br#"{"type":"final","text":{"nested":"not text"}}"#).is_err());
        assert!(extract_final_text(b"{\"type\":\"final\",\"text\":\"first\"}\n{\"type\":\"final\",\"text\":\"second\"}").is_err());
    }
    #[test]
    fn stdin_unicode_digest_and_profile_identity_are_enforced() {
        let folder = tempfile::tempdir().unwrap();
        let program = folder.path().join("approved-runtime");
        fs::write(&program, b"frozen runtime").unwrap();
        let home = folder.path().join("managed-home");
        fs::create_dir(&home).unwrap();
        let prompt = "文件索引\nsecond line $(never-executed)"
            .as_bytes()
            .to_vec();
        let envelope: ExecutionEnvelope=serde_json::from_value(serde_json::json!({
            "schema_version":"forgeflow.execution.v1","operation_id":"operation","project_id":"project","task_id":"task","task_revision":1,"attempt_id":"attempt","lease_id":"lease","generation":1,"worker_id":"worker","workspace_root":folder.path(),"base_sha":"a".repeat(40),
            "context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[],"prompt_artifact":{"artifact_id":"prompt","sha256":sha256(&prompt)},"model_route_id":"route","executor_profile_id":"profile","resource_profile_id":"resource","verification_plan_id":"verification","allowed_effects":["READ_WORKSPACE","REQUEST_APPROVED_MODEL"],
            "issued_at":"2026-10-09T00:00:00Z","expires_at":"2026-10-09T01:00:00Z","deadline_at":"2026-10-09T02:00:00Z","artifact_prefix":folder.path(),"secret_refs":[],"idempotency_key":"key","trace_id":"trace","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"PLANNING","max_model_requests":1,"resume_session_id":null
        })).unwrap();
        let profile = HeadlessProfile {
            id: "profile".into(),
            program: program.clone(),
            prefix_args: vec!["frozen-entry.js".into()],
            home,
            profile_name: "headless".into(),
            artifact_pins: vec![ArtifactPin {
                path: program.clone(),
                sha256: sha256(b"frozen runtime"),
            }],
            resume_verified: false,
            model_route_id: "route".into(),
            gateway_coverage_verified: false,
        };
        let launch = prepare_headless(&envelope, prompt.clone(), &profile).unwrap();
        assert_eq!(launch.stdin, prompt);
        assert!(!launch.args.iter().any(|a| a.contains("never-executed")));
        assert_eq!(launch.args.last().unwrap(), "-");
        let mut no_model = envelope.clone();
        no_model
            .allowed_effects
            .retain(|e| *e != forgeflow_domain::AllowedEffect::RequestApprovedModel);
        assert!(prepare_headless(&no_model, prompt.clone(), &profile).is_err());
        let mut no_budget = envelope.clone();
        no_budget.max_model_requests = 0;
        assert!(prepare_headless(&no_budget, prompt.clone(), &profile).is_err());
        assert!(prepare_headless(&envelope, b"wrong".to_vec(), &profile).is_err());
        fs::write(program, b"mutated runtime").unwrap();
        assert!(prepare_headless(&envelope, prompt, &profile).is_err());
    }
    fn stream(reason: &str) -> HeadlessStream {
        let mut s = HeadlessStream::new("run");
        s.observe_line(br#"{"type":"session","sessionId":"native-id"}"#);
        s.observe_line(
            format!(r#"{{"type":"status","phase":"turn_end","reason":{{"kind":"{reason}"}}}}"#)
                .as_bytes(),
        );
        s.observe_line(br#"{"type":"final","text":"still exists"}"#);
        s
    }
    #[test]
    fn final_with_failed_exit_is_failure() {
        assert_eq!(
            stream("error")
                .finish(Some(1), false, "digest".into(), Some("final".into()))
                .completion_reason,
            "PROCESS_FAILED"
        );
        let mut native = HeadlessStream::new("failed-native");
        native.observe_line(br#"{"type":"status","phase":"turn_end","reason":{"kind":"error","error":{"code":"NO_ADAPTER","message":"no adapter registered"}}}"#);
        native.observe_line(br#"{"type":"final","text":"still present on failure"}"#);
        assert_eq!(
            native
                .finish(
                    Some(1),
                    false,
                    "raw-digest".into(),
                    Some("raw-final".into())
                )
                .error_class
                .as_deref(),
            Some("NO_ADAPTER")
        );
    }
    #[test]
    fn completed_requires_final_and_persisted_evidence() {
        assert_eq!(
            stream("completed")
                .finish(Some(0), false, "digest".into(), Some("final".into()))
                .completion_reason,
            "EXECUTOR_COMPLETED"
        );
        assert_eq!(
            stream("completed")
                .finish(Some(0), false, "digest".into(), None)
                .completion_reason,
            "EVIDENCE_STORAGE_FAILED"
        );
    }
    #[test]
    fn unknown_event_is_lossless() {
        let raw = br#"{"type":"future","opaque":{"a":23}}"#;
        let e = HeadlessStream::new("r").observe_line(raw);
        assert_eq!(e.raw, raw);
        assert_eq!(e.payload["opaque"]["a"], 23);
    }
    #[test]
    fn malformed_never_succeeds() {
        let mut s = stream("completed");
        s.observe_line(b"not-json");
        assert_eq!(
            s.finish(Some(0), false, "d".into(), Some("f".into()))
                .completion_reason,
            "PROTOCOL_ERROR"
        );
    }
    #[test]
    fn final_is_not_truncated() {
        let mut s = stream("completed");
        let text = "界".repeat(65536);
        let raw = serde_json::to_vec(&serde_json::json!({"type":"final","text":text})).unwrap();
        let e = s.observe_line(&raw);
        assert_eq!(e.payload["text"].as_str().unwrap().len(), 196608);
    }
}
