//! Claude Code leaf projection only. Worker owns processes, leases and durable raw bytes.
use crate::{ArtifactPin, ExecutorError, HeadlessLaunchSpec, ParsedEvent, sha256};
use forgeflow_domain::{
    AllowedEffect, ExecutionEnvelope, ExecutorOutcome, ModelBudgetMode, SessionPurpose,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

// serde_json::Value alone accepts repeated object keys. A repeated terminal
// identity/error field must never be resolved by a last-value-wins parser.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictValue(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(StrictValue(Value::Array(items)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut items = serde_json::Map::new();
                while let Some((key, StrictValue(value))) =
                    map.next_entry::<String, StrictValue>()?
                {
                    if items.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictValue(Value::Object(items)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeLeafProfile {
    pub id: String,
    pub program: PathBuf,
    pub home: PathBuf,
    pub artifact_pins: Vec<ArtifactPin>,
    pub model_route_id: String,
    pub model_id: String,
    pub provider_base_url: String,
    pub credential_env: ClaudeCredentialEnv,
    /// CLI fuse only; neither trusted financial accounting nor request-count enforcement.
    pub max_budget_usd: String,
    pub tools_allowlist: Vec<String>,
    pub permission_mode: String,
    /// Flags observed in the exact pinned CLI help, not claims of runtime qualification.
    pub help_verified_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_turns: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaudeCredentialEnv {
    ApiKey,
    AuthToken,
}
impl ClaudeCredentialEnv {
    pub fn env_name(self) -> &'static str {
        match self {
            Self::ApiKey => "ANTHROPIC_API_KEY",
            Self::AuthToken => "ANTHROPIC_AUTH_TOKEN",
        }
    }
}

fn valid_provider_url(value: &str) -> bool {
    if value.len() > 2048
        || value
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b"\\?#@".contains(&b))
    {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "https" | "http") {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(tail) = authority.strip_prefix("[::1]") {
        ("::1", tail.strip_prefix(':'))
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or("");
        let port = parts.next();
        if parts.next().is_some() {
            return false;
        }
        (host, port)
    };
    if authority.starts_with('[') && authority != "[::1]" && !authority.starts_with("[::1]:") {
        return false;
    }
    if host.is_empty()
        || (host != "::1"
            && (!host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                || host.starts_with('.')
                || host.ends_with('.')
                || host.contains("..")))
    {
        return false;
    }
    if let Some(port) = port {
        if !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().is_none_or(|n| n == 0)
        {
            return false;
        }
    }
    if scheme == "https" {
        return true;
    }
    host == "::1" || {
        let octets = host
            .split('.')
            .map(str::parse::<u8>)
            .collect::<Result<Vec<_>, _>>();
        octets.is_ok_and(|octets| octets.len() == 4 && octets[0] == 127)
    }
}

const REQUIRED_FLAGS: &[&str] = &[
    "--bare",
    "--print",
    "--output-format",
    "--verbose",
    "--include-partial-messages",
    "--strict-mcp-config",
    "--mcp-config",
    "--model",
    "--max-budget-usd",
    "--tools",
    "--allowedTools",
    "--permission-mode",
    "--permission-prompts",
    "--no-session-persistence",
];

pub(crate) fn hash_file(path: &Path) -> Result<String, ExecutorError> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/-".contains(&c))
}
fn valid_budget(value: &str) -> bool {
    let mut dots = 0;
    !value.is_empty()
        && value.len() <= 32
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.bytes().any(|b| (b'1'..=b'9').contains(&b))
        && value.bytes().all(|b| {
            if b == b'.' {
                dots += 1;
                dots == 1
            } else {
                b.is_ascii_digit()
            }
        })
}

impl ClaudeLeafProfile {
    pub fn verify_identity(&self) -> Result<(), ExecutorError> {
        let reject = |s: &str| ExecutorError::Identity(s.into());
        if !self.program.is_absolute()
            || !self.home.is_absolute()
            || self.artifact_pins.is_empty()
            || self.artifact_pins.len() > 256
            || !token(&self.id)
            || !token(&self.model_route_id)
            || !token(&self.model_id)
            || !valid_budget(&self.max_budget_usd)
            || !valid_provider_url(&self.provider_base_url)
        {
            return Err(reject("invalid pinned Claude leaf profile"));
        }
        if self.max_turns.is_some() || self.permission_mode != "dontAsk" {
            return Err(ExecutorError::Unsupported(
                "v1 requires dontAsk and no unqualified max-turns".into(),
            ));
        }
        if !self.home.is_dir() || fs::symlink_metadata(&self.home)?.file_type().is_symlink() {
            return Err(reject(
                "managed Claude home must be a real existing directory",
            ));
        }
        let program = fs::canonicalize(&self.program)?;
        let metadata = fs::metadata(&program)?;
        if !metadata.is_file() {
            return Err(reject("Claude executable is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(reject("Claude executable lacks execute permission"));
            }
        }
        // Current v1 is the Linux native CLI, never a shell/personal environment wrapper.
        if cfg!(target_os = "linux") {
            let mut magic = [0; 4];
            fs::File::open(&program)?.read_exact(&mut magic)?;
            if magic != *b"\x7fELF" {
                return Err(reject("Claude v1 requires the pinned Linux ELF entrypoint"));
            }
        }
        let mut pinned_program = false;
        let mut seen = BTreeSet::new();
        for pin in &self.artifact_pins {
            if !pin.path.is_absolute()
                || pin.sha256.len() != 64
                || !pin
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(reject("invalid Claude artifact pin"));
            }
            let canonical = fs::canonicalize(&pin.path)?;
            if !seen.insert(canonical.clone()) || hash_file(&canonical)? != pin.sha256 {
                return Err(reject("Claude artifact changed or repeated"));
            }
            pinned_program |= canonical == program;
        }
        if !pinned_program {
            return Err(reject("Claude executable is not pinned"));
        }
        if self.tools_allowlist.len() > 32
            || self.tools_allowlist.iter().any(|tool| {
                tool.is_empty()
                    || tool.len() > 64
                    || !tool.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || matches!(tool.as_str(), "Agent" | "Task" | "Skill")
            })
            || self.tools_allowlist.iter().collect::<BTreeSet<_>>().len()
                != self.tools_allowlist.len()
        {
            return Err(ExecutorError::Unsupported(
                "invalid or non-leaf Claude tool allowlist".into(),
            ));
        }
        for flag in REQUIRED_FLAGS {
            if !self.help_verified_flags.iter().any(|f| f == flag) {
                return Err(ExecutorError::Unsupported(format!(
                    "pinned help missing required flag {flag}"
                )));
            }
        }
        Ok(())
    }
}

pub fn prepare_claude_leaf(
    envelope: &ExecutionEnvelope,
    prompt: Vec<u8>,
    profile: &ClaudeLeafProfile,
) -> Result<HeadlessLaunchSpec, ExecutorError> {
    envelope
        .validate()
        .map_err(|e| ExecutorError::InvalidEnvelope(e.to_string()))?;
    profile.verify_identity()?;
    if envelope.executor_profile_id != profile.id
        || envelope.model_route_id != profile.model_route_id
    {
        return Err(ExecutorError::Identity(
            "Claude profile or model route differs from admission".into(),
        ));
    }
    if envelope.command.is_some()
        || envelope.resume_session_id.is_some()
        || envelope.session_purpose != SessionPurpose::Execution
        || envelope.enforcement.model_budget_mode != ModelBudgetMode::DirectObserved
    {
        return Err(ExecutorError::Unsupported(
            "Claude v1 is code leaf, DirectObserved, fresh session only".into(),
        ));
    }
    if envelope.max_model_requests == 0
        || !envelope
            .allowed_effects
            .contains(&AllowedEffect::RequestApprovedModel)
    {
        return Err(ExecutorError::InvalidEnvelope(
            "Claude requires approved model effect and positive request budget".into(),
        ));
    }
    let text = std::str::from_utf8(&prompt)
        .map_err(|_| ExecutorError::InvalidEnvelope("prompt must be UTF-8".into()))?;
    if text.trim().is_empty() || sha256(&prompt) != envelope.prompt_artifact.sha256 {
        return Err(ExecutorError::InvalidEnvelope(
            "Claude prompt identity mismatch".into(),
        ));
    }
    let args = vec![
        "--bare".into(),
        "--print".into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--include-partial-messages".into(),
        "--strict-mcp-config".into(),
        "--mcp-config".into(),
        r#"{"mcpServers":{}}"#.into(),
        "--model".into(),
        profile.model_id.clone(),
        "--max-budget-usd".into(),
        profile.max_budget_usd.clone(),
        "--tools".into(),
        profile.tools_allowlist.join(","),
        "--allowedTools".into(),
        profile.tools_allowlist.join(","),
        "--permission-mode".into(),
        "dontAsk".into(),
        "--permission-prompts".into(),
        "none".into(),
        "--no-session-persistence".into(),
    ];
    let mut env = BTreeMap::from([
        (
            "CLAUDE_CONFIG_DIR".into(),
            profile.home.to_string_lossy().into_owned(),
        ),
        (
            "ANTHROPIC_BASE_URL".into(),
            profile.provider_base_url.clone(),
        ),
    ]);
    // Alias/background defaults are compatibility constraints, not a model-egress
    // firewall. The trusted external relay still validates every actual model.
    for name in [
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_FABLE_MODEL",
        "CLAUDE_CODE_SUBAGENT_MODEL",
        "ANTHROPIC_SMALL_FAST_MODEL",
    ] {
        env.insert(name.into(), profile.model_id.clone());
    }
    Ok(HeadlessLaunchSpec {
        program: profile.program.clone(),
        args,
        env,
        stdin: prompt,
        cwd: fs::canonicalize(&envelope.workspace_root)?,
    })
}

/// CLI success is only an execution candidate; canonical verification/integration is separate.
pub fn extract_claude_result_text(raw: &[u8]) -> Result<String, ExecutorError> {
    let StrictValue(value) = serde_json::from_slice(raw)
        .map_err(|_| ExecutorError::FinalArtifact("CLAUDE_INVALID_RESULT_JSON".into()))?;
    if !root_result_success(&value) {
        return Err(ExecutorError::FinalArtifact(
            "CLAUDE_INVALID_ROOT_RESULT".into(),
        ));
    }
    Ok(value["result"]
        .as_str()
        .expect("validated result text")
        .to_owned())
}

fn root(value: &Value) -> bool {
    value.get("parent_tool_use_id").is_none_or(Value::is_null)
}
fn session(value: &Value) -> Option<&str> {
    value
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256 && !s.contains('\0'))
}
fn root_result_success(value: &Value) -> bool {
    value.is_object()
        && root(value)
        && value["type"] == "result"
        && value["subtype"] == "success"
        && value["is_error"] == false
        && session(value).is_some()
        && value["result"].is_string()
}

fn root_api_error_status(value: &Value) -> Option<u16> {
    if !root(value)
        || value["type"] != "result"
        || value["is_error"] != true
        || value["terminal_reason"] != "api_error"
        || session(value).is_none()
        || !value["result"].is_string()
        || !value["subtype"]
            .as_str()
            .is_some_and(|s| s == "success" || s.starts_with("error_"))
    {
        return None;
    }
    value["api_error_status"]
        .as_u64()
        .filter(|status| (400..=599).contains(status))
        .map(|status| status as u16)
}

#[derive(Debug)]
pub struct ClaudeStream {
    execution_id: String,
    sequence: u64,
    session_id: Option<String>,
    // Pre-init metadata has no admitted/run identity. It only constrains the
    // later mandatory init; upstream_session_id() remains None until that init.
    pre_init_session_id: Option<String>,
    init_count: u32,
    result_count: u32,
    success: bool,
    api_error_status: Option<u16>,
    malformed: bool,
}
impl ClaudeStream {
    pub fn new(execution_id: impl Into<String>) -> Self {
        Self {
            execution_id: execution_id.into(),
            sequence: 0,
            session_id: None,
            pre_init_session_id: None,
            init_count: 0,
            result_count: 0,
            success: false,
            api_error_status: None,
            malformed: false,
        }
    }
    pub fn upstream_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
    pub fn observe_line(&mut self, raw: &[u8]) -> ParsedEvent {
        let mut error = None;
        if let Some(sequence) = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
        {
            self.sequence = sequence;
        } else {
            self.malformed = true;
            error = Some("CLAUDE_SEQUENCE_OVERFLOW".into());
        }
        let payload: Value = match serde_json::from_slice(raw) {
            Ok(StrictValue(value)) if matches!(value, Value::Object(_)) => value,
            _ => {
                self.malformed = true;
                error = Some("CLAUDE_MALFORMED_FRAME".into());
                Value::Null
            }
        };
        let native_kind = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let kind = if matches!(
            native_kind,
            "system" | "assistant" | "user" | "stream_event" | "result" | "rate_limit_event"
        ) {
            native_kind
        } else {
            self.malformed = true;
            error = Some("CLAUDE_UNKNOWN_EVENT_TYPE".into());
            // Never copy an unbounded upstream `type` into public native_type /
            // event_type metadata. The exact original remains in restricted raw.
            "unknown"
        }
        .to_owned();
        if root(&payload) {
            let pre_init_ui =
                self.init_count == 0 && kind == "system" && payload["subtype"] == "ui_invalidate";
            if self.init_count == 0
                && !(kind == "system" && payload["subtype"] == "init")
                && !pre_init_ui
            {
                self.malformed = true;
                error = Some("CLAUDE_FRAME_BEFORE_INIT".into());
            }
            if let Some(id) = session(&payload) {
                if self.session_id.as_deref().is_some_and(|old| old != id) {
                    self.malformed = true;
                    error = Some("CLAUDE_ROOT_SESSION_CHANGED".into());
                }
                if pre_init_ui {
                    if self
                        .pre_init_session_id
                        .as_deref()
                        .is_some_and(|old| old != id)
                    {
                        self.malformed = true;
                        error = Some("CLAUDE_PRE_INIT_SESSION_CHANGED".into());
                    } else {
                        self.pre_init_session_id = Some(id.to_owned());
                    }
                }
            } else {
                self.malformed = true;
                error = Some("CLAUDE_MISSING_ROOT_SESSION".into());
            }
            if kind == "system" && payload["subtype"] == "init" {
                self.init_count = self.init_count.saturating_add(1);
                if self.init_count != 1 || self.result_count != 0 || session(&payload).is_none() {
                    self.malformed = true;
                    error = Some("CLAUDE_INVALID_INIT".into());
                } else {
                    if self
                        .pre_init_session_id
                        .as_deref()
                        .is_some_and(|old| Some(old) != session(&payload))
                    {
                        self.malformed = true;
                        error = Some("CLAUDE_PRE_INIT_SESSION_CHANGED".into());
                    } else {
                        self.session_id = session(&payload).map(str::to_owned);
                    }
                }
            }
            if kind == "result" {
                self.result_count = self.result_count.saturating_add(1);
                self.success = root_result_success(&payload);
                self.api_error_status = root_api_error_status(&payload);
                if self.result_count != 1 || self.init_count != 1 {
                    self.malformed = true;
                    error = Some("CLAUDE_DUPLICATE_OR_UNINITIALIZED_RESULT".into());
                }
            } else if self.result_count != 0 {
                self.malformed = true;
                error = Some("CLAUDE_EVENT_AFTER_RESULT".into());
            }
        } else if !payload
            .get("parent_tool_use_id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty() && s.len() <= 512)
        {
            self.malformed = true;
            error = Some("CLAUDE_INVALID_PARENT_ID".into());
        }
        ParsedEvent {
            sequence: self.sequence,
            kind,
            payload,
            raw: raw.to_vec(),
            parse_error: error,
        }
    }
    pub fn finish(
        self,
        exit_code: Option<i32>,
        confirmed_cancelled: bool,
        raw_digest: String,
        final_artifact: Option<String>,
    ) -> ExecutorOutcome {
        let (reason, error): (&str, Option<String>) = if confirmed_cancelled {
            ("CANCELLED", None)
        } else if self.malformed {
            (
                "PROTOCOL_ERROR",
                Some("CLAUDE_MALFORMED_EVENT_STREAM".into()),
            )
        } else if let Some(status) = self.api_error_status.filter(|_| {
            self.init_count == 1
                && self.result_count == 1
                && self.session_id.is_some()
                && exit_code.is_some()
                && final_artifact.is_some()
        }) {
            // A complete CLI error result can accompany exit 1. Preserve that
            // upstream failure instead of losing it to generic process failure.
            // This never establishes physical stop; Worker checks StopEvidence.
            ("EXECUTOR_ERROR", Some(format!("CLAUDE_API_ERROR_{status}")))
        } else if exit_code != Some(0) {
            ("PROCESS_FAILED", Some("PROCESS_EXIT_FAILURE".into()))
        } else if self.init_count != 1 || self.result_count != 1 || self.session_id.is_none() {
            ("INCOMPLETE", Some("CLAUDE_INCOMPLETE_EVENT_STREAM".into()))
        } else if !self.success {
            ("EXECUTOR_ERROR", Some("CLAUDE_RESULT_REJECTED".into()))
        } else if final_artifact.is_none() {
            (
                "EVIDENCE_STORAGE_FAILED",
                Some("EVIDENCE_STORAGE_FAILED".into()),
            )
        } else {
            ("EXECUTOR_COMPLETED", None)
        };
        ExecutorOutcome {
            execution_id: self.execution_id,
            upstream_session_id: self.session_id,
            exit_code,
            completion_reason: reason.into(),
            raw_event_digest: raw_digest,
            transcript_completeness: "CLAUDE_STREAM_JSON_RAW_PRESERVED".into(),
            final_artifact,
            error_class: error,
        }
    }
}
