//! Claude leaf observations reuse the existing journal, lease and process supervisor.
//! The legacy restricted raw projection is PARTIAL, not a registered native-event v1 artifact.
use super::*;
use forgeflow_executors::{ClaudeStream, ParsedEvent};

pub(crate) const MAX_CLAUDE_FRAME_BYTES: u64 = 32 * 1024 * 1024;

/// These high-frequency observations remain lossless in stdout.ndjson. The caller
/// must feed every frame to ClaudeStream first, including frames not projected.
/// Source sequence is physical receive order, not a contiguous business-event cursor.
pub(crate) fn should_project(parsed: &ParsedEvent) -> bool {
    parsed.parse_error.is_some()
        || !(parsed.kind == "stream_event"
            || (parsed.kind == "system" && parsed.payload["subtype"] == "thinking_tokens"))
}

pub(crate) enum NativeStream {
    Dsh(HeadlessStream),
    Claude(ClaudeStream),
}
impl NativeStream {
    pub(crate) fn new(execution: &str, claude: bool) -> Self {
        if claude {
            Self::Claude(ClaudeStream::new(execution))
        } else {
            Self::Dsh(HeadlessStream::new(execution))
        }
    }
    pub(crate) fn is_claude(&self) -> bool {
        matches!(self, Self::Claude(_))
    }
    pub(crate) fn observe_line(&mut self, raw: &[u8]) -> ParsedEvent {
        match self {
            Self::Dsh(stream) => stream.observe_line(raw),
            Self::Claude(stream) => stream.observe_line(raw),
        }
    }
    pub(crate) fn terminal(&self, parsed: &ParsedEvent) -> bool {
        parsed.parse_error.is_none()
            && if self.is_claude() {
                parsed.kind == "result"
                    && parsed
                        .payload
                        .get("parent_tool_use_id")
                        .is_none_or(Value::is_null)
            } else {
                parsed.kind == "final"
            }
    }
    pub(crate) fn projection(&self, parsed: &ParsedEvent, raw: &[u8]) -> Value {
        if self.is_claude() {
            // Do not publish prompts, tool output, init config or complete result text in events.
            let mut summary = serde_json::Map::new();
            for name in [
                "type",
                "subtype",
                "session_id",
                "parent_tool_use_id",
                "is_error",
            ] {
                if let Some(value) = parsed.payload.get(name) {
                    if value.is_boolean()
                        || value.is_null()
                        || value.as_str().is_some_and(|s| s.len() <= 512)
                    {
                        summary.insert(name.into(), value.clone());
                    }
                }
            }
            json!({"sequence":parsed.sequence,"native_type":parsed.kind,"payload":summary,
                "parse_error":parsed.parse_error,"driver_id":"CLAUDE_CODE","executor_kind":"CLAUDE_CODE_LEAF",
                "native_event_contract":"PARTIAL_RESTRICTED_RAW_PROJECTION","raw_sha256":sha256(raw),
                "raw_bytes":raw.len(),"payload_in_artifact":true})
        } else if raw.len() > 65536 {
            json!({"sequence":parsed.sequence,"native_type":parsed.kind,"raw_sha256":sha256(raw),"raw_bytes":raw.len(),"payload_in_artifact":true})
        } else {
            json!({"sequence":parsed.sequence,"native_type":parsed.kind,"payload":parsed.payload,"parse_error":parsed.parse_error})
        }
    }
}

pub(crate) fn read_credentials(
    config: &WorkerConfig,
    envelope: &ExecutionEnvelope,
) -> Result<BTreeMap<String, String>> {
    let profile = config
        .profile
        .claude()
        .context("Claude credential profile missing")?;
    let expected = profile.credential_env.env_name();
    if envelope.secret_refs.len() != 1 {
        bail!("Claude leaf requires exactly one explicit credential secret reference");
    }
    let binding = config
        .secret_files
        .get(&envelope.secret_refs[0])
        .context("Claude credential reference unavailable")?;
    if binding.env_name != expected {
        bail!("Claude credential mechanism differs from frozen profile");
    }
    let values = read_secrets(config, envelope)?;
    if values.len() != 1
        || values
            .get(expected)
            .is_none_or(|value| value.trim().is_empty() || value.contains(['\r', '\n', '\0']))
    {
        bail!("Claude credential must be a nonempty single-line value");
    }
    Ok(values)
}

pub(crate) fn prepare_home(config: &WorkerConfig, envelope: &ExecutionEnvelope) -> Result<PathBuf> {
    let home = config
        .data_root
        .join("executor-homes")
        .join(&envelope.project_id)
        .join(&envelope.attempt_id)
        .join("claude");
    std::fs::create_dir_all(&home)?;
    let metadata = std::fs::symlink_metadata(&home)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("Claude home must be an independent real directory");
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    bind_project_home(&home, &envelope.project_id, config.profile.id())?;
    Ok(home)
}

pub(crate) fn validate_readonly_mount(
    config: &WorkerConfig,
    envelope: &ExecutionEnvelope,
    path: &Path,
) -> Result<()> {
    let source_home = std::fs::canonicalize(config.profile.home())?;
    if source_home.starts_with(path) || path.starts_with(&source_home) {
        bail!("Claude sandbox must not expose the source configuration home or its ancestor");
    }
    for reference in &envelope.secret_refs {
        let binding = config
            .secret_files
            .get(reference)
            .context("Claude credential reference unavailable")?;
        let secret = std::fs::canonicalize(&binding.path)?;
        if secret.starts_with(path) {
            bail!("Claude sandbox readonly mount exposes a credential file");
        }
    }
    Ok(())
}

pub(crate) async fn parse_persisted_stream(
    client: &ControlClient,
    journal: &Journal,
    envelope: &ExecutionEnvelope,
    stop: &StopEvidence,
) -> Result<ExecutorOutcome> {
    let raw_digest = hash_file(&journal.path("stdout.ndjson")).await?;
    let mut reader = BufReader::new(tokio::fs::File::open(journal.path("stdout.ndjson")).await?);
    let mut stream = ClaudeStream::new(journal.execution_id()?);
    let mut index = 0;
    let mut final_artifact = None;
    loop {
        index += 1;
        let Some(line) = read_native_line(&mut reader, journal, index).await? else {
            break;
        };
        let (raw, spool) = match line {
            NativeLine::Buffered(raw) => (raw, None),
            NativeLine::Spooled {
                path,
                raw_bytes,
                raw_sha256,
                ..
            } => {
                if raw_bytes > MAX_CLAUDE_FRAME_BYTES {
                    bail!(
                        "CLAUDE_FRAME_LIMIT_EXCEEDED: complete original retained in {}",
                        path.display()
                    );
                }
                let raw = tokio::fs::read(&path).await?;
                if raw.len() as u64 != raw_bytes || sha256(&raw) != raw_sha256 {
                    bail!("Claude spool identity changed");
                }
                (raw, Some(path))
            }
        };
        let parsed = stream.observe_line(&raw);
        if !should_project(&parsed) {
            // The complete source was fsynced by the supervisor before its stop
            // receipt. Remove only this parser's temporary oversized-line copy.
            if let Some(path) = spool {
                std::fs::remove_file(path)?;
            }
            continue;
        }
        let raw_path = native_raw_path(journal, parsed.sequence)?;
        persist_native_raw(&raw_path, &raw)?;
        if parsed.kind == "result"
            && parsed.parse_error.is_none()
            && parsed
                .payload
                .get("parent_tool_use_id")
                .is_none_or(Value::is_null)
        {
            link_final_artifact(journal, &raw_path)?;
            final_artifact = Some(journal.path("final.json").to_string_lossy().into_owned());
        }
        let projection =
            NativeStream::Claude(ClaudeStream::new("projection-only")).projection(&parsed, &raw);
        let projection = normalize_native_for_source(
            journal,
            envelope,
            parsed.sequence,
            &parsed.kind,
            projection,
            &raw_path,
            &sha256(&raw),
            raw.len() as u64,
            "claude_code_leaf",
        )?;
        queue_event(
            client,
            journal,
            &event(
                envelope,
                "EXECUTOR_EVENT",
                projection,
                &format!("native-{:020}", parsed.sequence),
            ),
        )
        .await?;
        if let Some(path) = spool {
            std::fs::remove_file(path)?;
        }
    }
    let cancelled = stop.process_exit_confirmed && stop.reason.starts_with("cancelled");
    let mut outcome = stream.finish(stop.exit_code, cancelled, raw_digest, final_artifact);
    if !stop.process_exit_confirmed {
        outcome.completion_reason = "RECOVERY_REQUIRED".into();
        outcome.error_class = Some("STOP_UNCONFIRMED".into());
    }
    if stop.log_error.is_some() {
        outcome.completion_reason = "EVIDENCE_STORAGE_FAILED".into();
        outcome.error_class = Some("EVIDENCE_STORAGE_FAILED".into());
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(root: &Path) -> WorkerConfig {
        let mut config = crate::tests::liveness_config("http://127.0.0.1:1", root);
        config.profile = serde_json::from_value(json!({"kind":"CLAUDE_CODE_LEAF","id":"profile-live","program":"/bin/true","home":root.join("source-home"),"artifact_pins":[],"model_route_id":"route-live","model_id":"glm-5.3","provider_base_url":"http://127.0.0.1:17891","credential_env":"API_KEY","max_budget_usd":"1.00","tools_allowlist":[],"permission_mode":"dontAsk","help_verified_flags":[]})).unwrap();
        config
    }
    #[test]
    fn suppressed_partial_observations_still_validate_session_and_malformed_frames() {
        for (kind, subtype) in [
            ("stream_event", Value::Null),
            ("system", json!("thinking_tokens")),
        ] {
            let mut stream = ClaudeStream::new("no-model-parser-fixture");
            stream.observe_line(br#"{"type":"system","subtype":"init","session_id":"root"}"#);
            let valid =
                serde_json::to_vec(&json!({"type":kind,"subtype":subtype,"session_id":"root"}))
                    .unwrap();
            let parsed = stream.observe_line(&valid);
            assert!(parsed.parse_error.is_none());
            assert!(!should_project(&parsed));
            assert_eq!(parsed.sequence, 2);
            let changed = serde_json::to_vec(
                &json!({"type":kind,"subtype":subtype,"session_id":"wrong-root"}),
            )
            .unwrap();
            let parsed = stream.observe_line(&changed);
            assert!(parsed.parse_error.is_some());
            assert!(should_project(&parsed));
            assert_eq!(
                stream
                    .finish(
                        Some(0),
                        false,
                        "digest".into(),
                        Some("fixture-final".into())
                    )
                    .completion_reason,
                "PROTOCOL_ERROR"
            );
        }
        let mut stream = ClaudeStream::new("no-model-malformed-fixture");
        let parsed = stream.observe_line(br#"{"type":"stream_event","session_id":"root""#);
        assert!(parsed.parse_error.is_some());
        assert!(should_project(&parsed));
    }
    #[test]
    fn credential_binding_cannot_override_environment_or_switch_auth() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let mut config = config(temp.path());
        let mut envelope = crate::tests::liveness_envelope();
        std::fs::create_dir_all(config.profile.home()).unwrap();
        let secret = temp.path().join("fixture-key");
        std::fs::write(&secret, "no-model-fixture-key\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        config.secret_files.insert(
            "credential".into(),
            SecretBinding {
                env_name: "ANTHROPIC_API_KEY".into(),
                path: secret,
            },
        );
        envelope.secret_refs = vec!["credential".into()];
        assert_eq!(read_credentials(&config, &envelope).unwrap().len(), 1);
        assert!(
            validate_readonly_mount(&config, &envelope, &config.secret_files["credential"].path)
                .unwrap_err()
                .to_string()
                .contains("credential")
        );
        for name in [
            "HOME",
            "PATH",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CONFIG_DIR",
            "ANTHROPIC_AUTH_TOKEN",
        ] {
            config.secret_files.get_mut("credential").unwrap().env_name = name.into();
            assert!(read_credentials(&config, &envelope).is_err());
        }
        config.secret_files.get_mut("credential").unwrap().env_name = "ANTHROPIC_API_KEY".into();
        envelope.secret_refs.push("credential".into());
        assert!(read_credentials(&config, &envelope).is_err());
    }
    #[test]
    fn claude_home_is_private_per_attempt_without_copying_source_home() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let config = config(temp.path());
        let mut envelope = crate::tests::liveness_envelope();
        std::fs::create_dir_all(config.profile.home()).unwrap();
        std::fs::write(
            config.profile.home().join("personal-hook"),
            b"not-inherited",
        )
        .unwrap();
        let first = prepare_home(&config, &envelope).unwrap();
        envelope.attempt_id = "attempt-second".into();
        let second = prepare_home(&config, &envelope).unwrap();
        assert_ne!(first, second);
        assert!(!first.join("personal-hook").exists());
        assert!(validate_readonly_mount(&config, &envelope, temp.path()).is_err());
        assert!(validate_readonly_mount(&config, &envelope, Path::new("/usr")).is_ok());
        assert_eq!(
            std::fs::metadata(first).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(second).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    #[test]
    fn claude_projection_retains_identity_without_publishing_prompt_or_result() {
        let mut stream = NativeStream::new("local-execution", true);
        let raw = br#"{"type":"system","subtype":"init","session_id":"root","secret":"not-public"}
"#;
        let parsed = stream.observe_line(raw);
        let projected = stream.projection(&parsed, raw);
        assert_eq!(projected["native_type"], "system");
        assert_eq!(projected["payload"]["session_id"], "root");
        assert!(!projected.to_string().contains("not-public"));
        let raw = br#"{"type":"result","subtype":"success","is_error":false,"session_id":"root","result":"private-complete-answer"}
"#;
        let parsed = stream.observe_line(raw);
        assert!(stream.terminal(&parsed));
        assert!(
            !stream
                .projection(&parsed, raw)
                .to_string()
                .contains("private-complete-answer")
        );
    }
    #[test]
    fn child_result_is_never_the_root_final() {
        let mut stream = NativeStream::new("local-execution", true);
        let parsed = stream.observe_line(br#"{"type":"result","subtype":"success","is_error":false,"session_id":"child","parent_tool_use_id":"call-1","result":"child-answer"}"#);
        assert!(!stream.terminal(&parsed));
    }
}
