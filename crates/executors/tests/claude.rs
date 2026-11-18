//! Local fixture/projection counterexamples only. No Claude process or model calls.
use forgeflow_domain::{ArtifactRef, CapabilityId, ExecutionEnvelope, VerificationStatus};
use forgeflow_executors::{
    ArtifactPin, ClaudeCredentialEnv, ClaudeDiscoveryEvidence, ClaudeLeafProfile, ClaudeStream,
    claude_doctor, extract_claude_result_text, prepare_claude_leaf, sha256,
};
use serde_json::json;

const INIT: &[u8] = b"{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"root\"}\n";
const RESULT: &[u8] = b"{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"session_id\":\"root\",\"result\":\"done\",\"unknown_field\":42}\n";
const UI_INVALIDATE: &[u8] = b"{\"type\":\"system\",\"subtype\":\"ui_invalidate\",\"session_id\":\"root\",\"event\":\"model\"}\n";
const API_ERROR_RESULT: &[u8] = b"{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"session_id\":\"root\",\"result\":\"API Error\",\"num_turns\":1,\"api_error_status\":404,\"terminal_reason\":\"api_error\"}\n";

fn stream(lines: &[&[u8]]) -> forgeflow_domain::ExecutorOutcome {
    let mut stream = ClaudeStream::new("fixture");
    for line in lines {
        stream.observe_line(line);
    }
    stream.finish(
        Some(0),
        false,
        sha256(&lines.concat()),
        Some("retained-final".into()),
    )
}
fn fixture() -> (
    tempfile::TempDir,
    ClaudeLeafProfile,
    ExecutionEnvelope,
    Vec<u8>,
) {
    let dir = tempfile::tempdir().unwrap();
    // Non-executed bytes with ELF identity; never represents a real CLI.
    let program = dir.path().join("fixture-elf");
    let executable = b"\x7fELFNO_MODEL_FIXTURE_NOT_A_REAL_PROGRAM";
    std::fs::write(&program, executable).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let home = dir.path().join("managed");
    std::fs::create_dir(&home).unwrap();
    let profile = ClaudeLeafProfile {
        id: "claude-leaf".into(),
        program: program.clone(),
        home,
        artifact_pins: vec![ArtifactPin {
            path: program,
            sha256: sha256(executable),
        }],
        model_route_id: "route".into(),
        model_id: "glm-5.3".into(),
        max_budget_usd: "0.50".into(),
        provider_base_url: "http://127.0.0.1:17891".into(),
        credential_env: ClaudeCredentialEnv::ApiKey,
        tools_allowlist: vec!["Read".into(), "Write".into()],
        permission_mode: "dontAsk".into(),
        help_verified_flags: [
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
        ]
        .map(str::to_owned)
        .to_vec(),
        max_turns: None,
    };
    let prompt = "实现文件\n$(never executed) `private`".as_bytes().to_vec();
    let envelope = serde_json::from_value(json!({
        "schema_version":"forgeflow.execution.v1","operation_id":"operation","project_id":"project","task_id":"task","task_revision":1,"attempt_id":"attempt","lease_id":"lease","generation":1,"worker_id":"worker","workspace_root":dir.path(),"base_sha":"a".repeat(40),
        "context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":["result.txt"],"prompt_artifact":{"artifact_id":"prompt","sha256":sha256(&prompt)},"model_route_id":"route","executor_profile_id":"claude-leaf","resource_profile_id":"resource","verification_plan_id":"verification","allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS","REQUEST_APPROVED_MODEL"],
        "issued_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-15T01:00:00Z","deadline_at":"2026-10-15T02:00:00Z","artifact_prefix":dir.path(),"secret_refs":[],"idempotency_key":"key","trace_id":"trace","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null
    })).unwrap();
    (dir, profile, envelope, prompt)
}

#[test]
fn prepare_preserves_stdin_and_fixes_permissions_model_and_config() {
    let (_dir, profile, envelope, prompt) = fixture();
    let launch = prepare_claude_leaf(&envelope, prompt.clone(), &profile).unwrap();
    assert_eq!(launch.stdin, prompt);
    assert_eq!(launch.program, profile.program);
    assert_eq!(launch.env.len(), 10);
    assert_eq!(launch.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:17891");
    assert_eq!(
        launch.env["CLAUDE_CONFIG_DIR"],
        profile.home.to_string_lossy()
    );
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
        assert_eq!(launch.env[name], profile.model_id);
    }
    assert!(!launch.env.contains_key("ANTHROPIC_API_KEY"));
    assert!(!launch.env.contains_key("ANTHROPIC_AUTH_TOKEN"));
    for flag in ["--bare", "--strict-mcp-config", "--no-session-persistence"] {
        assert!(launch.args.iter().any(|a| a == flag));
    }
    assert!(launch.args.windows(2).any(|w| w == ["--model", "glm-5.3"]));
    assert!(
        launch
            .args
            .windows(2)
            .any(|w| w == ["--permission-mode", "dontAsk"])
    );
    assert!(
        !launch
            .args
            .iter()
            .any(|a| a.contains("never executed") || a == "--dangerously-skip-permissions")
    );
}

#[test]
fn prepare_rejects_identity_tamper_no_model_resume_gateway_and_noncode() {
    let (_dir, profile, envelope, prompt) = fixture();
    let mut variants = Vec::new();
    let mut item = envelope.clone();
    item.executor_profile_id = "other".into();
    variants.push(item);
    let mut item = envelope.clone();
    item.model_route_id = "other".into();
    variants.push(item);
    let mut item = envelope.clone();
    item.max_model_requests = 0;
    variants.push(item);
    let mut item = envelope.clone();
    item.resume_session_id = Some("old".into());
    variants.push(item);
    let mut item = envelope.clone();
    item.enforcement.model_budget_mode = forgeflow_domain::ModelBudgetMode::GatewayEnforced;
    variants.push(item);
    let mut item = envelope.clone();
    item.session_purpose = forgeflow_domain::SessionPurpose::Planning;
    variants.push(item);
    for item in variants {
        assert!(prepare_claude_leaf(&item, prompt.clone(), &profile).is_err());
    }
    assert!(prepare_claude_leaf(&envelope, b"changed".to_vec(), &profile).is_err());
    std::fs::write(&profile.program, b"changed executable").unwrap();
    assert!(prepare_claude_leaf(&envelope, prompt, &profile).is_err());
}

#[test]
fn unsafe_profile_flags_tools_budget_and_wrapper_are_rejected() {
    let (_dir, profile, _envelope, _prompt) = fixture();
    for budget in ["0", "0.00", "1e2", "-1", "NaN", ".2", "1."] {
        let mut item = profile.clone();
        item.max_budget_usd = budget.into();
        assert!(item.verify_identity().is_err());
    }
    let mut item = profile.clone();
    item.max_turns = Some(1);
    assert!(item.verify_identity().is_err());
    let mut item = profile.clone();
    item.permission_mode = "bypassPermissions".into();
    assert!(item.verify_identity().is_err());
    let mut item = profile.clone();
    item.tools_allowlist.push("Agent".into());
    assert!(item.verify_identity().is_err());
    let mut item = profile.clone();
    item.help_verified_flags.retain(|f| f != "--bare");
    assert!(item.verify_identity().is_err());
    for url in [
        "http://remote.example",
        "https://user:pass@proxy.example",
        "http://127.0.0.1:17891?key=secret",
        "https://proxy.example/#fragment",
        "http://127.0.0.1:0",
        "http://127.0.0.1.evil",
    ] {
        let mut item = profile.clone();
        item.provider_base_url = url.into();
        assert!(item.verify_identity().is_err());
    }
    for url in [
        "https://proxy.example/anthropic",
        "http://127.0.0.1:17891",
        "http://[::1]:17891",
    ] {
        let mut item = profile.clone();
        item.provider_base_url = url.into();
        assert!(item.verify_identity().is_ok());
    }
    std::fs::write(&profile.program, b"#!/bin/sh\nexit 0\n").unwrap();
    let mut item = profile;
    item.artifact_pins[0].sha256 = sha256(b"#!/bin/sh\nexit 0\n");
    assert!(item.verify_identity().is_err());
}

#[test]
fn root_result_requires_exact_stream_and_keeps_raw_unknown_fields() {
    let mut parser = ClaudeStream::new("fixture");
    parser.observe_line(INIT);
    let parsed = parser.observe_line(RESULT);
    assert_eq!(parsed.raw, RESULT);
    assert_eq!(parsed.payload["unknown_field"], 42);
    assert_eq!(parser.upstream_session_id(), Some("root"));
    assert_eq!(
        parser
            .finish(Some(0), false, sha256(RESULT), Some("final".into()))
            .completion_reason,
        "EXECUTOR_COMPLETED"
    );
    assert_eq!(extract_claude_result_text(RESULT).unwrap(), "done");
    assert_eq!(stream(&[INIT]).completion_reason, "INCOMPLETE");
    assert_ne!(stream(&[RESULT]).completion_reason, "EXECUTOR_COMPLETED");
    assert_eq!(
        stream(&[INIT, RESULT, RESULT]).completion_reason,
        "PROTOCOL_ERROR"
    );
}

#[test]
fn child_result_is_observation_and_cannot_complete_or_replace_root() {
    let child = b"{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"session_id\":\"child\",\"parent_tool_use_id\":\"call-1\",\"result\":\"child done\"}\n";
    assert_eq!(stream(&[INIT, child]).completion_reason, "INCOMPLETE");
    assert_eq!(
        stream(&[INIT, child, RESULT]).completion_reason,
        "EXECUTOR_COMPLETED"
    );
    assert!(extract_claude_result_text(child).is_err());
}

#[test]
fn observed_pre_init_ui_and_complete_api_error_keep_upstream_failure_classification() {
    assert_eq!(
        stream(&[UI_INVALIDATE, INIT, RESULT]).completion_reason,
        "EXECUTOR_COMPLETED"
    );
    let mut parser = ClaudeStream::new("fixture");
    let metadata = parser.observe_line(UI_INVALIDATE);
    assert!(metadata.parse_error.is_none());
    assert_eq!(metadata.raw, UI_INVALIDATE);
    assert_eq!(parser.upstream_session_id(), None);
    parser.observe_line(INIT);
    let assistant_error = b"{\"type\":\"assistant\",\"session_id\":\"root\",\"parent_tool_use_id\":null,\"is_api_error_message\":true,\"error\":\"model_not_found\",\"message\":{\"role\":\"assistant\",\"content\":[]}}\n";
    assert!(parser.observe_line(assistant_error).parse_error.is_none());
    let terminal = parser.observe_line(API_ERROR_RESULT);
    assert!(terminal.parse_error.is_none());
    assert_eq!(terminal.raw, API_ERROR_RESULT);
    let outcome = parser.finish(Some(1), false, "raw".into(), Some("retained-final".into()));
    assert_eq!(outcome.completion_reason, "EXECUTOR_ERROR");
    assert_eq!(outcome.error_class.as_deref(), Some("CLAUDE_API_ERROR_404"));
    assert_eq!(outcome.exit_code, Some(1));
    assert!(extract_claude_result_text(API_ERROR_RESULT).is_err());
}

#[test]
fn api_error_metadata_never_bypasses_session_init_terminal_or_stop_checks() {
    let wrong_ui =
        b"{\"type\":\"system\",\"subtype\":\"ui_invalidate\",\"session_id\":\"wrong\"}\n";
    let other_pre_init =
        b"{\"type\":\"system\",\"subtype\":\"unqualified_metadata\",\"session_id\":\"root\"}\n";
    for lines in [
        vec![wrong_ui.as_slice(), INIT, API_ERROR_RESULT],
        vec![UI_INVALIDATE, INIT, INIT, API_ERROR_RESULT],
        vec![UI_INVALIDATE, INIT, API_ERROR_RESULT, API_ERROR_RESULT],
        vec![other_pre_init.as_slice(), INIT, API_ERROR_RESULT],
        vec![UI_INVALIDATE, API_ERROR_RESULT],
    ] {
        let mut parser = ClaudeStream::new("fixture");
        for raw in lines {
            parser.observe_line(raw);
        }
        let outcome = parser.finish(Some(1), false, "raw".into(), Some("final".into()));
        assert_eq!(outcome.completion_reason, "PROTOCOL_ERROR");
        assert_eq!(
            outcome.error_class.as_deref(),
            Some("CLAUDE_MALFORMED_EVENT_STREAM")
        );
    }
    let mut child: serde_json::Value = serde_json::from_slice(API_ERROR_RESULT).unwrap();
    child["parent_tool_use_id"] = "child-call".into();
    child["session_id"] = "child".into();
    let mut parser = ClaudeStream::new("fixture");
    parser.observe_line(INIT);
    parser.observe_line(&serde_json::to_vec(&child).unwrap());
    let outcome = parser.finish(Some(1), false, "raw".into(), Some("child-artifact".into()));
    assert_ne!(outcome.error_class.as_deref(), Some("CLAUDE_API_ERROR_404"));
    let mut parser = ClaudeStream::new("fixture");
    parser.observe_line(INIT);
    parser.observe_line(API_ERROR_RESULT);
    let no_exit = parser.finish(None, false, "raw".into(), Some("final".into()));
    assert_ne!(no_exit.error_class.as_deref(), Some("CLAUDE_API_ERROR_404"));
    for status in [json!("404"), json!(200), json!(1000), json!(null)] {
        let mut result: serde_json::Value = serde_json::from_slice(API_ERROR_RESULT).unwrap();
        result["api_error_status"] = status;
        let mut parser = ClaudeStream::new("fixture");
        parser.observe_line(INIT);
        parser.observe_line(&serde_json::to_vec(&result).unwrap());
        assert_eq!(
            parser
                .finish(Some(1), false, "raw".into(), Some("final".into()))
                .error_class
                .as_deref(),
            Some("PROCESS_EXIT_FAILURE")
        );
    }
}

#[test]
fn malformed_duplicate_keys_unknown_types_and_wrong_session_fail_closed() {
    for bad in [b"{\"secret\":\"do-not-echo\" invalid}\n".as_slice(), b"[]\n", b"{\"type\":\"invented\",\"session_id\":\"root\"}\n",
        b"{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"is_error\":false,\"session_id\":\"root\",\"result\":\"bad\"}\n",
        b"{\"type\":\"assistant\",\"session_id\":\"other\"}\n"] {
        let mut parser = ClaudeStream::new("fixture"); parser.observe_line(INIT);
        let observation = parser.observe_line(bad);
        assert_eq!(observation.raw, bad);
        assert!(observation.parse_error.as_deref().is_some_and(|s| !s.contains("do-not-echo")));
        parser.observe_line(RESULT);
        assert_eq!(parser.finish(Some(0), false, "raw".into(), Some("final".into())).completion_reason, "PROTOCOL_ERROR");
    }
}

#[test]
fn unknown_large_type_cannot_escape_as_public_event_kind() {
    for kind in [
        "unexpected-sensitive-kind".to_owned(),
        "sensitive-native-type".repeat(65536),
    ] {
        let raw = serde_json::to_vec(&json!({"type":kind,"session_id":"root"})).unwrap();
        let mut parser = ClaudeStream::new("fixture");
        parser.observe_line(INIT);
        let parsed = parser.observe_line(&raw);
        assert_eq!(parsed.kind, "unknown");
        assert_eq!(
            parsed.parse_error.as_deref(),
            Some("CLAUDE_UNKNOWN_EVENT_TYPE")
        );
        assert_eq!(parsed.raw, raw);
        assert_eq!(parsed.payload["type"], kind);
        parser.observe_line(RESULT);
        assert_eq!(
            parser
                .finish(Some(0), false, "raw".into(), Some("final".into()))
                .completion_reason,
            "PROTOCOL_ERROR"
        );
    }
}

#[test]
fn process_failure_storage_failure_and_terminal_errors_never_claim_completion() {
    let completed = |exit, cancelled, artifact| {
        let mut parser = ClaudeStream::new("fixture");
        parser.observe_line(INIT);
        parser.observe_line(RESULT);
        parser.finish(exit, cancelled, "raw".into(), artifact)
    };
    assert_eq!(
        completed(Some(1), false, Some("final".into())).completion_reason,
        "PROCESS_FAILED"
    );
    assert_eq!(
        completed(Some(0), false, None).completion_reason,
        "EVIDENCE_STORAGE_FAILED"
    );
    assert_eq!(
        completed(Some(0), true, Some("final".into())).completion_reason,
        "CANCELLED"
    );
    let error = b"{\"type\":\"result\",\"subtype\":\"error_max_budget_usd\",\"is_error\":true,\"session_id\":\"root\",\"errors\":[\"quota\"]}\n";
    assert_eq!(stream(&[INIT, error]).completion_reason, "EXECUTOR_ERROR");
}

#[test]
fn offline_doctor_never_upgrades_runtime_and_bounds_discovery() {
    let (_dir, profile, _envelope, _prompt) = fixture();
    let reference = || ArtifactRef {
        artifact_id: "fixture-receipt".into(),
        sha256: "b".repeat(64),
    };
    let evidence = || ClaudeDiscoveryEvidence {
        probe_id: "fixture-discovery".into(),
        version_stdout: b"2.1.287 (Claude Code)\n".to_vec(),
        version_exit_code: Some(0),
        help_stdout: profile.help_verified_flags.join("\n").into_bytes(),
        help_exit_code: Some(0),
        artifact_pins_ref: None,
        environment_ref: reference(),
        command_results_ref: reference(),
    };
    let report = claude_doctor(&profile, evidence()).unwrap();
    assert!(!report.capabilities.structured_events);
    for check in &report.checks {
        if matches!(
            check.check_id,
            CapabilityId::ExecutableIdentity | CapabilityId::VersionHelp
        ) {
            assert_eq!(check.status, VerificationStatus::Verified);
        } else {
            assert_eq!(check.status, VerificationStatus::NotRun);
        }
    }
    let mut bad = evidence();
    bad.help_exit_code = Some(1);
    let report = claude_doctor(&profile, bad).unwrap();
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.check_id == CapabilityId::VersionHelp)
            .unwrap()
            .status,
        VerificationStatus::Failed
    );
    let mut huge = evidence();
    huge.help_stdout = vec![b'x'; 131073];
    assert!(claude_doctor(&profile, huge).is_err());
}
