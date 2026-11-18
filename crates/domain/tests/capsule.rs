//! Contract counterexamples only. These tests do not prove runtime admission,
//! native-model capability, process stopping, or Git business acceptance.
use chrono::Utc;
use forgeflow_domain::*;
use serde_json::json;
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn reference(id: &str) -> ArtifactRef {
    ArtifactRef {
        artifact_id: id.into(),
        sha256: sha(id.as_bytes()),
    }
}
fn envelope() -> ExecutionEnvelope {
    ExecutionEnvelope {
        schema_version: "forgeflow.execution.v1".into(),
        operation_id: "op-1".into(),
        project_id: "project-1".into(),
        task_id: "task-1".into(),
        task_revision: 1,
        attempt_id: "attempt-1".into(),
        lease_id: "lease-1".into(),
        generation: 1,
        worker_id: "worker-1".into(),
        workspace_root: "/isolated/worktree".into(),
        base_sha: "a".repeat(40),
        context_manifest: ContextManifestRef {
            artifact_id: "context".into(),
            sha256: sha(b"context"),
            mandatory_paths: vec![],
            rendered_utf8_bytes: 7,
            token_estimate: None,
            tokenizer_id: None,
        },
        write_set: vec!["src/".into()],
        prompt_artifact: reference("prompt"),
        model_route_id: "route-1".into(),
        executor_profile_id: "profile-1".into(),
        resource_profile_id: "resource-1".into(),
        verification_plan_id: "verify-1".into(),
        allowed_effects: vec![
            AllowedEffect::ReadWorkspace,
            AllowedEffect::WriteDeclaredPaths,
        ],
        issued_at: "2026-10-15T00:00:00Z".into(),
        expires_at: "2026-10-15T00:01:00Z".into(),
        deadline_at: "2026-10-15T00:02:00Z".into(),
        artifact_prefix: "/isolated/artifacts".into(),
        secret_refs: vec![],
        idempotency_key: "key-1".into(),
        trace_id: "trace-1".into(),
        enforcement: Enforcement {
            model_budget_mode: ModelBudgetMode::DirectObserved,
            stage_resource_mode: StageResourceMode::AttemptReservation,
            build_capable: false,
            gateway_coverage_receipt_id: None,
            tool_guard_receipt_id: None,
            attempt_reserved_build_permits: 0,
            all_model_routes_covered: false,
            disabled_tool_entry_ids: vec![],
        },
        session_purpose: SessionPurpose::Execution,
        max_model_requests: 0,
        resume_session_id: None,
        command: None,
    }
}
fn capsule(e: &ExecutionEnvelope) -> CapsuleBinding {
    CapsuleBinding {
        schema_version: CAPSULE_SCHEMA_V1.into(),
        capsule_id: format!("capsule:{}", e.attempt_id),
        envelope_ref: ExecutionEnvelopeRef::from_envelope(e).unwrap(),
        driver_id: ExecutorDriverId::ClaudeCode,
        execution_kind: ExecutionKind::ManagedLeaf,
        executor_profile_sha256: sha(b"profile"),
        qualification_ref: reference("qualification"),
        team_write_policy: TeamWritePolicy::AggregateWriteScope,
    }
}
fn probe() -> DriverProbeResult {
    DriverProbeResult {
        schema_version: DRIVER_PROBE_SCHEMA_V1.into(),
        probe_id: "probe-1".into(),
        driver_id: ExecutorDriverId::ClaudeCode,
        mode: DriverMode::ClaudeLeaf,
        observed_at: Utc::now(),
        executable_sha256: Some(sha(b"executable")),
        artifact_pins_ref: Some(reference("pins")),
        executor_profile_sha256: Some(sha(b"profile")),
        cli_version: Some("bounded-local-version".into()),
        capabilities: ExecutorCapabilities {
            adapter_contract_version: "forgeflow.executor.v1".into(),
            protocol: "CLAUDE_STREAM_JSON".into(),
            protocol_version: None,
            structured_events: false,
            session_resume: false,
            session_cancel: false,
            process_cancel: false,
            session_close: false,
            usage_accounting: "UNKNOWN".into(),
            transcript_replay: false,
            nested_spawn_control: "UNKNOWN".into(),
        },
        checks: vec![CapabilityCheck {
            check_id: CapabilityId::VersionHelp,
            status: VerificationStatus::Verified,
            scope: "Pinned local --help only; no model".into(),
            reason_code: None,
            evidence_refs: vec![reference("help-receipt")],
        }],
        environment_ref: reference("environment"),
        command_results_ref: reference("commands"),
        evidence_class: EvidenceClass::LocalProcess,
    }
}
fn event() -> NativeEventObservation {
    let raw = b"{\"type\":\"result\",\"subtype\":\"success\"}\r\n";
    NativeEventObservation {
        schema_version: NATIVE_EVENT_SCHEMA_V1.into(),
        driver_id: ExecutorDriverId::ClaudeCode,
        capsule_id: "capsule:attempt-1".into(),
        executor_profile_sha256: sha(b"profile"),
        stream_id: "stream-1".into(),
        stream_seq: 1,
        native_seq: None,
        native_session_id: Some("native-root".into()),
        allocation_id: None,
        lifecycle_number: None,
        native_member_id: None,
        native_task_id: None,
        occurred_at: None,
        observed_at: Utc::now(),
        kind: NativeEventKind::AgentFinished,
        source_ref: ArtifactRef {
            artifact_id: "raw-segment-1".into(),
            sha256: sha(raw),
        },
        frame_offset: 0,
        frame_length: raw.len() as u64,
        raw_sha256: sha(raw),
        payload_ref: None,
        summary: json!({"native_type":"result","native_status":"success"}),
        parse_error: None,
        evidence_class: EvidenceClass::NoModelFixture,
    }
}
fn outer(event: &NativeEventObservation, e: &ExecutionEnvelope) -> WorkerEvent {
    WorkerEvent {
        event_id: "event-1".into(),
        project_id: e.project_id.clone(),
        attempt_id: e.attempt_id.clone(),
        lease_id: e.lease_id.clone(),
        generation: e.generation,
        worker_id: e.worker_id.clone(),
        kind: "EXECUTOR_EVENT".into(),
        payload: serde_json::to_value(event).unwrap(),
    }
}

#[test]
fn reference_hashes_original_typed_envelope_and_detects_frozen_input_changes() {
    let e = envelope();
    let r = ExecutionEnvelopeRef::from_envelope(&e).unwrap();
    assert_eq!(r.sha256, sha(&serde_json::to_vec(&e).unwrap()));
    assert!(r.validate_against(&e).is_ok());
    let mut changed = e.clone();
    changed.project_id = "project-2".into();
    assert!(r.validate_against(&changed).is_err());
    changed = e.clone();
    changed.generation = 2;
    assert!(r.validate_against(&changed).is_err());
    changed = e.clone();
    changed.write_set.push("other/".into());
    assert!(r.validate_against(&changed).is_err());
    changed = e.clone();
    changed.verification_plan_id = "other-plan".into();
    assert!(r.validate_against(&changed).is_err());
    // No new canonical field synonyms appear in the reference.
    let value = serde_json::to_value(r).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 4);
    assert!(value.get("work_unit_id").is_none());
}

#[test]
fn read_only_capsule_and_profile_mode_cannot_silently_expand_scope() {
    let e = envelope();
    let mut c = capsule(&e);
    assert!(c.validate_against(&e, &sha(b"profile")).is_ok());
    assert!(c.validate_against(&e, &sha(b"different-profile")).is_err());
    c.team_write_policy = TeamWritePolicy::ReadOnly;
    assert!(c.validate_against(&e, &sha(b"profile")).is_err());
    c = capsule(&e);
    c.capsule_id = "capsule:different-attempt".into();
    assert!(c.validate().is_err());
    c = capsule(&e);
    let mut p = probe();
    assert!(c.validate_probe_binding(&p).is_ok());
    p.mode = DriverMode::ClaudeInteractiveTeam;
    assert!(c.validate_probe_binding(&p).is_err());
    p.mode = DriverMode::DshHeadless;
    assert!(p.validate().is_err());
}

#[test]
fn observation_has_no_execution_identity_and_strictly_rejects_added_authority() {
    let o = ObserveOnlyBinding {
        schema_version: NATIVE_OBSERVATION_BINDING_SCHEMA_V1.into(),
        observation_id: "external-1".into(),
        project_id: "project-1".into(),
        driver_id: ExecutorDriverId::Dsh,
        executor_profile_sha256: None,
        native_session_id: "opaque-session".into(),
        registered_at: Utc::now(),
    };
    assert!(o.validate().is_ok());
    let mut value = serde_json::to_value(&o).unwrap();
    for name in ["attempt_id", "lease_id", "generation", "write_set"] {
        assert!(value.get(name).is_none());
    }
    value["lease_id"] = json!("forged");
    assert!(serde_json::from_value::<ObserveOnlyBinding>(value).is_err());
}

#[test]
fn probe_requires_nonduplicated_evidence_and_does_not_promote_fixtures() {
    let mut p = probe();
    assert!(p.validate().is_ok());
    p.checks.push(p.checks[0].clone());
    assert!(p.validate().is_err());
    p = probe();
    p.checks[0].evidence_refs.clear();
    assert!(p.validate().is_err());
    p = probe();
    let mut conflicting = p.checks[0].evidence_refs[0].clone();
    conflicting.sha256 = sha(b"different bytes with same artifact ID");
    p.checks[0].evidence_refs.push(conflicting);
    assert!(p.validate().is_err());
    for capability in [
        CapabilityId::StartHeadless,
        CapabilityId::NativeTeam,
        CapabilityId::NativeWorkflow,
        CapabilityId::BusinessE2e,
        CapabilityId::ModelEgressEnforced,
    ] {
        p = probe();
        p.evidence_class = EvidenceClass::NoModelFixture;
        p.checks[0].check_id = capability;
        assert!(p.validate().is_err(), "fixture promoted {capability:?}");
    }
    p = probe();
    p.evidence_class = EvidenceClass::Unknown;
    assert!(p.validate().is_err());
    // Unknown/untested is legal metadata, even if a legacy bool declares support.
    p = probe();
    p.checks[0].check_id = CapabilityId::SessionResume;
    p.checks[0].status = VerificationStatus::NotRun;
    p.checks[0].evidence_refs.clear();
    p.capabilities.session_resume = true;
    assert!(p.validate().is_ok());
    assert_eq!(p.checks[0].status, VerificationStatus::NotRun);
    p = probe();
    p.executable_sha256 = Some("A".repeat(64));
    assert!(p.validate().is_err());
}

#[test]
fn lifecycle_scope_preserves_history_without_becoming_a_grant() {
    let e = envelope();
    let c = capsule(&e);
    let mut r = NativeLifecycleRef {
        driver_id: c.driver_id,
        executor_profile_sha256: c.executor_profile_sha256.clone(),
        project_id: e.project_id.clone(),
        attempt_id: e.attempt_id.clone(),
        generation: e.generation,
        worker_id: e.worker_id.clone(),
        native_session_id: "same-native-session".into(),
        allocation_id: "allocation-1".into(),
        lifecycle_number: 1,
        parent_allocation_id: None,
    };
    assert!(r.validate_against(&e, &c).is_ok());
    let old = serde_json::to_value(&r).unwrap();
    r.lifecycle_number = 2;
    r.allocation_id = "allocation-2".into();
    assert!(r.validate_against(&e, &c).is_ok());
    assert_ne!(old, serde_json::to_value(&r).unwrap());
    r.driver_id = ExecutorDriverId::Dsh;
    assert!(r.validate_against(&e, &c).is_err());
    r.driver_id = c.driver_id;
    r.parent_allocation_id = Some(r.allocation_id.clone());
    assert!(r.validate_against(&e, &c).is_err());
}

#[test]
fn raw_frame_keeps_crlf_and_cannot_reference_altered_or_outside_bytes() {
    let mut event = event();
    let raw = b"{\"type\":\"result\",\"subtype\":\"success\"}\r\n";
    assert!(event.validate_raw_frame(raw).is_ok());
    let normalized = b"{\"type\":\"result\",\"subtype\":\"success\"}\n";
    assert!(event.validate_raw_frame(normalized).is_err());
    event.frame_offset = 1;
    assert!(event.validate_raw_frame(raw).is_err());
    event.frame_offset = u64::MAX;
    assert!(event.validate().is_err());
    event = self::event();
    event.raw_sha256 = sha(b"other");
    assert!(event.validate_raw_frame(raw).is_err());
}

#[test]
fn event_rejects_zero_or_large_sequence_partial_lifecycle_and_oversize_summary() {
    let mut e = event();
    e.stream_seq = 0;
    assert!(e.validate().is_err());
    e = event();
    e.stream_seq = i64::MAX as u64 + 1;
    assert!(e.validate().is_err());
    e = event();
    e.allocation_id = Some("allocation".into());
    assert!(e.validate().is_err());
    e.lifecycle_number = Some(1);
    assert!(e.validate().is_ok());
    e.native_session_id = None;
    assert!(e.validate().is_err());
    e = event();
    e.summary = json!({"text":"x".repeat(NATIVE_EVENT_SUMMARY_MAX_BYTES)});
    assert!(e.validate().is_err());
    e = event();
    e.summary["worker_id"] = json!("forged-worker");
    assert!(e.validate().is_err());
}

#[test]
fn stream_gap_duplicate_and_namespace_changes_are_not_contiguous_progress() {
    let previous = event();
    let mut next = previous.clone();
    next.stream_seq = 2;
    assert!(next.validate_successor_of(&previous).is_ok());
    next.stream_seq = 3;
    assert!(next.validate_successor_of(&previous).is_err());
    next.stream_seq = 1;
    assert!(next.validate_successor_of(&previous).is_err());
    next.stream_seq = 2;
    next.stream_id = "another-stream".into();
    assert!(next.validate_successor_of(&previous).is_err());
    next.stream_id = previous.stream_id.clone();
    next.driver_id = ExecutorDriverId::Dsh;
    assert!(next.validate_successor_of(&previous).is_err());
}

#[test]
fn event_outer_scope_profile_and_projection_are_bound_but_native_success_is_not_canonical_success()
{
    let e = envelope();
    let c = capsule(&e);
    let observed = event();
    let mut w = outer(&observed, &e);
    assert!(observed.validate_binding(&w, &e, &c).is_ok());
    w.generation += 1;
    assert!(observed.validate_binding(&w, &e, &c).is_err());
    w = outer(&observed, &e);
    w.payload["summary"]["native_status"] = json!("different");
    assert!(observed.validate_binding(&w, &e, &c).is_err());
    w = outer(&observed, &e);
    let mut other = observed.clone();
    other.executor_profile_sha256 = sha(b"other");
    assert!(other.validate_binding(&w, &e, &c).is_err());
    // The observation has no canonical state or transition. Existing transitions stay authoritative.
    let value = serde_json::to_value(&observed).unwrap();
    assert!(value.get("state").is_none());
    assert!(!AttemptState::Running.can_transition(AttemptState::Succeeded));
}

#[test]
fn cancellation_ack_and_failure_do_not_imply_physical_stop_proof() {
    let mut c = CancelObservation {
        request_id: "cancel-1".into(),
        phase: CancelPhase::Acknowledged,
        failure: None,
        evidence_ref: None,
    };
    assert!(c.validate_shape().is_ok());
    assert_ne!(c.phase, CancelPhase::ProcessExitProven);
    c.phase = CancelPhase::ProcessExitProven;
    assert!(c.validate_shape().is_err());
    c.evidence_ref = Some(reference("physical-stop"));
    assert!(c.validate_shape().is_ok()); // Reference shape only, not physical proof.
    c.failure = Some(CancelFailure::Timeout);
    assert!(c.validate_shape().is_err());
    c.phase = CancelPhase::Unknown;
    assert!(c.validate_shape().is_ok());
    let mut e = event();
    e.kind = NativeEventKind::StopObserved;
    e.summary = json!({"phase":"ACKNOWLEDGED"});
    assert!(e.validate().is_err());
    e.summary = serde_json::to_value(c).unwrap();
    assert!(e.validate().is_ok());
}

#[test]
fn static_write_scope_uses_components_and_rejects_effect_or_path_expansion() {
    let e = envelope();
    let mut r = WriteAuthorizationRequest {
        envelope_ref: ExecutionEnvelopeRef::from_envelope(&e).unwrap(),
        capsule_id: "capsule:attempt-1".into(),
        requested_effect: AllowedEffect::WriteDeclaredPaths,
        requested_paths: vec!["src/module.rs".into()],
        native_allocation_id: None,
    };
    assert!(r.validate_against(&e).is_ok());
    for path in [
        "src-other/file.rs",
        "../src/module.rs",
        "/src/module.rs",
        "src/../other.rs",
        "src\\module.rs",
    ] {
        r.requested_paths = vec![path.into()];
        assert!(r.validate_against(&e).is_err(), "accepted {path}");
    }
    r.requested_paths = vec!["src/".into(), "src".into()];
    assert!(r.validate_against(&e).is_err());
    r.requested_paths = vec!["src/a.rs".into()];
    r.requested_effect = AllowedEffect::RequestApprovedModel;
    assert!(r.validate_against(&e).is_err());
    r.requested_effect = AllowedEffect::WriteDeclaredPaths;
    r.requested_paths.clear();
    assert!(r.validate_against(&e).is_err());
    // Pure input check deliberately does not inspect the wall clock or a current lease.
    assert!(e.expires_at.starts_with("2026-10-15"));
    r.requested_paths = vec!["src/a.rs".into()];
    assert!(r.validate_against(&e).is_ok());
}

#[test]
fn explanation_only_shape_is_strict_without_computing_live_allow() {
    let e = envelope();
    let mut d = WriteAuthorizationDecision {
        schema_version: WRITE_AUTHORIZATION_SCHEMA_V1.into(),
        envelope_ref: ExecutionEnvelopeRef::from_envelope(&e).unwrap(),
        attempt_revision: 1,
        decision: AuthorizationDecisionKind::Deny,
        reason_codes: vec!["LEASE_REVOKED".into()],
        team_write_policy: TeamWritePolicy::AggregateWriteScope,
        guard_receipt_ref: None,
        checked_at: Utc::now(),
        operation_id: e.operation_id.clone(),
    };
    assert!(d.validate_shape().is_ok());
    d.reason_codes.push("LEASE_REVOKED".into());
    assert!(d.validate_shape().is_err());
    d.reason_codes = vec!["a prose message with secrets is not a machine code".into()];
    assert!(d.validate_shape().is_err());
    d.reason_codes = vec!["LEASE_REVOKED".into()];
    d.attempt_revision = 0;
    assert!(d.validate_shape().is_err());
}

#[test]
fn wire_names_unknown_fields_and_duplicate_json_fields_are_rejected() {
    assert_eq!(
        serde_json::to_value(CapabilityId::BusinessE2e).unwrap(),
        json!("BUSINESS_E2E")
    );
    assert_eq!(
        serde_json::to_value(DriverMode::ClaudeInteractiveTeam).unwrap(),
        json!("CLAUDE_INTERACTIVE_TEAM")
    );
    assert_eq!(
        serde_json::to_value(ExecutorDriverId::Dsh).unwrap(),
        json!("DSH")
    );
    let e = envelope();
    let c = capsule(&e);
    let mut value = serde_json::to_value(c).unwrap();
    value["work_unit_id"] = json!("synonym");
    assert!(serde_json::from_value::<CapsuleBinding>(value).is_err());
    let duplicate = format!(
        "{{\"project_id\":\"p\",\"project_id\":\"q\",\"attempt_id\":\"a\",\"generation\":1,\"sha256\":\"{}\"}}",
        sha(b"x")
    );
    assert!(serde_json::from_str::<ExecutionEnvelopeRef>(&duplicate).is_err());
    let mut p = serde_json::to_value(probe()).unwrap();
    p["new_authority"] = json!(true);
    assert!(serde_json::from_value::<DriverProbeResult>(p).is_err());
    let mut ev = serde_json::to_value(event()).unwrap();
    ev["state"] = json!("SUCCEEDED");
    assert!(serde_json::from_value::<NativeEventObservation>(ev).is_err());
}
