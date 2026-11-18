//! Pure binding checks only. Contract receipts here are synthetic identifiers;
//! registration and verified freezing remain the Store's responsibility.
use forgeflow_domain::*;
use forgeflow_planner::*;

fn envelope(task: &TaskCard) -> ExecutionEnvelope {
    ExecutionEnvelope {
        schema_version: "forgeflow.execution.v1".into(),
        operation_id: "operation".into(),
        project_id: task.project_id.clone(),
        task_id: task.task_id.clone(),
        task_revision: task.task_revision,
        attempt_id: "attempt".into(),
        lease_id: "lease".into(),
        generation: 1,
        worker_id: "worker".into(),
        workspace_root: "/tmp/contract-binding-fixture".into(),
        base_sha: "1111111111111111111111111111111111111111".into(),
        context_manifest: ContextManifestRef {
            artifact_id: "context".into(),
            sha256: sha256(b"context"),
            mandatory_paths: vec![],
            rendered_utf8_bytes: 7,
            token_estimate: None,
            tokenizer_id: None,
        },
        write_set: task.write_set.clone(),
        prompt_artifact: ArtifactRef {
            artifact_id: "prompt".into(),
            sha256: sha256(b"finite approved prompt"),
        },
        model_route_id: "route".into(),
        executor_profile_id: "exec".into(),
        resource_profile_id: "resources".into(),
        verification_plan_id: "verify".into(),
        allowed_effects: vec![AllowedEffect::ReadWorkspace],
        issued_at: "2026-10-09T00:00:00Z".into(),
        expires_at: "2026-10-09T00:05:00Z".into(),
        deadline_at: "2026-10-09T00:10:00Z".into(),
        artifact_prefix: "/tmp/contract-binding-artifacts".into(),
        secret_refs: vec![],
        idempotency_key: "operation".into(),
        trace_id: "trace".into(),
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
        max_model_requests: 1,
        resume_session_id: None,
        command: None,
    }
}

fn fixture() -> DraftBundle {
    let source = normalize_requirements(
        "spec.md",
        "- Produce a versioned public format\n- Consume that exact public format",
        RequirementFormat::Markdown,
    )
    .unwrap();
    let mut draft = rules_based_draft(DraftRequest {
        project_id: "project".into(),
        flow_revision: 1,
        source,
        owner_id: "owner".into(),
        team_id: "team".into(),
        write_set: vec![],
        execution_profile: "exec".into(),
        verification_plan: "verify".into(),
    })
    .unwrap();
    let binding = ContractBinding {
        contract_id: "public-format".into(),
        version: 1,
        spec_sha256: sha256(b"public format schema"),
    };
    let producer_id = draft.flow.tasks[0].task_id.clone();
    let consumer_id = draft.flow.tasks[1].task_id.clone();
    draft
        .context
        .task_specs
        .get_mut(&producer_id)
        .unwrap()
        .contract_produces = vec![binding.clone()];
    let consumer_spec = draft.context.task_specs.get_mut(&consumer_id).unwrap();
    consumer_spec.contract_consumes = vec![binding.clone()];
    consumer_spec.dependency_refs = vec![DependencySpec {
        task_id: producer_id.clone(),
        project_id: "project".into(),
        kind: DependencyKind::Integrated,
        binding_id: "producer:integrated".into(),
    }];
    draft.flow.tasks[1].dependencies = vec![producer_id];
    for task in &mut draft.flow.tasks {
        task.state = TaskPlanningState::Planned;
        let spec = draft.context.task_specs.get_mut(&task.task_id).unwrap();
        spec.verification_case_count = 2;
        task.input_digest = canonical_task_input_digest(task, spec);
        task.envelope = Some(envelope(task));
    }
    draft.context.contracts = vec![ContractSnapshot {
        contract_id: binding.contract_id,
        version: binding.version,
        spec_sha256: binding.spec_sha256,
        source_sha256: sha256(b"accepted producer tracked content manifest"),
        frozen: false,
        required_consumers: vec![consumer_id],
        passing_consumers: vec!["previous-compatible-consumer".into()],
        independent_receipt_id: None,
        integration_receipt_id: None,
    }];
    draft
}

fn frozen_context(old: &CompileContext) -> CompileContext {
    let mut new = old.clone();
    let contract = &mut new.contracts[0];
    contract.frozen = true;
    for required in contract.required_consumers.clone() {
        if !contract.passing_consumers.contains(&required) {
            contract.passing_consumers.push(required);
        }
    }
    contract
        .independent_receipt_id
        .get_or_insert("independent-receipt".into());
    contract
        .integration_receipt_id
        .get_or_insert("integration-receipt".into());
    new
}

fn assert_both_bindings(
    draft: &DraftBundle,
    old: &CompileContext,
    new: &CompileContext,
    expected: bool,
) {
    for task in &draft.flow.tasks {
        let mut next_task = task.clone();
        next_task.flow_revision += 1;
        next_task.revision += 1;
        assert_eq!(
            task_binding_equivalent(task, old, &next_task, new),
            expected,
            "unexpected equivalence for {}",
            task.task_id,
        );
    }
}

#[test]
fn identical_contract_snapshots_preserve_producer_and_consumer_bindings() {
    let draft = fixture();
    assert_both_bindings(&draft, &draft.context, &draft.context, true);
    let frozen = frozen_context(&draft.context);
    assert_both_bindings(&draft, &frozen, &frozen, true);
}

#[test]
fn monotonic_contract_freeze_reuses_same_revision_producer_and_consumer() {
    let draft = fixture();
    for already_observed in [false, true] {
        let mut old = draft.context.clone();
        if already_observed {
            old.contracts[0].independent_receipt_id = Some("prior-independent".into());
            old.contracts[0].integration_receipt_id = Some("prior-integration".into());
        }
        let new = frozen_context(&old);
        assert_both_bindings(&draft, &old, &new, true);
    }
}

#[test]
fn contract_freeze_cannot_change_identity_pins_or_required_consumers() {
    type Tamper = fn(&mut ContractSnapshot);
    let draft = fixture();
    let cases: &[(&str, Tamper)] = &[
        ("contract id", |c| c.contract_id = "another-contract".into()),
        ("version", |c| c.version += 1),
        ("schema pin", |c| {
            c.spec_sha256 = sha256(b"different schema")
        }),
        ("source pin", |c| {
            c.source_sha256 = sha256(b"different content")
        }),
        ("required consumers", |c| {
            c.required_consumers.push("new-consumer".into())
        }),
    ];
    for (name, tamper) in cases {
        let mut new = frozen_context(&draft.context);
        tamper(&mut new.contracts[0]);
        for task in &draft.flow.tasks {
            assert!(
                !task_binding_equivalent(task, &draft.context, task, &new),
                "accepted changed {name} for {}",
                task.task_id,
            );
        }
    }
    for invalid in ["", "1111111111111111111111111111111111111111", "planned"] {
        for field in ["spec", "source"] {
            let mut old = draft.context.clone();
            match field {
                "spec" => old.contracts[0].spec_sha256 = invalid.into(),
                _ => old.contracts[0].source_sha256 = invalid.into(),
            }
            let new = frozen_context(&old);
            assert_both_bindings(&draft, &old, &new, false);
        }
    }
    let mut old = draft.context.clone();
    old.contracts[0].required_consumers.clear();
    assert_both_bindings(&draft, &old, &frozen_context(&old), false);
}

#[test]
fn contract_freeze_requires_complete_receipts_and_preserves_previous_proofs() {
    let draft = fixture();
    let mut old = draft.context.clone();
    old.contracts[0].independent_receipt_id = Some("prior-independent".into());
    old.contracts[0].integration_receipt_id = Some("prior-integration".into());
    for field in ["independent", "integration"] {
        for invalid in [
            None,
            Some(String::new()),
            Some("replacement-receipt".into()),
        ] {
            let mut new = frozen_context(&old);
            match field {
                "independent" => new.contracts[0].independent_receipt_id = invalid,
                _ => new.contracts[0].integration_receipt_id = invalid,
            }
            assert_both_bindings(&draft, &old, &new, false);
        }
        for invalid in [None, Some(String::new())] {
            let mut new = frozen_context(&draft.context);
            match field {
                "independent" => new.contracts[0].independent_receipt_id = invalid,
                _ => new.contracts[0].integration_receipt_id = invalid,
            }
            assert_both_bindings(&draft, &draft.context, &new, false);
        }
    }
    let mut dropped_previous = frozen_context(&draft.context);
    dropped_previous.contracts[0].passing_consumers =
        draft.context.contracts[0].required_consumers.clone();
    assert_both_bindings(&draft, &draft.context, &dropped_previous, false);
    let mut missing_required = frozen_context(&draft.context);
    missing_required.contracts[0].passing_consumers =
        draft.context.contracts[0].passing_consumers.clone();
    assert_both_bindings(&draft, &draft.context, &missing_required, false);
}

#[test]
fn draft_proof_changes_frozen_proof_changes_and_downgrades_are_not_progress() {
    let draft = fixture();
    let mut changed_draft = draft.context.clone();
    changed_draft.contracts[0]
        .passing_consumers
        .push("extra-consumer".into());
    assert_both_bindings(&draft, &draft.context, &changed_draft, false);
    let frozen = frozen_context(&draft.context);
    let mut downgrade = frozen.clone();
    downgrade.contracts[0].frozen = false;
    assert_both_bindings(&draft, &frozen, &downgrade, false);
    type Tamper = fn(&mut ContractSnapshot);
    for tamper in [
        (|c: &mut ContractSnapshot| c.passing_consumers.push("extra-consumer".into())) as Tamper,
        |c| c.independent_receipt_id = Some("replacement-independent".into()),
        |c| c.integration_receipt_id = Some("replacement-integration".into()),
    ] {
        let mut changed = frozen.clone();
        tamper(&mut changed.contracts[0]);
        assert_both_bindings(&draft, &frozen, &changed, false);
    }
}

#[test]
fn contract_progress_does_not_allow_task_spec_or_execution_envelope_changes() {
    let draft = fixture();
    let frozen = frozen_context(&draft.context);
    for task in &draft.flow.tasks {
        let mut changed_spec = frozen.clone();
        changed_spec
            .task_specs
            .get_mut(&task.task_id)
            .unwrap()
            .outcome = "changed behavior".into();
        assert!(!task_binding_equivalent(
            task,
            &draft.context,
            task,
            &changed_spec
        ));
        let mut changed_task = task.clone();
        changed_task
            .envelope
            .as_mut()
            .unwrap()
            .prompt_artifact
            .sha256 = sha256(b"changed prompt");
        assert!(!task_binding_equivalent(
            task,
            &draft.context,
            &changed_task,
            &frozen
        ));
        let mut changed_task = task.clone();
        changed_task.task_revision += 1;
        assert!(!task_binding_equivalent(
            task,
            &draft.context,
            &changed_task,
            &frozen
        ));
    }
}
