use forgeflow_domain::{FlowState, TaskPlanningState};
use forgeflow_planner::*;
use std::collections::{BTreeMap, BTreeSet};

fn fixture(count: usize) -> DraftBundle {
    let text = (0..count)
        .map(|i| format!("- Preserve business outcome {i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = normalize_requirements("spec.md", &text, RequirementFormat::Markdown).unwrap();
    let mut draft = rules_based_draft(DraftRequest {
        project_id: "project".into(),
        flow_revision: 1,
        source,
        owner_id: "owner".into(),
        team_id: "team".into(),
        write_set: vec![],
        execution_profile: "trusted-local".into(),
        verification_plan: "positive-and-negative".into(),
    })
    .unwrap();
    draft.context.owners[0].include = vec!["src/".into()];
    draft.context.owners[0].root_team_id = Some("team".into());
    for (i, t) in draft.flow.tasks.iter_mut().enumerate() {
        t.write_set = vec![format!("src/{i}.rs")];
        t.state = TaskPlanningState::Planned;
        let spec = draft.context.task_specs.get_mut(&t.task_id).unwrap();
        spec.verification_case_count = 2;
        t.input_digest = canonical_task_input_digest(t, spec);
    }
    draft
}
fn codes(report: &CheckReport) -> BTreeSet<&str> {
    report.findings.iter().map(|f| f.rule_id.as_str()).collect()
}
fn edge(d: &mut DraftBundle, consumer: usize, producer: usize) {
    let id = d.flow.tasks[producer].task_id.clone();
    let t = &mut d.flow.tasks[consumer];
    t.dependencies.push(id.clone());
    let s = d.context.task_specs.get_mut(&t.task_id).unwrap();
    s.dependency_refs.push(DependencySpec {
        task_id: id.clone(),
        project_id: "project".into(),
        kind: DependencyKind::Integrated,
        binding_id: format!("{id}:integrated"),
    });
    t.input_digest = canonical_task_input_digest(t, s);
}
#[test]
fn valid_parallel_and_join_compiles_and_freezes_only_with_approval() {
    let mut d = fixture(4);
    edge(&mut d, 2, 0);
    edge(&mut d, 2, 1);
    edge(&mut d, 3, 2);
    let report = compile(&d.flow, &d.context);
    assert!(report.passed, "{:?}", report.findings);
    assert_eq!(report.topological_order.len(), 4);
    assert!(freeze(d.flow.clone(), &d.context, "", 1).is_err());
    assert!(freeze(d.flow.clone(), &d.context, "owner", 9).is_err());
    let frozen = freeze(d.flow, &d.context, "owner", 1).unwrap();
    assert!(matches!(frozen.flow.state, FlowState::Committed));
    assert!(
        frozen
            .flow
            .tasks
            .iter()
            .all(|t| matches!(t.state, TaskPlanningState::ReadyForAdmission))
    );
}
#[test]
fn actual_cycle_and_downstream_impact_are_reported() {
    let mut d = fixture(4);
    edge(&mut d, 0, 1);
    edge(&mut d, 1, 0);
    edge(&mut d, 2, 1);
    let r = compile(&d.flow, &d.context);
    let f = r
        .findings
        .iter()
        .find(|f| f.rule_id == "DEPENDENCY_CYCLE")
        .unwrap();
    assert_eq!(f.evidence_refs.first(), f.evidence_refs.last());
    assert_eq!(f.evidence_refs.len(), 3);
    assert_eq!(f.blocked_tasks.len(), 3);
    assert!(!f.blocked_tasks.contains(&d.flow.tasks[3].task_id));
}
#[test]
fn dangling_duplicate_territory_and_coverage_fail_with_precise_rules() {
    let mut d = fixture(3);
    d.flow.tasks[0].dependencies.push("missing".into());
    d.flow.tasks[1].write_set = vec!["secrets/key".into()];
    d.flow.tasks[2].requirement_ids.clear();
    d.flow.tasks.push(d.flow.tasks[0].clone());
    let r = compile(&d.flow, &d.context);
    let c = codes(&r);
    for expected in [
        "DANGLING_DEPENDENCY",
        "DUPLICATE_TASK_ID",
        "OWNER_TERRITORY",
        "REQUIREMENT_UNCOVERED",
    ] {
        assert!(c.contains(expected), "missing {expected}: {c:?}");
    }
    assert!(
        r.findings
            .iter()
            .all(|f| !f.subject_ref.is_empty() && !f.suggested_action.is_empty())
    );
}
#[test]
fn self_rehashed_manifest_cannot_delete_canonical_read_input() {
    let mut d = fixture(1);
    let t = &mut d.flow.tasks[0];
    t.read_set = vec!["src/required.rs".into()];
    let s = d.context.task_specs.get_mut(&t.task_id).unwrap();
    s.inputs.clear();
    s.mandatory_paths.clear();
    t.input_digest = canonical_task_input_digest(t, s);
    assert!(codes(&compile(&d.flow, &d.context)).contains("MANDATORY_INPUT_MISSING"));
}
#[test]
fn existing_hash_drift_and_future_producer_closure_are_independent() {
    let mut d = fixture(2);
    let producer = d.flow.tasks[0].task_id.clone();
    let t = &mut d.flow.tasks[1];
    t.read_set = vec!["src/0.rs".into(), "spec.md".into()];
    let s = d.context.task_specs.get_mut(&t.task_id).unwrap();
    s.inputs = vec![
        InputBinding {
            path: "src/0.rs".into(),
            sha256: "planned".into(),
            producer_task_id: Some(producer),
        },
        InputBinding {
            path: "spec.md".into(),
            sha256: sha256(b"old"),
            producer_task_id: None,
        },
    ];
    t.input_digest = canonical_task_input_digest(t, s);
    d.context
        .current_inputs
        .insert("spec.md".into(), sha256(b"new"));
    let r = compile(&d.flow, &d.context);
    assert!(codes(&r).contains("INPUT_HASH_DRIFT"));
    assert!(codes(&r).contains("FUTURE_INPUT_PRODUCER"));
    edge(&mut d, 1, 0);
    assert!(!codes(&compile(&d.flow, &d.context)).contains("FUTURE_INPUT_PRODUCER"));
}
#[test]
fn canonical_symlink_aliases_conflict_and_escape_is_rejected() {
    let mut d = fixture(2);
    d.flow.tasks[0].write_set = vec!["src/alias.rs".into()];
    d.flow.tasks[1].write_set = vec!["src/real.rs".into()];
    d.context
        .resolved_paths
        .insert("src/alias.rs".into(), "src/real.rs".into());
    assert!(codes(&compile(&d.flow, &d.context)).contains("WRITE_SCOPE_CONFLICT"));
    d.context
        .resolved_paths
        .insert("src/alias.rs".into(), "../outside".into());
    assert!(codes(&compile(&d.flow, &d.context)).contains("OWNER_TERRITORY"));
}
#[test]
fn directory_prefix_exclude_and_ordered_write_conflict() {
    let mut d = fixture(2);
    d.flow.tasks[0].write_set = vec!["src/".into()];
    d.flow.tasks[1].write_set = vec!["src/child.rs".into()];
    assert!(codes(&compile(&d.flow, &d.context)).contains("WRITE_SCOPE_CONFLICT"));
    edge(&mut d, 1, 0);
    assert!(!codes(&compile(&d.flow, &d.context)).contains("WRITE_SCOPE_CONFLICT"));
    d.context.owners[0].exclude = vec!["src/child.rs".into()];
    assert!(codes(&compile(&d.flow, &d.context)).contains("OWNER_TERRITORY"));
    assert!(normalize_path("src2/../src/x").is_err());
    assert!(normalize_path("a//b/").is_err());
    assert!(normalize_path("C:/outside").is_err());
}
#[test]
fn contract_freeze_requires_all_consumer_and_independent_receipts() {
    let mut d = fixture(1);
    let t = &mut d.flow.tasks[0];
    let s = d.context.task_specs.get_mut(&t.task_id).unwrap();
    s.contract_consumes = vec![ContractBinding {
        contract_id: "format".into(),
        version: 2,
        spec_sha256: sha256(b"spec"),
    }];
    t.input_digest = canonical_task_input_digest(t, s);
    let snapshot = ContractSnapshot {
        contract_id: "format".into(),
        version: 2,
        spec_sha256: sha256(b"spec"),
        source_sha256: sha256(b"source"),
        frozen: true,
        required_consumers: vec!["reader".into(), "renderer".into()],
        passing_consumers: vec!["reader".into()],
        independent_receipt_id: Some("independent".into()),
        integration_receipt_id: Some("integrated".into()),
    };
    d.context.contracts.push(snapshot);
    assert!(codes(&compile(&d.flow, &d.context)).contains("CONTRACT_NOT_FROZEN"));
    d.context.contracts[0]
        .passing_consumers
        .push("renderer".into());
    assert!(compile(&d.flow, &d.context).passed);
    d.context.contracts[0].independent_receipt_id = None;
    assert!(codes(&compile(&d.flow, &d.context)).contains("CONTRACT_NOT_FROZEN"));
}
#[test]
fn json_identity_duplicate_keys_unknown_fields_and_numeric_types_are_strict() {
    assert!(strict_json::<serde_json::Value>(r#"{"nested":{"id":1,"id":2}}"#).is_err());
    assert!(
        strict_json::<ContractBinding>(r#"{"contract_id":"c","version":true,"spec_sha256":"h"}"#)
            .is_err()
    );
    assert!(
        strict_json::<ContractBinding>(r#"{"contract_id":"c","version":1.0,"spec_sha256":"h"}"#)
            .is_err()
    );
    assert!(
        strict_json::<ContractBinding>(
            r#"{"contract_id":"c","version":1,"spec_sha256":"h","unknown":0}"#
        )
        .is_err()
    );
    let a: serde_json::Value = strict_json("true").unwrap();
    let b: serde_json::Value = strict_json("1").unwrap();
    assert_ne!(
        sha256(&serde_json::to_vec(&a).unwrap()),
        sha256(&serde_json::to_vec(&b).unwrap())
    );
}
#[test]
fn source_bytes_and_semantics_preserved_and_rules_based_scaffold_is_honest() {
    let doc = normalize_requirements(
        "spec.md",
        "# Goal\n- Read back bytes\n",
        RequirementFormat::Markdown,
    )
    .unwrap();
    assert_eq!(doc.raw_sha256, sha256(b"# Goal\n- Read back bytes\n"));
    assert_eq!(doc.requirements[0].anchor, "Goal:L2");
    let d = rules_based_draft(DraftRequest {
        project_id: "p".into(),
        flow_revision: 1,
        source: doc,
        owner_id: "o".into(),
        team_id: "t".into(),
        write_set: vec![],
        execution_profile: "profile".into(),
        verification_plan: "v".into(),
    })
    .unwrap();
    assert_eq!(d.generation_method, "rules_based");
    assert!(codes(&compile(&d.flow, &d.context)).contains("ZERO_CASE_VERIFICATION"));
    assert!(parse_model_draft(&serde_json::to_string(&d).unwrap()).is_err());
}
#[test]
fn ten_thousand_nodes_are_checked_against_an_independent_reference() {
    let mut d = fixture(10_000);
    for i in 1..10_000 {
        edge(&mut d, i, i - 1)
    }
    let report = compile(&d.flow, &d.context);
    assert!(report.passed, "{:?}", report.findings.first());
    // Independent elimination oracle: chain fixture has exactly one node at each frontier.
    let mut unresolved = d
        .flow
        .tasks
        .iter()
        .map(|t| (t.task_id.clone(), t.dependencies.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut done = BTreeSet::new();
    let mut expected = vec![];
    while !unresolved.is_empty() {
        let id = unresolved
            .iter()
            .find(|(_, deps)| deps.iter().all(|d| done.contains(d)))
            .map(|(id, _)| id.clone())
            .unwrap();
        unresolved.remove(&id);
        done.insert(id.clone());
        expected.push(id);
    }
    assert_eq!(report.topological_order, expected);
}

#[test]
fn semantic_identity_excludes_observation_and_approval_but_covers_authority() {
    let d = fixture(1);
    let initial = semantic_digest(&d.flow, &d.context);
    let mut updated = d.context.clone();
    updated.observed_at = "later-observation".into();
    assert_eq!(initial, semantic_digest(&d.flow, &updated));
    let frozen = freeze(d.flow.clone(), &updated, "owner", 1).unwrap();
    assert_eq!(initial, semantic_digest(&frozen.flow, &updated));
    assert_eq!(initial, frozen.semantic_digest);
    let mut changed = d.flow.clone();
    changed.tasks[0].owner_id = "other-owner".into();
    assert_ne!(initial, semantic_digest(&changed, &updated));
    assert!(codes(&compile(&changed, &updated)).contains("CONTEXT_DIGEST_DRIFT"));
    changed = d.flow;
    changed.tasks[0].state = TaskPlanningState::RemovedFromPlan;
    assert_ne!(initial, semantic_digest(&changed, &updated));
    assert!(codes(&compile(&changed, &updated)).contains("REQUIREMENT_UNCOVERED"));
}
#[test]
fn model_cannot_rewrite_request_source_or_expand_writes() {
    let source = normalize_requirements(
        "spec.md",
        "- Independent readback\n",
        RequirementFormat::Markdown,
    )
    .unwrap();
    let request = DraftRequest {
        project_id: "p".into(),
        flow_revision: 1,
        source,
        owner_id: "o".into(),
        team_id: "t".into(),
        write_set: vec!["src/".into()],
        execution_profile: "profile".into(),
        verification_plan: "v".into(),
    };
    let mut draft = rules_based_draft(request.clone()).unwrap();
    draft.generation_method = "dsh_model_assisted".into();
    assert!(validate_model_draft(&serde_json::to_string(&draft).unwrap(), &request).is_ok());
    draft.context.requirements[0].acceptance = "weaker check".into();
    assert!(validate_model_draft(&serde_json::to_string(&draft).unwrap(), &request).is_err());
    draft.context.requirements = request.source.requirements.clone();
    draft.flow.tasks[0].write_set = vec!["secrets/key".into()];
    assert!(validate_model_draft(&serde_json::to_string(&draft).unwrap(), &request).is_err());
}

#[test]
fn replan_preview_preserves_old_attempts_and_reports_transitive_impact() {
    let mut old = fixture(4);
    edge(&mut old, 1, 0);
    edge(&mut old, 2, 1);
    let mut new = old.clone();
    new.flow.flow_revision = 2;
    for t in &mut new.flow.tasks {
        t.flow_revision = 2;
    }
    new.context
        .task_specs
        .get_mut(&new.flow.tasks[0].task_id)
        .unwrap()
        .outcome = "Changed finite outcome".into();
    let make_attempt = |task_id: &str, id: &str, state: &str| {
        serde_json::from_value::<forgeflow_domain::Attempt>(serde_json::json!({"project_id":"project","task_id":task_id,"task_revision":1,"attempt_id":id,"lease_id":format!("lease-{id}"),"generation":1,"worker_id":"worker","operation_id":format!("op-{id}"),"base_sha":"base","state":state,"revision":1,"created_at":"2026-10-09T00:00:00Z","terminal_at":null,"result":null})).unwrap()
    };
    let attempts = vec![
        make_attempt(&old.flow.tasks[1].task_id, "active", "RUNNING"),
        make_attempt(&old.flow.tasks[3].task_id, "unrelated", "RUNNING"),
        make_attempt(&old.flow.tasks[2].task_id, "finished", "SUCCEEDED"),
    ];
    let before = serde_json::to_value(&attempts).unwrap();
    let diff = diff_flows(&old.flow, &old.context, &new.flow, &new.context, &attempts).unwrap();
    assert_eq!(diff.changed_tasks, vec![old.flow.tasks[0].task_id.clone()]);
    assert_eq!(diff.impacted_tasks.len(), 3);
    assert_eq!(diff.active_attempt_ids, vec!["active"]);
    assert!(diff.requires_full_graph_check);
    assert_eq!(before, serde_json::to_value(&attempts).unwrap());
}

#[test]
fn broad_directory_writes_cannot_swallow_excludes_and_root_owners_are_unique() {
    let mut d = fixture(1);
    d.flow.tasks[0].write_set = vec!["src/".into()];
    d.context.owners[0].exclude = vec!["src/private/".into()];
    let r = compile(&d.flow, &d.context);
    assert!(codes(&r).contains("OWNER_TERRITORY"));
    d.context.owners[0].exclude.clear();
    d.context.owners.push(OwnerTerritory {
        root_team_id: Some("team".into()),
        owner_id: "other".into(),
        include: vec!["src/".into()],
        exclude: vec![],
    });
    assert!(codes(&compile(&d.flow, &d.context)).contains("OWNER_TERRITORY_AMBIGUOUS"));
}

#[test]
fn unchanged_active_rebinding_preserves_identity_and_same_id_changes_are_rejected() {
    let old = fixture(1);
    let mut new = old.clone();
    new.flow.flow_revision = 2;
    new.flow.tasks[0].flow_revision = 2;
    let old_task = &old.flow.tasks[0];
    let new_task = &new.flow.tasks[0];
    assert_eq!(
        canonical_task_input_digest(old_task, &old.context.task_specs[&old_task.task_id]),
        canonical_task_input_digest(new_task, &new.context.task_specs[&new_task.task_id])
    );
    assert!(task_binding_equivalent(
        old_task,
        &old.context,
        new_task,
        &new.context
    ));
    assert_ne!(
        semantic_digest(&old.flow, &old.context),
        semantic_digest(&new.flow, &new.context)
    );
    new.context.requirements[0].acceptance = "Changed meaning at the same source ID".into();
    assert!(!task_binding_equivalent(
        old_task,
        &old.context,
        &new.flow.tasks[0],
        &new.context
    ));
    new.context = old.context.clone();
    new.context.owners[0].exclude = vec!["src/elsewhere/".into()];
    assert!(!task_binding_equivalent(
        old_task,
        &old.context,
        &new.flow.tasks[0],
        &new.context
    ));
    new.context = old.context.clone();
    new.context.source_revision = "changed without source input proof".into();
    assert!(!task_binding_equivalent(
        old_task,
        &old.context,
        &new.flow.tasks[0],
        &new.context
    ));
    assert_eq!(old.flow.tasks[0].flow_revision, 1);
    let mut bound_old = old.clone();
    let input_sha = sha256(b"unchanged source bytes");
    let task = &mut bound_old.flow.tasks[0];
    let spec = bound_old.context.task_specs.get_mut(&task.task_id).unwrap();
    spec.inputs.push(InputBinding {
        path: "spec.md".into(),
        sha256: input_sha.clone(),
        producer_task_id: None,
    });
    task.input_digest = canonical_task_input_digest(task, spec);
    bound_old
        .context
        .current_inputs
        .insert("spec.md".into(), input_sha);
    let mut bound_new = bound_old.clone();
    bound_new.flow.flow_revision = 2;
    bound_new.flow.tasks[0].flow_revision = 2;
    bound_new.context.source_revision = "unrelated denominator change".into();
    assert!(task_binding_equivalent(
        &bound_old.flow.tasks[0],
        &bound_old.context,
        &bound_new.flow.tasks[0],
        &bound_new.context
    ));
    bound_new
        .context
        .current_inputs
        .insert("spec.md".into(), sha256(b"same-ID source rewritten"));
    assert!(!task_binding_equivalent(
        &bound_old.flow.tasks[0],
        &bound_old.context,
        &bound_new.flow.tasks[0],
        &bound_new.context
    ));
}
#[test]
fn read_only_planning_bootstrap_has_source_artifact_identity_and_no_lease() {
    let source = normalize_requirements(
        "original-source-id",
        "- Full outcome\n",
        RequirementFormat::Markdown,
    )
    .unwrap();
    let request = DraftRequest {
        project_id: "p".into(),
        flow_revision: 1,
        source,
        owner_id: "o".into(),
        team_id: "t".into(),
        write_set: vec!["src/".into()],
        execution_profile: "dsh".into(),
        verification_plan: "draft-json-source-scope-compiler".into(),
    };
    let source_input = InputBinding {
        path: "source-artifacts/original-source-id.md".into(),
        sha256: request.source.raw_sha256.clone(),
        producer_task_id: None,
    };
    let mut bundle =
        planning_bootstrap_with_source_input(&request, "p-planning", source_input).unwrap();
    bundle.context.owners[0].root_team_id = Some("t".into());
    assert_eq!(bundle.flow.tasks.len(), 1);
    assert!(bundle.flow.tasks[0].write_set.is_empty());
    assert_eq!(bundle.flow.tasks[0].resource_request.active_slot, 1);
    assert!(bundle.flow.tasks[0].envelope.is_none());
    assert!(
        bundle.context.task_specs["p-planning"].design_anchors[0]
            .starts_with("original-source-id#")
    );
    assert!(compile(&bundle.flow, &bundle.context).passed);
}

fn envelope_for(
    task: &forgeflow_domain::TaskCard,
    spec: &TaskSpec,
) -> forgeflow_domain::ExecutionEnvelope {
    serde_json::from_value(serde_json::json!({"schema_version":"forgeflow.execution.v1","operation_id":"op","project_id":task.project_id,"task_id":task.task_id,"task_revision":task.task_revision,"attempt_id":"attempt","lease_id":"lease","generation":1,"worker_id":"worker","workspace_root":"/tmp/managed-repository","base_sha":"1111111111111111111111111111111111111111","context_manifest":{"artifact_id":"context","sha256":sha256(b"context"),"mandatory_paths":[],"rendered_utf8_bytes":10,"token_estimate":null,"tokenizer_id":null},"write_set":task.write_set,"prompt_artifact":{"artifact_id":"prompt","sha256":sha256(b"rendered prompt")},"model_route_id":"route","executor_profile_id":spec.execution_profile,"resource_profile_id":"resources","verification_plan_id":spec.verification_plan,"allowed_effects":[],"issued_at":"2026-10-09T00:00:00Z","expires_at":"2026-10-09T01:00:00Z","deadline_at":"2026-10-10T00:00:00Z","artifact_prefix":"artifacts","secret_refs":[],"idempotency_key":"key","trace_id":"trace","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null,"command":null})).unwrap()
}
#[test]
fn flow_approval_binds_static_template_without_creating_task_prompt_hash_cycle() {
    let mut old = fixture(1);
    let task = &mut old.flow.tasks[0];
    let spec = &old.context.task_specs[&task.task_id];
    let input_digest = canonical_task_input_digest(task, spec);
    let envelope = envelope_for(task, spec);
    task.envelope = Some(envelope);
    assert_eq!(input_digest, canonical_task_input_digest(task, spec));
    assert!(compile(&old.flow, &old.context).passed);
    let approval = semantic_digest(&old.flow, &old.context);
    let mut new = old.clone();
    new.flow.tasks[0]
        .envelope
        .as_mut()
        .unwrap()
        .prompt_artifact
        .sha256 = sha256(b"different rendered prompt");
    assert_eq!(
        input_digest,
        canonical_task_input_digest(
            &new.flow.tasks[0],
            &new.context.task_specs[&new.flow.tasks[0].task_id]
        )
    );
    assert_ne!(approval, semantic_digest(&new.flow, &new.context));
    assert_eq!(
        diff_flows(&old.flow, &old.context, &new.flow, &new.context, &[])
            .unwrap()
            .changed_tasks,
        vec![old.flow.tasks[0].task_id.clone()]
    );
    assert_eq!(
        compile(&old.flow, &old.context).digest_algorithm,
        FLOW_APPROVAL_DIGEST_ALGORITHM
    );
}
#[test]
fn dynamic_runtime_identity_does_not_change_approval_but_profile_and_plan_must_match() {
    let mut d = fixture(1);
    let task = &mut d.flow.tasks[0];
    let spec = &d.context.task_specs[&task.task_id];
    task.envelope = Some(envelope_for(task, spec));
    let before = semantic_digest(&d.flow, &d.context);
    let envelope = d.flow.tasks[0].envelope.as_mut().unwrap();
    envelope.operation_id = "another-op".into();
    envelope.attempt_id = "another-attempt".into();
    envelope.lease_id = "another-lease".into();
    envelope.generation = 99;
    envelope.worker_id = "other-worker".into();
    envelope.issued_at = "later".into();
    envelope.expires_at = "later-expiry".into();
    envelope.trace_id = "other-trace".into();
    envelope.idempotency_key = "other-key".into();
    assert_eq!(before, semantic_digest(&d.flow, &d.context));
    d.flow.tasks[0]
        .envelope
        .as_mut()
        .unwrap()
        .executor_profile_id = "wrong-profile".into();
    assert!(codes(&compile(&d.flow, &d.context)).contains("EXECUTION_TEMPLATE_SPEC_MISMATCH"));
    assert_ne!(before, semantic_digest(&d.flow, &d.context));
    assert!(normalize_path("src//").is_err());
}

#[test]
fn full_domain_scope_and_weight_changes_cannot_hide_behind_same_acceptance_or_source_id() {
    let old = fixture(1);
    let normalized = &old.context.requirements[0];
    let mut requirement = forgeflow_domain::Requirement {
        project_id: "project".into(),
        requirement_id: normalized.requirement_id.clone(),
        title: "cosmetic title".into(),
        source_anchor: format!("{}#{}", normalized.source_document, normalized.anchor),
        outcome: normalized.acceptance.clone(),
        scope: "imported requirement; refine before admission".into(),
        acceptance: vec![normalized.acceptance.clone()],
        priority: normalized.priority,
        weight: 1,
        deferred_reason: None,
        revision: 1,
    };
    let initial = requirement_semantic_digest(&requirement);
    assert_eq!(
        old.context.requirement_semantic_digests[&requirement.requirement_id],
        initial
    );
    requirement.title = "another cosmetic title".into();
    requirement.revision = 99;
    assert_eq!(initial, requirement_semantic_digest(&requirement));
    requirement.scope = "different same-ID authoritative scope".into();
    assert_ne!(initial, requirement_semantic_digest(&requirement));
    let mut new = old.clone();
    new.context.requirement_semantic_digests.insert(
        requirement.requirement_id.clone(),
        requirement_semantic_digest(&requirement),
    );
    assert!(codes(&compile(&new.flow, &new.context)).contains("REQUIREMENT_SEMANTIC_BINDING"));
    assert!(!task_binding_equivalent(
        &old.flow.tasks[0],
        &old.context,
        &new.flow.tasks[0],
        &new.context
    ));
    assert_eq!(
        diff_flows(&old.flow, &old.context, &new.flow, &new.context, &[])
            .unwrap()
            .changed_requirements,
        vec![requirement.requirement_id.clone()]
    );
    requirement.weight = 20;
    assert_ne!(initial, requirement_semantic_digest(&requirement));
    new.context.requirement_semantic_digests.clear();
    assert!(codes(&compile(&new.flow, &new.context)).contains("REQUIREMENT_SEMANTICS_UNQUALIFIED"));
}

#[test]
fn nonmaterial_catalog_revision_requires_unchanged_real_source_identity() {
    let mut old = fixture(1);
    let path = format!(
        "source-artifacts/{}.md",
        old.context.requirements[0].source_document
    );
    old.context
        .current_inputs
        .insert(path.clone(), sha256(b"original source bytes"));
    let mut new = old.clone();
    new.context.source_revision = sha256(b"new catalog title and row revision");
    let equivalent = |new: &DraftBundle| {
        task_binding_equivalent(
            &old.flow.tasks[0],
            &old.context,
            &new.flow.tasks[0],
            &new.context,
        )
    };
    assert!(equivalent(&new));
    new.context.requirement_semantic_digests.insert(
        "unrelated-retired-auxiliary".into(),
        sha256(b"explicitly deferred outside this task"),
    );
    assert!(equivalent(&new));
    new.context
        .current_inputs
        .insert(path.clone(), sha256(b"rewritten source bytes"));
    assert!(!equivalent(&new));
    new.context = old.context.clone();
    new.context.source_revision = sha256(b"new metadata without a source pin");
    new.context.current_inputs.remove(&path);
    assert!(!equivalent(&new));
    new.context = old.context.clone();
    new.context.source_revision = sha256(b"changed functional requirement");
    new.context.requirements[0].acceptance = "different required behavior".into();
    assert!(!equivalent(&new));
    new.context = old.context.clone();
    new.context.source_revision = sha256(b"different material scope");
    let id = old.context.requirements[0].requirement_id.clone();
    new.context
        .requirement_semantic_digests
        .insert(id, sha256(b"different scope"));
    assert!(!equivalent(&new));
}
