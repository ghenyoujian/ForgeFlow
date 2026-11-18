use forgeflow_domain::*;
use forgeflow_planner::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const ORIGINAL: &str = "1111111111111111111111111111111111111111";
const CANDIDATE: &str = "2222222222222222222222222222222222222222";
const INTEGRATED: &str = "3333333333333333333333333333333333333333";
const SELECTED: &str = "4444444444444444444444444444444444444444";
const CANDIDATE_TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INTEGRATED_TREE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTENT_ALGORITHM: &str = "forgeflow.source-content.v1";
const OUTPUT: &str = "src/index-format.json";
const SOURCE: &str = "src/config.txt";

fn integrated_source_content() -> ProducerSourceContent {
    ProducerSourceContent {
        algorithm: CONTENT_ALGORITHM.into(),
        commit_sha: INTEGRATED.into(),
        tree_oid: INTEGRATED_TREE.into(),
        source_sha256: sha256(b"synthetic integrated tracked content manifest"),
    }
}

fn fixture() -> (
    DraftBundle,
    Vec<u8>,
    ProducerInputEvidence,
    ProducerInputTree,
) {
    let source = normalize_requirements(
        "spec.md",
        "- Produce a typed index format\n- Read the format through a finite consumer",
        RequirementFormat::Markdown,
    )
    .unwrap();
    let mut d = rules_based_draft(DraftRequest {
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
    d.context.owners[0].include = vec!["src/".into()];
    d.context.owners[0].root_team_id = Some("team".into());
    let schema = json!({"type":"object","required":["version","entries"],"properties":{"version":{"const":1},"entries":{"type":"array"}}});
    let contract = ContractBinding {
        contract_id: "index-format".into(),
        version: 1,
        spec_sha256: sha256(&serde_json::to_vec(&schema).unwrap()),
    };
    for t in &mut d.flow.tasks {
        t.state = TaskPlanningState::Planned;
        d.context
            .task_specs
            .get_mut(&t.task_id)
            .unwrap()
            .verification_case_count = 2;
    }
    d.flow.tasks[0].write_set = vec![OUTPUT.into()];
    let producer_id = d.flow.tasks[0].task_id.clone();
    let consumer_id = d.flow.tasks[1].task_id.clone();
    let producer_spec = d.context.task_specs.get_mut(&producer_id).unwrap();
    producer_spec.contract_produces.push(contract.clone());
    d.flow.tasks[0].input_digest = canonical_task_input_digest(&d.flow.tasks[0], producer_spec);
    let producer = d.flow.tasks[0].clone();
    let consumer = &mut d.flow.tasks[1];
    consumer.write_set = vec!["src/reader.json".into()];
    consumer.read_set = vec![SOURCE.into(), OUTPUT.into()];
    consumer.dependencies = vec![producer_id.clone()];
    let spec = d.context.task_specs.get_mut(&consumer_id).unwrap();
    spec.inputs = vec![InputBinding {
        path: SOURCE.into(),
        sha256: sha256(b"immutable configuration"),
        producer_task_id: None,
    }];
    spec.mandatory_paths = consumer.read_set.clone();
    spec.contract_consumes = vec![contract.clone()];
    spec.isolated_contract_probe = true;
    spec.dependency_refs = vec![DependencySpec {
        task_id: producer_id.clone(),
        project_id: "project".into(),
        kind: DependencyKind::Integrated,
        binding_id: "producer:integrated".into(),
    }];
    spec.producer_inputs = vec![ProducerInputBinding {
        path: OUTPUT.into(),
        producer_task_id: producer_id.clone(),
        producer_task_revision: producer.task_revision,
        producer_input_digest: producer.input_digest.clone(),
        dependency_binding_id: "producer:integrated".into(),
        contract: contract.clone(),
    }];
    consumer.input_digest = canonical_task_input_digest(consumer, spec);
    let manifest = ContextManifest {
        files: vec![ContextFile {
            path: SOURCE.into(),
            sha256: sha256(b"immutable configuration"),
        }],
        mandatory_paths: consumer.read_set.clone(),
        artifact_inputs: vec![],
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    consumer.envelope = Some(serde_json::from_value(json!({
        "schema_version":"forgeflow.execution.v1","operation_id":"template-op","project_id":"project",
        "task_id":consumer.task_id,"task_revision":consumer.task_revision,"attempt_id":"template-attempt",
        "lease_id":"template-lease","generation":1,"worker_id":"pending-worker","workspace_root":"/tmp/project",
        "base_sha":ORIGINAL,"context_manifest":{"artifact_id":"approved-context","sha256":sha256(&manifest_bytes),
        "mandatory_paths":manifest.mandatory_paths,"rendered_utf8_bytes":100,"token_estimate":null,"tokenizer_id":null},
        "write_set":consumer.write_set,"prompt_artifact":{"artifact_id":"prompt","sha256":sha256(b"approved finite prompt")},
        "model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resources","verification_plan_id":"verify",
        "allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS","RUN_APPROVED_COMMANDS","REQUEST_APPROVED_MODEL"],
        "issued_at":"2026-10-09T00:00:00Z","expires_at":"2026-10-09T00:00:30Z","deadline_at":"2026-10-10T00:00:00Z",
        "artifact_prefix":"/tmp/artifacts","secret_refs":[],"idempotency_key":"template-key","trace_id":"trace",
        "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,
        "gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},
        "session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null,"command":null
    })).unwrap());
    d.context
        .current_inputs
        .insert(SOURCE.into(), sha256(b"immutable configuration"));
    d.context.contracts.push(ContractSnapshot {
        contract_id: contract.contract_id.clone(),
        version: 1,
        spec_sha256: contract.spec_sha256.clone(),
        source_sha256: String::new(),
        frozen: false,
        required_consumers: vec![consumer_id.clone()],
        passing_consumers: vec![],
        independent_receipt_id: None,
        integration_receipt_id: None,
    });
    let attempt: Attempt = serde_json::from_value(json!({
        "project_id":"project","task_id":producer_id,"task_revision":producer.task_revision,"attempt_id":"producer-attempt",
        "lease_id":"producer-lease","generation":7,"worker_id":"worker","operation_id":"producer-op","base_sha":ORIGINAL,
        "state":"SUCCEEDED","revision":8,"created_at":"2026-10-09T00:00:00Z","terminal_at":"2026-10-09T00:00:10Z","result":null
    })).unwrap();
    let verification = json!({
        "binding":{"task_revision":producer.task_revision,"attempt_id":attempt.attempt_id,"generation":7,"base_sha":ORIGINAL,
        "candidate_sha":CANDIDATE,"integrated_sha":null,"contract_version":"index-format:1","verification_plan_id":"producer-plan",
        "verification_plan_hash":sha256(b"plan"),"input_hash":producer.input_digest,"source_hash":CANDIDATE_TREE},
        "environment_profile":"profile","command":["python","verify-format.py"],"exit_code":0,"total":2,"failed":0,"skipped":0,
        "positive_cases":1,"negative_cases":1,"oracle_id":"independent-format-oracle","verifier_id":"independent-verifier",
        "author_id":"producer-author","independent":true,"log_path":"verification.ndjson","log_hash":sha256(b"real runner log")
    });
    let receipt: EvidenceReceipt = serde_json::from_value(json!({
        "receipt_id":"producer-independent","project_id":"project","attempt_id":attempt.attempt_id,"generation":7,
        "kind":"INDEPENDENT_VERIFICATION","input_digest":producer.input_digest,"candidate_sha":CANDIDATE,"integrated_sha":null,
        "verifier_id":"independent-verifier","author_id":"producer-author","total":2,"failed":0,"skipped":0,
        "artifact":{"artifact_id":"producer-log","sha256":sha256(b"real runner log")},"details":verification,"created_at":"2026-10-09T00:00:09Z"
    })).unwrap();
    let mut integrated_verification = verification;
    integrated_verification["binding"]["integrated_sha"] = json!(INTEGRATED);
    integrated_verification["binding"]["source_hash"] = json!(INTEGRATED_TREE);
    let source_content = integrated_source_content();
    let integration: MergeIntent = serde_json::from_value(json!({
        "intent_id":"producer-integrated","project_id":"project","attempt_id":attempt.attempt_id,"generation":7,
        "target_ref":"refs/heads/main","expected_sha":ORIGINAL,"candidate_sha":CANDIDATE,"integrated_sha":INTEGRATED,
        "state":"FINALIZED","revision":4,"receipt":{"verification":integrated_verification,"verification_receipt_hash":sha256(b"registered integration receipt"),
        "source_content_algorithm":source_content.algorithm,"source_content_sha256":source_content.source_sha256,"source_tree_oid":source_content.tree_oid}
    })).unwrap();
    let registered_contract = ContractVersion {
        project_id: "project".into(),
        contract_id: contract.contract_id,
        version: 1,
        spec_sha256: contract.spec_sha256,
        source_sha256: String::new(),
        producer_task_id: producer_id,
        required_consumers: vec![consumer_id],
        passing_consumers: vec![],
        independent_receipt_id: None,
        integration_receipt_id: None,
        frozen: false,
        revision: 1,
        schema,
    };
    let output = br#"{"version":1,"entries":[{"key":"alpha","value":42}]}"#.to_vec();
    let tree = ProducerInputTree {
        base_sha: SELECTED.into(),
        integrated_ancestors: BTreeSet::from([INTEGRATED.into()]),
        base_inputs: BTreeMap::from([
            (SOURCE.into(), b"immutable configuration".to_vec()),
            (OUTPUT.into(), output.clone()),
        ]),
        producer_inputs: BTreeMap::from([(
            INTEGRATED.into(),
            BTreeMap::from([(OUTPUT.into(), output)]),
        )]),
        source_contents: BTreeMap::from([(INTEGRATED.into(), source_content)]),
    };
    (
        d,
        manifest_bytes,
        ProducerInputEvidence {
            producer,
            attempt,
            receipt,
            integration,
            contract: registered_contract,
        },
        tree,
    )
}
fn materialize(
    d: &DraftBundle,
    manifest: &[u8],
    proof: &ProducerInputEvidence,
    tree: &ProducerInputTree,
) -> Result<ProducerInputMaterialization, PlannerError> {
    let task = &d.flow.tasks[1];
    materialize_producer_inputs(
        task,
        &d.context.task_specs[&task.task_id],
        manifest,
        std::slice::from_ref(proof),
        tree,
    )
}

#[test]
fn approved_dag_has_no_unknown_content_hash_and_materialization_preserves_semantics() {
    let (d, manifest, proof, tree) = fixture();
    assert!(
        compile(&d.flow, &d.context).passed,
        "{:?}",
        compile(&d.flow, &d.context).findings
    );
    let frozen = freeze(d.flow.clone(), &d.context, "owner", d.flow.revision).unwrap();
    assert_eq!(
        frozen.flow.tasks[1].task_revision,
        d.flow.tasks[1].task_revision
    );
    let task_before = serde_json::to_value(&d.flow.tasks[1]).unwrap();
    let spec_before =
        serde_json::to_value(&d.context.task_specs[&d.flow.tasks[1].task_id]).unwrap();
    assert!(spec_before["producer_inputs"][0].get("sha256").is_none());
    let materialized = materialize(&d, &manifest, &proof, &tree).unwrap();
    assert_eq!(materialized.base_sha, SELECTED);
    assert_ne!(materialized.base_sha, ORIGINAL);
    assert_ne!(materialized.base_sha, INTEGRATED);
    assert_eq!(materialized.manifest.files.len(), 2);
    assert_eq!(
        materialized.inputs[0].sha256,
        sha256(&tree.base_inputs[OUTPUT])
    );
    assert_eq!(
        materialized.inputs[0].evidence_receipt_id,
        proof.receipt.receipt_id
    );
    assert_eq!(
        materialized.inputs[0].integration_receipt_id,
        proof.integration.intent_id
    );
    assert_eq!(
        materialized.manifest_sha256,
        sha256(&serde_json::to_vec(&materialized.manifest).unwrap())
    );
    assert_eq!(task_before, serde_json::to_value(&d.flow.tasks[1]).unwrap());
    assert_eq!(
        spec_before,
        serde_json::to_value(&d.context.task_specs[&d.flow.tasks[1].task_id]).unwrap()
    );
    assert_eq!(
        materialized.recipe.task_input_digest,
        d.flow.tasks[1].input_digest
    );
}

#[test]
fn unknown_placeholder_and_changed_producer_definition_are_rejected_before_approval() {
    let (mut d, _, _, _) = fixture();
    let producer_id = d.flow.tasks[0].task_id.clone();
    let consumer = &mut d.flow.tasks[1];
    let spec = d.context.task_specs.get_mut(&consumer.task_id).unwrap();
    spec.producer_inputs.clear();
    spec.inputs.push(InputBinding {
        path: OUTPUT.into(),
        sha256: "planned".into(),
        producer_task_id: Some(producer_id),
    });
    consumer.input_digest = canonical_task_input_digest(consumer, spec);
    let report = compile(&d.flow, &d.context);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "INVALID_INPUT_HASH")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "PRODUCER_INPUT_RECIPE_REQUIRED")
    );
    let (mut d, _, _, _) = fixture();
    d.flow.tasks[0].task_revision += 1;
    d.flow.tasks[0].input_digest = canonical_task_input_digest(
        &d.flow.tasks[0],
        &d.context.task_specs[&d.flow.tasks[0].task_id],
    );
    assert!(
        compile(&d.flow, &d.context)
            .findings
            .iter()
            .any(|f| f.rule_id == "FUTURE_INPUT_PRODUCER")
    );
}

#[test]
fn multiple_producer_integrations_materialize_at_one_verified_descendant() {
    let (mut d, old_manifest, first, mut tree) = fixture();
    let other_path = "src/metadata.json";
    let other_integrated = "5555555555555555555555555555555555555555";
    let schema = json!({"type":"object","required":["count"]});
    let contract = ContractBinding {
        contract_id: "index-metadata".into(),
        version: 1,
        spec_sha256: sha256(&serde_json::to_vec(&schema).unwrap()),
    };
    let mut producer = d.flow.tasks[0].clone();
    producer.task_id = "producer-two".into();
    producer.write_set = vec![other_path.into()];
    let mut producer_spec = d.context.task_specs[&d.flow.tasks[0].task_id].clone();
    producer_spec.contract_produces = vec![contract.clone()];
    producer.input_digest = canonical_task_input_digest(&producer, &producer_spec);
    d.context
        .task_specs
        .insert(producer.task_id.clone(), producer_spec);
    d.flow.tasks.push(producer.clone());
    let task = &mut d.flow.tasks[1];
    task.dependencies.push(producer.task_id.clone());
    task.read_set.push(other_path.into());
    let spec = d.context.task_specs.get_mut(&task.task_id).unwrap();
    spec.mandatory_paths.push(other_path.into());
    spec.contract_consumes.push(contract.clone());
    spec.dependency_refs.push(DependencySpec {
        task_id: producer.task_id.clone(),
        project_id: "project".into(),
        kind: DependencyKind::Integrated,
        binding_id: "producer-two:integrated".into(),
    });
    spec.producer_inputs.push(ProducerInputBinding {
        path: other_path.into(),
        producer_task_id: producer.task_id.clone(),
        producer_task_revision: producer.task_revision,
        producer_input_digest: producer.input_digest.clone(),
        dependency_binding_id: "producer-two:integrated".into(),
        contract: contract.clone(),
    });
    task.input_digest = canonical_task_input_digest(task, spec);
    let mut manifest: ContextManifest = serde_json::from_slice(&old_manifest).unwrap();
    manifest.mandatory_paths.push(other_path.into());
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let envelope = task.envelope.as_mut().unwrap();
    envelope.context_manifest.sha256 = sha256(&bytes);
    envelope.context_manifest.mandatory_paths = manifest.mandatory_paths;
    d.context.contracts.push(ContractSnapshot {
        contract_id: contract.contract_id.clone(),
        version: 1,
        spec_sha256: contract.spec_sha256.clone(),
        source_sha256: String::new(),
        frozen: false,
        required_consumers: vec![task.task_id.clone()],
        passing_consumers: vec![],
        independent_receipt_id: None,
        integration_receipt_id: None,
    });
    let mut second = first.clone();
    second.producer = producer.clone();
    second.attempt.task_id = producer.task_id.clone();
    second.attempt.attempt_id = "producer-two-attempt".into();
    second.receipt.attempt_id = second.attempt.attempt_id.clone();
    second.receipt.receipt_id = "producer-two-independent".into();
    second.receipt.input_digest = producer.input_digest.clone();
    second.receipt.details["binding"]["attempt_id"] = json!(second.attempt.attempt_id);
    second.receipt.details["binding"]["input_hash"] = json!(producer.input_digest);
    second.receipt.details["binding"]["contract_version"] = json!("index-metadata:1");
    second.integration.attempt_id = second.attempt.attempt_id.clone();
    second.integration.intent_id = "producer-two-integrated".into();
    second.integration.integrated_sha = Some(other_integrated.into());
    let integrated_verification = &mut second.integration.receipt.as_mut().unwrap()["verification"];
    integrated_verification["binding"]["attempt_id"] = json!(second.attempt.attempt_id);
    integrated_verification["binding"]["input_hash"] = json!(producer.input_digest);
    integrated_verification["binding"]["contract_version"] = json!("index-metadata:1");
    integrated_verification["binding"]["integrated_sha"] = json!(other_integrated);
    let other_source_content = ProducerSourceContent {
        algorithm: CONTENT_ALGORITHM.into(),
        commit_sha: other_integrated.into(),
        tree_oid: "cccccccccccccccccccccccccccccccccccccccc".into(),
        source_sha256: sha256(b"synthetic second integrated tracked content manifest"),
    };
    integrated_verification["binding"]["source_hash"] = json!(other_source_content.tree_oid);
    let integration_receipt = second.integration.receipt.as_mut().unwrap();
    integration_receipt["source_content_algorithm"] = json!(other_source_content.algorithm);
    integration_receipt["source_content_sha256"] = json!(other_source_content.source_sha256);
    integration_receipt["source_tree_oid"] = json!(other_source_content.tree_oid);
    second.contract.contract_id = contract.contract_id;
    second.contract.spec_sha256 = contract.spec_sha256;
    second.contract.producer_task_id = producer.task_id;
    second.contract.schema = schema;
    let other_bytes = br#"{"count":1}"#.to_vec();
    tree.integrated_ancestors.insert(other_integrated.into());
    tree.base_inputs
        .insert(other_path.into(), other_bytes.clone());
    tree.producer_inputs.insert(
        other_integrated.into(),
        BTreeMap::from([(other_path.into(), other_bytes)]),
    );
    tree.source_contents
        .insert(other_integrated.into(), other_source_content);
    assert!(
        compile(&d.flow, &d.context).passed,
        "{:?}",
        compile(&d.flow, &d.context).findings
    );
    let task = &d.flow.tasks[1];
    let materialized = materialize_producer_inputs(
        task,
        &d.context.task_specs[&task.task_id],
        &bytes,
        &[first, second],
        &tree,
    )
    .unwrap();
    assert_eq!(materialized.base_sha, SELECTED);
    assert_eq!(materialized.inputs.len(), 2);
    assert_ne!(
        materialized.inputs[0].integrated_sha,
        materialized.inputs[1].integrated_sha
    );
    assert_eq!(materialized.manifest.files.len(), 3);
    let (request, _) = native_proposal();
    let mut proposed = d.clone();
    proposed.generation_method = "dsh_model_assisted".into();
    for task in &mut proposed.flow.tasks {
        task.envelope = None;
    }
    let mut value = serde_json::to_value(proposed).unwrap();
    value["flow"]["input_digest"] = serde_json::Value::Null;
    for task in value["flow"]["tasks"].as_array_mut().unwrap() {
        task["input_digest"] = serde_json::Value::Null;
    }
    for spec in value["context"]["task_specs"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        if let Some(inputs) = spec
            .get_mut("producer_inputs")
            .and_then(serde_json::Value::as_array_mut)
        {
            for input in inputs {
                input["producer_task_revision"] = serde_json::Value::Null;
                input["producer_input_digest"] = serde_json::Value::Null;
            }
        }
    }
    let proposal =
        parse_model_draft_proposal(&serde_json::to_string(&value).unwrap(), &request).unwrap();
    let context = proposal.context.clone();
    let sealed = seal_model_draft_proposal(proposal, context).unwrap();
    assert_eq!(sealed.producer_input_resolution.len(), 2);
    assert_eq!(sealed.draft.flow.tasks.len(), 3);
}

#[test]
fn exact_registered_producer_receipt_integration_contract_and_denominators_are_required() {
    type Tamper = fn(&mut ProducerInputEvidence);
    let cases: &[(&str, Tamper)] = &[
        ("project", |p| p.producer.project_id = "other".into()),
        ("producer semantic input", |p| {
            p.producer.input_digest = sha256(b"changed")
        }),
        ("producer revision", |p| p.producer.task_revision += 1),
        ("producer path", |p| p.producer.write_set.clear()),
        ("attempt task", |p| p.attempt.task_id = "other".into()),
        ("attempt not successful", |p| {
            p.attempt.state = AttemptState::ReviewReady
        }),
        ("generation", |p| p.receipt.generation -= 1),
        ("receipt input", |p| {
            p.receipt.input_digest = sha256(b"changed")
        }),
        ("zero cases", |p| p.receipt.total = 0),
        ("skipped", |p| p.receipt.skipped = 1),
        ("non independent", |p| {
            p.receipt.details["independent"] = json!(false)
        }),
        ("missing negative oracle", |p| {
            p.receipt.details["negative_cases"] = json!(0)
        }),
        ("receipt contract", |p| {
            p.receipt.details["binding"]["contract_version"] = json!("other:1")
        }),
        ("unfinalized merge", |p| {
            p.integration.state = MergeIntentState::RefUpdated
        }),
        ("merge attempt", |p| {
            p.integration.attempt_id = "other".into()
        }),
        ("merge candidate", |p| {
            p.integration.candidate_sha = ORIGINAL.into()
        }),
        ("integration verifier", |p| {
            p.integration.receipt.as_mut().unwrap()["verification"]["independent"] = json!(false)
        }),
        ("integration plan", |p| {
            p.integration.receipt.as_mut().unwrap()["verification"]["binding"]["verification_plan_id"] =
                json!("other")
        }),
        ("contract producer", |p| {
            p.contract.producer_task_id = "other".into()
        }),
        ("contract schema", |p| {
            p.contract.schema = json!({"type":"string"})
        }),
    ];
    let (d, manifest, proof, tree) = fixture();
    for (name, tamper) in cases {
        let mut changed = proof.clone();
        tamper(&mut changed);
        assert!(
            materialize(&d, &manifest, &changed, &tree).is_err(),
            "accepted {name}"
        );
    }
    assert!(
        materialize_producer_inputs(
            &d.flow.tasks[1],
            &d.context.task_specs[&d.flow.tasks[1].task_id],
            &manifest,
            &[proof.clone(), proof],
            &tree
        )
        .is_err()
    );
}

#[test]
fn selected_descendant_must_preserve_produced_and_known_bytes_and_required_scope() {
    let (d, manifest, proof, tree) = fixture();
    for path in [SOURCE, OUTPUT] {
        let mut changed = tree.clone();
        changed
            .base_inputs
            .insert(path.into(), b"different bytes".to_vec());
        assert!(
            materialize(&d, &manifest, &proof, &changed)
                .unwrap_err()
                .to_string()
                .contains("INPUT_HASH_DRIFT")
        );
        let mut missing = tree.clone();
        missing.base_inputs.remove(path);
        assert!(materialize(&d, &manifest, &proof, &missing).is_err());
    }
    let mut no_ancestry = tree.clone();
    no_ancestry.integrated_ancestors.clear();
    assert!(materialize(&d, &manifest, &proof, &no_ancestry).is_err());
    let mut old_base = tree.clone();
    old_base.base_sha = ORIGINAL.into();
    old_base.integrated_ancestors.clear();
    assert!(materialize(&d, &manifest, &proof, &old_base).is_err());
    let mut extra = tree.clone();
    extra
        .base_inputs
        .insert("src/unapproved".into(), b"extra".to_vec());
    assert!(materialize(&d, &manifest, &proof, &extra).is_err());
    let mut incomplete: ContextManifest = serde_json::from_slice(&manifest).unwrap();
    incomplete.mandatory_paths.retain(|p| p != OUTPUT);
    let bytes = serde_json::to_vec(&incomplete).unwrap();
    let mut rewritten = d.clone();
    let envelope = rewritten.flow.tasks[1].envelope.as_mut().unwrap();
    envelope.context_manifest.sha256 = sha256(&bytes);
    envelope.context_manifest.mandatory_paths = incomplete.mandatory_paths;
    assert!(materialize(&rewritten, &bytes, &proof, &tree).is_err());
}

#[test]
fn public_consumers_keep_contract_freeze_requirement() {
    let (mut d, manifest, mut proof, tree) = fixture();
    let task = &mut d.flow.tasks[1];
    let spec = d.context.task_specs.get_mut(&task.task_id).unwrap();
    spec.isolated_contract_probe = false;
    task.input_digest = canonical_task_input_digest(task, spec);
    assert!(
        compile(&d.flow, &d.context)
            .findings
            .iter()
            .any(|f| f.rule_id == "CONTRACT_NOT_FROZEN")
    );
    assert!(materialize(&d, &manifest, &proof, &tree).is_err());
    proof.contract.frozen = true;
    proof.contract.source_sha256 = tree.source_contents[INTEGRATED].source_sha256.clone();
    proof.contract.passing_consumers = proof.contract.required_consumers.clone();
    proof.contract.independent_receipt_id = Some(proof.receipt.receipt_id.clone());
    proof.contract.integration_receipt_id = Some(proof.integration.intent_id.clone());
    assert!(materialize(&d, &manifest, &proof, &tree).is_ok());
    for invalid_source in [
        String::new(),
        INTEGRATED_TREE.into(),
        sha256(b"different valid but unaccepted content"),
    ] {
        let mut changed = proof.clone();
        changed.contract.source_sha256 = invalid_source;
        assert!(materialize(&d, &manifest, &changed, &tree).is_err());
    }
}

#[test]
fn registered_source_content_attestation_must_match_observed_commit_tree_algorithm_and_digest() {
    let (d, manifest, proof, tree) = fixture();
    let content = &tree.source_contents[INTEGRATED];
    assert_eq!(content.tree_oid.len(), 40);
    assert_eq!(content.source_sha256.len(), 64);
    assert_ne!(content.tree_oid, content.source_sha256);
    assert!(materialize(&d, &manifest, &proof, &tree).is_ok());
    for field in [
        "source_content_algorithm",
        "source_content_sha256",
        "source_tree_oid",
    ] {
        let mut missing = proof.clone();
        missing
            .integration
            .receipt
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            materialize(&d, &manifest, &missing, &tree).is_err(),
            "accepted missing {field}"
        );
        let mut changed = proof.clone();
        changed.integration.receipt.as_mut().unwrap()[field] = json!(match field {
            "source_content_algorithm" => "forgeflow.source-content.v0".to_owned(),
            "source_content_sha256" => sha256(b"different tracked content"),
            _ => CANDIDATE_TREE.to_owned(),
        });
        assert!(
            materialize(&d, &manifest, &changed, &tree).is_err(),
            "accepted different {field}"
        );
    }
    let mut wrong_verification_tree = proof.clone();
    wrong_verification_tree
        .integration
        .receipt
        .as_mut()
        .unwrap()["verification"]["binding"]["source_hash"] = json!(content.source_sha256);
    assert!(materialize(&d, &manifest, &wrong_verification_tree, &tree).is_err());
    let mut absent_observation = tree.clone();
    absent_observation.source_contents.clear();
    assert!(materialize(&d, &manifest, &proof, &absent_observation).is_err());
    for field in ["algorithm", "commit_sha", "source_sha256"] {
        let mut changed = tree.clone();
        let content = changed.source_contents.get_mut(INTEGRATED).unwrap();
        match field {
            "algorithm" => content.algorithm = "forgeflow.source-content.v0".into(),
            "commit_sha" => content.commit_sha = CANDIDATE.into(),
            _ => content.source_sha256 = INTEGRATED_TREE.into(),
        }
        assert!(
            materialize(&d, &manifest, &proof, &changed).is_err(),
            "accepted invalid observed {field}"
        );
    }
}

#[test]
fn nonempty_probe_contract_source_must_match_observed_content_sha256() {
    let (d, manifest, mut proof, tree) = fixture();
    proof.contract.source_sha256 = tree.source_contents[INTEGRATED].source_sha256.clone();
    assert!(materialize(&d, &manifest, &proof, &tree).is_ok());
    for invalid_source in [INTEGRATED_TREE.into(), sha256(b"other content manifest")] {
        proof.contract.source_sha256 = invalid_source;
        assert!(materialize(&d, &manifest, &proof, &tree).is_err());
    }
}

fn native_proposal() -> (DraftRequest, serde_json::Value) {
    let (mut d, _, _, _) = fixture();
    d.generation_method = "dsh_model_assisted".into();
    for task in &mut d.flow.tasks {
        task.envelope = None;
    }
    let source = normalize_requirements(
        "spec.md",
        "- Produce a typed index format\n- Read the format through a finite consumer",
        RequirementFormat::Markdown,
    )
    .unwrap();
    let request = DraftRequest {
        project_id: "project".into(),
        flow_revision: 1,
        source,
        owner_id: "owner".into(),
        team_id: "team".into(),
        write_set: vec!["src/".into()],
        execution_profile: "exec".into(),
        verification_plan: "verify".into(),
    };
    let mut value = serde_json::to_value(d).unwrap();
    value["flow"]["input_digest"] = serde_json::Value::Null;
    for task in value["flow"]["tasks"].as_array_mut().unwrap() {
        task["input_digest"] = serde_json::Value::Null;
    }
    let consumer_id = value["flow"]["tasks"][1]["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let input = value["context"]["task_specs"][&consumer_id]["producer_inputs"][0]
        .as_object_mut()
        .unwrap();
    input.remove("producer_task_revision");
    input.remove("producer_input_digest");
    (request, value)
}
#[test]
fn native_unresolved_proposals_resolve_exact_pins_topologically_before_review() {
    for explicit_null in [false, true] {
        let (request, mut value) = native_proposal();
        let consumer_id = value["flow"]["tasks"][1]["task_id"]
            .as_str()
            .unwrap()
            .to_owned();
        if explicit_null {
            let input = &mut value["context"]["task_specs"][&consumer_id]["producer_inputs"][0];
            input["producer_task_revision"] = serde_json::Value::Null;
            input["producer_input_digest"] = serde_json::Value::Null;
        }
        let proposal =
            parse_model_draft_proposal(&serde_json::to_string(&value).unwrap(), &request).unwrap();
        let context = proposal.context.clone();
        let sealed = seal_model_draft_proposal(proposal, context).unwrap();
        let producer = &sealed.draft.flow.tasks[0];
        let consumer = &sealed.draft.flow.tasks[1];
        let input = &sealed.draft.context.task_specs[&consumer.task_id].producer_inputs[0];
        assert_eq!(input.producer_task_revision, producer.task_revision);
        assert_eq!(input.producer_input_digest, producer.input_digest);
        assert_eq!(sealed.producer_input_resolution.len(), 1);
        assert!(!sealed.producer_input_resolution[0].supplied_revision);
        assert!(!sealed.producer_input_resolution[0].supplied_digest);
        assert_eq!(
            sealed.draft.flow.input_digest,
            semantic_digest(&sealed.draft.flow, &sealed.draft.context)
        );
        assert!(
            sealed
                .draft
                .flow
                .tasks
                .iter()
                .all(|task| task.envelope.is_none()
                    && task.input_digest
                        == canonical_task_input_digest(
                            task,
                            &sealed.draft.context.task_specs[&task.task_id]
                        ))
        );
        assert!(compile(&sealed.draft.flow, &sealed.draft.context).passed);
    }
}

#[test]
fn native_proposal_never_rebinds_supplied_pins_or_accepts_cycles_and_fake_hashes() {
    let (request, value) = native_proposal();
    let consumer_id = value["flow"]["tasks"][1]["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let producer_id = value["flow"]["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for field in ["producer_task_revision", "producer_input_digest"] {
        let mut changed = value.clone();
        changed["context"]["task_specs"][&consumer_id]["producer_inputs"][0][field] =
            if field == "producer_task_revision" {
                json!(99)
            } else {
                json!(sha256(b"different producer meaning"))
            };
        let proposal =
            parse_model_draft_proposal(&serde_json::to_string(&changed).unwrap(), &request)
                .unwrap();
        let context = proposal.context.clone();
        assert!(
            seal_model_draft_proposal(proposal, context).is_err(),
            "rebound {field}"
        );
    }
    let mut fake = value.clone();
    fake["context"]["task_specs"][&consumer_id]["producer_inputs"][0]["producer_input_digest"] =
        json!("planned");
    assert!(parse_model_draft_proposal(&serde_json::to_string(&fake).unwrap(), &request).is_err());
    let mut legacy = value.clone();
    legacy["context"]["task_specs"][&consumer_id]["inputs"][0]["producer_task_id"] =
        json!(producer_id);
    assert!(
        parse_model_draft_proposal(&serde_json::to_string(&legacy).unwrap(), &request).is_err()
    );
    let mut cycle = value.clone();
    cycle["flow"]["tasks"][0]["dependencies"] = json!([consumer_id]);
    let proposal =
        parse_model_draft_proposal(&serde_json::to_string(&cycle).unwrap(), &request).unwrap();
    let context = proposal.context.clone();
    assert!(
        seal_model_draft_proposal(proposal, context)
            .unwrap_err()
            .to_string()
            .contains("DAG_CYCLE")
    );
    for field in ["input_digest", "flow_input_digest"] {
        let mut changed = value.clone();
        if field == "input_digest" {
            changed["flow"]["tasks"][0]["input_digest"] = json!(sha256(b"wrong task"));
        } else {
            changed["flow"]["input_digest"] = json!(sha256(b"wrong flow"));
        }
        let proposal =
            parse_model_draft_proposal(&serde_json::to_string(&changed).unwrap(), &request)
                .unwrap();
        let context = proposal.context.clone();
        assert!(seal_model_draft_proposal(proposal, context).is_err());
    }
    let mut changed_source = value.clone();
    changed_source["context"]["requirements"][0]["acceptance"] = json!("lowered acceptance");
    assert!(
        parse_model_draft_proposal(&serde_json::to_string(&changed_source).unwrap(), &request)
            .is_err()
    );
    let mut changed_scope = value;
    changed_scope["flow"]["tasks"][0]["write_set"] = json!(["outside.py"]);
    assert!(
        parse_model_draft_proposal(&serde_json::to_string(&changed_scope).unwrap(), &request)
            .is_err()
    );
}

#[test]
fn producer_first_binding_requires_explicit_reviewable_draft_reseal() {
    let (mut d, _, _, _) = fixture();
    let original_spec =
        serde_json::to_value(&d.context.task_specs[&d.flow.tasks[1].task_id]).unwrap();
    d.flow.tasks[0].task_revision += 1;
    d.flow.tasks[0].input_digest = canonical_task_input_digest(
        &d.flow.tasks[0],
        &d.context.task_specs[&d.flow.tasks[0].task_id],
    );
    let (resealed, changes) =
        draft_producer_input_reseal(&d.flow, &d.context, &d.flow.tasks[1].task_id).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].previous_task_revision, 1);
    assert_eq!(changes[0].producer_task_revision, 2);
    assert_eq!(
        resealed.producer_inputs[0].producer_input_digest,
        d.flow.tasks[0].input_digest
    );
    assert_eq!(
        original_spec,
        serde_json::to_value(&d.context.task_specs[&d.flow.tasks[1].task_id]).unwrap()
    );
    d.flow.state = FlowState::Committed;
    d.flow.approved_by = Some("owner".into());
    assert!(draft_producer_input_reseal(&d.flow, &d.context, &d.flow.tasks[1].task_id).is_err());
}
