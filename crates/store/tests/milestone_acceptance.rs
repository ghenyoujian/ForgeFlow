//! Actual PostgreSQL adjudication transactions. Persisted verifier/integration
//! rows are explicit fixtures of already-verified authority, not an execution or
//! Git qualification claim; this test executes no model, author, or verifier.
use chrono::Utc;
use forgeflow_domain::*;
use forgeflow_evidence::{VerificationPlan, VerificationReceipt};
use forgeflow_planner::{CompileContext, TaskSpec};
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

fn code(error: StoreError) -> String {
    match error {
        StoreError::Domain(error) => error.code,
        error => panic!("unexpected Store error: {error}"),
    }
}

async fn command(
    store: &Store,
    key: &str,
    command: CatalogCommand,
) -> Result<CommandResult, StoreError> {
    store
        .execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: key.into(),
            },
            command,
        )
        .await
}

async fn put_milestone(store: &Store, milestone: Milestone, revision: Option<u64>) {
    command(
        store,
        &format!(
            "milestone-{}-{}",
            milestone.milestone_id, milestone.baseline_version
        ),
        CatalogCommand::PutDocument {
            project_id: "p".into(),
            collection: "milestones".into(),
            id: milestone.milestone_id.clone(),
            expected_revision: revision,
            value: json!(milestone),
        },
    )
    .await
    .unwrap();
}

async fn accept(
    store: &Store,
    key: &str,
    id: &str,
    revision: u64,
    baseline: u64,
) -> Result<CommandResult, StoreError> {
    command(
        store,
        key,
        CatalogCommand::AcceptMilestone {
            project_id: "p".into(),
            milestone_id: id.into(),
            expected_revision: revision,
            baseline_version: baseline,
        },
    )
    .await
}

async fn insert_candidate(store: &Store, receipt: &EvidenceReceipt) {
    sqlx::query("INSERT INTO evidence_receipts(project_id,receipt_id,attempt_id,generation,kind,data,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(&receipt.project_id).bind(&receipt.receipt_id).bind(&receipt.attempt_id)
        .bind(receipt.generation).bind(&receipt.kind).bind(json!(receipt)).bind(receipt.created_at)
        .execute(store.pool()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn milestone_acceptance_binds_current_requirements_and_immutable_verified_delivery() {
    let url = std::env::var("DATABASE_URL").expect("live PostgreSQL DATABASE_URL required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("milestone_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options: PgConnectOptions = url.parse().unwrap();
    let store = Store::connect_with_options(options.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let root = std::env::temp_dir().join(&schema);
    std::fs::create_dir_all(&root).unwrap();
    store
        .create_project(Project {
            project_id: "p".into(),
            name: "milestone adjudication".into(),
            root_path: root.to_string_lossy().into_owned(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "acceptance authority only".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: false,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    store
        .create_team(Team {
            project_id: "p".into(),
            team_id: "owner".into(),
            parent_team_id: None,
            name: "Owner".into(),
            paused: false,
            revision: 1,
        })
        .await
        .unwrap();
    let requirement = Requirement {
        project_id: "p".into(),
        requirement_id: "r".into(),
        title: "deliver".into(),
        source_anchor: "source#L1".into(),
        outcome: "original outcome".into(),
        scope: "original scope".into(),
        acceptance: vec!["positive and negative cases".into()],
        priority: 1,
        weight: 1,
        deferred_reason: None,
        revision: 1,
    };
    store.create_requirement(requirement.clone()).await.unwrap();
    let raw = b"retained independent fixture log bytes\n";
    let raw_hash = forgeflow_evidence::sha256(raw);
    let raw_path = root.join("candidate.raw.log");
    std::fs::write(&raw_path, raw).unwrap();
    let envelope: ExecutionEnvelope = serde_json::from_value(json!({
        "schema_version":"forgeflow.execution.v1","operation_id":"op","project_id":"p","task_id":"t","task_revision":1,
        "attempt_id":"a","lease_id":"l","generation":1,"worker_id":"w","workspace_root":root,
        "base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),
        "mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},
        "write_set":["output.txt"],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},
        "model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":"plan",
        "allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS"],"issued_at":"2026-01-01T00:00:00Z",
        "expires_at":"2026-01-01T00:01:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":root,
        "secret_refs":[],"idempotency_key":"op","trace_id":"milestone-fixture",
        "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION",
        "build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,
        "attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},
        "session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null,
    })).unwrap();
    let task = TaskCard {
        project_id: "p".into(),
        task_id: "t".into(),
        task_revision: 1,
        flow_revision: 1,
        title: "unit".into(),
        owner_id: "owner".into(),
        team_id: "owner".into(),
        requirement_ids: vec!["r".into()],
        read_set: vec![],
        write_set: vec!["output.txt".into()],
        dependencies: vec![],
        state: TaskPlanningState::ReadyForAdmission,
        input_digest: "d".repeat(64),
        resource_request: ResourceVector::default(),
        envelope: Some(envelope.clone()),
        revision: 1,
    };
    let flow = FlowRevision {
        project_id: "p".into(),
        flow_revision: 1,
        parent_revision: None,
        state: FlowState::Committed,
        tasks: vec![task.clone()],
        input_digest: "e".repeat(64),
        approved_by: Some("owner".into()),
        revision: 1,
    };
    sqlx::query("INSERT INTO flow_revisions(project_id,flow_revision,revision,state,input_digest,data) VALUES('p',1,1,'COMMITTED',$1,$2)")
        .bind(&flow.input_digest).bind(json!(flow)).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,revision,data) VALUES('p','t',1,1,'owner','owner','READY_FOR_ADMISSION',$1,1,$2)")
        .bind(&task.input_digest).bind(json!(task)).execute(store.pool()).await.unwrap();
    sqlx::query(
        "INSERT INTO task_revisions(project_id,task_id,task_revision,data) VALUES('p','t',1,$1)",
    )
    .bind(json!(task))
    .execute(store.pool())
    .await
    .unwrap();
    let plan: VerificationPlan = serde_json::from_value(json!({
        "plan_id":"plan","task_revision":1,"contract_version":"contract:1","input_hash":task.input_digest,
        "environment_profile":"fixture","oracle_id":"oracle","verifier_id":"independent","author_id":"author",
        "commands":[{"role":"independent","program":"python3","args":["oracle.py"],"env":{},
        "executable_hash":"f".repeat(64),"bound_inputs":[],"report_path":"report.json","timeout_seconds":30,
        "expected_cases":[{"name":"positive","kind":"positive"},{"name":"negative","kind":"negative"}]}],
    })).unwrap();
    let mut context = CompileContext::default();
    let requirement_digest = forgeflow_planner::requirement_semantic_digest(&requirement);
    context
        .requirement_semantic_digests
        .insert("r".into(), requirement_digest.clone());
    let spec: TaskSpec = serde_json::from_value(json!({
        "outcome":"original outcome","requirement_digest_refs":{"r":requirement_digest},"design_anchors":[],
        "inputs":[],"mandatory_paths":[],"dependency_refs":[],"contract_produces":[],"contract_consumes":[],
        "execution_profile":"exec","verification_plan":"plan","verification_case_count":2,"rollback_plan":"retain",
        "known_unknowns":[],"not_proven":[],"isolated_contract_probe":false,
    })).unwrap();
    context.task_specs.insert("t".into(), spec);
    for (collection, id, value) in [
        ("flow_contexts", "1", json!(context)),
        ("verification_plans", "plan", json!(plan)),
        (
            "artifacts",
            "raw",
            // Actual independent-verification producer: identity is the
            // documents.document_id; descriptor stores only path and hash.
            json!({"path":raw_path,"sha256":raw_hash}),
        ),
    ] {
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES('p',$1,$2,1,$3)")
            .bind(collection).bind(id).bind(value).execute(store.pool()).await.unwrap();
    }
    let attempt = Attempt {
        project_id: "p".into(),
        task_id: "t".into(),
        task_revision: 1,
        attempt_id: "a".into(),
        lease_id: "l".into(),
        generation: 1,
        worker_id: "w".into(),
        operation_id: "op".into(),
        base_sha: envelope.base_sha.clone(),
        state: AttemptState::Succeeded,
        revision: 2,
        created_at: Utc::now(),
        terminal_at: Some(Utc::now()),
        result: None,
    };
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,terminal_at,data,envelope) VALUES('p','a','t',1,'l',1,'w','op','SUCCEEDED',2,$1,$2,$3)")
        .bind(attempt.terminal_at).bind(json!(attempt)).bind(json!(envelope)).execute(store.pool()).await.unwrap();
    let verification: VerificationReceipt = serde_json::from_value(json!({
        "binding":{"task_revision":1,"attempt_id":"a","generation":1,"base_sha":attempt.base_sha,
        "candidate_sha":"b".repeat(40),"integrated_sha":null,"contract_version":"contract:1","verification_plan_id":"plan",
        "verification_plan_hash":plan.digest(),"input_hash":task.input_digest,"source_hash":"c".repeat(40)},
        "environment_profile":"fixture","command":["python3","oracle.py"],"exit_code":0,"total":2,"failed":0,"skipped":0,
        "positive_cases":1,"negative_cases":1,"oracle_id":"oracle","verifier_id":"independent","author_id":"author",
        "independent":true,"log_path":"candidate.raw.log","log_hash":raw_hash,
    })).unwrap();
    let candidate = EvidenceReceipt {
        receipt_id: "candidate".into(),
        project_id: "p".into(),
        attempt_id: "a".into(),
        generation: 1,
        kind: "INDEPENDENT_VERIFICATION".into(),
        input_digest: task.input_digest.clone(),
        candidate_sha: Some("b".repeat(40)),
        integrated_sha: None,
        verifier_id: "independent".into(),
        author_id: "author".into(),
        total: 2,
        failed: 0,
        skipped: 0,
        artifact: ArtifactRef {
            artifact_id: "raw".into(),
            sha256: raw_hash,
        },
        details: json!(verification),
        created_at: Utc::now(),
    };
    insert_candidate(&store, &candidate).await;
    let mut integrated = verification.clone();
    integrated.binding.integrated_sha = Some("d".repeat(40));
    integrated.binding.source_hash = "e".repeat(40);
    let intent = MergeIntent {
        intent_id: "merge".into(),
        project_id: "p".into(),
        attempt_id: "a".into(),
        generation: 1,
        target_ref: "refs/heads/main".into(),
        expected_sha: attempt.base_sha.clone(),
        candidate_sha: "b".repeat(40),
        integrated_sha: Some("d".repeat(40)),
        state: MergeIntentState::Finalized,
        revision: 4,
        receipt: Some(
            json!({"verification":integrated,"verification_receipt_hash":integrated.digest(),"artifact_root":root,
            "source_content_sha256":"f".repeat(64)}),
        ),
    };
    sqlx::query("INSERT INTO merge_intents(intent_id,project_id,attempt_id,generation,target_ref,state,revision,data) VALUES('merge','p','a',1,'refs/heads/main','FINALIZED',4,$1)")
        .bind(json!(intent)).execute(store.pool()).await.unwrap();
    let milestone = Milestone {
        change_reason: None,
        project_id: "p".into(),
        milestone_id: "m".into(),
        title: "delivery".into(),
        due_at: Utc::now(),
        baseline_version: 1,
        requirement_ids: vec!["r".into()],
        required_work_packages: vec!["t".into()],
        required_gate_ids: vec!["plan".into()],
        revision: 0,
    };
    put_milestone(&store, milestone.clone(), None).await;
    assert_eq!(
        code(accept(&store, "bad-revision", "m", 2, 1).await.unwrap_err()),
        "REVISION_CONFLICT"
    );
    assert_eq!(
        code(accept(&store, "bad-baseline", "m", 1, 2).await.unwrap_err()),
        "CONTEXT_STALE"
    );
    let mut empty = milestone.clone();
    empty.milestone_id = "empty".into();
    empty.required_work_packages.clear();
    put_milestone(&store, empty, None).await;
    assert_eq!(
        code(accept(&store, "empty", "empty", 1, 1).await.unwrap_err()),
        "VALIDATION_ERROR"
    );
    let mut bare = milestone.clone();
    bare.milestone_id = "bare".into();
    bare.required_gate_ids = vec!["bare-pass".into()];
    put_milestone(&store, bare, None).await;
    sqlx::query("INSERT INTO gate_runs(project_id,gate_run_id,status,data) VALUES('p','bare-pass','PASS',$1)")
        .bind(json!({"task_id":"t"})).execute(store.pool()).await.unwrap();
    assert_eq!(
        code(accept(&store, "bare", "bare", 1, 1).await.unwrap_err()),
        "EVIDENCE_INCOMPLETE"
    );
    sqlx::query("DELETE FROM evidence_receipts WHERE receipt_id='candidate'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        code(accept(&store, "missing", "m", 1, 1).await.unwrap_err()),
        "EVIDENCE_INCOMPLETE"
    );
    insert_candidate(&store, &candidate).await;
    for (key, change) in [
        ("failed", json!({"failed":1})),
        ("skipped", json!({"skipped":1,"negative_cases":0})),
    ] {
        let mut altered = candidate.clone();
        for (name, value) in change.as_object().unwrap() {
            altered.details[name] = value.clone();
        }
        sqlx::query("UPDATE evidence_receipts SET data=$1 WHERE receipt_id='candidate'")
            .bind(json!(altered))
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            code(accept(&store, key, "m", 1, 1).await.unwrap_err()),
            "VERIFIER_INVALID"
        );
    }
    sqlx::query("UPDATE evidence_receipts SET data=$1 WHERE receipt_id='candidate'")
        .bind(json!(candidate))
        .execute(store.pool())
        .await
        .unwrap();
    for (key, descriptor) in [
        (
            "wrong-artifact-hash",
            json!({"path":raw_path,"sha256":"0".repeat(64)}),
        ),
        (
            "wrong-explicit-artifact-id",
            json!({"artifact_id":"another-artifact","path":raw_path,"sha256":candidate.artifact.sha256}),
        ),
    ] {
        sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='artifacts' AND document_id='raw'")
            .bind(descriptor).execute(store.pool()).await.unwrap();
        assert_eq!(
            code(accept(&store, key, "m", 1, 1).await.unwrap_err()),
            "EVIDENCE_BINDING_MISMATCH"
        );
    }
    sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='artifacts' AND document_id='raw'")
        .bind(json!({"path":raw_path,"sha256":candidate.artifact.sha256})).execute(store.pool()).await.unwrap();
    let mut changed = requirement.clone();
    changed.outcome = "new outcome without a new task revision".into();
    command(
        &store,
        "requirement-change-before-accept",
        CatalogCommand::UpdateRequirement {
            requirement: changed.clone(),
            expected_revision: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        code(
            accept(&store, "stale-requirement-before-accept", "m", 1, 1)
                .await
                .unwrap_err()
        ),
        "REQUIREMENT_COVERAGE_STALE"
    );
    command(
        &store,
        "requirement-revert-before-accept",
        CatalogCommand::UpdateRequirement {
            requirement: requirement.clone(),
            expected_revision: 2,
        },
    )
    .await
    .unwrap();
    let accepted = accept(&store, "first-valid", "m", 1, 1).await.unwrap();
    assert_eq!(accepted.value["status"], "ACCEPTED");
    assert_eq!(
        accepted.value["conditions"]["requirement_refs"][0]["revision"],
        3
    );
    assert_eq!(
        accepted.value["conditions"]["requirement_refs"][0]["semantic_sha256"],
        forgeflow_planner::requirement_semantic_digest(&requirement)
    );
    assert_eq!(
        accepted.value["evidence_refs"][0]["integrated_sha"],
        "d".repeat(40)
    );
    assert!(!accepted.value["accepted_at"].as_str().unwrap().is_empty());
    assert_eq!(
        accept(&store, "second-valid-key", "m", 1, 1)
            .await
            .unwrap()
            .value,
        accepted.value
    );
    let replay = accept(&store, "first-valid", "m", 1, 1).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.value, accepted.value);
    assert_eq!(
        code(
            command(
                &store,
                "forge-acceptance",
                CatalogCommand::PutDocument {
                    project_id: "p".into(),
                    collection: "milestone_acceptances".into(),
                    id: "forged:1".into(),
                    expected_revision: None,
                    value: json!({"status":"ACCEPTED","accepted_at":Utc::now()}),
                }
            )
            .await
            .unwrap_err()
        ),
        "COMMAND_REQUIRED"
    );
    command(
        &store,
        "requirement-change-after-accept",
        CatalogCommand::UpdateRequirement {
            requirement: changed,
            expected_revision: 3,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        code(
            accept(&store, "changed-after-accepted", "m", 1, 1)
                .await
                .unwrap_err()
        ),
        "ACCEPTANCE_STALE"
    );
    assert_eq!(
        store
            .get_document("p", "milestone_acceptances", "m:1")
            .await
            .unwrap(),
        accepted.value
    );
    let historical_replay = accept(&store, "first-valid", "m", 1, 1).await.unwrap();
    assert!(historical_replay.replayed);
    assert_eq!(historical_replay.value, accepted.value);
    let mut new_baseline = milestone;
    new_baseline.baseline_version = 2;
    new_baseline.change_reason = Some("reviewed new baseline".into());
    put_milestone(&store, new_baseline, Some(1)).await;
    assert_eq!(
        code(
            accept(&store, "new-baseline-old-delivery", "m", 2, 2)
                .await
                .unwrap_err()
        ),
        "REQUIREMENT_COVERAGE_STALE"
    );
    assert!(
        store
            .get_document("p", "milestone_acceptances", "m:2")
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_document("p", "milestone_baselines", "m:1")
            .await
            .unwrap()["baseline_version"],
        1
    );
    store.dispatch_pool().close().await;
    store.control_pool().close().await;
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    std::fs::remove_dir_all(root).unwrap();
}
