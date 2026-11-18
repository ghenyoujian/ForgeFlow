//! Real PostgreSQL transaction tests with real lightweight author subprocess receipts.
//! These tests do not qualify the sustained 128-channel/3600-second workload.
use async_trait::async_trait;
use forgeflow_domain::*;
use forgeflow_planner::{CompileContext, OwnerTerritory, TaskSpec};
use forgeflow_store::{
    HandoffRequest, HandoffScheduler, QueuedReplacement, Store, StoreError, TerminalAcknowledgement,
};
use serde_json::Value;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::sync::Notify;

async fn setup() -> (Store, String, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL required for PostgreSQL authority tests");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .after_connect(move |conn, _| {
            let search = search.clone();
            Box::pin(async move {
                sqlx::query(&format!("SET search_path TO {search}"))
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let store = Store::from_pool(pool);
    store.migrate().await.unwrap();
    (store, schema, admin)
}
async fn cleanup(store: Store, schema: String, admin: sqlx::PgPool) {
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
fn envelope(task: &str) -> ExecutionEnvelope {
    serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":"preflight","project_id":"p","task_id":task,"task_revision":1,"attempt_id":"preflight","lease_id":"preflight","generation":1,"worker_id":"w","workspace_root":"/tmp/forgeflow-test","base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[format!("src/{task}.rs")],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":format!("verify-{task}"),"allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS"],"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:01:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":"/tmp/forgeflow-test/artifacts","secret_refs":[],"idempotency_key":"preflight","trace_id":"test","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null,"command":{"program":"/usr/bin/sleep","args":["30"]}})).unwrap()
}
async fn fixture(s: &Store) -> Vec<TaskCard> {
    fixture_with_pool(s, false).await
}
async fn fixture_with_pool(s: &Store, strict: bool) -> Vec<TaskCard> {
    let executor_id = if strict {
        "controlled-lightweight.v1"
    } else {
        "exec"
    };
    s.create_project(Project {
        project_id: "p".into(),
        name: "safety fixture".into(),
        root_path: "/tmp/forgeflow-test".into(),
        authority_mode: AuthorityMode::Managed,
        data_origin: DataOrigin::Native,
        goal: "verify authority".into(),
        technology_stack: vec![],
        timezone: "UTC".into(),
        paused: false,
        archived: false,
        revision: 1,
    })
    .await
    .unwrap();
    s.create_team(Team {
        project_id: "p".into(),
        team_id: "owner".into(),
        parent_team_id: None,
        name: "owner".into(),
        paused: false,
        revision: 1,
    })
    .await
    .unwrap();
    s.register_worker(WorkerRegisterRequest {
        project_id: Some("p".into()),
        executor_profile_ids: vec![executor_id.into()],
        worker_id: "w".into(),
        boot_id: "boot1".into(),
        capabilities: vec!["CONTROLLED_LIGHTWEIGHT".into()],
    })
    .await
    .unwrap();
    let limit = ResourceVector {
        active_slot: 2,
        coding_slot: 2,
        cpu_units: 2,
        ..Default::default()
    };
    for (scope, p, team, worker, parent) in [
        ("global", None, None, None, None),
        ("project", Some("p"), None, None, Some("global")),
        ("team", Some("p"), Some("owner"), None, Some("project")),
        ("worker", None, None, Some("w"), Some("global")),
    ] {
        s.put_resource_policy(
            ResourcePolicy {
                scope_id: scope.into(),
                parent_scope_id: parent.map(str::to_owned),
                project_id: p.map(str::to_owned),
                team_id: team.map(str::to_owned),
                worker_id: worker.map(str::to_owned),
                limits: limit.clone(),
                revision: 1,
                paused: false,
            },
            None,
        )
        .await
        .unwrap();
    }
    let requirement = Requirement {
        project_id: "p".into(),
        requirement_id: "r".into(),
        title: "requirement".into(),
        source_anchor: "spec#L1".into(),
        outcome: "outcome".into(),
        scope: "test".into(),
        acceptance: vec!["independent behavior".into()],
        priority: 1,
        weight: 1,
        deferred_reason: None,
        revision: 1,
    };
    s.create_requirement(requirement.clone()).await.unwrap();
    let owner = OwnerTerritory {
        root_team_id: Some("owner".into()),
        owner_id: "owner".into(),
        include: vec!["src/".into()],
        exclude: vec![],
    };
    s.execute_command(
        CommandIdentity {
            actor_id: "owner".into(),
            idempotency_key: "territory".into(),
        },
        CatalogCommand::PutDocument {
            project_id: "p".into(),
            collection: "owners".into(),
            id: "owner".into(),
            expected_revision: None,
            value: serde_json::to_value(&owner).unwrap(),
        },
    )
    .await
    .unwrap();
    let true_hash = forgeflow_evidence::sha256(&std::fs::read("/usr/bin/true").unwrap());
    for (collection, doc_id, value) in [
        (
            "executor_profiles",
            executor_id,
            json!({"id":executor_id,"program":"/usr/bin/true","prefix_args":[],"home":"/tmp/forgeflow-test/home","profile_name":"authority-test-only","artifact_pins":[{"path":"/usr/bin/true","sha256":true_hash}],"resume_verified":false,"model_route_id":"route","gateway_coverage_verified":false}),
        ),
        (
            "resource_profiles",
            "resource",
            json!({"id":"resource","qualification":"NOT_TESTED_RUNTIME"}),
        ),
        (
            "model_routes",
            "route",
            json!({"id":"route","qualification":"NO_MODEL_CALLS_IN_AUTHORITY_TEST"}),
        ),
    ] {
        s.execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: doc_id.into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: collection.into(),
                id: doc_id.into(),
                expected_revision: None,
                value,
            },
        )
        .await
        .unwrap();
    }
    let mut context = CompileContext {
        requirement_semantic_digests: std::collections::BTreeMap::from([(
            "r".into(),
            forgeflow_planner::requirement_semantic_digest(&requirement),
        )]),
        requirements: vec![forgeflow_planner::Requirement {
            requirement_id: "r".into(),
            source_document: "spec".into(),
            anchor: "L1".into(),
            acceptance: "independent behavior".into(),
            priority: 1,
            deferred_reason: None,
        }],
        owners: vec![owner],
        source_revision: forgeflow_planner::sha256(
            &serde_json::to_vec(&vec![requirement.clone()]).unwrap(),
        ),
        ..Default::default()
    };
    let mut tasks = Vec::new();
    for n in 0..6 {
        let task_id = format!("t{n}");
        let spec = TaskSpec {
            requirement_digest_refs: context.requirement_semantic_digests.clone(),
            outcome: "independent behavior".into(),
            design_anchors: vec!["spec#L1".into()],
            inputs: vec![],
            producer_inputs: vec![],
            mandatory_paths: vec![],
            dependency_refs: vec![],
            contract_produces: vec![],
            contract_consumes: vec![],
            execution_profile: executor_id.into(),
            verification_plan: format!("verify-{task_id}"),
            verification_case_count: 2,
            rollback_plan: "preserve then retry new attempt".into(),
            known_unknowns: vec![],
            not_proven: vec![],
            isolated_contract_probe: false,
        };
        let mut approved_envelope = envelope(&task_id);
        approved_envelope.executor_profile_id = executor_id.into();
        if strict {
            approved_envelope.max_model_requests = 0;
        }
        let mut task = TaskCard {
            project_id: "p".into(),
            task_id: task_id.clone(),
            task_revision: 1,
            flow_revision: 1,
            title: task_id.clone(),
            owner_id: "owner".into(),
            team_id: "owner".into(),
            requirement_ids: vec!["r".into()],
            read_set: vec![],
            write_set: vec![format!("src/{task_id}.rs")],
            dependencies: vec![],
            state: TaskPlanningState::ReadyForAdmission,
            input_digest: String::new(),
            resource_request: ResourceVector {
                active_slot: 1,
                coding_slot: 1,
                cpu_units: 1,
                ..Default::default()
            },
            envelope: Some(approved_envelope),
            revision: 1,
        };
        task.input_digest = forgeflow_planner::canonical_task_input_digest(&task, &spec);
        let commands:Vec<serde_json::Value>=["author","consumer","independent"].into_iter().map(|role|json!({"role":role,"program":"/usr/bin/true","args":[],"env":{},"executable_hash":true_hash,"bound_inputs":[],"report_path":format!("{role}.json"),"expected_cases":[{"name":"positive","kind":"positive"},{"name":"negative","kind":"negative"}],"timeout_seconds":5})).collect();
        let plan = json!({"plan_id":format!("verify-{task_id}"),"task_revision":1,"contract_version":"authority-fixture-v1","input_hash":task.input_digest,"environment_profile":"authority-db-only","oracle_id":"independent-authority-oracle","verifier_id":"verifier","author_id":"owner","commands":commands});
        s.execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: format!("plan-{task_id}"),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "verification_plans".into(),
                id: format!("verify-{task_id}"),
                expected_revision: None,
                value: plan,
            },
        )
        .await
        .unwrap();
        context.task_specs.insert(task_id, spec);
        tasks.push(task);
    }
    let mut flow = FlowRevision {
        project_id: "p".into(),
        flow_revision: 1,
        parent_revision: None,
        state: FlowState::Committed,
        tasks: tasks.clone(),
        input_digest: String::new(),
        approved_by: Some("owner".into()),
        revision: 1,
    };
    flow.input_digest = forgeflow_planner::semantic_digest(&flow, &context);
    let report = forgeflow_planner::compile(&flow, &context);
    assert!(report.passed, "{:?}", report.findings);
    s.execute_command(
        CommandIdentity {
            actor_id: "owner".into(),
            idempotency_key: "flow".into(),
        },
        CatalogCommand::PutFlow {
            flow,
            expected_revision: None,
            context: Some(serde_json::to_value(&context).unwrap()),
        },
    )
    .await
    .unwrap();
    tasks
}
fn request(t: &TaskCard, key: &str) -> AdmissionRequest {
    AdmissionRequest {
        actor_id: "owner".into(),
        idempotency_key: key.into(),
        project_id: t.project_id.clone(),
        task_id: t.task_id.clone(),
        task_revision: 1,
        flow_revision: 1,
        policy_revision: 1,
        input_digest: t.input_digest.clone(),
        worker_id: "w".into(),
        lease_seconds: 300,
        envelope: t.envelope.clone().unwrap(),
    }
}
fn code(r: &StoreError) -> &str {
    match r {
        StoreError::Domain(d) => &d.code,
        _ => "unexpected error",
    }
}

#[derive(Clone)]
struct UniqueQueuedSuccessor {
    selected: Option<QueuedReplacement>,
    entered: Option<Arc<Notify>>,
    proceed: Option<Arc<Notify>>,
}
#[async_trait]
impl HandoffScheduler for UniqueQueuedSuccessor {
    async fn select(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        _terminal: &Attempt,
    ) -> forgeflow_store::Result<Option<QueuedReplacement>> {
        if self.selected.is_some() {
            // There is only one queued task in these Store transaction tests.
            // Real cross-project priority/fairness tests belong to the scheduler.
            let queued: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM documents WHERE collection='queue_entries' AND data->>'status'='QUEUED'",
            ).fetch_one(&mut **tx).await?;
            assert_eq!(queued, 1);
        }
        if let Some(entered) = &self.entered {
            entered.notify_one();
        }
        if let Some(proceed) = &self.proceed {
            proceed.notified().await;
        }
        Ok(self.selected.clone())
    }
}

async fn queue_successor(s: &Store, task: &TaskCard) -> UniqueQueuedSuccessor {
    let result = s
        .execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: format!("enqueue:{}", task.task_id),
            },
            CatalogCommand::EnqueueTask {
                project_id: task.project_id.clone(),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                worker_id: "w".into(),
                priority: 0,
                lease_seconds: 300,
                worker_scope_id: "worker".into(),
                scope_ids: vec!["global".into(), "project".into(), "team".into()],
            },
        )
        .await
        .unwrap();
    let revision = result.value["revision"].as_u64().unwrap();
    let mut admission = request(task, &format!("schedule:p:{}:1:{revision}", task.task_id));
    admission.actor_id = "scheduler-service".into();
    UniqueQueuedSuccessor {
        selected: Some(QueuedReplacement {
            admission,
            queue_revision: revision,
            scheduler_anchor_project_id: "p".into(),
            scheduler_state_revision: None,
            scheduler_state: json!({"cursor":{"project_index":0,"remaining_project_turns":0,"owner_indices":{},"queue_scan_indices":{}},"source":"unique-queued-Store-transaction-oracle"}),
        }),
        entered: None,
        proceed: None,
    }
}

async fn failed_author(s: &Store, a: &Attempt) -> WorkerResult {
    failed_author_receipt(s, a, true).await
}

async fn failed_author_receipt(s: &Store, a: &Attempt, publish_launch: bool) -> WorkerResult {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let claimed = s.claim("w", "p").await.unwrap().unwrap();
    assert_eq!(claimed.attempt_id, a.attempt_id);
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let start_ticks = fields[19].parse::<u64>().unwrap();
    let pgid = fields[2].parse::<i32>().unwrap();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned();
    let execution = uuid::Uuid::new_v4().to_string();
    let launch = json!({
        "execution_id":execution,
        "intent":{"execution_id":execution,"operation_id":a.operation_id,"attempt_id":a.attempt_id,
            "generation":a.generation,"worker_id":a.worker_id,"boot_id":boot,
            "workspace":"/tmp/forgeflow-test","prompt_sha256":"c".repeat(64),
            "created_at":chrono::Utc::now().to_rfc3339()},
        "process":{"pid":pid,"pgid":pgid,"start_ticks":start_ticks,"boot_id":boot,"attempt_id":a.attempt_id},
        "launched_at":chrono::Utc::now().to_rfc3339(),"command_program":"/usr/bin/sleep",
        "command_args":["30"],"environment_key_names":[]
    });
    let result = if publish_launch {
        s.record_worker_event(WorkerEvent {
            event_id: format!("{}:running", a.operation_id),
            project_id: a.project_id.clone(),
            attempt_id: a.attempt_id.clone(),
            lease_id: a.lease_id.clone(),
            generation: a.generation,
            worker_id: a.worker_id.clone(),
            kind: "RUNNING".into(),
            payload: launch.clone(),
        })
        .await
    } else {
        Ok(())
    };
    child.kill().unwrap();
    let status = child.wait().unwrap();
    result.unwrap();
    assert!(!status.success());
    let stop = json!({"process_exit_confirmed":true,"exit_code":status.code(),"signal":status.signal(),
        "reason":"actual_author_killed_and_waited","stdout_bytes":0,"stderr_bytes":0,
        "notification_overflow":0,"log_error":null});
    WorkerResult {
        event_id: format!("{}:result", a.operation_id),
        project_id: a.project_id.clone(),
        attempt_id: a.attempt_id.clone(),
        lease_id: a.lease_id.clone(),
        generation: a.generation,
        worker_id: a.worker_id.clone(),
        evidence: json!({"process_exit_confirmed":true,"execution_id":execution,"launch_receipt":launch,"stop":stop,
            "executor_kind":"CONTROLLED_LIGHTWEIGHT","real_dsh":false}),
        outcome: ExecutorOutcome {
            execution_id: execution,
            upstream_session_id: None,
            exit_code: status.code(),
            completion_reason: "PROCESS_FAILED".into(),
            raw_event_digest: "d".repeat(64),
            transcript_completeness: "CONTROLLED_LIGHTWEIGHT_STDIO_NOT_DSH".into(),
            final_artifact: None,
            error_class: Some("intentional actual subprocess termination".into()),
        },
    }
}

fn handoff_request(result: WorkerResult, key: &str) -> HandoffRequest {
    HandoffRequest {
        identity: CommandIdentity {
            actor_id: "worker-service".into(),
            idempotency_key: key.into(),
        },
        terminal: TerminalAcknowledgement::WorkerResult { result },
    }
}

async fn occupied(s: &Store) -> i64 {
    sqlx::query_scalar("SELECT count(DISTINCT attempt_id) FROM resource_allocations WHERE dimension='active_slot' AND state<>'RELEASED'")
        .fetch_one(s.pool()).await.unwrap()
}

async fn authority_snapshot(s: &Store) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
        'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attempt_id) FROM attempts a),
        'tasks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY task_id) FROM tasks t),
        'leases',(SELECT jsonb_agg(to_jsonb(l) ORDER BY lease_id) FROM leases l),
        'allocations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY allocation_id) FROM resource_allocations r),
        'limits',(SELECT jsonb_agg(to_jsonb(l) ORDER BY scope_id,dimension) FROM resource_limits l),
        'queue_and_cursor',(SELECT jsonb_agg(to_jsonb(d) ORDER BY collection,document_id) FROM documents d WHERE collection IN('queue_entries','operations','channel_pools')),
        'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY project_seq) FROM events e),
        'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM outbox o),
        'replays',(SELECT jsonb_agg(to_jsonb(i) ORDER BY operation_id) FROM idempotency_records i),
        'worker_events',(SELECT jsonb_agg(to_jsonb(w) ORDER BY event_id) FROM worker_event_ids w),
        'merge_intents',(SELECT jsonb_agg(to_jsonb(m) ORDER BY intent_id) FROM merge_intents m),
        'model_permits',(SELECT jsonb_agg(to_jsonb(m) ORDER BY request_id) FROM model_request_permit m),
        'gateway_budgets',(SELECT jsonb_agg(to_jsonb(g) ORDER BY token_sha256) FROM gateway_scope_budget g))")
        .fetch_one(s.pool()).await.unwrap()
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn observer_never_sees_release_without_fresh_successor_and_replay_is_one_group() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let a = s
        .admit(request(&tasks[0], "predecessor"))
        .await
        .unwrap()
        .attempt;
    let result = failed_author(&s, &a).await;
    let _other = s.admit(request(&tasks[1], "other-occupied")).await.unwrap();
    let mut selector = queue_successor(&s, &tasks[2]).await;
    let entered = Arc::new(Notify::new());
    let proceed = Arc::new(Notify::new());
    selector.entered = Some(entered.clone());
    selector.proceed = Some(proceed.clone());
    let r = handoff_request(result, "atomic-observer");
    let running_s = s.clone();
    let running_r = r.clone();
    let running =
        tokio::spawn(async move { running_s.terminal_handoff(running_r, &selector).await });
    entered.notified().await;
    assert_eq!(occupied(&s).await, 2);
    assert_eq!(
        s.get_attempt("p", &a.attempt_id).await.unwrap().state,
        AttemptState::Running
    );
    proceed.notify_one();
    let receipt = running.await.unwrap().unwrap();
    assert_eq!(occupied(&s).await, 2);
    assert_eq!(receipt.terminal.state, AttemptState::Failed);
    assert_eq!(receipt.replacement.attempt.state, AttemptState::Leased);
    assert_ne!(receipt.replacement.attempt.attempt_id, a.attempt_id);
    assert_eq!(
        receipt.evidence["allocated_before"],
        receipt.evidence["allocated_after"]
    );
    assert_eq!(
        receipt.evidence["allocated_after"]["controlled_allocated_attempts"],
        2
    );
    assert!(
        receipt.evidence["author_launch"]["process"]["pid"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        receipt.evidence["successor_author_pid_at_commit"],
        Value::Null
    );
    assert!(
        receipt.evidence["released_allocations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["state"] == "RELEASED")
    );
    assert!(
        receipt.evidence["acquired_allocations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["state"] == "RESERVED")
    );
    let before = authority_snapshot(&s).await;
    for (label, document, expected_revision, value, expected_code) in [
        (
            "create",
            "forged-handoff".to_owned(),
            None,
            json!({"kind":"RESOURCE_HANDOFF"}),
            "COMMAND_REQUIRED",
        ),
        (
            "overwrite",
            format!("handoff:{}", receipt.operation_id),
            Some(1),
            json!({"kind":"FORGED_REPLACEMENT"}),
            "IMMUTABLE_VERIFIER_FACT",
        ),
    ] {
        let error = s
            .execute_command(
                CommandIdentity {
                    actor_id: "internal".into(),
                    idempotency_key: format!("forged:{label}"),
                },
                CatalogCommand::PutDocument {
                    project_id: "p".into(),
                    collection: "operations".into(),
                    id: document,
                    expected_revision,
                    value,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(code(&error), expected_code);
        assert_eq!(before, authority_snapshot(&s).await);
    }
    let no_selection = UniqueQueuedSuccessor {
        selected: None,
        entered: None,
        proceed: None,
    };
    let replay = s.terminal_handoff(r.clone(), &no_selection).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, receipt.operation_id);
    assert_eq!(
        replay.replacement.attempt.attempt_id,
        receipt.replacement.attempt.attempt_id
    );
    assert_eq!(before, authority_snapshot(&s).await);
    let mut changed = r;
    if let TerminalAcknowledgement::WorkerResult { result } = &mut changed.terminal {
        result.outcome.completion_reason = "changed".into();
    }
    assert_eq!(
        code(
            &s.terminal_handoff(changed, &no_selection)
                .await
                .unwrap_err()
        ),
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(before, authority_snapshot(&s).await);
    // The old author generation cannot acquire new effects after transfer.
    assert_eq!(
        code(
            &s.heartbeat(HeartbeatRequest {
                project_id: "p".into(),
                attempt_id: a.attempt_id,
                generation: a.generation,
                worker_id: "w".into(),
                lease_seconds: 300
            })
            .await
            .unwrap_err()
        ),
        "LEASE_STALE"
    );
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn every_rejected_handoff_rolls_back_terminal_fence_vector_cursor_and_outbox() {
    for case in [
        "no-replacement",
        "changed-input",
        "changed-policy",
        "stale-worker",
        "retry-delay",
        "author-unknown",
        "verifier-unsettled",
        "model-admitted",
        "model-quarantined",
        "gateway-inflight",
        "merge-decided",
        "cursor-conflict",
        "queue-unavailable",
        "independent-successor-replay",
        "execution-success-not-terminal",
    ] {
        let (s, schema, admin) = setup().await;
        let tasks = fixture(&s).await;
        let a = s.admit(request(&tasks[0], case)).await.unwrap().attempt;
        let mut result = failed_author(&s, &a).await;
        let mut selector = queue_successor(&s, &tasks[1]).await;
        let expected = match case {
            "no-replacement" => {
                selector.selected = None;
                "HANDOFF_UNAVAILABLE"
            }
            "changed-input" => {
                selector.selected.as_mut().unwrap().admission.input_digest = "f".repeat(64);
                "CONTEXT_STALE"
            }
            "changed-policy" => {
                selector
                    .selected
                    .as_mut()
                    .unwrap()
                    .admission
                    .policy_revision = 2;
                "REVISION_CONFLICT"
            }
            "stale-worker" => {
                sqlx::query(
                    "UPDATE workers SET heartbeat_at=clock_timestamp()-interval '5 minutes'",
                )
                .execute(s.pool())
                .await
                .unwrap();
                "WORKER_STALE"
            }
            "retry-delay" => {
                sqlx::query("UPDATE documents SET data=jsonb_set(data,'{retry_not_before_ms}',to_jsonb((extract(epoch from clock_timestamp()+interval '1 hour')*1000)::bigint)) WHERE collection='queue_entries'").execute(s.pool()).await.unwrap();
                "ADMISSION_BLOCKED"
            }
            "author-unknown" => {
                result.evidence["stop"]["process_exit_confirmed"] = json!(false);
                "PROCESS_EXIT_UNCONFIRMED"
            }
            "verifier-unsettled" => {
                s.execute_command(CommandIdentity { actor_id:"verification-service".into(),idempotency_key:"verifier-root".into() },CatalogCommand::PutDocument { project_id:"p".into(),collection:"operations".into(),id:"verifier-root".into(),expected_revision:None,value:json!({"kind":"VERIFIER_PROCESS_ROOT","operation_id":"verify-op","attempt_id":a.attempt_id,"verifier_root":"/tmp/unsettled-actual-root"}) }).await.unwrap();
                "PROCESS_EXIT_UNCONFIRMED"
            }
            "model-admitted" | "model-quarantined" | "gateway-inflight" => {
                let token = "d".repeat(64);
                sqlx::query("INSERT INTO gateway_scope_budget(token_sha256,attempt_id,route_id,model,max_requests,inflight_limit,requests_used,inflight,expires_at,project_id,generation) VALUES($1,$2,'route','model',1,1,1,1,clock_timestamp()+interval '1 minute','p',$3)")
                    .bind(&token).bind(&a.attempt_id).bind(a.generation).execute(s.pool()).await.unwrap();
                if case != "gateway-inflight" {
                    sqlx::query("INSERT INTO model_request_permit(request_id,attempt_id,route_id,model,generation,status,scope_token_digest) VALUES($1,$2,'route','model',$3,$4,$5)")
                        .bind(case).bind(&a.attempt_id).bind(a.generation)
                        .bind(if case=="model-admitted"{"ADMITTED"}else{"QUARANTINED"}).bind(token).execute(s.pool()).await.unwrap();
                }
                "MODEL_EFFECT_UNCONFIRMED"
            }
            "merge-decided" => {
                sqlx::query("INSERT INTO merge_intents(intent_id,project_id,attempt_id,generation,target_ref,state,revision,data) VALUES('decided','p',$1,$2,'refs/heads/main','COMMIT_DECIDED',1,'{}')")
                .bind(&a.attempt_id).bind(a.generation).execute(s.pool()).await.unwrap();
                "MERGE_EFFECT_UNCONFIRMED"
            }
            "cursor-conflict" => {
                selector.selected.as_mut().unwrap().scheduler_state_revision = Some(1);
                "REVISION_CONFLICT"
            }
            "queue-unavailable" => {
                selector.selected.as_mut().unwrap().queue_revision = 2;
                "REVISION_CONFLICT"
            }
            "independent-successor-replay" => {
                s.admit(selector.selected.as_ref().unwrap().admission.clone())
                    .await
                    .unwrap();
                "HANDOFF_REPLACEMENT_REPLAYED"
            }
            "execution-success-not-terminal" => {
                // Attempting to claim business success from an execution outcome
                // must retain the allocation pending independent authority.
                result.outcome.completion_reason = "EXECUTOR_COMPLETED".into();
                result.outcome.exit_code = Some(0);
                "HANDOFF_NOT_TERMINAL"
            }
            _ => unreachable!(),
        };
        let before = authority_snapshot(&s).await;
        let error = s
            .terminal_handoff(handoff_request(result, case), &selector)
            .await
            .unwrap_err();
        assert_eq!(code(&error), expected, "{case}: {error}");
        assert_eq!(
            before,
            authority_snapshot(&s).await,
            "partial authoritative mutation: {case}"
        );
        assert_eq!(
            occupied(&s).await,
            if case == "independent-successor-replay" {
                2
            } else {
                1
            }
        );
        cleanup(s, schema, admin).await;
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn concurrent_identical_handoffs_have_one_fresh_lease_and_one_group() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let a = s
        .admit(request(&tasks[0], "concurrent-predecessor"))
        .await
        .unwrap()
        .attempt;
    let result = failed_author(&s, &a).await;
    let selector = queue_successor(&s, &tasks[1]).await;
    let request = handoff_request(result, "concurrent-handoff");
    let mut runs = vec![];
    for _ in 0..8 {
        let s = s.clone();
        let selector = selector.clone();
        let request = request.clone();
        runs.push(tokio::spawn(async move {
            s.terminal_handoff(request, &selector).await.unwrap()
        }));
    }
    let mut receipts = vec![];
    for run in runs {
        receipts.push(run.await.unwrap());
    }
    assert_eq!(receipts.iter().filter(|r| !r.replayed).count(), 1);
    assert!(
        receipts
            .iter()
            .all(|r| r.operation_id == receipts[0].operation_id
                && r.replacement.attempt.attempt_id == receipts[0].replacement.attempt.attempt_id)
    );
    assert_eq!(occupied(&s).await, 1);
    let grouped:i64=sqlx::query_scalar("SELECT count(*) FROM documents WHERE collection='operations' AND data->>'kind'='RESOURCE_HANDOFF'")
        .fetch_one(s.pool()).await.unwrap();
    let starts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE kind='attempt.start' AND payload->>'attempt_id'=$1",
    )
    .bind(&receipts[0].replacement.attempt.attempt_id)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!((grouped, starts), (1, 1));
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn undispatched_reservation_does_not_establish_launched_channel_lineage() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let a = s
        .admit(request(&tasks[0], "never-launched"))
        .await
        .unwrap()
        .attempt;
    let selector = queue_successor(&s, &tasks[1]).await;
    let before = authority_snapshot(&s).await;
    let request = HandoffRequest {
        identity: CommandIdentity {
            actor_id: "worker-service".into(),
            idempotency_key: "never-launched-handoff".into(),
        },
        terminal: TerminalAcknowledgement::ConfirmStop {
            receipt: StopReceipt {
                project_id: "p".into(),
                attempt_id: a.attempt_id,
                generation: a.generation,
                worker_id: "w".into(),
                process_exit_confirmed: true,
                evidence: json!({"process_exit_confirmed":true,"stop":{"process_exit_confirmed":true,"reason":"never-launched","stdout_bytes":0,"stderr_bytes":0,"notification_overflow":0}}),
            },
        },
    };
    assert_eq!(
        code(&s.terminal_handoff(request, &selector).await.unwrap_err()),
        "HANDOFF_PREDECESSOR_UNLAUNCHED"
    );
    assert_eq!(before, authority_snapshot(&s).await);
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn actual_stopped_cancel_timeout_and_worker_recovery_transfer_full_quarantined_vector() {
    for case in [
        "cancel-result",
        "cancel-stop-receipt",
        "timeout",
        "worker-recovery",
    ] {
        let (s, schema, admin) = setup().await;
        let tasks = fixture(&s).await;
        let a = s.admit(request(&tasks[0], case)).await.unwrap().attempt;
        let result = failed_author(&s, &a).await;
        if case.starts_with("cancel") {
            let current = s.get_attempt("p", &a.attempt_id).await.unwrap();
            s.cancel(CancelRequest {
                actor_id: "owner".into(),
                idempotency_key: format!("cancel:{case}"),
                project_id: "p".into(),
                attempt_id: a.attempt_id.clone(),
                expected_revision: current.revision,
                reason: "authorized actual author cancellation".into(),
            })
            .await
            .unwrap();
        } else if case == "timeout" {
            sqlx::query("UPDATE leases SET expires_at=clock_timestamp()-interval '1 second',issued_at=clock_timestamp()-interval '2 seconds' WHERE attempt_id=$1")
                .bind(&a.attempt_id).execute(s.pool()).await.unwrap();
            s.expire_leases().await.unwrap();
        } else {
            s.register_worker(WorkerRegisterRequest {
                project_id: Some("p".into()),
                executor_profile_ids: vec!["exec".into()],
                worker_id: "w".into(),
                boot_id: "new-worker-boot".into(),
                capabilities: vec!["CONTROLLED_LIGHTWEIGHT".into()],
            })
            .await
            .unwrap();
        }
        assert_eq!(occupied(&s).await, 1);
        let selector = queue_successor(&s, &tasks[1]).await;
        let mut request = handoff_request(result.clone(), case);
        if case == "cancel-stop-receipt" {
            request.terminal = TerminalAcknowledgement::ConfirmStop {
                receipt: StopReceipt {
                    project_id: "p".into(),
                    attempt_id: a.attempt_id.clone(),
                    generation: a.generation,
                    worker_id: "w".into(),
                    process_exit_confirmed: true,
                    evidence: result.evidence,
                },
            };
        }
        let receipt = s.terminal_handoff(request, &selector).await.unwrap();
        assert_eq!(receipt.terminal.state, AttemptState::Cancelled, "{case}");
        assert_eq!(occupied(&s).await, 1);
        assert_eq!(
            receipt.evidence["allocated_before"],
            receipt.evidence["allocated_after"]
        );
        assert!(
            receipt.evidence["released_allocations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v["state"] == "RELEASED")
        );
        assert!(
            receipt.evidence["acquired_allocations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v["state"] == "RESERVED")
        );
        cleanup(s, schema, admin).await;
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn unpublished_real_launch_receipt_recovers_but_forged_identity_never_transfers() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let a = s
        .admit(request(&tasks[0], "unpublished-launch"))
        .await
        .unwrap()
        .attempt;
    let result = failed_author_receipt(&s, &a, false).await;
    let selector = queue_successor(&s, &tasks[1]).await;
    let before = authority_snapshot(&s).await;
    for field in [
        "pid",
        "operation",
        "generation",
        "report-generation",
        "execution",
        "stop-execution",
    ] {
        let mut forged = result.clone();
        match field {
            "pid" => forged.evidence["launch_receipt"]["process"]["pid"] = json!(0),
            "operation" => {
                forged.evidence["launch_receipt"]["intent"]["operation_id"] =
                    json!(uuid::Uuid::new_v4().to_string())
            }
            "generation" => {
                forged.evidence["launch_receipt"]["intent"]["generation"] = json!(a.generation + 1)
            }
            "report-generation" => forged.generation = a.generation + 1,
            "execution" => forged.outcome.execution_id = uuid::Uuid::new_v4().to_string(),
            "stop-execution" => {}
            _ => unreachable!(),
        }
        let mut request = handoff_request(forged.clone(), &format!("forged:{field}"));
        if field == "stop-execution" {
            s.cancel(CancelRequest {
                actor_id: "owner".into(),
                idempotency_key: "cancel-unpublished".into(),
                project_id: "p".into(),
                attempt_id: a.attempt_id.clone(),
                expected_revision: 2,
                reason: "authorized stop of unpublished actual author".into(),
            })
            .await
            .unwrap();
            forged.evidence["execution_id"] = json!(uuid::Uuid::new_v4().to_string());
            request.terminal = TerminalAcknowledgement::ConfirmStop {
                receipt: StopReceipt {
                    project_id: "p".into(),
                    attempt_id: a.attempt_id.clone(),
                    generation: a.generation,
                    worker_id: "w".into(),
                    process_exit_confirmed: true,
                    evidence: forged.evidence,
                },
            };
        }
        let snapshot = authority_snapshot(&s).await;
        assert!(
            s.terminal_handoff(request, &selector).await.is_err(),
            "accepted forged {field}"
        );
        assert_eq!(
            snapshot,
            authority_snapshot(&s).await,
            "changed authority for forged {field}"
        );
        assert_eq!(occupied(&s).await, 1);
    }
    // All forgeries before the explicitly authorized cancel kept the original
    // state. The real bound receipt remains acceptable after that cancel fence.
    assert_eq!(before["attempts"][0]["state"], "STARTING");
    let receipt = s
        .terminal_handoff(handoff_request(result, "recover-unpublished"), &selector)
        .await
        .unwrap();
    assert_eq!(receipt.terminal.state, AttemptState::Cancelled);
    assert_eq!(occupied(&s).await, 1);
    assert!(
        receipt.evidence["author_launch"]["process"]["pid"]
            .as_u64()
            .unwrap()
            > 0
    );
    cleanup(s, schema, admin).await;
}

async fn strict_pool_value(s: &Store, a: &Attempt) -> Value {
    let snapshot = s.snapshot("p").await.unwrap();
    let now = chrono::Utc::now();
    json!({"schema_version":"forgeflow.channel_pool.v1","project_id":"p","status":"ACTIVE",
        "starts_at":now,"ends_at":now+chrono::Duration::seconds(3),"target_channels":1,
        "worker_id":"w","resource_profile_id":"resource","executor_profile_id":"controlled-lightweight.v1",
        "controlled_only":true,"launch_grace_ms":2000,
        "known_baseline_proof":{"attempt_ids":[a.attempt_id],"snapshot_revision":snapshot["revision"],
            "observed_at":snapshot["as_of"],"snapshot_sha256":forgeflow_planner::sha256(&serde_json::to_vec(&snapshot).unwrap())},
        "authorized_by":"owner","authorized_at":now,"activation_identity":{"actor_id":"owner","idempotency_key":"activate-pool"},
        "activation_request_sha256":"a".repeat(64)})
}
async fn save_pool(
    s: &Store,
    value: Value,
    expected: Option<u64>,
    key: &str,
) -> std::result::Result<Value, StoreError> {
    s.execute_command(
        CommandIdentity {
            actor_id: "channel-pool-service".into(),
            idempotency_key: key.into(),
        },
        CatalogCommand::PutDocument {
            project_id: "p".into(),
            collection: "channel_pools".into(),
            id: "strict-controlled".into(),
            expected_revision: expected,
            value,
        },
    )
    .await
    .map(|result| result.value)
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn strict_pool_requires_atomic_closure_and_explicit_elapsed_owner_drain() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture_with_pool(&s, true).await;
    let a = s
        .admit(request(&tasks[0], "pool-baseline"))
        .await
        .unwrap()
        .attempt;
    let result = failed_author(&s, &a).await;
    let selector = queue_successor(&s, &tasks[1]).await;
    let policy = save_pool(&s, strict_pool_value(&s, &a).await, None, "activate")
        .await
        .unwrap();
    let before = authority_snapshot(&s).await;
    assert_eq!(
        code(&s.worker_result(result.clone()).await.unwrap_err()),
        "CHANNEL_POOL_HANDOFF_REQUIRED"
    );
    assert_eq!(before, authority_snapshot(&s).await);
    assert_eq!(
        code(
            &s.admit(request(&tasks[2], "ordinary-extra"))
                .await
                .unwrap_err()
        ),
        "CHANNEL_POOL_HANDOFF_REQUIRED"
    );
    assert_eq!(before, authority_snapshot(&s).await);
    let mut early_drain = policy.clone();
    early_drain["status"] = json!("DRAINING");
    early_drain["drain_authorized_by"] = json!("owner");
    early_drain["drain_authorized_at"] = json!(chrono::Utc::now());
    early_drain["drain_reason"] = json!("early drain attempt");
    early_drain["drain_identity"] = json!({"actor_id":"owner","idempotency_key":"early-drain"});
    early_drain["drain_request_sha256"] = json!("b".repeat(64));
    assert!(
        save_pool(&s, early_drain, Some(1), "early-drain")
            .await
            .is_err()
    );
    assert_eq!(before, authority_snapshot(&s).await);
    let original = handoff_request(result, "strict-handoff");
    let receipt = s
        .terminal_handoff(original.clone(), &selector)
        .await
        .unwrap();
    assert_eq!(receipt.evidence["strict_pool_id"], "strict-controlled");
    assert_eq!(receipt.evidence["lineage_root_attempt_id"], a.attempt_id);
    assert_eq!(occupied(&s).await, 1);
    let successor_result = failed_author(&s, &receipt.replacement.attempt).await;
    let ends: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(policy["ends_at"].clone()).unwrap();
    let wait = (ends - chrono::Utc::now()).to_std().unwrap_or_default()
        + std::time::Duration::from_millis(20);
    tokio::time::sleep(wait).await;
    assert_eq!(
        code(&s.worker_result(successor_result.clone()).await.unwrap_err()),
        "CHANNEL_POOL_HANDOFF_REQUIRED"
    );
    assert_eq!(occupied(&s).await, 1);
    let mut drain = policy;
    drain["status"] = json!("DRAINING");
    drain["drain_authorized_by"] = json!("owner");
    drain["drain_authorized_at"] = json!(chrono::Utc::now());
    drain["drain_reason"] = json!("original smoke interval elapsed");
    drain["drain_identity"] = json!({"actor_id":"owner","idempotency_key":"drain"});
    drain["drain_request_sha256"] = json!("b".repeat(64));
    let draining = save_pool(&s, drain, Some(1), "drain").await.unwrap();
    let replay = s.terminal_handoff(original, &selector).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, receipt.operation_id);
    assert_eq!(
        code(
            &s.terminal_handoff(
                handoff_request(successor_result.clone(), "after-drain"),
                &selector
            )
            .await
            .unwrap_err()
        ),
        "CHANNEL_POOL_DRAINING"
    );
    assert_eq!(
        code(
            &s.admit(request(&tasks[2], "drain-refill"))
                .await
                .unwrap_err()
        ),
        "CHANNEL_POOL_DRAINING"
    );
    let mut ended = draining.clone();
    ended["status"] = json!("ENDED");
    ended["ended_by"] = json!("owner");
    ended["ended_at"] = json!(chrono::Utc::now());
    ended["end_reason"] = json!("zero allocation required");
    ended["end_identity"] = json!({"actor_id":"owner","idempotency_key":"end"});
    ended["end_request_sha256"] = json!("c".repeat(64));
    assert_eq!(
        code(
            &save_pool(&s, ended.clone(), Some(2), "early-end")
                .await
                .unwrap_err()
        ),
        "CHANNEL_POOL_NOT_DRAINED"
    );
    s.worker_result(successor_result).await.unwrap();
    assert_eq!(occupied(&s).await, 0);
    ended["ended_at"] = json!(chrono::Utc::now());
    let completed = save_pool(&s, ended, Some(2), "end").await.unwrap();
    assert_eq!(completed["status"], "ENDED");
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn owner_abort_retains_original_window_and_requires_real_stop_before_release() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture_with_pool(&s, true).await;
    let attempt = s
        .admit(request(&tasks[0], "abort-baseline"))
        .await
        .unwrap()
        .attempt;
    let result = failed_author(&s, &attempt).await;
    let mut definition = strict_pool_value(&s, &attempt).await;
    definition["ends_at"] = json!(chrono::Utc::now() + chrono::Duration::hours(1));
    let policy = save_pool(&s, definition, None, "abort-activate")
        .await
        .unwrap();
    let original_end = policy["ends_at"].clone();
    let mut drain = policy.clone();
    drain["status"] = json!("DRAINING");
    drain["drain_authorized_by"] = json!("owner");
    drain["drain_authorized_at"] = json!(chrono::Utc::now());
    drain["drain_reason"] =
        json!("Owner aborts failed qualification without changing its interval");
    drain["drain_identity"] = json!({"actor_id":"owner","idempotency_key":"abort-drain"});
    drain["drain_request_sha256"] = json!("b".repeat(64));
    assert!(
        save_pool(&s, drain.clone(), Some(1), "ordinary-early-drain")
            .await
            .is_err()
    );
    assert_eq!(occupied(&s).await, 1);
    drain["qualification_aborted"] = json!(true);
    let draining = save_pool(&s, drain, Some(1), "explicit-abort")
        .await
        .unwrap();
    assert_eq!(draining["ends_at"], original_end);
    assert_eq!(draining["qualification_aborted"], true);
    assert_eq!(
        occupied(&s).await,
        1,
        "abort authorization alone cannot release a running allocation"
    );
    let mut ended = draining;
    ended["status"] = json!("ENDED");
    ended["ended_by"] = json!("owner");
    ended["ended_at"] = json!(chrono::Utc::now());
    ended["end_reason"] = json!("retain failed qualification after proven stop");
    ended["end_identity"] = json!({"actor_id":"owner","idempotency_key":"abort-end"});
    ended["end_request_sha256"] = json!("c".repeat(64));
    assert_eq!(
        code(
            &save_pool(&s, ended.clone(), Some(2), "end-with-live-allocation")
                .await
                .unwrap_err()
        ),
        "CHANNEL_POOL_NOT_DRAINED"
    );
    s.worker_result(result).await.unwrap();
    assert_eq!(occupied(&s).await, 0);
    let mut erased_abort = ended.clone();
    erased_abort["qualification_aborted"] = json!(false);
    assert!(
        save_pool(&s, erased_abort, Some(2), "erase-abort")
            .await
            .is_err()
    );
    ended["ended_at"] = json!(chrono::Utc::now());
    let completed = save_pool(&s, ended, Some(2), "abort-ended").await.unwrap();
    assert_eq!(completed["status"], "ENDED");
    assert_eq!(completed["qualification_aborted"], true);
    assert_eq!(completed["ends_at"], original_end);
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn strict_pool_rejects_unused_baseline_and_cross_worker_atomic_rerouting() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture_with_pool(&s, true).await;
    let a = s
        .admit(request(&tasks[0], "pool-baseline"))
        .await
        .unwrap()
        .attempt;
    assert_eq!(
        code(
            &save_pool(&s, strict_pool_value(&s, &a).await, None, "unused-baseline")
                .await
                .unwrap_err()
        ),
        "CHANNEL_POOL_BASELINE_INVALID"
    );
    let result = failed_author(&s, &a).await;
    let mut selector = queue_successor(&s, &tasks[1]).await;
    s.register_worker(WorkerRegisterRequest {
        project_id: Some("p".into()),
        executor_profile_ids: vec!["controlled-lightweight.v1".into()],
        worker_id: "other-worker".into(),
        boot_id: "boot-other".into(),
        capabilities: vec!["CONTROLLED_LIGHTWEIGHT".into()],
    })
    .await
    .unwrap();
    s.put_resource_policy(
        ResourcePolicy {
            scope_id: "other-worker-scope".into(),
            parent_scope_id: Some("global".into()),
            project_id: None,
            team_id: None,
            worker_id: Some("other-worker".into()),
            limits: ResourceVector {
                active_slot: 2,
                coding_slot: 2,
                cpu_units: 2,
                ..Default::default()
            },
            revision: 1,
            paused: false,
        },
        None,
    )
    .await
    .unwrap();
    let mut queue = s
        .get_document("p", "queue_entries", &tasks[1].task_id)
        .await
        .unwrap();
    queue["worker_id"] = json!("");
    let changed = s
        .execute_command(
            CommandIdentity {
                actor_id: "scheduler-service".into(),
                idempotency_key: "blank-worker".into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "queue_entries".into(),
                id: tasks[1].task_id.clone(),
                expected_revision: Some(1),
                value: queue,
            },
        )
        .await
        .unwrap();
    let selected = selector.selected.as_mut().unwrap();
    selected.queue_revision = changed.value["revision"].as_u64().unwrap();
    selected.admission.worker_id = "other-worker".into();
    selected.admission.idempotency_key = format!(
        "schedule:p:{}:1:{}",
        tasks[1].task_id, selected.queue_revision
    );
    save_pool(&s, strict_pool_value(&s, &a).await, None, "activate-good")
        .await
        .unwrap();
    let before = authority_snapshot(&s).await;
    assert_eq!(
        code(
            &s.terminal_handoff(handoff_request(result, "wrong-worker"), &selector)
                .await
                .unwrap_err()
        ),
        "CHANNEL_POOL_SCOPE_MISMATCH"
    );
    assert_eq!(before, authority_snapshot(&s).await);
    assert_eq!(occupied(&s).await, 1);
    cleanup(s, schema, admin).await;
}
