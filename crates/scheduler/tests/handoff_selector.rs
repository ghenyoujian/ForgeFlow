//! Actual PostgreSQL selector authority tests. An end-to-end handoff uses real
//! lightweight launch/stop receipts; this does not qualify sustained channel Gates.
use forgeflow_domain::*;
use forgeflow_planner::{CompileContext, OwnerTerritory, TaskSpec};
use forgeflow_scheduler::{
    ActiveWrite, PumpConfig, PumpError, QueueEntry, StoreHandoffScheduler, pump_once,
};
use forgeflow_store::{HandoffRequest, HandoffScheduler, Store, TerminalAcknowledgement};
use serde_json::{Value, json};
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicU64, Ordering};
// Exercise exactly the read helpers called by service.rs without expanding the
// public scheduler API or introducing runtime metrics/serialization overhead.
#[path = "../src/frontier.rs"]
mod read_projection;

fn vector(amount: u64) -> ResourceVector {
    ResourceVector {
        active_slot: amount,
        coding_slot: amount,
        cpu_units: amount,
        memory_bytes: amount,
        build_permit: amount,
        gpu_permit: amount,
        provider_inflight: amount,
    }
}
async fn setup() -> (Store, String, sqlx::PgPool) {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL required for real PostgreSQL selector tests");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!(
        "selector_{}_{}_{}",
        std::process::id(),
        chrono::Utc::now().timestamp_micros(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(8)
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
    store
        .put_resource_policy(
            ResourcePolicy {
                scope_id: "global".into(),
                parent_scope_id: None,
                project_id: None,
                team_id: None,
                worker_id: None,
                limits: vector(1),
                revision: 1,
                paused: false,
            },
            None,
        )
        .await
        .unwrap();
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
fn envelope(project: &str, root: &str, task: &str) -> ExecutionEnvelope {
    serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":"preflight","project_id":project,"task_id":task,"task_revision":1,"attempt_id":"preflight","lease_id":"preflight","generation":1,"worker_id":format!("{project}-w"),"workspace_root":root,"base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[format!("src/{task}.rs")],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":format!("verify-{task}"),"allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS"],"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:01:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":"/tmp/forgeflow-test/artifacts","secret_refs":[],"idempotency_key":"preflight","trace_id":"test","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null,"command":{"program":"/usr/bin/sleep","args":["30"]}})).unwrap()
}
async fn fixture(s: &Store, project: &str, root: &str, dependency: bool) -> Vec<TaskCard> {
    fixture_with_profiles(s, project, root, dependency, false).await
}
async fn fixture_with_profiles(
    s: &Store,
    project: &str,
    root: &str,
    dependency: bool,
    strict: bool,
) -> Vec<TaskCard> {
    std::fs::create_dir_all(root).unwrap();
    s.create_project(Project {
        project_id: project.into(),
        name: "safety fixture".into(),
        root_path: root.into(),
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
        project_id: project.into(),
        team_id: "owner".into(),
        parent_team_id: None,
        name: "owner".into(),
        paused: false,
        revision: 1,
    })
    .await
    .unwrap();
    s.register_worker(WorkerRegisterRequest {
        project_id: Some(project.into()),
        executor_profile_ids: if strict {
            vec!["exec".into(), "controlled-lightweight.v1".into()]
        } else {
            vec!["exec".into()]
        },
        worker_id: format!("{project}-w"),
        boot_id: "boot1".into(),
        capabilities: vec!["CONTROLLED_LIGHTWEIGHT".into()],
    })
    .await
    .unwrap();
    let limit = vector(1);
    for (scope, p, team, worker, parent) in [
        (
            format!("project:{project}"),
            Some(project.to_owned()),
            None,
            None,
            "global".to_owned(),
        ),
        (
            format!("team:{project}"),
            Some(project.to_owned()),
            Some("owner".to_owned()),
            None,
            format!("project:{project}"),
        ),
        (
            format!("worker:{project}-w"),
            None,
            None,
            Some(format!("{project}-w")),
            "global".to_owned(),
        ),
    ] {
        s.put_resource_policy(
            ResourcePolicy {
                scope_id: scope,
                parent_scope_id: Some(parent),
                project_id: p,
                team_id: team,
                worker_id: worker,
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
        project_id: project.into(),
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
            idempotency_key: format!("{project}:territory"),
        },
        CatalogCommand::PutDocument {
            project_id: project.into(),
            collection: "owners".into(),
            id: "owner".into(),
            expected_revision: None,
            value: serde_json::to_value(&owner).unwrap(),
        },
    )
    .await
    .unwrap();
    let true_hash = forgeflow_planner::sha256(&std::fs::read("/usr/bin/true").unwrap());
    for (collection, doc_id, value) in [
        (
            "executor_profiles",
            "exec",
            json!({"id":"exec","program":"/usr/bin/true","prefix_args":[],"home":"/tmp/forgeflow-test/home","profile_name":"authority-test-only","artifact_pins":[{"path":"/usr/bin/true","sha256":true_hash}],"resume_verified":false,"model_route_id":"route","gateway_coverage_verified":false}),
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
                idempotency_key: format!("{project}:{doc_id}"),
            },
            CatalogCommand::PutDocument {
                project_id: project.into(),
                collection: collection.into(),
                id: doc_id.into(),
                expected_revision: None,
                value,
            },
        )
        .await
        .unwrap();
    }
    if strict {
        for (collection, id, value) in [
            (
                "executor_profiles",
                "controlled-lightweight.v1",
                json!({"id":"controlled-lightweight.v1","kind":"CONTROLLED_LIGHTWEIGHT","approved_programs":["/usr/bin/sleep"]}),
            ),
            (
                "resource_profiles",
                "outside-resource",
                json!({"id":"outside-resource","qualification":"SELECTOR_TEST_ONLY"}),
            ),
        ] {
            s.execute_command(
                CommandIdentity {
                    actor_id: "owner".into(),
                    idempotency_key: format!("{project}:{id}"),
                },
                CatalogCommand::PutDocument {
                    project_id: project.into(),
                    collection: collection.into(),
                    id: id.into(),
                    expected_revision: None,
                    value,
                },
            )
            .await
            .unwrap();
        }
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
        let mut spec = TaskSpec {
            requirement_digest_refs: context.requirement_semantic_digests.clone(),
            outcome: "independent behavior".into(),
            design_anchors: vec!["spec#L1".into()],
            inputs: vec![],
            producer_inputs: vec![],
            mandatory_paths: vec![],
            dependency_refs: vec![],
            contract_produces: vec![],
            contract_consumes: vec![],
            execution_profile: "exec".into(),
            verification_plan: format!("verify-{task_id}"),
            verification_case_count: 2,
            rollback_plan: "preserve then retry new attempt".into(),
            known_unknowns: vec![],
            not_proven: vec![],
            isolated_contract_probe: false,
        };
        if dependency && n == 2 {
            spec.dependency_refs
                .push(forgeflow_planner::DependencySpec {
                    project_id: project.into(),
                    task_id: "t0".into(),
                    kind: forgeflow_planner::DependencyKind::GatePass,
                    binding_id: "predecessor-gate".into(),
                });
        }
        let mut task = TaskCard {
            project_id: project.into(),
            task_id: task_id.clone(),
            task_revision: 1,
            flow_revision: 1,
            title: task_id.clone(),
            owner_id: "owner".into(),
            team_id: "owner".into(),
            requirement_ids: vec!["r".into()],
            read_set: vec![],
            write_set: vec![format!("src/{task_id}.rs")],
            dependencies: if dependency && n == 2 {
                vec!["t0".into()]
            } else {
                vec![]
            },
            state: TaskPlanningState::ReadyForAdmission,
            input_digest: String::new(),
            resource_request: vector(1),
            envelope: Some(envelope(project, root, &task_id)),
            revision: 1,
        };
        if strict {
            let envelope = task.envelope.as_mut().unwrap();
            envelope.executor_profile_id = "controlled-lightweight.v1".into();
            envelope.max_model_requests = 0;
            task.resource_request.provider_inflight = 0;
            spec.execution_profile = "controlled-lightweight.v1".into();
            if n == 1 {
                envelope.resource_profile_id = "outside-resource".into();
            }
            if n == 4 {
                envelope.executor_profile_id = "exec".into();
                spec.execution_profile = "exec".into();
            }
            if n == 5 {
                envelope.max_model_requests = 1;
                task.resource_request.provider_inflight = 1;
            }
        }
        task.input_digest = forgeflow_planner::canonical_task_input_digest(&task, &spec);
        let commands:Vec<serde_json::Value>=["author","consumer","independent"].into_iter().map(|role|json!({"role":role,"program":"/usr/bin/true","args":[],"env":{},"executable_hash":true_hash,"bound_inputs":[],"report_path":format!("{role}.json"),"expected_cases":[{"name":"positive","kind":"positive"},{"name":"negative","kind":"negative"}],"timeout_seconds":5})).collect();
        let plan = json!({"plan_id":format!("verify-{task_id}"),"task_revision":1,"contract_version":"authority-fixture-v1","input_hash":task.input_digest,"environment_profile":"authority-db-only","oracle_id":"independent-authority-oracle","verifier_id":"verifier","author_id":"owner","commands":commands});
        s.execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: format!("{project}:plan-{task_id}"),
            },
            CatalogCommand::PutDocument {
                project_id: project.into(),
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
        project_id: project.into(),
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
            idempotency_key: format!("{project}:flow"),
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
        worker_id: format!("{}-w", t.project_id),
        lease_seconds: 300,
        envelope: t.envelope.clone().unwrap(),
    }
}
async fn failed_author(s: &Store, a: &Attempt, root: &str) -> WorkerResult {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let claimed = s.claim(&a.worker_id, &a.project_id).await.unwrap().unwrap();
    assert_eq!(claimed.attempt_id, a.attempt_id);
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .current_dir(root)
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
    let execution = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .unwrap()
        .trim()
        .to_owned();
    let launch = json!({
        "execution_id":execution,
        "intent":{"execution_id":execution,"operation_id":a.operation_id,"attempt_id":a.attempt_id,
            "generation":a.generation,"worker_id":a.worker_id,"boot_id":boot,
            "workspace":root,"prompt_sha256":"c".repeat(64),
            "created_at":chrono::Utc::now().to_rfc3339()},
        "process":{"pid":pid,"pgid":pgid,"start_ticks":start_ticks,"boot_id":boot,"attempt_id":a.attempt_id},
        "launched_at":chrono::Utc::now().to_rfc3339(),"command_program":"/usr/bin/sleep",
        "command_args":["30"],"environment_key_names":[]
    });
    let result = {
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

async fn enqueue(s: &Store, task: &TaskCard, priority: i32, worker: &str) -> u64 {
    s.execute_command(
        CommandIdentity {
            actor_id: "owner".into(),
            idempotency_key: format!("enqueue:{}:{}", task.project_id, task.task_id),
        },
        CatalogCommand::EnqueueTask {
            project_id: task.project_id.clone(),
            task_id: task.task_id.clone(),
            expected_revision: task.revision,
            worker_id: worker.into(),
            priority,
            lease_seconds: 300,
            worker_scope_id: if worker.is_empty() {
                String::new()
            } else {
                format!("worker:{worker}")
            },
            scope_ids: vec![],
        },
    )
    .await
    .unwrap()
    .value["revision"]
        .as_u64()
        .unwrap()
}
async fn age_queue(s: &Store, project: &str, task: &str) -> u64 {
    let mut value = s
        .get_document(project, "queue_entries", task)
        .await
        .unwrap();
    let revision = value["revision"].as_u64().unwrap();
    value.as_object_mut().unwrap().remove("revision");
    value["enqueued_at_ms"] = json!(chrono::Utc::now().timestamp_millis() - 600_000);
    s.execute_command(
        CommandIdentity {
            actor_id: "scheduler-service".into(),
            idempotency_key: format!("age:{project}:{task}"),
        },
        CatalogCommand::PutDocument {
            project_id: project.into(),
            collection: "queue_entries".into(),
            id: task.into(),
            expected_revision: Some(revision),
            value,
        },
    )
    .await
    .unwrap()
    .value["revision"]
        .as_u64()
        .unwrap()
}
fn handoff(result: WorkerResult, key: &str) -> HandoffRequest {
    HandoffRequest {
        identity: CommandIdentity {
            actor_id: "worker-service".into(),
            idempotency_key: key.into(),
        },
        terminal: TerminalAcknowledgement::WorkerResult { result },
    }
}
async fn count(s: &Store) -> i64 {
    sqlx::query_scalar("SELECT count(DISTINCT attempt_id) FROM resource_allocations WHERE dimension='active_slot' AND state<>'RELEASED'")
        .fetch_one(s.pool()).await.unwrap()
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn queue_projection_reconciles_idle_resources_stale_proposals_and_admission_replay() {
    let (s, schema, admin) = setup().await;
    let idle_root = format!("/tmp/{schema}/a-idle");
    let root = format!("/tmp/{schema}/p");
    let idle = fixture(&s, "a-idle", &idle_root, false).await;
    let tasks = fixture(&s, "p", &root, false).await;
    let predecessor = s
        .admit(request(&idle[0], "idle-allocation"))
        .await
        .unwrap()
        .attempt;
    let queue_revision = enqueue(&s, &tasks[1], 0, "").await;
    let projects = vec!["a-idle".to_owned(), "p".to_owned()];
    let queued = read_projection::queued(s.pool(), &projects).await.unwrap();
    assert_eq!(queued.keys().cloned().collect::<Vec<_>>(), vec!["p"]);
    let task_ids = read_projection::task_ids(&queued["p"]);
    let selected_tasks = read_projection::tasks(s.pool(), "p", &task_ids)
        .await
        .unwrap();
    assert_eq!(selected_tasks.len(), 1);
    assert_eq!(selected_tasks[0].task_id, "t1");
    let states = read_projection::attempts(s.pool(), "p", &task_ids)
        .await
        .unwrap();
    assert!(states.is_empty());
    let writes = read_projection::active_writes(s.pool(), &projects)
        .await
        .unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].project_id, "a-idle");
    let (committed, flows) = read_projection::flows(s.pool(), "p", &selected_tasks)
        .await
        .unwrap();
    assert_eq!(committed, Some(1));
    assert_eq!(flows.len(), 1);

    // Compare the same persisted workload, before either pump mutates it. Count
    // actual projection SELECTs and returned JSON bytes, excluding unchanged
    // leader/clock/resource reads and Store's authoritative validation queries.
    let json_bytes = |values: &[Value]| {
        values
            .iter()
            .map(|v| serde_json::to_vec(v).unwrap().len())
            .sum::<usize>()
    };
    let mut old_statements = 0;
    let mut old_bytes = 0;
    for project in &projects {
        for query in [
            "SELECT data FROM tasks WHERE project_id=$1 ORDER BY task_id",
            "SELECT data FROM attempts WHERE project_id=$1 ORDER BY created_at,attempt_id",
            "SELECT data FROM flow_revisions WHERE project_id=$1 ORDER BY flow_revision",
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
            "SELECT envelope FROM attempts WHERE project_id=$1 AND terminal_at IS NULL ORDER BY attempt_id",
            "SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='queue_entries' AND data->>'status'='QUEUED' ORDER BY document_id",
            "SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id='1'",
        ] {
            let values: Vec<Value> = sqlx::query_scalar(query)
                .bind(project)
                .fetch_all(s.pool())
                .await
                .unwrap();
            old_statements += 1;
            old_bytes += json_bytes(&values);
        }
    }
    let mut new_statements = 0;
    let mut new_bytes = 0;
    let rows = sqlx::query(read_projection::QUEUED_SQL)
        .bind(&projects)
        .fetch_all(s.pool())
        .await
        .unwrap();
    new_statements += 1;
    new_bytes += json_bytes(
        &rows
            .into_iter()
            .map(|r| r.get("data"))
            .collect::<Vec<Value>>(),
    );
    let values: Vec<Value> = sqlx::query_scalar(read_projection::ACTIVE_WRITES_SQL)
        .bind(&projects)
        .fetch_all(s.pool())
        .await
        .unwrap();
    new_statements += 1;
    new_bytes += json_bytes(&values);
    for query in [read_projection::TASKS_SQL, read_projection::ATTEMPTS_SQL] {
        let values: Vec<Value> = sqlx::query_scalar(query)
            .bind("p")
            .bind(&task_ids)
            .fetch_all(s.pool())
            .await
            .unwrap();
        new_statements += 1;
        new_bytes += json_bytes(&values);
    }
    let flow_row = sqlx::query(read_projection::FLOWS_SQL)
        .bind("p")
        .bind(vec![1_i64])
        .fetch_one(s.pool())
        .await
        .unwrap();
    new_statements += 1;
    new_bytes += serde_json::to_vec(&flow_row.get::<Value, _>("flows"))
        .unwrap()
        .len();
    new_bytes += serde_json::to_vec(&flow_row.get::<Option<i64>, _>("latest_committed"))
        .unwrap()
        .len();
    for query in [
        "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
        "SELECT data || jsonb_build_object('revision',revision) FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id='1'",
    ] {
        let values: Vec<Value> = sqlx::query_scalar(query)
            .bind("p")
            .fetch_all(s.pool())
            .await
            .unwrap();
        new_statements += 1;
        new_bytes += json_bytes(&values);
    }
    println!(
        "{}",
        json!({"scope":"same workload snapshot projection reads only; not total pump or capacity qualification", "projects":2,"tasks":12,"queued":1,"old_statements":old_statements,"new_statements":new_statements,"old_json_bytes":old_bytes,"new_json_bytes":new_bytes})
    );
    assert_eq!((old_statements, new_statements), (14, 7));
    assert!(
        new_bytes * 2 < old_bytes,
        "actual returned JSON should shrink by more than half"
    );

    // An idle project's held allocation must still block the queued project.
    let first = pump_once(&s).await.unwrap();
    assert!(first.admitted.is_empty());
    assert!(
        first
            .decision
            .blocked
            .iter()
            .any(|reason| reason.code == "CAPACITY_EXHAUSTED"
                && reason.scope_id.as_deref() == Some("global"))
    );
    assert!(
        s.get_document("a-idle", "operations", "scheduler-state")
            .await
            .is_ok(),
        "the first active project remains the anchor even when it has no queue"
    );
    assert!(
        s.get_document("p", "operations", "scheduler-state")
            .await
            .is_err()
    );

    // A deliberately corrupt idle context is not scheduling input. No stale
    // cache can hide the same corruption when it belongs to a queued project.
    sqlx::query("UPDATE documents SET data='\"invalid context fault fixture\"'::jsonb WHERE project_id='a-idle' AND collection='flow_contexts'").execute(s.pool()).await.unwrap();
    assert!(pump_once(&s).await.unwrap().admitted.is_empty());
    let context: Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id='p' AND collection='flow_contexts' AND document_id='1'").fetch_one(s.pool()).await.unwrap();
    sqlx::query("UPDATE documents SET data='\"invalid context fault fixture\"'::jsonb WHERE project_id='p' AND collection='flow_contexts'").execute(s.pool()).await.unwrap();
    assert!(
        pump_once(&s).await.is_err(),
        "queued context corruption must fail closed immediately"
    );
    sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='flow_contexts' AND document_id='1'").bind(context).execute(s.pool()).await.unwrap();
    s.worker_result(failed_author(&s, &predecessor, &idle_root).await)
        .await
        .unwrap();
    assert_eq!(count(&s).await, 0);

    // Reproduce the actual admission/projection crash window with Store, then
    // let the pump repair QUEUED -> DISPATCHED without a second Attempt/lease.
    let mut admission = request(&tasks[1], &format!("schedule:p:t1:1:{queue_revision}"));
    admission.actor_id = "scheduler-service".into();
    let committed = s.admit(admission).await.unwrap();
    let repaired = pump_once(&s).await.unwrap();
    assert!(repaired.admitted.is_empty());
    assert_eq!(
        s.get_document("p", "queue_entries", "t1").await.unwrap()["attempt_id"],
        committed.attempt.attempt_id
    );
    assert_eq!(s.list_attempts("p").await.unwrap().len(), 1);
    let projected = read_projection::attempts(s.pool(), "p", &task_ids)
        .await
        .unwrap();
    assert_eq!(projected.len(), 1);
    assert_eq!(projected[0].task_id, "t1");
    assert_eq!(projected[0].task_revision, 1);
    assert!(!projected[0].state.is_terminal());

    enqueue(&s, &tasks[2], 0, "").await;
    sqlx::query("UPDATE documents SET data=jsonb_set(data,'{task_revision}','2'::jsonb) WHERE project_id='p' AND collection='queue_entries' AND document_id='t2'").execute(s.pool()).await.unwrap();
    let stale = pump_once(&s).await.unwrap();
    assert!(
        stale
            .admission_rejected
            .iter()
            .any(|reason| reason.task_id == "t2" && reason.code == "REVISION_CONFLICT")
    );
    assert!(stale.admitted.is_empty());
    assert_eq!(count(&s).await, 1);
    cleanup(s, schema.clone(), admin).await;
    std::fs::remove_dir_all(format!("/tmp/{schema}")).unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn actual_handoffs_reuse_aging_skip_blocked_heads_and_persist_cross_project_fairness() {
    let (s, schema, admin) = setup().await;
    let root_p = format!("/tmp/{schema}/p");
    let root_q = format!("/tmp/{schema}/q");
    let p = fixture(&s, "p", &root_p, false).await;
    let q = fixture(&s, "q", &root_q, false).await;
    let predecessor = s
        .admit(request(&p[0], "predecessor"))
        .await
        .unwrap()
        .attempt;
    enqueue(&s, &p[1], 100, "missing-worker").await;
    enqueue(&s, &p[2], 0, "").await;
    let aged_revision = age_queue(&s, "p", "t2").await;
    enqueue(&s, &p[3], 5, "").await;
    enqueue(&s, &q[1], 0, "").await;
    let selector = StoreHandoffScheduler::new(PumpConfig {
        candidate_window: 3,
        maximum_selections: 16,
        ..Default::default()
    })
    .unwrap();
    let result = failed_author(&s, &predecessor, &root_p).await;
    // Every dimension is saturated before Store releases the predecessor.
    let mut tx = s.pool().begin().await.unwrap();
    assert!(
        selector
            .select(&mut tx, &predecessor)
            .await
            .unwrap()
            .is_none()
    );
    tx.rollback().await.unwrap();
    let first_request = handoff(result, "selector-first");
    let first = s
        .terminal_handoff(first_request.clone(), &selector)
        .await
        .unwrap();
    assert_eq!(first.replacement.attempt.project_id, "p");
    assert_eq!(
        first.replacement.attempt.task_id, "t2",
        "aging must outrank the younger priority-5 task after skipping the blocked head"
    );
    assert_eq!(first.replacement.attempt.worker_id, "p-w");
    assert_eq!(count(&s).await, 1);
    assert_eq!(
        first.evidence["allocated_before"],
        first.evidence["allocated_after"]
    );
    let state = s
        .get_document("p", "operations", "scheduler-state")
        .await
        .unwrap();
    assert_eq!(state["cursor"]["project_index"], 1);
    assert_eq!(state["scanned"], 2);
    assert!(
        state["blocked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason["task_id"] == "t1")
    );
    let queue = s.get_document("p", "queue_entries", "t2").await.unwrap();
    assert_eq!(queue["revision"], aged_revision + 1);
    assert_eq!(queue["status"], "DISPATCHED");
    assert_eq!(queue["worker_id"], "p-w");
    assert_eq!(queue["worker_scope_id"], "worker:p-w");
    let replay = s.terminal_handoff(first_request, &selector).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(
        replay.replacement.attempt.attempt_id,
        first.replacement.attempt.attempt_id
    );
    assert_eq!(
        state,
        s.get_document("p", "operations", "scheduler-state")
            .await
            .unwrap()
    );
    let result = failed_author(&s, &first.replacement.attempt, &root_p).await;
    let second = s
        .terminal_handoff(handoff(result, "selector-second"), &selector)
        .await
        .unwrap();
    assert_eq!(
        second.replacement.attempt.project_id, "q",
        "persisted project rotation must give q its next turn"
    );
    assert_eq!(second.replacement.attempt.task_id, "t1");
    assert_eq!(second.replacement.attempt.worker_id, "q-w");
    assert_eq!(count(&s).await, 1);
    assert_eq!(
        s.get_document("p", "operations", "scheduler-state")
            .await
            .unwrap()["revision"],
        2
    );
    assert_eq!(
        s.get_document("p", "queue_entries", "t3").await.unwrap()["status"],
        "QUEUED"
    );
    cleanup(s, schema.clone(), admin).await;
    std::fs::remove_dir_all(format!("/tmp/{schema}")).unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn every_resource_dimension_is_read_from_the_supplied_transaction() {
    let (s, schema, admin) = setup().await;
    let root = format!("/tmp/{schema}/p");
    let tasks = fixture(&s, "p", &root, false).await;
    let predecessor = s
        .admit(request(&tasks[0], "predecessor"))
        .await
        .unwrap()
        .attempt;
    enqueue(&s, &tasks[1], 0, "").await;
    let selector = StoreHandoffScheduler::default();
    // Transaction-local fault fixtures deliberately roll back; they do not
    // manufacture terminal evidence or commit mismatched allocation ledgers.
    for dimension in [
        "active_slot",
        "coding_slot",
        "cpu_units",
        "memory_bytes",
        "build_permit",
        "gpu_permit",
        "provider_inflight",
    ] {
        let mut tx = s.pool().begin().await.unwrap();
        sqlx::query("UPDATE resource_limits SET allocated=0")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE resource_limits SET allocated=1 WHERE scope_id='global' AND dimension=$1",
        )
        .bind(dimension)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(
            selector
                .select(&mut tx, &predecessor)
                .await
                .unwrap()
                .is_none(),
            "{dimension} must block the complete requested vector"
        );
        sqlx::query(
            "UPDATE resource_limits SET allocated=0 WHERE scope_id='global' AND dimension=$1",
        )
        .bind(dimension)
        .execute(&mut *tx)
        .await
        .unwrap();
        let selected = selector
            .select(&mut tx, &predecessor)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.admission.task_id, "t1");
        let observer: i64 = sqlx::query_scalar(
            "SELECT allocated FROM resource_limits WHERE scope_id='global' AND dimension=$1",
        )
        .bind(dimension)
        .fetch_one(s.pool())
        .await
        .unwrap();
        assert_eq!(
            observer, 1,
            "selector must use its uncommitted snapshot while other connections retain predecessor allocations"
        );
        tx.rollback().await.unwrap();
    }
    assert_eq!(count(&s).await, 1);
    assert_eq!(
        s.get_document("p", "queue_entries", "t1").await.unwrap()["status"],
        "QUEUED"
    );
    assert!(
        s.get_document("p", "operations", "scheduler-state")
            .await
            .is_err()
    );
    cleanup(s, schema.clone(), admin).await;
    std::fs::remove_dir_all(format!("/tmp/{schema}")).unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn typed_dependency_readiness_observes_only_the_supplied_transaction() {
    let (s, schema, admin) = setup().await;
    let root = format!("/tmp/{schema}/p");
    let tasks = fixture(&s, "p", &root, true).await;
    let predecessor = s
        .admit(request(&tasks[0], "predecessor"))
        .await
        .unwrap()
        .attempt;
    enqueue(&s, &tasks[2], 0, "").await;
    let queued = read_projection::queued(s.pool(), &["p".into()])
        .await
        .unwrap();
    let scoped = read_projection::tasks(s.pool(), "p", &read_projection::task_ids(&queued["p"]))
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].task_id, "t2");
    assert_eq!(scoped[0].dependencies, vec!["t0"]);
    // t0 is deliberately outside the Task/Attempt read projection. Its typed
    // Gate predicate must still be resolved by Store in the supplied transaction.
    let selector = StoreHandoffScheduler::default();
    let mut tx = s.pool().begin().await.unwrap();
    sqlx::query("UPDATE resource_limits SET allocated=0")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        selector
            .select(&mut tx, &predecessor)
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("INSERT INTO gate_runs(project_id,gate_run_id,status,data) VALUES('p','predecessor-gate','PASS',$1)")
        .bind(json!({"task_id":"t0","fixture_scope":"transaction-local typed-dependency selector test"}))
        .execute(&mut *tx).await.unwrap();
    let selected = selector
        .select(&mut tx, &predecessor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.admission.task_id, "t2");
    assert!(!s.dependency_ready("p", 1, "t2", "t0").await.unwrap());
    tx.rollback().await.unwrap();
    assert!(!s.dependency_ready("p", 1, "t2", "t0").await.unwrap());
    cleanup(s, schema.clone(), admin).await;
    std::fs::remove_dir_all(format!("/tmp/{schema}")).unwrap();
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn ordinary_pump_resolves_a_nonqueued_predecessor_from_postgres_receipts() {
    let (s, schema, admin) = setup().await;
    let root = format!("/tmp/{schema}/p");
    let tasks = fixture(&s, "p", &root, true).await;
    enqueue(&s, &tasks[2], 0, "").await;
    let blocked = pump_once(&s).await.unwrap();
    assert!(blocked.admitted.is_empty());
    assert!(
        blocked
            .decision
            .blocked
            .iter()
            .any(|reason| reason.task_id == "t2" && reason.code == "DEPENDENCY_EVIDENCE")
    );
    // This is an isolated receipt-predicate fixture, not a claim that a real
    // producer/product Gate ran. The pump and Store must independently read it.
    sqlx::query("INSERT INTO gate_runs(project_id,gate_run_id,status,data) VALUES('p','predecessor-gate','PASS',$1)")
        .bind(json!({"task_id":"t0","fixture_scope":"isolated scheduler typed dependency predicate; not product Gate evidence"}))
        .execute(s.pool()).await.unwrap();
    let admitted = pump_once(&s).await.unwrap();
    assert_eq!(admitted.admitted.len(), 1);
    assert_eq!(admitted.admitted[0].attempt.task_id, "t2");
    assert!(
        s.list_attempts("p")
            .await
            .unwrap()
            .iter()
            .all(|attempt| attempt.task_id != "t0")
    );
    assert!(s.get_document("p", "queue_entries", "t0").await.is_err());
    assert_eq!(
        s.get_document("p", "queue_entries", "t2").await.unwrap()["status"],
        "DISPATCHED"
    );
    cleanup(s, schema.clone(), admin).await;
    std::fs::remove_dir_all(format!("/tmp/{schema}")).unwrap();
}

fn pool_code(error: &forgeflow_store::StoreError) -> &str {
    match error {
        forgeflow_store::StoreError::Domain(error) => &error.code,
        _ => "UNEXPECTED_NON_DOMAIN_ERROR",
    }
}
async fn selector_pool_policy(s: &Store, predecessor: &Attempt) -> Value {
    let snapshot = s.snapshot(&predecessor.project_id).await.unwrap();
    let now = chrono::Utc::now();
    let request = json!({
        "starts_at": (now - chrono::Duration::seconds(1)).to_rfc3339(),
        "ends_at": (now + chrono::Duration::hours(1)).to_rfc3339(),
        "target_channels": 1,
        "worker_id": predecessor.worker_id,
        "resource_profile_id": "resource",
        "controlled_only": true,
        "launch_grace_ms": 2000,
        "baseline_attempt_ids": [predecessor.attempt_id],
    });
    json!({
        "schema_version": "forgeflow.channel_pool.v1",
        "project_id": predecessor.project_id,
        "status": "ACTIVE",
        "starts_at": request["starts_at"],
        "ends_at": request["ends_at"],
        "target_channels": 1,
        "worker_id": predecessor.worker_id,
        "resource_profile_id": "resource",
        "executor_profile_id": "controlled-lightweight.v1",
        "controlled_only": true,
        "launch_grace_ms": 2000,
        "known_baseline_proof": {
            "attempt_ids": [predecessor.attempt_id],
            "snapshot_revision": snapshot["revision"],
            "observed_at": snapshot["as_of"],
            "snapshot_sha256": forgeflow_planner::sha256(&serde_json::to_vec(&snapshot).unwrap()),
        },
        "authorized_by": "owner",
        "authorized_at": now.to_rfc3339(),
        "activation_identity": {"actor_id":"owner","idempotency_key":"selector-policy-fixture"},
        "activation_request_sha256": forgeflow_planner::sha256(&serde_json::to_vec(&request).unwrap()),
        "drain_authorized_by": null,
        "drain_authorized_at": null,
        "drain_reason": null,
        "drain_identity": null,
        "drain_request_sha256": null,
        "ended_by": null,
        "ended_at": null,
        "end_reason": null,
        "end_identity": null,
        "end_request_sha256": null,
    })
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn strict_pool_filters_workers_profiles_and_projects_and_rejects_inactive_or_stale_policy() {
    let (s, schema, admin) = setup().await;
    let root_p = format!("/tmp/{schema}/p");
    let root_q = format!("/tmp/{schema}/q");
    let p = fixture_with_profiles(&s, "p", &root_p, false, true).await;
    let q = fixture_with_profiles(&s, "q", &root_q, false, true).await;
    // A fresh capable worker sorts ahead of p-w. A strict blank proposal must
    // still resolve to its explicitly configured p-w worker.
    s.register_worker(WorkerRegisterRequest {
        project_id: Some("p".into()),
        executor_profile_ids: vec!["controlled-lightweight.v1".into()],
        worker_id: "p-a".into(),
        boot_id: "selector-alternate-worker".into(),
        capabilities: vec!["CONTROLLED_LIGHTWEIGHT".into()],
    })
    .await
    .unwrap();
    let mut limits = vector(1);
    limits.provider_inflight = 0;
    s.put_resource_policy(
        ResourcePolicy {
            scope_id: "worker:p-a".into(),
            parent_scope_id: Some("global".into()),
            project_id: None,
            team_id: None,
            worker_id: Some("p-a".into()),
            limits,
            revision: 1,
            paused: false,
        },
        None,
    )
    .await
    .unwrap();
    let predecessor = s
        .admit(request(&p[0], "strict-selector-predecessor"))
        .await
        .unwrap()
        .attempt;
    let _actual_stopped_author = failed_author(&s, &predecessor, &root_p).await;
    enqueue(&s, &p[1], 300, "").await; // different frozen resource profile
    enqueue(&s, &p[2], 200, "p-a").await; // capable, different worker
    enqueue(&s, &p[3], 10, "").await; // actual pool member proposal
    enqueue(&s, &p[4], 400, "").await; // different frozen executor
    enqueue(&s, &p[5], 500, "").await; // nonzero model budget/resources
    enqueue(&s, &q[3], 9999, "").await; // another managed project
    let selector =
        StoreHandoffScheduler::for_strict_pool(PumpConfig::default(), "p".into()).unwrap();
    let policy = selector_pool_policy(&s, &predecessor).await;
    let mut tx = s.pool().begin().await.unwrap();
    assert_eq!(
        pool_code(&selector.select(&mut tx, &predecessor).await.unwrap_err()),
        "CHANNEL_POOL_MISSING"
    );
    // One real allocated baseline is the truthful selector test denominator.
    // Policy and capacity faults stay in this transaction and are rolled back;
    // this is no strict-128 activation or sustained-channel qualification.
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES('p','channel_pools','strict-controlled',1,$1)")
        .bind(&policy).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE resource_limits SET allocated=0")
        .execute(&mut *tx)
        .await
        .unwrap();
    let selected = selector
        .select(&mut tx, &predecessor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.admission.project_id, "p");
    assert_eq!(selected.admission.task_id, "t3");
    assert_eq!(selected.admission.worker_id, "p-w");
    assert_eq!(
        selected.admission.envelope.executor_profile_id,
        "controlled-lightweight.v1"
    );
    assert_eq!(selected.admission.envelope.max_model_requests, 0);
    let excluded = selected.scheduler_state["admission_rejected"]
        .as_array()
        .unwrap();
    for task in ["t1", "t2", "t4", "t5"] {
        assert!(
            excluded
                .iter()
                .any(|reason| reason["task_id"] == task
                    && reason["code"] == "CHANNEL_POOL_CANDIDATE")
        );
    }
    assert!(
        s.get_document("p", "channel_pools", "strict-controlled")
            .await
            .is_err(),
        "selector must see transaction-local policy while an observer still sees absence"
    );
    assert_eq!(
        s.get_document("p", "queue_entries", "t3").await.unwrap()["worker_id"],
        ""
    );
    for status in ["DRAINING", "ENDED"] {
        let mut inactive = policy.clone();
        inactive["status"] = json!(status);
        sqlx::query(
            "UPDATE documents SET data=$1 WHERE project_id='p' AND collection='channel_pools'",
        )
        .bind(inactive)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert_eq!(
            pool_code(&selector.select(&mut tx, &predecessor).await.unwrap_err()),
            "CHANNEL_POOL_DRAINING"
        );
    }
    let mut expired = policy.clone();
    expired["starts_at"] = json!((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339());
    expired["ends_at"] = json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
    sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='channel_pools'")
        .bind(expired)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        pool_code(&selector.select(&mut tx, &predecessor).await.unwrap_err()),
        "CHANNEL_POOL_WINDOW"
    );
    let mut ambiguous_utc = policy.clone();
    ambiguous_utc["ends_at"] = json!(
        policy["ends_at"]
            .as_str()
            .unwrap()
            .replace("+00:00", "-00:00")
    );
    sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='channel_pools'")
        .bind(ambiguous_utc)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        pool_code(&selector.select(&mut tx, &predecessor).await.unwrap_err()),
        "CHANNEL_POOL_INVALID"
    );
    let mut stale_worker = policy.clone();
    stale_worker["worker_id"] = json!("p-a");
    sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='channel_pools'")
        .bind(stale_worker)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        pool_code(&selector.select(&mut tx, &predecessor).await.unwrap_err()),
        "CHANNEL_POOL_MEMBERSHIP"
    );
    let mut changed_lineage = policy.clone();
    changed_lineage["known_baseline_proof"]["attempt_ids"] = json!([p[3].task_id]);
    sqlx::query("UPDATE documents SET data=$1 WHERE project_id='p' AND collection='channel_pools'")
        .bind(changed_lineage)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        pool_code(&selector.select(&mut tx, &predecessor).await.unwrap_err()),
        "CHANNEL_POOL_MEMBERSHIP"
    );
    tx.rollback().await.unwrap();
    assert_eq!(count(&s).await, 1);
    assert!(
        s.get_document("p", "channel_pools", "strict-controlled")
            .await
            .is_err()
    );
    cleanup(s, schema.clone(), admin).await;
    std::fs::remove_dir_all(format!("/tmp/{schema}")).unwrap();
}
