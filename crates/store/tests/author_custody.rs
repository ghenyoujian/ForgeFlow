//! Focused real PostgreSQL author/custody transaction regression.
//! Synthetic trusted Worker DTOs qualify ledger guards only, never OS or model execution.
use forgeflow_domain::*;
use forgeflow_planner::{CompileContext, OwnerTerritory, TaskSpec};
use forgeflow_store::{Store, StoreError};
use serde_json::Value;
use serde_json::json;
use sqlx::{Row, postgres::PgPoolOptions};

async fn setup() -> (Store, String, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL required for PostgreSQL authority tests");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("custody_test_{}", uuid::Uuid::new_v4().simple());
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
    serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":"preflight","project_id":"p","task_id":task,"task_revision":1,"attempt_id":"preflight","lease_id":"preflight","generation":1,"worker_id":"w","workspace_root":"/tmp/forgeflow-test","base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[format!("src/{task}.rs")],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":format!("verify-{task}"),"allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS","REQUEST_APPROVED_MODEL"],"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:01:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":"/tmp/forgeflow-test/artifacts","secret_refs":[],"idempotency_key":"preflight","trace_id":"test","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null})).unwrap()
}
async fn fixture(s: &Store, physical: bool) -> Vec<TaskCard> {
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
    for (team, parent) in [
        ("owner", None),
        ("level1", Some("owner")),
        ("level2", Some("level1")),
        ("leaf", Some("level2")),
    ] {
        s.create_team(Team {
            project_id: "p".into(),
            team_id: team.into(),
            parent_team_id: parent.map(str::to_owned),
            name: team.into(),
            paused: false,
            revision: 1,
        })
        .await
        .unwrap();
    }
    s.register_worker(WorkerRegisterRequest {
        project_id: Some("p".into()),
        executor_profile_ids: vec!["exec".into()],
        worker_id: "w".into(),
        boot_id: "boot1".into(),
        capabilities: vec!["exec".into()],
    })
    .await
    .unwrap();
    let limit = root_vector().checked_pool(&child_vector(), 2).unwrap();
    let limit = limit.checked_pool(&limit, 1).unwrap();
    for (scope, p, team, worker, parent) in [
        ("global", None, None, None, None),
        ("project", Some("p"), None, None, Some("global")),
        ("team", Some("p"), Some("owner"), None, Some("project")),
        ("level1", Some("p"), Some("level1"), None, Some("team")),
        ("level2", Some("p"), Some("level2"), None, Some("level1")),
        ("leaf", Some("p"), Some("leaf"), None, Some("level2")),
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
            "exec",
            json!({"id":"exec","program":"/usr/bin/true","prefix_args":[],"home":"/tmp/forgeflow-test/home","profile_name":"authority-test-only","artifact_pins":[{"path":"/usr/bin/true","sha256":true_hash}],"resume_verified":false,"model_route_id":"route","gateway_coverage_verified":false}),
        ),
        (
            "resource_profiles",
            "resource",
            if physical {
                json!({"id":"resource","qualification":"PG_LEDGER_ONLY","physical_limits":physical_policy(),"native_child_policy":native_policy()})
            } else {
                json!({"id":"resource","qualification":"PG_LEDGER_ONLY_LEGACY","native_child_policy":native_policy()})
            },
        ),
        (
            "model_routes",
            "route",
            json!({"id":"route","provider":"deepseek","model":"deepseek-chat","max_output_tokens":128,"qualification":"NO_UPSTREAM_MODEL_CALLS"}),
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
    for n in 0..2 {
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
            execution_profile: "exec".into(),
            verification_plan: format!("verify-{task_id}"),
            verification_case_count: 2,
            rollback_plan: "preserve then retry new attempt".into(),
            known_unknowns: vec![],
            not_proven: vec![],
            isolated_contract_probe: false,
        };
        let mut task = TaskCard {
            project_id: "p".into(),
            task_id: task_id.clone(),
            task_revision: 1,
            flow_revision: 1,
            title: task_id.clone(),
            owner_id: "owner".into(),
            team_id: "leaf".into(),
            requirement_ids: vec!["r".into()],
            read_set: vec![],
            write_set: vec![format!("src/{task_id}.rs")],
            dependencies: vec![],
            state: TaskPlanningState::ReadyForAdmission,
            input_digest: String::new(),
            resource_request: root_vector(),
            envelope: Some(envelope(&task_id)),
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

fn root_vector() -> ResourceVector {
    ResourceVector {
        active_slot: 1,
        coding_slot: 1,
        cpu_units: 250,
        memory_bytes: 64 * 1024 * 1024,
        build_permit: 1,
        gpu_permit: 1,
        provider_inflight: 1,
    }
}
fn child_vector() -> ResourceVector {
    ResourceVector {
        active_slot: 1,
        coding_slot: 1,
        cpu_units: 250,
        memory_bytes: 16 * 1024 * 1024,
        build_permit: 1,
        gpu_permit: 1,
        provider_inflight: 1,
    }
}
fn physical_policy() -> PhysicalLimitsPolicy {
    PhysicalLimitsPolicy {
        schema_version: "forgeflow.physical-limits.v1".into(),
        required: true,
        cpu_units_per_cpu: 1000,
        period_us: 100000,
        pids_max: 32,
        swap_max_bytes: 0,
        memory_oom_group: true,
    }
}
fn native_policy() -> Value {
    json!({"schema_version":"forgeflow.native-child-policy.v1","enabled":true,"max_live_agents":3,"max_lifecycles":20,"max_delegation_depth":2,"model_inflight_limit":3,"child_resources":child_vector()})
}
fn rpc(a: &Attempt, operation: &str, fields: Value) -> Value {
    let mut raw = json!({"schema_version":"forgeflow.dsh-bridge.v2","rpc_id":uuid::Uuid::new_v4(),"operation":operation,"project_id":a.project_id,"task_id":a.task_id,"attempt_id":a.attempt_id,"generation":a.generation});
    raw.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    raw
}
fn native_admit(a: &Attempt, session: &str, parent: Option<&str>) -> Value {
    rpc(
        a,
        "admit",
        json!({"native_session_id":session,"parent_session_id":parent,"source":"startup","delegation_depth":u32::from(parent.is_some()),"origin":null,"agent_options":{"provider":null,"model":null}}),
    )
}
fn native_release(a: &Attempt, session: &str, allocation: &Value) -> Value {
    rpc(
        a,
        "release",
        json!({"native_session_id":session,"allocation_id":allocation,"reason":"native_disposed"}),
    )
}
// Synthetic *trusted Worker DTO* fixture, never an actual PID/cgroup claim.
fn trusted_stop_dto(a: &Attempt, pool: &PhysicalResourceBinding) -> Value {
    let execution = uuid::Uuid::new_v4().to_string();
    let boot = uuid::Uuid::new_v4().to_string();
    let intent = json!({"execution_id":execution,"operation_id":a.operation_id,"attempt_id":a.attempt_id,"generation":a.generation,"worker_id":a.worker_id,"boot_id":boot});
    let mut fence = json!({"schema_version":"forgeflow.cgroup-fence.v1","project_id":a.project_id,"attempt_id":a.attempt_id,"generation":a.generation,"execution_id":execution,"boot_id":boot,"owner_uid":1000,"delegation":{"unit_name":"forgeflow-worker-pg-fixture.service","root_path":"/sys/fs/cgroup/fixture/forgeflow-worker-pg-fixture.service"},"mount_id":10,"mount_path":"/sys/fs/cgroup","mount_device":20,"root_inode":30,"leaf_path":"/sys/fs/cgroup/fixture/attempt","leaf_inode":40,"limits":{"cpu_quota_us":pool.cpu_quota_us,"cpu_period_us":pool.physical_limits.period_us,"memory_max_bytes":pool.memory_max_bytes,"memory_swap_max_bytes":0,"pids_max":pool.physical_limits.pids_max,"memory_oom_group":true},"resource_binding_sha256":pool.reservation_sha256});
    let hash = forgeflow_evidence::sha256(&serde_json::to_vec(&fence).unwrap());
    fence["identity_sha256"] = hash.clone().into();
    json!({"scope":"TRUSTED_WORKER_DTO_AUTHORITY_FIXTURE_NO_OS_LAUNCH","execution_id":execution,"process_exit_confirmed":true,"launch_receipt":{"execution_id":execution,"intent":intent,"process":{"pid":123,"pgid":123,"start_ticks":456,"boot_id":boot,"attempt_id":a.attempt_id}},"physical_fence":fence,"physical_stop":{"schema_version":"forgeflow.cgroup-stop.v1","identity_sha256":hash,"boot_id":boot,"leaf_inode":40,"observed_at":chrono::Utc::now(),"populated":false,"process_exit_confirmed":true,"snapshot":{"cgroup.events":"populated 0\nfrozen 0","cgroup.procs":""}}})
}

async fn charged_snapshot(store: &Store) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('allocations',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY allocation_id) FROM resource_allocations r),'[]'::jsonb),'limits',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY scope_id,dimension) FROM resource_limits r),'[]'::jsonb),'native_allocations',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY resource_allocation_id) FROM native_child_allocations r),'[]'::jsonb),'models',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY request_id) FROM native_model_requests r),'[]'::jsonb),'permits',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY request_id) FROM model_request_permit r),'[]'::jsonb),'gateway',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY attempt_id,route_id) FROM gateway_scope_budget r),'[]'::jsonb))")
        .fetch_one(store.pool()).await.unwrap()
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn actual_postgres_author_closure_keeps_unknown_custody_and_retries_same_task() {
    let (store, schema, admin) = setup().await;
    let tasks = fixture(&store, true).await;
    let first = store
        .admit(request(&tasks[0], "first-attempt"))
        .await
        .unwrap();
    let env = store.claim("w", "p").await.unwrap().unwrap();
    let pool: PhysicalResourceBinding = serde_json::from_value(
        sqlx::query_scalar::<_, Value>(
            "SELECT execution_bindings->'physical_resources' FROM attempts WHERE attempt_id=$1",
        )
        .bind(&env.attempt_id)
        .fetch_one(store.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    let mut evidence = trusted_stop_dto(&first.attempt, &pool);
    evidence["stop"] = json!({"process_exit_confirmed":true});
    store
        .record_worker_event(WorkerEvent {
            event_id: "custody-running".into(),
            project_id: "p".into(),
            attempt_id: env.attempt_id.clone(),
            lease_id: env.lease_id.clone(),
            generation: env.generation,
            worker_id: "w".into(),
            kind: "RUNNING".into(),
            payload: evidence["launch_receipt"].clone(),
        })
        .await
        .unwrap();
    let active = store.get_attempt("p", &env.attempt_id).await.unwrap();
    let root = store
        .collaboration_rpc("w", native_admit(&active, "custody-native-root", None))
        .await
        .unwrap();
    let model = rpc(
        &active,
        "model_request",
        json!({"native_session_id":"custody-native-root","allocation_id":root["allocation_id"],
        "request_id":uuid::Uuid::new_v4(),"provider":"deepseek","model":"deepseek-chat","max_output_tokens":128,"purpose":"conversation"}),
    );
    let grant = store.collaboration_rpc("w", model.clone()).await.unwrap();
    store.collaboration_rpc("w", rpc(&active, "model_settle", json!({"native_session_id":"custody-native-root","allocation_id":root["allocation_id"],
        "request_id":model["request_id"],"request_grant_id":grant["request_grant_id"],"usage":null,"usage_complete":false,"finish_reason":"abandoned"}))).await.unwrap();
    store
        .cancel(CancelRequest {
            actor_id: "owner".into(),
            idempotency_key: "cancel-first".into(),
            project_id: "p".into(),
            attempt_id: env.attempt_id.clone(),
            expected_revision: active.revision,
            reason: "retain unknown model custody".into(),
        })
        .await
        .unwrap();
    let stopping = store.get_attempt("p", &env.attempt_id).await.unwrap();
    let execution_id = evidence["execution_id"].as_str().unwrap().to_owned();
    let original = WorkerResult {
        event_id: "custody-result".into(),
        project_id: "p".into(),
        attempt_id: env.attempt_id.clone(),
        lease_id: env.lease_id.clone(),
        generation: env.generation,
        worker_id: "w".into(),
        evidence,
        outcome: ExecutorOutcome {
            execution_id,
            upstream_session_id: None,
            exit_code: Some(1),
            completion_reason: "PROCESS_FAILED".into(),
            raw_event_digest: String::new(),
            transcript_completeness: "AUTHORITY_FIXTURE_ONLY".into(),
            final_artifact: None,
            error_class: Some("MODEL_UNKNOWN".into()),
        },
    };
    let original_bytes = serde_json::to_vec(&original).unwrap();
    let charged = charged_snapshot(&store).await;
    assert_eq!(charged["models"][0]["status"], "QUARANTINED");
    assert!(charged["models"][0]["usage"].is_null());
    let mut bad = original.clone();
    bad.evidence["physical_stop"]["populated"] = true.into();
    assert_eq!(
        code(&store.record_author_stop_observation(bad).await.unwrap_err()),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    let mut bad = original.clone();
    bad.worker_id = "foreign-worker".into();
    assert_eq!(
        code(&store.record_author_stop_observation(bad).await.unwrap_err()),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    let mut bad = original.clone();
    bad.generation += 1;
    assert_eq!(
        code(&store.record_author_stop_observation(bad).await.unwrap_err()),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    assert_eq!(charged_snapshot(&store).await, charged);
    let observation = store
        .record_author_stop_observation(original.clone())
        .await
        .unwrap();
    assert_eq!(
        store
            .record_author_stop_observation(original.clone())
            .await
            .unwrap()["replayed"],
        true
    );
    let mut changed_observation = original.clone();
    changed_observation.outcome.error_class = Some("changed historical cause".into());
    assert_eq!(
        code(
            &store
                .record_author_stop_observation(changed_observation)
                .await
                .unwrap_err()
        ),
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(charged_snapshot(&store).await, charged);
    let close_request = CloseAuthorRetainCustodyRequest {
        project_id: "p".into(),
        attempt_id: env.attempt_id.clone(),
        expected_revision: stopping.revision,
        observation_event_id: observation["event_id"].as_str().unwrap().into(),
        reason: "physically stopped author; financial usage remains unknown".into(),
    };
    let command_identity = CommandIdentity {
        actor_id: "owner".into(),
        idempotency_key: "close-author-only".into(),
    };
    let mut stale = close_request.clone();
    stale.expected_revision += 1;
    assert_eq!(
        code(
            &store
                .close_author_retain_custody(command_identity.clone(), stale)
                .await
                .unwrap_err()
        ),
        "REVISION_CONFLICT"
    );
    assert_eq!(
        store
            .author_custody_status("p", &env.attempt_id)
            .await
            .unwrap()["author_close_eligible"],
        true
    );
    let closed = store
        .close_author_retain_custody(command_identity.clone(), close_request.clone())
        .await
        .unwrap();
    assert_eq!(closed.status, "AUTHOR_CLOSED_CUSTODY_RETAINED");
    let cancelled = store.get_attempt("p", &env.attempt_id).await.unwrap();
    assert_eq!(cancelled.state, AttemptState::Cancelled);
    assert!(cancelled.terminal_at.is_some());
    assert_eq!(cancelled.result, stopping.result);
    assert_eq!(
        charged_snapshot(&store).await,
        charged,
        "author closure released or rewrote original financial/resource custody"
    );
    assert_eq!(serde_json::to_vec(&original).unwrap(), original_bytes);
    let replayed = store
        .close_author_retain_custody(command_identity.clone(), close_request.clone())
        .await
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.operation_id, closed.operation_id);
    let mut changed = close_request.clone();
    changed.reason += " changed";
    assert_eq!(
        code(
            &store
                .close_author_retain_custody(command_identity, changed)
                .await
                .unwrap_err()
        ),
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        store
            .author_custody_status("p", &env.attempt_id)
            .await
            .unwrap()["custody_pending"],
        true
    );
    let fresh = store
        .admit(request(&tasks[0], "retry-original-task"))
        .await
        .unwrap();
    assert_eq!(fresh.attempt.task_id, cancelled.task_id);
    assert_ne!(fresh.attempt.attempt_id, cancelled.attempt_id);
    assert_ne!(fresh.attempt.lease_id, cancelled.lease_id);
    assert!(fresh.attempt.generation > cancelled.generation);
    assert!(
        !store
            .attempt_control("p", &cancelled.attempt_id, cancelled.generation, "w")
            .await
            .unwrap()
            .valid
    );
    assert_eq!(
        code(
            &store
                .admit(request(&tasks[1], "no-spare-capacity"))
                .await
                .unwrap_err()
        ),
        "CAPACITY_EXHAUSTED"
    );
    let after = charged_snapshot(&store).await;
    assert_eq!(
        after["models"], charged["models"],
        "fresh attempt changed old unknown model facts"
    );
    let physical_request = ReleaseStoppedPhysicalResourcesRequest {
        project_id: "p".into(),
        attempt_id: cancelled.attempt_id.clone(),
        expected_revision: cancelled.revision,
        observation_event_id: close_request.observation_event_id.clone(),
        reason: "recover the proven empty physical pool while retaining unknown provider custody"
            .into(),
    };
    let physical_identity = CommandIdentity {
        actor_id: "owner".into(),
        idempotency_key: "recover-physical-only".into(),
    };
    let mut bad = physical_request.clone();
    bad.expected_revision += 1;
    assert_eq!(
        code(
            &store
                .release_stopped_physical_resources(physical_identity.clone(), bad)
                .await
                .unwrap_err()
        ),
        "REVISION_CONFLICT"
    );
    let mut bad = physical_request.clone();
    bad.observation_event_id = "foreign-stop-observation".into();
    assert_eq!(
        code(
            &store
                .release_stopped_physical_resources(physical_identity.clone(), bad)
                .await
                .unwrap_err()
        ),
        "AUTHOR_STOP_OBSERVATION_MISSING"
    );
    assert_eq!(
        code(
            &store
                .release_stopped_physical_resources(
                    CommandIdentity {
                        actor_id: "worker:w".into(),
                        idempotency_key: "wrong-owner".into()
                    },
                    physical_request.clone()
                )
                .await
                .unwrap_err()
        ),
        "OWNER_AUTHORIZATION_REQUIRED"
    );
    let mut live_request = physical_request.clone();
    live_request.attempt_id = fresh.attempt.attempt_id.clone();
    live_request.expected_revision = fresh.attempt.revision;
    assert_eq!(
        code(
            &store
                .release_stopped_physical_resources(physical_identity.clone(), live_request)
                .await
                .unwrap_err()
        ),
        "AUTHOR_CLOSE_STATE_INVALID"
    );
    assert_eq!(
        charged_snapshot(&store).await,
        after,
        "rejected recovery changed custody"
    );
    let provider_rows = |snapshot: &Value, key: &str| {
        snapshot[key]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["dimension"] == "provider_inflight")
            .cloned()
            .collect::<Vec<_>>()
    };
    let receipt = store
        .release_stopped_physical_resources(physical_identity.clone(), physical_request.clone())
        .await
        .unwrap();
    assert_eq!(receipt.status, "STOPPED_PHYSICAL_RESOURCES_RECOVERED");
    let recovered = charged_snapshot(&store).await;
    for key in ["models", "permits", "gateway"] {
        assert_eq!(
            recovered[key], after[key],
            "physical recovery changed {key}"
        );
    }
    for key in ["allocations", "native_allocations", "limits"] {
        assert_eq!(
            provider_rows(&recovered, key),
            provider_rows(&after, key),
            "physical recovery changed provider dimension in {key}"
        );
    }
    for row in recovered["allocations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["attempt_id"] == cancelled.attempt_id && r["dimension"] != "provider_inflight"
        })
    {
        assert_eq!(row["state"], "RELEASED");
        assert_eq!(row["release_reason"], "trusted_stopped_physical_custody");
    }
    let held_model_capacity: i64 = sqlx::query_scalar("SELECT sum(amount)::bigint FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED' AND dimension='provider_inflight'").bind(&cancelled.attempt_id).fetch_one(store.pool()).await.unwrap();
    assert!(held_model_capacity > 0);
    let corrupt: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_limits l WHERE l.allocated<>COALESCE((SELECT sum(amount) FROM resource_allocations r WHERE r.scope_id=l.scope_id AND r.dimension=l.dimension AND r.state<>'RELEASED'),0)+COALESCE((SELECT sum(amount) FROM native_child_allocations r WHERE r.scope_id=l.scope_id AND r.dimension=l.dimension AND r.state<>'RELEASED'),0))").fetch_one(store.pool()).await.unwrap();
    assert!(
        !corrupt,
        "per-dimension ledger counters disagree with retained rows"
    );
    let replay = store
        .release_stopped_physical_resources(physical_identity, physical_request.clone())
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, receipt.operation_id);
    assert_eq!(
        charged_snapshot(&store).await,
        recovered,
        "replay decremented local capacity twice"
    );
    let status = store
        .author_custody_status("p", &cancelled.attempt_id)
        .await
        .unwrap();
    assert_eq!(status["held_physical_allocation_count"], 0);
    assert_eq!(status["custody_pending"], true);
    assert_eq!(status["pending_native_model_request_count"], 1);
    assert_eq!(
        serde_json::to_value(store.get_attempt("p", &cancelled.attempt_id).await.unwrap()).unwrap(),
        serde_json::to_value(&cancelled).unwrap(),
        "physical recovery changed the closed author record"
    );
    cleanup(store, schema, admin).await;
}
