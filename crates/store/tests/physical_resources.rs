//! Whole-attempt physical reservation authority, using actual PostgreSQL.
//! This proves ledger transactions, not actual cgroup enforcement/native execution.
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
    let schema = format!("physical_test_{}", uuid::Uuid::new_v4().simple());
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

async fn assert_pool(s: &Store, expected: &ResourceVector, state: &str) {
    let rows = sqlx::query(
        "SELECT scope_id,dimension,allocated FROM resource_limits ORDER BY scope_id,dimension",
    )
    .fetch_all(s.pool())
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        7 * 7,
        "four team layers plus global/project/worker, without duplicated global ancestors"
    );
    for row in rows {
        let dimension: String = row.get("dimension");
        let amount = expected
            .dimensions()
            .into_iter()
            .find(|(d, _)| *d == dimension)
            .unwrap()
            .1;
        assert_eq!(
            row.get::<i64, _>("allocated"),
            amount as i64,
            "scope {} dimension {}",
            row.get::<String, _>("scope_id"),
            dimension
        );
    }
    let wrong: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED' AND state<>$1",
    )
    .bind(state)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(wrong, 0);
    let child_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_allocations")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(
        child_rows, 0,
        "native children borrow; no second charge or later partial pool release"
    );
}

async fn orphan_pair(s: &Store, task: &TaskCard, key: &str) -> (Attempt, Value, Value) {
    let admitted = s.admit(request(task, key)).await.unwrap();
    let envelope = s.claim("w", "p").await.unwrap().unwrap();
    assert_eq!(envelope.attempt_id, admitted.attempt.attempt_id);
    let a = s.get_attempt("p", &envelope.attempt_id).await.unwrap();
    let root_session = format!("{key}-root");
    let child_session = format!("{key}-child");
    let root = s
        .collaboration_rpc("w", native_admit(&a, &root_session, None))
        .await
        .unwrap();
    let child = s
        .collaboration_rpc("w", native_admit(&a, &child_session, Some(&root_session)))
        .await
        .unwrap();
    (a, root, child)
}

async fn stop_orphans(s: &Store, a: &Attempt, key: &str, evidence: Value) -> StopReceipt {
    let current = s.get_attempt("p", &a.attempt_id).await.unwrap();
    s.cancel(CancelRequest {
        actor_id: "owner".into(),
        idempotency_key: key.into(),
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        expected_revision: current.revision,
        reason: "orphan physical closure regression".into(),
    })
    .await
    .unwrap();
    StopReceipt {
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        worker_id: "w".into(),
        process_exit_confirmed: true,
        evidence,
    }
}

async fn orphan_model(s: &Store, a: &Attempt, session: &str, allocation: &Value) -> (Value, Value) {
    let model = rpc(
        a,
        "model_request",
        json!({"native_session_id":session,"allocation_id":allocation,"request_id":uuid::Uuid::new_v4(),"provider":"deepseek","model":"deepseek-chat","max_output_tokens":128,"purpose":"conversation"}),
    );
    let grant = s.collaboration_rpc("w", model.clone()).await.unwrap();
    (model, grant)
}

fn orphan_settlement(a: &Attempt, model: &Value, grant: &Value, known: bool) -> Value {
    rpc(
        a,
        "model_settle",
        json!({"native_session_id":model["native_session_id"],"allocation_id":model["allocation_id"],"request_id":model["request_id"],"request_grant_id":grant["request_grant_id"],"usage":if known {json!({"inputTokens":2,"outputTokens":1})} else {Value::Null},"usage_complete":known,"finish_reason":if known {"stop"} else {"abandoned"}}),
    )
}

async fn orphan_physical_regression(s: &Store, tasks: &[TaskCard], pool: &PhysicalResourceBinding) {
    // claim leaves the root ledger RESERVED; cancel revokes native grants,
    // and a rejected stop must retain that original occupied ledger state.
    // Root -> Team child -> subagent: all disposal callbacks were lost, but
    // every actual model settlement is known. Parent PID stop alone is unsafe.
    let (a, _, child) = orphan_pair(s, &tasks[0], "orphan-physical").await;
    let mut grandchild = native_admit(&a, "orphan-leaf", Some("orphan-physical-child"));
    grandchild["delegation_depth"] = 2.into();
    let leaf = s.collaboration_rpc("w", grandchild).await.unwrap();
    let (model, grant) = orphan_model(s, &a, "orphan-leaf", &leaf["allocation_id"]).await;
    s.collaboration_rpc("w", orphan_settlement(&a, &model, &grant, true))
        .await
        .unwrap();
    let stop = stop_orphans(s, &a, "stop-orphan-physical", trusted_stop_dto(&a, pool)).await;
    for key in ["missing", "wrong_hash", "occupied"] {
        let mut bad = stop.clone();
        match key {
            "missing" => {
                bad.evidence
                    .as_object_mut()
                    .unwrap()
                    .remove("physical_stop");
            }
            "wrong_hash" => {
                bad.evidence["physical_fence"]["identity_sha256"] = "0".repeat(64).into()
            }
            "occupied" => bad.evidence["physical_stop"]["snapshot"]["cgroup.procs"] = "123".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            code(&s.confirm_stop(bad).await.unwrap_err()),
            "PROCESS_EXIT_UNCONFIRMED"
        );
        assert_pool(s, &pool.reserved_resources, "RESERVED").await;
        let stopped: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_lifecycles WHERE attempt_id=$1 AND process_stopped_at IS NOT NULL")
            .bind(&a.attempt_id).fetch_one(s.pool()).await.unwrap();
        assert_eq!(
            stopped, 0,
            "invalid stop cannot create descendant closure facts"
        );
    }
    assert_eq!(
        s.confirm_stop(stop.clone()).await.unwrap().state,
        AttemptState::Cancelled
    );
    s.confirm_stop(stop).await.unwrap();
    assert_pool(s, &ResourceVector::default(), "RELEASED").await;
    let closed: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_lifecycles WHERE attempt_id=$1 AND state='RELEASED' AND process_stopped_at IS NOT NULL AND disposed_at IS NULL")
        .bind(&a.attempt_id).fetch_one(s.pool()).await.unwrap();
    assert_eq!(
        closed, 3,
        "validated whole-pool stop closes orphan descendants and ancestors without forged disposal"
    );
    let reason: String = sqlx::query_scalar(
        "SELECT release_reason FROM native_child_lifecycles WHERE allocation_id=$1",
    )
    .bind(child["allocation_id"].as_str().unwrap())
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(reason, "trusted_worker_physical_pool_stopped");

    // The identical physical proof still cannot erase unsettled or unknown
    // upstream model effects, and failed terminal transactions remain atomic.
    let (a, _, child) = orphan_pair(s, &tasks[1], "orphan-unknown").await;
    let (model, grant) = orphan_model(s, &a, "orphan-unknown-child", &child["allocation_id"]).await;
    let stop = stop_orphans(s, &a, "stop-orphan-unknown", trusted_stop_dto(&a, pool)).await;
    assert_eq!(
        code(&s.confirm_stop(stop.clone()).await.unwrap_err()),
        "NATIVE_EFFECT_UNCONFIRMED"
    );
    assert_pool(s, &pool.reserved_resources, "RESERVED").await;
    let status: String =
        sqlx::query_scalar("SELECT status FROM native_model_requests WHERE request_id=$1")
            .bind(model["request_id"].as_str().unwrap())
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(status, "ADMITTED");
    s.collaboration_rpc("w", orphan_settlement(&a, &model, &grant, false))
        .await
        .unwrap();
    assert_eq!(
        code(&s.confirm_stop(stop).await.unwrap_err()),
        "NATIVE_EFFECT_UNCONFIRMED"
    );
    assert_pool(s, &pool.reserved_resources, "RESERVED").await;
    let unknown = sqlx::query(
        "SELECT status,cost_status,usage_complete FROM native_model_requests WHERE request_id=$1",
    )
    .bind(model["request_id"].as_str().unwrap())
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(unknown.get::<String, _>("status"), "QUARANTINED");
    assert_eq!(unknown.get::<String, _>("cost_status"), "UNKNOWN");
    assert!(!unknown.get::<bool, _>("usage_complete"));
}

// Authority DTOs and explicitly sealed unused grants only. No verifier process,
// cgroup or model is launched; actual enforcement is qualified separately.
async fn verifier_pool_regression() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s, true).await;
    let admitted = s.admit(request(&tasks[0], "verifier-pool")).await.unwrap();
    s.claim("w", "p").await.unwrap().unwrap();
    let a = s
        .get_attempt("p", &admitted.attempt.attempt_id)
        .await
        .unwrap();
    let bindings = s.attempt_bindings("p", &a.attempt_id).await.unwrap();
    let pool: PhysicalResourceBinding =
        serde_json::from_value(bindings["physical_resources"].clone()).unwrap();
    let plan: forgeflow_evidence::VerificationPlan =
        serde_json::from_value(bindings["verification_plan"].clone()).unwrap();
    let base = std::env::temp_dir().join(format!(
        "forgeflow-verifier-pg-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let root = base.join("candidate");
    std::fs::create_dir_all(&root).unwrap();
    let physical_request = json!({"project_id":"p","delegation":{"unit_name":"forgeflow-control.service","root_path":format!("/sys/fs/cgroup/pg-authority-no-os-{}/forgeflow-control.service",uuid::Uuid::new_v4())},"limits":{"cpu_quota_us":pool.cpu_quota_us,"cpu_period_us":pool.physical_limits.period_us,"memory_max_bytes":pool.memory_max_bytes,"memory_swap_max_bytes":0,"pids_max":pool.physical_limits.pids_max,"memory_oom_group":true},"resource_binding_sha256":pool.reservation_sha256});
    let context = forgeflow_evidence::PhysicalVerificationContext::new(
        &a.attempt_id,
        a.generation,
        "verify-pg",
        &root,
        "verifier-root-pg",
        &plan,
        serde_json::from_value(physical_request).unwrap(),
    )
    .unwrap();
    let registration = json!({"kind":"VERIFIER_PROCESS_ROOT","operation_id":"verify-pg","attempt_id":a.attempt_id,"status":"REGISTERED","verifier_root":root,"physical_grant":context});
    let register = |key: &str, value: Value| {
        s.execute_command(
            CommandIdentity {
                actor_id: "verification-service".into(),
                idempotency_key: key.into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "operations".into(),
                id: "verifier-root-pg".into(),
                expected_revision: None,
                value,
            },
        )
    };
    assert_eq!(
        code(
            &register("author-still-starting", registration.clone())
                .await
                .unwrap_err()
        ),
        "ILLEGAL_TRANSITION"
    );
    s.transition(TransitionRequest {
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        worker_id: "w".into(),
        expected_state: AttemptState::Starting,
        next_state: AttemptState::Running,
        reason: "authority fixture only".into(),
        receipt: None,
    })
    .await
    .unwrap();
    s.transition(TransitionRequest {
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        worker_id: "w".into(),
        expected_state: AttemptState::Running,
        next_state: AttemptState::Verifying,
        reason: "state alone is not a physical stop".into(),
        receipt: None,
    })
    .await
    .unwrap();
    assert_eq!(
        code(
            &register("state-is-not-stop", registration.clone())
                .await
                .unwrap_err()
        ),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    assert_pool(&s, &pool.reserved_resources, "HELD").await;
    let stop = stop_orphans(
        &s,
        &a,
        "end-state-only-fixture",
        trusted_stop_dto(&a, &pool),
    )
    .await;
    s.confirm_stop(stop).await.unwrap();

    let admitted = s
        .admit(request(&tasks[0], "verifier-author-returned"))
        .await
        .unwrap();
    s.claim("w", "p").await.unwrap().unwrap();
    let a = s
        .get_attempt("p", &admitted.attempt.attempt_id)
        .await
        .unwrap();
    let mut evidence = trusted_stop_dto(&a, &pool);
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned();
    evidence["physical_fence"]["boot_id"] = boot.clone().into();
    evidence["physical_stop"]["boot_id"] = boot.clone().into();
    evidence["launch_receipt"]["intent"]["boot_id"] = boot.clone().into();
    evidence["launch_receipt"]["process"]["boot_id"] = boot.into();
    let mut fence = evidence["physical_fence"].clone();
    fence.as_object_mut().unwrap().remove("identity_sha256");
    let hash = forgeflow_evidence::sha256(&serde_json::to_vec(&fence).unwrap());
    evidence["physical_fence"]["identity_sha256"] = hash.clone().into();
    evidence["physical_stop"]["identity_sha256"] = hash.into();
    let result = s
        .worker_result(WorkerResult {
            event_id: uuid::Uuid::new_v4().to_string(),
            project_id: "p".into(),
            attempt_id: a.attempt_id.clone(),
            lease_id: a.lease_id.clone(),
            generation: a.generation,
            worker_id: "w".into(),
            evidence: evidence.clone(),
            outcome: ExecutorOutcome {
                execution_id: evidence["execution_id"].as_str().unwrap().into(),
                upstream_session_id: None,
                exit_code: Some(0),
                completion_reason: "EXECUTOR_COMPLETED".into(),
                raw_event_digest: "0".repeat(64),
                transcript_completeness: "AUTHORITY_DTO_NO_OS_LAUNCH".into(),
                final_artifact: None,
                error_class: None,
            },
        })
        .await
        .unwrap();
    assert_eq!(result.state, AttemptState::Verifying);
    let mut context = context;
    context.parent_attempt_id = a.attempt_id.clone();
    context.generation = a.generation;
    let registration = json!({"kind":"VERIFIER_PROCESS_ROOT","operation_id":"verify-pg","attempt_id":a.attempt_id,"status":"REGISTERED","verifier_root":root,"physical_grant":context});
    let register = |key: &str, value: Value| {
        s.execute_command(
            CommandIdentity {
                actor_id: "verification-service".into(),
                idempotency_key: key.into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "operations".into(),
                id: "verifier-root-pg".into(),
                expected_revision: None,
                value,
            },
        )
    };
    for (key, field) in [
        ("no-grant", "missing"),
        ("wrong-pool", "resource_binding_sha256"),
        ("wrong-limits", "limits"),
    ] {
        let mut bad = registration.clone();
        match field {
            "missing" => {
                bad.as_object_mut().unwrap().remove("physical_grant");
            }
            "resource_binding_sha256" => {
                bad["physical_grant"]["physical_request"][field] = "0".repeat(64).into()
            }
            _ => bad["physical_grant"]["physical_request"]["limits"]["cpu_quota_us"] = 1000.into(),
        }
        assert_eq!(
            code(&register(key, bad).await.unwrap_err()),
            "PROCESS_EXIT_UNCONFIRMED"
        );
    }
    let accepted = register("register-pool", registration.clone())
        .await
        .unwrap();
    assert!(!accepted.replayed);
    assert!(
        register("register-pool", registration.clone())
            .await
            .unwrap()
            .replayed
    );
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    let other_root = base.join("integrated");
    std::fs::create_dir_all(&other_root).unwrap();
    let mut other = registration.clone();
    other["operation_id"] = "competing-op".into();
    other["verifier_root"] = serde_json::to_value(&other_root).unwrap();
    let denied = s
        .execute_command(
            CommandIdentity {
                actor_id: "verification-service".into(),
                idempotency_key: "competing-root".into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "operations".into(),
                id: "competing-root".into(),
                expected_revision: None,
                value: other,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        code(&denied),
        "PROCESS_EXIT_UNCONFIRMED",
        "a second op/root cannot borrow the occupied pool concurrently"
    );
    let merge = MergeIntent {
        intent_id: uuid::Uuid::new_v4().to_string(),
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        target_ref: "refs/heads/main".into(),
        expected_sha: "a".repeat(40),
        candidate_sha: "b".repeat(40),
        integrated_sha: None,
        state: MergeIntentState::Prepared,
        revision: 1,
        receipt: None,
    };
    assert_eq!(
        code(&s.prepare_merge(merge).await.unwrap_err()),
        "PROCESS_EXIT_UNCONFIRMED",
        "merge cannot race a registered verifier"
    );
    let settlement = |physical: Vec<Value>| json!({"kind":"VERIFIER_PROCESS_SETTLED","operation_id":"settle-pg","registered_operation_id":"verify-pg","attempt_id":a.attempt_id,"registration_id":"verifier-root-pg","verifier_root":root,"status":"NEVER_LAUNCHED","never_launched":true,"stop_evidence":[],"physical_evidence":physical,"source":"COMPLETED_AWAITED_RUNNER"});
    let settle = |key: &str, value: Value| {
        s.execute_command(
            CommandIdentity {
                actor_id: "verification-service".into(),
                idempotency_key: key.into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "operations".into(),
                id: "verifier-settled-pg".into(),
                expected_revision: None,
                value,
            },
        )
    };
    assert_eq!(
        code(
            &settle("empty-is-not-closure", settlement(vec![]))
                .await
                .unwrap_err()
        ),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    std::fs::write(
        root.join("verification-physical-context.json"),
        serde_json::to_vec(&context).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("verification-physical-closed.json"),serde_json::to_vec(&json!({"context":context,"runner_closed":true,"unused_execution_ids":context.commands.iter().map(|c|c.execution_id.clone()).collect::<Vec<_>>()})).unwrap()).unwrap();
    let physical = forgeflow_evidence::verification_physical_stop_evidence(&root).unwrap();
    assert_eq!(physical.len(), 3);
    let mut wrong = physical.clone();
    wrong[0]["command"]["execution_id"] = uuid::Uuid::new_v4().to_string().into();
    assert_eq!(
        code(
            &settle("wrong-command-closure", settlement(wrong))
                .await
                .unwrap_err()
        ),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    settle("closed-unused-pool", settlement(physical))
        .await
        .unwrap();
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    // Root closure returns only physical custody; it does not release the
    // canonical Attempt pool before the final task/stop transaction.
    let stop = stop_orphans(&s, &a, "end-verifier-fixture", evidence).await;
    s.confirm_stop(stop.clone()).await.unwrap();
    s.confirm_stop(stop).await.unwrap();
    assert_pool(&s, &ResourceVector::default(), "RELEASED").await;
    std::fs::remove_dir_all(base).unwrap();
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; Root runs only this target with --ignored"]
async fn actual_postgres_upfront_pool_loans_fencing_and_release() {
    let policy = physical_policy();
    for invalid in [
        PhysicalLimitsPolicy {
            required: false,
            ..policy.clone()
        },
        PhysicalLimitsPolicy {
            pids_max: 0,
            ..policy.clone()
        },
        PhysicalLimitsPolicy {
            pids_max: 65537,
            ..policy.clone()
        },
        PhysicalLimitsPolicy {
            period_us: 999,
            ..policy.clone()
        },
        PhysicalLimitsPolicy {
            cpu_units_per_cpu: 0,
            ..policy.clone()
        },
        PhysicalLimitsPolicy {
            swap_max_bytes: 1,
            ..policy.clone()
        },
        PhysicalLimitsPolicy {
            memory_oom_group: false,
            ..policy.clone()
        },
    ] {
        assert_eq!(
            invalid.validate().unwrap_err().code,
            "PHYSICAL_POLICY_INVALID"
        );
    }
    let create = |root, child, n, policy| {
        PhysicalResourceBinding::new("resource".into(), root, child, n, policy)
    };
    let pool = create(root_vector(), child_vector(), 2, policy.clone()).unwrap();
    pool.verify().unwrap();
    assert_eq!(pool.cpu_quota_us, 75000);
    assert_eq!(pool.memory_max_bytes, 96 * 1024 * 1024);
    let zero_children =
        create(root_vector(), ResourceVector::default(), 0, policy.clone()).unwrap();
    assert_eq!(zero_children.accounting_mode, "UPFRONT_NATIVE_POOL");
    for root in [
        ResourceVector {
            cpu_units: 0,
            ..root_vector()
        },
        ResourceVector {
            memory_bytes: 0,
            ..root_vector()
        },
    ] {
        assert!(create(root, child_vector(), 2, policy.clone()).is_err());
    }
    assert!(
        create(
            root_vector(),
            child_vector(),
            2,
            PhysicalLimitsPolicy {
                cpu_units_per_cpu: 7,
                ..policy.clone()
            }
        )
        .is_err(),
        "inexact CPU quota denied"
    );
    assert!(
        create(
            ResourceVector {
                cpu_units: u64::MAX,
                ..root_vector()
            },
            child_vector(),
            2,
            policy.clone()
        )
        .is_err(),
        "complete vector overflow denied"
    );
    assert!(
        create(
            ResourceVector {
                cpu_units: i64::MAX as u64,
                ..root_vector()
            },
            ResourceVector::default(),
            0,
            policy.clone()
        )
        .is_err(),
        "CPU product overflow denied"
    );
    let mut tampered = pool.clone();
    tampered.reserved_resources.memory_bytes += 1;
    assert!(tampered.verify().is_err());
    let mut tampered = pool.clone();
    tampered.reservation_sha256 = "0".repeat(64);
    assert!(tampered.verify().is_err());

    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s, true).await;
    // A root alone fits, but the complete authorized child pool must fit too.
    sqlx::query("UPDATE resource_limits SET hard_limit=250 WHERE scope_id='level2' AND dimension='cpu_units'").execute(s.pool()).await.unwrap();
    let denied = s
        .admit(request(&tasks[0], "pool-capacity-denied"))
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "CAPACITY_EXHAUSTED");
    assert_pool(&s, &ResourceVector::default(), "RESERVED").await;
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM attempts")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(attempts, 0, "all writes roll back on one ancestor failure");
    sqlx::query("UPDATE resource_limits SET hard_limit=750 WHERE scope_id='level2' AND dimension='cpu_units'").execute(s.pool()).await.unwrap();
    for (n, invalid) in [
        json!({"required":false}),
        json!({"pids_max":0}),
        json!({"pids_max":65537}),
        Value::Null,
    ]
    .into_iter()
    .enumerate()
    {
        let mut limits = serde_json::to_value(&policy).unwrap();
        if let Some(object) = invalid.as_object() {
            limits.as_object_mut().unwrap().extend(object.clone());
        } else {
            limits = invalid;
        }
        let id = format!("bad-{n}");
        assert!(
            s.execute_command(
                CommandIdentity {
                    actor_id: "owner".into(),
                    idempotency_key: id.clone()
                },
                CatalogCommand::PutDocument {
                    project_id: "p".into(),
                    collection: "resource_profiles".into(),
                    id: id.clone(),
                    expected_revision: None,
                    value: json!({"id":id,"physical_limits":limits})
                }
            )
            .await
            .is_err()
        );
    }
    let req = request(&tasks[0], "upfront-admission");
    let admitted = s.admit(req.clone()).await.unwrap();
    let replay = s.admit(req).await.unwrap();
    assert_eq!(admitted.attempt.attempt_id, replay.attempt.attempt_id);
    assert_eq!(admitted.attempt.generation, replay.attempt.generation);
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    let bindings = s
        .attempt_bindings("p", &admitted.attempt.attempt_id)
        .await
        .unwrap();
    let frozen: PhysicalResourceBinding =
        serde_json::from_value(bindings["physical_resources"].clone()).unwrap();
    assert_eq!(frozen, pool);
    frozen.verify().unwrap();
    assert_eq!(
        code(&s.admit(request(&tasks[1], "full-pool")).await.unwrap_err()),
        "CAPACITY_EXHAUSTED"
    );
    let env = s.claim("w", "p").await.unwrap().unwrap();
    assert_eq!(env.attempt_id, admitted.attempt.attempt_id);
    let a = s.get_attempt("p", &env.attempt_id).await.unwrap();
    let root_req = native_admit(&a, "root-session", None);
    let root = s.collaboration_rpc("w", root_req.clone()).await.unwrap();
    assert_eq!(root, s.collaboration_rpc("w", root_req).await.unwrap());
    let first_req = native_admit(&a, "child-one", Some("root-session"));
    let first = s.collaboration_rpc("w", first_req.clone()).await.unwrap();
    assert_eq!(first, s.collaboration_rpc("w", first_req).await.unwrap());
    let second = s
        .collaboration_rpc("w", native_admit(&a, "child-two", Some("root-session")))
        .await
        .unwrap();
    assert_eq!(first["resource_accounting"], "UPFRONT_NATIVE_POOL");
    assert_eq!(
        first["physical_reservation_sha256"],
        pool.reservation_sha256
    );
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    assert_eq!(
        code(
            &s.collaboration_rpc(
                "w",
                native_admit(&a, "child-overflow", Some("root-session"))
            )
            .await
            .unwrap_err()
        ),
        "NATIVE_CAPACITY_EXHAUSTED"
    );
    let mut stale = native_admit(&a, "stale", Some("root-session"));
    stale["generation"] = (a.generation + 1).into();
    assert_eq!(
        code(&s.collaboration_rpc("w", stale).await.unwrap_err()),
        "LEASE_STALE"
    );
    let release = native_release(&a, "child-one", &first["allocation_id"]);
    s.collaboration_rpc("w", release.clone()).await.unwrap();
    s.collaboration_rpc("w", release).await.unwrap();
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    let replacement = s
        .collaboration_rpc("w", native_admit(&a, "child-three", Some("root-session")))
        .await
        .unwrap();
    let model = rpc(
        &a,
        "model_request",
        json!({"native_session_id":"child-three","allocation_id":replacement["allocation_id"],"request_id":uuid::Uuid::new_v4(),"provider":"deepseek","model":"deepseek-chat","max_output_tokens":128,"purpose":"conversation"}),
    );
    let grant = s.collaboration_rpc("w", model.clone()).await.unwrap();
    s.collaboration_rpc(
        "w",
        native_release(&a, "child-three", &replacement["allocation_id"]),
    )
    .await
    .unwrap();
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    s.collaboration_rpc(
        "w",
        native_release(&a, "child-two", &second["allocation_id"]),
    )
    .await
    .unwrap();
    s.collaboration_rpc(
        "w",
        native_release(&a, "root-session", &root["allocation_id"]),
    )
    .await
    .unwrap();
    assert_pool(&s, &pool.reserved_resources, "RESERVED").await;
    sqlx::query("UPDATE leases SET expires_at=clock_timestamp()-interval '1 second',issued_at=clock_timestamp()-interval '2 seconds' WHERE attempt_id=$1").bind(&a.attempt_id).execute(s.pool()).await.unwrap();
    s.expire_leases().await.unwrap();
    let current = s.get_attempt("p", &a.attempt_id).await.unwrap();
    s.cancel(CancelRequest {
        actor_id: "owner".into(),
        idempotency_key: "stop-pool".into(),
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        expected_revision: current.revision,
        reason: "pool lifecycle proof".into(),
    })
    .await
    .unwrap();
    assert_pool(&s, &pool.reserved_resources, "QUARANTINED").await;
    let stop = StopReceipt {
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        worker_id: "w".into(),
        process_exit_confirmed: false,
        evidence: trusted_stop_dto(&a, &pool),
    };
    assert_eq!(
        code(&s.confirm_stop(stop.clone()).await.unwrap_err()),
        "PROCESS_EXIT_UNCONFIRMED"
    );
    let stop = StopReceipt {
        process_exit_confirmed: true,
        ..stop
    };
    assert_eq!(
        code(&s.confirm_stop(stop.clone()).await.unwrap_err()),
        "NATIVE_EFFECT_UNCONFIRMED",
        "matching trusted physical DTO cannot release unsettled native model loan"
    );
    assert_pool(&s, &pool.reserved_resources, "QUARANTINED").await;
    let settlement = rpc(
        &a,
        "model_settle",
        json!({"native_session_id":"child-three","allocation_id":replacement["allocation_id"],"request_id":model["request_id"],"request_grant_id":grant["request_grant_id"],"usage":{"inputTokens":2,"outputTokens":1},"usage_complete":true,"finish_reason":"stop"}),
    );
    s.collaboration_rpc("w", settlement.clone()).await.unwrap();
    s.collaboration_rpc("w", settlement).await.unwrap();
    assert_pool(&s, &pool.reserved_resources, "QUARANTINED").await;
    for key in [
        "missing",
        "hash",
        "generation",
        "populated",
        "procs",
        "limits",
        "execution",
    ] {
        let mut bad = stop.clone();
        match key {
            "missing" => {
                bad.evidence
                    .as_object_mut()
                    .unwrap()
                    .remove("physical_stop");
            }
            "hash" => bad.evidence["physical_fence"]["identity_sha256"] = "0".repeat(64).into(),
            "generation" => {
                bad.evidence["physical_fence"]["generation"] = (a.generation + 1).into()
            }
            "populated" => bad.evidence["physical_stop"]["populated"] = true.into(),
            "procs" => bad.evidence["physical_stop"]["snapshot"]["cgroup.procs"] = "123".into(),
            "limits" => bad.evidence["physical_fence"]["limits"]["cpu_quota_us"] = 1000.into(),
            "execution" => bad.evidence["execution_id"] = uuid::Uuid::new_v4().to_string().into(),
            _ => unreachable!(),
        }
        assert_eq!(
            code(&s.confirm_stop(bad).await.unwrap_err()),
            "PROCESS_EXIT_UNCONFIRMED",
            "{key}"
        );
        assert_pool(&s, &pool.reserved_resources, "QUARANTINED").await;
    }
    let terminal = s.confirm_stop(stop.clone()).await.unwrap();
    assert_eq!(terminal.state, AttemptState::Cancelled);
    s.confirm_stop(stop).await.unwrap();
    assert_pool(&s, &ResourceVector::default(), "RELEASED").await;
    let next = s.admit(request(&tasks[0], "fresh-pool")).await.unwrap();
    assert!(next.attempt.generation > a.generation);
    assert_ne!(next.attempt.attempt_id, a.attempt_id);
    // Never-dispatched successor has a durable no-launch proof and releases once.
    s.cancel(CancelRequest {
        actor_id: "owner".into(),
        idempotency_key: "end-fixture".into(),
        project_id: "p".into(),
        attempt_id: next.attempt.attempt_id.clone(),
        expected_revision: next.attempt.revision,
        reason: "zero final resources".into(),
    })
    .await
    .unwrap();
    assert_pool(&s, &ResourceVector::default(), "RELEASED").await;
    orphan_physical_regression(&s, &tasks, &pool).await;
    cleanup(s, schema, admin).await;

    // A legacy parent-only stop may not substitute for a lost child disposal.
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s, false).await;
    let (a, _, child) = orphan_pair(&s, &tasks[0], "orphan-legacy").await;
    let stop = stop_orphans(&s, &a, "stop-orphan-legacy", trusted_stop_dto(&a, &pool)).await;
    assert_eq!(
        code(&s.confirm_stop(stop.clone()).await.unwrap_err()),
        "NATIVE_EFFECT_UNCONFIRMED"
    );
    let stopped: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT process_stopped_at FROM native_child_lifecycles WHERE allocation_id=$1",
    )
    .bind(child["allocation_id"].as_str().unwrap())
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert!(
        stopped.is_none(),
        "even plausible physical fields cannot upgrade a frozen legacy profile"
    );
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM native_child_allocations WHERE attempt_id=$1 AND state<>'RELEASED'",
    )
    .bind(&a.attempt_id)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert!(held > 0, "legacy child capacity remains occupied");
    s.collaboration_rpc(
        "w",
        native_release(&a, "orphan-legacy-child", &child["allocation_id"]),
    )
    .await
    .unwrap();
    assert_eq!(
        s.confirm_stop(stop).await.unwrap().state,
        AttemptState::Cancelled
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT COALESCE(sum(allocated),0)::bigint FROM resource_limits")
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(
        retained, 0,
        "legacy closure still works after actual child disposal"
    );
    cleanup(s, schema, admin).await;
    verifier_pool_regression().await;
}
