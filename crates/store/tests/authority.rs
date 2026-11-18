//! Actual PostgreSQL safety tests. Each run uses a new isolated schema; no mock authority.
use forgeflow_domain::*;
use forgeflow_planner::{CompileContext, OwnerTerritory, TaskSpec};
use forgeflow_store::{Store, StoreError};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

pub(crate) async fn setup() -> (Store, String, sqlx::PgPool) {
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
pub(crate) async fn cleanup(store: Store, schema: String, admin: sqlx::PgPool) {
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
fn envelope(task: &str) -> ExecutionEnvelope {
    serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":"preflight","project_id":"p","task_id":task,"task_revision":1,"attempt_id":"preflight","lease_id":"preflight","generation":1,"worker_id":"w","workspace_root":"/tmp/forgeflow-test","base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":[format!("src/{task}.rs")],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":format!("verify-{task}"),"allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS"],"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:01:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":"/tmp/forgeflow-test/artifacts","secret_refs":[],"idempotency_key":"preflight","trace_id":"test","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":1,"resume_session_id":null})).unwrap()
}
pub(crate) async fn fixture(s: &Store) -> Vec<TaskCard> {
    fixture_with_commit_pool(s, false).await
}
async fn fixture_with_commit_pool(s: &Store, full_pool: bool) -> Vec<TaskCard> {
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
    if full_pool {
        for (team, parent) in [
            ("level1", "owner"),
            ("level2", "level1"),
            ("leaf", "level2"),
        ] {
            s.create_team(Team {
                project_id: "p".into(),
                team_id: team.into(),
                parent_team_id: Some(parent.into()),
                name: team.into(),
                paused: false,
                revision: 1,
            })
            .await
            .unwrap();
        }
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
    let limit = if full_pool {
        commit_root_resources()
            .checked_pool(&commit_child_resources(), 1)
            .unwrap()
    } else {
        ResourceVector {
            active_slot: 2,
            coding_slot: 2,
            cpu_units: 2,
            ..Default::default()
        }
    };
    let mut scopes = vec![
        ("global", None, None, None, None),
        ("project", Some("p"), None, None, Some("global")),
        ("team", Some("p"), Some("owner"), None, Some("project")),
        ("worker", None, None, Some("w"), Some("global")),
    ];
    if full_pool {
        scopes.extend([
            ("level1", Some("p"), Some("level1"), None, Some("team")),
            ("level2", Some("p"), Some("level2"), None, Some("level1")),
            ("leaf", Some("p"), Some("leaf"), None, Some("level2")),
        ]);
    }
    for (scope, p, team, worker, parent) in scopes {
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
            if full_pool {
                json!({"id":"resource","qualification":"TRUSTED_WORKER_DTO_NO_OS_TRANSACTION_FIXTURE",
                    "physical_limits":{"schema_version":"forgeflow.physical-limits.v1","required":true,"cpu_units_per_cpu":1000,"period_us":100000,"pids_max":32,"swap_max_bytes":0,"memory_oom_group":true},
                    "native_child_policy":{"schema_version":"forgeflow.native-child-policy.v1","enabled":true,"max_live_agents":2,"max_lifecycles":2,"max_delegation_depth":1,"model_inflight_limit":1,"child_resources":commit_child_resources()}})
            } else {
                json!({"id":"resource","qualification":"NOT_TESTED_RUNTIME"})
            },
        ),
        (
            "model_routes",
            "route",
            if full_pool {
                json!({"id":"route","provider":"deepseek","model":"deepseek-chat","max_output_tokens":128,"qualification":"NO_MODEL_CALLS_IN_AUTHORITY_TEST"})
            } else {
                json!({"id":"route","qualification":"NO_MODEL_CALLS_IN_AUTHORITY_TEST"})
            },
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
            team_id: if full_pool { "leaf" } else { "owner" }.into(),
            requirement_ids: vec!["r".into()],
            read_set: vec![],
            write_set: vec![format!("src/{task_id}.rs")],
            dependencies: vec![],
            state: TaskPlanningState::ReadyForAdmission,
            input_digest: String::new(),
            resource_request: if full_pool {
                commit_root_resources()
            } else {
                ResourceVector {
                    active_slot: 1,
                    coding_slot: 1,
                    cpu_units: 1,
                    ..Default::default()
                }
            },
            envelope: Some({
                let mut envelope = envelope(&task_id);
                if full_pool {
                    envelope
                        .allowed_effects
                        .push(AllowedEffect::RequestApprovedModel);
                }
                envelope
            }),
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
pub(crate) fn request(t: &TaskCard, key: &str) -> AdmissionRequest {
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

async fn expire_attempt(s: &Store, a: &Attempt) -> Attempt {
    sqlx::query("UPDATE leases SET expires_at=clock_timestamp()-interval '1 second',issued_at=clock_timestamp()-interval '2 seconds' WHERE attempt_id=$1")
        .bind(&a.attempt_id)
        .execute(s.pool())
        .await
        .unwrap();
    s.expire_leases().await.unwrap();
    let expired = s.get_attempt(&a.project_id, &a.attempt_id).await.unwrap();
    assert_eq!(expired.state, AttemptState::RecoveryRequired);
    expired
}

async fn occupied_capacity(s: &Store) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(sum(allocated),0)::bigint FROM resource_limits")
        .fetch_one(s.pool())
        .await
        .unwrap()
}

fn cancellation(a: &Attempt, key: &str) -> CancelRequest {
    CancelRequest {
        actor_id: "owner".into(),
        idempotency_key: key.into(),
        project_id: a.project_id.clone(),
        attempt_id: a.attempt_id.clone(),
        expected_revision: a.revision,
        reason: "authority recovery test".into(),
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn expired_never_dispatched_cancel_releases_once_with_auditable_proof() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let admitted = s
        .admit(request(&tasks[0], "never-dispatched"))
        .await
        .unwrap();
    let initial = &admitted.attempt;
    assert!(
        !s.attempt_control("p", &initial.attempt_id, initial.generation, "w")
            .await
            .unwrap()
            .valid,
        "an admission envelope alone cannot authorize launch or binding access"
    );
    assert_eq!(
        code(
            &s.transition(TransitionRequest {
                project_id: "p".into(),
                attempt_id: initial.attempt_id.clone(),
                generation: initial.generation,
                worker_id: "w".into(),
                expected_state: AttemptState::Leased,
                next_state: AttemptState::Cancelled,
                reason: "attempted generic cancellation bypass".into(),
                receipt: None,
            })
            .await
            .unwrap_err()
        ),
        "ILLEGAL_TRANSITION"
    );
    let expired = expire_attempt(&s, initial).await;
    let occupied = occupied_capacity(&s).await;
    assert!(occupied > 0);
    let start_outbox_id: String = sqlx::query_scalar(
        "SELECT outbox_id FROM outbox WHERE operation_id=$1 AND kind='attempt.start' AND delivered_at IS NULL AND claimed_by IS NULL",
    )
    .bind(&initial.operation_id)
    .fetch_one(s.pool())
    .await
    .unwrap();

    let command = cancellation(&expired, "recover-never-dispatched");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = s.clone();
        let command = command.clone();
        handles.push(tokio::spawn(
            async move { store.cancel(command).await.unwrap() },
        ));
    }
    let mut operations = std::collections::BTreeSet::new();
    let mut original_count = 0;
    for handle in handles {
        let receipt = handle.await.unwrap();
        assert_eq!(receipt.status, "ACCEPTED");
        assert_eq!(receipt.revision, expired.revision + 1);
        original_count += usize::from(!receipt.replayed);
        operations.insert(receipt.operation_id);
    }
    assert_eq!(operations.len(), 1);
    assert_eq!(original_count, 1);
    let cancelled = s.get_attempt("p", &initial.attempt_id).await.unwrap();
    assert_eq!(cancelled.state, AttemptState::Cancelled);
    assert!(cancelled.terminal_at.is_some());
    let proof = cancelled.result.as_ref().unwrap();
    assert_eq!(proof["kind"], "NEVER_DISPATCHED");
    assert_eq!(proof["receipt_id"], operations.first().unwrap().as_str());
    assert_eq!(proof["state_before"], "RECOVERY_REQUIRED");
    assert_eq!(proof["dispatch_contract"], "CLAIM_BEFORE_EFFECTS_V1");
    assert_eq!(proof["start_outbox"]["outbox_id"], start_outbox_id);
    assert!(proof["start_outbox"]["delivered_at"].is_null());
    assert!(proof["start_outbox"]["claimed_by"].is_null());
    assert_eq!(
        proof["start_outbox"]["payload"]["attempt_id"],
        initial.attempt_id
    );
    assert_eq!(occupied_capacity(&s).await, 0);
    let released: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM resource_allocations WHERE attempt_id=$1 AND state='RELEASED' AND released_at IS NOT NULL",
    )
    .bind(&initial.attempt_id)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert!(released > 0);
    let audit: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM events WHERE object_id=$1 AND kind='attempt.never_dispatched'",
    )
    .bind(&initial.attempt_id)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(&audit, proof);
    let stops: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE kind='attempt.stop' AND payload->>'attempt_id'=$1",
    )
    .bind(&initial.attempt_id)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(stops, 0);
    assert!(s.claim("w", "p").await.unwrap().is_none());
    assert_eq!(
        code(
            &s.cancel(cancellation(&expired, "stale-revision"))
                .await
                .unwrap_err()
        ),
        "REVISION_CONFLICT"
    );
    let mut changed = command;
    changed.reason = "changed request with same key".into();
    assert_eq!(
        code(&s.cancel(changed).await.unwrap_err()),
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        s.cancel(cancellation(&cancelled, "already-terminal"))
            .await
            .unwrap()
            .status,
        "ALREADY_TERMINAL"
    );
    assert_eq!(occupied_capacity(&s).await, 0);
    let retry = s
        .admit(request(&tasks[0], "new-attempt-after-recovery"))
        .await
        .unwrap();
    assert_ne!(retry.attempt.attempt_id, initial.attempt_id);
    assert!(retry.attempt.generation > initial.generation);
    assert_eq!(
        code(
            &s.heartbeat(HeartbeatRequest {
                project_id: "p".into(),
                attempt_id: initial.attempt_id.clone(),
                generation: initial.generation,
                worker_id: "w".into(),
                lease_seconds: 300,
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
async fn uncertain_dispatch_recovery_retains_capacity_and_requests_stop() {
    for case in [
        "claimed",
        "delivered-only",
        "claimed-only",
        "missing-start",
        "mismatched-start",
        "transitioned-starting",
        "worker-launch-evidence",
        "native-session",
        "legacy-dispatch-contract",
    ] {
        let (s, schema, admin) = setup().await;
        let tasks = fixture(&s).await;
        let admitted = s.admit(request(&tasks[0], case)).await.unwrap();
        let a = &admitted.attempt;
        match case {
            "claimed" => {
                let claimed = s.claim("w", "p").await.unwrap().unwrap();
                assert_eq!(claimed.attempt_id, a.attempt_id);
                assert!(
                    s.attempt_control("p", &a.attempt_id, a.generation, "w")
                        .await
                        .unwrap()
                        .valid,
                    "transactional dispatch grants launch authority"
                );
                sqlx::query("UPDATE outbox SET payload=jsonb_set(payload,'{generation}',to_jsonb($2::bigint)) WHERE operation_id=$1 AND kind='attempt.start'")
                    .bind(&a.operation_id).bind(a.generation + 1).execute(s.pool()).await.unwrap();
                assert!(
                    !s.attempt_control("p", &a.attempt_id, a.generation, "w")
                        .await
                        .unwrap()
                        .valid,
                    "dispatch markers cannot authorize a mismatched execution identity"
                );
            }
            "delivered-only" => {
                sqlx::query("UPDATE outbox SET delivered_at=clock_timestamp() WHERE operation_id=$1 AND kind='attempt.start'")
                    .bind(&a.operation_id).execute(s.pool()).await.unwrap();
            }
            "claimed-only" => {
                sqlx::query("UPDATE outbox SET claimed_by='w' WHERE operation_id=$1 AND kind='attempt.start'")
                    .bind(&a.operation_id).execute(s.pool()).await.unwrap();
            }
            "missing-start" => {
                sqlx::query("DELETE FROM outbox WHERE operation_id=$1 AND kind='attempt.start'")
                    .bind(&a.operation_id)
                    .execute(s.pool())
                    .await
                    .unwrap();
            }
            "mismatched-start" => {
                sqlx::query("UPDATE outbox SET payload=jsonb_set(payload,'{generation}',to_jsonb($2::bigint)) WHERE operation_id=$1 AND kind='attempt.start'")
                    .bind(&a.operation_id).bind(a.generation + 1).execute(s.pool()).await.unwrap();
            }
            "transitioned-starting" => {
                s.transition(TransitionRequest {
                    project_id: "p".into(),
                    attempt_id: a.attempt_id.clone(),
                    generation: a.generation,
                    worker_id: "w".into(),
                    expected_state: AttemptState::Leased,
                    next_state: AttemptState::Starting,
                    reason: "state history without canonical claim".into(),
                    receipt: None,
                })
                .await
                .unwrap();
                assert!(
                    !s.attempt_control("p", &a.attempt_id, a.generation, "w")
                        .await
                        .unwrap()
                        .valid
                );
            }
            "worker-launch-evidence" => {
                s.record_worker_event(WorkerEvent {
                    event_id: format!("{}:launch", a.operation_id),
                    project_id: "p".into(),
                    attempt_id: a.attempt_id.clone(),
                    lease_id: a.lease_id.clone(),
                    generation: a.generation,
                    worker_id: "w".into(),
                    kind: "EXECUTOR_EVENT".into(),
                    payload: json!({"native_type":"launch", "execution_id":"persisted-launch-evidence"}),
                }).await.unwrap();
            }
            "native-session" => {
                sqlx::query("INSERT INTO native_sessions(upstream_session_id,project_id,attempt_id,generation,worker_id) VALUES('session','p',$1,$2,'w')")
                    .bind(&a.attempt_id).bind(a.generation).execute(s.pool()).await.unwrap();
            }
            "legacy-dispatch-contract" => {
                sqlx::query("UPDATE attempts SET execution_bindings=execution_bindings-'dispatch_contract' WHERE attempt_id=$1")
                    .bind(&a.attempt_id).execute(s.pool()).await.unwrap();
            }
            _ => unreachable!(),
        }
        let expired = expire_attempt(&s, a).await;
        let occupied = occupied_capacity(&s).await;
        assert!(occupied > 0, "{case}");
        let receipt = s
            .cancel(cancellation(&expired, "uncertain-stop"))
            .await
            .unwrap();
        assert_eq!(receipt.status, "ACCEPTED", "{case}");
        let pending = s.get_attempt("p", &a.attempt_id).await.unwrap();
        assert_eq!(pending.state, AttemptState::RecoveryRequired, "{case}");
        assert!(pending.terminal_at.is_none(), "{case}");
        assert!(pending.result.is_none(), "{case}");
        assert_eq!(occupied_capacity(&s).await, occupied, "{case}");
        let held: i64 = sqlx::query_scalar("SELECT count(*) FROM resource_allocations WHERE attempt_id=$1 AND state='QUARANTINED' AND released_at IS NULL")
            .bind(&a.attempt_id).fetch_one(s.pool()).await.unwrap();
        assert!(held > 0, "{case}");
        let stops: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE kind='attempt.stop' AND payload->>'attempt_id'=$1 AND delivered_at IS NULL")
            .bind(&a.attempt_id).fetch_one(s.pool()).await.unwrap();
        assert_eq!(stops, 1, "{case}");
        let proof_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE object_id=$1 AND kind='attempt.never_dispatched'",
        )
        .bind(&a.attempt_id)
        .fetch_one(s.pool())
        .await
        .unwrap();
        assert_eq!(proof_count, 0, "{case}");
        assert_eq!(
            code(
                &s.confirm_stop(StopReceipt {
                    project_id: "p".into(),
                    attempt_id: a.attempt_id.clone(),
                    generation: a.generation,
                    worker_id: "w".into(),
                    process_exit_confirmed: false,
                    evidence: json!({"journal_missing":true}),
                })
                .await
                .unwrap_err()
            ),
            "PROCESS_EXIT_UNCONFIRMED",
            "{case}"
        );
        assert_eq!(occupied_capacity(&s).await, occupied, "{case}");
        cleanup(s, schema, admin).await;
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn cancel_revision_race_cannot_release_or_record_never_dispatched_twice() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let admitted = s.admit(request(&tasks[0], "cancel-race")).await.unwrap();
    let expired = expire_attempt(&s, &admitted.attempt).await;
    let mut handles = Vec::new();
    for n in 0..8 {
        let store = s.clone();
        let command = cancellation(&expired, &format!("cancel-race-{n}"));
        handles.push(tokio::spawn(async move { store.cancel(command).await }));
    }
    let mut accepted = 0;
    let mut conflicts = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(receipt) => {
                assert_eq!(receipt.status, "ACCEPTED");
                accepted += 1;
            }
            Err(error) => {
                assert_eq!(code(&error), "REVISION_CONFLICT");
                conflicts += 1;
            }
        }
    }
    assert_eq!((accepted, conflicts), (1, 7));
    assert_eq!(occupied_capacity(&s).await, 0);
    let proof_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE object_id=$1 AND kind='attempt.never_dispatched'",
    )
    .bind(&expired.attempt_id)
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(proof_count, 1);
    let command_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM idempotency_records WHERE operation='cancel'")
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(
        command_count, 1,
        "failed CAS commands leave no partial receipt"
    );
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn recovery_cancel_preserves_model_verifier_and_commit_boundaries() {
    for case in ["model-permit", "verifier-registration", "commit-decided"] {
        let (s, schema, admin) = setup().await;
        let tasks = fixture(&s).await;
        let admitted = s.admit(request(&tasks[0], case)).await.unwrap();
        let a = &admitted.attempt;
        match case {
            "model-permit" => {
                let token = "d".repeat(64);
                sqlx::query("INSERT INTO gateway_scope_budget(token_sha256,attempt_id,route_id,model,max_requests,inflight_limit,requests_used,inflight,expires_at,project_id,generation) VALUES($1,$2,'route','model',1,1,1,1,clock_timestamp()+interval '1 minute','p',$3)")
                    .bind(&token).bind(&a.attempt_id).bind(a.generation)
                    .execute(s.pool()).await.unwrap();
                sqlx::query("INSERT INTO model_request_permit(request_id,attempt_id,route_id,model,generation,status,scope_token_digest) VALUES('inflight',$1,'route','model',$2,'QUARANTINED',$3)")
                    .bind(&a.attempt_id).bind(a.generation).bind(token)
                    .execute(s.pool()).await.unwrap();
            }
            "verifier-registration" => {
                sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES('p','operations','verifier-root',1,$1)")
                    .bind(json!({"kind":"VERIFIER_PROCESS_ROOT","attempt_id":a.attempt_id,"operation_id":"verifier","verifier_root":"/tmp/forgeflow-authority-unsettled-verifier"}))
                    .execute(s.pool()).await.unwrap();
            }
            "commit-decided" => {
                sqlx::query("INSERT INTO merge_intents(intent_id,project_id,attempt_id,generation,target_ref,state,revision,data) VALUES('decided','p',$1,$2,'refs/heads/main','COMMIT_DECIDED',1,$3)")
                    .bind(&a.attempt_id).bind(a.generation)
                    .bind(json!({"receipt":{"commit_decided":true}}))
                    .execute(s.pool()).await.unwrap();
            }
            _ => unreachable!(),
        }
        let expired = expire_attempt(&s, a).await;
        let occupied = occupied_capacity(&s).await;
        let receipt = s
            .cancel(cancellation(&expired, "boundary-stop"))
            .await
            .unwrap();
        assert_eq!(
            receipt.status,
            if case == "commit-decided" {
                "COMMIT_IN_PROGRESS"
            } else {
                "ACCEPTED"
            },
            "{case}"
        );
        let pending = s.get_attempt("p", &a.attempt_id).await.unwrap();
        assert_eq!(pending.state, AttemptState::RecoveryRequired, "{case}");
        assert!(pending.terminal_at.is_none(), "{case}");
        assert!(pending.result.is_none(), "{case}");
        assert_eq!(occupied_capacity(&s).await, occupied, "{case}");
        let proof_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE object_id=$1 AND kind='attempt.never_dispatched'",
        )
        .bind(&a.attempt_id)
        .fetch_one(s.pool())
        .await
        .unwrap();
        assert_eq!(proof_count, 0, "{case}");
        if case == "commit-decided" {
            assert_eq!(pending.revision, expired.revision);
        }
        cleanup(s, schema, admin).await;
    }
}

fn commit_root_resources() -> ResourceVector {
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
fn commit_child_resources() -> ResourceVector {
    ResourceVector {
        memory_bytes: 16 * 1024 * 1024,
        ..commit_root_resources()
    }
}

// Trusted remote DTO syntax only: no OS process/cgroup, Git ref update, model,
// verification success or production completion is claimed by this fixture.
fn commit_stop_dto(a: &Attempt, pool: &PhysicalResourceBinding) -> serde_json::Value {
    let execution = uuid::Uuid::new_v4().to_string();
    let boot = uuid::Uuid::new_v4().to_string();
    let intent = json!({"execution_id":execution,"operation_id":a.operation_id,"attempt_id":a.attempt_id,"generation":a.generation,"worker_id":a.worker_id,"boot_id":boot});
    let mut fence = json!({"schema_version":"forgeflow.cgroup-fence.v1","project_id":a.project_id,"attempt_id":a.attempt_id,"generation":a.generation,"execution_id":execution,"boot_id":boot,"owner_uid":1000,"delegation":{"unit_name":"forgeflow-worker-pg-fixture.service","root_path":"/sys/fs/cgroup/fixture/forgeflow-worker-pg-fixture.service"},"mount_id":10,"mount_path":"/sys/fs/cgroup","mount_device":20,"root_inode":30,"leaf_path":"/sys/fs/cgroup/fixture/attempt","leaf_inode":40,"limits":{"cpu_quota_us":pool.cpu_quota_us,"cpu_period_us":pool.physical_limits.period_us,"memory_max_bytes":pool.memory_max_bytes,"memory_swap_max_bytes":0,"pids_max":pool.physical_limits.pids_max,"memory_oom_group":true},"resource_binding_sha256":pool.reservation_sha256});
    let hash = forgeflow_evidence::sha256(&serde_json::to_vec(&fence).unwrap());
    fence["identity_sha256"] = hash.clone().into();
    json!({"scope":"TRUSTED_WORKER_DTO_AUTHORITY_FIXTURE_NO_OS_LAUNCH","execution_id":execution,"process_exit_confirmed":true,"launch_receipt":{"execution_id":execution,"intent":intent,"process":{"pid":123,"pgid":123,"start_ticks":456,"boot_id":boot,"attempt_id":a.attempt_id}},"physical_fence":fence,"physical_stop":{"schema_version":"forgeflow.cgroup-stop.v1","identity_sha256":hash,"boot_id":boot,"leaf_inode":40,"observed_at":chrono::Utc::now(),"populated":false,"process_exit_confirmed":true,"snapshot":{"cgroup.events":"populated 0\nfrozen 0","cgroup.procs":""}}})
}

async fn commit_custody_snapshot(s: &Store, a: &Attempt) -> serde_json::Value {
    sqlx::query_scalar("SELECT jsonb_build_object(\
        'limits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY scope_id,dimension) FROM resource_limits r),\
        'allocations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY allocation_id) FROM resource_allocations r WHERE attempt_id=$1),\
        'native',(SELECT jsonb_agg(to_jsonb(r) ORDER BY allocation_id) FROM native_child_lifecycles r WHERE attempt_id=$1),\
        'child_allocations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY resource_allocation_id) FROM native_child_allocations r WHERE attempt_id=$1),\
        'leases',(SELECT jsonb_agg(to_jsonb(r) ORDER BY lease_id) FROM leases r WHERE attempt_id=$1),\
        'merge',(SELECT jsonb_agg(to_jsonb(r) ORDER BY intent_id) FROM merge_intents r WHERE attempt_id=$1))")
        .bind(&a.attempt_id).fetch_one(s.pool()).await.unwrap()
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; transaction-only trusted DTO, no OS/Git execution"]
async fn commit_decided_stopped_callback_retains_full_pool_and_replays() {
    for initial_state in [AttemptState::Stopping, AttemptState::RecoveryRequired] {
        let (s, schema, admin) = setup().await;
        let tasks = fixture_with_commit_pool(&s, true).await;
        let admitted = s.admit(request(&tasks[0], "commit-stop")).await.unwrap();
        let claimed = s.claim("w", "p").await.unwrap().unwrap();
        assert_eq!(claimed.attempt_id, admitted.attempt.attempt_id);
        let mut a = s.get_attempt("p", &claimed.attempt_id).await.unwrap();
        for (session, parent) in [("root", None), ("child", Some("root"))] {
            s.collaboration_rpc("w", json!({"schema_version":"forgeflow.dsh-bridge.v2","rpc_id":uuid::Uuid::new_v4(),"operation":"admit","project_id":"p","task_id":a.task_id,"attempt_id":a.attempt_id,"generation":a.generation,"native_session_id":session,"parent_session_id":parent,"source":"startup","delegation_depth":u32::from(parent.is_some()),"origin":null,"agent_options":{"provider":null,"model":null}})).await.unwrap();
        }
        a = s
            .transition(TransitionRequest {
                project_id: "p".into(),
                attempt_id: a.attempt_id.clone(),
                generation: a.generation,
                worker_id: "w".into(),
                expected_state: a.state,
                next_state: AttemptState::Running,
                reason: "NO_OS transaction fixture".into(),
                receipt: None,
            })
            .await
            .unwrap();
        if initial_state == AttemptState::Stopping {
            a = s
                .transition(TransitionRequest {
                    project_id: "p".into(),
                    attempt_id: a.attempt_id.clone(),
                    generation: a.generation,
                    worker_id: "w".into(),
                    expected_state: a.state,
                    next_state: AttemptState::Stopping,
                    reason: "NO_OS callback branch fixture".into(),
                    receipt: None,
                })
                .await
                .unwrap();
        } else {
            a = expire_attempt(&s, &a).await;
        }
        // Seed only the crash predicate; this is not a fabricated successful
        // merge, verified artifact or business completion. Recovery must remain.
        let intent_state = if initial_state == AttemptState::Stopping {
            "COMMIT_DECIDED"
        } else {
            "RECOVERY_REQUIRED"
        };
        sqlx::query("INSERT INTO merge_intents(intent_id,project_id,attempt_id,generation,target_ref,state,revision,data) VALUES('no-os-decided','p',$1,$2,'refs/heads/main',$3,1,$4)")
            .bind(&a.attempt_id).bind(a.generation).bind(intent_state)
            .bind(json!({"scope":"NO_OS_DURABLE_DECISION_PREDICATE_FIXTURE","receipt":{"commit_decided":true}}))
            .execute(s.pool()).await.unwrap();
        let bindings: serde_json::Value =
            sqlx::query_scalar("SELECT execution_bindings FROM attempts WHERE attempt_id=$1")
                .bind(&a.attempt_id)
                .fetch_one(s.pool())
                .await
                .unwrap();
        let pool: PhysicalResourceBinding =
            serde_json::from_value(bindings["physical_resources"].clone()).unwrap();
        assert_eq!(
            pool.reserved_resources,
            commit_root_resources()
                .checked_pool(&commit_child_resources(), 1)
                .unwrap()
        );
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT scope_id,dimension,allocated FROM resource_limits ORDER BY scope_id,dimension",
        )
        .fetch_all(s.pool())
        .await
        .unwrap();
        assert_eq!(
            rows.len(),
            49,
            "all seven dimensions at seven selected scopes"
        );
        for (scope, dimension, amount) in rows {
            let expected = pool
                .reserved_resources
                .dimensions()
                .into_iter()
                .find(|(d, _)| *d == dimension)
                .unwrap()
                .1;
            assert_eq!(amount, expected as i64, "{scope}/{dimension}");
        }
        let before = commit_custody_snapshot(&s, &a).await;
        assert_eq!(before["native"].as_array().unwrap().len(), 2);
        assert!(
            before["child_allocations"].is_null(),
            "physical children do not double charge"
        );
        let evidence = commit_stop_dto(&a, &pool);
        let result = WorkerResult {
            event_id: "fresh-post-author-stop".into(),
            project_id: "p".into(),
            attempt_id: a.attempt_id.clone(),
            lease_id: a.lease_id.clone(),
            generation: a.generation,
            worker_id: "w".into(),
            outcome: ExecutorOutcome {
                execution_id: evidence["execution_id"].as_str().unwrap().into(),
                upstream_session_id: None,
                exit_code: Some(0),
                completion_reason: "CANCELLED".into(),
                raw_event_digest: "d".repeat(64),
                transcript_completeness: "COMPLETE".into(),
                final_artifact: None,
                error_class: None,
            },
            evidence,
        };
        let mut stale = result.clone();
        stale.generation += 1;
        assert_eq!(
            code(&s.worker_result(stale).await.unwrap_err()),
            "LEASE_STALE"
        );
        let mut occupied = result.clone();
        occupied.evidence["physical_stop"]["populated"] = true.into();
        assert_eq!(
            code(&s.worker_result(occupied).await.unwrap_err()),
            "PROCESS_EXIT_UNCONFIRMED"
        );
        assert_eq!(
            commit_custody_snapshot(&s, &a).await,
            before,
            "failed callback rolls back"
        );
        let returned = s.worker_result(result.clone()).await.unwrap();
        assert_eq!(returned.state, AttemptState::RecoveryRequired);
        assert!(returned.terminal_at.is_none());
        assert_eq!(returned.revision, a.revision + 1);
        assert_eq!(
            returned.result,
            Some(serde_json::to_value(&result).unwrap())
        );
        assert_eq!(
            commit_custody_snapshot(&s, &a).await,
            before,
            "root/native/lease/merge custody unchanged"
        );
        let replay = s.worker_result(result.clone()).await.unwrap();
        assert_eq!(replay.revision, returned.revision);
        assert_eq!(replay.state, AttemptState::RecoveryRequired);
        let mut conflicting = result;
        conflicting.outcome.completion_reason = "EXECUTOR_COMPLETED".into();
        assert_eq!(
            code(&s.worker_result(conflicting).await.unwrap_err()),
            "IDEMPOTENCY_CONFLICT"
        );
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM worker_event_ids WHERE attempt_id=$1")
                .bind(&a.attempt_id)
                .fetch_one(s.pool())
                .await
                .unwrap();
        assert_eq!(count, 1, "only one accepted durable author stop");
        assert_eq!(
            s.cancel(cancellation(&returned, "cancel-after-stop"))
                .await
                .unwrap()
                .status,
            "COMMIT_IN_PROGRESS"
        );
        assert_eq!(commit_custody_snapshot(&s, &a).await, before);
        cleanup(s, schema, admin).await;
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; full-pool admission transactions, no OS/model execution"]
async fn atomic_full_physical_pool_admission_deduplicates_and_bounds_races() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture_with_commit_pool(&s, true).await;
    let same_request = request(&tasks[0], "same-full-pool");
    let mut duplicate_calls = Vec::new();
    for _ in 0..12 {
        let store = s.clone();
        let request = same_request.clone();
        duplicate_calls.push(tokio::spawn(
            async move { store.admit(request).await.unwrap() },
        ));
    }
    let mut attempts = std::collections::BTreeSet::new();
    let mut leases = std::collections::BTreeSet::new();
    for call in duplicate_calls {
        let receipt = call.await.unwrap();
        attempts.insert(receipt.attempt.attempt_id);
        leases.insert(receipt.attempt.lease_id);
    }
    assert_eq!(
        attempts.len(),
        1,
        "12 duplicate calls create exactly one Attempt"
    );
    assert_eq!(
        leases.len(),
        1,
        "12 duplicate calls create exactly one lease"
    );
    let mut conflict = same_request;
    conflict.lease_seconds += 1;
    assert_eq!(
        code(&s.admit(conflict).await.unwrap_err()),
        "IDEMPOTENCY_CONFLICT"
    );
    let mut competitors = Vec::new();
    for task in &tasks[1..] {
        let store = s.clone();
        let request = request(task, &format!("full-pool-{}", task.task_id));
        competitors.push(tokio::spawn(async move { store.admit(request).await }));
    }
    let mut rejected = 0;
    for call in competitors {
        let error = call.await.unwrap().unwrap_err();
        assert_eq!(code(&error), "CAPACITY_EXHAUSTED");
        rejected += 1;
    }
    assert_eq!(
        rejected, 5,
        "all five competitors encounter the already held whole pool"
    );
    let count: (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM attempts),(SELECT count(*) FROM leases)")
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(
        count,
        (1, 1),
        "no partial attempt/lease survives capacity rejection"
    );
    let claimed = s.claim("w", "p").await.unwrap().unwrap();
    let a = s.get_attempt("p", &claimed.attempt_id).await.unwrap();
    assert_eq!(&a.attempt_id, attempts.first().unwrap());
    let bindings: serde_json::Value =
        sqlx::query_scalar("SELECT execution_bindings FROM attempts WHERE attempt_id=$1")
            .bind(&a.attempt_id)
            .fetch_one(s.pool())
            .await
            .unwrap();
    let pool: PhysicalResourceBinding =
        serde_json::from_value(bindings["physical_resources"].clone()).unwrap();
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT scope_id,dimension,allocated FROM resource_limits ORDER BY scope_id,dimension",
    )
    .fetch_all(s.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 49, "7 scopes by 7 dimensions");
    for (scope, dimension, amount) in rows {
        let expected = pool
            .reserved_resources
            .dimensions()
            .into_iter()
            .find(|(d, _)| *d == dimension)
            .unwrap()
            .1;
        assert_eq!(amount, expected as i64, "{scope}/{dimension}");
    }
    let occupied = occupied_capacity(&s).await;
    for (session, parent) in [("root", None), ("child", Some("root"))] {
        s.collaboration_rpc("w",json!({"schema_version":"forgeflow.dsh-bridge.v2","rpc_id":uuid::Uuid::new_v4(),"operation":"admit","project_id":"p","task_id":a.task_id,"attempt_id":a.attempt_id,"generation":a.generation,"native_session_id":session,"parent_session_id":parent,"source":"startup","delegation_depth":u32::from(parent.is_some()),"origin":null,"agent_options":{"provider":null,"model":null}})).await.unwrap();
    }
    assert_eq!(
        occupied_capacity(&s).await,
        occupied,
        "native loans do not double charge any scope"
    );
    let child_charges: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_allocations")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(child_charges, 0);
    s.cancel(cancellation(&a, "full-pool-cleanup"))
        .await
        .unwrap();
    let stopped = s
        .confirm_stop(StopReceipt {
            project_id: "p".into(),
            attempt_id: a.attempt_id.clone(),
            generation: a.generation,
            worker_id: "w".into(),
            process_exit_confirmed: true,
            evidence: commit_stop_dto(&a, &pool),
        })
        .await
        .unwrap();
    assert_eq!(stopped.state, AttemptState::Cancelled);
    assert_eq!(
        occupied_capacity(&s).await,
        0,
        "trusted positive stop closes the fixture pool"
    );
    let held:i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED')+(SELECT count(*) FROM native_child_lifecycles WHERE state<>'RELEASED')")
        .fetch_one(s.pool()).await.unwrap();
    assert_eq!(held, 0);
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn reviewed_parent_assignment_draft_rejects_stale_or_active_authority() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    s.create_team(Team {
        project_id: "p".into(),
        team_id: "owner-child".into(),
        parent_team_id: Some("owner".into()),
        name: "reviewed assignment target".into(),
        paused: false,
        revision: 1,
    })
    .await
    .unwrap();
    let parent = s.get_flow("p", 1).await.unwrap();
    let original_task = s.get_task("p", &tasks[0].task_id).await.unwrap();
    let mut context = s.get_document("p", "flow_contexts", "1").await.unwrap();
    context.as_object_mut().unwrap().remove("revision");
    let typed: CompileContext = serde_json::from_value(context.clone()).unwrap();
    let mut proposal = parent.clone();
    proposal.flow_revision = 2;
    proposal.parent_revision = Some(1);
    proposal.state = FlowState::Draft;
    proposal.approved_by = None;
    for task in &mut proposal.tasks {
        task.flow_revision = 2;
    }
    proposal.tasks[0].team_id = "owner-child".into();
    proposal.tasks[0].task_revision += 1;
    proposal.tasks[0].state = TaskPlanningState::NeedsReview;
    proposal.tasks[0].envelope = None;
    proposal.tasks[0].input_digest = forgeflow_planner::canonical_task_input_digest(
        &proposal.tasks[0],
        &typed.task_specs[&proposal.tasks[0].task_id],
    );
    proposal.input_digest = forgeflow_planner::semantic_digest(&proposal, &typed);
    let command = |parent_expected_revision, expected_source_revision: String| {
        CatalogCommand::PutFlowFromParent {
            flow: proposal.clone(),
            expected_revision: None,
            context: context.clone(),
            parent_flow_revision: 1,
            parent_expected_revision,
            expected_source_revision,
        }
    };
    assert_eq!(
        code(
            &s.execute_command(
                CommandIdentity {
                    actor_id: "owner".into(),
                    idempotency_key: "stale-parent-assignment".into(),
                },
                command(parent.revision + 1, typed.source_revision.clone()),
            )
            .await
            .unwrap_err()
        ),
        "REVISION_CONFLICT"
    );
    assert!(s.get_flow("p", 2).await.is_err());
    assert_eq!(
        code(
            &s.execute_command(
                CommandIdentity {
                    actor_id: "owner".into(),
                    idempotency_key: "stale-source-assignment".into(),
                },
                command(parent.revision, "f".repeat(64)),
            )
            .await
            .unwrap_err()
        ),
        "CONTEXT_STALE"
    );
    let active = s
        .admit(request(&tasks[0], "assignment-active"))
        .await
        .unwrap();
    assert_eq!(
        code(
            &s.execute_command(
                CommandIdentity {
                    actor_id: "owner".into(),
                    idempotency_key: "active-parent-assignment".into(),
                },
                command(parent.revision, typed.source_revision.clone()),
            )
            .await
            .unwrap_err()
        ),
        "ACTIVE_ATTEMPT"
    );
    assert!(s.get_flow("p", 2).await.is_err());
    s.cancel(cancellation(&active.attempt, "close-assignment-fixture"))
        .await
        .unwrap();
    s.execute_command(
        CommandIdentity {
            actor_id: "owner".into(),
            idempotency_key: "reviewed-parent-assignment".into(),
        },
        command(parent.revision, typed.source_revision.clone()),
    )
    .await
    .unwrap();
    let child = s.get_flow("p", 2).await.unwrap();
    assert_eq!(child.state, FlowState::Draft);
    assert_eq!(child.parent_revision, Some(1));
    assert_eq!(
        child.tasks[0].task_revision,
        original_task.task_revision + 1
    );
    assert_eq!(child.tasks[0].team_id, "owner-child");
    assert_eq!(child.tasks[0].state, TaskPlanningState::NeedsReview);
    assert!(child.tasks[0].envelope.is_none());
    assert_eq!(
        serde_json::to_value(s.get_task("p", &tasks[0].task_id).await.unwrap()).unwrap(),
        serde_json::to_value(original_task).unwrap(),
        "review draft leaves canonical task assignment unchanged"
    );
    assert_eq!(
        serde_json::to_value(s.get_flow("p", 1).await.unwrap()).unwrap(),
        serde_json::to_value(parent).unwrap(),
        "review draft preserves the committed parent"
    );
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn atomic_admission_races_fencing_quarantine_and_idempotency() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let mut handles = Vec::new();
    for _ in 0..12 {
        let s = s.clone();
        let r = request(&tasks[0], "same-key");
        handles.push(tokio::spawn(async move { s.admit(r).await.unwrap() }));
    }
    let mut ids = std::collections::BTreeSet::new();
    for h in handles {
        ids.insert(h.await.unwrap().attempt.attempt_id);
    }
    assert_eq!(ids.len(), 1, "same operation creates exactly one attempt");
    let first = s.get_attempt("p", ids.first().unwrap()).await.unwrap();
    let mut changed = request(&tasks[0], "same-key");
    changed.lease_seconds = 301;
    assert_eq!(
        code(&s.admit(changed).await.unwrap_err()),
        "IDEMPOTENCY_CONFLICT"
    );
    let mut handles = Vec::new();
    for t in &tasks[1..] {
        let s = s.clone();
        let r = request(t, &format!("race-{}", t.task_id));
        handles.push(tokio::spawn(async move { s.admit(r).await }));
    }
    let mut admitted = 0;
    let mut rejected = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => admitted += 1,
            Err(e) => {
                assert_eq!(code(&e), "CAPACITY_EXHAUSTED");
                rejected += 1;
            }
        }
    }
    assert_eq!((admitted, rejected), (1, 4));
    let snapshot = s.snapshot("p").await.unwrap();
    for limit in snapshot["resource_limits"].as_array().unwrap() {
        assert!(limit["allocated"].as_i64().unwrap() <= limit["hard_limit"].as_i64().unwrap());
    }
    let claimed = s.claim("w", "p").await.unwrap().unwrap();
    let replay = s.claim("w", "p").await.unwrap().unwrap();
    assert_eq!(
        claimed.operation_id, replay.operation_id,
        "lost claim response reoffers same stable op"
    );
    let second = s
        .claim_with_known_attempts("w", "p", &[claimed.attempt_id.clone()])
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        claimed.attempt_id, second.attempt_id,
        "acknowledged STARTING claim must not prevent parallel delivery"
    );
    assert!(
        s.claim_with_known_attempts(
            "w",
            "p",
            &[claimed.attempt_id.clone(), second.attempt_id.clone()]
        )
        .await
        .unwrap()
        .is_none()
    );
    let replay_second = s
        .claim_with_known_attempts("w", "p", &[claimed.attempt_id.clone()])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second.operation_id, replay_second.operation_id,
        "a lost response for the next claim remains replayable"
    );
    let a = s.get_attempt("p", &claimed.attempt_id).await.unwrap();
    let cancel = s
        .cancel(CancelRequest {
            actor_id: "owner".into(),
            idempotency_key: "stop".into(),
            project_id: "p".into(),
            attempt_id: a.attempt_id.clone(),
            expected_revision: a.revision,
            reason: "test".into(),
        })
        .await
        .unwrap();
    assert_eq!(cancel.status, "ACCEPTED");
    assert_eq!(
        s.get_attempt("p", &a.attempt_id).await.unwrap().state,
        AttemptState::Stopping
    );
    let late = s
        .heartbeat(HeartbeatRequest {
            project_id: "p".into(),
            attempt_id: a.attempt_id.clone(),
            generation: a.generation,
            worker_id: "w".into(),
            lease_seconds: 300,
        })
        .await
        .unwrap_err();
    assert_eq!(code(&late), "LEASE_STALE");
    let snapshot = s.snapshot("p").await.unwrap();
    assert!(
        snapshot["allocations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["attempt_id"] == a.attempt_id && x["state"] != "RELEASED")
    );
    let stopped = s
        .confirm_stop(StopReceipt {
            project_id: "p".into(),
            attempt_id: a.attempt_id.clone(),
            generation: a.generation,
            worker_id: "w".into(),
            process_exit_confirmed: true,
            evidence: json!({"oracle":"actual confirmed-stop fixture"}),
        })
        .await
        .unwrap();
    assert_eq!(stopped.state, AttemptState::Cancelled);
    s.confirm_stop(StopReceipt {
        project_id: "p".into(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        worker_id: "w".into(),
        process_exit_confirmed: true,
        evidence: json!({}),
    })
    .await
    .unwrap();
    let next = s.admit(request(&tasks[0], "retry-new-id")).await.unwrap();
    if first.attempt_id == a.attempt_id {
        assert!(next.attempt.generation > first.generation);
        assert_ne!(next.attempt.attempt_id, first.attempt_id);
    }
    sqlx::query("UPDATE leases SET expires_at=clock_timestamp()-interval '1 second',issued_at=clock_timestamp()-interval '2 seconds' WHERE attempt_id=$1").bind(&next.attempt.attempt_id).execute(s.pool()).await.unwrap();
    let expired = s.expire_leases().await.unwrap();
    assert!(
        expired
            .iter()
            .any(|x| x.attempt_id == next.attempt.attempt_id)
    );
    let snapshot = s.snapshot("p").await.unwrap();
    assert!(
        snapshot["allocations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["attempt_id"] == next.attempt.attempt_id && x["state"] == "QUARANTINED")
    );
    assert_eq!(
        code(
            &s.heartbeat(HeartbeatRequest {
                project_id: "p".into(),
                attempt_id: next.attempt.attempt_id,
                generation: next.attempt.generation,
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
async fn committed_replan_retains_active_identity_and_blocks_semantic_rewrites() {
    let (s, schema, admin) = setup().await;
    let tasks = fixture(&s).await;
    let admitted = s.admit(request(&tasks[0], "active-replan")).await.unwrap();
    let mut flow = s.get_flow("p", 1).await.unwrap();
    let mut context = s.get_document("p", "flow_contexts", "1").await.unwrap();
    context.as_object_mut().unwrap().remove("revision");
    let context_t: CompileContext = serde_json::from_value(context.clone()).unwrap();
    flow.flow_revision = 2;
    flow.parent_revision = Some(1);
    for task in &mut flow.tasks {
        task.flow_revision = 2;
        task.input_digest = forgeflow_planner::canonical_task_input_digest(
            task,
            &context_t.task_specs[&task.task_id],
        );
    }
    flow.input_digest = forgeflow_planner::semantic_digest(&flow, &context_t);
    s.execute_command(
        CommandIdentity {
            actor_id: "owner".into(),
            idempotency_key: "replan2".into(),
        },
        CatalogCommand::PutFlow {
            flow: flow.clone(),
            expected_revision: None,
            context: Some(context.clone()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        s.get_flow("p", 1).await.unwrap().state,
        FlowState::Superseded
    );
    assert_eq!(
        s.get_task("p", &tasks[0].task_id)
            .await
            .unwrap()
            .flow_revision,
        2
    );
    assert_eq!(
        s.attempt_task(&admitted.attempt)
            .await
            .unwrap()
            .flow_revision,
        1,
        "attempt resolves immutable original flow"
    );
    assert_eq!(
        s.get_attempt("p", &admitted.attempt.attempt_id)
            .await
            .unwrap()
            .generation,
        admitted.attempt.generation
    );
    let mut changed = flow.clone();
    changed.flow_revision = 3;
    changed.parent_revision = Some(2);
    for task in &mut changed.tasks {
        task.flow_revision = 3;
    }
    changed.tasks[0].envelope.as_mut().unwrap().command = Some(CommandSpec {
        program: "/usr/bin/false".into(),
        args: vec![],
    });
    changed.tasks[0].task_revision = 2;
    changed.tasks[0].input_digest = forgeflow_planner::canonical_task_input_digest(
        &changed.tasks[0],
        &context_t.task_specs[&changed.tasks[0].task_id],
    );
    changed.input_digest = forgeflow_planner::semantic_digest(&changed, &context_t);
    let rejected = s
        .execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: "rewrite3".into(),
            },
            CatalogCommand::PutFlow {
                flow: changed,
                expected_revision: None,
                context: Some(context),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(code(&rejected), "REVISION_CONFLICT");
    assert!(s.get_flow("p", 3).await.is_err());
    assert_eq!(
        s.get_flow("p", 2).await.unwrap().state,
        FlowState::Committed,
        "failed replan rolls back all mutations"
    );
    let page = s
        .paginated_catalog(Some("p"), "tasks", None, 2)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(page.next_cursor.is_some());
    let next = s
        .paginated_catalog(Some("p"), "tasks", page.next_cursor.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(next.items.len(), 2);
    assert_ne!(page.items[0]["task_id"], next.items[0]["task_id"]);
    cleanup(s, schema, admin).await;
}
