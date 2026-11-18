//! Real PostgreSQL authority proofs. These fixtures qualify transaction behavior,
//! not native DSH execution, per-child OS isolation, financial or 100-Agent operation.
use chrono::{Duration, Utc};
use forgeflow_domain::*;
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

async fn setup() -> (Store, String, PgPool) {
    let url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL required for actual PostgreSQL tests");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("native_test_{}", uuid::Uuid::new_v4().simple());
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
    fixture(&store).await;
    (store, schema, admin)
}
async fn cleanup(store: Store, schema: String, admin: PgPool) {
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
fn vector() -> ResourceVector {
    ResourceVector {
        active_slot: 1,
        coding_slot: 1,
        cpu_units: 1,
        memory_bytes: 1024,
        build_permit: 1,
        gpu_permit: 1,
        provider_inflight: 1,
    }
}
fn envelope() -> ExecutionEnvelope {
    serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":"op","project_id":"p","task_id":"t","task_revision":1,"attempt_id":"a","lease_id":"l","generation":1,"worker_id":"w","workspace_root":"/tmp/native-authority","base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"ctx","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},"write_set":["out.txt"],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},"model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":"verify","allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS","REQUEST_APPROVED_MODEL"],"issued_at":"2026-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":"/tmp/native-authority/artifacts","secret_refs":[],"idempotency_key":"admission","trace_id":"proof","enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},"session_purpose":"EXECUTION","max_model_requests":8,"resume_session_id":null,"command":{"program":"/usr/bin/true","args":[]}})).unwrap()
}
async fn fixture(s: &Store) {
    s.create_project(Project {
        project_id: "p".into(),
        name: "native authority proof".into(),
        root_path: "/tmp/native-authority".into(),
        authority_mode: AuthorityMode::Managed,
        data_origin: DataOrigin::Native,
        goal: "authority negative proofs".into(),
        technology_stack: vec![],
        timezone: "UTC".into(),
        paused: false,
        archived: false,
        revision: 1,
    })
    .await
    .unwrap();
    for (team, parent) in [
        ("root", None),
        ("level1", Some("root")),
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
    sqlx::query(
        "INSERT INTO workers(worker_id,boot_id,capabilities) VALUES('w','boot','[\"DSH_NATIVE\"]')",
    )
    .execute(s.pool())
    .await
    .unwrap();
    let mut limits = vector();
    for (_, v) in limits.dimensions() {
        assert!(v > 0);
    }
    limits.active_slot = 5;
    limits.coding_slot = 5;
    limits.cpu_units = 5;
    limits.memory_bytes = 5120;
    limits.build_permit = 5;
    limits.gpu_permit = 5;
    limits.provider_inflight = 5;
    for (scope, p, team, worker, parent) in [
        ("global", None, None, None, None),
        ("project", Some("p"), None, None, Some("global")),
        ("root", Some("p"), Some("root"), None, Some("project")),
        ("level1", Some("p"), Some("level1"), None, Some("root")),
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
                limits: limits.clone(),
                revision: 1,
                paused: false,
            },
            None,
        )
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO flow_revisions(project_id,flow_revision,revision,state,input_digest,data) VALUES('p',1,1,'COMMITTED','fixture','{}')").execute(s.pool()).await.unwrap();
    sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,fence_epoch,revision,data) VALUES('p','t',1,1,'leaf','leaf','READY_FOR_ADMISSION','fixture',1,1,'{}')").execute(s.pool()).await.unwrap();
    sqlx::query("INSERT INTO task_revisions VALUES('p','t',1,'{}')")
        .execute(s.pool())
        .await
        .unwrap();
    let attempt = Attempt {
        project_id: "p".into(),
        task_id: "t".into(),
        task_revision: 1,
        attempt_id: "a".into(),
        lease_id: "l".into(),
        generation: 1,
        worker_id: "w".into(),
        operation_id: "op".into(),
        base_sha: "a".repeat(40),
        state: AttemptState::Running,
        revision: 1,
        created_at: Utc::now(),
        terminal_at: None,
        result: None,
    };
    let bindings = json!({"resource_profile":{"native_child_policy":{"schema_version":"forgeflow.native-child-policy.v1","enabled":true,"max_live_agents":4,"max_lifecycles":20,"max_delegation_depth":2,"model_inflight_limit":4,"child_resources":vector()}},"model_route":{"id":"route","provider":"deepseek","model":"deepseek-chat","max_output_tokens":128}});
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,data,envelope,execution_bindings) VALUES('p','a','t',1,'l',1,'w','op','RUNNING',1,$1,$2,$3)")
        .bind(serde_json::to_value(attempt).unwrap()).bind(serde_json::to_value(envelope()).unwrap()).bind(bindings).execute(s.pool()).await.unwrap();
    sqlx::query("INSERT INTO leases(project_id,lease_id,attempt_id,generation,worker_id,capability_scope,issued_at,expires_at) VALUES('p','l','a',1,'w','[\"out.txt\"]',$1,$2)")
        .bind(Utc::now()-Duration::minutes(1)).bind(Utc::now()+Duration::hours(2)).execute(s.pool()).await.unwrap();
    sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload,claimed_by,delivered_at) VALUES('start','p','op','attempt.start','{}','w',clock_timestamp())").execute(s.pool()).await.unwrap();
    sqlx::query("UPDATE outbox SET payload=$1 WHERE outbox_id='start'")
        .bind(serde_json::to_value(envelope()).unwrap())
        .execute(s.pool())
        .await
        .unwrap();
    for scope in [
        "global", "project", "root", "level1", "level2", "leaf", "worker",
    ] {
        for (dimension, amount) in vector().dimensions() {
            sqlx::query(
                "UPDATE resource_limits SET allocated=$3 WHERE scope_id=$1 AND dimension=$2",
            )
            .bind(scope)
            .bind(dimension)
            .bind(amount as i64)
            .execute(s.pool())
            .await
            .unwrap();
            sqlx::query("INSERT INTO resource_allocations(allocation_id,project_id,attempt_id,scope_id,dimension,amount,state) VALUES($1,'p','a',$2,$3,$4,'HELD')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(scope).bind(dimension).bind(amount as i64).execute(s.pool()).await.unwrap();
        }
    }
}
fn rpc(op: &str, fields: Value) -> Value {
    let mut request = json!({"schema_version":"forgeflow.dsh-bridge.v2","rpc_id":uuid::Uuid::new_v4(),"operation":op,"project_id":"p","task_id":"t","attempt_id":"a","generation":1});
    request
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    request
}
fn admit(session: &str, parent: Option<&str>, depth: u64) -> Value {
    rpc(
        "admit",
        json!({"native_session_id":session,"parent_session_id":parent,"source":"startup","delegation_depth":depth,"origin":null,"agent_options":{"provider":null,"model":null}}),
    )
}
fn call(session: &str, allocation: &str, purpose: &str) -> Value {
    rpc(
        "model_request",
        json!({"native_session_id":session,"allocation_id":allocation,"request_id":uuid::Uuid::new_v4(),"provider":"deepseek","model":"deepseek-chat","max_output_tokens":128,"purpose":purpose}),
    )
}
fn settle(request: &Value, grant: &Value, complete: bool) -> Value {
    rpc(
        "model_settle",
        json!({"native_session_id":request["native_session_id"],"allocation_id":request["allocation_id"],"request_id":request["request_id"],"request_grant_id":grant["request_grant_id"],"usage":if complete {json!({"inputTokens":17,"outputTokens":4,"cacheReadTokens":0,"cacheWriteTokens":0,"reasoningTokens":0})} else {Value::Null},"usage_complete":complete,"finish_reason":if complete {"stop"} else {"aborted"}}),
    )
}
fn release(session: &str, allocation: &str) -> Value {
    rpc(
        "release",
        json!({"native_session_id":session,"allocation_id":allocation,"reason":"native_disposed"}),
    )
}
fn code(error: StoreError) -> String {
    match error {
        StoreError::Domain(e) => e.code,
        other => panic!("unexpected database/decoding error: {other}"),
    }
}
async fn grant(s: &Store, session: &str, parent: Option<&str>, depth: u64) -> String {
    s.collaboration_rpc("w", admit(session, parent, depth))
        .await
        .unwrap()["allocation_id"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn pending(s: &Store) -> bool {
    let mut tx = s.pool().begin().await.unwrap();
    Store::collaboration_pending_in_transaction(&mut tx, "a")
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_concurrent_seven_dimensional_children_and_replay() {
    let (s, schema, admin) = setup().await;
    let request = admit("root-session", None, 0);
    let root = s.collaboration_rpc("w", request.clone()).await.unwrap();
    assert_eq!(
        s.collaboration_rpc("w", request.clone()).await.unwrap(),
        root
    );
    let charged: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_allocations")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(charged, 0, "root borrows existing parent reservation");
    let mut joins = Vec::new();
    for n in 0..16 {
        let s = s.clone();
        joins.push(tokio::spawn(async move {
            s.collaboration_rpc("w", admit(&format!("child-{n}"), Some("root-session"), 1))
                .await
        }));
    }
    let mut granted = 0;
    for join in joins {
        match join.await.unwrap() {
            Ok(_) => granted += 1,
            Err(e) => assert_eq!(code(e), "NATIVE_CAPACITY_EXHAUSTED"),
        }
    }
    assert_eq!(granted, 3);
    let rows = sqlx::query("SELECT scope_id,dimension,allocated,hard_limit FROM resource_limits")
        .fetch_all(s.pool())
        .await
        .unwrap();
    assert_eq!(rows.len(), 49);
    for row in rows {
        let multiplier = if row.get::<String, _>("dimension") == "memory_bytes" {
            1024
        } else {
            1
        };
        assert_eq!(row.get::<i64, _>("allocated"), 4 * multiplier);
        assert!(row.get::<i64, _>("allocated") <= row.get::<i64, _>("hard_limit"));
    }
    let child_entries: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_allocations")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(child_entries, 3 * 7 * 7);
    let mut conflicting = request.clone();
    conflicting["native_session_id"] = "other".into();
    assert_eq!(
        code(s.collaboration_rpc("w", conflicting).await.unwrap_err()),
        "IDEMPOTENCY_CONFLICT"
    );
    let mut unknown = request;
    unknown["unexpected_grant"] = true.into();
    assert_eq!(
        code(s.collaboration_rpc("w", unknown).await.unwrap_err()),
        "NATIVE_RPC_INVALID"
    );
    assert!(pending(&s).await);
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_every_resource_dimension_rejects_without_partial_charge() {
    let (s, schema, admin) = setup().await;
    grant(&s, "root-session", None, 0).await;
    for (dimension, amount) in vector().dimensions() {
        sqlx::query("UPDATE resource_limits SET hard_limit=allocated WHERE scope_id='level1' AND dimension=$1").bind(dimension).execute(s.pool()).await.unwrap();
        assert_eq!(
            code(
                s.collaboration_rpc(
                    "w",
                    admit(&format!("reject-{dimension}"), Some("root-session"), 1)
                )
                .await
                .unwrap_err()
            ),
            "RESOURCE_CAPACITY_EXHAUSTED"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_allocations")
            .fetch_one(s.pool())
            .await
            .unwrap();
        assert_eq!(rows, 0);
        let drift:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_limits WHERE allocated<>CASE WHEN dimension='memory_bytes' THEN 1024 ELSE 1 END)").fetch_one(s.pool()).await.unwrap();
        assert!(
            !drift,
            "rollback restores all earlier dimension reservations"
        );
        sqlx::query(
            "UPDATE resource_limits SET hard_limit=$2 WHERE scope_id='level1' AND dimension=$1",
        )
        .bind(dimension)
        .bind(5 * amount as i64)
        .execute(s.pool())
        .await
        .unwrap();
    }
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_identity_claim_fence_depth_and_default_deny() {
    let (s, schema, admin) = setup().await;
    for key in ["task_id", "generation"] {
        let mut wrong = admit("root-session", None, 0);
        wrong[key] = if key == "generation" {
            json!(2)
        } else {
            json!("other")
        };
        assert_eq!(
            code(s.collaboration_rpc("w", wrong).await.unwrap_err()),
            "LEASE_STALE"
        );
    }
    assert_eq!(
        code(
            s.collaboration_rpc("other-worker", admit("root-session", None, 0))
                .await
                .unwrap_err()
        ),
        "LEASE_STALE"
    );
    sqlx::query("UPDATE outbox SET claimed_by=NULL,delivered_at=NULL")
        .execute(s.pool())
        .await
        .unwrap();
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("root-session", None, 0))
                .await
                .unwrap_err()
        ),
        "NATIVE_ADMISSION_BLOCKED"
    );
    sqlx::query("UPDATE outbox SET claimed_by='w',delivered_at=clock_timestamp()")
        .execute(s.pool())
        .await
        .unwrap();
    grant(&s, "root-session", None, 0).await;
    grant(&s, "child", Some("root-session"), 1).await;
    grant(&s, "grandchild", Some("child"), 2).await;
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("too-deep", Some("grandchild"), 3))
                .await
                .unwrap_err()
        ),
        "NATIVE_LINEAGE_INVALID"
    );
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("wrong-depth", Some("root-session"), 2))
                .await
                .unwrap_err()
        ),
        "NATIVE_LINEAGE_INVALID"
    );
    sqlx::query("UPDATE attempts SET execution_bindings=jsonb_set(execution_bindings,'{resource_profile,native_child_policy,enabled}','false')").execute(s.pool()).await.unwrap();
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("deny", Some("root-session"), 1))
                .await
                .unwrap_err()
        ),
        "NATIVE_CHILD_DENIED"
    );
    sqlx::query("UPDATE tasks SET fence_epoch=2")
        .execute(s.pool())
        .await
        .unwrap();
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("stale", Some("root-session"), 1))
                .await
                .unwrap_err()
        ),
        "LEASE_STALE"
    );
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_disposal_cold_resume_root_stop_and_unknown_retention() {
    let (s, schema, admin) = setup().await;
    let root = grant(&s, "root-session", None, 0).await;
    let child = grant(&s, "child", Some("root-session"), 1).await;
    let mut resume = admit("child", Some("root-session"), 1);
    resume["source"] = "resume".into();
    assert_eq!(
        code(s.collaboration_rpc("w", resume.clone()).await.unwrap_err()),
        "NATIVE_LIFECYCLE_ACTIVE"
    );
    let bad = rpc(
        "release",
        json!({"native_session_id":"child","allocation_id":child,"reason":"idle"}),
    );
    assert_eq!(
        code(s.collaboration_rpc("w", bad).await.unwrap_err()),
        "NATIVE_DISPOSAL_UNCONFIRMED"
    );
    let old_admission: Value =
        sqlx::query_scalar("SELECT admission FROM native_child_lifecycles WHERE allocation_id=$1")
            .bind(&child)
            .fetch_one(s.pool())
            .await
            .unwrap();
    let disposal = release("child", &child);
    s.collaboration_rpc("w", disposal.clone()).await.unwrap();
    s.collaboration_rpc("w", disposal).await.unwrap();
    assert_eq!(
        code(s.collaboration_rpc("w", old_admission).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE",
        "lost ACK receipt cannot reactivate disposed grant"
    );
    let resumed = s.collaboration_rpc("w", resume.clone()).await.unwrap();
    assert_ne!(resumed["allocation_id"], child);
    assert_eq!(s.collaboration_rpc("w", resume).await.unwrap(), resumed);
    let resumed_id = resumed["allocation_id"].as_str().unwrap();
    let model = call("child", resumed_id, "compaction");
    let admitted = s.collaboration_rpc("w", model.clone()).await.unwrap();
    let unknown = settle(&model, &admitted, false);
    s.collaboration_rpc("w", unknown.clone()).await.unwrap();
    assert_eq!(s.collaboration_rpc("w", unknown).await.unwrap()["ok"], true);
    s.collaboration_rpc("w", release("child", resumed_id))
        .await
        .unwrap();
    let retained: i64 = sqlx::query_scalar(
        "SELECT allocated FROM resource_limits WHERE scope_id='global' AND dimension='active_slot'",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(retained, 2);
    let row =
        sqlx::query("SELECT status,cost_status,usage_complete,usage FROM native_model_requests")
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(row.get::<String, _>("status"), "QUARANTINED");
    assert_eq!(row.get::<String, _>("cost_status"), "UNKNOWN");
    assert!(!row.get::<bool, _>("usage_complete"));
    assert!(row.get::<Option<Value>, _>("usage").is_none());
    assert_eq!(
        code(
            s.collaboration_rpc("w", settle(&model, &admitted, true))
                .await
                .unwrap_err()
        ),
        "IDEMPOTENCY_CONFLICT"
    );
    s.collaboration_rpc("w", release("root-session", &root))
        .await
        .unwrap();
    assert!(
        pending(&s).await,
        "root disposed and unknown child cannot free parent"
    );
    let a: Value = sqlx::query_scalar("SELECT data FROM attempts WHERE attempt_id='a'")
        .fetch_one(s.pool())
        .await
        .unwrap();
    let mut tx = s.pool().begin().await.unwrap();
    Store::collaboration_process_stopped_in_transaction(
        &mut tx,
        &serde_json::from_value(a).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        Store::collaboration_pending_in_transaction(&mut tx, "a")
            .await
            .unwrap(),
        "unknown child still blocks after actual root stop"
    );
    tx.commit().await.unwrap();
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_auxiliary_budget_route_replay_and_complete_settlement() {
    let (s, schema, admin) = setup().await;
    let root = grant(&s, "root-session", None, 0).await;
    for n in 0..8 {
        let request = call(
            "root-session",
            &root,
            ["conversation", "compaction", "session-title"][n % 3],
        );
        if n == 0 {
            let mut wrong = request.clone();
            wrong["model"] = "bypass".into();
            assert_eq!(
                code(s.collaboration_rpc("w", wrong).await.unwrap_err()),
                "NATIVE_ROUTE_INVALID"
            );
            let mut wrong = request.clone();
            wrong["max_output_tokens"] = 129.into();
            assert_eq!(
                code(s.collaboration_rpc("w", wrong).await.unwrap_err()),
                "NATIVE_ROUTE_INVALID"
            );
        }
        let granted = s.collaboration_rpc("w", request.clone()).await.unwrap();
        assert_eq!(
            s.collaboration_rpc("w", request.clone()).await.unwrap(),
            granted
        );
        let done = settle(&request, &granted, true);
        assert_eq!(
            s.collaboration_rpc("w", done.clone()).await.unwrap(),
            s.collaboration_rpc("w", done).await.unwrap()
        );
        assert_eq!(
            code(s.collaboration_rpc("w", request).await.unwrap_err()),
            "NATIVE_IDENTITY_STALE",
            "settled cached permit cannot dispatch again"
        );
    }
    assert_eq!(
        code(
            s.collaboration_rpc("w", call("root-session", &root, "session-title"))
                .await
                .unwrap_err()
        ),
        "NATIVE_MODEL_BUDGET_EXHAUSTED"
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM native_model_requests WHERE status='SETTLED' AND cost_status='UNKNOWN'").fetch_one(s.pool()).await.unwrap();
    assert_eq!(count, 8);
    let ack = rpc(
        "cancel_ack",
        json!({"reason":"test","active_model_requests":0,"sessions":[{"native_session_id":"root-session","status":"idle"}]}),
    );
    s.collaboration_rpc("w", ack).await.unwrap();
    assert!(
        pending(&s).await,
        "idle never releases borrowed root reservation"
    );
    let a: Value = sqlx::query_scalar("SELECT data FROM attempts WHERE attempt_id='a'")
        .fetch_one(s.pool())
        .await
        .unwrap();
    let mut tx = s.pool().begin().await.unwrap();
    Store::collaboration_process_stopped_in_transaction(
        &mut tx,
        &serde_json::from_value(a).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        !Store::collaboration_pending_in_transaction(&mut tx, "a")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_revoke_closes_grants_and_rejects_incomplete_quiescence() {
    let (s, schema, admin) = setup().await;
    let root = grant(&s, "root-session", None, 0).await;
    let child = grant(&s, "child", Some("root-session"), 1).await;
    let request = call("child", &child, "session-title");
    let model = s.collaboration_rpc("w", request.clone()).await.unwrap();
    let incomplete = rpc(
        "cancel_ack",
        json!({"reason":"stop","active_model_requests":0,"sessions":[{"native_session_id":"root-session","status":"idle"}]}),
    );
    assert_eq!(
        code(s.collaboration_rpc("w", incomplete).await.unwrap_err()),
        "NATIVE_QUIESCENCE_UNCONFIRMED"
    );
    let poll = rpc("poll", json!({}));
    assert_eq!(
        s.collaboration_rpc("w", poll.clone()).await.unwrap()["revoked"],
        false
    );
    let mut tx = s.pool().begin().await.unwrap();
    Store::collaboration_revoke_in_transaction(&mut tx, "a")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        code(s.collaboration_rpc("w", request.clone()).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE",
        "same original RPC cannot replay grant after revoke"
    );
    assert_eq!(
        s.collaboration_rpc("w", poll).await.unwrap()["revoked"],
        true,
        "poll retry recomputes current revocation"
    );
    assert!(
        s.collaboration_rpc("w", rpc("poll", json!({})))
            .await
            .unwrap()["revoked"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        code(
            s.collaboration_rpc("w", call("root-session", &root, "conversation"))
                .await
                .unwrap_err()
        ),
        "NATIVE_IDENTITY_STALE"
    );
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("late", Some("root-session"), 1))
                .await
                .unwrap_err()
        ),
        "NATIVE_IDENTITY_STALE"
    );
    s.collaboration_rpc("w", settle(&request, &model, true))
        .await
        .unwrap();
    s.collaboration_rpc("w", release("child", &child))
        .await
        .unwrap();
    assert!(pending(&s).await);
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_reordered_disposal_and_settlement_finalize_once() {
    let (s, schema, admin) = setup().await;
    let root = grant(&s, "root-session", None, 0).await;
    let parent = grant(&s, "parent", Some("root-session"), 1).await;
    let child = grant(&s, "child", Some("parent"), 2).await;
    let request = call("child", &child, "conversation");
    let model = s.collaboration_rpc("w", request.clone()).await.unwrap();
    let parent_disposal = release("parent", &parent);
    s.collaboration_rpc("w", parent_disposal.clone())
        .await
        .unwrap();
    assert_eq!(
        code(s.collaboration_rpc("w", request.clone()).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE",
        "cached descendant grant requires exact live ancestors"
    );
    let child_disposal = release("child", &child);
    s.collaboration_rpc("w", child_disposal.clone())
        .await
        .unwrap();
    let occupied: i64 = sqlx::query_scalar(
        "SELECT allocated FROM resource_limits WHERE scope_id='global' AND dimension='active_slot'",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(occupied, 3);
    s.collaboration_rpc("w", settle(&request, &model, true))
        .await
        .unwrap();
    s.collaboration_rpc("w", parent_disposal).await.unwrap();
    s.collaboration_rpc("w", child_disposal).await.unwrap();
    let occupied: i64 = sqlx::query_scalar(
        "SELECT allocated FROM resource_limits WHERE scope_id='global' AND dimension='active_slot'",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(
        occupied, 1,
        "complete settlement closes acknowledged child and ancestor exactly once"
    );
    assert_eq!(
        s.collaboration_rpc("w", rpc("poll", json!({})))
            .await
            .unwrap()["revoked"],
        false,
        "released historical revocation does not cancel healthy root"
    );
    let historical = call("root-session", &root, "session-title");
    let admitted = s.collaboration_rpc("w", historical.clone()).await.unwrap();
    let a: Value = sqlx::query_scalar("SELECT data FROM attempts WHERE attempt_id='a'")
        .fetch_one(s.pool())
        .await
        .unwrap();
    let mut tx = s.pool().begin().await.unwrap();
    Store::collaboration_process_stopped_in_transaction(
        &mut tx,
        &serde_json::from_value(a).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        Store::collaboration_pending_in_transaction(&mut tx, "a")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    s.collaboration_rpc("w", settle(&historical, &admitted, true))
        .await
        .unwrap();
    assert!(
        !pending(&s).await,
        "late complete root settlement closes persisted actual-stop ack"
    );
    assert_eq!(
        code(s.collaboration_rpc("w", historical).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE"
    );
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_provider_reservation_inflight_and_native_zero_usage() {
    let (s, schema, admin) = setup().await;
    let root = grant(&s, "root-session", None, 0).await;
    let request = call("root-session", &root, "conversation");
    let admitted = s.collaboration_rpc("w", request.clone()).await.unwrap();
    assert_eq!(
        code(
            s.collaboration_rpc("w", call("root-session", &root, "session-title"))
                .await
                .unwrap_err()
        ),
        "NATIVE_MODEL_BUDGET_EXHAUSTED",
        "one parent provider_inflight reservation cannot be four concurrent auxiliary calls"
    );
    let mut unknown = settle(&request, &admitted, true);
    unknown["usage"] = json!({"inputTokens":0,"outputTokens":0,"totalTokens":0});
    s.collaboration_rpc("w", unknown).await.unwrap();
    let row = sqlx::query("SELECT status,usage_complete,cost_status FROM native_model_requests")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "QUARANTINED");
    assert!(!row.get::<bool, _>("usage_complete"));
    assert_eq!(row.get::<String, _>("cost_status"), "UNKNOWN");
    assert_eq!(
        code(s.collaboration_rpc("w", request).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE"
    );
    assert!(pending(&s).await);
    cleanup(s, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_missing_policy_denies_children_and_lifecycles_are_finite() {
    let (s, schema, admin) = setup().await;
    grant(&s, "root-session", None, 0).await;
    sqlx::query("UPDATE attempts SET execution_bindings=execution_bindings#-'{resource_profile,native_child_policy}'").execute(s.pool()).await.unwrap();
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("default-deny", Some("root-session"), 1))
                .await
                .unwrap_err()
        ),
        "NATIVE_CHILD_DENIED"
    );
    let policy = json!({"schema_version":"forgeflow.native-child-policy.v1","enabled":true,"max_live_agents":2,"max_lifecycles":2,"max_delegation_depth":2,"model_inflight_limit":2,"child_resources":vector()});
    sqlx::query("UPDATE attempts SET execution_bindings=jsonb_set(execution_bindings,'{resource_profile,native_child_policy}',$1)").bind(policy).execute(s.pool()).await.unwrap();
    let child = grant(&s, "child", Some("root-session"), 1).await;
    s.collaboration_rpc("w", release("child", &child))
        .await
        .unwrap();
    let mut resume = admit("child", Some("root-session"), 1);
    resume["source"] = "resume".into();
    assert_eq!(
        code(s.collaboration_rpc("w", resume).await.unwrap_err()),
        "NATIVE_CAPACITY_EXHAUSTED",
        "released lifecycles do not reset total history limit"
    );
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_root_cold_resume_after_reordered_disposal_preserves_reservation() {
    let (s, schema, admin) = setup().await;
    let original = admit("root-session", None, 0);
    let root = s.collaboration_rpc("w", original.clone()).await.unwrap();
    let child = grant(&s, "child", Some("root-session"), 1).await;
    s.collaboration_rpc(
        "w",
        release("root-session", root["allocation_id"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(
        code(
            s.collaboration_rpc("w", call("child", &child, "conversation"))
                .await
                .unwrap_err()
        ),
        "NATIVE_IDENTITY_STALE"
    );
    assert_eq!(
        code(
            s.collaboration_rpc("w", admit("late-grandchild", Some("child"), 2))
                .await
                .unwrap_err()
        ),
        "NATIVE_LINEAGE_INVALID",
        "fresh admission also requires entire live ancestry"
    );
    s.collaboration_rpc("w", release("child", &child))
        .await
        .unwrap();
    assert_eq!(
        s.collaboration_rpc("w", rpc("poll", json!({})))
            .await
            .unwrap()["revoked"],
        false
    );
    let mut resume = admit("root-session", None, 0);
    resume["source"] = "resume".into();
    let resumed = s.collaboration_rpc("w", resume).await.unwrap();
    assert_ne!(resumed["allocation_id"], root["allocation_id"]);
    assert_eq!(
        code(s.collaboration_rpc("w", original).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE"
    );
    let allocated: i64 = sqlx::query_scalar(
        "SELECT allocated FROM resource_limits WHERE scope_id='global' AND dimension='active_slot'",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(
        allocated, 1,
        "root lifecycle resumes borrow the original reservation"
    );
    let request = call(
        "root-session",
        resumed["allocation_id"].as_str().unwrap(),
        "conversation",
    );
    let admitted = s.collaboration_rpc("w", request.clone()).await.unwrap();
    s.collaboration_rpc("w", settle(&request, &admitted, true))
        .await
        .unwrap();
    let a: Value = sqlx::query_scalar("SELECT data FROM attempts WHERE attempt_id='a'")
        .fetch_one(s.pool())
        .await
        .unwrap();
    let mut tx = s.pool().begin().await.unwrap();
    Store::collaboration_process_stopped_in_transaction(
        &mut tx,
        &serde_json::from_value(a).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        !Store::collaboration_pending_in_transaction(&mut tx, "a")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    cleanup(s, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored; native execution qualification is separate"]
async fn actual_postgres_bounded_native_tool_observation_never_grants() {
    let (s, schema, admin) = setup().await;
    grant(&s, "root-session", None, 0).await;
    let observed = rpc(
        "observe",
        json!({"event":"tool/call","value":{"native_session_id":"root-session","seq":1,"callId":"native-call-1","name":"forgeflow_native_wait"}}),
    );
    s.collaboration_rpc("w", observed.clone()).await.unwrap();
    let mut arguments = observed.clone();
    arguments["rpc_id"] = json!(uuid::Uuid::new_v4());
    arguments["value"]["arguments"] = json!({"prompt":"must never persist"});
    assert_eq!(
        code(s.collaboration_rpc("w", arguments).await.unwrap_err()),
        "NATIVE_RPC_INVALID"
    );
    let mut overlong = observed.clone();
    overlong["rpc_id"] = json!(uuid::Uuid::new_v4());
    overlong["value"]["name"] = "x".repeat(129).into();
    assert_eq!(
        code(s.collaboration_rpc("w", overlong).await.unwrap_err()),
        "NATIVE_RPC_INVALID"
    );
    let mut unknown = observed;
    unknown["rpc_id"] = json!(uuid::Uuid::new_v4());
    unknown["value"]["native_session_id"] = "unallocated-native".into();
    assert_eq!(
        code(s.collaboration_rpc("w", unknown).await.unwrap_err()),
        "NATIVE_IDENTITY_STALE"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM native_model_requests")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    let occupied: i64 = sqlx::query_scalar(
        "SELECT allocated FROM resource_limits WHERE scope_id='global' AND dimension='active_slot'",
    )
    .fetch_one(s.pool())
    .await
    .unwrap();
    assert_eq!(occupied, 1);
    let payload: Value =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind='native_child.observed'")
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(payload["grants_authority"], false);
    assert!(payload["value"].get("arguments").is_none());
    cleanup(s, schema, admin).await;
}
