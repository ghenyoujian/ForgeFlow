//! Focused actual PostgreSQL control-lane and renewal/expiry concurrency checks.
//! SQL fixture rows exercise authority predicates; they do not qualify real authors.
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use forgeflow_domain::*;
use forgeflow_store::{Store, StoreError};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::time::Duration;

async fn setup() -> (Store, String, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL").expect("live PostgreSQL DATABASE_URL required");
    let admin = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("renewal_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options: PgConnectOptions = url.parse().unwrap();
    let store = Store::connect_with_options(options.options([
        ("search_path", schema.as_str()),
        ("application_name", schema.as_str()),
    ]))
    .await
    .unwrap();
    store.migrate().await.unwrap();
    store
        .create_project(Project {
            project_id: "p".into(),
            name: "renewal lane fixture".into(),
            root_path: "/tmp/renewal-fixture".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "real PostgreSQL control-lane lock behavior only".into(),
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
            name: "fixture owner".into(),
            paused: false,
            revision: 1,
        })
        .await
        .unwrap();
    store
        .register_worker(WorkerRegisterRequest {
            worker_id: "w".into(),
            project_id: Some("p".into()),
            boot_id: "fixture-boot".into(),
            capabilities: vec![],
            executor_profile_ids: vec!["fixture".into()],
        })
        .await
        .unwrap();
    sqlx::query("INSERT INTO flow_revisions(project_id,flow_revision,revision,state,input_digest,data) VALUES('p',1,1,'COMMITTED',$1,'{}')")
        .bind("a".repeat(64)).execute(store.pool()).await.unwrap();
    (store, schema, admin)
}

async fn cleanup(store: Store, schema: String, admin: sqlx::PgPool) {
    store.control_pool().close().await;
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

async fn seed(store: &Store, task: &str, lease_seconds: i64, deadline: DateTime<Utc>) -> Attempt {
    let now = Utc::now();
    let attempt = Attempt {
        project_id: "p".into(),
        task_id: task.into(),
        task_revision: 1,
        attempt_id: uuid::Uuid::new_v4().to_string(),
        lease_id: uuid::Uuid::new_v4().to_string(),
        generation: 1,
        worker_id: "w".into(),
        operation_id: uuid::Uuid::new_v4().to_string(),
        base_sha: "a".repeat(40),
        state: AttemptState::Starting,
        revision: 2,
        created_at: now,
        terminal_at: None,
        result: None,
    };
    let envelope: ExecutionEnvelope = serde_json::from_value(json!({
        "schema_version":"forgeflow.execution.v1","operation_id":attempt.operation_id,
        "project_id":"p","task_id":task,"task_revision":1,"attempt_id":attempt.attempt_id,
        "lease_id":attempt.lease_id,"generation":1,"worker_id":"w",
        "workspace_root":"/tmp/renewal-fixture","base_sha":attempt.base_sha,
        "context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},
        "write_set":[],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},
        "model_route_id":"none","executor_profile_id":"fixture","resource_profile_id":"fixture","verification_plan_id":"fixture",
        "allowed_effects":["READ_WORKSPACE"],"issued_at":(now-ChronoDuration::seconds(30)).to_rfc3339(),
        "expires_at":(now+ChronoDuration::seconds(lease_seconds)).to_rfc3339(),"deadline_at":deadline.to_rfc3339(),
        "artifact_prefix":"/tmp/renewal-fixture/artifacts","secret_refs":[],"idempotency_key":"fixture","trace_id":"fixture",
        "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},
        "session_purpose":"EXECUTION","max_model_requests":0,"resume_session_id":null,
    })).unwrap();
    sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,fence_epoch,revision,data) VALUES('p',$1,1,1,'owner','owner','READY_FOR_ADMISSION',$2,1,1,'{}')")
        .bind(task).bind("a".repeat(64)).execute(store.pool()).await.unwrap();
    sqlx::query(
        "INSERT INTO task_revisions(project_id,task_id,task_revision,data) VALUES('p',$1,1,'{}')",
    )
    .bind(task)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,data,envelope) VALUES('p',$1,$2,1,$3,1,'w',$4,'STARTING',2,$5,$6)")
        .bind(&attempt.attempt_id).bind(task).bind(&attempt.lease_id).bind(&attempt.operation_id)
        .bind(serde_json::to_value(&attempt).unwrap()).bind(serde_json::to_value(&envelope).unwrap())
        .execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO leases(project_id,lease_id,attempt_id,generation,worker_id,capability_scope,issued_at,expires_at) VALUES('p',$1,$2,1,'w','[]',$3,$4)")
        .bind(&attempt.lease_id).bind(&attempt.attempt_id).bind(now-ChronoDuration::seconds(30))
        .bind(now+ChronoDuration::seconds(lease_seconds)).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload,claimed_by,delivered_at) VALUES($1,'p',$2,'attempt.start',$3,'w',clock_timestamp())")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&attempt.operation_id)
        .bind(serde_json::to_value(&envelope).unwrap()).execute(store.pool()).await.unwrap();
    attempt
}

fn renewal(a: &Attempt) -> HeartbeatRequest {
    HeartbeatRequest {
        project_id: a.project_id.clone(),
        attempt_id: a.attempt_id.clone(),
        generation: a.generation,
        worker_id: a.worker_id.clone(),
        lease_seconds: 30,
    }
}

fn code(error: StoreError) -> String {
    match error {
        StoreError::Domain(error) => error.code,
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn renewal_and_control_survive_occupied_main_pool_and_global_project_locks() {
    let (store, schema, admin) = setup().await;
    let attempt = seed(
        &store,
        "busy",
        300,
        Utc::now() + ChronoDuration::minutes(10),
    )
    .await;
    let main_identity: (String, String) =
        sqlx::query_as("SELECT current_database(),current_schema()")
            .fetch_one(store.pool())
            .await
            .unwrap();
    let control_identity: (String, String) =
        sqlx::query_as("SELECT current_database(),current_schema()")
            .fetch_one(store.control_pool())
            .await
            .unwrap();
    assert_eq!(
        main_identity, control_identity,
        "both lanes must share the same database and session schema"
    );
    assert_eq!(main_identity.1, schema);
    assert_eq!(store.pool().options().get_max_connections(), 16);
    assert_eq!(store.control_pool().options().get_max_connections(), 4);
    let mut guard = admin.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(46001337)")
        .execute(&mut *guard)
        .await
        .unwrap();
    sqlx::query(&format!(
        "SELECT project_id FROM {schema}.projects WHERE project_id='p' FOR UPDATE"
    ))
    .execute(&mut *guard)
    .await
    .unwrap();
    let mut occupied = Vec::new();
    for _ in 0..16 {
        occupied.push(store.pool().acquire().await.unwrap());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), store.pool().acquire())
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        let lease = store.heartbeat(renewal(&attempt)).await.unwrap();
        assert!(lease.expires_at > Utc::now());
        assert!(
            store
                .attempt_control("p", &attempt.attempt_id, 1, "w")
                .await
                .unwrap()
                .valid
        );
        assert!(
            store
                .attempt_bindings("p", &attempt.attempt_id)
                .await
                .unwrap()
                .is_object()
        );
    })
    .await
    .expect("control lane was blocked by unrelated main/global/project authority work");
    drop(occupied);
    // Keep the authority locks while testing again with main connections available:
    // this separately proves renewal removed the global and project locks.
    tokio::time::timeout(Duration::from_secs(2), store.heartbeat(renewal(&attempt)))
        .await
        .unwrap()
        .unwrap();
    guard.rollback().await.unwrap();
    cleanup(store, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn cancellation_expiry_generation_fence_dispatch_and_deadline_keep_their_fences() {
    let (store, schema, admin) = setup().await;
    let attempt = seed(
        &store,
        "identity",
        300,
        Utc::now() + ChronoDuration::minutes(10),
    )
    .await;
    let mut stale = renewal(&attempt);
    stale.generation += 1;
    assert_eq!(
        code(store.heartbeat(stale).await.unwrap_err()),
        "LEASE_STALE"
    );
    let mut wrong_worker = renewal(&attempt);
    wrong_worker.worker_id = "other".into();
    assert_eq!(
        code(store.heartbeat(wrong_worker).await.unwrap_err()),
        "LEASE_STALE"
    );
    sqlx::query("UPDATE tasks SET fence_epoch=2 WHERE project_id='p' AND task_id='identity'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        code(store.heartbeat(renewal(&attempt)).await.unwrap_err()),
        "LEASE_STALE"
    );
    assert!(
        !store
            .attempt_control("p", &attempt.attempt_id, 1, "w")
            .await
            .unwrap()
            .valid
    );
    sqlx::query("UPDATE tasks SET fence_epoch=1 WHERE project_id='p' AND task_id='identity'")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET claimed_by=NULL,delivered_at=NULL WHERE operation_id=$1")
        .bind(&attempt.operation_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        !store
            .attempt_control("p", &attempt.attempt_id, 1, "w")
            .await
            .unwrap()
            .valid
    );
    sqlx::query(
        "UPDATE outbox SET claimed_by='w',delivered_at=clock_timestamp() WHERE operation_id=$1",
    )
    .bind(&attempt.operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    store
        .cancel(CancelRequest {
            actor_id: "owner".into(),
            idempotency_key: "cancel-renewal".into(),
            project_id: "p".into(),
            attempt_id: attempt.attempt_id.clone(),
            expected_revision: 2,
            reason: "actual authority cancellation must fence renewal".into(),
        })
        .await
        .unwrap();
    assert_eq!(
        code(store.heartbeat(renewal(&attempt)).await.unwrap_err()),
        "LEASE_STALE"
    );
    let control = store
        .attempt_control("p", &attempt.attempt_id, 1, "w")
        .await
        .unwrap();
    assert!(!control.valid && control.cancel_requested);
    let expired = seed(
        &store,
        "expired",
        -1,
        Utc::now() + ChronoDuration::minutes(10),
    )
    .await;
    assert_eq!(
        code(store.heartbeat(renewal(&expired)).await.unwrap_err()),
        "LEASE_STALE"
    );
    assert!(
        !store
            .attempt_control("p", &expired.attempt_id, 1, "w")
            .await
            .unwrap()
            .valid
    );
    let elapsed = seed(
        &store,
        "deadline",
        300,
        Utc::now() - ChronoDuration::seconds(1),
    )
    .await;
    assert_eq!(
        code(store.heartbeat(renewal(&elapsed)).await.unwrap_err()),
        "LEASE_STALE"
    );
    assert!(
        !store
            .attempt_control("p", &elapsed.attempt_id, 1, "w")
            .await
            .unwrap()
            .valid
    );
    let deadline = Utc::now() + ChronoDuration::seconds(10);
    let bounded = seed(&store, "bounded", 300, deadline).await;
    assert_eq!(
        store.heartbeat(renewal(&bounded)).await.unwrap().expires_at,
        deadline
    );
    cleanup(store, schema, admin).await;
}

async fn wait_for_locked_statement(admin: &sqlx::PgPool, schema: &str, statement: &str) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE $2)")
                .bind(schema).bind(format!("%{statement}%")).fetch_one(admin).await.unwrap();
            if blocked { return; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("required actual PostgreSQL lock wait was never observed");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn expiry_scan_rechecks_lease_after_waiting_for_inflight_renewal() {
    let (store, schema, admin) = setup().await;
    let attempt = seed(
        &store,
        "expiry-race",
        3,
        Utc::now() + ChronoDuration::minutes(10),
    )
    .await;
    // A real trigger stalls only the renewal UPDATE after valid_lease has accepted
    // it and the renewal transaction holds Attempt then Lease locks.
    let gate = 880000000i64 + (uuid::Uuid::new_v4().as_u128() % 100000000) as i64;
    sqlx::query(&format!("CREATE FUNCTION {schema}.renewal_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END $$"))
        .execute(store.pool()).await.unwrap();
    sqlx::query("CREATE TRIGGER renewal_gate BEFORE UPDATE OF expires_at ON leases FOR EACH ROW EXECUTE FUNCTION renewal_gate()")
        .execute(store.pool()).await.unwrap();
    let mut held_gate = admin.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(gate)
        .execute(&mut *held_gate)
        .await
        .unwrap();
    let renew_store = store.clone();
    let request = renewal(&attempt);
    let renew = tokio::spawn(async move { renew_store.heartbeat(request).await });
    wait_for_locked_statement(&admin, &schema, "UPDATE leases SET expires_at").await;
    let initial_expiry: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM leases WHERE attempt_id=$1")
            .bind(&attempt.attempt_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let until_expired = (initial_expiry - Utc::now()).to_std().unwrap_or_default();
    tokio::time::sleep(until_expired + Duration::from_millis(50)).await;
    let expire_store = store.clone();
    let expire = tokio::spawn(async move { expire_store.expire_leases().await });
    wait_for_locked_statement(&admin, &schema, "SELECT data FROM attempts").await;
    held_gate.rollback().await.unwrap();
    let lease = tokio::time::timeout(Duration::from_secs(3), renew)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(lease.expires_at > Utc::now());
    let expired = tokio::time::timeout(Duration::from_secs(3), expire)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        expired.is_empty(),
        "scan revoked a renewal that committed while its stale candidate waited"
    );
    assert!(
        store
            .attempt_control("p", &attempt.attempt_id, 1, "w")
            .await
            .unwrap()
            .valid
    );
    cleanup(store, schema, admin).await;
}
