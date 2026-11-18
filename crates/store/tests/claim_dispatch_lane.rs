//! Focused live PostgreSQL competition checks for delivery of admitted reservations.
//! Fixtures seed immutable reservation rows; these checks do not qualify Worker launch latency.
use chrono::Utc;
use forgeflow_domain::{
    Attempt, AttemptState, AuthorityMode, CancelRequest, DataOrigin, ExecutionEnvelope, Project,
    WorkerEvent, WorkerHeartbeatRequest, WorkerRegisterRequest,
};
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::time::Duration;

async fn setup() -> (Store, String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("claim_lane_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options = url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .unwrap()
        .application_name(&schema)
        .options([("search_path", schema.as_str())]);
    let store = Store::connect_with_options(options).await.unwrap();
    store.migrate().await.unwrap();
    let project = Project {
        project_id: "p".into(),
        name: "claim lane".into(),
        root_path: "/tmp/forgeflow-claim-lane".into(),
        authority_mode: AuthorityMode::Managed,
        data_origin: DataOrigin::Native,
        goal: "dispatch locking".into(),
        technology_stack: vec![],
        timezone: "UTC".into(),
        paused: false,
        archived: false,
        revision: 1,
    };
    sqlx::query(
        "INSERT INTO projects(project_id,revision,authority_mode,data) VALUES('p',1,'MANAGED',$1)",
    )
    .bind(serde_json::to_value(project).unwrap())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO owner_nodes(project_id,owner_id,data) VALUES('p','team','{}')")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO flow_revisions(project_id,flow_revision,state,revision,input_digest,data) VALUES('p',1,'COMMITTED',1,'digest','{}')")
        .execute(store.pool()).await.unwrap();
    store.register_worker(registration("boot1")).await.unwrap();
    sqlx::query("INSERT INTO resource_scopes(scope_id,revision,data) VALUES('global',1,'{}')")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO resource_limits(scope_id,dimension,hard_limit,allocated) VALUES('global','active_slot',10,0)")
        .execute(store.pool()).await.unwrap();
    (store, schema, admin)
}

fn registration(boot: &str) -> WorkerRegisterRequest {
    WorkerRegisterRequest {
        project_id: Some("p".into()),
        executor_profile_ids: vec!["exec".into()],
        worker_id: "w".into(),
        boot_id: boot.into(),
        capabilities: vec!["exec".into()],
    }
}

async fn reserve(store: &Store, attempt: &str) -> ExecutionEnvelope {
    let now = Utc::now();
    let envelope: ExecutionEnvelope = serde_json::from_value(json!({
        "schema_version":"forgeflow.execution.v1", "project_id":"p", "task_id":attempt,
        "task_revision":1, "attempt_id":attempt, "operation_id":format!("operation:{attempt}"),
        "lease_id":format!("lease:{attempt}"), "generation":1, "worker_id":"w",
        "workspace_root":"/tmp/forgeflow-claim-lane", "base_sha":"a".repeat(40),
        "context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],
            "rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},
        "write_set":[], "prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},
        "model_route_id":"route", "executor_profile_id":"exec", "resource_profile_id":"resource",
        "verification_plan_id":"verify", "allowed_effects":["READ_WORKSPACE"],
        "issued_at":now.to_rfc3339(), "expires_at":(now+chrono::Duration::hours(1)).to_rfc3339(),
        "deadline_at":(now+chrono::Duration::hours(2)).to_rfc3339(),
        "artifact_prefix":"/tmp/forgeflow-claim-lane/artifacts", "secret_refs":[],
        "idempotency_key":format!("admit:{attempt}"), "trace_id":"claim-lane",
        "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION",
            "build_capable":false,"gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,
            "attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},
        "session_purpose":"EXECUTION", "max_model_requests":1, "resume_session_id":null
    })).unwrap();
    envelope.validate().unwrap();
    let a = Attempt {
        project_id: "p".into(),
        task_id: attempt.into(),
        task_revision: 1,
        attempt_id: attempt.into(),
        lease_id: envelope.lease_id.clone(),
        generation: 1,
        worker_id: "w".into(),
        operation_id: envelope.operation_id.clone(),
        base_sha: envelope.base_sha.clone(),
        state: AttemptState::Leased,
        revision: 1,
        created_at: now,
        terminal_at: None,
        result: None,
    };
    let mut tx = store.pool().begin().await.unwrap();
    sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,fence_epoch,revision,data) VALUES('p',$1,1,1,'team','team','READY_FOR_ADMISSION','digest',1,1,'{}')")
        .bind(attempt).execute(&mut *tx).await.unwrap();
    sqlx::query(
        "INSERT INTO task_revisions(project_id,task_id,task_revision,data) VALUES('p',$1,1,'{}')",
    )
    .bind(attempt)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,data,envelope,execution_bindings) VALUES('p',$1,$1,1,$2,1,'w',$3,'LEASED',1,$4,$5,$6)")
        .bind(attempt).bind(&a.lease_id).bind(&a.operation_id).bind(serde_json::to_value(&a).unwrap())
        .bind(serde_json::to_value(&envelope).unwrap()).bind(json!({"dispatch_contract":"CLAIM_BEFORE_EFFECTS_V1"}))
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO leases(project_id,lease_id,attempt_id,generation,worker_id,capability_scope,issued_at,expires_at) VALUES('p',$1,$2,1,'w','[]',$3,$4)")
        .bind(&envelope.lease_id).bind(attempt).bind(now).bind(now+chrono::Duration::hours(1))
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO resource_allocations(allocation_id,project_id,attempt_id,scope_id,dimension,amount,state) VALUES($1,'p',$2,'global','active_slot',1,'RESERVED')")
        .bind(format!("allocation:{attempt}")).bind(attempt).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE resource_limits SET allocated=allocated+1 WHERE scope_id='global' AND dimension='active_slot'")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO outbox(outbox_id,project_id,operation_id,kind,payload) VALUES($1,'p',$2,'attempt.start',$3)")
        .bind(format!("outbox:{attempt}")).bind(&envelope.operation_id)
        .bind(serde_json::to_value(&envelope).unwrap()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    envelope
}

async fn ledger(store: &Store) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('limits',(SELECT jsonb_agg(to_jsonb(l) ORDER BY scope_id,dimension) FROM resource_limits l),'allocations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY allocation_id) FROM resource_allocations a))")
        .fetch_one(store.dispatch_pool()).await.unwrap()
}

async fn blocked_by(admin: &PgPool, blocker: i32) -> i32 {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND pid<>pg_backend_pid() ORDER BY pid LIMIT 1")
                .bind(blocker).fetch_optional(admin).await.unwrap();
            if let Some(pid) = pid { return pid; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("expected transaction reached its conflicting lock")
}

fn code(error: &StoreError) -> &str {
    match error {
        StoreError::Domain(error) => &error.code,
        _ => "DATABASE_ERROR",
    }
}

async fn cleanup(store: Store, schema: String, admin: PgPool) {
    store.dispatch_pool().close().await;
    store.control_pool().close().await;
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn claim_commits_without_writer_control_or_global_resource_lane() {
    let (store, schema, admin) = setup().await;
    let envelope = reserve(&store, "a").await;
    let before = ledger(&store).await;
    for pool in [store.pool(), store.control_pool(), store.dispatch_pool()] {
        let actual: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(actual, schema, "all lanes use identical authority options");
    }
    let mut ordinary = vec![store.pool().acquire().await.unwrap()];
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *ordinary[0])
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_lock(46001337)")
        .execute(&mut *ordinary[0])
        .await
        .unwrap();
    let mut writers = Vec::new();
    for n in 0..4 {
        let writing = store.clone();
        let event = WorkerEvent {
            event_id: format!("blocked-log:{n}"),
            project_id: "p".into(),
            attempt_id: "a".into(),
            lease_id: envelope.lease_id.clone(),
            generation: 1,
            worker_id: "w".into(),
            kind: "LOG".into(),
            payload: json!({"message":"writer lane contention"}),
        };
        writers.push(tokio::spawn(async move {
            writing.record_worker_event(event).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=$2 AND $1=ANY(pg_blocking_pids(pid))")
                .bind(blocker).bind(&schema).fetch_one(&admin).await.unwrap();
            if waiting == 4 { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("all four ordinary writer permits must be occupied");
    // Four writers own main-lane connections; retain all remaining connections.
    for _ in 0..store.pool().options().get_max_connections() - 5 {
        ordinary.push(store.pool().acquire().await.unwrap());
    }
    let mut control = Vec::new();
    for _ in 0..store.control_pool().options().get_max_connections() {
        control.push(store.control_pool().acquire().await.unwrap());
    }
    let claimed = tokio::time::timeout(Duration::from_secs(2), store.claim("w", "p"))
        .await
        .expect("dispatch must not borrow a saturated writer/control lane or global coordinator")
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&claimed).unwrap(),
        serde_json::to_value(&envelope).unwrap()
    );
    assert_eq!(
        ledger(&store).await,
        before,
        "claim must not change reservations"
    );
    let replay = store.claim("w", "p").await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(replay).unwrap(),
        serde_json::to_value(&envelope).unwrap()
    );
    assert!(
        store
            .claim_with_known_attempts("w", "p", &["a".into()])
            .await
            .unwrap()
            .is_none()
    );
    let row = sqlx::query("SELECT a.state,a.revision,o.claimed_by,o.delivered_at IS NOT NULL AS delivered FROM attempts a JOIN outbox o ON o.operation_id=a.operation_id WHERE a.attempt_id='a'")
        .fetch_one(store.dispatch_pool()).await.unwrap();
    assert_eq!(row.get::<String, _>("state"), "STARTING");
    assert_eq!(row.get::<i64, _>("revision"), 2);
    assert_eq!(row.get::<String, _>("claimed_by"), "w");
    assert!(row.get::<bool, _>("delivered"));
    for writer in &writers {
        writer.abort();
    }
    sqlx::query("SELECT pg_advisory_unlock(46001337)")
        .execute(&mut *ordinary[0])
        .await
        .unwrap();
    drop(ordinary);
    drop(control);
    for writer in writers {
        assert!(writer.await.unwrap_err().is_cancelled());
    }
    assert!(store.attempt_control("p", "a", 1, "w").await.unwrap().valid);
    cleanup(store, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn cancellation_reboot_and_stale_authority_remain_serialized_with_claim() {
    let (store, schema, admin) = setup().await;
    reserve(&store, "cancel-first").await;
    let mut command_blocker = store.pool().begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *command_blocker)
        .await
        .unwrap();
    sqlx::query("SELECT outbox_id FROM outbox WHERE outbox_id='outbox:cancel-first' FOR UPDATE")
        .execute(&mut *command_blocker)
        .await
        .unwrap();
    let cancelling = store.clone();
    let cancel = tokio::spawn(async move {
        cancelling
            .cancel(CancelRequest {
                actor_id: "owner".into(),
                idempotency_key: "cancel-first".into(),
                project_id: "p".into(),
                attempt_id: "cancel-first".into(),
                expected_revision: 1,
                reason: "owner cancellation".into(),
            })
            .await
    });
    let cancel_pid = blocked_by(&admin, blocker).await;
    let claiming = store.clone();
    let claim = tokio::spawn(async move { claiming.claim("w", "p").await });
    blocked_by(&admin, cancel_pid).await;
    command_blocker.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), cancel)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), claim)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.get_attempt("p", "cancel-first").await.unwrap().state,
        AttemptState::Cancelled
    );
    assert!(
        !store
            .attempt_control("p", "cancel-first", 1, "w")
            .await
            .unwrap()
            .valid
    );

    let envelope = reserve(&store, "reboot-race").await;
    sqlx::query("UPDATE tasks SET fence_epoch=2 WHERE project_id='p' AND task_id='reboot-race'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        code(&store.claim("w", "p").await.unwrap_err()),
        "LEASE_STALE"
    );
    sqlx::query("UPDATE tasks SET fence_epoch=1 WHERE project_id='p' AND task_id='reboot-race'")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE leases SET expires_at=clock_timestamp()-interval '1 second',issued_at=clock_timestamp()-interval '1 hour' WHERE attempt_id='reboot-race'")
        .execute(store.pool()).await.unwrap();
    assert_eq!(
        code(&store.claim("w", "p").await.unwrap_err()),
        "LEASE_STALE"
    );
    sqlx::query("UPDATE leases SET expires_at=clock_timestamp()+interval '1 hour' WHERE attempt_id='reboot-race'")
        .execute(store.pool()).await.unwrap();
    let untouched: bool = sqlx::query_scalar("SELECT delivered_at IS NULL AND claimed_by IS NULL FROM outbox WHERE outbox_id='outbox:reboot-race'")
        .fetch_one(store.pool()).await.unwrap();
    assert!(
        untouched,
        "failed authority checks must not deliver the start command"
    );

    let mut project_blocker = store.pool().begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *project_blocker)
        .await
        .unwrap();
    sqlx::query("SELECT project_id FROM projects WHERE project_id='p' FOR UPDATE")
        .execute(&mut *project_blocker)
        .await
        .unwrap();
    let claiming = store.clone();
    let claim = tokio::spawn(async move { claiming.claim("w", "p").await });
    let claim_pid = blocked_by(&admin, blocker).await;
    // A real claim now holds KEY SHARE while waiting for Project. Ordinary
    // heartbeat must remain possible; a reboot must wait before taking Project.
    tokio::time::timeout(
        Duration::from_secs(2),
        store.heartbeat_worker(WorkerHeartbeatRequest {
            worker_id: "w".into(),
            boot_id: "boot1".into(),
            active_attempt_ids: vec![],
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let registering = store.clone();
    let reboot =
        tokio::spawn(async move { registering.register_worker(registration("boot2")).await });
    blocked_by(&admin, claim_pid).await;
    project_blocker.commit().await.unwrap();
    let claimed = tokio::time::timeout(Duration::from_secs(3), claim)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(claimed).unwrap(),
        serde_json::to_value(envelope).unwrap()
    );
    tokio::time::timeout(Duration::from_secs(3), reboot)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        store.get_attempt("p", "reboot-race").await.unwrap().state,
        AttemptState::RecoveryRequired
    );
    assert!(
        !store
            .attempt_control("p", "reboot-race", 1, "w")
            .await
            .unwrap()
            .valid
    );
    let state: String =
        sqlx::query_scalar("SELECT state FROM resource_allocations WHERE attempt_id='reboot-race'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        state, "QUARANTINED",
        "reboot retains occupied reservations until actual stop"
    );
    assert!(store.claim("w", "p").await.unwrap().is_none());
    cleanup(store, schema, admin).await;
}
