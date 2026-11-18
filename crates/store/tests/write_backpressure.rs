//! Real PostgreSQL waits: queued writers preserve reads and cannot invert leadership.
use forgeflow_domain::*;
use forgeflow_store::{
    HandoffRequest, HandoffScheduler, QueuedReplacement, Store, StoreError, TerminalAcknowledgement,
};
use sqlx::{
    Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{sync::Arc, time::Duration};

async fn setup() -> (Store, String, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL").expect("live PostgreSQL DATABASE_URL required");
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("write_lane_{}", uuid::Uuid::new_v4().simple());
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
            name: "backpressure fixture".into(),
            root_path: "/tmp/write-backpressure-fixture".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "actual PostgreSQL writer/read and leader progress only".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: false,
            archived: false,
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
            executor_profile_ids: vec![],
        })
        .await
        .unwrap();
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

fn requirement(project: &str, id: &str) -> Requirement {
    Requirement {
        project_id: project.into(),
        requirement_id: id.into(),
        title: id.into(),
        source_anchor: "fixture#L1".into(),
        outcome: "write-lane producer commit".into(),
        scope: "actual lock behavior only; no author/model qualification".into(),
        acceptance: vec!["authoritative row can commit".into()],
        priority: 1,
        weight: 1,
        deferred_reason: None,
        revision: 1,
    }
}

async fn waiters(admin: &sqlx::PgPool, schema: &str, query: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE $2")
        .bind(schema).bind(format!("%{query}%")).fetch_one(admin).await.unwrap()
}

async fn wait_for_waiters(admin: &sqlx::PgPool, schema: &str, query: &str, expected: i64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if waiters(admin, schema, query).await == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expected actual PostgreSQL lock wait count was not observed");
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn released_orphan_transactions_are_rolled_back_before_connection_reuse() {
    let (store, schema, admin) = setup().await;
    sqlx::query(&format!(
        "CREATE TABLE {schema}.orphan_probe (lane TEXT PRIMARY KEY)"
    ))
    .execute(&admin)
    .await
    .unwrap();

    for (lane, pool, maximum_connections) in [
        ("ordinary", store.pool(), 16),
        ("control", store.control_pool(), 4),
        ("dispatch", store.dispatch_pool(), 4),
    ] {
        // Reserve every other connection so the same single available backend
        // must serve both the orphan transaction and the following read.
        let mut reserved = Vec::new();
        for _ in 1..maximum_connections {
            reserved.push(pool.acquire().await.unwrap());
        }
        let mut connection = pool.acquire().await.unwrap();
        let original_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        // Reproduce the server/driver state at a cancelled initial BEGIN:
        // PostgreSQL owns a real transaction while SQLx has no Transaction RAII
        // object or recorded transaction depth to trigger rollback on drop.
        sqlx::query("BEGIN")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO orphan_probe(lane) VALUES ($1)")
            .bind(lane)
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);

        let mut reused = tokio::time::timeout(Duration::from_secs(3), pool.acquire())
            .await
            .expect("released connection was not returned to its bounded pool")
            .unwrap();
        let reused_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *reused)
            .await
            .unwrap();
        assert_eq!(
            original_backend, reused_backend,
            "healthy orphan cleanup must retain the same backend rather than rely on reconnection"
        );
        use sqlx::Connection;
        let mut tx = reused.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .expect("previous caller's transaction leaked into this read");
        let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let read_only: String = sqlx::query_scalar("SHOW transaction_read_only")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(isolation, "repeatable read");
        assert_eq!(read_only, "on");
        let orphan_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM orphan_probe WHERE lane=$1")
                .bind(lane)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(
            orphan_rows, 0,
            "an uncommitted write must be rolled back, never committed during cleanup"
        );
        tx.commit().await.unwrap();
        drop(reused);

        // Ordinary idle release must keep the same backend and must not alter
        // server logging settings to hide warnings from subsequent business SQL.
        let mut idle = tokio::time::timeout(Duration::from_secs(3), pool.acquire())
            .await
            .expect("idle connection was not returned to its pool")
            .unwrap();
        let idle_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *idle)
            .await
            .unwrap();
        assert_eq!(idle_backend, original_backend);
        let log_level: String = sqlx::query_scalar("SHOW log_min_messages")
            .fetch_one(&mut *idle)
            .await
            .unwrap();
        drop(idle);
        let mut failed = tokio::time::timeout(Duration::from_secs(3), pool.acquire())
            .await
            .expect("ordinary idle release must remain reusable")
            .unwrap();
        let failed_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *failed)
            .await
            .unwrap();
        assert_eq!(failed_backend, original_backend);
        let restored_log_level: String = sqlx::query_scalar("SHOW log_min_messages")
            .fetch_one(&mut *failed)
            .await
            .unwrap();
        assert_eq!(restored_log_level, log_level);

        // An aborted raw transaction also has no SQLx RAII transaction owner.
        // Cleanup must discard this backend, not return its failed state or
        // accidentally commit the write made before the error.
        let failed_lane = format!("{lane}-failed");
        sqlx::query("BEGIN").execute(&mut *failed).await.unwrap();
        sqlx::query("INSERT INTO orphan_probe(lane) VALUES ($1)")
            .bind(&failed_lane)
            .execute(&mut *failed)
            .await
            .unwrap();
        let error = sqlx::query("SELECT 1 / 0")
            .execute(&mut *failed)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("22012")
        );
        drop(failed);
        let mut recovered = tokio::time::timeout(Duration::from_secs(3), pool.acquire())
            .await
            .expect("failed orphan must free capacity for a healthy connection")
            .unwrap();
        let recovered_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *recovered)
            .await
            .unwrap();
        assert_ne!(
            recovered_backend, failed_backend,
            "aborted orphan backend must be discarded"
        );
        let mut tx = recovered.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .expect("aborted orphan state leaked into a later transaction");
        let failed_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM orphan_probe WHERE lane=$1")
                .bind(&failed_lane)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(
            failed_rows, 0,
            "failed orphan cleanup must never commit earlier writes"
        );
        tx.commit().await.unwrap();
        drop(recovered);
        drop(reserved);
    }
    let snapshot = store.snapshot("p").await.unwrap();
    assert_eq!(snapshot["project"]["project_id"], "p");
    store.dispatch_pool().close().await;
    cleanup(store, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn blocked_writers_wait_before_pool_acquisition_and_readers_remain_serviceable() {
    let (store, schema, admin) = setup().await;
    let mut coordination = admin.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(46001337)")
        .execute(&mut *coordination)
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(65));
    let mut producers = tokio::task::JoinSet::new();
    for n in 0..64 {
        let store = store.clone();
        let barrier = barrier.clone();
        producers.spawn(async move {
            barrier.wait().await;
            store
                .create_requirement(requirement("p", &format!("producer-{n}")))
                .await
        });
    }
    barrier.wait().await;
    wait_for_waiters(&admin, &schema, "pg_advisory_xact_lock(46001337)", 4).await;
    assert_eq!(
        producers.len(),
        64,
        "all cloned producers should remain pending behind coordination"
    );
    assert_eq!(
        waiters(&admin, &schema, "pg_advisory_xact_lock(46001337)").await,
        4,
        "only four queued writers may occupy PostgreSQL connections"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        let snapshot = store.snapshot("p").await.unwrap();
        assert_eq!(snapshot["project"]["project_id"], "p");
        assert_eq!(store.get_project("p").await.unwrap().project_id, "p");
        store.heartbeat_worker(WorkerHeartbeatRequest {
            worker_id: "w".into(), boot_id: "fixture-boot".into(), active_attempt_ids: vec![],
        }).await.unwrap();
        let healthy: bool = sqlx::query_scalar("SELECT heartbeat_at>clock_timestamp()-interval '5 seconds' FROM workers WHERE worker_id='w'")
            .fetch_one(store.control_pool()).await.unwrap();
        assert!(healthy, "worker presence must also avoid the occupied write lane");
    }).await.expect("independent snapshot/read/control update was starved by queued writers");
    coordination.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(result) = producers.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .expect("released writer queue did not drain");
    assert_eq!(store.list_requirements("p").await.unwrap().len(), 64);
    // Four failed transactions also return their owned permits; errors cannot
    // leak capacity or silently enlarge the fixed writer budget.
    for n in 0..4 {
        assert!(
            store
                .create_requirement(requirement("missing-project", &format!("rejected-{n}")))
                .await
                .is_err()
        );
    }
    tokio::time::timeout(
        Duration::from_secs(2),
        store.create_requirement(requirement("p", "after-errors")),
    )
    .await
    .unwrap()
    .unwrap();
    cleanup(store, schema, admin).await;
}

struct NoReplacement;
#[async_trait::async_trait]
impl HandoffScheduler for NoReplacement {
    async fn select(
        &self,
        _: &mut Transaction<'_, Postgres>,
        _: &Attempt,
    ) -> forgeflow_store::Result<Option<QueuedReplacement>> {
        panic!("missing fixture predecessor must fail before replacement scheduling");
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn leader_waiting_handoffs_leave_a_writer_slot_for_the_current_pump() {
    let (store, schema, admin) = setup().await;
    let mut leadership = admin.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(46001338)")
        .execute(&mut *leadership)
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(5));
    let mut handoffs = tokio::task::JoinSet::new();
    for n in 0..4 {
        let store = store.clone();
        let barrier = barrier.clone();
        handoffs.spawn(async move {
            barrier.wait().await;
            store
                .terminal_handoff(
                    HandoffRequest {
                        identity: CommandIdentity {
                            actor_id: "owner".into(),
                            idempotency_key: format!("lock-only-handoff-{n}"),
                        },
                        // This deliberately absent predecessor cannot invent a stop,
                        // author, release or replacement; only the pre-author lock path is exercised.
                        terminal: TerminalAcknowledgement::ConfirmStop {
                            receipt: StopReceipt {
                                project_id: "p".into(),
                                attempt_id: uuid::Uuid::new_v4().to_string(),
                                generation: 1,
                                worker_id: "w".into(),
                                process_exit_confirmed: false,
                                evidence: serde_json::Value::Null,
                            },
                        },
                    },
                    &NoReplacement,
                )
                .await
        });
    }
    barrier.wait().await;
    wait_for_waiters(&admin, &schema, "pg_advisory_xact_lock(46001338)", 3).await;
    assert_eq!(handoffs.len(), 4);
    // The real pump owns this same leader while performing ordinary catalog or
    // admission writes. Three handoff waiters must not consume its fourth permit.
    tokio::time::timeout(
        Duration::from_secs(2),
        store.create_requirement(requirement("p", "pump-progress")),
    )
    .await
    .expect("writer/leader inversion prevented the current pump from making progress")
    .unwrap();
    assert_eq!(
        waiters(&admin, &schema, "pg_advisory_xact_lock(46001338)").await,
        3
    );
    leadership.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(result) = handoffs.join_next().await {
            match result.unwrap().unwrap_err() {
                StoreError::Domain(error) => assert_eq!(error.code, "NOT_FOUND"),
                error => panic!("unexpected lock fixture error: {error}"),
            }
        }
    })
    .await
    .expect("handoff gates did not release after actual leadership completion");
    assert_eq!(store.list_requirements("p").await.unwrap().len(), 1);
    cleanup(store, schema, admin).await;
}
