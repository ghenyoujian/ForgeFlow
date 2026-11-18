//! Focused PostgreSQL checks for committed, scoped notification projections.
//! Seeded rows exercise the read contract; this is not Worker/Gate qualification.
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

fn error_code(error: &StoreError) -> &str {
    match error {
        StoreError::Domain(error) => &error.code,
        _ => "DATABASE_ERROR",
    }
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn notifications_require_committed_release_and_replay_only_exact_worker_scope() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("dispatch_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let isolated = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |connection, _| {
            let isolated = isolated.clone();
            Box::pin(async move {
                sqlx::query(&format!("SET search_path TO {isolated}"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let store = Store::from_pool(pool);
    store.migrate().await.unwrap();
    for project in ["p", "q"] {
        sqlx::query("INSERT INTO projects(project_id,revision,authority_mode,data) VALUES($1,1,'MANAGED',$2)")
            .bind(project).bind(json!({"project_id":project,"revision":1,"authority_mode":"MANAGED","paused":false,"archived":false,"root_path":format!("/tmp/{schema}/{project}")}))
            .execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO owner_nodes(project_id,owner_id,data) VALUES($1,'team','{}')")
            .bind(project)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO flow_revisions(project_id,flow_revision,revision,state,input_digest,data) VALUES($1,1,1,'COMMITTED','digest','{}')")
            .bind(project).execute(store.pool()).await.unwrap();
    }
    for (worker, project) in [("w", "p"), ("other-worker", "p"), ("q-worker", "q")] {
        sqlx::query("INSERT INTO workers(worker_id,boot_id,capabilities,project_id,executor_profile_ids) VALUES($1,'boot','[]',$2,'[]')")
            .bind(worker).bind(project).execute(store.pool()).await.unwrap();
    }
    sqlx::query("INSERT INTO resource_scopes(scope_id,revision,data) VALUES('global',1,'{}')")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO resource_limits(scope_id,dimension,hard_limit,allocated) VALUES('global','active_slot',10,3)")
        .execute(store.pool()).await.unwrap();
    for (project, worker, attempt, state, released) in [
        ("p", "w", "author", "RUNNING", false),
        ("p", "other-worker", "other", "FAILED", true),
        ("p", "w", "successor", "LEASED", false),
        ("p", "w", "partial-release", "FAILED", false),
        ("q", "q-worker", "cross-project", "FAILED", true),
    ] {
        let terminal = matches!(state, "FAILED" | "SUCCEEDED" | "CANCELLED");
        sqlx::query("INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,fence_epoch,revision,data) VALUES($1,$2,1,1,'team','team','READY_FOR_ADMISSION','digest',1,1,'{}')")
            .bind(project).bind(attempt).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO task_revisions(project_id,task_id,task_revision,data) VALUES($1,$2,1,'{}')")
            .bind(project).bind(attempt).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,terminal_at,data,envelope) VALUES($1,$2,$2,1,$3,1,$4,$5,$6,1,CASE WHEN $7 THEN clock_timestamp() ELSE NULL END,$8,'{}')")
            .bind(project).bind(attempt).bind(format!("lease:{attempt}"))
            .bind(worker).bind(format!("operation:{attempt}")).bind(state).bind(terminal)
            .bind(json!({"project_id":project,"attempt_id":attempt,"task_id":attempt,"state":state,"generation":1,"base_sha":"a".repeat(40)}))
            .execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(project_id,lease_id,attempt_id,generation,worker_id,capability_scope,issued_at,expires_at,revoked_at) VALUES($1,$2,$3,1,$4,'[]',clock_timestamp(),clock_timestamp()+interval '1 hour',CASE WHEN $5 THEN clock_timestamp() ELSE NULL END)")
            .bind(project).bind(format!("lease:{attempt}")).bind(attempt).bind(worker).bind(terminal)
            .execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO resource_allocations(allocation_id,project_id,attempt_id,scope_id,dimension,amount,state,released_at) VALUES($1,$2,$3,'global','active_slot',1,$4,CASE WHEN $5 THEN clock_timestamp() ELSE NULL END)")
            .bind(format!("allocation:{attempt}")).bind(project).bind(attempt)
            .bind(if released {"RELEASED"} else {"HELD"}).bind(released)
            .execute(store.pool()).await.unwrap();
    }
    for (project, seq, attempt, kind) in [
        ("p", 1, "author", "attempt.succeeded"), // Forged event cannot turn a RUNNING row terminal.
        ("p", 2, "other", "attempt.execution_returned"),
        ("p", 3, "successor", "attempt.leased"),
        ("p", 4, "partial-release", "attempt.succeeded"),
        ("q", 1, "cross-project", "attempt.succeeded"),
    ] {
        sqlx::query("INSERT INTO events(event_id,project_id,project_seq,object_id,object_revision,schema_version,kind,payload) VALUES($1,$2,$3,$4,1,'forgeflow.event.v1',$5,$6)")
            .bind(format!("event:{project}:{seq}")).bind(project).bind(seq as i64).bind(attempt).bind(kind)
            .bind(json!({"state":"SUCCEEDED","worker_id":"forged-worker","model_context":"SECRET_MODEL_CONTEXT"}))
            .execute(store.pool()).await.unwrap();
    }
    sqlx::query("UPDATE projects SET event_seq=CASE WHEN project_id='p' THEN 4 ELSE 1 END")
        .execute(store.pool())
        .await
        .unwrap();
    let first = store.worker_dispatch_events("w", "p", 0, 2).await.unwrap();
    assert_eq!(first.len(), 1);
    let first = serde_json::to_value(&first[0]).unwrap();
    assert_eq!(first["kind"], "CURSOR");
    assert_eq!(first["project_seq"], 2);
    assert!(first.get("attempt_id").is_none());
    let page = store.worker_dispatch_events("w", "p", 2, 2).await.unwrap();
    let page = serde_json::to_value(page).unwrap();
    assert_eq!(page[0]["kind"], "HANDOFF_WAKE");
    assert_eq!(page[0]["attempt_id"], "successor");
    assert_eq!(page[0]["worker_id"], "w");
    assert_eq!(page[0]["project_id"], "p");
    assert_eq!(page[1]["kind"], "CURSOR");
    assert_eq!(page[1]["project_seq"], 4);
    assert!(!page.to_string().contains("SECRET_MODEL_CONTEXT"));
    assert_eq!(
        error_code(
            &store
                .worker_dispatch_events("w", "q", 0, 512)
                .await
                .unwrap_err()
        ),
        "WORKER_SCOPE_DENIED"
    );
    assert_eq!(
        error_code(
            &store
                .worker_dispatch_events("unknown", "p", 0, 512)
                .await
                .unwrap_err()
        ),
        "WORKER_SCOPE_DENIED"
    );
    assert_eq!(
        error_code(
            &store
                .worker_dispatch_events("w", "p", 5, 512)
                .await
                .unwrap_err()
        ),
        "SNAPSHOT_REQUIRED"
    );

    let mut closing = store.pool().begin().await.unwrap();
    sqlx::query("UPDATE attempts SET state='FAILED',revision=2,terminal_at=clock_timestamp(),data=jsonb_set(data,'{state}','\"FAILED\"') WHERE attempt_id='author'")
        .execute(&mut *closing).await.unwrap();
    sqlx::query("UPDATE leases SET revoked_at=clock_timestamp() WHERE attempt_id='author'")
        .execute(&mut *closing)
        .await
        .unwrap();
    sqlx::query("UPDATE resource_allocations SET state='RELEASED',released_at=clock_timestamp() WHERE attempt_id='author'")
        .execute(&mut *closing).await.unwrap();
    sqlx::query("UPDATE resource_limits SET allocated=allocated-1 WHERE scope_id='global' AND dimension='active_slot'")
        .execute(&mut *closing).await.unwrap();
    sqlx::query("UPDATE projects SET event_seq=5 WHERE project_id='p'")
        .execute(&mut *closing)
        .await
        .unwrap();
    sqlx::query("INSERT INTO events VALUES('real-terminal','p',5,'author',2,'forgeflow.event.v1','attempt.execution_returned',$1,clock_timestamp())")
        .bind(json!({"model_context":"SECRET_MODEL_CONTEXT"})).execute(&mut *closing).await.unwrap();
    assert!(
        store
            .worker_dispatch_events("w", "p", 4, 512)
            .await
            .unwrap()
            .is_empty()
    );
    closing.commit().await.unwrap();
    let facts = store
        .worker_dispatch_events("w", "p", 4, 512)
        .await
        .unwrap();
    let terminal = serde_json::to_value(&facts[0]).unwrap();
    assert_eq!(terminal["kind"], "TERMINAL");
    assert_eq!(terminal["state"], "FAILED");
    for (key, expected) in [
        ("project_id", json!("p")),
        ("worker_id", json!("w")),
        ("attempt_id", json!("author")),
        ("lease_id", json!("lease:author")),
        ("generation", json!(1)),
        ("task_id", json!("author")),
        ("task_revision", json!(1)),
        ("operation_id", json!("operation:author")),
        ("base_sha", json!("a".repeat(40))),
    ] {
        assert_eq!(terminal[key], expected);
    }
    assert_eq!(terminal["project_seq"], 5);
    let history = serde_json::to_value(
        store
            .worker_dispatch_events("w", "p", 0, 512)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        history
            .as_array()
            .unwrap()
            .iter()
            .filter(|fact| fact["kind"] == "TERMINAL")
            .map(|fact| fact["project_seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![5]
    );
    let replay = serde_json::to_value(
        store
            .worker_dispatch_events("w", "p", 4, 512)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(replay[0], terminal);
    assert!(
        store
            .worker_dispatch_events("w", "p", 5, 512)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!replay.to_string().contains("SECRET_MODEL_CONTEXT"));
    assert!(!replay.to_string().contains("other-worker"));
    assert_eq!(
        terminal["schema_version"],
        Value::String("forgeflow.worker_dispatch.v1".into())
    );
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
