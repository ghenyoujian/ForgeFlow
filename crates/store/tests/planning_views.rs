//! Real PostgreSQL read-model regression; temporary accounting fixtures grant no execution.
use forgeflow_domain::{AuthorityMode, DataOrigin, Project};
use forgeflow_store::{Store, TaskListFilter};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL DATABASE_URL; run with --ignored"]
async fn resource_projection_keeps_native_charges_and_exact_empty_counts() {
    let url = std::env::var("DATABASE_URL").expect("disposable PostgreSQL URL required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("planning_views_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options: PgConnectOptions = url.parse().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    let store = Store::from_pool(pool);
    store.migrate().await.unwrap();
    store
        .create_project(Project {
            project_id: "p".into(),
            name: "read model regression".into(),
            root_path: "/tmp/planning-view-fixture".into(),
            authority_mode: AuthorityMode::ObservedReadOnly,
            data_origin: DataOrigin::Demo,
            goal: "accounting projection only; zero attempts or models".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: true,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    // Temporary charge tables deliberately avoid claiming legal Attempt/Native
    // lifecycle provenance. They exercise projection, never admission or release.
    sqlx::query("CREATE TEMP TABLE resource_allocations(allocation_id TEXT,project_id TEXT,attempt_id TEXT,scope_id TEXT,dimension TEXT,amount BIGINT,state TEXT)")
        .execute(store.pool()).await.unwrap();
    sqlx::query("CREATE TEMP TABLE native_child_allocations(resource_allocation_id TEXT,project_id TEXT,attempt_id TEXT,scope_id TEXT,dimension TEXT,amount BIGINT,state TEXT)")
        .execute(store.pool()).await.unwrap();
    sqlx::query(
        "INSERT INTO resource_scopes(scope_id,project_id,revision,data) VALUES('scope','p',1,'{}')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO resource_limits(scope_id,dimension,hard_limit,allocated) VALUES('scope','active_slot',4,3)")
        .execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO resource_allocations VALUES('root','p','fixture','scope','active_slot',1,'HELD'),('released','p','fixture','scope','active_slot',7,'RELEASED')")
        .execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO native_child_allocations VALUES('child','p','fixture','scope','active_slot',2,'QUARANTINED'),('released-child','p','fixture','scope','active_slot',5,'RELEASED')")
        .execute(store.pool()).await.unwrap();
    let projection = store.resource_overview().await.unwrap();
    assert_eq!(projection["data"]["usage"][0]["allocated"], 3);
    assert_eq!(
        projection["data"]["allocations"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        projection["data"]["native_allocations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(projection["data"]["native_allocations"][0]["amount"], 2);
    assert_eq!(projection["data"]["allocation_scope"], "unreleased");
    assert_eq!(projection["version_vector"]["p"], 1);
    assert_eq!(projection["data"]["workers"], json!([]));
    let page = store
        .task_page("p", &TaskListFilter::default(), None, 500)
        .await
        .unwrap();
    assert_eq!(page["total_count"], 0);
    assert_eq!(page["data"], json!([]));
    assert_eq!(page["next_cursor"], Value::Null);
    let portfolio = store.portfolio_overview().await.unwrap();
    assert_eq!(portfolio.len(), 1);
    assert_eq!(portfolio[0]["task_progress"], Value::Null);
    assert_eq!(portfolio[0]["active_attempts"], 0);
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
