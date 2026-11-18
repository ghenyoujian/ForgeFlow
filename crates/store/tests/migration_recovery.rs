use forgeflow_store::Store;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{str::FromStr, time::Duration};
use tokio::time::{sleep, timeout};
async fn locks(admin: &PgPool, app: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.granted AND a.application_name=$1").bind(app).fetch_one(admin).await.unwrap()
}
async fn settle(admin: &PgPool, app: &str) -> i64 {
    for _ in 0..60 {
        let n = locks(admin, app).await;
        if n == 0 {
            return n;
        }
        sleep(Duration::from_millis(100)).await;
    }
    locks(admin, app).await
}
// This test modifies migration data and only runs after the repository guard
// validates its private disposable cluster, marker, socket, and postmaster.
// Provision the cluster as shown in ops/ecp/tests/test_database_guard.py.
#[tokio::test]
#[ignore = "requires the guarded disposable PostgreSQL fixture"]
async fn failed_and_cancelled_migrations_release_advisory_lock() {
    assert!(
        std::env::vars_os().all(|(key, _)| !key.to_string_lossy().starts_with("PG")),
        "PG environment overrides are forbidden"
    );
    let url = std::env::var("ECP_DATABASE_URL").expect("guarded database URL required");
    let guard =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/ecp/test_database.sh");
    let mut guard_command = std::process::Command::new("/usr/bin/bash");
    // Keep the child guard tied to the parent's URL. Shell and Python startup
    // hooks must not be able to replace it before the guard reads it.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("PYTHON")
            || name.starts_with("BASH_FUNC_")
            || matches!(
                name.as_ref(),
                "BASH_ENV"
                    | "ENV"
                    | "SHELLOPTS"
                    | "BASHOPTS"
                    | "CDPATH"
                    | "GLOBIGNORE"
                    | "LD_PRELOAD"
                    | "LD_AUDIT"
            )
        {
            guard_command.env_remove(key);
        }
    }
    guard_command.env("ECP_DATABASE_URL", &url);
    let status = guard_command
        .arg(guard)
        .status()
        .expect("disposable database guard could not execute");
    assert!(
        status.success(),
        "disposable database guard rejected the fixture"
    );
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let actual: String = sqlx::query_scalar("SHOW data_directory")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(
        actual,
        std::env::var("ECP_DATABASE_EXPECTED_DATA_DIR").unwrap()
    );
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(db.starts_with("ecp_disposable_"));
    let existing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN ('r','p','v','m','S')",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(existing, 0, "the disposable database must start empty");
    let opts = PgConnectOptions::from_str(&url)
        .unwrap()
        .application_name("ecp_store_failure_probe");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    timeout(Duration::from_secs(120), store.migrate())
        .await
        .expect("initial migration timeout")
        .expect("initial migration error");
    let original: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations ORDER BY version LIMIT 1")
            .fetch_one(&admin)
            .await
            .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum=decode('000102','hex') WHERE version=(SELECT min(version) FROM _sqlx_migrations)").execute(&admin).await.unwrap();
    let failure = timeout(Duration::from_secs(10), store.migrate())
        .await
        .expect("failure timeout")
        .expect_err("expected checksum mismatch");
    println!("failure={failure}");
    assert!(
        failure
            .to_string()
            .contains("previously applied but has been modified")
    );
    let failure_locks = settle(&admin, "ecp_store_failure_probe").await;
    println!("failure_granted_advisory_locks={failure_locks}");
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=(SELECT min(version) FROM _sqlx_migrations)").bind(original).execute(&admin).await.unwrap();
    let held = pool.acquire().await.unwrap();
    let retry = timeout(Duration::from_secs(8), store.migrate()).await;
    println!(
        "same_pool_different_connection_retry={:?}",
        retry
            .as_ref()
            .map(|x| x.as_ref().map(|_| "ok").map_err(|e| e.to_string()))
    );
    assert_eq!(failure_locks, 0);
    assert!(matches!(retry, Ok(Ok(()))));
    drop(held);
    pool.close().await;
    let opts = PgConnectOptions::from_str(&url)
        .unwrap()
        .application_name("ecp_store_cancel_probe");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .unwrap();
    let store = Store::from_pool(pool.clone());
    let mut blocker = admin.begin().await.unwrap();
    sqlx::query("LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let handle = tokio::spawn(async move { store.migrate().await });
    let mut blocked = false;
    for _ in 0..100 {
        let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.granted AND a.application_name='ecp_store_cancel_probe' AND a.wait_event_type='Lock'").fetch_one(&admin).await.unwrap();
        if n == 1 {
            blocked = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        blocked,
        "migration never confirmed holding advisory lock and waiting for table"
    );
    handle.abort();
    let _ = handle.await;
    blocker.rollback().await.unwrap();
    let cancel_locks = settle(&admin, "ecp_store_cancel_probe").await;
    println!("cancel_granted_advisory_locks={cancel_locks}");
    let held = pool.acquire().await.unwrap();
    let store = Store::from_pool(pool.clone());
    let retry = timeout(Duration::from_secs(8), store.migrate()).await;
    println!(
        "cancel_same_pool_different_connection_retry={:?}",
        retry
            .as_ref()
            .map(|x| x.as_ref().map(|_| "ok").map_err(|e| e.to_string()))
    );
    assert_eq!(cancel_locks, 0);
    assert!(matches!(retry, Ok(Ok(()))));
    drop(held);
    pool.close().await;
    admin.close().await;
}
