//! One database-session ownership regression. No schema/data changes, model,
//! Worker or production endpoints. Requires a dedicated local next_* database.
use forgeflow_store::{Store, StoreError, core_authority::CoreAuthorityGuard};
use sqlx::postgres::PgConnectOptions;
use std::time::{Duration, Instant};

fn code(error: &StoreError) -> &str {
    match error {
        StoreError::Domain(error) => &error.code,
        _ => "NOT_DOMAIN_ERROR",
    }
}

async fn eventually_acquire(store: &Store) -> CoreAuthorityGuard {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match store.acquire_core_authority().await {
                Ok(guard) => break guard,
                Err(error) if code(&error) == "CORE_AUTHORITY_HELD" => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(error) => panic!("unexpected Core ownership failure: {error}"),
            }
        }
    })
    .await
    .expect("closed dedicated session must release its database lock")
}

#[tokio::test]
#[ignore = "requires dedicated local next_* PostgreSQL DATABASE_URL, no running Core"]
async fn core_authority_is_database_wide_dedicated_and_loss_is_permanent() {
    let url = std::env::var("DATABASE_URL").expect("isolated DATABASE_URL required");
    let options: PgConnectOptions = url
        .parse()
        .expect("valid isolated PostgreSQL configuration required");
    assert!(
        options
            .get_database()
            .is_some_and(|database| database.starts_with("next_")),
        "ownership failure injection requires a dedicated next_* database"
    );
    assert!(
        matches!(options.get_host(), "127.0.0.1" | "::1" | "localhost")
            && !matches!(options.get_port(), 5432 | 55432),
        "ownership failure injection refuses production/default database ports"
    );

    let first = Store::connect_with_options(options.clone()).await.unwrap();
    let alternate = options.options([("search_path", "core_authority_alternate,public")]);
    let second = Store::connect_with_options(alternate).await.unwrap();
    let held = first
        .acquire_core_authority()
        .await
        .expect("the isolated database must not have another running Core");
    let held_pid = held.backend_pid();
    assert_eq!(
        code(&second.acquire_core_authority().await.unwrap_err()),
        "CORE_AUTHORITY_HELD",
        "different Store/schema/data-root candidates cannot form another Core"
    );

    // Dedicated ownership cannot accidentally follow the ordinary pool's
    // checkout/release hooks or migrate to another pooled backend.
    let mut ordinary = first.pool().acquire().await.unwrap();
    let ordinary_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *ordinary)
        .await
        .unwrap();
    assert_ne!(ordinary_pid, held_pid);
    drop(ordinary);
    tokio::join!(
        first.pool().close(),
        first.control_pool().close(),
        first.dispatch_pool().close()
    );
    assert_eq!(
        code(&second.acquire_core_authority().await.unwrap_err()),
        "CORE_AUTHORITY_HELD",
        "closing ordinary pools must not release dedicated ownership"
    );

    // Drop closes the socket; the backend releases its session lock. A normal
    // explicit close also releases ownership without a pooled session leak.
    drop(held);
    let normal = eventually_acquire(&second).await;
    assert_ne!(normal.backend_pid(), held_pid);
    normal.close().await.unwrap();
    let mut killed = eventually_acquire(&second).await;
    let killed_pid = killed.backend_pid();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(killed_pid)
        .fetch_one(second.control_pool())
        .await
        .unwrap();
    assert!(terminated);
    let failure = tokio::time::timeout(Duration::from_secs(4), killed.wait_for_loss())
        .await
        .expect("ownership connection death must be detected within the bounded check window");
    assert_eq!(code(&failure), "CORE_AUTHORITY_LOST");

    let successor = eventually_acquire(&second).await;
    assert_ne!(successor.backend_pid(), killed_pid);
    let started = Instant::now();
    assert_eq!(code(&killed.wait_for_loss().await), "CORE_AUTHORITY_LOST");
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "failed guard must stay failed without reconnect/query retries"
    );
    assert_eq!(
        killed.backend_pid(),
        killed_pid,
        "failed guard never changes backend identity"
    );
    drop(killed);
    assert_eq!(
        code(&second.acquire_core_authority().await.unwrap_err()),
        "CORE_AUTHORITY_HELD",
        "dropping an obsolete guard cannot release the successor session's lock"
    );
    successor.close().await.unwrap();
    tokio::join!(
        second.pool().close(),
        second.control_pool().close(),
        second.dispatch_pool().close()
    );
}
