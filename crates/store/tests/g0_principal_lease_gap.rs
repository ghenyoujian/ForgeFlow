//! Characterization of the current Store trust boundary, not G0 qualification.
//! Only run against the guard-verified, private fixture cluster. No HTTP or
//! authenticated-user authorization is exercised; no external worker starts.
//! This intentionally records a current gap; once authority is fixed, replace
//! the expected admission with a denial and update this characterization.
#[path = "authority.rs"]
mod authority;

use forgeflow_domain::AttemptState;

fn require_private_fixture() {
    let url = std::env::var("ECP_DATABASE_URL").expect("BLOCKED: ECP_DATABASE_URL is required");
    let actual = std::env::var("DATABASE_URL").expect("BLOCKED: DATABASE_URL is required");
    assert_eq!(actual, url, "BLOCKED: Store URL differs from guarded URL");
    assert!(
        std::env::vars_os().all(|(key, _)| !key.to_string_lossy().starts_with("PG")),
        "BLOCKED: inherited PostgreSQL environment options are forbidden"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
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
    let output = guard_command
        .arg(root.join("ops/ecp/test_database.sh"))
        .current_dir(root)
        .output()
        .expect("BLOCKED: cannot invoke private database guard");
    assert!(
        output.status.success(),
        "BLOCKED: private database guard refused the fixture: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("invalid database guard receipt");
    assert_eq!(
        value["status"], "PASS",
        "BLOCKED: disposable identity not confirmed"
    );
}

#[tokio::test]
#[ignore = "private fixture PostgreSQL only; characterization, not product authorization or Gate"]
async fn store_claim_can_be_valid_without_principal_or_grant_binding() {
    require_private_fixture();
    let (store, schema, admin) = authority::setup().await;
    let tasks = authority::fixture(&store).await;
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM principals),(SELECT count(*) FROM capability_grants)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        counts,
        (0, 0),
        "fixture must start with no principals or grants"
    );

    // Store::admit is called directly: this is NOT an HTTP auth bypass claim.
    let mut request = authority::request(&tasks[0], "fixture-principal-gap");
    request.actor_id = "fixture:no-such-principal".into();
    let result = store.admit(request).await.unwrap();
    let a = &result.attempt;
    assert_eq!(a.state, AttemptState::Leased);
    assert!(
        !store
            .attempt_control("p", &a.attempt_id, a.generation, "w")
            .await
            .unwrap()
            .valid
    );
    let claim = store
        .claim("w", "p")
        .await
        .unwrap()
        .expect("fixture claim missing");
    assert_eq!(claim.attempt_id, a.attempt_id);
    assert_eq!(claim.lease_id, a.lease_id);
    assert!(
        store
            .attempt_control("p", &a.attempt_id, a.generation, "w")
            .await
            .unwrap()
            .valid
    );
    assert!(
        !store
            .attempt_control("p", &a.attempt_id, a.generation + 1, "w")
            .await
            .unwrap()
            .valid
    );
    assert!(
        !store
            .attempt_control("p", &a.attempt_id, a.generation, "fixture-wrong-worker")
            .await
            .unwrap()
            .valid
    );
    let facts: (i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM principals),(SELECT count(*) FROM capability_grants),(SELECT count(*) FROM leases WHERE lease_id=$1 AND attempt_id=$2 AND generation=$3 AND worker_id='w'),(SELECT count(*) FROM outbox WHERE operation_id=$4 AND kind='attempt.start' AND claimed_by='w' AND delivered_at IS NOT NULL)")
        .bind(&a.lease_id).bind(&a.attempt_id).bind(a.generation).bind(&a.operation_id)
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(facts, (0, 0, 1, 1));
    println!(
        "{{\"fixture_only\":true,\"principal_count\":0,\"grant_count\":0,\"lease_count\":1,\"confirmed_dispatch_count\":1,\"preclaim_valid\":false,\"postclaim_valid\":true,\"wrong_worker_valid\":false,\"wrong_generation_valid\":false,\"product_gate_effect\":\"NONE\"}}"
    );
    authority::cleanup(store, schema, admin).await;
}
