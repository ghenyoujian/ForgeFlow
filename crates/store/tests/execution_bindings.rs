//! One isolated PostgreSQL storage/admission regression; no OS or model effects.
//! Run only `frozen_executor_profiles_share_without_changing_binding_authority`.
//! The shared authority module supplies its existing setup and admission fixture.
#[path = "authority.rs"]
mod authority;

use forgeflow_domain::{AuthorityMode, DataOrigin, Project};
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};

fn profile_hash(profile: &Value) -> String {
    forgeflow_planner::sha256(
        &serde_json::to_vec(&json!(["forgeflow.frozen-executor-profile.v1", profile])).unwrap(),
    )
}

fn retained_binding_hash(bindings: &Value) -> String {
    forgeflow_planner::sha256(
        &serde_json::to_vec(&json!(["forgeflow.retained-source.bindings.v1", bindings])).unwrap(),
    )
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
}

fn domain_code(error: &StoreError) -> &str {
    match error {
        StoreError::Domain(error) => &error.code,
        _ => "NOT_DOMAIN_ERROR",
    }
}

// Explicit terminal storage fixtures exercise historical/corrupt representation
// reads. They never acquire a lease, resource, outbox start or acceptance receipt.
async fn terminal_storage_fixture(
    store: &Store,
    source: &str,
    id: &str,
    bindings: &Value,
    digest: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,\
         worker_id,operation_id,state,revision,created_at,terminal_at,data,envelope,\
         execution_bindings,executor_profile_sha256) \
         SELECT project_id,$2,task_id,task_revision,$2||'-lease',generation,worker_id,\
         $2||'-operation','CANCELLED',1,clock_timestamp(),clock_timestamp(),\
         data||jsonb_build_object('attempt_id',$2::text,'state','CANCELLED',\
         'lease_id',$2||'-lease','operation_id',$2||'-operation','terminal_at',clock_timestamp()),\
         envelope||jsonb_build_object('attempt_id',$2::text,'lease_id',$2||'-lease',\
         'operation_id',$2||'-operation'),$3,$4 FROM attempts WHERE attempt_id=$1",
    )
    .bind(source)
    .bind(id)
    .bind(bindings)
    .bind(digest)
    .execute(store.pool())
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; isolated schema, no execution qualification"]
async fn frozen_executor_profiles_share_without_changing_binding_authority() {
    let (store, schema, admin) = authority::setup().await;
    let tasks = authority::fixture(&store).await;
    let mut expected_profile = store
        .get_document("p", "executor_profiles", "exec")
        .await
        .unwrap();
    expected_profile.as_object_mut().unwrap().remove("revision");
    let expected_digest = profile_hash(&expected_profile);

    // Force failure after CAS/Attempt insertion, proving the same admission
    // transaction rolls both back and does not consume a task generation.
    sqlx::raw_sql("CREATE FUNCTION reject_fixture_lease() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated storage rollback probe'; END; $$; CREATE TRIGGER reject_fixture_lease BEFORE INSERT ON leases FOR EACH ROW EXECUTE FUNCTION reject_fixture_lease();")
        .execute(store.pool()).await.unwrap();
    let failed = store
        .admit(authority::request(&tasks[0], "cas-rollback"))
        .await
        .unwrap_err();
    assert!(matches!(failed, StoreError::Database(_)));
    let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM frozen_executor_profiles),(SELECT count(*) FROM attempts),(SELECT fence_epoch FROM tasks WHERE project_id='p' AND task_id='t0')")
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(counts, (0, 0, 0));
    sqlx::raw_sql(
        "DROP TRIGGER reject_fixture_lease ON leases; DROP FUNCTION reject_fixture_lease();",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let first = store
        .admit(authority::request(&tasks[0], "cas-first"))
        .await
        .unwrap();
    let second = store
        .admit(authority::request(&tasks[1], "cas-second"))
        .await
        .unwrap();
    let rows: Vec<(Option<String>, bool)> = sqlx::query_as("SELECT executor_profile_sha256,execution_bindings ? 'executor_profile' FROM attempts ORDER BY attempt_id")
        .fetch_all(store.pool()).await.unwrap();
    assert_eq!(rows, vec![(Some(expected_digest.clone()), false); 2]);
    let objects: i64 = sqlx::query_scalar("SELECT count(*) FROM frozen_executor_profiles")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(objects, 1);
    let first_bindings = store
        .attempt_bindings("p", &first.attempt.attempt_id)
        .await
        .unwrap();
    let second_bindings = store
        .attempt_bindings("p", &second.attempt.attempt_id)
        .await
        .unwrap();
    assert_eq!(first_bindings["executor_profile"], expected_profile);
    assert_eq!(second_bindings["executor_profile"], expected_profile);
    assert_eq!(first.envelope.executor_profile_id, "exec");
    let replay = store
        .admit(authority::request(&tasks[0], "cas-first"))
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        serde_json::to_value(&replay.attempt).unwrap(),
        serde_json::to_value(&first.attempt).unwrap()
    );

    terminal_storage_fixture(
        &store,
        &first.attempt.attempt_id,
        "legacy-inline",
        &first_bindings,
        None,
    )
    .await
    .unwrap();
    let legacy_before: Value = sqlx::query_scalar(
        "SELECT execution_bindings FROM attempts WHERE attempt_id='legacy-inline'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let legacy = store.attempt_bindings("p", "legacy-inline").await.unwrap();
    assert_eq!(legacy, first_bindings);
    assert_eq!(
        retained_binding_hash(&legacy),
        retained_binding_hash(&first_bindings)
    );
    assert_eq!(
        legacy, legacy_before,
        "reading legacy must not rewrite or reseal it"
    );
    assert_eq!(
        domain_code(
            &store
                .attempt_bindings("other", &first.attempt.attempt_id)
                .await
                .unwrap_err()
        ),
        "NOT_FOUND"
    );

    for statement in [
        "UPDATE frozen_executor_profiles SET data=data WHERE project_id='p'",
        "DELETE FROM frozen_executor_profiles WHERE project_id='p'",
        "TRUNCATE frozen_executor_profiles CASCADE",
        "UPDATE attempts SET executor_profile_sha256=NULL WHERE executor_profile_sha256 IS NOT NULL",
    ] {
        assert_eq!(
            sqlstate(
                &sqlx::query(statement)
                    .execute(store.pool())
                    .await
                    .unwrap_err()
            )
            .as_deref(),
            Some("55000")
        );
    }
    for inline in [expected_profile.clone(), Value::Null] {
        let error = sqlx::query("UPDATE attempts SET execution_bindings=jsonb_set(execution_bindings,'{executor_profile}',$2) WHERE attempt_id=$1")
            .bind(&second.attempt.attempt_id).bind(inline).execute(store.pool()).await.unwrap_err();
        assert_eq!(sqlstate(&error).as_deref(), Some("23514"));
    }

    store
        .create_project(Project {
            project_id: "q".into(),
            name: "isolated cross-project CAS fixture".into(),
            root_path: "/tmp/forgeflow-cas-other-project".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "storage isolation only".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: true,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    let mut other_profile = expected_profile.clone();
    other_profile["profile_name"] = json!("other-project-only");
    let other_digest = profile_hash(&other_profile);
    sqlx::query("INSERT INTO frozen_executor_profiles(project_id,sha256,data) VALUES('q',$1,$2)")
        .bind(&other_digest)
        .bind(&other_profile)
        .execute(store.pool())
        .await
        .unwrap();
    let mut compact = first_bindings.clone();
    compact.as_object_mut().unwrap().remove("executor_profile");
    let cross_project = terminal_storage_fixture(
        &store,
        &first.attempt.attempt_id,
        "cross-project",
        &compact,
        Some(&other_digest),
    )
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&cross_project).as_deref(), Some("23503"));
    assert_eq!(
        cross_project.as_database_error().unwrap().constraint(),
        Some("attempts_executor_profile_object_fk")
    );

    // Simulate an inconsistent imported object without disabling immutable
    // triggers. A syntactically valid key is insufficient to authorize reads.
    let wrong_digest = "0".repeat(64);
    assert_ne!(wrong_digest, expected_digest);
    sqlx::query("INSERT INTO frozen_executor_profiles(project_id,sha256,data) VALUES('p',$1,$2)")
        .bind(&wrong_digest)
        .bind(&expected_profile)
        .execute(store.pool())
        .await
        .unwrap();
    terminal_storage_fixture(
        &store,
        &first.attempt.attempt_id,
        "wrong-content-pin",
        &compact,
        Some(&wrong_digest),
    )
    .await
    .unwrap();
    assert_eq!(
        domain_code(
            &store
                .attempt_bindings("p", "wrong-content-pin")
                .await
                .unwrap_err()
        ),
        "FROZEN_EXECUTOR_PROFILE_INVALID"
    );
    let mut wrong_identity = expected_profile.clone();
    wrong_identity["id"] = json!("another-executor");
    let wrong_identity_digest = profile_hash(&wrong_identity);
    sqlx::query("INSERT INTO frozen_executor_profiles(project_id,sha256,data) VALUES('p',$1,$2)")
        .bind(&wrong_identity_digest)
        .bind(&wrong_identity)
        .execute(store.pool())
        .await
        .unwrap();
    terminal_storage_fixture(
        &store,
        &first.attempt.attempt_id,
        "wrong-profile-id",
        &compact,
        Some(&wrong_identity_digest),
    )
    .await
    .unwrap();
    assert_eq!(
        domain_code(
            &store
                .attempt_bindings("p", "wrong-profile-id")
                .await
                .unwrap_err()
        ),
        "FROZEN_EXECUTOR_PROFILE_INVALID"
    );
    assert_eq!(
        store
            .attempt_bindings("p", &second.attempt.attempt_id)
            .await
            .unwrap(),
        second_bindings
    );
    assert_eq!(
        store.attempt_bindings("p", "legacy-inline").await.unwrap(),
        legacy_before
    );
    authority::cleanup(store, schema, admin).await;
}
