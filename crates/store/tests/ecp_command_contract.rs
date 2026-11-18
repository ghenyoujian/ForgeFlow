//! Real Store contract checks against a guard-verified empty disposable cluster.
//! These synthetic accounts test Store authorization; they do not test HTTP login
//! or stand in for a formally admitted ECP principal or lease.
use forgeflow_domain::{AuthorityMode, CatalogCommand, CommandIdentity, DataOrigin, Project};
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

fn identity(account: &str, workspace: &str, key: &str) -> CommandIdentity {
    CommandIdentity {
        actor_id: format!("account:{account}@workspace:{workspace}"),
        idempotency_key: key.into(),
    }
}
fn document(id: &str, revision: Option<u64>, value: i64) -> CatalogCommand {
    CatalogCommand::PutDocument {
        project_id: "p004-project".into(),
        collection: "operations".into(),
        id: id.into(),
        expected_revision: revision,
        value: json!({"kind":"P004_FIXTURE","value":value}),
    }
}
fn expect_code(error: StoreError, expected: &str) {
    match error {
        StoreError::Domain(domain) => assert_eq!(domain.code, expected),
        other => panic!("expected {expected}, got {other}"),
    }
}

#[tokio::test]
#[ignore = "requires the guarded disposable PostgreSQL fixture"]
async fn catalog_replay_revision_and_revoked_member() {
    assert!(
        std::env::vars_os().all(|(key, _)| !key.to_string_lossy().starts_with("PG")),
        "PG environment overrides are forbidden"
    );
    let url = std::env::var("ECP_DATABASE_URL").expect("guarded database URL required");
    let guard =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/ecp/test_database.sh");
    // The local fixture operator must provide a trusted PATH and, when needed,
    // LD_LIBRARY_PATH for the PostgreSQL installation. All other inherited
    // variables are cleared so shell/Python startup hooks cannot run.
    let mut command = std::process::Command::new("/usr/bin/bash");
    command.env_clear().env("ECP_DATABASE_URL", &url);
    for name in [
        "PATH",
        "LD_LIBRARY_PATH",
        "ECP_DATABASE_DISPOSABLE",
        "ECP_DATABASE_EXPECTED_DATA_DIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let status = command
        .arg(guard)
        .status()
        .expect("disposable database guard could not execute");
    assert!(
        status.success(),
        "disposable database guard rejected the fixture"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let existing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN ('r','p','v','m','S')",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(
        existing, 0,
        "the guarded disposable database must start empty"
    );
    let store = Store::from_pool(pool.clone());
    store.migrate().await.unwrap();

    let owner = store
        .register_account("owner@p004.invalid", "fixture owner", "fixture-no-login")
        .await
        .unwrap();
    let editor = store
        .register_account("editor@p004.invalid", "fixture editor", "fixture-no-login")
        .await
        .unwrap();
    let owner_id = owner["account_id"].as_str().unwrap();
    let workspace = owner["workspace_id"].as_str().unwrap();
    let editor_id = editor["account_id"].as_str().unwrap();
    store
        .create_workspace_invitation(
            owner_id,
            workspace,
            "EDITOR",
            Some("editor@p004.invalid"),
            "p004-fixture-token-hash",
        )
        .await
        .unwrap();
    store
        .accept_workspace_invitation(editor_id, "p004-fixture-token-hash")
        .await
        .unwrap();
    assert_eq!(
        store
            .workspace_role(editor_id, workspace)
            .await
            .unwrap()
            .as_deref(),
        Some("EDITOR")
    );
    let project = Project {
        project_id: "p004-project".into(),
        name: "fixture".into(),
        root_path: "/tmp/p004-fixture".into(),
        authority_mode: AuthorityMode::Managed,
        data_origin: DataOrigin::Native,
        goal: "contract fixture".into(),
        technology_stack: vec![],
        timezone: "UTC".into(),
        paused: false,
        archived: false,
        revision: 1,
    };
    store
        .execute_command(
            identity(owner_id, workspace, "p004-project-create"),
            CatalogCommand::CreateProject(project),
        )
        .await
        .unwrap();

    let original = document("p004-doc", None, 1);
    let first = store
        .execute_command(
            identity(editor_id, workspace, "p004-replay-key"),
            original.clone(),
        )
        .await
        .unwrap();
    let replay = store
        .execute_command(
            identity(editor_id, workspace, "p004-replay-key"),
            original.clone(),
        )
        .await
        .unwrap();
    assert!(!first.replayed && replay.replayed);
    assert_eq!(first.operation_id, replay.operation_id);
    assert_eq!(first.value, replay.value);
    let error = store
        .execute_command(
            identity(editor_id, workspace, "p004-replay-key"),
            document("p004-doc", None, 2),
        )
        .await
        .unwrap_err();
    expect_code(error, "IDEMPOTENCY_CONFLICT");
    let actor = format!("account:{editor_id}@workspace:{workspace}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM idempotency_records WHERE actor_id=$1 AND operation='catalog' AND idempotency_key='p004-replay-key'").bind(&actor).fetch_one(&pool).await.unwrap();
    assert_eq!(rows, 1);
    let (revision, value): (i64, Value) = sqlx::query_as("SELECT revision,data FROM documents WHERE project_id='p004-project' AND collection='operations' AND document_id='p004-doc'").fetch_one(&pool).await.unwrap();
    assert_eq!(revision, 1);
    assert_eq!(value["value"], 1);
    println!("idempotency_rows={rows} revision_after_conflict={revision} same_operation_id=true");

    let conflict = store
        .execute_command(
            identity(editor_id, workspace, "p004-create-again"),
            document("p004-doc", None, 3),
        )
        .await
        .unwrap_err();
    expect_code(conflict, "REVISION_CONFLICT");
    store
        .execute_command(
            identity(editor_id, workspace, "p004-update"),
            document("p004-doc", Some(1), 4),
        )
        .await
        .unwrap();
    let stale = store
        .execute_command(
            identity(editor_id, workspace, "p004-stale"),
            document("p004-doc", Some(1), 5),
        )
        .await
        .unwrap_err();
    expect_code(stale, "REVISION_CONFLICT");
    let (revision, value): (i64, Value) = sqlx::query_as("SELECT revision,data FROM documents WHERE project_id='p004-project' AND collection='operations' AND document_id='p004-doc'").fetch_one(&pool).await.unwrap();
    assert_eq!(revision, 2);
    assert_eq!(value["value"], 4);
    let rejected_records: i64 = sqlx::query_scalar("SELECT count(*) FROM idempotency_records WHERE actor_id=$1 AND idempotency_key IN ('p004-create-again','p004-stale')").bind(&actor).fetch_one(&pool).await.unwrap();
    assert_eq!(rejected_records, 0);
    println!("revision_after_exact_update={revision} rejected_revision_records={rejected_records}");

    let member_revision: i64 = sqlx::query_scalar("SELECT revision FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL").bind(workspace).bind(editor_id).fetch_one(&pool).await.unwrap();
    store
        .change_workspace_member(owner_id, workspace, editor_id, None, Some(member_revision))
        .await
        .unwrap();
    let denied = store
        .execute_command(identity(editor_id, workspace, "p004-replay-key"), original)
        .await
        .unwrap_err();
    expect_code(denied, "FORBIDDEN");
    let role = store.workspace_role(editor_id, workspace).await.unwrap();
    assert!(role.is_none());
    let count_after: i64 = sqlx::query_scalar("SELECT count(*) FROM idempotency_records WHERE actor_id=$1 AND operation='catalog' AND idempotency_key='p004-replay-key'").bind(&actor).fetch_one(&pool).await.unwrap();
    assert_eq!(count_after, 1);
    println!("revoked_replay=FORBIDDEN original_idempotency_rows={count_after}");
    pool.close().await;
}
