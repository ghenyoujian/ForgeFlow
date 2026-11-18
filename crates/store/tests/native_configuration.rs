//! Real isolated PostgreSQL draft authority checks only; no native execution claim.
use forgeflow_domain::*;
use forgeflow_store::{Store, StoreError};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
async fn setup() -> (Store, String, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL required for PostgreSQL authority tests");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("custody_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .after_connect(move |conn, _| {
            let search = search.clone();
            Box::pin(async move {
                sqlx::query(&format!("SET search_path TO {search}"))
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let store = Store::from_pool(pool);
    store.migrate().await.unwrap();
    (store, schema, admin)
}
async fn cleanup(store: Store, schema: String, admin: sqlx::PgPool) {
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

fn code(error: &StoreError) -> &str {
    match error {
        StoreError::Domain(error) => &error.code,
        _ => "OTHER",
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL schema"]
async fn worker_capacity_draft_round_trip_and_invalid_saves_are_atomic() {
    let (store, schema, admin) = setup().await;
    store
        .create_project(Project {
            project_id: "p".into(),
            name: "native capacity draft".into(),
            root_path: "/tmp/native-capacity-editor".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "bounded per-Worker capacity".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: false,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    let base = json!({"base_executor_profile_id":"base","presets":[{"id":"preset"}],
        "plugins":[{"entry_id":"team"}],"role_bindings":[{"position_id":"position"}]});
    for (index, capacity) in [None, Some(1), Some(21), Some(64)].into_iter().enumerate() {
        let mut spec = base.clone();
        if let Some(capacity) = capacity {
            spec["max_active_attempts_per_worker"] = capacity.into();
        }
        let id = format!("valid-{index}");
        let result = store
            .execute_command(
                CommandIdentity {
                    actor_id: "native-configuration-service".into(),
                    idempotency_key: id.clone(),
                },
                CatalogCommand::NativeConfiguration {
                    project_id: "p".into(),
                    command: NativeConfigurationCommand::Save {
                        draft_id: id.clone(),
                        expected_revision: None,
                        base_config_sha256: "a".repeat(64),
                        spec: spec.clone(),
                        requested_by: "owner".into(),
                    },
                },
            )
            .await
            .unwrap();
        assert_eq!(result.value["spec"], spec);
        assert_eq!(result.value["execution_rights_granted"], false);
        assert_eq!(
            store
                .get_document("p", "native_configuration_drafts", &id)
                .await
                .unwrap(),
            result.value
        );
    }
    let mut invalid_specs = Vec::new();
    for value in [
        json!(0),
        json!(65),
        json!(-1),
        json!(true),
        json!(21.0),
        json!("21"),
        json!(null),
    ] {
        let mut spec = base.clone();
        spec["max_active_attempts_per_worker"] = value;
        invalid_specs.push(spec);
    }
    let mut unknown = base;
    unknown["max_active_attempts_per_worker"] = 21.into();
    unknown["unknown_capacity"] = 21.into();
    invalid_specs.push(unknown);
    for (index, spec) in invalid_specs.into_iter().enumerate() {
        let id = format!("invalid-{index}");
        let error = store
            .execute_command(
                CommandIdentity {
                    actor_id: "native-configuration-service".into(),
                    idempotency_key: id.clone(),
                },
                CatalogCommand::NativeConfiguration {
                    project_id: "p".into(),
                    command: NativeConfigurationCommand::Save {
                        draft_id: id.clone(),
                        expected_revision: None,
                        base_config_sha256: "a".repeat(64),
                        spec,
                        requested_by: "owner".into(),
                    },
                },
            )
            .await
            .unwrap_err();
        assert_eq!(code(&error), "VALIDATION_ERROR");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM documents WHERE project_id='p' AND collection='native_configuration_drafts' AND document_id=$1")
            .bind(&id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(count, 0, "invalid draft {id} was persisted");
    }
    cleanup(store, schema, admin).await;
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL schema"]
async fn actual_draft_cas_idempotency_and_authority() {
    let (store, schema, admin) = setup().await;
    store
        .create_project(Project {
            project_id: "p".into(),
            name: "native draft authority".into(),
            root_path: "/tmp/native-editor".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "draft guards".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: false,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    let spec = json!({"base_executor_profile_id":"base","presets":[{"id":"preset"}],"plugins":[{"entry_id":"team"}],"role_bindings":[{"position_id":"position"}]});
    let save = CatalogCommand::NativeConfiguration {
        project_id: "p".into(),
        command: NativeConfigurationCommand::Save {
            draft_id: "draft".into(),
            expected_revision: None,
            base_config_sha256: "a".repeat(64),
            spec: spec.clone(),
            requested_by: "owner".into(),
        },
    };
    let identity = CommandIdentity {
        actor_id: "native-configuration-service".into(),
        idempotency_key: "save-once".into(),
    };
    let denied = store
        .execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: "unauthorized".into(),
            },
            save.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "AUTHORITY_SCOPE_VIOLATION");
    let first = store
        .execute_command(identity.clone(), save.clone())
        .await
        .unwrap();
    let replay = store.execute_command(identity, save).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(first.value, replay.value);
    assert_eq!(first.value["revision"], 1);
    assert_eq!(first.value["execution_rights_granted"], false);
    let bypass = store
        .execute_command(
            CommandIdentity {
                actor_id: "owner".into(),
                idempotency_key: "generic-bypass".into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "native_configuration_drafts".into(),
                id: "draft".into(),
                expected_revision: Some(1),
                value: json!({"status":"PUBLISHED"}),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(code(&bypass), "COMMAND_REQUIRED");
    let stale = store
        .execute_command(
            CommandIdentity {
                actor_id: "native-configuration-service".into(),
                idempotency_key: "stale-edit".into(),
            },
            CatalogCommand::NativeConfiguration {
                project_id: "p".into(),
                command: NativeConfigurationCommand::Save {
                    draft_id: "draft".into(),
                    expected_revision: Some(2),
                    base_config_sha256: "a".repeat(64),
                    spec,
                    requested_by: "owner".into(),
                },
            },
        )
        .await
        .unwrap_err();
    assert_eq!(code(&stale), "REVISION_CONFLICT");
    let current = store
        .get_document("p", "native_configuration_drafts", "draft")
        .await
        .unwrap();
    assert_eq!(current, first.value);
    cleanup(store, schema, admin).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL schema"]
async fn activation_stages_future_worker_policy_without_registering_execution() {
    // Adding paired resource publication must not change old idempotent request
    // bytes when a historical Publish command is decoded and replayed.
    let legacy = json!({"action":"PUBLISH","draft_id":"legacy","expected_revision":2,
        "review_sha256":"a".repeat(64),"profile":{"id":"legacy"},"approved_by":"owner"});
    let decoded: NativeConfigurationCommand = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
    let (store, schema, admin) = setup().await;
    store
        .create_project(Project {
            project_id: "p".into(),
            name: "future Worker activation".into(),
            root_path: "/tmp/native-editor".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "activation lifecycle regression".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: true,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    // Isolate the activation transition from publication's composition checks.
    // This fixture is confined to this test's private PostgreSQL schema.
    let resource = json!({"id":"published-resource",
        "sandbox":{"readonly_paths":["/frozen/new-plugin.mjs"]}});
    let resource_sha = forgeflow_planner::sha256(&serde_json::to_vec(&resource).unwrap());
    store
        .execute_command(
            CommandIdentity {
                actor_id: "native-configuration-service".into(),
                idempotency_key: "register-published-resource".into(),
            },
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "resource_profiles".into(),
                id: "published-resource".into(),
                expected_revision: None,
                value: resource.clone(),
            },
        )
        .await
        .unwrap();
    let registered_resource = store
        .get_document("p", "resource_profiles", "published-resource")
        .await
        .unwrap();
    assert_eq!(registered_resource["revision"], 1);
    let published = json!({"project_id":"p","draft_id":"draft","revision":3,
        "status":"PUBLISHED","spec_sha256":"b".repeat(64),
        "published_executor_profile_id":"published","execution_rights_granted":false,
        "published_resource_profile_id":"published-resource",
        "published_resource_profile_sha256":resource_sha});
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES('p','native_configuration_drafts','draft',3,$1)")
        .bind(published).execute(store.pool()).await.unwrap();
    let policy = ResourcePolicy {
        worker_id: Some("future-worker".into()),
        scope_id: "future-worker-scope".into(),
        parent_scope_id: None,
        project_id: None,
        team_id: None,
        limits: ResourceVector {
            active_slot: 1,
            coding_slot: 1,
            provider_inflight: 1,
            ..Default::default()
        },
        revision: 1,
        paused: false,
    };
    let receipt = json!({"project_id":"p","draft_id":"draft",
        "spec_sha256":"b".repeat(64),"executor_profile_id":"published",
        "resource_profile_id":"published-resource","resource_profile_sha256":resource_sha,
        "config_sha256":"c".repeat(64),"worker_ids":["future-worker"],
        "active_attempts_modified":false,"execution_rights_granted":false});
    let activation = CatalogCommand::NativeConfiguration {
        project_id: "p".into(),
        command: NativeConfigurationCommand::Activate {
            draft_id: "draft".into(),
            expected_revision: 3,
            receipt,
            resource_policies: vec![policy.clone()],
            activated_by: "owner".into(),
        },
    };
    let mut invalid = activation.clone();
    if let CatalogCommand::NativeConfiguration {
        command: NativeConfigurationCommand::Activate { receipt, .. },
        ..
    } = &mut invalid
    {
        receipt["project_id"] = json!("another-project");
    }
    let denied = store
        .execute_command(
            CommandIdentity {
                actor_id: "native-configuration-service".into(),
                idempotency_key: "wrong-project".into(),
            },
            invalid,
        )
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "CONTEXT_STALE");
    let mut wrong_resource = activation.clone();
    if let CatalogCommand::NativeConfiguration {
        command: NativeConfigurationCommand::Activate { receipt, .. },
        ..
    } = &mut wrong_resource
    {
        receipt["resource_profile_sha256"] = json!("d".repeat(64));
    }
    let denied = store
        .execute_command(
            CommandIdentity {
                actor_id: "native-configuration-service".into(),
                idempotency_key: "wrong-resource".into(),
            },
            wrong_resource,
        )
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "CONTEXT_STALE");
    let identity = CommandIdentity {
        actor_id: "native-configuration-service".into(),
        idempotency_key: "activate-once".into(),
    };
    let first = store
        .execute_command(identity.clone(), activation.clone())
        .await
        .unwrap();
    let replay = store.execute_command(identity, activation).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(first.value, replay.value);
    assert_eq!(first.value["revision"], 4);
    assert_eq!(first.value["status"], "PUBLISHED");
    assert_eq!(first.value["execution_rights_granted"], false);
    assert_eq!(first.value["activation"]["active_attempts_modified"], false);
    assert_eq!(
        first.value["published_resource_profile_sha256"],
        resource_sha
    );
    assert_eq!(
        first.value["pending_resource_policy_updates"],
        json!([{"policy":policy,"expected_revision":null}])
    );
    for table in ["workers", "resource_scopes", "resource_limits", "attempts"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "activation created execution state in {table}");
    }
    // FK protection still applies until the ordinary registration transaction.
    assert!(
        store
            .put_resource_policy(policy.clone(), None)
            .await
            .is_err()
    );
    store
        .register_worker(WorkerRegisterRequest {
            project_id: Some("p".into()),
            executor_profile_ids: vec!["published".into()],
            worker_id: "future-worker".into(),
            boot_id: "registered-test-boot".into(),
            capabilities: vec!["published".into()],
        })
        .await
        .unwrap();
    let applied = store.put_resource_policy(policy, None).await.unwrap();
    assert_eq!(applied.worker_id.as_deref(), Some("future-worker"));
    assert_eq!(applied.revision, 1);
    cleanup(store, schema, admin).await;
}
