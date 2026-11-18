//! Public metadata fidelity and privacy over a real PostgreSQL snapshot.
//! Synthetic temporary attempts exercise projection only, not execution gates.
use forgeflow_domain::{AuthorityMode, DataOrigin, Project};
use forgeflow_store::Store;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

#[tokio::test]
#[ignore = "requires live PostgreSQL DATABASE_URL; run with --ignored"]
async fn snapshot_keeps_public_native_metadata_and_excludes_private_execution_configuration() {
    let url = std::env::var("DATABASE_URL").expect("live PostgreSQL DATABASE_URL required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("snapshot_projection_{}", uuid::Uuid::new_v4().simple());
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
            name: "metadata projection".into(),
            root_path: "/tmp/snapshot-projection-fixture".into(),
            authority_mode: AuthorityMode::Managed,
            data_origin: DataOrigin::Native,
            goal: "public metadata projection only".into(),
            technology_stack: vec![],
            timezone: "UTC".into(),
            paused: true,
            archived: false,
            revision: 1,
        })
        .await
        .unwrap();
    // The single connection deliberately shadows attempts for this metadata
    // test. No fake admission, process, lease or execution evidence is created.
    sqlx::query("CREATE TEMP TABLE attempts(project_id TEXT,attempt_id TEXT,created_at TIMESTAMPTZ DEFAULT clock_timestamp(),data JSONB,envelope JSONB,execution_bindings JSONB,executor_profile_sha256 TEXT)")
        .execute(store.pool()).await.unwrap();
    let envelope = json!({"executor_profile_id":"executor","resource_profile_id":"resource",
        "model_route_id":"route","private_instruction":"PRIVATE_ENVELOPE_SENTINEL".repeat(8192)});
    let resources = json!({"active_slot":1,"coding_slot":1,"cpu_units":2,"memory_bytes":4096,
        "build_permit":0,"gpu_permit":0,"provider_inflight":1});
    let bindings = json!({"private_runtime":"PRIVATE_BINDING_SENTINEL".repeat(8192),
        "executor_profile":{"id":"executor","kind":"DSH_HEADLESS","private_config":"PRIVATE_EXECUTOR_SENTINEL",
            "native_mode":{"mode_id":"forgeflow-collaboration-v2",
                "preset_patch":{"sha256":"preset-pin","private_config":"PRIVATE_PRESET_SENTINEL"},
                "enabled_capabilities":["workflow", "agent_teams", 42, "团".repeat(43), "a".repeat(128), "b".repeat(129)]}},
        "resource_profile":{"native_child_policy":{"enabled":true,"max_live_agents":4,
            "max_lifecycles":8,"max_delegation_depth":2,"model_inflight_limit":3,
            "child_resources":resources,"private_policy":"PRIVATE_POLICY_SENTINEL"}}});
    let empty_policy = json!({"resource_profile":{"native_child_policy":{}},
        "executor_profile":{"native_mode":{"enabled_capabilities":[]}}});
    let malformed_policy = json!({"resource_profile":{"native_child_policy":["PRIVATE_ARRAY_SENTINEL"]},
        "executor_profile":{"native_mode":{"enabled_capabilities":"not-an-array"}}});
    for (project, id, value) in [
        ("p", "a00", bindings.clone()),
        ("p", "a01", malformed_policy),
        ("p", "a02", empty_policy),
        ("other", "b99", json!({})),
    ] {
        sqlx::query("INSERT INTO attempts(project_id,attempt_id,data,envelope,execution_bindings) VALUES($1,$2,$3,$4,$5)")
            .bind(project).bind(id).bind(json!({"attempt_id":id})).bind(&envelope).bind(value)
            .execute(store.pool()).await.unwrap();
    }
    // Same public metadata from the new representation; neither query nor UI
    // should re-expand the shared private executor object into the snapshot.
    let mut compact = bindings.clone();
    let profile = compact
        .as_object_mut()
        .unwrap()
        .remove("executor_profile")
        .unwrap();
    let profile_sha = forgeflow_planner::sha256(
        &serde_json::to_vec(&json!(["forgeflow.frozen-executor-profile.v1", profile])).unwrap(),
    );
    sqlx::query("INSERT INTO frozen_executor_profiles(project_id,sha256,data) VALUES('p',$1,$2)")
        .bind(&profile_sha)
        .bind(&profile)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,data,envelope,execution_bindings,executor_profile_sha256) VALUES('p','a03',$1,$2,$3,$4)")
        .bind(json!({"attempt_id":"a03"})).bind(&envelope).bind(compact).bind(&profile_sha)
        .execute(store.pool()).await.unwrap();
    assert_eq!(store.attempt_bindings("p", "a03").await.unwrap(), bindings);
    // Transport metadata is projected from trusted columns, while arbitrary
    // transport payloads and native request grants remain private. These temp
    // rows are projection fixtures, not evidence of actual model execution.
    sqlx::query("CREATE TEMP TABLE native_model_requests(project_id TEXT,request_id TEXT,attempt_id TEXT,generation BIGINT,worker_id TEXT,allocation_id TEXT,native_session_id TEXT,provider TEXT,model TEXT,max_output_tokens BIGINT,purpose TEXT,status TEXT,usage_complete BOOLEAN,cost_status TEXT,admitted_at TIMESTAMPTZ,settled_at TIMESTAMPTZ,dispatched_at TIMESTAMPTZ,usage JSONB,dispatch_transport_settlement JSONB)")
        .execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO native_model_requests VALUES('p','model-fixture','a00',1,'worker','allocation','session','provider','model',100,'conversation','SETTLED',true,'UNKNOWN',clock_timestamp(),clock_timestamp(),clock_timestamp(),$1,$2)")
        .bind(json!({"inputTokens":12,"outputTokens":3,"private":"PRIVATE_USAGE_SENTINEL"}))
        .bind(json!({"outcome":"RESPONSE_BODY_COMPLETED","upstream_status":200,"received_bytes":128,"usage_complete":true,"private":"PRIVATE_TRANSPORT_SENTINEL"}))
        .execute(store.pool()).await.unwrap();
    let snapshot = store.snapshot("p").await.unwrap();
    assert_eq!(
        snapshot["native_model_requests"][0]["transport"],
        json!({"outcome":"RESPONSE_BODY_COMPLETED","upstream_status":200,"received_bytes":128,"usage_complete":true})
    );
    assert_eq!(
        snapshot["native_model_requests"][0]["usage"],
        json!({"inputTokens":12,"outputTokens":3})
    );
    assert!(!snapshot["native_model_requests"][0]["dispatched_at"].is_null());

    let profiles = snapshot["attempt_native_profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 4);
    assert_eq!(
        profiles[0],
        json!({"attempt_id":"a00","executor_profile_id":"executor",
        "resource_profile_id":"resource","model_route_id":"route","executor_kind":"DSH_HEADLESS",
        "mode_id":"forgeflow-collaboration-v2","preset_sha256":"preset-pin","native_root_binding":null,
        "capabilities":["workflow","agent_teams","a".repeat(128)],
        "native_child_policy":{"enabled":true,"max_live_agents":4,"max_lifecycles":8,
            "max_delegation_depth":2,"model_inflight_limit":3,"child_resources":resources}})
    );
    assert_eq!(profiles[1]["native_child_policy"], Value::Null);
    assert_eq!(profiles[1]["capabilities"], Value::Null);
    assert_eq!(profiles[2]["capabilities"], json!([]));
    assert_eq!(
        profiles[2]["native_child_policy"],
        json!({"enabled":null,"max_live_agents":null,
        "max_lifecycles":null,"max_delegation_depth":null,"model_inflight_limit":null,
        "child_resources":{"active_slot":null,"coding_slot":null,"cpu_units":null,
            "memory_bytes":null,"build_permit":null,"gpu_permit":null,"provider_inflight":null}})
    );
    let mut expected_cas_projection = profiles[0].clone();
    expected_cas_projection["attempt_id"] = json!("a03");
    assert_eq!(profiles[3], expected_cas_projection);
    assert_eq!(snapshot["attempts"].as_array().unwrap().len(), 4);
    assert!(!snapshot.to_string().contains("PRIVATE_"));
    for collection in [
        "leases",
        "allocations",
        "native_child_lifecycles",
        "native_child_allocations",
    ] {
        assert_eq!(
            snapshot[collection],
            json!([]),
            "{collection} must remain present and empty"
        );
    }
    assert_eq!(snapshot["source"], "POSTGRESQL_AUTHORITY");
    assert_eq!(snapshot["revision"], 1);
    assert!(!snapshot["as_of"].is_null());
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
