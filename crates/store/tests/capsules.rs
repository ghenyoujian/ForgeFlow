//! Isolated PostgreSQL integrity/counterexample tests only. No executor, network,
//! model, native Team, live lease or production qualification is exercised.
use chrono::Utc;
use forgeflow_domain::*;
use forgeflow_store::{
    Store, StoreError,
    capsules::{CapsuleContextRequest, CapsulePolicyRequest},
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

fn code(error: &StoreError) -> &str {
    match error {
        StoreError::Domain(error) => &error.code,
        _ => "NOT_DOMAIN_ERROR",
    }
}
fn hash(bytes: &[u8]) -> String {
    forgeflow_planner::sha256(bytes)
}
fn profile_hash(value: &Value) -> String {
    hash(&serde_json::to_vec(&json!(["forgeflow.frozen-executor-profile.v1", value])).unwrap())
}
fn identity(key: &str) -> CommandIdentity {
    CommandIdentity {
        actor_id: "owner".into(),
        idempotency_key: key.into(),
    }
}
fn policy(reference: ArtifactRef) -> CapsulePolicyRequest {
    CapsulePolicyRequest {
        schema_version: "forgeflow.capsule-policy.v1".into(),
        executor_profile_id: "exec".into(),
        resource_profile_id: "resource".into(),
        model_route_id: "route".into(),
        mode: DriverMode::ClaudeLeaf,
        team_write_policy: TeamWritePolicy::AggregateWriteScope,
        qualification_ref: reference,
    }
}

async fn setup() -> (Store, String, sqlx::PgPool, std::path::PathBuf, Value) {
    let url = std::env::var("DATABASE_URL").expect("isolated DATABASE_URL is required");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("capsule_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let scoped = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let scoped = scoped.clone();
            Box::pin(async move {
                sqlx::query(&format!("SET search_path TO {scoped}"))
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
    let directory = std::env::temp_dir().join(format!(
        "forgeflow-capsule-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&directory).unwrap();
    let project = Project {
        project_id: "p".into(),
        name: "Capsule storage fixture".into(),
        root_path: directory.to_string_lossy().into(),
        authority_mode: AuthorityMode::Managed,
        data_origin: DataOrigin::Native,
        goal: "No execution qualification".into(),
        technology_stack: vec![],
        timezone: "UTC".into(),
        paused: true,
        archived: false,
        revision: 1,
    };
    sqlx::query("INSERT INTO projects(project_id,revision,paused,archived,authority_mode,data) VALUES('p',1,true,false,'MANAGED',$1)")
        .bind(json!(project)).execute(store.pool()).await.unwrap();
    let executable = std::fs::canonicalize("/usr/bin/true").unwrap();
    let executor = json!({"id":"exec","kind":"CLAUDE_CODE_LEAF","program":executable,
        "artifact_pins":[{"path":executable,"sha256":hash(&std::fs::read(&executable).unwrap())}],
        "fixture":"STORAGE_ONLY_NO_EXECUTION"});
    for (collection, id, value) in [
        ("executor_profiles", "exec", executor.clone()),
        (
            "resource_profiles",
            "resource",
            json!({"id":"resource","fixture":"NO_RUNTIME_GUARD_QUALIFICATION"}),
        ),
        (
            "model_routes",
            "route",
            json!({"id":"route","qualification":"NO_NETWORK_OR_MODEL_CALL"}),
        ),
    ] {
        store
            .execute_command(
                identity(collection),
                CatalogCommand::PutDocument {
                    project_id: "p".into(),
                    collection: collection.into(),
                    id: id.into(),
                    expected_revision: None,
                    value,
                },
            )
            .await
            .unwrap();
    }
    (store, schema, admin, directory, executor)
}

async fn artifact(
    store: &Store,
    directory: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> ArtifactRef {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    let reference = ArtifactRef {
        artifact_id: name.into(),
        sha256: hash(bytes),
    };
    store
        .execute_command(
            identity(name),
            CatalogCommand::PutArtifact {
                project_id: "p".into(),
                id: name.into(),
                path: path.to_string_lossy().into(),
                sha256: reference.sha256.clone(),
                kind: "CAPSULE_COUNTEREXAMPLE_ONLY".into(),
                bytes: bytes.len() as u64,
            },
        )
        .await
        .unwrap();
    reference
}

fn probe(profile: &Value, evidence: &ArtifactRef) -> DriverProbeResult {
    DriverProbeResult {
        schema_version: DRIVER_PROBE_SCHEMA_V1.into(),
        probe_id: "fixture-only".into(),
        driver_id: ExecutorDriverId::ClaudeCode,
        mode: DriverMode::ClaudeLeaf,
        observed_at: Utc::now(),
        executable_sha256: profile["artifact_pins"][0]["sha256"]
            .as_str()
            .map(str::to_owned),
        artifact_pins_ref: Some(evidence.clone()),
        executor_profile_sha256: Some(profile_hash(profile)),
        cli_version: None,
        capabilities: ExecutorCapabilities {
            adapter_contract_version: "fixture-only".into(),
            protocol: "fixture-only".into(),
            protocol_version: None,
            structured_events: false,
            session_resume: false,
            session_cancel: false,
            process_cancel: false,
            session_close: false,
            usage_accounting: "UNKNOWN".into(),
            transcript_replay: false,
            nested_spawn_control: "UNKNOWN".into(),
        },
        checks: vec![],
        environment_ref: evidence.clone(),
        command_results_ref: evidence.clone(),
        evidence_class: EvidenceClass::NoModelFixture,
    }
}

fn envelope(attempt: &str) -> ExecutionEnvelope {
    serde_json::from_value(json!({"schema_version":"forgeflow.execution.v1","operation_id":format!("op-{attempt}"),
        "project_id":"p","task_id":"t","task_revision":1,"attempt_id":attempt,"lease_id":format!("lease-{attempt}"),
        "generation":1,"worker_id":"unlaunched-storage-fixture","workspace_root":"/tmp/capsule-storage-only",
        "base_sha":"a".repeat(40),"context_manifest":{"artifact_id":"context","sha256":"b".repeat(64),"mandatory_paths":[],"rendered_utf8_bytes":0,"token_estimate":null,"tokenizer_id":null},
        "write_set":["owned/"],"prompt_artifact":{"artifact_id":"prompt","sha256":"c".repeat(64)},
        "model_route_id":"route","executor_profile_id":"exec","resource_profile_id":"resource","verification_plan_id":"verify",
        "allowed_effects":["READ_WORKSPACE","WRITE_DECLARED_PATHS"],"issued_at":"2026-01-01T00:00:00Z",
        "expires_at":"2026-01-01T00:01:00Z","deadline_at":"2099-01-01T00:00:00Z","artifact_prefix":"/tmp/capsule-storage-only/artifacts",
        "secret_refs":["PRIVATE_REFERENCE_MUST_NOT_APPEAR_IN_PUBLIC_VIEW"],"idempotency_key":"fixture","trace_id":"fixture",
        "enforcement":{"model_budget_mode":"direct_observed","stage_resource_mode":"ATTEMPT_RESERVATION","build_capable":false,
        "gateway_coverage_receipt_id":null,"tool_guard_receipt_id":null,"attempt_reserved_build_permits":0,"all_model_routes_covered":false,"disabled_tool_entry_ids":[]},
        "session_purpose":"EXECUTION","max_model_requests":0,"resume_session_id":null})).unwrap()
}

async fn terminal_fixture(
    store: &Store,
    executor: &Value,
    name: &str,
    binding: Option<&CapsuleBinding>,
) {
    // Terminal, unlaunched fixtures deliberately have no Lease, allocation,
    // Outbox or success receipt. This only tests storage and public projection.
    sqlx::raw_sql("INSERT INTO owner_nodes(project_id,owner_id,data) VALUES('p','owner','{}') ON CONFLICT DO NOTHING;
        INSERT INTO flow_revisions(project_id,flow_revision,revision,state,input_digest,data) VALUES('p',1,1,'DRAFT','fixture','{}') ON CONFLICT DO NOTHING;
        INSERT INTO tasks(project_id,task_id,task_revision,flow_revision,team_id,owner_id,state,input_digest,revision,data) VALUES('p','t',1,1,'owner','owner','PLANNED','fixture',1,'{}') ON CONFLICT DO NOTHING;
        INSERT INTO task_revisions(project_id,task_id,task_revision,data) VALUES('p','t',1,'{}') ON CONFLICT DO NOTHING;")
        .execute(store.pool()).await.unwrap();
    let digest = profile_hash(executor);
    sqlx::query("INSERT INTO frozen_executor_profiles(project_id,sha256,data) VALUES('p',$1,$2) ON CONFLICT DO NOTHING")
        .bind(&digest).bind(executor).execute(store.pool()).await.unwrap();
    let envelope = envelope(name);
    let a = Attempt {
        project_id: "p".into(),
        task_id: "t".into(),
        task_revision: 1,
        attempt_id: name.into(),
        lease_id: envelope.lease_id.clone(),
        generation: 1,
        worker_id: envelope.worker_id.clone(),
        operation_id: envelope.operation_id.clone(),
        base_sha: envelope.base_sha.clone(),
        state: AttemptState::Cancelled,
        revision: 1,
        created_at: Utc::now(),
        terminal_at: Some(Utc::now()),
        result: None,
    };
    let mut bindings = json!({});
    if let Some(binding) = binding {
        bindings["capsule"] = json!(binding);
    }
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,created_at,terminal_at,data,envelope,execution_bindings,executor_profile_sha256) VALUES('p',$1,'t',1,$2,1,$3,$4,'CANCELLED',1,$5,$6,$7,$8,$9,$10)")
        .bind(name).bind(&a.lease_id).bind(&a.worker_id).bind(&a.operation_id).bind(a.created_at).bind(a.terminal_at)
        .bind(json!(a)).bind(json!(envelope)).bind(bindings).bind(digest).execute(store.pool()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL DATABASE_URL; no native/model execution"]
async fn capsule_metadata_cannot_manufacture_qualification_or_authority() {
    let (store, schema, admin, directory, executor) = setup().await;
    let context_request = CapsuleContextRequest {
        executor_profile_id: "exec".into(),
        resource_profile_id: "resource".into(),
        model_route_id: "route".into(),
    };
    let context = store.capsule_context("p", &context_request).await.unwrap();
    assert_eq!(context.executor_profile_sha256, profile_hash(&executor));
    assert_eq!(context.control_build_sha256.len(), 64);
    assert_eq!(
        code(
            &store
                .capsule_context("other", &context_request)
                .await
                .unwrap_err()
        ),
        "NOT_FOUND"
    );

    let raw = artifact(
        &store,
        &directory,
        "raw-evidence",
        b"No model was called; this is not business evidence.",
    )
    .await;
    let fixture_probe = probe(&executor, &raw);
    let fixture_ref = artifact(
        &store,
        &directory,
        "fixture-probe",
        &serde_json::to_vec(&fixture_probe).unwrap(),
    )
    .await;
    let request = policy(fixture_ref.clone());
    assert_eq!(
        code(
            &store
                .register_capsule_policy(identity("fixture-denied"), "p", request.clone())
                .await
                .unwrap_err()
        ),
        "CAPSULE_QUALIFICATION_REQUIRED"
    );
    for mode in [
        DriverMode::ClaudeInteractiveTeam,
        DriverMode::ClaudeSavedWorkflow,
        DriverMode::DshManagedTeam,
        DriverMode::DshManagedWorkflow,
    ] {
        let mut unsupported = request.clone();
        unsupported.mode = mode;
        assert_eq!(
            code(
                &store
                    .register_capsule_policy(identity("team-denied"), "p", unsupported)
                    .await
                    .unwrap_err()
            ),
            "CAPSULE_MODE_UNQUALIFIED"
        );
    }
    let mut disjoint = request.clone();
    disjoint.team_write_policy = TeamWritePolicy::DisjointAttested;
    assert_eq!(
        code(
            &store
                .register_capsule_policy(identity("disjoint-denied"), "p", disjoint)
                .await
                .unwrap_err()
        ),
        "CAPSULE_MODE_UNQUALIFIED"
    );
    std::fs::write(
        directory.join("fixture-probe"),
        b"changed after registration",
    )
    .unwrap();
    assert_eq!(
        code(
            &store
                .register_capsule_policy(identity("changed-bytes"), "p", request)
                .await
                .unwrap_err()
        ),
        "CAPSULE_QUALIFICATION_REQUIRED"
    );

    // A caller can write VERIFIED into JSON; that must never become execution
    // qualification without the existing canonical successful native chain.
    let mut forged = fixture_probe;
    forged.evidence_class = EvidenceClass::RealModel;
    forged.checks = [
        CapabilityId::ExecutableIdentity,
        CapabilityId::VersionHelp,
        CapabilityId::StartHeadless,
        CapabilityId::StructuredEvents,
        CapabilityId::ProcessCancel,
        CapabilityId::TranscriptReplay,
        CapabilityId::VerifiedWriteIsolation,
        CapabilityId::BusinessE2e,
    ]
    .into_iter()
    .map(|id| CapabilityCheck {
        check_id: id,
        status: VerificationStatus::Verified,
        scope: "FORGED_METADATA_COUNTEREXAMPLE_ONLY".into(),
        reason_code: None,
        evidence_refs: vec![raw.clone()],
    })
    .collect();
    let forged_ref = artifact(
        &store,
        &directory,
        "forged-probe",
        &serde_json::to_vec(&forged).unwrap(),
    )
    .await;
    let error = store
        .register_capsule_policy(identity("forged-denied"), "p", policy(forged_ref))
        .await
        .unwrap_err();
    assert_eq!(code(&error), "CAPSULE_QUALIFICATION_REQUIRED");
    assert!(error.to_string().contains("successful native leaf"));
    let counts:(i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM documents WHERE collection='capsule_policies'),(SELECT count(*) FROM attempts),(SELECT count(*) FROM leases),(SELECT count(*) FROM outbox)")
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(counts, (0, 0, 0, 0));

    let denied = store
        .execute_command(
            identity("generic-bypass"),
            CatalogCommand::PutDocument {
                project_id: "p".into(),
                collection: "capsule_policies".into(),
                id: "exec".into(),
                expected_revision: None,
                value: json!({"policy":"unvalidated"}),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "CAPSULE_COMMAND_REQUIRED");

    terminal_fixture(&store, &executor, "a-legacy", None).await;
    let old = store.attempt_capsule("p", "a-legacy").await.unwrap();
    assert_eq!(old["binding_status"], "UNBOUND");
    assert!(old["capsule"].is_null());
    let envelope = envelope("b-bound");
    let binding = CapsuleBinding {
        schema_version: CAPSULE_SCHEMA_V1.into(),
        capsule_id: "capsule:b-bound".into(),
        envelope_ref: ExecutionEnvelopeRef::from_envelope(&envelope).unwrap(),
        driver_id: ExecutorDriverId::ClaudeCode,
        execution_kind: ExecutionKind::ManagedLeaf,
        executor_profile_sha256: context.executor_profile_sha256,
        qualification_ref: raw,
        team_write_policy: TeamWritePolicy::AggregateWriteScope,
    };
    terminal_fixture(&store, &executor, "b-bound", Some(&binding)).await;
    let view = store.attempt_capsule("p", "b-bound").await.unwrap();
    assert_eq!(view["binding_status"], "BOUND_IDENTITY_CHECKED");
    assert_eq!(view["authorization_granted"], false);
    assert_eq!(view["qualification_revalidated"], false);
    assert!(
        !view
            .to_string()
            .contains("PRIVATE_REFERENCE_MUST_NOT_APPEAR")
    );
    assert!(!view.to_string().contains("workspace_root"));
    assert_eq!(
        store.check_capsule("p", &binding).await.unwrap()["authorization_granted"],
        false
    );
    assert_eq!(
        code(&store.check_capsule("other", &binding).await.unwrap_err()),
        "CAPSULE_IDENTITY_MISMATCH"
    );
    for variant in 0..3 {
        let mut changed = binding.clone();
        match variant {
            0 => changed.envelope_ref.generation += 1,
            1 => changed.executor_profile_sha256 = "0".repeat(64),
            _ => changed.qualification_ref.sha256 = "0".repeat(64),
        }
        assert_eq!(
            code(&store.check_capsule("p", &changed).await.unwrap_err()),
            "CAPSULE_IDENTITY_MISMATCH"
        );
    }
    let first = store.capsules("p", None, 1).await.unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["next_cursor"], "a-legacy");
    let second = store
        .capsules("p", first["next_cursor"].as_str(), 1)
        .await
        .unwrap();
    assert_eq!(second["items"][0]["attempt_id"], "b-bound");
    assert!(second["next_cursor"].is_null());
    sqlx::query("UPDATE attempts SET envelope=jsonb_set(envelope,'{generation}','2') WHERE attempt_id='b-bound'").execute(store.pool()).await.unwrap();
    assert_eq!(
        code(&store.attempt_capsule("p", "b-bound").await.unwrap_err()),
        "CAPSULE_IDENTITY_MISMATCH"
    );
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM leases),(SELECT count(*) FROM resource_allocations),(SELECT count(*) FROM outbox)")
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(counts, (0, 0, 0));

    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    std::fs::remove_dir_all(directory).unwrap();
}
