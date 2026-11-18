//! Real PostgreSQL/Git authority tests. Producer rows and runner receipts are explicit
//! synthetic fixtures; these tests do not establish an executed producer/consumer Gate.
use forgeflow_domain::*;
use forgeflow_store::{Store, StoreError};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

// Reuse typed fixture data, preserving the same API-visible semantic contract.
mod model {
    include!("../../planner/tests/producer_inputs.rs");
    pub fn data() -> (
        DraftBundle,
        Vec<u8>,
        ProducerInputEvidence,
        ProducerInputTree,
    ) {
        fixture()
    }
}
async fn setup() -> (Store, String, sqlx::PgPool) {
    let url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL required for actual PostgreSQL tests");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("materialization_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(8)
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
    let s = Store::from_pool(pool);
    s.migrate().await.unwrap();
    (s, schema, admin)
}
async fn cleanup(s: Store, schema: String, admin: sqlx::PgPool, root: PathBuf) {
    s.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    fs::remove_dir_all(root).unwrap();
}
fn git(repo: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Authority fixture",
            "-c",
            "user.email=fixture@localhost",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}
async fn put(s: &Store, collection: &str, id: &str, value: Value) {
    s.execute_command(
        CommandIdentity {
            actor_id: "fixture".into(),
            idempotency_key: format!("{collection}:{id}"),
        },
        CatalogCommand::PutDocument {
            project_id: "project".into(),
            collection: collection.into(),
            id: id.into(),
            expected_revision: None,
            value,
        },
    )
    .await
    .unwrap();
}
struct Fixture {
    root: PathBuf,
    task: TaskCard,
    selected: String,
    frozen_flow: FlowRevision,
    producer_log: PathBuf,
    actual_source_content: forgeflow_git::SourceContentManifest,
}
async fn fixture(s: &Store) -> Fixture {
    fixture_with_source_attestation(s, false).await
}
async fn fixture_with_source_attestation(s: &Store, wrong_content_attestation: bool) -> Fixture {
    let (mut d, _, mut evidence, _) = model::data();
    let root = std::env::temp_dir().join(format!(
        "forgeflow-materialization-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "--initial-branch=main"]);
    fs::write(root.join("src/config.txt"), b"immutable configuration").unwrap();
    fs::write(
        root.join("README.txt"),
        b"Actual Git fixture, synthetic runner receipts; no product qualification.",
    )
    .unwrap();
    git(&root, &["add", "src/config.txt", "README.txt"]);
    git(&root, &["commit", "-m", "Initial immutable input"]);
    let original = git(&root, &["rev-parse", "HEAD"]);
    let artifacts = root.join("approved-artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    s.create_project(Project {
        project_id: "project".into(),
        name: "materialization authority test".into(),
        root_path: root.to_string_lossy().into_owned(),
        authority_mode: AuthorityMode::Managed,
        data_origin: DataOrigin::Native,
        goal: "preserve approved semantics".into(),
        technology_stack: vec![],
        timezone: "UTC".into(),
        paused: false,
        archived: false,
        revision: 1,
    })
    .await
    .unwrap();
    for team in ["team", "owner"] {
        s.create_team(Team {
            project_id: "project".into(),
            team_id: team.into(),
            parent_team_id: None,
            name: team.into(),
            paused: false,
            revision: 1,
        })
        .await
        .unwrap();
    }
    s.register_worker(WorkerRegisterRequest {
        project_id: Some("project".into()),
        executor_profile_ids: vec!["exec".into()],
        worker_id: "worker".into(),
        boot_id: "boot".into(),
        capabilities: vec!["exec".into()],
    })
    .await
    .unwrap();
    for (id, project, team, worker, parent) in [
        ("global", None, None, None, None),
        ("project", Some("project"), None, None, Some("global")),
        ("team", Some("project"), Some("team"), None, Some("project")),
        ("worker", None, None, Some("worker"), Some("global")),
    ] {
        s.put_resource_policy(
            ResourcePolicy {
                scope_id: id.into(),
                parent_scope_id: parent.map(str::to_owned),
                project_id: project.map(str::to_owned),
                team_id: team.map(str::to_owned),
                worker_id: worker.map(str::to_owned),
                limits: ResourceVector {
                    active_slot: 4,
                    coding_slot: 4,
                    cpu_units: 4,
                    provider_inflight: 20,
                    ..Default::default()
                },
                revision: 1,
                paused: false,
            },
            None,
        )
        .await
        .unwrap();
    }
    let mut requirements: Vec<_> = d
        .context
        .requirements
        .iter()
        .map(|r| Requirement {
            project_id: "project".into(),
            requirement_id: r.requirement_id.clone(),
            title: r.acceptance.clone(),
            source_anchor: format!("{}#{}", r.source_document, r.anchor),
            outcome: r.acceptance.clone(),
            scope: "authority fixture".into(),
            acceptance: vec![r.acceptance.clone()],
            priority: r.priority,
            weight: 1,
            deferred_reason: None,
            revision: 1,
        })
        .collect();
    requirements.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));
    d.context.requirements = requirements
        .iter()
        .map(|r| {
            let (source, anchor) = r.source_anchor.split_once('#').unwrap();
            forgeflow_planner::Requirement {
                requirement_id: r.requirement_id.clone(),
                source_document: source.into(),
                anchor: anchor.into(),
                acceptance: r.acceptance.join("\n"),
                priority: r.priority,
                deferred_reason: None,
            }
        })
        .collect();
    d.context.requirement_semantic_digests = requirements
        .iter()
        .map(|r| {
            (
                r.requirement_id.clone(),
                forgeflow_planner::requirement_semantic_digest(r),
            )
        })
        .collect();
    d.context.source_revision =
        forgeflow_planner::sha256(&serde_json::to_vec(&requirements).unwrap());
    for r in requirements {
        s.create_requirement(r).await.unwrap();
    }
    put(
        s,
        "owners",
        "owner",
        serde_json::to_value(&d.context.owners[0]).unwrap(),
    )
    .await;
    for (collection, id, value) in [
        ("executor_profiles", "exec", json!({"id":"exec"})),
        (
            "resource_profiles",
            "resources",
            json!({"id":"resources","qualification":"SYNTHETIC_AUTHORITY_FIXTURE"}),
        ),
        (
            "model_routes",
            "route",
            json!({"id":"route","qualification":"NO_MODEL_CALLS"}),
        ),
    ] {
        put(s, collection, id, value).await;
    }
    let consumer_envelope = d.flow.tasks[1].envelope.clone().unwrap();
    for t in &mut d.flow.tasks {
        let spec = d.context.task_specs.get_mut(&t.task_id).unwrap();
        spec.requirement_digest_refs = t
            .requirement_ids
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    d.context.requirement_semantic_digests[id].clone(),
                )
            })
            .collect();
        spec.verification_plan = format!("verify-{}", t.task_id);
        spec.verification_case_count = 6;
        t.resource_request.coding_slot = 1;
        let mut envelope = consumer_envelope.clone();
        envelope.task_id = t.task_id.clone();
        envelope.task_revision = t.task_revision;
        envelope.write_set = t.write_set.clone();
        envelope.workspace_root = root.to_string_lossy().into_owned();
        envelope.artifact_prefix = artifacts.to_string_lossy().into_owned();
        envelope.base_sha = original.clone();
        envelope.verification_plan_id = spec.verification_plan.clone();
        envelope.deadline_at = "2099-01-01T00:00:00Z".into();
        let manifest = ContextManifest {
            files: spec
                .inputs
                .iter()
                .map(|i| ContextFile {
                    path: i.path.clone(),
                    sha256: i.sha256.clone(),
                })
                .collect(),
            mandatory_paths: t.read_set.clone(),
            artifact_inputs: vec![],
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let id = format!("approved-context-{}", t.task_id);
        let path = artifacts.join(&id);
        fs::write(&path, &bytes).unwrap();
        put(
            s,
            "artifacts",
            &id,
            json!({"path":path,"sha256":forgeflow_planner::sha256(&bytes)}),
        )
        .await;
        envelope.context_manifest.artifact_id = id;
        envelope.context_manifest.sha256 = forgeflow_planner::sha256(&bytes);
        envelope.context_manifest.mandatory_paths = manifest.mandatory_paths;
        t.envelope = Some(envelope);
        t.input_digest = forgeflow_planner::canonical_task_input_digest(t, spec);
    }
    let producer = d.flow.tasks[0].clone();
    let consumer = &mut d.flow.tasks[1];
    let spec = d.context.task_specs.get_mut(&consumer.task_id).unwrap();
    spec.producer_inputs[0].producer_input_digest = producer.input_digest.clone();
    consumer.input_digest = forgeflow_planner::canonical_task_input_digest(consumer, spec);
    s.execute_command(CommandIdentity { actor_id: "fixture".into(), idempotency_key: "snapshots".into() }, CatalogCommand::RegisterInputSnapshots {
        project_id: "project".into(), snapshots: vec![json!({"path":"src/config.txt","relative_path":"src/config.txt","sha256":forgeflow_planner::sha256(b"immutable configuration")})] }).await.unwrap();
    for t in &d.flow.tasks {
        let spec = &d.context.task_specs[&t.task_id];
        let commands: Vec<Value> = ["author", "consumer", "independent"].into_iter().map(|role| json!({"role":role,"program":"/usr/bin/true","args":[],"env":{},
            "executable_hash":forgeflow_evidence::sha256(&fs::read("/usr/bin/true").unwrap()),"bound_inputs":[],"report_path":format!("{role}.json"),
            "expected_cases":[{"name":"positive","kind":"positive"},{"name":"negative","kind":"negative"}],"timeout_seconds":5})).collect();
        put(s, "verification_plans", &spec.verification_plan, json!({"plan_id":spec.verification_plan,"task_revision":t.task_revision,"contract_version":"index-format:1",
            "input_hash":t.input_digest,"environment_profile":"profile","oracle_id":"independent-format-oracle","verifier_id":"independent-verifier","author_id":"producer-author","commands":commands})).await;
    }
    put(
        s,
        "contract_versions",
        "index-format:1",
        serde_json::to_value(&evidence.contract).unwrap(),
    )
    .await;
    let frozen_flow =
        forgeflow_planner::freeze(d.flow.clone(), &d.context, "owner", d.flow.revision)
            .unwrap()
            .flow;
    s.execute_command(
        CommandIdentity {
            actor_id: "fixture".into(),
            idempotency_key: "flow".into(),
        },
        CatalogCommand::PutFlow {
            flow: frozen_flow.clone(),
            expected_revision: None,
            context: Some(serde_json::to_value(&d.context).unwrap()),
        },
    )
    .await
    .unwrap();
    assert!(!root.join("src/index-format.json").exists());
    fs::write(
        root.join("src/index-format.json"),
        br#"{"version":1,"entries":[{"key":"alpha","value":42}]}"#,
    )
    .unwrap();
    git(&root, &["add", "src/index-format.json"]);
    git(
        &root,
        &["commit", "-m", "Synthetic accepted producer output"],
    );
    let accepted = git(&root, &["rev-parse", "HEAD"]);
    let actual_source_content = forgeflow_git::source_content_manifest(&root, &accepted).unwrap();
    assert_eq!(actual_source_content.tree_oid.len(), 40);
    assert_eq!(actual_source_content.source_sha256.len(), 64);
    assert_ne!(
        actual_source_content.tree_oid,
        actual_source_content.source_sha256
    );
    let mut source_attestation = actual_source_content.clone();
    if wrong_content_attestation {
        source_attestation.source_sha256 = forgeflow_git::source_content_manifest(&root, &original)
            .unwrap()
            .source_sha256;
        assert_ne!(
            source_attestation.source_sha256,
            actual_source_content.source_sha256
        );
    }
    // The contract remains an isolated draft fixture. Use the supported CAS,
    // rather than seeding a frozen contract or changing authoritative rows.
    let registered_contract = s
        .get_document("project", "contract_versions", "index-format:1")
        .await
        .unwrap();
    evidence.contract.source_sha256 = source_attestation.source_sha256.clone();
    s.execute_command(
        CommandIdentity {
            actor_id: "fixture".into(),
            idempotency_key: "bind-actual-contract-source".into(),
        },
        CatalogCommand::PutDocument {
            project_id: "project".into(),
            collection: "contract_versions".into(),
            id: "index-format:1".into(),
            expected_revision: Some(registered_contract["revision"].as_u64().unwrap()),
            value: serde_json::to_value(&evidence.contract).unwrap(),
        },
    )
    .await
    .unwrap();
    evidence.producer = producer.clone();
    evidence.attempt.task_id = producer.task_id.clone();
    evidence.attempt.base_sha = original.clone();
    evidence.attempt.task_revision = producer.task_revision;
    let mut producer_envelope = producer.envelope.clone().unwrap();
    producer_envelope.attempt_id = evidence.attempt.attempt_id.clone();
    producer_envelope.generation = evidence.attempt.generation;
    producer_envelope.lease_id = evidence.attempt.lease_id.clone();
    producer_envelope.worker_id = evidence.attempt.worker_id.clone();
    producer_envelope.operation_id = evidence.attempt.operation_id.clone();
    evidence.receipt.input_digest = producer.input_digest.clone();
    evidence.receipt.candidate_sha = Some(accepted.clone());
    let plan_value = s
        .get_document(
            "project",
            "verification_plans",
            &producer_envelope.verification_plan_id,
        )
        .await
        .unwrap();
    let mut plan_value = plan_value;
    plan_value.as_object_mut().unwrap().remove("revision");
    let plan: forgeflow_evidence::VerificationPlan = serde_json::from_value(plan_value).unwrap();
    let log_dir = artifacts.join("synthetic-producer-run");
    fs::create_dir_all(&log_dir).unwrap();
    let producer_log = log_dir.join("verification.ndjson");
    fs::write(
        &producer_log,
        b"Explicit synthetic six-case fixture; no executed model or oracle claims.",
    )
    .unwrap();
    evidence.receipt.total = 6;
    evidence.receipt.artifact.sha256 =
        forgeflow_evidence::sha256(&fs::read(&producer_log).unwrap());
    let v = &mut evidence.receipt.details;
    v["binding"]["base_sha"] = json!(original);
    v["binding"]["candidate_sha"] = json!(accepted);
    v["binding"]["input_hash"] = json!(producer.input_digest);
    v["binding"]["verification_plan_id"] = json!(plan.plan_id);
    v["binding"]["verification_plan_hash"] = json!(plan.digest());
    v["binding"]["source_hash"] = json!(actual_source_content.tree_oid);
    v["command"] = json!(["/usr/bin/true", "/usr/bin/true", "/usr/bin/true"]);
    v["total"] = json!(6);
    v["positive_cases"] = json!(3);
    v["negative_cases"] = json!(3);
    v["log_hash"] = json!(evidence.receipt.artifact.sha256);
    fs::write(
        log_dir.join("verification-receipt.json"),
        serde_json::to_vec(v).unwrap(),
    )
    .unwrap();
    put(
        s,
        "artifacts",
        &evidence.receipt.artifact.artifact_id,
        json!({"path":producer_log,"sha256":evidence.receipt.artifact.sha256}),
    )
    .await;
    evidence.integration.candidate_sha = accepted.clone();
    evidence.integration.integrated_sha = Some(accepted.clone());
    evidence.integration.expected_sha = original;
    let mut verification: forgeflow_evidence::VerificationReceipt =
        serde_json::from_value(evidence.receipt.details.clone()).unwrap();
    verification.binding.integrated_sha = Some(accepted.clone());
    let integration_root = root
        .join("forgeflow-evidence")
        .join(&evidence.integration.intent_id);
    fs::create_dir_all(&integration_root).unwrap();
    fs::copy(&producer_log, integration_root.join(&verification.log_path)).unwrap();
    let integration_receipt = json!({"new_sha":accepted,"verification_receipt_hash":verification.digest(),"verification":verification,"artifact_root":integration_root,
        "source_content_sha256":source_attestation.source_sha256,"source_content_algorithm":source_attestation.algorithm,"source_tree_oid":source_attestation.tree_oid});
    fs::write(
        integration_root.join("forgeflow-verification.json"),
        serde_json::to_vec(&integration_receipt).unwrap(),
    )
    .unwrap();
    evidence.integration.receipt = Some(integration_receipt);
    sqlx::query("INSERT INTO attempts(project_id,attempt_id,task_id,task_revision,lease_id,generation,worker_id,operation_id,state,revision,created_at,terminal_at,data,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'SUCCEEDED',$9,$10,$11,$12,$13)")
        .bind("project").bind(&evidence.attempt.attempt_id).bind(&producer.task_id).bind(producer.task_revision as i64).bind(&evidence.attempt.lease_id)
        .bind(evidence.attempt.generation).bind(&evidence.attempt.worker_id).bind(&evidence.attempt.operation_id).bind(evidence.attempt.revision as i64)
        .bind(evidence.attempt.created_at).bind(evidence.attempt.terminal_at).bind(serde_json::to_value(&evidence.attempt).unwrap()).bind(serde_json::to_value(&producer_envelope).unwrap()).execute(s.pool()).await.unwrap();
    sqlx::query("INSERT INTO evidence_receipts VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind("project")
        .bind(&evidence.receipt.receipt_id)
        .bind(&evidence.attempt.attempt_id)
        .bind(evidence.attempt.generation)
        .bind(&evidence.receipt.kind)
        .bind(serde_json::to_value(&evidence.receipt).unwrap())
        .bind(evidence.receipt.created_at)
        .execute(s.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO merge_intents VALUES($1,$2,$3,$4,$5,'FINALIZED',$6,$7)")
        .bind(&evidence.integration.intent_id)
        .bind("project")
        .bind(&evidence.attempt.attempt_id)
        .bind(evidence.attempt.generation)
        .bind("refs/heads/main")
        .bind(evidence.integration.revision as i64)
        .bind(serde_json::to_value(&evidence.integration).unwrap())
        .execute(s.pool())
        .await
        .unwrap();
    fs::write(
        root.join("README.txt"),
        b"Unrelated main advance preserves every approved consumer input.",
    )
    .unwrap();
    git(&root, &["add", "README.txt"]);
    git(&root, &["commit", "-m", "Actual descendant base"]);
    let selected = git(&root, &["rev-parse", "HEAD"]);
    Fixture {
        root,
        task: frozen_flow.tasks[1].clone(),
        selected,
        frozen_flow,
        producer_log,
        actual_source_content,
    }
}
fn request(task: &TaskCard, key: &str) -> AdmissionRequest {
    AdmissionRequest {
        actor_id: "fixture".into(),
        idempotency_key: key.into(),
        project_id: "project".into(),
        task_id: task.task_id.clone(),
        task_revision: task.task_revision,
        flow_revision: 1,
        policy_revision: 1,
        input_digest: task.input_digest.clone(),
        worker_id: "worker".into(),
        lease_seconds: 300,
        envelope: task.envelope.clone().unwrap(),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL and real isolated PostgreSQL schema; synthetic producer receipts, no product Gate"]
async fn actual_admission_materializes_registered_producer_at_descendant_without_replanning() {
    let (s, schema, admin) = setup().await;
    let fixture = fixture(&s).await;
    let contract = s
        .get_document("project", "contract_versions", "index-format:1")
        .await
        .unwrap();
    assert_eq!(
        contract["source_sha256"],
        fixture.actual_source_content.source_sha256
    );
    assert_eq!(contract["source_sha256"].as_str().unwrap().len(), 64);
    assert_ne!(
        contract["source_sha256"],
        fixture.actual_source_content.tree_oid
    );
    let result = s
        .admit(request(&fixture.task, "materialize"))
        .await
        .unwrap();
    assert_eq!(result.envelope.base_sha, fixture.selected);
    assert_ne!(
        result.envelope.context_manifest.sha256,
        fixture
            .task
            .envelope
            .as_ref()
            .unwrap()
            .context_manifest
            .sha256
    );
    assert_eq!(
        s.get_flow("project", 1).await.unwrap().input_digest,
        fixture.frozen_flow.input_digest
    );
    assert_eq!(
        s.get_task("project", &fixture.task.task_id)
            .await
            .unwrap()
            .input_digest,
        fixture.task.input_digest
    );
    let bindings = s
        .attempt_bindings("project", &result.envelope.attempt_id)
        .await
        .unwrap();
    assert_eq!(
        bindings["producer_input_materialization"]["base_sha"],
        fixture.selected
    );
    let descriptor = s
        .get_document(
            "project",
            "artifacts",
            &result.envelope.context_manifest.artifact_id,
        )
        .await
        .unwrap();
    let bytes = fs::read(descriptor["path"].as_str().unwrap()).unwrap();
    assert_eq!(
        forgeflow_planner::sha256(&bytes),
        result.envelope.context_manifest.sha256
    );
    let manifest: ContextManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest.files.len(), 2);
    let replay = s
        .admit(request(&fixture.task, "materialize"))
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.envelope.attempt_id, result.envelope.attempt_id);
    cleanup(s, schema, admin, fixture.root).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL and real isolated PostgreSQL schema; synthetic producer receipts, no product Gate"]
async fn actual_git_drift_and_corrupted_registered_logs_cannot_allocate_a_consumer() {
    for path in ["src/config.txt", "src/index-format.json", "raw-log"] {
        let (s, schema, admin) = setup().await;
        let fixture = fixture(&s).await;
        if path == "raw-log" {
            fs::write(&fixture.producer_log, b"corrupted receipt log").unwrap();
        } else {
            fs::write(fixture.root.join(path), b"changed after approval").unwrap();
            git(&fixture.root, &["add", path]);
            git(&fixture.root, &["commit", "-m", "Negative input drift"]);
        }
        let result = s.admit(request(&fixture.task, "negative-drift")).await;
        assert!(
            matches!(result, Err(StoreError::Domain(_))),
            "accepted {path}: {result:?}"
        );
        let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM attempts WHERE task_id=$1")
            .bind(&fixture.task.task_id)
            .fetch_one(s.pool())
            .await
            .unwrap();
        let allocations: i64 = sqlx::query_scalar("SELECT count(*) FROM resource_allocations")
            .fetch_one(s.pool())
            .await
            .unwrap();
        assert_eq!(attempts, 0);
        assert_eq!(allocations, 0);
        cleanup(s, schema, admin, fixture.root).await;
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL and real isolated PostgreSQL schema; synthetic producer receipts, no product Gate"]
async fn consistent_synthetic_contract_and_receipts_cannot_substitute_another_tree_content_digest()
{
    let (s, schema, admin) = setup().await;
    let fixture = fixture_with_source_attestation(&s, true).await;
    let contract = s
        .get_document("project", "contract_versions", "index-format:1")
        .await
        .unwrap();
    let integration: Value =
        sqlx::query_scalar("SELECT data FROM merge_intents WHERE project_id=$1")
            .bind("project")
            .fetch_one(s.pool())
            .await
            .unwrap();
    let durable: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join("forgeflow-evidence/producer-integrated/forgeflow-verification.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(
        contract["source_sha256"],
        fixture.actual_source_content.source_sha256
    );
    assert_eq!(contract["source_sha256"].as_str().unwrap().len(), 64);
    for receipt in [&integration["receipt"], &durable] {
        assert_eq!(receipt["source_content_sha256"], contract["source_sha256"]);
        assert_eq!(
            receipt["source_content_algorithm"],
            forgeflow_git::SOURCE_CONTENT_ALGORITHM
        );
        assert_eq!(
            receipt["source_tree_oid"],
            fixture.actual_source_content.tree_oid
        );
        assert_eq!(
            receipt["verification"]["binding"]["source_hash"],
            fixture.actual_source_content.tree_oid
        );
    }
    let result = s
        .admit(request(&fixture.task, "forged-source-content"))
        .await;
    assert!(
        matches!(result, Err(StoreError::Domain(_))),
        "accepted another Git tree's content digest: {result:?}"
    );
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM attempts WHERE task_id=$1")
        .bind(&fixture.task.task_id)
        .fetch_one(s.pool())
        .await
        .unwrap();
    let allocations: i64 = sqlx::query_scalar("SELECT count(*) FROM resource_allocations")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(attempts, 0);
    assert_eq!(allocations, 0);
    cleanup(s, schema, admin, fixture.root).await;
}
