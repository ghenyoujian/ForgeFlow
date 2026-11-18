//! Resolve approved future inputs from canonical records and actual immutable Git trees.
use super::*;
use forgeflow_planner::{
    CompileContext, ProducerInputEvidence, ProducerInputTree, ProducerSourceContent,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
fn io(error: impl std::fmt::Display) -> StoreError {
    err("PRODUCER_INPUT_EVIDENCE", error.to_string())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err(err(
            "INPUT_BUDGET_EXCEEDED",
            "producer input artifact must be a regular file of at most 32 MiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(err(
            "INPUT_BUDGET_EXCEEDED",
            "producer input artifact grew beyond its 32 MiB read budget",
        ));
    }
    Ok(bytes)
}
async fn document(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    collection: &str,
    id: &str,
) -> Result<Value> {
    sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3 FOR SHARE")
        .bind(project).bind(collection).bind(id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("PRODUCER_INPUT_EVIDENCE", format!("registered {collection}/{id} missing")))
}
fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_NAMESPACE")
        .env_remove("GIT_LITERAL_PATHSPECS")
        .env_remove("GIT_GLOB_PATHSPECS")
        .env_remove("GIT_NOGLOB_PATHSPECS")
        .env_remove("GIT_ICASE_PATHSPECS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(io)?;
    let mut bytes = Vec::new();
    let read_result = child
        .stdout
        .take()
        .ok_or_else(|| io("Git object stdout missing"))?
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes);
    if read_result.is_err() || bytes.len() as u64 > MAX_INPUT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err(
            "PRODUCER_INPUT_TREE",
            "exact registered Git object read failed or exceeded input budget",
        ));
    }
    if !child.wait().map_err(io)?.success() {
        return Err(err(
            "PRODUCER_INPUT_TREE",
            "exact registered Git object read failed or exceeded input budget",
        ));
    }
    Ok(bytes)
}
fn blob(repo: &Path, sha: &str, path: &str) -> Result<Vec<u8>> {
    validate_relative_path(path)?;
    if !valid_sha(sha) {
        return Err(err("PRODUCER_INPUT_TREE", "exact commit SHA required"));
    }
    // Literal pathspec prevents an input path from being interpreted as a pattern.
    let literal = format!(":(literal){path}");
    let entries = git(repo, &["ls-tree", "-z", sha, "--", &literal])?;
    let entries: Vec<_> = entries
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .collect();
    if entries.len() != 1 {
        return Err(err(
            "PRODUCER_INPUT_TREE",
            "required exact regular file is missing from verified tree",
        ));
    }
    let separator = entries[0]
        .iter()
        .position(|b| *b == b'\t')
        .ok_or_else(|| err("PRODUCER_INPUT_TREE", "invalid tree object record"))?;
    let (header, name_with_tab) = entries[0].split_at(separator);
    let name = &name_with_tab[1..];
    let header = std::str::from_utf8(header).map_err(io)?;
    let mut fields = header.split(' ');
    let mode = fields.next();
    let kind = fields.next();
    let object = fields.next().unwrap_or("");
    if !matches!(mode, Some("100644" | "100755"))
        || kind != Some("blob")
        || fields.next().is_some()
        || !valid_sha(object)
        || name != path.as_bytes()
    {
        return Err(err(
            "PRODUCER_INPUT_TREE",
            "producer inputs must be exact regular blobs, never symlinks or submodules",
        ));
    }
    let size = git(repo, &["cat-file", "-s", object])?;
    let size: u64 = std::str::from_utf8(&size)
        .map_err(io)?
        .trim()
        .parse()
        .map_err(io)?;
    if size > MAX_INPUT_BYTES {
        return Err(err(
            "INPUT_BUDGET_EXCEEDED",
            "producer input Git blob exceeds its 32 MiB read budget",
        ));
    }
    let bytes = git(repo, &["cat-file", "blob", object])?;
    if bytes.len() as u64 != size {
        return Err(err(
            "PRODUCER_INPUT_TREE",
            "immutable Git blob length differs from its registered object size",
        ));
    }
    Ok(bytes)
}

fn publish_context(root: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(err(
            "INPUT_BUDGET_EXCEEDED",
            "materialized context exceeds its 32 MiB artifact read budget",
        ));
    }
    // The final content-addressed name appears only after a complete, durable write.
    // Failed temporary files remain separate so a retry cannot inherit partial bytes.
    let pending = root.join(format!(".producer-context-{}.pending", id()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)
        .map_err(io)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            io(format!(
                "{e}; unpublished artifact retained at {}",
                pending.display()
            ))
        })?;
    drop(file);
    match fs::hard_link(&pending, path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)
                .map_err(io)?
                .file_type()
                .is_file()
                || read(path)? != bytes
            {
                return Err(err(
                    "CONTEXT_STALE",
                    "existing immutable materialized context has different bytes; unpublished artifact retained",
                ));
            }
        }
        Err(e) => {
            return Err(io(format!(
                "{e}; unpublished artifact retained at {}",
                pending.display()
            )));
        }
    }
    fs::remove_file(&pending).map_err(io)?;
    fs::File::open(root).map_err(io)?.sync_all().map_err(io)
}
fn validate_log_bounded(
    receipt: &forgeflow_evidence::VerificationReceipt,
    artifact_root: &Path,
) -> Result<PathBuf> {
    let relative = Path::new(&receipt.log_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "unsafe raw log artifact path",
        ));
    }
    let root = fs::canonicalize(artifact_root).map_err(io)?;
    let log = fs::canonicalize(root.join(relative)).map_err(io)?;
    if !log.starts_with(&root) {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "raw log escapes artifact root",
        ));
    }
    let bytes = read(&log)?;
    if bytes.is_empty() || forgeflow_evidence::sha256(&bytes) != receipt.log_hash {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "missing or mismatched immutable raw log bytes",
        ));
    }
    Ok(log)
}
fn verify_receipt(
    receipt: &forgeflow_evidence::VerificationReceipt,
    attempt: &Attempt,
    producer: &TaskCard,
    integration: &MergeIntent,
    plan: &forgeflow_evidence::VerificationPlan,
    contract_version: &str,
    repo: &Path,
    integrated: bool,
) -> Result<()> {
    let mut expected = receipt.binding.clone();
    expected.task_revision = attempt.task_revision;
    expected.attempt_id = attempt.attempt_id.clone();
    expected.generation = attempt.generation;
    expected.base_sha = attempt.base_sha.clone();
    expected.candidate_sha = integration.candidate_sha.clone();
    expected.integrated_sha = if integrated {
        integration.integrated_sha.clone()
    } else {
        None
    };
    expected.contract_version = contract_version.into();
    expected.verification_plan_id = plan.plan_id.clone();
    expected.verification_plan_hash = plan.digest();
    expected.input_hash = producer.input_digest.clone();
    let source_sha = if integrated {
        integration
            .integrated_sha
            .as_deref()
            .ok_or_else(|| err("PRODUCER_INPUT_EVIDENCE", "final integrated SHA missing"))?
    } else {
        &integration.candidate_sha
    };
    expected.source_hash = forgeflow_git::source_hash(repo, source_sha).map_err(io)?;
    let commands: Vec<_> = plan
        .commands
        .iter()
        .flat_map(|c| {
            std::iter::once(c.program.to_string_lossy().into_owned()).chain(c.args.clone())
        })
        .collect();
    if receipt.command != commands
        || receipt.total
            != plan
                .commands
                .iter()
                .map(|c| c.expected_cases.len() as u64)
                .sum::<u64>()
        || receipt.environment_profile != plan.environment_profile
        || receipt.oracle_id != plan.oracle_id
        || receipt.verifier_id != plan.verifier_id
        || receipt.author_id != plan.author_id
    {
        return Err(err(
            "VERIFIER_INVALID",
            "producer receipt differs from pinned verification plan and denominator",
        ));
    }
    receipt.validate(&expected, true).map_err(io)
}
async fn proof(
    tx: &mut Transaction<'_, Postgres>,
    project: &Project,
    input: &forgeflow_planner::ProducerInputBinding,
) -> Result<ProducerInputEvidence> {
    let producer: TaskCard = decode(sqlx::query_scalar("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3 FOR SHARE")
        .bind(&project.project_id).bind(&input.producer_task_id).bind(i64v(input.producer_task_revision)?)
        .fetch_optional(&mut **tx).await?.ok_or_else(|| err("PRODUCER_INPUT_EVIDENCE", "exact immutable producer revision missing"))?)?;
    let producer_context: CompileContext = decode(
        document(
            tx,
            &project.project_id,
            "flow_contexts",
            &producer.flow_revision.to_string(),
        )
        .await?,
    )?;
    let spec = producer_context
        .task_specs
        .get(&producer.task_id)
        .ok_or_else(|| {
            err(
                "PRODUCER_INPUT_EVIDENCE",
                "original producer specification missing",
            )
        })?;
    if producer.input_digest != input.producer_input_digest
        || forgeflow_planner::canonical_task_input_digest(&producer, spec)
            != input.producer_input_digest
        || !spec.contract_produces.contains(&input.contract)
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "producer semantic identity or exact output contract changed",
        ));
    }
    let attempts = sqlx::query("SELECT data,envelope FROM attempts WHERE project_id=$1 AND task_id=$2 AND task_revision=$3 AND state='SUCCEEDED' FOR SHARE")
        .bind(&project.project_id).bind(&producer.task_id).bind(i64v(producer.task_revision)?).fetch_all(&mut **tx).await?;
    if attempts.len() != 1 {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "exact successful producer attempt is missing or ambiguous",
        ));
    }
    let attempt: Attempt = decode(attempts[0].try_get("data")?)?;
    let producer_envelope: ExecutionEnvelope = decode(attempts[0].try_get("envelope")?)?;
    if producer_envelope.project_id != project.project_id
        || producer_envelope.task_id != producer.task_id
        || producer_envelope.task_revision != producer.task_revision
        || producer_envelope.attempt_id != attempt.attempt_id
        || producer_envelope.generation != attempt.generation
        || producer_envelope.lease_id != attempt.lease_id
        || producer_envelope.worker_id != attempt.worker_id
        || producer_envelope.operation_id != attempt.operation_id
        || producer_envelope.base_sha != attempt.base_sha
        || fs::canonicalize(&producer_envelope.workspace_root).map_err(io)?
            != fs::canonicalize(&project.root_path).map_err(io)?
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "registered producer envelope differs from immutable attempt",
        ));
    }
    let integrations: Vec<Value> = sqlx::query_scalar("SELECT data FROM merge_intents WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 AND state IN('FINALIZED','COMMITTED') FOR SHARE")
        .bind(&project.project_id).bind(&attempt.attempt_id).bind(attempt.generation).fetch_all(&mut **tx).await?;
    if integrations.len() != 1 {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "final producer integration is missing or ambiguous",
        ));
    }
    let integration: MergeIntent = decode(integrations[0].clone())?;
    let contract_id = format!("{}:{}", input.contract.contract_id, input.contract.version);
    let receipts: Vec<Value> = sqlx::query_scalar("SELECT data FROM evidence_receipts WHERE project_id=$1 AND attempt_id=$2 AND generation=$3 AND kind='INDEPENDENT_VERIFICATION' AND data->'details'->'binding'->>'contract_version'=$4 FOR SHARE")
        .bind(&project.project_id).bind(&attempt.attempt_id).bind(attempt.generation).bind(&contract_id).fetch_all(&mut **tx).await?;
    if receipts.len() != 1 {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "exact independent producer receipt is missing or ambiguous",
        ));
    }
    let receipt: EvidenceReceipt = decode(receipts[0].clone())?;
    let plan: forgeflow_evidence::VerificationPlan = decode(
        document(
            tx,
            &project.project_id,
            "verification_plans",
            &producer_envelope.verification_plan_id,
        )
        .await?,
    )?;
    if plan.task_revision != producer.task_revision || plan.input_hash != producer.input_digest {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "registered producer verification plan has different semantics",
        ));
    }
    let repo = Path::new(&project.root_path);
    let verification: forgeflow_evidence::VerificationReceipt = decode(receipt.details.clone())?;
    verify_receipt(
        &verification,
        &attempt,
        &producer,
        &integration,
        &plan,
        &contract_id,
        repo,
        false,
    )?;
    let log_descriptor = document(
        tx,
        &project.project_id,
        "artifacts",
        &receipt.artifact.artifact_id,
    )
    .await?;
    let log = fs::canonicalize(log_descriptor["path"].as_str().ok_or_else(|| {
        err(
            "PRODUCER_INPUT_EVIDENCE",
            "registered producer log path missing",
        )
    })?)
    .map_err(io)?;
    let artifact_root = fs::canonicalize(&producer_envelope.artifact_prefix).map_err(io)?;
    if !log.starts_with(&artifact_root)
        || log_descriptor["sha256"].as_str() != Some(&receipt.artifact.sha256)
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "registered producer log escapes approved artifact root or has wrong hash",
        ));
    }
    let log_parent = log
        .parent()
        .ok_or_else(|| err("PRODUCER_INPUT_EVIDENCE", "producer log parent missing"))?;
    if validate_log_bounded(&verification, log_parent)? != log
        || serde_json::from_slice::<Value>(&read(&log_parent.join("verification-receipt.json"))?)?
            != receipt.details
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "independent producer durable receipt/log identity differs",
        ));
    }
    let integration_receipt = integration.receipt.as_ref().ok_or_else(|| {
        err(
            "PRODUCER_INPUT_EVIDENCE",
            "final integration receipt missing",
        )
    })?;
    let integrated_verification: forgeflow_evidence::VerificationReceipt =
        decode(integration_receipt["verification"].clone())?;
    verify_receipt(
        &integrated_verification,
        &attempt,
        &producer,
        &integration,
        &plan,
        &contract_id,
        repo,
        true,
    )?;
    let integration_root = fs::canonicalize(
        integration_receipt["artifact_root"]
            .as_str()
            .ok_or_else(|| {
                err(
                    "PRODUCER_INPUT_EVIDENCE",
                    "integration raw evidence root missing",
                )
            })?,
    )
    .map_err(io)?;
    if !integration_root.starts_with(fs::canonicalize(repo).map_err(io)?)
        || integration_receipt["verification_receipt_hash"].as_str()
            != Some(&integrated_verification.digest())
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "integration source or raw receipt identity differs",
        ));
    }
    validate_log_bounded(&integrated_verification, &integration_root)?;
    let durable: Value = serde_json::from_slice(&read(
        &integration_root.join("forgeflow-verification.json"),
    )?)?;
    if durable["verification"] != integration_receipt["verification"]
        || durable["verification_receipt_hash"] != integration_receipt["verification_receipt_hash"]
        || durable["new_sha"].as_str() != integration.integrated_sha.as_deref()
        || [
            "source_content_sha256",
            "source_content_algorithm",
            "source_tree_oid",
        ]
        .into_iter()
        .any(|field| {
            integration_receipt[field].as_str().is_none()
                || durable.get(field) != integration_receipt.get(field)
        })
    {
        return Err(err(
            "PRODUCER_INPUT_EVIDENCE",
            "durable final integration receipt differs from registered proof",
        ));
    }
    let contract: ContractVersion = decode(sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='contract_versions' AND document_id=$2 FOR SHARE")
        .bind(&project.project_id).bind(&contract_id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("PRODUCER_INPUT_EVIDENCE", "exact registered producer contract missing"))?)?;
    Ok(ProducerInputEvidence {
        producer,
        attempt,
        receipt,
        integration,
        contract,
    })
}

/// Called only from the locked admission transaction, after frozen-template comparison.
pub(crate) async fn materialize(
    tx: &mut Transaction<'_, Postgres>,
    project: &Project,
    task: &TaskCard,
    context: &CompileContext,
    envelope: &mut ExecutionEnvelope,
    execution_bindings: &mut Value,
) -> Result<()> {
    let spec = context.task_specs.get(&task.task_id).ok_or_else(|| {
        err(
            "PRODUCER_INPUT_EVIDENCE",
            "frozen task specification missing",
        )
    })?;
    if spec
        .inputs
        .iter()
        .any(|input| input.producer_task_id.is_some())
    {
        return Err(err(
            "PRODUCER_INPUT_RECIPE_REQUIRED",
            "legacy producer-tagged hashes cannot bypass exact immutable producer input materialization",
        ));
    }
    if spec.producer_inputs.is_empty() {
        return Ok(());
    }
    let frozen = task.envelope.as_ref().ok_or_else(|| {
        err(
            "PRODUCER_INPUT_EVIDENCE",
            "frozen execution template missing",
        )
    })?;
    if envelope != frozen {
        return Err(err(
            "CONTEXT_STALE",
            "materialization requires the exact approved frozen template",
        ));
    }
    let descriptor = document(
        tx,
        &project.project_id,
        "artifacts",
        &frozen.context_manifest.artifact_id,
    )
    .await?;
    let manifest_path = PathBuf::from(descriptor["path"].as_str().ok_or_else(|| {
        err(
            "PRODUCER_INPUT_EVIDENCE",
            "registered approved manifest path missing",
        )
    })?);
    let manifest_bytes = read(&manifest_path)?;
    if descriptor["sha256"].as_str() != Some(&frozen.context_manifest.sha256)
        || forgeflow_planner::sha256(&manifest_bytes) != frozen.context_manifest.sha256
    {
        return Err(err(
            "CONTEXT_STALE",
            "approved context manifest bytes changed",
        ));
    }
    let manifest: ContextManifest = decode(serde_json::from_slice(&manifest_bytes)?)?;
    let mut unique = BTreeSet::new();
    let mut proofs = Vec::new();
    for input in &spec.producer_inputs {
        let identity = (
            input.producer_task_id.clone(),
            input.producer_task_revision,
            input.contract.contract_id.clone(),
            input.contract.version,
        );
        if unique.insert(identity) {
            proofs.push(proof(tx, project, input).await?);
        }
    }
    let repo = Path::new(&project.root_path);
    let base_sha = forgeflow_git::resolve(repo, "refs/heads/main").map_err(io)?;
    let mut tree = ProducerInputTree {
        base_sha: base_sha.clone(),
        integrated_ancestors: BTreeSet::new(),
        base_inputs: BTreeMap::new(),
        producer_inputs: BTreeMap::new(),
        source_contents: BTreeMap::new(),
    };
    for proof in &proofs {
        let integrated = proof
            .integration
            .integrated_sha
            .as_deref()
            .ok_or_else(|| err("PRODUCER_INPUT_EVIDENCE", "producer integrated SHA missing"))?;
        if proof.integration.target_ref != "refs/heads/main"
            || !forgeflow_git::is_ancestor(repo, integrated, &base_sha).map_err(io)?
        {
            return Err(err(
                "PRODUCER_INPUT_TREE",
                "producer integration is not reachable from canonical execution base",
            ));
        }
        tree.integrated_ancestors.insert(integrated.into());
        if !tree.source_contents.contains_key(integrated) {
            // Recompute once per immutable integrated SHA, even when multiple
            // approved paths or contracts refer to that producer. The existing
            // admission API owns this transaction; do not trust receipt extras
            // or release its authority locks while constructing a reservation.
            // The Git helper has bounded object bytes and a 30-second deadline.
            let repository = repo.to_path_buf();
            let accepted_sha = integrated.to_owned();
            let actual = tokio::task::spawn_blocking(move || {
                forgeflow_git::source_content_manifest(&repository, &accepted_sha)
            })
            .await
            .map_err(io)?
            .map_err(io)?;
            if actual.commit_sha != integrated {
                return Err(err(
                    "PRODUCER_INPUT_EVIDENCE",
                    "actual content digest belongs to another integrated commit",
                ));
            }
            tree.source_contents.insert(
                integrated.into(),
                ProducerSourceContent {
                    algorithm: actual.algorithm,
                    commit_sha: actual.commit_sha,
                    tree_oid: actual.tree_oid,
                    source_sha256: actual.source_sha256,
                },
            );
        }
    }
    for input in &manifest.files {
        tree.base_inputs
            .insert(input.path.clone(), blob(repo, &base_sha, &input.path)?);
    }
    for input in &manifest.artifact_inputs {
        let descriptor = document(
            tx,
            &project.project_id,
            "artifacts",
            &input.artifact.artifact_id,
        )
        .await?;
        let path = descriptor["path"].as_str().ok_or_else(|| {
            err(
                "PRODUCER_INPUT_EVIDENCE",
                "known artifact input path missing",
            )
        })?;
        if descriptor["sha256"].as_str() != Some(&input.artifact.sha256)
            || forgeflow_planner::sha256(&read(Path::new(path))?) != input.artifact.sha256
        {
            return Err(err(
                "CONTEXT_STALE",
                "known controlled artifact input bytes changed",
            ));
        }
    }
    for input in &spec.producer_inputs {
        let accepted = proofs
            .iter()
            .find(|p| {
                p.producer.task_id == input.producer_task_id
                    && p.contract.contract_id == input.contract.contract_id
                    && p.contract.version == input.contract.version
            })
            .and_then(|p| p.integration.integrated_sha.as_deref())
            .ok_or_else(|| {
                err(
                    "PRODUCER_INPUT_EVIDENCE",
                    "exact producer integration missing",
                )
            })?;
        tree.producer_inputs
            .entry(accepted.into())
            .or_default()
            .insert(input.path.clone(), blob(repo, accepted, &input.path)?);
        tree.base_inputs
            .insert(input.path.clone(), blob(repo, &base_sha, &input.path)?);
    }
    let materialization =
        forgeflow_planner::materialize_producer_inputs(task, spec, &manifest_bytes, &proofs, &tree)
            .map_err(|e| {
                err(
                    if e.to_string().contains("INPUT_HASH_DRIFT") {
                        "CONTEXT_STALE"
                    } else {
                        "PRODUCER_INPUT_EVIDENCE"
                    },
                    e.to_string(),
                )
            })?;
    let bytes = serde_json::to_vec(&materialization.manifest)?;
    let root = fs::canonicalize(&frozen.artifact_prefix).map_err(io)?;
    if !root.is_dir() || !Path::new(&frozen.artifact_prefix).is_absolute() {
        return Err(err(
            "OWNER_PATH_VIOLATION",
            "materialized context must stay in approved canonical artifact root",
        ));
    }
    let artifact_id = format!(
        "producer-context-{}-{}",
        materialization.recipe_sha256, materialization.manifest_sha256
    );
    let path = root.join(format!("{artifact_id}.json"));
    publish_context(&root, &path, &bytes)?;
    if forgeflow_planner::sha256(&read(&path)?) != materialization.manifest_sha256
        || forgeflow_git::resolve(repo, "refs/heads/main").map_err(io)? != base_sha
    {
        return Err(err(
            "CONTEXT_STALE",
            "canonical execution base or materialized artifact changed during admission",
        ));
    }
    let descriptor = serde_json::json!({"artifact_id":artifact_id,"path":path,"sha256":materialization.manifest_sha256,
        "kind":"producer-input-context","bytes":bytes.len() as u64,"revision":1});
    let inserted = sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'artifacts',$2,1,$3) ON CONFLICT DO NOTHING")
        .bind(&project.project_id).bind(&artifact_id).bind(&descriptor).execute(&mut **tx).await?.rows_affected();
    let registered: Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE")
        .bind(&project.project_id).bind(&artifact_id).fetch_one(&mut **tx).await?;
    if registered != descriptor {
        return Err(err(
            "IDEMPOTENCY_CONFLICT",
            "materialized artifact immutable identity reused",
        ));
    }
    if inserted == 1 {
        event(
            tx,
            &project.project_id,
            &artifact_id,
            1,
            "context.producer_inputs_materialized",
            json(&materialization)?,
        )
        .await?;
    }
    envelope.base_sha = materialization.base_sha.clone();
    envelope.context_manifest.artifact_id = artifact_id;
    envelope.context_manifest.sha256 = materialization.manifest_sha256.clone();
    execution_bindings["producer_input_materialization"] = json(&materialization)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_publication_does_not_poison_immutable_retry_or_overwrite_existing_context() {
        let root = std::env::temp_dir().join(format!("forgeflow-context-publication-{}", id()));
        fs::create_dir_all(&root).unwrap();
        let pending = root.join(".producer-context-interrupted.pending");
        let final_path = root.join("context.json");
        fs::write(&pending, b"{partial").unwrap();
        assert!(!final_path.exists());
        let bytes = b"{\"complete\":true}";
        publish_context(&root, &final_path, bytes).unwrap();
        assert_eq!(read(&final_path).unwrap(), bytes);
        assert_eq!(read(&pending).unwrap(), b"{partial");
        publish_context(&root, &final_path, bytes).unwrap();
        assert!(publish_context(&root, &final_path, b"{\"different\":true}").is_err());
        assert_eq!(read(&final_path).unwrap(), bytes);
        #[cfg(unix)]
        {
            let alias = root.join("alias.json");
            std::os::unix::fs::symlink(&final_path, &alias).unwrap();
            assert!(publish_context(&root, &alias, bytes).is_err());
        }
        let oversized = root.join("oversized");
        fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_INPUT_BYTES + 1)
            .unwrap();
        assert!(read(&oversized).is_err());
        let oversized_context = root.join("oversized-context.json");
        assert!(
            publish_context(
                &root,
                &oversized_context,
                &vec![b' '; MAX_INPUT_BYTES as usize + 1],
            )
            .is_err()
        );
        assert!(!oversized_context.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
