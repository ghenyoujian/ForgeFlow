//! Owner-scoped release acceptance, real manifest export and phase handoff.
//! Existing milestone verification remains the sole evidence acceptance oracle.
use crate::*;
use std::{
    collections::BTreeSet,
    io::Read,
    path::Path,
    process::{Command, Stdio},
};

const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

impl Store {
    pub async fn list_releases(&self, project: &str) -> Result<Vec<Release>> {
        self.get_project(project).await?;
        let rows: Vec<Value> = sqlx::query_scalar("SELECT d.data FROM documents d WHERE d.project_id=$1 AND d.collection='releases' AND d.data->>'schema_version'=$2 AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='release_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data) ORDER BY d.document_id")
            .bind(project).bind(RELEASE_SCHEMA).fetch_all(&self.pool).await?;
        rows.into_iter().map(decode).collect()
    }
    pub async fn get_release(&self, project: &str, release: &str) -> Result<Release> {
        let row: Option<Value> = sqlx::query_scalar("SELECT d.data FROM documents d WHERE d.project_id=$1 AND d.collection='releases' AND d.document_id=$2 AND d.data->>'schema_version'=$3 AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='release_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data)")
            .bind(project).bind(release).bind(RELEASE_SCHEMA).fetch_optional(&self.pool).await?;
        decode(row.ok_or_else(|| err("NOT_FOUND", "verified release not found"))?)
    }
    pub async fn list_project_phases(&self, project: &str) -> Result<Vec<ProjectPhase>> {
        self.get_project(project).await?;
        let rows: Vec<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='project_phases' AND data->>'schema_version'='forgeflow.project-phase.v1' ORDER BY (data->>'ordinal')::bigint,document_id")
            .bind(project).fetch_all(&self.pool).await?;
        rows.into_iter().map(decode).collect()
    }
    /// Exact compact UTF8 JSON bytes, no trailing newline. Downloading these
    /// bytes neither accepts a release nor records an actual exported artifact.
    pub async fn release_manifest_bytes(&self, project: &str, release: &str) -> Result<Vec<u8>> {
        manifest_bytes(&self.get_release(project, release).await?)
    }
    pub async fn get_release_export(
        &self,
        project: &str,
        release: &str,
    ) -> Result<Option<ReleaseExportReceipt>> {
        let release = self.get_release(project, release).await?;
        let value:Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='release_exports' AND document_id=$2")
            .bind(project).bind(&release.release_id).fetch_optional(&self.pool).await?;
        let receipt: Option<ReleaseExportReceipt> = value.map(decode).transpose()?;
        if receipt.as_ref().is_some_and(|r| {
            r.schema_version != "forgeflow.release-export.v1"
                || r.project_id != project
                || r.release_id != release.release_id
                || Some(&r.manifest_sha256) != release.manifest_sha256.as_ref()
        }) {
            return Err(err(
                "RELEASE_EXPORT_MISMATCH",
                "immutable export receipt binding differs from accepted release",
            ));
        }
        Ok(receipt)
    }
}

fn explanation(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(err(
            "RELEASE_INVALID",
            "nonempty release explanation up to 4096 bytes required",
        ));
    }
    Ok(())
}

fn manifest_bytes(release: &Release) -> Result<Vec<u8>> {
    let manifest = release.manifest.as_ref().ok_or_else(|| {
        err(
            "RELEASE_STATE_CONFLICT",
            "release candidate manifest not created",
        )
    })?;
    let bytes = serde_json::to_vec(manifest)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES
        || release.manifest_sha256.as_deref() != Some(forgeflow_planner::sha256(&bytes).as_str())
    {
        return Err(err(
            "RELEASE_MANIFEST_MISMATCH",
            "immutable release manifest bytes/hash differ",
        ));
    }
    Ok(bytes)
}

fn actual_file(path: &str) -> Result<Vec<u8>> {
    actual_file_with_limit(path, MAX_MANIFEST_BYTES)
}
fn actual_file_with_limit(path: &str, limit: u64) -> Result<Vec<u8>> {
    let path = Path::new(path);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| err("RELEASE_ARTIFACT_MISSING", e.to_string()))?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > limit
    {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "registered artifact must be a bounded regular absolute file",
        ));
    }
    let file =
        std::fs::File::open(path).map_err(|e| err("RELEASE_ARTIFACT_MISSING", e.to_string()))?;
    if !file
        .metadata()
        .map_err(|e| err("RELEASE_ARTIFACT_MISSING", e.to_string()))?
        .is_file()
    {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "opened artifact is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| err("RELEASE_ARTIFACT_MISSING", e.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "actual artifact exceeds byte limit",
        ));
    }
    Ok(bytes)
}

fn bounded_output(mut command: Command, limit: u64) -> Result<Vec<u8>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| err("RELEASE_EXPORT_MISMATCH", e.to_string()))?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or_else(|| {
            err(
                "RELEASE_EXPORT_MISMATCH",
                "export command stdout unavailable",
            )
        })?
        .take(limit + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > limit {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "export command exceeded bounded output or failed read",
        ));
    }
    if !child
        .wait()
        .map_err(|e| err("RELEASE_EXPORT_MISMATCH", e.to_string()))?
        .success()
    {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "export member/source command failed",
        ));
    }
    Ok(bytes)
}

fn trusted_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LC_ALL", "C");
    command
}

fn source_archive(project: &Project, commit: &str) -> Result<Vec<u8>> {
    if !valid_sha(commit) {
        return Err(err("RELEASE_MAIN_STALE", "release archive commit invalid"));
    }
    let mut command = trusted_command("git");
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .args([
            "-C",
            &project.root_path,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "archive",
            "--format=tar",
            commit,
        ]);
    bounded_output(command, MAX_BUNDLE_BYTES)
}

fn tar_member(path: &str, member: &str, limit: u64) -> Result<Vec<u8>> {
    let mut command = trusted_command("tar");
    command.args(["--force-local", "-xOf", path, "--", member]);
    bounded_output(command, limit)
}

fn verify_bundle(project: &Project, release: &Release, path: &str) -> Result<String> {
    let manifest = release
        .manifest
        .as_ref()
        .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "release manifest missing"))?;
    let mut expected: BTreeSet<String> = ["manifest.json", "source.tar", "INSTALLATION.txt"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for file in &manifest.files {
        if file.artifact_id.is_empty()
            || file.artifact_id == "."
            || file.artifact_id == ".."
            || file
                .artifact_id
                .chars()
                .any(|c| c == '/' || c == '\\' || c.is_control())
        {
            return Err(err(
                "RELEASE_EXPORT_MISMATCH",
                "unsafe bound artifact bundle identity",
            ));
        }
        expected.insert(format!("artifacts/{}", file.artifact_id));
    }
    let mut command = trusted_command("tar");
    command.args(["--force-local", "-tf", path]);
    let listing = String::from_utf8(bounded_output(command, 1024 * 1024)?).map_err(|_| {
        err(
            "RELEASE_EXPORT_MISMATCH",
            "bundle member listing must be UTF8",
        )
    })?;
    let mut seen = BTreeSet::new();
    for member in listing.lines() {
        if !seen.insert(member.to_owned()) || (member != "artifacts/" && !expected.contains(member))
        {
            return Err(err(
                "RELEASE_EXPORT_MISMATCH",
                "bundle has duplicate or undeclared members",
            ));
        }
    }
    seen.remove("artifacts/");
    if seen != expected
        || tar_member(path, "manifest.json", MAX_MANIFEST_BYTES)? != manifest_bytes(release)?
        || tar_member(path, "INSTALLATION.txt", MAX_MANIFEST_BYTES)?
            != manifest.installation.as_bytes()
    {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "bundle manifest/installation/members differ from frozen declaration",
        ));
    }
    for file in &manifest.files {
        let bytes = tar_member(
            path,
            &format!("artifacts/{}", file.artifact_id),
            MAX_MANIFEST_BYTES,
        )?;
        if bytes.len() as u64 != file.bytes || forgeflow_planner::sha256(&bytes) != file.sha256 {
            return Err(err(
                "RELEASE_EXPORT_MISMATCH",
                "bundled independent artifact bytes/hash mismatch",
            ));
        }
    }
    let source = tar_member(path, "source.tar", MAX_BUNDLE_BYTES)?;
    let expected_source = source_archive(project, &manifest.main_sha)?;
    let digest = forgeflow_planner::sha256(&source);
    if digest != forgeflow_planner::sha256(&expected_source) {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "bundle source archive is not exact frozen canonical main output",
        ));
    }
    Ok(digest)
}

async fn record(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    collection: &str,
    id: &str,
    revision: u64,
    value: &Value,
) -> Result<()> {
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,$2,$3,$4,$5)")
        .bind(project).bind(collection).bind(id).bind(i64v(revision)?).bind(value).execute(&mut **tx).await?;
    Ok(())
}

async fn persist_release(
    tx: &mut Transaction<'_, Postgres>,
    release: &Release,
    old: Option<u64>,
    kind: &str,
) -> Result<()> {
    let value = json(release)?;
    if let Some(old) = old {
        let changed = sqlx::query("UPDATE documents SET revision=$4,data=$5 WHERE project_id=$1 AND collection='releases' AND document_id=$2 AND revision=$3")
            .bind(&release.project_id).bind(&release.release_id).bind(i64v(old)?).bind(i64v(release.revision)?).bind(&value)
            .execute(&mut **tx).await?.rows_affected();
        if changed != 1 {
            return Err(err("REVISION_CONFLICT", "release compare-and-set lost"));
        }
    } else {
        record(
            tx,
            &release.project_id,
            "releases",
            &release.release_id,
            release.revision,
            &value,
        )
        .await?;
    }
    record(
        tx,
        &release.project_id,
        "release_history",
        &format!("{}:{}", release.release_id, release.revision),
        release.revision,
        &value,
    )
    .await?;
    event(
        tx,
        &release.project_id,
        &release.release_id,
        release.revision,
        kind,
        value,
    )
    .await
}

async fn release_lock(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    id: &str,
    revision: u64,
) -> Result<Release> {
    let row = sqlx::query("SELECT d.data,d.revision FROM documents d WHERE d.project_id=$1 AND d.collection='releases' AND d.document_id=$2 AND d.data->>'schema_version'=$3 AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='release_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data) FOR UPDATE OF d")
        .bind(project).bind(id).bind(RELEASE_SCHEMA).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("NOT_FOUND", "verified release not found"))?;
    let release: Release = decode(row.get("data"))?;
    if release.project_id != project
        || release.release_id != id
        || release.revision != revision
        || row.get::<i64, _>("revision") != i64v(revision)?
    {
        return Err(err("REVISION_CONFLICT", "release revision changed"));
    }
    Ok(release)
}

async fn latest_phase(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
) -> Result<Option<ProjectPhase>> {
    let value: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='project_phases' AND data->>'schema_version'='forgeflow.project-phase.v1' ORDER BY (data->>'ordinal')::bigint DESC LIMIT 1 FOR SHARE")
        .bind(project).fetch_optional(&mut **tx).await?;
    value.map(decode).transpose()
}

fn main_identity(project: &Project) -> Result<(String, String)> {
    let repo = Path::new(&project.root_path);
    let main = forgeflow_git::resolve(repo, "refs/heads/main")
        .map_err(|e| err("RELEASE_MAIN_STALE", e.to_string()))?;
    let tree = forgeflow_git::source_hash(repo, &main)
        .map_err(|e| err("RELEASE_MAIN_STALE", e.to_string()))?;
    if !valid_sha(&main) || !valid_sha(&tree) {
        return Err(err(
            "RELEASE_MAIN_STALE",
            "canonical main/tree identity invalid",
        ));
    }
    Ok((main, tree))
}

async fn no_pending_integration(tx: &mut Transaction<'_, Postgres>, project: &str) -> Result<()> {
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND state IN('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED'))")
        .bind(project).fetch_one(&mut **tx).await?;
    if pending {
        return Err(err(
            "RELEASE_MAIN_CONFLICT",
            "pending canonical integration retains main authority",
        ));
    }
    Ok(())
}

async fn build_manifest(
    tx: &mut Transaction<'_, Postgres>,
    release: &Release,
    project: &Project,
    expected_main: &str,
    actor: &str,
) -> Result<ReleaseManifest> {
    no_pending_integration(tx, &project.project_id).await?;
    let (main_sha, main_tree_oid) = main_identity(project)?;
    if main_sha != expected_main {
        return Err(err(
            "RELEASE_MAIN_STALE",
            "actual canonical main differs from reviewed release commit",
        ));
    }
    let mut milestone_acceptances = Vec::new();
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for binding in &release.milestone_refs {
        let accepted: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='milestone_acceptances' AND document_id=$2 FOR SHARE")
            .bind(&project.project_id).bind(format!("{}:{}", binding.milestone_id, binding.baseline_version)).fetch_optional(&mut **tx).await?;
        let accepted = accepted.ok_or_else(|| {
            err(
                "EVIDENCE_INCOMPLETE",
                "required milestone baseline has not been accepted",
            )
        })?;
        if accepted["status"] != "ACCEPTED"
            || accepted["milestone_revision"] != binding.milestone_revision
            || accepted["baseline_version"] != binding.baseline_version
        {
            return Err(err(
                "RELEASE_ACCEPTANCE_STALE",
                "milestone acceptance differs from frozen requested baseline",
            ));
        }
        // Reuse the existing independent current-requirement/task/Gate validator.
        // This must find the original receipt first; never accept implicitly.
        let checked = crate::milestone_acceptance::accept_in_transaction(
            tx,
            &project.project_id,
            &binding.milestone_id,
            binding.milestone_revision,
            binding.baseline_version,
            actor,
        )
        .await?;
        if checked != accepted {
            return Err(err(
                "RELEASE_ACCEPTANCE_STALE",
                "milestone acceptance changed",
            ));
        }
        let evidence = accepted["evidence_refs"]
            .as_array()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                err(
                    "EVIDENCE_INCOMPLETE",
                    "accepted baseline lacks independent integration evidence",
                )
            })?;
        for evidence in evidence {
            let integrated = evidence["integrated_sha"]
                .as_str()
                .filter(|v| valid_sha(v))
                .ok_or_else(|| {
                    err(
                        "EVIDENCE_INCOMPLETE",
                        "accepted baseline lacks integrated commit",
                    )
                })?;
            if !forgeflow_git::is_ancestor(Path::new(&project.root_path), integrated, &main_sha)
                .map_err(|e| err("RELEASE_MAIN_STALE", e.to_string()))?
            {
                return Err(err(
                    "RELEASE_MAIN_STALE",
                    "accepted integration is not an actual ancestor of release main",
                ));
            }
            let artifact: ArtifactRef = decode(evidence["candidate_artifact"].clone())?;
            if seen.insert(artifact.artifact_id.clone()) {
                let descriptor: Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE")
                    .bind(&project.project_id).bind(&artifact.artifact_id).fetch_optional(&mut **tx).await?
                    .ok_or_else(||err("EVIDENCE_INCOMPLETE", "accepted independent artifact no longer registered"))?;
                let path = descriptor["path"].as_str().ok_or_else(|| {
                    err("EVIDENCE_INCOMPLETE", "registered artifact path missing")
                })?;
                let bytes = actual_file(path)?;
                if descriptor["sha256"] != artifact.sha256
                    || forgeflow_planner::sha256(&bytes) != artifact.sha256
                {
                    return Err(err(
                        "RELEASE_ARTIFACT_MISMATCH",
                        "actual independent artifact bytes differ from accepted receipt",
                    ));
                }
                files.push(ReleaseFileIdentity {
                    artifact_id: artifact.artifact_id,
                    sha256: artifact.sha256,
                    bytes: bytes.len() as u64,
                });
            }
        }
        milestone_acceptances.push(accepted);
    }
    // Include explicit system limitations rather than upgrading product Gates
    // through an Owner's acceptance of a narrower milestone release scope.
    let mut not_proven = release.not_proven.clone();
    not_proven.push(
        "Global product production qualification is outside this Owner-declared release scope."
            .into(),
    );
    not_proven.push("Bundled source and bound artifacts do not by themselves prove a clean installation; installation instructions are Owner-declared.".into());
    let manifest = ReleaseManifest {
        schema_version: "forgeflow.release-manifest.v1".into(),
        release_id: release.release_id.clone(),
        project_id: project.project_id.clone(),
        phase_id: release.phase_id.clone(),
        title: release.title.clone(),
        scope: "OWNER_DECLARED_MILESTONE_SCOPE".into(),
        main_sha,
        main_tree_oid,
        milestone_acceptances,
        files,
        installation: release.installation.clone(),
        not_proven,
        risk_dispositions: release.risk_dispositions.clone(),
        production_gate_claim: "NO_GLOBAL_PRODUCTION_GATE_PROMOTION".into(),
        export_scope: "MANIFEST_SOURCE_AND_BOUND_ARTIFACTS_BUNDLE".into(),
    };
    if serde_json::to_vec(&manifest)?.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(err(
            "RELEASE_INVALID",
            "release manifest exceeds bounded byte limit",
        ));
    }
    // The coordinator prevents a new platform merge decision during these
    // reads; external repository drift is detected again before transaction end.
    if main_identity(project)? != (manifest.main_sha.clone(), manifest.main_tree_oid.clone()) {
        return Err(err(
            "RELEASE_MAIN_STALE",
            "canonical main changed while preparing release",
        ));
    }
    Ok(manifest)
}

async fn export_receipt(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    release: &str,
) -> Result<Option<ReleaseExportReceipt>> {
    let row: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='release_exports' AND document_id=$2 FOR SHARE")
        .bind(project).bind(release).fetch_optional(&mut **tx).await?;
    row.map(decode).transpose()
}

async fn export_available(
    tx: &mut Transaction<'_, Postgres>,
    release: &Release,
) -> Result<ReleaseExportReceipt> {
    let receipt = export_receipt(tx, &release.project_id, &release.release_id)
        .await?
        .ok_or_else(|| {
            err(
                "EVIDENCE_INCOMPLETE",
                "actual immutable release bundle export required",
            )
        })?;
    if Some(&receipt.manifest_sha256) != release.manifest_sha256.as_ref() {
        return Err(err(
            "RELEASE_EXPORT_MISMATCH",
            "export receipt differs from frozen manifest",
        ));
    }
    for (artifact, kind, size, limit) in [
        (
            &receipt.artifact,
            "RELEASE_MANIFEST",
            receipt.bytes,
            MAX_MANIFEST_BYTES,
        ),
        (
            &receipt.bundle,
            "RELEASE_BUNDLE",
            receipt.bundle_bytes,
            MAX_BUNDLE_BYTES,
        ),
    ] {
        let descriptor:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE")
            .bind(&release.project_id).bind(&artifact.artifact_id).fetch_optional(&mut **tx).await?
            .ok_or_else(||err("EVIDENCE_INCOMPLETE","registered release export artifact missing"))?;
        let bytes = actual_file_with_limit(
            descriptor["path"]
                .as_str()
                .ok_or_else(|| err("RELEASE_EXPORT_MISMATCH", "export artifact path missing"))?,
            limit,
        )?;
        if descriptor["kind"] != kind
            || descriptor["sha256"] != artifact.sha256
            || bytes.len() as u64 != size
            || forgeflow_planner::sha256(&bytes) != artifact.sha256
        {
            return Err(err(
                "RELEASE_EXPORT_MISMATCH",
                "actual exported artifact no longer matches immutable receipt",
            ));
        }
    }
    Ok(receipt)
}

async fn quiescent(tx: &mut Transaction<'_, Postgres>, project: &str) -> Result<()> {
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attempts WHERE project_id=$1 AND terminal_at IS NULL) OR EXISTS(SELECT 1 FROM leases WHERE project_id=$1 AND revoked_at IS NULL) OR EXISTS(SELECT 1 FROM resource_allocations WHERE project_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_child_lifecycles WHERE project_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_child_allocations WHERE project_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_model_requests WHERE project_id=$1 AND status IN('ADMITTED','QUARANTINED')) OR EXISTS(SELECT 1 FROM merge_intents WHERE project_id=$1 AND state IN('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED')) OR EXISTS(SELECT 1 FROM model_request_permit m JOIN attempts a ON a.attempt_id=m.attempt_id WHERE a.project_id=$1 AND m.status IN('ADMITTED','QUARANTINED')) OR EXISTS(SELECT 1 FROM gateway_scope_budget g JOIN attempts a ON a.attempt_id=g.attempt_id WHERE a.project_id=$1 AND g.inflight>0)")
        .bind(project).fetch_one(&mut **tx).await?;
    if pending {
        return Err(err(
            "ARCHIVE_BLOCKED",
            "release archive/reopen requires confirmed zero project custody; pause new work and drain",
        ));
    }
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT data FROM attempts WHERE project_id=$1 ORDER BY attempt_id FOR SHARE",
    )
    .bind(project)
    .fetch_all(&mut **tx)
    .await?;
    for value in rows {
        let attempt: Attempt = decode(value)?;
        crate::collaboration::require_verifier_roots_settled(tx, &attempt).await?;
    }
    Ok(())
}

async fn outcome(
    tx: &mut Transaction<'_, Postgres>,
    release: Release,
    project: Project,
    phase: ProjectPhase,
) -> Result<Value> {
    let export = export_receipt(tx, &project.project_id, &release.release_id).await?;
    json(&ReleaseOutcome {
        accepted: release.state == ReleaseState::Accepted,
        release,
        project,
        phase,
        export,
    })
}

pub(crate) async fn apply_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    command: ReleaseCommand,
    actor: &str,
) -> Result<Value> {
    if actor.trim().is_empty()
        || actor.starts_with("worker-service")
        || matches!(
            actor,
            "internal"
                | "release-service"
                | "scheduler-service"
                | "verification-service"
                | "recovery-service"
        )
    {
        return Err(err(
            "RELEASE_OWNER_REQUIRED",
            "authenticated Owner review required",
        ));
    }
    let project = match &command {
        ReleaseCommand::CreateDraft { project_id, .. }
        | ReleaseCommand::CreateCandidate { project_id, .. }
        | ReleaseCommand::Accept { project_id, .. }
        | ReleaseCommand::RecordExport { project_id, .. }
        | ReleaseCommand::Archive { project_id, .. }
        | ReleaseCommand::Reopen { project_id, .. } => project_id,
    };
    let mut p = project_lock(tx, project).await?;
    if p.authority_mode != AuthorityMode::Managed {
        return Err(err(
            "RELEASE_SCOPE_DENIED",
            "managed canonical project required",
        ));
    }
    if let ReleaseCommand::CreateDraft {
        project_id,
        expected_project_revision,
        title,
        milestone_refs,
        installation,
        not_proven,
        risk_dispositions,
    } = command
    {
        if p.archived || p.revision != expected_project_revision {
            return Err(err(
                "REVISION_CONFLICT",
                "draft requires current nonarchived project revision",
            ));
        }
        explanation(&title)?;
        explanation(&installation)?;
        if milestone_refs.is_empty()
            || milestone_refs.len() > 128
            || not_proven.len() > 128
            || risk_dispositions.len() > 128
        {
            return Err(err(
                "RELEASE_INVALID",
                "bounded nonempty milestone scope required",
            ));
        }
        for text in not_proven.iter().chain(&risk_dispositions) {
            explanation(text)?;
        }
        let mut ids = BTreeSet::new();
        for binding in &milestone_refs {
            if !ids.insert(&binding.milestone_id)
                || binding.milestone_id.trim().is_empty()
                || binding.milestone_revision == 0
                || binding.baseline_version == 0
            {
                return Err(err(
                    "RELEASE_INVALID",
                    "distinct milestone IDs and positive bound revisions required",
                ));
            }
            let row: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='milestones' AND document_id=$2 FOR SHARE")
                .bind(&project_id).bind(&binding.milestone_id).fetch_optional(&mut **tx).await?;
            let milestone: Milestone =
                decode(row.ok_or_else(|| err("NOT_FOUND", "release milestone missing"))?)?;
            if milestone.revision != binding.milestone_revision
                || milestone.baseline_version != binding.baseline_version
            {
                return Err(err(
                    "RELEASE_ACCEPTANCE_STALE",
                    "release draft milestone baseline changed",
                ));
            }
        }
        let now = db_now(tx).await?;
        let phase = if let Some(phase) = latest_phase(tx, &project_id).await? {
            phase
        } else {
            let phase = ProjectPhase {
                schema_version: "forgeflow.project-phase.v1".into(),
                phase_id: id(),
                project_id: project_id.clone(),
                ordinal: 1,
                previous_release_id: None,
                title: p.name.clone(),
                goal: p.goal.clone(),
                baseline_main_sha: main_identity(&p)?.0,
                created_by: actor.into(),
                created_at: now,
                revision: 1,
            };
            record(
                tx,
                &project_id,
                "project_phases",
                &phase.phase_id,
                1,
                &json(&phase)?,
            )
            .await?;
            event(
                tx,
                &project_id,
                &phase.phase_id,
                1,
                "project.phase.created",
                json(&phase)?,
            )
            .await?;
            phase
        };
        let release = Release {
            schema_version: RELEASE_SCHEMA.into(),
            release_id: id(),
            project_id,
            phase_id: phase.phase_id.clone(),
            state: ReleaseState::Draft,
            revision: 1,
            title,
            milestone_refs,
            installation,
            not_proven,
            risk_dispositions,
            created_by: actor.into(),
            created_at: now,
            updated_at: now,
            candidate_by: None,
            candidate_at: None,
            accepted_by: None,
            accepted_at: None,
            acceptance_note: None,
            manifest: None,
            manifest_sha256: None,
        };
        persist_release(tx, &release, None, "release.draft.created").await?;
        return outcome(tx, release, p, phase).await;
    }
    let (release_id, expected_revision) = match &command {
        ReleaseCommand::CreateCandidate {
            release_id,
            expected_revision,
            ..
        }
        | ReleaseCommand::Accept {
            release_id,
            expected_revision,
            ..
        }
        | ReleaseCommand::RecordExport {
            release_id,
            expected_revision,
            ..
        }
        | ReleaseCommand::Archive {
            release_id,
            expected_revision,
            ..
        }
        | ReleaseCommand::Reopen {
            release_id,
            expected_revision,
            ..
        } => (release_id, *expected_revision),
        ReleaseCommand::CreateDraft { .. } => unreachable!(),
    };
    let mut release = release_lock(tx, &p.project_id, release_id, expected_revision).await?;
    let mut phase = latest_phase(tx, &p.project_id)
        .await?
        .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "release project phase missing"))?;
    if phase.phase_id != release.phase_id {
        return Err(err(
            "RELEASE_PHASE_STALE",
            "old release cannot mutate a later project phase",
        ));
    }
    match command {
        ReleaseCommand::CreateCandidate {
            expected_main_sha, ..
        } => {
            if p.archived || release.state != ReleaseState::Draft {
                return Err(err(
                    "RELEASE_STATE_CONFLICT",
                    "candidate requires nonarchived DRAFT release",
                ));
            }
            let manifest = build_manifest(tx, &release, &p, &expected_main_sha, actor).await?;
            release.manifest_sha256 =
                Some(forgeflow_planner::sha256(&serde_json::to_vec(&manifest)?));
            release.manifest = Some(manifest);
            let now = db_now(tx).await?;
            release.state = ReleaseState::Candidate;
            release.candidate_by = Some(actor.into());
            release.candidate_at = Some(now);
            release.updated_at = now;
            release.revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| err("REVISION_CONFLICT", "release revision overflow"))?;
            persist_release(
                tx,
                &release,
                Some(expected_revision),
                "release.candidate.created",
            )
            .await?;
        }
        ReleaseCommand::Accept {
            expected_manifest_sha256,
            note,
            ..
        } => {
            explanation(&note)?;
            if p.archived || release.state != ReleaseState::Candidate {
                return Err(err(
                    "RELEASE_STATE_CONFLICT",
                    "Owner acceptance requires current CANDIDATE",
                ));
            }
            let bytes = manifest_bytes(&release)?;
            if forgeflow_planner::sha256(&bytes) != expected_manifest_sha256 {
                return Err(err(
                    "RELEASE_MANIFEST_STALE",
                    "Owner reviewed manifest digest changed",
                ));
            }
            let previous = release.manifest.as_ref().unwrap();
            let current = build_manifest(tx, &release, &p, &previous.main_sha, actor).await?;
            if serde_json::to_vec(&current)? != bytes {
                return Err(err(
                    "RELEASE_ACCEPTANCE_STALE",
                    "candidate source/evidence/baseline changed before Owner acceptance",
                ));
            }
            let now = db_now(tx).await?;
            release.state = ReleaseState::Accepted;
            release.accepted_by = Some(actor.into());
            release.accepted_at = Some(now);
            release.acceptance_note = Some(note);
            release.updated_at = now;
            release.revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| err("REVISION_CONFLICT", "release revision overflow"))?;
            let acceptance = serde_json::json!({"schema_version":"forgeflow.release-acceptance.v1","release_id":release.release_id,"project_id":p.project_id,
                "phase_id":phase.phase_id,"manifest_sha256":expected_manifest_sha256,"release_revision":release.revision,"accepted_by":actor,"accepted_at":now,
                "note":release.acceptance_note,"scope":"OWNER_DECLARED_MILESTONE_SCOPE","production_gate_claim":"NO_GLOBAL_PRODUCTION_GATE_PROMOTION","revision":1});
            record(
                tx,
                &p.project_id,
                "release_acceptances",
                &release.release_id,
                1,
                &acceptance,
            )
            .await?;
            persist_release(tx, &release, Some(expected_revision), "release.accepted").await?;
        }
        ReleaseCommand::RecordExport {
            artifact_id,
            bundle_artifact_id,
            ..
        } => {
            if release.state != ReleaseState::Accepted {
                return Err(err(
                    "RELEASE_STATE_CONFLICT",
                    "actual export receipt requires ACCEPTED release",
                ));
            }
            let expected = manifest_bytes(&release)?;
            let descriptor: Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE")
                .bind(&p.project_id).bind(&artifact_id).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE", "server export artifact not registered"))?;
            let path = descriptor["path"].as_str().ok_or_else(|| {
                err(
                    "RELEASE_EXPORT_MISMATCH",
                    "server export descriptor missing path",
                )
            })?;
            let bytes = actual_file(path)?;
            let hash = forgeflow_planner::sha256(&bytes);
            if bytes != expected
                || descriptor["kind"] != "RELEASE_MANIFEST"
                || descriptor["sha256"] != hash
                || descriptor["bytes"].as_u64() != Some(bytes.len() as u64)
            {
                return Err(err(
                    "RELEASE_EXPORT_MISMATCH",
                    "actual registered server artifact differs from frozen manifest bytes/hash/size",
                ));
            }
            let artifact = ArtifactRef {
                artifact_id,
                sha256: hash.clone(),
            };
            let bundle_descriptor:Value=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE")
                .bind(&p.project_id).bind(&bundle_artifact_id).fetch_optional(&mut **tx).await?.ok_or_else(||err("EVIDENCE_INCOMPLETE","server bundle artifact not registered"))?;
            let bundle_path = bundle_descriptor["path"].as_str().ok_or_else(|| {
                err(
                    "RELEASE_EXPORT_MISMATCH",
                    "bundle descriptor missing actual path",
                )
            })?;
            let bundle_bytes = actual_file_with_limit(bundle_path, MAX_BUNDLE_BYTES)?;
            let bundle_sha = forgeflow_planner::sha256(&bundle_bytes);
            if bundle_descriptor["kind"] != "RELEASE_BUNDLE"
                || bundle_descriptor["sha256"] != bundle_sha
                || bundle_descriptor["bytes"].as_u64() != Some(bundle_bytes.len() as u64)
            {
                return Err(err(
                    "RELEASE_EXPORT_MISMATCH",
                    "actual bundle bytes/hash/size differ from registered server descriptor",
                ));
            }
            let source_archive_sha256 = verify_bundle(&p, &release, bundle_path)?;
            // A path replacement during member validation cannot confer rights.
            if forgeflow_planner::sha256(&actual_file_with_limit(bundle_path, MAX_BUNDLE_BYTES)?)
                != bundle_sha
            {
                return Err(err(
                    "RELEASE_EXPORT_MISMATCH",
                    "bundle bytes changed while validating members",
                ));
            }
            let bundle = ArtifactRef {
                artifact_id: bundle_artifact_id,
                sha256: bundle_sha,
            };
            if let Some(old) = export_receipt(tx, &p.project_id, &release.release_id).await? {
                if old.artifact != artifact
                    || old.manifest_sha256 != hash
                    || old.bundle != bundle
                    || old.source_archive_sha256 != source_archive_sha256
                {
                    return Err(err(
                        "IDEMPOTENCY_CONFLICT",
                        "release export receipt immutable",
                    ));
                }
            } else {
                let receipt = ReleaseExportReceipt {
                    schema_version: "forgeflow.release-export.v1".into(),
                    export_id: id(),
                    project_id: p.project_id.clone(),
                    release_id: release.release_id.clone(),
                    manifest_sha256: hash,
                    artifact,
                    bytes: bytes.len() as u64,
                    bundle,
                    bundle_bytes: bundle_bytes.len() as u64,
                    source_archive_sha256,
                    exported_by: actor.into(),
                    exported_at: db_now(tx).await?,
                    revision: 1,
                };
                record(
                    tx,
                    &p.project_id,
                    "release_exports",
                    &release.release_id,
                    1,
                    &json(&receipt)?,
                )
                .await?;
                event(
                    tx,
                    &p.project_id,
                    &release.release_id,
                    release.revision,
                    "export.completed",
                    json(&receipt)?,
                )
                .await?;
            }
        }
        ReleaseCommand::Archive {
            expected_project_revision,
            reason,
            ..
        } => {
            explanation(&reason)?;
            if p.archived
                || p.revision != expected_project_revision
                || release.state != ReleaseState::Accepted
            {
                return Err(err(
                    "REVISION_CONFLICT",
                    "archive requires current nonarchived project and ACCEPTED release",
                ));
            }
            export_available(tx, &release).await?;
            let manifest = release
                .manifest
                .as_ref()
                .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "accepted manifest missing"))?;
            manifest_bytes(&release)?;
            if main_identity(&p)? != (manifest.main_sha.clone(), manifest.main_tree_oid.clone()) {
                return Err(err(
                    "RELEASE_MAIN_STALE",
                    "canonical main changed after accepted release",
                ));
            }
            quiescent(tx, &p.project_id).await?;
            p.archived = true;
            p.paused = true;
            p = decode(
                Box::pin(crate::catalog::apply_catalog(
                    tx,
                    CatalogCommand::UpdateProject {
                        project: p,
                        expected_revision: expected_project_revision,
                    },
                    "release-service",
                ))
                .await?,
            )?;
            let receipt = serde_json::json!({"schema_version":"forgeflow.release-archive.v1","project_id":p.project_id,"release_id":release.release_id,"phase_id":phase.phase_id,
                "project_revision":p.revision,"manifest_sha256":release.manifest_sha256,"archived_by":actor,"archived_at":db_now(tx).await?,"reason":reason,"revision":1});
            record(
                tx,
                &p.project_id,
                "release_archives",
                &format!("{}:{}", release.release_id, p.revision),
                1,
                &receipt,
            )
            .await?;
            event(
                tx,
                &p.project_id,
                &p.project_id,
                p.revision,
                "project.archived",
                receipt,
            )
            .await?;
        }
        ReleaseCommand::Reopen {
            expected_project_revision,
            title,
            goal,
            reason,
            ..
        } => {
            explanation(&title)?;
            explanation(&goal)?;
            explanation(&reason)?;
            if !p.archived
                || p.revision != expected_project_revision
                || release.state != ReleaseState::Accepted
            {
                return Err(err(
                    "REVISION_CONFLICT",
                    "new phase requires current archived project and its ACCEPTED release",
                ));
            }
            export_available(tx, &release).await?;
            let manifest = release
                .manifest
                .as_ref()
                .ok_or_else(|| err("EVIDENCE_INCOMPLETE", "accepted release manifest missing"))?;
            if main_identity(&p)? != (manifest.main_sha.clone(), manifest.main_tree_oid.clone()) {
                return Err(err(
                    "RELEASE_MAIN_STALE",
                    "archived canonical source changed before new phase",
                ));
            }
            let archive: Option<Value>=sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='release_archives' ORDER BY (data->>'project_revision')::bigint DESC LIMIT 1 FOR SHARE")
                .bind(&p.project_id).fetch_optional(&mut **tx).await?;
            if archive.as_ref().is_none_or(|v| {
                v["release_id"] != release.release_id || v["phase_id"] != phase.phase_id
            }) {
                return Err(err(
                    "RELEASE_PHASE_STALE",
                    "archived project must bind this accepted release phase",
                ));
            }
            quiescent(tx, &p.project_id).await?;
            let ordinal = phase
                .ordinal
                .checked_add(1)
                .ok_or_else(|| err("REVISION_CONFLICT", "phase ordinal overflow"))?;
            let previous = phase.phase_id;
            phase = ProjectPhase {
                schema_version: "forgeflow.project-phase.v1".into(),
                phase_id: id(),
                project_id: p.project_id.clone(),
                ordinal,
                previous_release_id: Some(release.release_id.clone()),
                title,
                goal,
                baseline_main_sha: main_identity(&p)?.0,
                created_by: actor.into(),
                created_at: db_now(tx).await?,
                revision: 1,
            };
            record(
                tx,
                &p.project_id,
                "project_phases",
                &phase.phase_id,
                1,
                &json(&phase)?,
            )
            .await?;
            p.archived = false;
            p.paused = true;
            p = decode(
                Box::pin(crate::catalog::apply_catalog(
                    tx,
                    CatalogCommand::UpdateProject {
                        project: p,
                        expected_revision: expected_project_revision,
                    },
                    "release-service",
                ))
                .await?,
            )?;
            event(tx,&p.project_id,&p.project_id,p.revision,"project.reopened",serde_json::json!({"phase":phase,"previous_phase_id":previous,"release_id":release.release_id,
                "manifest_sha256":release.manifest_sha256,"reason":reason,"authorized_by":actor,"execution_authority":"PAUSED_PENDING_REVIEWED_NEW_STAGE"})).await?;
        }
        ReleaseCommand::CreateDraft { .. } => unreachable!(),
    }
    outcome(tx, release, p, phase).await
}
