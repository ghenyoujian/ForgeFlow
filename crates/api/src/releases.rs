//! Project-scoped release and phase authority, with exact frozen manifest exports.
use super::*;
use tokio::io::AsyncWriteExt;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftRequest {
    expected_project_revision: u64,
    title: String,
    milestone_refs: Vec<ReleaseMilestoneBinding>,
    installation: String,
    not_proven: Vec<String>,
    risk_dispositions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    expected_revision: u64,
    expected_main_sha: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceRequest {
    expected_revision: u64,
    expected_manifest_sha256: String,
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRequest {
    expected_revision: u64,
    expected_project_revision: u64,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenRequest {
    expected_revision: u64,
    expected_project_revision: u64,
    title: String,
    goal: String,
    reason: String,
}

fn authorize(actor: &Principal, project: &str) -> Result<(), ApiError> {
    if actor.worker || !matches!(actor.actor_id.as_str(), "owner" | "owner-service") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "releases require Owner authorization",
        ));
    }
    if actor
        .project_id
        .as_deref()
        .is_some_and(|bound| bound != project)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "AUTHORITY_SCOPE_VIOLATION",
            "release project differs from authenticated scope",
        ));
    }
    Ok(())
}

fn positive_revision(value: u64) -> Result<(), ApiError> {
    if value == 0 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "a positive expected revision is required",
        ));
    }
    Ok(())
}

fn page<T: Serialize>(mut items: Vec<(String, T)>, query: ListQuery) -> Json<Value> {
    items.sort_by(|a, b| a.0.cmp(&b.0));
    if let Some(cursor) = query.cursor {
        items.retain(|(key, _)| key > &cursor);
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500) as usize;
    let more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = if more {
        items.last().map(|item| item.0.clone())
    } else {
        None
    };
    let mut response = view(items.into_iter().map(|(_, item)| item).collect::<Vec<_>>());
    response.0["next_cursor"] = json!(next_cursor);
    response.0["snapshot_across_pages"] = json!(false);
    response
}

pub async fn list(
    State(state): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    state.store.get_project(&project).await?;
    let items = state.store.list_releases(&project).await?;
    Ok(page(
        items
            .into_iter()
            .map(|item| (item.release_id.clone(), item))
            .collect(),
        query,
    ))
}

pub async fn phases(
    State(state): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    state.store.get_project(&project).await?;
    let items = state.store.list_project_phases(&project).await?;
    // Numeric ordering stays stable when phase ordinals pass a decimal boundary.
    Ok(page(
        items
            .into_iter()
            .map(|item| (format!("{:020}", item.ordinal), item))
            .collect(),
        query,
    ))
}

pub async fn detail(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    state.store.get_project(&project).await?;
    Ok(view(state.store.get_release(&project, &release).await?))
}

pub async fn draft(
    State(state): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<DraftRequest>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    positive_revision(body.expected_project_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Release(ReleaseCommand::CreateDraft {
            project_id: project,
            expected_project_revision: body.expected_project_revision,
            title: body.title,
            milestone_refs: body.milestone_refs,
            installation: body.installation,
            not_proven: body.not_proven,
            risk_dispositions: body.risk_dispositions,
        }),
    )
    .await
}

pub async fn candidate(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<CandidateRequest>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    positive_revision(body.expected_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Release(ReleaseCommand::CreateCandidate {
            project_id: project,
            release_id: release,
            expected_revision: body.expected_revision,
            expected_main_sha: body.expected_main_sha,
        }),
    )
    .await
}

pub async fn accept(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<AcceptanceRequest>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    positive_revision(body.expected_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Release(ReleaseCommand::Accept {
            project_id: project,
            release_id: release,
            expected_revision: body.expected_revision,
            expected_manifest_sha256: body.expected_manifest_sha256,
            note: body.note,
        }),
    )
    .await
}

pub async fn archive(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ArchiveRequest>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    positive_revision(body.expected_revision)?;
    positive_revision(body.expected_project_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Release(ReleaseCommand::Archive {
            project_id: project,
            release_id: release,
            expected_revision: body.expected_revision,
            expected_project_revision: body.expected_project_revision,
            reason: body.reason,
        }),
    )
    .await
}

pub async fn reopen(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ReopenRequest>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    positive_revision(body.expected_revision)?;
    positive_revision(body.expected_project_revision)?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Release(ReleaseCommand::Reopen {
            project_id: project,
            release_id: release,
            expected_revision: body.expected_revision,
            expected_project_revision: body.expected_project_revision,
            title: body.title,
            goal: body.goal,
            reason: body.reason,
        }),
    )
    .await
}

pub async fn manifest(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
) -> Result<Response, ApiError> {
    authorize(&actor, &project)?;
    state.store.get_project(&project).await?;
    let bytes = state
        .store
        .release_manifest_bytes(&project, &release)
        .await?;
    let digest = forgeflow_evidence::sha256(&bytes);
    Ok((
        [
            ("content-type", "application/json".to_owned()),
            (
                "content-disposition",
                format!("attachment; filename=\"release-{}.json\"", &digest[..16]),
            ),
            ("x-content-type-options", "nosniff".to_owned()),
            ("cache-control", "private, no-store".to_owned()),
            ("etag", format!("\"{digest}\"")),
        ],
        bytes,
    )
        .into_response())
}

pub async fn exports(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    Ok(view(
        state
            .store
            .get_release_export(&project, &release)
            .await?
            .into_iter()
            .collect::<Vec<_>>(),
    ))
}

pub async fn bundle(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
) -> Result<Response, ApiError> {
    authorize(&actor, &project)?;
    let receipt = state
        .store
        .get_release_export(&project, &release)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Release has no registered bundle export",
            )
        })?;
    let descriptor = state
        .store
        .get_document(&project, "artifacts", &receipt.bundle.artifact_id)
        .await?;
    let path = descriptor
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "EXPORT_MISMATCH",
                "bundle artifact path is missing",
            )
        })?;
    let expected_root = state
        .data_root
        .join("artifacts")
        .canonicalize()
        .map_err(artifact_io)?;
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(artifact_io)?;
    let canonical = std::path::Path::new(path)
        .canonicalize()
        .map_err(artifact_io)?;
    if !metadata.is_file()
        || !canonical.starts_with(expected_root)
        || metadata.len() != receipt.bundle_bytes
        || receipt.bundle_bytes > MAX_BUNDLE_BYTES
        || descriptor.get("sha256").and_then(Value::as_str) != Some(receipt.bundle.sha256.as_str())
        || descriptor.get("kind").and_then(Value::as_str) != Some("RELEASE_BUNDLE")
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EXPORT_MISMATCH",
            "bundle descriptor or file differs from its actual export receipt",
        ));
    }
    let bytes = tokio::fs::read(canonical).await.map_err(artifact_io)?;
    if bytes.len() as u64 != receipt.bundle_bytes
        || forgeflow_evidence::sha256(&bytes) != receipt.bundle.sha256
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EXPORT_MISMATCH",
            "bundle bytes differ from actual export receipt",
        ));
    }
    Ok((
        [
            ("content-type", "application/x-tar".to_owned()),
            (
                "content-disposition",
                format!(
                    "attachment; filename=\"release-{}.tar\"",
                    &receipt.bundle.sha256[..16]
                ),
            ),
            ("x-content-type-options", "nosniff".to_owned()),
            ("cache-control", "private, no-store".to_owned()),
            ("etag", format!("\"{}\"", receipt.bundle.sha256)),
        ],
        bytes,
    )
        .into_response())
}

pub async fn export(
    State(state): State<App>,
    Path((project, release)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ExportRequest>,
) -> ApiResult<Value> {
    authorize(&actor, &project)?;
    positive_revision(body.expected_revision)?;
    let original = identity(&headers, &actor)?;
    if let Some(receipt) = state.store.get_release_export(&project, &release).await? {
        // Reuse the already registered identities rather than rematerializing
        // source archives on a lost-ACK retry. Store still owns replay/CAS and
        // validates actual bytes when this is a genuinely new export command.
        return command(
            &state,
            &headers,
            &actor,
            CatalogCommand::Release(ReleaseCommand::RecordExport {
                project_id: project,
                release_id: release,
                expected_revision: body.expected_revision,
                artifact_id: receipt.artifact.artifact_id,
                bundle_artifact_id: receipt.bundle.artifact_id,
            }),
        )
        .await;
    }
    if state.store.get_release(&project, &release).await?.state != ReleaseState::Accepted {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "RELEASE_STATE_CONFLICT",
            "only an accepted Release can register a manifest export",
        ));
    }
    let bytes = state
        .store
        .release_manifest_bytes(&project, &release)
        .await?;
    if bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EXPORT_MISMATCH",
            "frozen release manifest must be nonempty and at most 32 MiB",
        ));
    }
    let digest = forgeflow_evidence::sha256(&bytes);
    let artifact = format!("release-manifest-{digest}");
    let root = state.data_root.join("artifacts");
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(artifact_io)?;
    let path = root.join(&artifact);
    persist_immutable(&path, &bytes).await?;
    // A separate, derived registration key cannot consume or change the public
    // release command key. The final RecordExport transaction replays its own
    // original outcome before checking any later project/release state.
    let registration_key = forgeflow_evidence::sha256(
        serde_json::to_vec(&(
            &original.actor_id,
            &original.idempotency_key,
            &project,
            &release,
            "release-export-artifact",
        ))
        .expect("artifact identity serializable")
        .as_slice(),
    );
    state
        .store
        .execute_command(
            CommandIdentity {
                actor_id: original.actor_id,
                idempotency_key: format!("release-artifact-{registration_key}"),
            },
            CatalogCommand::PutArtifact {
                project_id: project.clone(),
                id: artifact.clone(),
                path: path.to_string_lossy().into_owned(),
                sha256: digest,
                kind: "RELEASE_MANIFEST".into(),
                bytes: bytes.len() as u64,
            },
        )
        .await?;
    let bundle_bytes = build_bundle(&state, &project, &bytes).await?;
    let bundle_digest = forgeflow_evidence::sha256(&bundle_bytes);
    let bundle_id = format!("release-bundle-{bundle_digest}");
    let bundle_path = root.join(&bundle_id);
    persist_immutable(&bundle_path, &bundle_bytes).await?;
    state
        .store
        .execute_command(
            CommandIdentity {
                actor_id: actor.actor_id.clone(),
                idempotency_key: format!("release-bundle-{registration_key}"),
            },
            CatalogCommand::PutArtifact {
                project_id: project.clone(),
                id: bundle_id.clone(),
                path: bundle_path.to_string_lossy().into_owned(),
                sha256: bundle_digest,
                kind: "RELEASE_BUNDLE".into(),
                bytes: bundle_bytes.len() as u64,
            },
        )
        .await?;
    command(
        &state,
        &headers,
        &actor,
        CatalogCommand::Release(ReleaseCommand::RecordExport {
            project_id: project,
            release_id: release,
            expected_revision: body.expected_revision,
            artifact_id: artifact,
            bundle_artifact_id: bundle_id,
        }),
    )
    .await
}

const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

async fn build_bundle(
    state: &App,
    project: &str,
    manifest_bytes: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let manifest: ReleaseManifest = serde_json::from_slice(manifest_bytes).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EXPORT_MISMATCH",
            "frozen manifest does not match ReleaseManifest",
        )
    })?;
    let project_row = state.store.get_project(project).await?;
    let exports_root = state.data_root.join("exports");
    tokio::fs::create_dir_all(&exports_root)
        .await
        .map_err(artifact_io)?;
    let scratch = exports_root.join(format!(".release-bundle-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir(&scratch).await.map_err(artifact_io)?;
    let result = async {
        let content = scratch.join("content");
        tokio::fs::create_dir(&content).await.map_err(artifact_io)?;
        let artifacts = content.join("artifacts");
        tokio::fs::create_dir(&artifacts)
            .await
            .map_err(artifact_io)?;
        tokio::fs::write(content.join("manifest.json"), manifest_bytes)
            .await
            .map_err(artifact_io)?;
        tokio::fs::write(
            content.join("INSTALLATION.txt"),
            manifest.installation.as_bytes(),
        )
        .await
        .map_err(artifact_io)?;
        let mut reserved = manifest_bytes.len() as u64 + manifest.installation.len() as u64;
        let mut seen = std::collections::BTreeSet::new();
        for file in &manifest.files {
            if file.artifact_id.is_empty()
                || matches!(file.artifact_id.as_str(), "." | "..")
                || !file
                    .artifact_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                || !seen.insert(file.artifact_id.clone())
            {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "EXPORT_MISMATCH",
                    "manifest artifact IDs must be distinct safe file identities",
                ));
            }
            reserved = reserved
                .checked_add(file.bytes)
                .filter(|total| *total <= MAX_BUNDLE_BYTES)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "EXPORT_TOO_LARGE",
                        "bound release files exceed the 256 MiB core bundle limit",
                    )
                })?;
            let descriptor = state
                .store
                .get_document(project, "artifacts", &file.artifact_id)
                .await?;
            let path = descriptor
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "EXPORT_MISMATCH",
                        "bound artifact locator is missing",
                    )
                })?;
            let metadata = tokio::fs::symlink_metadata(path)
                .await
                .map_err(artifact_io)?;
            if !metadata.is_file() || metadata.len() != file.bytes {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "EXPORT_MISMATCH",
                    "bound artifact must be an actual regular file with frozen byte length",
                ));
            }
            let bytes = tokio::fs::read(path).await.map_err(artifact_io)?;
            if bytes.len() as u64 != file.bytes || forgeflow_evidence::sha256(&bytes) != file.sha256
            {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "EXPORT_MISMATCH",
                    "bound artifact bytes no longer match the frozen manifest",
                ));
            }
            tokio::fs::write(artifacts.join(&file.artifact_id), bytes)
                .await
                .map_err(artifact_io)?;
        }
        let source = content.join("source.tar");
        let mut git = tokio::process::Command::new("/usr/bin/git");
        git.args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-C",
        ])
        .arg(&project_row.root_path)
        .args(["archive", "--format=tar"])
        .arg(format!("--output={}", source.display()))
        .arg(&manifest.main_sha);
        run_export_tool(git, "git archive").await?;
        let source_len = tokio::fs::metadata(&source)
            .await
            .map_err(artifact_io)?
            .len();
        if reserved
            .checked_add(source_len)
            .is_none_or(|sum| sum > MAX_BUNDLE_BYTES)
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "EXPORT_TOO_LARGE",
                "source and bound artifacts exceed the 256 MiB core bundle limit",
            ));
        }
        let archive = scratch.join("bundle.tar");
        let mut tar = tokio::process::Command::new("/usr/bin/tar");
        tar.args([
            "--format=gnu",
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=u=rwX,go=rX",
            "-cf",
        ])
        .arg(&archive)
        .arg("-C")
        .arg(&content)
        .args([
            "manifest.json",
            "INSTALLATION.txt",
            "source.tar",
            "artifacts",
        ]);
        run_export_tool(tar, "tar").await?;
        if tokio::fs::metadata(&archive)
            .await
            .map_err(artifact_io)?
            .len()
            > MAX_BUNDLE_BYTES
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "EXPORT_TOO_LARGE",
                "actual core bundle including tar metadata exceeds 256 MiB",
            ));
        }
        tokio::fs::read(&archive).await.map_err(artifact_io)
    }
    .await;
    if let Err(error) = tokio::fs::remove_dir_all(&scratch).await {
        tracing::warn!(%error, "release bundle scratch cleanup failed");
    }
    result
}

async fn run_export_tool(mut tool: tokio::process::Command, name: &str) -> Result<(), ApiError> {
    tool.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .kill_on_drop(true);
    let result = tokio::time::timeout(Duration::from_secs(120), tool.output())
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "EXPORT_FAILED",
                format!("{name} exceeded its bounded export time"),
            )
        })?
        .map_err(artifact_io)?;
    if !result.status.success() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EXPORT_FAILED",
            format!("{name} could not materialize the frozen release bundle"),
        ));
    }
    Ok(())
}

fn artifact_io(error: std::io::Error) -> ApiError {
    tracing::error!(%error, "release manifest artifact I/O failed");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "ARTIFACT_IO_FAILED",
        "release manifest artifact could not be persisted or read",
    )
}

async fn persist_immutable(path: &std::path::Path, bytes: &[u8]) -> Result<(), ApiError> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .await
        .map_err(artifact_io)?;
    if let Err(error) = async {
        file.write_all(bytes).await?;
        file.sync_all().await?;
        Ok::<(), std::io::Error>(())
    }
    .await
    {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(artifact_io(error));
    }
    drop(file);
    let linked = tokio::fs::hard_link(&temporary, path).await;
    let _ = tokio::fs::remove_file(&temporary).await;
    match linked {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(artifact_io(error)),
    }
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(artifact_io)?;
    if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "ARTIFACT_IDENTITY_CONFLICT",
            "export artifact namespace contains a different identity",
        ));
    }
    let saved = tokio::fs::read(path).await.map_err(artifact_io)?;
    if saved != bytes {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "ARTIFACT_IDENTITY_CONFLICT",
            "existing export artifact differs from the frozen manifest bytes",
        ));
    }
    // Persist the directory entry before an export receipt can commit in DB.
    let parent = path.parent().expect("artifact has a parent").to_owned();
    tokio::task::spawn_blocking(move || std::fs::File::open(parent)?.sync_all())
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ARTIFACT_IO_FAILED",
                "export artifact directory could not be synchronized",
            )
        })?
        .map_err(artifact_io)?;
    Ok(())
}
