//! Owner maintenance: durable backup jobs and truthful recovery observations.
//! No handler starts an executor, settles unknown usage, restores production or resumes dispatch.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::Path as FsPath,
    sync::OnceLock,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const BACKUP_SCRIPT: &str = include_str!("../../../ops/backup.py");
const RESTORE_SCRIPT: &str = include_str!("../../../ops/restore.py");
const MAX_RECORD: u64 = 4 * 1024 * 1024;
const MAX_UNPACKED: u64 = 32 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = MAX_UNPACKED + 1024 * 1024 * 1024;
static HASH_LANE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
static DOWNLOAD_LANE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

fn owner(actor: &Principal) -> Result<(), ApiError> {
    if actor.worker
        || !matches!(actor.actor_id.as_str(), "owner" | "owner-service")
        || actor.project_id.is_some()
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_AUTHORIZATION_REQUIRED",
            "workspace maintenance requires an unscoped Owner identity",
        ));
    }
    Ok(())
}
fn io_error(error: impl std::fmt::Display) -> ApiError {
    tracing::warn!(%error, "private maintenance IO failed");
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "MAINTENANCE_IO_FAILED",
        "private maintenance files are unavailable; no successful backup or restore is implied",
    )
}
fn instance() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn private_directory(path: &FsPath) -> Result<(), ApiError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        if !path.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(path).map_err(io_error)?;
        }
        let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "BACKUP_DIRECTORY_UNSAFE",
                "backup directories must be owned private directories, never symbolic links",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io_error("private backup permissions require Unix"))
    }
}
fn root(state: &App) -> Result<PathBuf, ApiError> {
    let data = state.data_root.canonicalize().map_err(io_error)?;
    let configured = std::env::var_os("FORGEFLOW_BACKUP_ROOT").map(PathBuf::from);
    let path = configured.unwrap_or_else(|| {
        data.with_file_name(format!(
            "{}-backups",
            data.file_name().unwrap_or_default().to_string_lossy()
        ))
    });
    if !path.is_absolute() || path.starts_with(&data) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_DIRECTORY_UNSAFE",
            "backup output must be an absolute directory outside authoritative data",
        ));
    }
    private_directory(&path)?;
    let canonical = path.canonicalize().map_err(io_error)?;
    if canonical.starts_with(&data) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_DIRECTORY_UNSAFE",
            "backup output resolves inside authoritative data",
        ));
    }
    Ok(canonical)
}
fn open_private(path: &FsPath, create: bool) -> Result<File, ApiError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(create)
            .create_new(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io_error("maintenance file permissions or type changed"));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, create);
        Err(io_error("private backup files require Unix"))
    }
}
fn write_bytes(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    let mut file = open_private(path, true)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}
fn write_record(directory: &FsPath, value: &Value) -> Result<(), ApiError> {
    let temporary = directory.join(format!("record-{}.tmp", uuid::Uuid::new_v4()));
    write_bytes(&temporary, &serde_json::to_vec(value).map_err(io_error)?)?;
    std::fs::rename(&temporary, directory.join("record.json")).map_err(io_error)?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}
fn read_json(path: &FsPath) -> Result<Value, ApiError> {
    let mut file = open_private(path, false)?;
    if file.metadata().map_err(io_error)?.len() > MAX_RECORD {
        return Err(io_error("maintenance record is oversized"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(io_error("maintenance record is oversized"));
    }
    serde_json::from_slice(&bytes).map_err(io_error)
}
fn directory(state: &App, id: &str) -> Result<PathBuf, ApiError> {
    if !valid_id(id) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "BACKUP_ID_INVALID",
            "invalid backup identity",
        ));
    }
    let path = root(state)?.join(id);
    if !path.exists() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "backup job not found",
        ));
    }
    private_directory(&path)?;
    Ok(path)
}
fn projected(directory: &FsPath) -> Result<Value, ApiError> {
    if !directory.join("record.json").exists() {
        return Ok(
            json!({"schema_version":"forgeflow.backup-job.v1","backup_id":directory.file_name().map(|name|name.to_string_lossy()),"status":"RECOVERY_REQUIRED","phase":"INTERRUPTED","reason":"Backup initialization did not durably record its request.","download_available":false,"partial_files_retained":true}),
        );
    }
    let mut record = read_json(&directory.join("record.json"))?;
    if record["schema_version"] != "forgeflow.backup-job.v1"
        || record["backup_id"].as_str() != directory.file_name().and_then(|name| name.to_str())
    {
        return Err(io_error(
            "backup record identity differs from its private directory",
        ));
    }
    if matches!(record["status"].as_str(), Some("ACCEPTED" | "RUNNING"))
        && record["server_instance"].as_str() != Some(instance())
    {
        record["status"] = json!("RECOVERY_REQUIRED");
        record["phase"] = json!("INTERRUPTED");
        record["error"] = json!({"code":"BACKUP_INTERRUPTED","message":"The owning control process changed. Partial files are retained; this job is not automatically replayed or downloadable."});
    } else if record["status"] == "RUNNING"
        && record["phase"] == "CHECKING_CUSTODY"
        && directory.join("progress.json").exists()
    {
        let progress = read_json(&directory.join("progress.json"))?;
        record["phase"] = progress["phase"].clone();
        record["progress"] = progress;
    }
    record
        .as_object_mut()
        .map(|object| object.remove("server_instance"));
    let available = record["status"] == "SUCCEEDED"
        && std::fs::symlink_metadata(directory.join("backup.tar.gz")).is_ok_and(|metadata| {
            metadata.is_file() && Some(metadata.len()) == record["archive_bytes"].as_u64()
        });
    record["download_available"] = json!(available);
    if record["status"] == "SUCCEEDED" && !available {
        record["archive_warning"] = json!(
            "The sealed archive is missing or its observed type/length changed. Download is unavailable until integrity is reviewed."
        );
    }
    Ok(record)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryQuery {
    project_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}
pub async fn recovery_items(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<RecoveryQuery>,
) -> ApiResult<Value> {
    owner(&actor)?;
    if let Some(project) = &query.project_id {
        state.store.get_project(project).await?;
    }
    let page = state
        .store
        .recovery_items(
            query.project_id.as_deref(),
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    let mut response = view(page.items);
    response.0["next_cursor"] = json!(page.next_cursor);
    response.0["snapshot_across_pages"] = json!(false);
    Ok(response)
}
async fn readiness(state: &App) -> Result<Value, ApiError> {
    let mut value = state.store.backup_readiness().await?;
    let mut blockers = Vec::new();
    if !value["unsettled_attempts"]
        .as_array()
        .is_some_and(Vec::is_empty)
    {
        blockers.push(json!({"code":"UNSETTLED_ATTEMPTS","count":value["unsettled_attempts"].as_array().map(Vec::len)}));
    }
    if let Some(counts) = value["custody"].as_object() {
        for (kind, count) in counts {
            if count.as_u64().unwrap_or(u64::MAX) > 0 {
                blockers.push(json!({"code":"CUSTODY_PENDING","kind":kind,"count":count}));
            }
        }
    } else {
        blockers.push(json!({"code":"CUSTODY_UNKNOWN"}));
    }
    if let Some(projects) = value["projects"].as_array() {
        for project in projects {
            if project["authority_mode"] == "MANAGED" {
                let available = match project["root_path"].as_str() {
                    Some(path) => tokio::fs::metadata(path)
                        .await
                        .is_ok_and(|metadata| metadata.is_dir()),
                    None => false,
                };
                if !available {
                    blockers.push(
                        json!({"code":"REPOSITORY_UNAVAILABLE","project_id":project["project_id"]}),
                    );
                }
            }
        }
    }
    value["scope_sha256"] = json!(forgeflow_evidence::sha256(
        &serde_json::to_vec(&value).map_err(io_error)?
    ));
    value["ready"] = json!(blockers.is_empty());
    value["blockers"] = json!(blockers);
    value["dispatch_will_remain_paused"] = json!(true);
    value["backup_root"] = json!(root(state)?);
    Ok(value)
}
pub async fn backup_readiness(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(view(readiness(&state).await?))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBackup {
    reason: String,
    pause_new_dispatch: bool,
    expected_scope_sha256: String,
}
pub async fn create_backup(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<CreateBackup>,
) -> Result<Response, ApiError> {
    owner(&actor)?;
    let identity = identity(&headers, &actor)?;
    if !request.pause_new_dispatch
        || request.reason.trim().is_empty()
        || request.reason.len() > 2000
        || !valid_id(&request.expected_scope_sha256)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "BACKUP_REVIEW_REQUIRED",
            "review the exact scope, provide a reason and acknowledge that all projects remain paused",
        ));
    }
    let id = forgeflow_evidence::sha256(
        format!(
            "forgeflow.backup-job.v1:{}:{}",
            identity.actor_id, identity.idempotency_key
        )
        .as_bytes(),
    );
    let request_hash = forgeflow_evidence::sha256(&serde_json::to_vec(&request).map_err(io_error)?);
    let backup_root = root(&state)?;
    let job_root = backup_root.join(&id);
    if job_root.exists() {
        private_directory(&job_root)?;
        let original = read_json(&job_root.join("record.json"))?;
        if original["request_sha256"] != request_hash {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "IDEMPOTENCY_CONFLICT",
                "backup request differs from the original request identity",
            ));
        }
        return Ok((
            StatusCode::ACCEPTED,
            view_from(projected(&job_root)?, "private-maintenance-journal"),
        )
            .into_response());
    }
    if state.auth.is_shutting_down() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "CONTROL_SHUTTING_DOWN",
            "maintenance cannot start during shutdown",
        ));
    }
    let before = readiness(&state).await?;
    if before["scope_sha256"] != request.expected_scope_sha256 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_SCOPE_STALE",
            "project or custody scope changed; read and review backup readiness again",
        ));
    }
    if before["ready"] != true {
        return Err(ApiError(
            StatusCode::CONFLICT,
            DomainError::new(
                "BACKUP_BLOCKED",
                "unsettled attempts, model requests, resources or integration must be resolved before backup",
            ),
        ));
    }
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "BACKUP_BEARER_REQUIRED",
                "backup commands require an authenticated Owner bearer credential",
            )
        })?
        .to_owned();
    if std::env::var_os("DATABASE_URL").is_none() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "BACKUP_DATABASE_UNCONFIGURED",
            "database export configuration is unavailable",
        ));
    }
    // OS lock spans the actual child process and archive sealing, across API processes.
    let lock_path = backup_root.join(".backup.lock");
    let lock = if lock_path.exists() {
        open_private(&lock_path, false)?
    } else {
        open_private(&lock_path, true)?
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "BACKUP_BUSY",
                "another backup still owns the maintenance lane",
            ));
        }
    }
    if job_root.exists() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_REQUEST_RACE",
            "the same backup identity was created concurrently; replay the original request",
        ));
    }
    std::fs::create_dir(&job_root).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&job_root, std::fs::Permissions::from_mode(0o700))
            .map_err(io_error)?;
    }
    let record = json!({"schema_version":"forgeflow.backup-job.v1","backup_id":id,"status":"ACCEPTED","phase":"ACCEPTED","reason":request.reason,"created_by":actor.actor_id,"created_at":Utc::now(),"updated_at":Utc::now(),"server_instance":instance(),"request_sha256":request_hash,"reviewed_scope":before,"dispatch_pause_policy":"PAUSE_AND_LEAVE_PAUSED","backup_script_sha256":forgeflow_evidence::sha256(BACKUP_SCRIPT.as_bytes()),"restore_script_sha256":forgeflow_evidence::sha256(RESTORE_SCRIPT.as_bytes())});
    write_record(&job_root, &record)?;
    let response = projected(&job_root)?;
    tokio::spawn(async move {
        let _lock = lock;
        let mut record = record;
        record["status"] = json!("RUNNING");
        record["phase"] = json!("CHECKING_CUSTODY");
        let result = async {
            write_record(&job_root, &record)?;
            run_backup(&state, &job_root, &mut record, token).await
        }
        .await;
        if let Err(error) = result {
            record["status"] = json!(if state.auth.is_shutting_down() {
                "RECOVERY_REQUIRED"
            } else {
                "FAILED"
            });
            record["error"] =
                serde_json::to_value(error.1).unwrap_or(json!({"code":"BACKUP_FAILED"}));
            record["partial_files_retained"] = json!(true);
        }
        record["updated_at"] = json!(Utc::now());
        if let Err(error) = write_record(&job_root, &record) {
            tracing::error!(error=%error.1, "backup result journal could not be sealed; no successful job is implied");
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        view_from(response, "private-maintenance-journal"),
    )
        .into_response())
}

async fn process(
    state: &App,
    directory: &FsPath,
    name: &str,
    command: &mut tokio::process::Command,
) -> Result<(), ApiError> {
    let mut shutdown = state.auth.shutdown_receiver();
    if *shutdown.borrow() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "CONTROL_SHUTTING_DOWN",
            "maintenance cannot launch a child during shutdown",
        ));
    }
    let stdout = open_private(&directory.join(format!("{name}.stdout")), true)?;
    let stderr = open_private(&directory.join(format!("{name}.stderr")), true)?;
    command
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
        #[cfg(target_os = "linux")]
        unsafe {
            command.as_std_mut().pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() == 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "maintenance parent exited",
                    ));
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().map_err(io_error)?;
    let pid = child.id();
    let outcome = tokio::select! {
        outcome = child.wait() => Some(outcome.map_err(io_error)?),
        _ = shutdown.changed() => None,
        _ = tokio::time::sleep(Duration::from_secs(7200)) => None,
    };
    let Some(outcome) = outcome else {
        #[cfg(unix)]
        if let Some(pid) = pid {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_INTERRUPTED",
            "maintenance was interrupted; partial files and paused projects are retained",
        ));
    };
    if !outcome.success() {
        // Raw child diagnostics stay in private files, never in HTTP or command arguments.
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_STEP_FAILED",
            format!(
                "{name} did not complete successfully; inspect the private maintenance diagnostics and retained files"
            ),
        ));
    }
    Ok(())
}
fn python(directory: &FsPath, script: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("python3");
    command
        .arg("-B")
        .arg(directory.join(script))
        .env("PYTHONNOUSERSITE", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1");
    command
}
async fn hash_file(path: &FsPath) -> Result<(File, String, u64), ApiError> {
    // The permit lives inside the blocking task, including when its HTTP caller
    // disconnects. At most two whole-archive reads can consume disk at once.
    let permit = HASH_LANE.acquire().await.map_err(io_error)?;
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut file = open_private(&path, false)?;
        let bytes = file.metadata().map_err(io_error)?.len();
        if bytes > MAX_ARCHIVE_BYTES {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "BACKUP_ARCHIVE_OVERSIZED",
                "archive exceeds the supported bounded download size",
            ));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok((file, format!("{:x}", hasher.finalize()), bytes))
    })
    .await
    .map_err(io_error)?
}
async fn run_backup(
    state: &App,
    directory: &FsPath,
    record: &mut Value,
    token: String,
) -> Result<(), ApiError> {
    write_bytes(&directory.join("backup.py"), BACKUP_SCRIPT.as_bytes())?;
    write_bytes(&directory.join("restore.py"), RESTORE_SCRIPT.as_bytes())?;
    let snapshot = directory.join("snapshot");
    let mut command = python(directory, "backup.py");
    command
        .arg("--destination")
        .arg(&snapshot)
        .arg("--data-root")
        .arg(&state.data_root)
        .arg("--progress-file")
        .arg(directory.join("progress.json"))
        .env("FORGEFLOW_OWNER_TOKEN", token);
    let mut repositories = BTreeSet::new();
    for project in state.store.list_projects().await? {
        if project.authority_mode == AuthorityMode::Managed {
            repositories.insert(
                PathBuf::from(project.root_path)
                    .canonicalize()
                    .map_err(io_error)?,
            );
        }
    }
    for repository in repositories {
        command.arg("--repository").arg(repository);
    }
    process(state, directory, "snapshot", &mut command).await?;
    record["phase"] = json!("ARCHIVING");
    write_record(directory, record)?;
    let archive = directory.join("backup.tar.gz");
    let mut tar = tokio::process::Command::new("tar");
    tar.arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&snapshot)
        .arg(".");
    process(state, directory, "archive", &mut tar).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
    }
    record["phase"] = json!("VERIFYING_ARCHIVE");
    write_record(directory, record)?;
    let mut verify = python(directory, "restore.py");
    verify
        .arg("--archive")
        .arg(&archive)
        .arg("--verify-only")
        .arg("--max-unpacked-bytes")
        .arg(MAX_UNPACKED.to_string());
    process(state, directory, "verification", &mut verify).await?;
    let verification = read_json(&directory.join("verification.stdout"))?;
    if verification["status"] != "VERIFIED"
        || verification["sql_executed"] != false
        || verification["state_copied"] != false
    {
        return Err(io_error(
            "archive verification did not return its exact read-only receipt",
        ));
    }
    let (file, digest, bytes) = hash_file(&archive).await?;
    tokio::task::spawn_blocking(move || file.sync_all())
        .await
        .map_err(io_error)?
        .map_err(io_error)?;
    record["archive_sha256"] = json!(digest);
    record["archive_bytes"] = json!(bytes);
    record["verification"] = verification;
    // Only this job's staging snapshot is removed, after full archive inventory/hash
    // verification and file sync. Production and previous jobs are never cleaned here.
    tokio::fs::remove_dir_all(&snapshot)
        .await
        .map_err(io_error)?;
    record["status"] = json!("SUCCEEDED");
    record["phase"] = json!("SEALED");
    record["staging_snapshot_removed"] = json!(true);
    record["snapshot_dispatch_paused"] = json!(true);
    record["completed_at"] = json!(Utc::now());
    Ok(())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}
pub async fn backups(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<BackupQuery>,
) -> ApiResult<Value> {
    owner(&actor)?;
    let entries = std::fs::read_dir(root(&state)?)
        .map_err(io_error)?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(io_error)?;
    let mut ids = entries
        .into_iter()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|id| valid_id(id) && query.cursor.as_ref().is_none_or(|after| id > after))
        .collect::<Vec<_>>();
    ids.sort();
    let limit = query.limit.unwrap_or(100).clamp(1, 500) as usize;
    let more = ids.len() > limit;
    ids.truncate(limit);
    let next = if more { ids.last().cloned() } else { None };
    let records = ids
        .into_iter()
        .map(|id| directory(&state, &id).and_then(|directory| projected(&directory)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut response = view_from(records, "private-maintenance-journal");
    response.0["next_cursor"] = json!(next);
    response.0["snapshot_across_pages"] = json!(false);
    Ok(response)
}
pub async fn backup(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(view_from(
        projected(&directory(&state, &id)?)?,
        "private-maintenance-journal",
    ))
}
async fn sealed(state: &App, id: &str) -> Result<(Value, File), ApiError> {
    let directory = directory(state, id)?;
    let record = projected(&directory)?;
    if record["status"] != "SUCCEEDED" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_NOT_SEALED",
            "only a completed, verified backup can be downloaded or previewed",
        ));
    }
    let (file, digest, bytes) = hash_file(&directory.join("backup.tar.gz")).await?;
    if record["archive_sha256"] != digest || record["archive_bytes"] != bytes {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "BACKUP_INTEGRITY_MISMATCH",
            "archive bytes differ from the sealed backup receipt",
        ));
    }
    Ok((record, file))
}
pub async fn backup_archive(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    owner(&actor)?;
    let permit = DOWNLOAD_LANE.acquire().await.map_err(io_error)?;
    let (record, file) = sealed(&state, &id).await?;
    let mut file = tokio::fs::File::from_std(file);
    file.rewind().await.map_err(io_error)?;
    let stream = futures::stream::try_unfold((file, permit), |(mut file, permit)| async move {
        let mut buffer = vec![0u8; 65536];
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            Ok::<_, std::io::Error>(None)
        } else {
            buffer.truncate(count);
            Ok(Some((buffer, (file, permit))))
        }
    });
    Ok((
        [
            ("content-type", "application/gzip".to_owned()),
            (
                "content-disposition",
                format!(
                    "attachment; filename=\"forgeflow-backup-{}.tar.gz\"",
                    &id[..16]
                ),
            ),
            ("content-length", record["archive_bytes"].to_string()),
            (
                "etag",
                format!(
                    "\"{}\"",
                    record["archive_sha256"].as_str().unwrap_or_default()
                ),
            ),
            ("cache-control", "private, no-store".to_owned()),
            ("x-content-type-options", "nosniff".to_owned()),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}
pub async fn restore_preview(
    State(state): State<App>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    owner(&actor)?;
    let (record, _) = sealed(&state, &id).await?;
    // The exact archive digest binds this original full streamed verification.
    // No extraction, Python subprocess, database or production write occurs here.
    Ok(view_from(
        json!({"backup_id":id,"archive_sha256":record["archive_sha256"],"archive_bytes":record["archive_bytes"],"verification":record["verification"],"restore_executed":false,"production_overwritten":false,"next":"Download and verify the archive, extract into a new isolated directory, then use restore.py with a private database-env file targeting an explicitly empty database. Never reuse old Worker credentials or automatically resume dispatch."}),
        "sealed-backup-verification",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maintenance_scope_and_path_boundaries() {
        assert!(valid_id(&"a".repeat(64)));
        assert!(!valid_id("../record.json"));
        assert!(!valid_id(&"A".repeat(64)));
        let owner_actor = Principal {
            actor_id: "owner-service".into(),
            worker: false,
            worker_id: None,
            project_id: None,
        };
        assert!(owner(&owner_actor).is_ok());
        assert!(
            owner(&Principal {
                worker: true,
                ..owner_actor.clone()
            })
            .is_err()
        );
        assert!(
            owner(&Principal {
                project_id: Some("foreign".into()),
                ..owner_actor
            })
            .is_err()
        );
    }
}
