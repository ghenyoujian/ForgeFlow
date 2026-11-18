//! Managed Git repositories, complete scope auditing, and recoverable CAS integration.
//! Linked worktrees isolate attempts; they are not a hostile-code sandbox.
pub mod safe_probe;

use async_trait::async_trait;
use forgeflow_evidence::{EvidenceBinding, VerificationReceipt, sha256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("Git command failed: {0}")]
    Command(String),
    #[error("invalid managed repository or path: {0}")]
    Invalid(String),
    #[error("WRITE_SCOPE_VIOLATION: {0:?}")]
    WriteScopeViolation(Vec<String>),
    #[error("MERGE_CONFLICT preserved at {0}")]
    Conflict(PathBuf),
    #[error("STALE_REF: expected {expected}, actual {actual}")]
    StaleRef { expected: String, actual: String },
    #[error("MERGE_DIVERGED: {0}")]
    Diverged(String),
    #[error("verification rejected: {0}")]
    Evidence(String),
    #[error("integration persistence: {0}")]
    Store(String),
    #[error(
        "COMMIT_IN_PROGRESS: intent {intent_id}, new SHA {new_sha}, confirmation unresolved: {reason}"
    )]
    CommitInProgress {
        intent_id: String,
        new_sha: String,
        reason: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn git_command(repo: Option<&Path>) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("--no-pager");
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(repo) = repo {
        cmd.arg("-C").arg(repo);
        if repo.join(".git").is_dir() {
            cmd.arg("--git-dir")
                .arg(repo.join(".git"))
                .arg("--work-tree")
                .arg(repo);
        }
    }
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.filemode=true",
        "-c",
        "core.ignorecase=false",
    ])
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_COUNT", "0")
    .env("GIT_LITERAL_PATHSPECS", "1")
    .env("GIT_NO_LAZY_FETCH", "1")
    .env_remove("GIT_DIR")
    .env_remove("GIT_WORK_TREE")
    .env_remove("GIT_INDEX_FILE")
    .env_remove("GIT_OBJECT_DIRECTORY")
    .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
    .env_remove("GIT_NAMESPACE");
    cmd
}
fn run(repo: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let mut command = git_command(Some(repo));
    if args.first() == Some(&"diff") {
        command
            .arg("diff")
            .args(["--no-ext-diff", "--no-textconv"])
            .args(&args[1..]);
    } else {
        command.args(args);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(GitError::Command(
            String::from_utf8_lossy(&output.stderr).trim().into(),
        ));
    }
    Ok(output.stdout)
}
fn txt(repo: &Path, args: &[&str]) -> Result<String, GitError> {
    String::from_utf8(run(repo, args)?)
        .map(|s| s.trim().into())
        .map_err(|_| GitError::Invalid("non UTF-8 Git identity".into()))
}
fn canonical(repo: &Path) -> Result<(), GitError> {
    if txt(repo, &["rev-parse", "--is-bare-repository"])? != "true" {
        return Err(GitError::Invalid(
            "canonical repository must be bare; user checkout is never silently taken over".into(),
        ));
    }
    Ok(())
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 160
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn resolve(repo: &Path, revision: &str) -> Result<String, GitError> {
    txt(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{revision}^{{commit}}"),
        ],
    )
}
pub fn source_hash(repo: &Path, revision: &str) -> Result<String, GitError> {
    txt(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{revision}^{{tree}}"),
        ],
    )
}

/// Content identity, separate from the legacy `source_hash` Git tree object ID.
/// The SHA256 input is `forgeflow.source-content.v1\0`, entry count (u64 BE), then
/// entries sorted by their raw Git path bytes: mode (u32 BE), path length (u64 BE),
/// raw path, blob length (u64 BE), and the 32 raw bytes of the blob SHA256.
/// Commit and Git object IDs are provenance, not content digest input. Symlink
/// blobs hash the tracked link target bytes; gitlinks/submodules are rejected.
pub const SOURCE_CONTENT_ALGORITHM: &str = "forgeflow.source-content.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceContentEntry {
    /// Hex encoding preserves every raw Git path byte, including non-UTF8 names.
    pub path_hex: String,
    pub mode: String,
    pub blob_bytes: u64,
    pub blob_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceContentManifest {
    pub algorithm: String,
    pub commit_sha: String,
    pub tree_oid: String,
    pub source_sha256: String,
    pub tracked_entries: u64,
    pub total_blob_bytes: u64,
    pub entries: Vec<SourceContentEntry>,
}

fn source_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

// Every object-read subprocess shares a 30-second deadline. Its process group
// is killed on timeout or early failure; stderr cannot exhaust controller RAM.
struct SourceGitProcess {
    child: std::process::Child,
    wake: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    watchdog: Option<std::thread::JoinHandle<()>>,
}
impl SourceGitProcess {
    fn spawn(repo: &Path, args: &[&str], deadline: std::time::Instant) -> Result<Self, GitError> {
        let mut command = git_command(Some(repo));
        command
            .arg("--no-replace-objects")
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0");
        Self::spawn_command(command, deadline)
    }
    fn spawn_command(mut command: Command, deadline: std::time::Instant) -> Result<Self, GitError> {
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let child = command.spawn()?;
        let pid = child.id();
        let wake = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let signal = wake.clone();
        let watchdog = std::thread::spawn(move || {
            let (lock, condition) = &*signal;
            let done = lock.lock().unwrap();
            let (done, _) = condition
                .wait_timeout_while(
                    done,
                    deadline.saturating_duration_since(std::time::Instant::now()),
                    |done| !*done,
                )
                .unwrap();
            if !*done {
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
                #[cfg(not(unix))]
                let _ = pid;
            }
        });
        Ok(Self {
            child,
            wake,
            watchdog: Some(watchdog),
        })
    }
    fn stop_watchdog(&mut self) {
        let (lock, condition) = &*self.wake;
        *lock.lock().unwrap() = true;
        condition.notify_all();
        if let Some(thread) = self.watchdog.take() {
            let _ = thread.join();
        }
    }
    fn finish(&mut self) -> Result<(), GitError> {
        self.child.stdin.take();
        let status = self.child.wait()?;
        self.stop_watchdog();
        if !status.success() {
            return Err(GitError::Command(format!(
                "source manifest Git process exited {status}"
            )));
        }
        Ok(())
    }
}
impl Drop for SourceGitProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stop_watchdog();
    }
}

fn source_git_read(
    repo: &Path,
    args: &[&str],
    max_bytes: u64,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, GitError> {
    use std::io::Read;
    let mut process = SourceGitProcess::spawn(repo, args, deadline)?;
    process.child.stdin.take();
    let mut bytes = Vec::new();
    process
        .child
        .stdout
        .take()
        .unwrap()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(GitError::Invalid(
            "source manifest Git output exceeds limit".into(),
        ));
    }
    process.finish()?;
    Ok(bytes)
}

/// Read only a frozen commit's tracked objects. Never executes filters, hooks,
/// textconv, external diff or lazy network fetch; ignores Git replacement refs.
/// Bounds: 100,000 entries, 16 MiB tree listing, 512 MiB per blob, 4 GiB logical
/// tracked bytes, 30 seconds total. Blob contents are streamed, not buffered.
pub fn source_content_manifest(
    repo: &Path,
    revision: &str,
) -> Result<SourceContentManifest, GitError> {
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, Read, Write};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let object_id = |args: &[&str]| -> Result<String, GitError> {
        let bytes = source_git_read(repo, args, 256, deadline)?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| GitError::Invalid("non ASCII object ID".into()))?
            .trim();
        if !matches!(value.len(), 40 | 64)
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(GitError::Invalid("invalid frozen object ID".into()));
        }
        Ok(value.into())
    };
    let commit_sha = object_id(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{revision}^{{commit}}"),
    ])?;
    let tree_oid = object_id(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{commit_sha}^{{tree}}"),
    ])?;
    let listing = source_git_read(
        repo,
        &["ls-tree", "-rz", "--full-tree", &tree_oid],
        16 * 1024 * 1024,
        deadline,
    )?;
    let mut tracked = Vec::new();
    for record in listing
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| GitError::Invalid("malformed tracked entry".into()))?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| GitError::Invalid("non ASCII tree header".into()))?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3
            || fields[1] != "blob"
            || !matches!(fields[0], "100644" | "100755" | "120000")
        {
            return Err(GitError::Invalid(
                "unsupported tracked object: submodules cannot prove source contents".into(),
            ));
        }
        if !matches!(fields[2].len(), 40 | 64)
            || !fields[2]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(GitError::Invalid("invalid tracked blob identity".into()));
        }
        let path = &record[tab + 1..];
        if path.is_empty()
            || path
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            return Err(GitError::Invalid("unsafe raw tracked path".into()));
        }
        tracked.push((path.to_vec(), fields[0].to_string(), fields[2].to_string()));
        if tracked.len() > 100_000 {
            return Err(GitError::Invalid("source entry count exceeds limit".into()));
        }
    }
    tracked.sort_by(|left, right| left.0.cmp(&right.0));
    if tracked.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(GitError::Invalid("duplicate tracked path".into()));
    }
    let mut hash = Sha256::new();
    hash.update(b"forgeflow.source-content.v1\0");
    hash.update((tracked.len() as u64).to_be_bytes());
    let mut process = SourceGitProcess::spawn(repo, &["cat-file", "--batch"], deadline)?;
    let mut input = process.child.stdin.take().unwrap();
    let mut output = std::io::BufReader::new(process.child.stdout.take().unwrap());
    let mut seen = std::collections::BTreeMap::<String, (u64, [u8; 32])>::new();
    let mut entries = Vec::with_capacity(tracked.len());
    let mut total_blob_bytes = 0u64;
    for (path, mode, oid) in tracked {
        let (size, blob_hash) = if let Some(previous) = seen.get(&oid) {
            *previous
        } else {
            writeln!(input, "{oid}")?;
            input.flush()?;
            let mut header = Vec::new();
            output.by_ref().take(256).read_until(b'\n', &mut header)?;
            if !header.ends_with(b"\n") {
                return Err(GitError::Invalid(
                    "invalid or oversized batch object header".into(),
                ));
            }
            let header = std::str::from_utf8(&header)
                .map_err(|_| GitError::Invalid("invalid blob header".into()))?;
            let fields: Vec<_> = header.trim_end_matches('\n').split(' ').collect();
            if fields.len() != 3 || fields[0] != oid || fields[1] != "blob" {
                return Err(GitError::Invalid(
                    "missing or substituted tracked blob".into(),
                ));
            }
            let size = fields[2]
                .parse::<u64>()
                .map_err(|_| GitError::Invalid("invalid blob byte count".into()))?;
            if size > 512 * 1024 * 1024
                || total_blob_bytes.saturating_add(size) > 4 * 1024 * 1024 * 1024
            {
                return Err(GitError::Invalid(
                    "tracked source byte budget exceeded".into(),
                ));
            }
            let mut blob_hash = Sha256::new();
            let mut remaining = size;
            let mut buffer = [0u8; 64 * 1024];
            while remaining > 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                output.read_exact(&mut buffer[..count])?;
                blob_hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            let mut newline = [0u8; 1];
            output.read_exact(&mut newline)?;
            if newline[0] != b'\n' {
                return Err(GitError::Invalid("invalid blob terminator".into()));
            }
            let blob_hash: [u8; 32] = blob_hash.finalize().into();
            seen.insert(oid, (size, blob_hash));
            (size, blob_hash)
        };
        total_blob_bytes = total_blob_bytes
            .checked_add(size)
            .filter(|total| *total <= 4 * 1024 * 1024 * 1024)
            .ok_or_else(|| GitError::Invalid("tracked source byte budget exceeded".into()))?;
        hash.update(u32::from_str_radix(&mode, 8).unwrap().to_be_bytes());
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(&path);
        hash.update(size.to_be_bytes());
        hash.update(blob_hash);
        entries.push(SourceContentEntry {
            path_hex: source_hex(&path),
            mode,
            blob_bytes: size,
            blob_sha256: source_hex(&blob_hash),
        });
    }
    drop(input);
    process.finish()?;
    Ok(SourceContentManifest {
        algorithm: SOURCE_CONTENT_ALGORITHM.into(),
        commit_sha,
        tree_oid,
        source_sha256: source_hex(&hash.finalize()),
        tracked_entries: entries.len() as u64,
        total_blob_bytes,
        entries,
    })
}
pub fn worktree_metadata_dir(worktree: &Path) -> Result<PathBuf, GitError> {
    Ok(PathBuf::from(txt(
        worktree,
        &["rev-parse", "--absolute-git-dir"],
    )?))
}
/// Scratch exposed writable to verifier processes, separate from source/Git metadata.
pub fn integration_verification_root(worktree: &Path) -> Result<PathBuf, GitError> {
    let worktree = fs::canonicalize(worktree)?;
    let name = worktree
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| GitError::Invalid("non UTF-8 integration workspace".into()))?;
    let root = worktree
        .parent()
        .ok_or_else(|| GitError::Invalid("integration workspace has no parent".into()))?
        .join(format!("{name}-verification"));
    fs::create_dir_all(&root)?;
    Ok(fs::canonicalize(root)?)
}
pub fn is_ancestor(repo: &Path, ancestor: &str, descendant: &str) -> Result<bool, GitError> {
    let ancestor = resolve(repo, ancestor)?;
    let descendant = resolve(repo, descendant)?;
    let out = git_command(Some(repo))
        .args(["merge-base", "--is-ancestor", &ancestor, &descendant])
        .output()?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Command(
            String::from_utf8_lossy(&out.stderr).into(),
        )),
    }
}
pub fn init_managed_repository(source: Option<&Path>, target: &Path) -> Result<PathBuf, GitError> {
    if target.exists() {
        return Err(GitError::Invalid("target already exists".into()));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut cmd = git_command(None);
    if let Some(src) = source {
        cmd.args(["clone", "--bare", "--no-hardlinks", "--"])
            .arg(src)
            .arg(target);
    } else {
        cmd.args(["init", "--bare", "--initial-branch=main"])
            .arg(target);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(GitError::Command(
            String::from_utf8_lossy(&out.stderr).into(),
        ));
    }
    canonical(target)?;
    Ok(fs::canonicalize(target)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorktreeRecord {
    pub branch: String,
    pub absolute_path: PathBuf,
    pub base_sha: String,
    pub attempt_id: String,
    #[serde(default)]
    pub isolation_profile: String,
    #[serde(default)]
    pub clone_duration_ms: u64,
    #[serde(default)]
    pub object_bytes: u64,
    #[serde(default)]
    pub object_files: u64,
}
pub fn prepare_worktree(
    repo: &Path,
    base_sha: &str,
    attempt_id: &str,
    target: &Path,
) -> Result<WorktreeRecord, GitError> {
    canonical(repo)?;
    if !valid_id(attempt_id) || target.exists() {
        return Err(GitError::Invalid(
            "invalid attempt id or existing worktree".into(),
        ));
    }
    let base_sha = resolve(repo, base_sha)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let target = fs::canonicalize(
        target
            .parent()
            .ok_or_else(|| GitError::Invalid("missing worktree parent".into()))?,
    )?
    .join(
        target
            .file_name()
            .ok_or_else(|| GitError::Invalid("missing worktree name".into()))?,
    );
    let branch = format!("attempt/{attempt_id}");
    run(
        repo,
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            target
                .to_str()
                .ok_or_else(|| GitError::Invalid("non UTF-8 worktree path".into()))?,
            &base_sha,
        ],
    )?;
    Ok(WorktreeRecord {
        branch,
        absolute_path: target,
        base_sha,
        attempt_id: attempt_id.into(),
        isolation_profile: "LOCAL_TRUSTED_WORKTREE".into(),
        clone_duration_ms: 0,
        object_bytes: 0,
        object_files: 0,
    })
}

/// Materialize a private repository with independent object storage and metadata.
/// The caller's OS guard must hide the canonical source after this factory returns.
pub fn prepare_isolated_repository(
    repo: &Path,
    base_sha: &str,
    attempt_id: &str,
    target: &Path,
) -> Result<WorktreeRecord, GitError> {
    let started = std::time::Instant::now();
    if !valid_id(attempt_id) || target.exists() {
        return Err(GitError::Invalid(
            "invalid attempt id or existing private repository".into(),
        ));
    }
    let repo = fs::canonicalize(repo)?;
    // Resolve the exact commit and require a bare authority in one process.
    // rev-parse's --end-of-options keeps caller-supplied revisions out of flags.
    let identity = txt(
        &repo,
        &[
            "rev-parse",
            "--is-bare-repository",
            "--verify",
            "--end-of-options",
            &format!("{base_sha}^{{commit}}"),
        ],
    )?;
    let mut identity = identity.lines();
    if identity.next() != Some("true") {
        return Err(GitError::Invalid(
            "canonical repository must be bare".into(),
        ));
    }
    let base_sha = identity
        .next()
        .filter(|sha| {
            matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(|| GitError::Invalid("invalid frozen base commit".into()))?
        .to_owned();
    if identity.next().is_some() {
        return Err(GitError::Invalid(
            "ambiguous canonical repository identity".into(),
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| GitError::Invalid("missing private repository parent".into()))?;
    fs::create_dir_all(parent)?;
    let target = fs::canonicalize(parent)?.join(
        target
            .file_name()
            .ok_or_else(|| GitError::Invalid("missing repository name".into()))?,
    );
    if target.starts_with(&repo) {
        return Err(GitError::Invalid(
            "private repository must be outside canonical metadata".into(),
        ));
    }
    let output = git_command(None)
        .args([
            "clone",
            // Local object copying avoids transport/upload-pack recompression
            // of all history. --no-hardlinks makes every object a private inode;
            // the mandatory scan below still rejects any shared storage.
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            "--origin",
            "bootstrap",
            "--",
        ])
        .arg(&repo)
        .arg(&target)
        .output()?;
    if !output.status.success() {
        return Err(GitError::Command(
            String::from_utf8_lossy(&output.stderr).into(),
        ));
    }
    run(&target, &["remote", "remove", "bootstrap"])?;
    let branch = format!("attempt/{attempt_id}");
    run(
        &target,
        &["checkout", "--no-track", "-b", &branch, &base_sha],
    )?;
    // Clone provenance never becomes an executor-visible source pointer.
    let logs = target.join(".git/logs");
    if logs.exists() {
        fs::remove_dir_all(logs)?;
    }
    let (object_files, object_bytes) = verify_private_repository(&target)?;
    Ok(WorktreeRecord {
        branch,
        absolute_path: target,
        base_sha,
        attempt_id: attempt_id.into(),
        isolation_profile: "PRIVATE_GIT_METADATA".into(),
        clone_duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        object_bytes,
        object_files,
    })
}

/// Reject linked Git metadata, object alternates, symlinks, and shared hardlinks.
pub fn verify_private_repository(worktree: &Path) -> Result<(u64, u64), GitError> {
    let root = fs::canonicalize(worktree)?;
    let dir = root.join(".git");
    let root_metadata = fs::symlink_metadata(&dir)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(GitError::Invalid(
            "private repository requires its own .git directory".into(),
        ));
    }
    if dir.join("commondir").exists() || dir.join("objects/info/alternates").exists() {
        return Err(GitError::Invalid(
            "private repository has shared metadata or object alternates".into(),
        ));
    }
    let mut files = 0u64;
    let mut bytes = 0u64;
    let objects = dir.join("objects");
    let mut pending = vec![dir.clone()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(GitError::Invalid(
                    "private Git metadata contains symlink".into(),
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(GitError::Invalid(
                    "private Git metadata contains special file".into(),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(GitError::Invalid(
                        "private Git metadata contains shared hardlink".into(),
                    ));
                }
            }
            if path.starts_with(&objects) {
                files = files.checked_add(1).ok_or_else(|| {
                    GitError::Invalid("private object file accounting overflow".into())
                })?;
                bytes = bytes.checked_add(metadata.len()).ok_or_else(|| {
                    GitError::Invalid("private object byte accounting overflow".into())
                })?;
            }
        }
    }
    let configuration = run(
        &root,
        &["config", "--local", "--no-includes", "--null", "--list"],
    )?;
    let safe_keys = [
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.ignorecase",
        "core.precomposeunicode",
        "extensions.objectformat",
        "user.name",
        "user.email",
        "author.name",
        "author.email",
        "committer.name",
        "committer.email",
    ];
    let mut bare_value = None;
    for record in configuration
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        // --null --list separates each key from its value with the first LF;
        // values may contain further LFs or non-UTF8 identity bytes.
        let split = record
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(record.len());
        let key = std::str::from_utf8(&record[..split])
            .map_err(|_| GitError::Invalid("non ASCII private config key".into()))?
            .to_ascii_lowercase();
        if !safe_keys.contains(&key.as_str()) {
            return Err(GitError::Invalid("private repository contains unapproved executable configuration or external config pointers".into()));
        }
        if key == "core.bare" {
            bare_value = Some(if split < record.len() {
                &record[split + 1..]
            } else {
                &[]
            });
        }
    }
    let metadata = txt(
        &root,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--absolute-git-dir",
            "--git-common-dir",
        ],
    )?;
    let mut metadata = metadata.lines();
    let own_dir = metadata.next().map(PathBuf::from);
    let common_dir = metadata.next().map(PathBuf::from);
    if own_dir.as_deref() != Some(dir.as_path())
        || common_dir
            .as_ref()
            .is_none_or(|common| fs::canonicalize(common).ok().as_ref() != Some(&dir))
        || metadata.next().is_some()
        || bare_value != Some(b"false".as_slice())
    {
        return Err(GitError::Invalid(
            "Git metadata resolves outside private repository".into(),
        ));
    }
    Ok((files, bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathScope {
    pub owner_paths: Vec<String>,
    pub write_set: Vec<String>,
}
fn normalized(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn matches(path: &str, rule: &str) -> bool {
    if let Some(prefix) = rule.strip_suffix('/') {
        normalized(prefix) && path.starts_with(&format!("{prefix}/"))
    } else {
        normalized(rule) && path == rule
    }
}
impl PathScope {
    pub fn permits(&self, path: &str) -> bool {
        normalized(path)
            && self.owner_paths.iter().any(|r| matches(path, r))
            && self.write_set.iter().any(|r| matches(path, r))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChange {
    pub layer: String,
    pub status: String,
    pub path: String,
    pub old_path: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffManifest {
    pub base_sha: String,
    pub head_sha: String,
    pub changes: Vec<FileChange>,
    pub patch: String,
    pub untracked: Vec<UntrackedArtifact>,
    pub hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UntrackedArtifact {
    pub path: String,
    pub hash: String,
    pub bytes: Vec<u8>,
}
fn fields(bytes: Vec<u8>) -> Result<Vec<String>, GitError> {
    bytes
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .map(|v| {
            String::from_utf8(v.to_vec())
                .map_err(|_| GitError::Invalid("non UTF-8 path; cannot audit safely".into()))
        })
        .collect()
}
fn changes(repo: &Path, args: &[&str], layer: &str) -> Result<Vec<FileChange>, GitError> {
    let f = fields(run(repo, args)?)?;
    let mut out = vec![];
    let mut i = 0;
    while i < f.len() {
        let status = f[i].clone();
        i += 1;
        let first = f
            .get(i)
            .ok_or_else(|| GitError::Invalid("malformed Git diff".into()))?
            .clone();
        i += 1;
        let (path, old_path) = if status.starts_with('R') || status.starts_with('C') {
            let second = f
                .get(i)
                .ok_or_else(|| GitError::Invalid("malformed rename".into()))?
                .clone();
            i += 1;
            (second, Some(first))
        } else {
            (first, None)
        };
        out.push(FileChange {
            layer: layer.into(),
            status,
            path,
            old_path,
        });
    }
    Ok(out)
}
pub fn audit_worktree(
    worktree: &Path,
    base: &str,
    scope: &PathScope,
) -> Result<DiffManifest, GitError> {
    if worktree.join(".git").is_dir() {
        verify_private_repository(worktree)?;
    }
    let base_sha = resolve(worktree, base)?;
    let head_sha = resolve(worktree, "HEAD")?;
    let mut all = changes(
        worktree,
        &[
            "diff",
            "--name-status",
            "-z",
            "-M",
            &base_sha,
            &head_sha,
            "--",
        ],
        "committed",
    )?;
    all.extend(changes(
        worktree,
        &["diff", "--cached", "--name-status", "-z", "-M", "--"],
        "staged",
    )?);
    all.extend(changes(
        worktree,
        &["diff", "--name-status", "-z", "-M", "--"],
        "unstaged",
    )?);
    for path in fields(run(worktree, &["ls-files", "--others", "-z"])?)? {
        all.push(FileChange {
            layer: "untracked".into(),
            status: "?".into(),
            path,
            old_path: None,
        });
    }
    let mut violations = BTreeSet::new();
    for c in &all {
        for path in std::iter::once(&c.path).chain(c.old_path.iter()) {
            if !scope.permits(path) {
                violations.insert(path.clone());
            }
            // Check changed symlinks in every version: a later deletion cannot hide an escaped committed target.
            for revision in [&base_sha, &head_sha] {
                let entries = run(worktree, &["ls-tree", "-z", revision, "--", path])?;
                let entries = String::from_utf8_lossy(&entries);
                if entries.starts_with("160000 ") {
                    violations.insert(format!("submodule:{path}"));
                }
                if entries.starts_with("120000 ") {
                    let target = run(worktree, &["show", &format!("{revision}:{path}")])?;
                    if !safe_link(path, &String::from_utf8_lossy(&target)) {
                        violations.insert(format!("symlink:{path}"));
                    }
                }
            }
            let disk = worktree.join(path);
            if let Ok(meta) = fs::symlink_metadata(&disk) {
                if meta.file_type().is_symlink() {
                    if !safe_link(path, &fs::read_link(&disk)?.to_string_lossy()) {
                        violations.insert(format!("symlink:{path}"));
                    }
                }
            }
            let staged = run(worktree, &["ls-files", "--stage", "-z", "--", path])?;
            if staged.starts_with(b"160000 ") {
                violations.insert(format!("submodule:{path}"));
            }
            if staged.starts_with(b"120000 ") {
                let target = run(worktree, &["show", &format!(":{path}")])?;
                if !safe_link(path, &String::from_utf8_lossy(&target)) {
                    violations.insert(format!("symlink:{path}"));
                }
            }
        }
    }
    let mut patch = Vec::new();
    for args in [
        vec!["diff", "--binary", &base_sha, &head_sha, "--"],
        vec!["diff", "--cached", "--binary", "--"],
        vec!["diff", "--binary", "--"],
    ] {
        patch.extend(run(worktree, &args)?);
    }
    let patch = String::from_utf8_lossy(&patch).into_owned();
    let mut untracked_bytes = Vec::new();
    for c in &all {
        if c.layer == "untracked" {
            let p = worktree.join(&c.path);
            let meta = fs::symlink_metadata(&p)?;
            let bytes = if meta.file_type().is_symlink() {
                fs::read_link(&p)?.to_string_lossy().as_bytes().to_vec()
            } else if meta.is_file() {
                fs::read(p)?
            } else {
                violations.insert(format!("unsupported-file:{}", c.path));
                Vec::new()
            };
            untracked_bytes.push(UntrackedArtifact {
                path: c.path.clone(),
                hash: sha256(&bytes),
                bytes,
            });
        }
    }
    let hash = sha256(
        &serde_json::to_vec(&(&base_sha, &head_sha, &all, &patch, &untracked_bytes)).unwrap(),
    );
    let manifest = DiffManifest {
        base_sha,
        head_sha,
        changes: all,
        patch,
        untracked: untracked_bytes,
        hash,
    };
    // Save the full observed manifest before rejecting, without adding it to candidate bytes.
    if !violations.is_empty() {
        let git_dir = txt(worktree, &["rev-parse", "--absolute-git-dir"])?;
        fs::write(
            Path::new(&git_dir).join("forgeflow-rejected-diff.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )?;
        return Err(GitError::WriteScopeViolation(
            violations.into_iter().collect(),
        ));
    }
    Ok(manifest)
}
pub fn audit_private_worktree(
    worktree: &Path,
    base: &str,
    scope: &PathScope,
) -> Result<DiffManifest, GitError> {
    verify_private_repository(worktree)?;
    audit_worktree(worktree, base, scope)
}
fn safe_link(path: &str, target: &str) -> bool {
    if Path::new(target).is_absolute() || target.contains('\\') || target.is_empty() {
        return false;
    }
    let mut depth = Path::new(path)
        .parent()
        .map(|p| p.components().count())
        .unwrap_or(0);
    for c in Path::new(target).components() {
        match c {
            Component::ParentDir => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            _ => return false,
        }
    }
    true
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub base_sha: String,
    pub candidate_sha: String,
    pub diff_manifest_hash: String,
    pub source_hash: String,
    pub manifest: DiffManifest,
}
pub fn freeze_candidate(
    worktree: &Path,
    base: &str,
    scope: &PathScope,
    message: &str,
) -> Result<Candidate, GitError> {
    if worktree.join(".git").is_dir() {
        verify_private_repository(worktree)?;
    }
    let before = audit_worktree(worktree, base, scope)?;
    let paths: BTreeSet<_> = before
        .changes
        .iter()
        .filter(|c| c.layer != "committed")
        .flat_map(|c| std::iter::once(c.path.as_str()).chain(c.old_path.as_deref()))
        .collect();
    if !paths.is_empty() {
        let mut args = vec!["add", "--all", "--"];
        args.extend(paths);
        run(worktree, &args)?;
        if !run(worktree, &["diff", "--cached", "--name-only", "-z", "--"])?.is_empty() {
            run(
                worktree,
                &[
                    "-c",
                    "user.name=ForgeFlow",
                    "-c",
                    "user.email=forgeflow@localhost",
                    "commit",
                    "-m",
                    message,
                ],
            )?;
        }
    }
    let manifest = audit_worktree(worktree, base, scope)?;
    if manifest.changes.is_empty() {
        return Err(GitError::Invalid("code-write attempt has no candidate changes; read-only work uses structured artifact evidence".into()));
    }
    if manifest.changes.iter().any(|c| c.layer != "committed") {
        return Err(GitError::Invalid("worktree changed during freeze".into()));
    }
    let candidate_sha = manifest.head_sha.clone();
    Ok(Candidate {
        base_sha: manifest.base_sha.clone(),
        source_hash: source_hash(worktree, &candidate_sha)?,
        candidate_sha,
        diff_manifest_hash: manifest.hash.clone(),
        manifest,
    })
}
pub fn freeze_private_candidate(
    worktree: &Path,
    base: &str,
    scope: &PathScope,
    message: &str,
) -> Result<Candidate, GitError> {
    verify_private_repository(worktree)?;
    freeze_candidate(worktree, base, scope, message)
}

/// Transfer one independently stored, frozen and fully audited candidate into
/// a server-only canonical receipt ref. Does not update any integration branch.
pub fn import_candidate(
    canonical_repo: &Path,
    private_worktree: &Path,
    candidate: &Candidate,
    attempt_id: &str,
    scope: &PathScope,
) -> Result<(), GitError> {
    canonical(canonical_repo)?;
    if !valid_id(attempt_id) {
        return Err(GitError::Invalid("invalid candidate attempt id".into()));
    }
    verify_private_repository(private_worktree)?;
    resolve(canonical_repo, &candidate.base_sha)?;
    if !is_ancestor(
        private_worktree,
        &candidate.base_sha,
        &candidate.candidate_sha,
    )? {
        return Err(GitError::Invalid(
            "private candidate does not descend from registered base".into(),
        ));
    }
    let observed = audit_worktree(private_worktree, &candidate.base_sha, scope)?;
    if observed.head_sha != candidate.candidate_sha
        || observed.hash != candidate.diff_manifest_hash
        || observed.changes.iter().any(|c| c.layer != "committed")
        || source_hash(private_worktree, &candidate.candidate_sha)? != candidate.source_hash
    {
        return Err(GitError::Evidence(
            "private candidate changed after freeze".into(),
        ));
    }
    let reference = format!("refs/forgeflow/candidates/{attempt_id}");
    if let Ok(existing) = resolve(canonical_repo, &reference) {
        if existing == candidate.candidate_sha {
            return Ok(());
        }
        return Err(GitError::Invalid(
            "candidate receipt ref already binds different bytes".into(),
        ));
    }
    let path = fs::canonicalize(private_worktree)?;
    run(
        canonical_repo,
        &[
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-auto-gc",
            path.to_str()
                .ok_or_else(|| GitError::Invalid("non UTF-8 private source".into()))?,
            &candidate.candidate_sha,
        ],
    )?;
    let zero = "0".repeat(candidate.candidate_sha.len());
    if run(
        canonical_repo,
        &["update-ref", &reference, &candidate.candidate_sha, &zero],
    )
    .is_err()
        && resolve(canonical_repo, &reference)? != candidate.candidate_sha
    {
        return Err(GitError::Invalid(
            "candidate receipt ref was concurrently rebound".into(),
        ));
    }
    if resolve(canonical_repo, &reference)? != candidate.candidate_sha
        || source_hash(canonical_repo, &candidate.candidate_sha)? != candidate.source_hash
    {
        return Err(GitError::Evidence(
            "imported candidate source identity mismatch".into(),
        ));
    }
    Ok(())
}

pub fn compare_and_swap_ref(
    repo: &Path,
    target_ref: &str,
    expected: &str,
    new_sha: &str,
) -> Result<(), GitError> {
    canonical(repo)?;
    if !target_ref.starts_with("refs/heads/") {
        return Err(GitError::Invalid(
            "integration target must be branch ref".into(),
        ));
    }
    run(repo, &["check-ref-format", target_ref])?;
    let expected = resolve(repo, expected)?;
    let new_sha = resolve(repo, new_sha)?;
    if run(repo, &["update-ref", target_ref, &new_sha, &expected]).is_err() {
        return Err(GitError::StaleRef {
            expected,
            actual: resolve(repo, target_ref)?,
        });
    }
    Ok(())
}

// Async durable store port is implemented by the PostgreSQL authority.
#[async_trait]
pub trait IntegrationStore: Send + Sync {
    async fn prepare_merge(
        &self,
        intent: forgeflow_domain::MergeIntent,
    ) -> Result<forgeflow_domain::MergeIntent, String>;
    async fn decide_merge(
        &self,
        project_id: &str,
        intent_id: &str,
        expected_revision: u64,
    ) -> Result<forgeflow_domain::MergeIntent, String>;
    async fn confirm_merge(
        &self,
        project_id: &str,
        intent_id: &str,
        integrated_sha: &str,
        receipt: serde_json::Value,
    ) -> Result<forgeflow_domain::MergeIntent, String>;
    async fn get_merge_intent(
        &self,
        project_id: &str,
        intent_id: &str,
    ) -> Result<forgeflow_domain::MergeIntent, String>;
    async fn pending_merges(
        &self,
        project_id: &str,
        target_ref: &str,
    ) -> Result<Vec<forgeflow_domain::MergeIntent>, String>;
    async fn abort_merge(
        &self,
        _project_id: &str,
        _intent_id: &str,
        _reason: &str,
    ) -> Result<forgeflow_domain::MergeIntent, String> {
        Err("store does not expose PREPARED abort".into())
    }
    async fn mark_merge_recovery_required(
        &self,
        _project_id: &str,
        _intent_id: &str,
        _reason: &str,
    ) -> Result<forgeflow_domain::MergeIntent, String> {
        Err("store does not expose divergence recording".into())
    }
}

static GLOBAL_INTEGRATION_LANE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub struct IntegrationService {
    lane: &'static tokio::sync::Mutex<()>,
}
impl Default for IntegrationService {
    fn default() -> Self {
        Self {
            lane: &GLOBAL_INTEGRATION_LANE,
        }
    }
}
struct RepositoryLane(fs::File);
impl RepositoryLane {
    fn acquire(repo: &Path) -> Result<Self, GitError> {
        canonical(repo)?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(repo.join("forgeflow-integration.lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(GitError::Store("integration lane busy".into()));
            }
        }
        #[cfg(not(unix))]
        return Err(GitError::Invalid(
            "OS integration locking is unsupported on this platform".into(),
        ));
        Ok(Self(file))
    }
}
impl Drop for RepositoryLane {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
pub struct IntegrationRequest<'a> {
    pub repo: &'a Path,
    pub project_id: &'a str,
    pub attempt_id: &'a str,
    pub generation: i64,
    pub target_ref: &'a str,
    pub candidate: &'a Candidate,
    pub scope: &'a PathScope,
    pub integration_path: &'a Path,
    pub binding: &'a EvidenceBinding,
}
impl IntegrationService {
    /// Serialize all integrations. Revalidation runs against the newly constructed integration SHA.
    pub async fn integrate<S, F>(
        &self,
        store: &S,
        request: IntegrationRequest<'_>,
        verify: F,
    ) -> Result<forgeflow_domain::MergeIntent, GitError>
    where
        S: IntegrationStore,
        F: FnOnce(&Path, &EvidenceBinding) -> Result<VerificationReceipt, GitError>,
    {
        self.integrate_async(store, request, |path, binding| async move {
            verify(&path, &binding)
        })
        .await
    }

    pub async fn integrate_async<S, F, Fut>(
        &self,
        store: &S,
        request: IntegrationRequest<'_>,
        verify: F,
    ) -> Result<forgeflow_domain::MergeIntent, GitError>
    where
        S: IntegrationStore,
        F: FnOnce(PathBuf, EvidenceBinding) -> Fut,
        Fut: std::future::Future<Output = Result<VerificationReceipt, GitError>>,
    {
        let _lane = self.lane.lock().await;
        let _repository_lane = RepositoryLane::acquire(request.repo)?;
        if !store
            .pending_merges(request.project_id, request.target_ref)
            .await
            .map_err(GitError::Store)?
            .is_empty()
        {
            return Err(GitError::Store(
                "unresolved merge intent; recovery required before next integration".into(),
            ));
        }
        let old = resolve(request.repo, request.target_ref)?;
        if !is_ancestor(
            request.repo,
            &request.candidate.base_sha,
            &request.candidate.candidate_sha,
        )? || !is_ancestor(request.repo, &request.candidate.base_sha, &old)?
        {
            return Err(GitError::Diverged(
                "candidate base no longer belongs to candidate and current main history".into(),
            ));
        }
        if request.candidate.source_hash
            != source_hash(request.repo, &request.candidate.candidate_sha)?
        {
            return Err(GitError::Evidence("candidate bytes changed".into()));
        }
        let committed = changes(
            request.repo,
            &[
                "diff",
                "--name-status",
                "-z",
                "-M",
                &request.candidate.base_sha,
                &request.candidate.candidate_sha,
                "--",
            ],
            "committed",
        )?;
        let violations: Vec<_> = committed
            .iter()
            .flat_map(|c| std::iter::once(&c.path).chain(c.old_path.iter()))
            .filter(|p| !request.scope.permits(p))
            .cloned()
            .collect();
        if !violations.is_empty() {
            return Err(GitError::WriteScopeViolation(violations));
        }
        let intent_id = uuid::Uuid::new_v4().to_string();
        let wt = prepare_isolated_repository(
            request.repo,
            &old,
            &format!("integration-{intent_id}"),
            request.integration_path,
        )?;
        run(
            &wt.absolute_path,
            &[
                "-c",
                "protocol.file.allow=always",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-auto-gc",
                request
                    .repo
                    .to_str()
                    .ok_or_else(|| GitError::Invalid("non UTF-8 canonical source".into()))?,
                &request.candidate.candidate_sha,
            ],
        )?;
        if run(
            &wt.absolute_path,
            &[
                "-c",
                "user.name=ForgeFlow",
                "-c",
                "user.email=forgeflow@localhost",
                "merge",
                "--no-ff",
                "--no-commit",
                &request.candidate.candidate_sha,
            ],
        )
        .is_err()
        {
            return Err(GitError::Conflict(wt.absolute_path));
        }
        // If merge already up-to-date it is a duplicate candidate, never fabricate another commit.
        if resolve(&wt.absolute_path, "HEAD")? == old
            && !Path::new(&txt(
                &wt.absolute_path,
                &["rev-parse", "--absolute-git-dir"],
            )?)
            .join("MERGE_HEAD")
            .exists()
        {
            return Err(GitError::Invalid(
                "candidate already reachable; no new integration".into(),
            ));
        }
        audit_worktree(&wt.absolute_path, &old, request.scope)?;
        run(
            &wt.absolute_path,
            &[
                "-c",
                "user.name=ForgeFlow",
                "-c",
                "user.email=forgeflow@localhost",
                "commit",
                "-m",
                &format!("Integrate attempt {}", request.attempt_id),
            ],
        )?;
        let new_sha = resolve(&wt.absolute_path, "HEAD")?;
        let mut binding = request.binding.clone();
        if binding.attempt_id != request.attempt_id
            || binding.generation != request.generation
            || binding.base_sha != request.candidate.base_sha
            || binding.candidate_sha != request.candidate.candidate_sha
        {
            return Err(GitError::Evidence("candidate binding mismatch".into()));
        }
        binding.integrated_sha = Some(new_sha.clone());
        binding.source_hash = source_hash(&wt.absolute_path, &new_sha)?;
        let receipt = verify(wt.absolute_path.clone(), binding.clone()).await?;
        receipt
            .validate(&binding, true)
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        let verification_root = integration_verification_root(&wt.absolute_path)?;
        receipt
            .validate_log(&verification_root)
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        fs::File::open(verification_root.join(&receipt.log_path))?.sync_all()?;
        let audit = audit_worktree(&wt.absolute_path, &old, request.scope)?;
        if audit.head_sha != new_sha
            || source_hash(&wt.absolute_path, "HEAD")? != binding.source_hash
            || audit.changes.iter().any(|c| c.layer != "committed")
        {
            return Err(GitError::Invalid(
                "verification changed integration bytes".into(),
            ));
        }
        let integrated_candidate = Candidate {
            base_sha: old.clone(),
            candidate_sha: new_sha.clone(),
            diff_manifest_hash: audit.hash.clone(),
            source_hash: binding.source_hash.clone(),
            manifest: audit.clone(),
        };
        import_candidate(
            request.repo,
            &wt.absolute_path,
            &integrated_candidate,
            &format!("integration-{intent_id}"),
            request.scope,
        )?;
        // The canonical snapshot is controller-only and is never a verifier mount.
        let artifact_root = fs::canonicalize(request.repo)?
            .join("forgeflow-evidence")
            .join(&intent_id);
        fs::create_dir_all(&artifact_root)?;
        let snapshot_log = artifact_root.join(&receipt.log_path);
        fs::create_dir_all(
            snapshot_log
                .parent()
                .ok_or_else(|| GitError::Invalid("snapshot log has no parent".into()))?,
        )?;
        fs::copy(verification_root.join(&receipt.log_path), &snapshot_log)?;
        receipt
            .validate_log(&artifact_root)
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        fs::File::open(&snapshot_log)?.sync_all()?;
        let source_content = source_content_manifest(request.repo, &new_sha)?;
        if source_content.tree_oid != receipt.binding.source_hash {
            return Err(GitError::Evidence(
                "integrated source tree differs from verified tree".into(),
            ));
        }
        let receipt_value = serde_json::json!({"new_sha":new_sha,"verification_receipt_hash":receipt.digest(),"verification":receipt,"diff_manifest_hash":audit.hash,"artifact_root":artifact_root,"integration_workspace":wt.absolute_path,"verifier_scratch_root":verification_root,
            "source_content_sha256":source_content.source_sha256,
            "source_content_algorithm":source_content.algorithm,
            "source_tree_oid":source_content.tree_oid});
        // Immutable receipt is written before the durable decision and ref update.
        let receipt_path = artifact_root.join("forgeflow-verification.json");
        let mut receipt_file = fs::File::create(&receipt_path)?;
        use std::io::Write;
        receipt_file.write_all(&serde_json::to_vec_pretty(&receipt_value).unwrap())?;
        receipt_file.sync_all()?;
        fs::File::open(&artifact_root)?.sync_all()?;
        let intent = forgeflow_domain::MergeIntent {
            intent_id,
            project_id: request.project_id.into(),
            attempt_id: request.attempt_id.into(),
            generation: request.generation,
            target_ref: request.target_ref.into(),
            expected_sha: old.clone(),
            candidate_sha: request.candidate.candidate_sha.clone(),
            integrated_sha: Some(new_sha.clone()),
            state: forgeflow_domain::MergeIntentState::Prepared,
            revision: 0,
            receipt: Some(receipt_value.clone()),
        };
        let prepared = store.prepare_merge(intent).await.map_err(GitError::Store)?;
        let decided = store
            .decide_merge(&prepared.project_id, &prepared.intent_id, prepared.revision)
            .await
            .map_err(|reason| GitError::CommitInProgress {
                intent_id: prepared.intent_id.clone(),
                new_sha: new_sha.clone(),
                reason,
            })?;
        if let Err(error) = compare_and_swap_ref(request.repo, request.target_ref, &old, &new_sha) {
            let _ = store
                .mark_merge_recovery_required(
                    &decided.project_id,
                    &decided.intent_id,
                    &error.to_string(),
                )
                .await;
            return Err(error);
        }
        store
            .confirm_merge(
                &decided.project_id,
                &decided.intent_id,
                &new_sha,
                receipt_value,
            )
            .await
            .map_err(|reason| GitError::CommitInProgress {
                intent_id: decided.intent_id.clone(),
                new_sha,
                reason,
            })
    }

    /// Idempotent recovery never reapplies a candidate or rewrites history.
    pub async fn recover<S: IntegrationStore>(
        &self,
        store: &S,
        repo: &Path,
        project_id: &str,
        intent_id: &str,
    ) -> Result<forgeflow_domain::MergeIntent, GitError> {
        let _lane = self.lane.lock().await;
        let _repository_lane = RepositoryLane::acquire(repo)?;
        let intent = store
            .get_merge_intent(project_id, intent_id)
            .await
            .map_err(GitError::Store)?;
        if matches!(
            intent.state,
            forgeflow_domain::MergeIntentState::Committed
                | forgeflow_domain::MergeIntentState::Finalized
        ) {
            return Ok(intent);
        }
        if intent.state == forgeflow_domain::MergeIntentState::Prepared {
            return store
                .abort_merge(
                    project_id,
                    intent_id,
                    "recovery observed no durable commit decision",
                )
                .await
                .map_err(GitError::Store);
        }
        if !matches!(
            intent.state,
            forgeflow_domain::MergeIntentState::CommitDecided
                | forgeflow_domain::MergeIntentState::RefUpdated
        ) && !(intent.state == forgeflow_domain::MergeIntentState::RecoveryRequired
            && intent
                .receipt
                .as_ref()
                .and_then(|r| r.get("commit_decided"))
                .and_then(serde_json::Value::as_bool)
                == Some(true))
        {
            return Err(GitError::Store(
                "only durable COMMIT_DECIDED intent may recover".into(),
            ));
        }
        let new_sha = intent
            .integrated_sha
            .as_ref()
            .ok_or_else(|| GitError::Evidence("missing integration SHA".into()))?;
        let ref_was_updated = intent.state == forgeflow_domain::MergeIntentState::RefUpdated
            || intent
                .receipt
                .as_ref()
                .and_then(|r| r.get("ref_updated"))
                .and_then(serde_json::Value::as_bool)
                == Some(true);
        let mut value = intent
            .receipt
            .clone()
            .ok_or_else(|| GitError::Evidence("missing verification receipt".into()))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("commit_decided");
            object.remove("ref_updated");
        }
        let receipt: VerificationReceipt = serde_json::from_value(value["verification"].clone())
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        if value["new_sha"] != *new_sha
            || value["verification_receipt_hash"] != receipt.digest()
            || receipt.binding.integrated_sha.as_deref() != Some(new_sha)
            || receipt.binding.candidate_sha != intent.candidate_sha
            || receipt.binding.attempt_id != intent.attempt_id
            || receipt.binding.generation != intent.generation
            || receipt.binding.source_hash != source_hash(repo, new_sha)?
        {
            return Err(GitError::Evidence(
                "recovery receipt binding mismatch".into(),
            ));
        }
        receipt
            .validate(&receipt.binding, true)
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        let artifact_root = value["artifact_root"]
            .as_str()
            .ok_or_else(|| GitError::Evidence("missing artifact root".into()))?;
        let artifact_root = fs::canonicalize(artifact_root)?;
        let repo_root = fs::canonicalize(repo)?;
        if !valid_id(&intent.intent_id)
            || artifact_root != repo_root.join("forgeflow-evidence").join(&intent.intent_id)
        {
            return Err(GitError::Evidence(
                "artifact root outside controller-only canonical intent snapshot".into(),
            ));
        }
        receipt
            .validate_log(&artifact_root)
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        let receipt_bytes = fs::read(artifact_root.join("forgeflow-verification.json"))?;
        let disk_receipt: serde_json::Value = serde_json::from_slice(&receipt_bytes)
            .map_err(|e| GitError::Evidence(e.to_string()))?;
        if disk_receipt != value {
            return Err(GitError::Evidence(
                "persisted verification bytes mismatch".into(),
            ));
        }
        let current = resolve(repo, &intent.target_ref)?;
        if current == intent.expected_sha {
            if ref_was_updated {
                let _ = store
                    .mark_merge_recovery_required(
                        project_id,
                        intent_id,
                        "MERGE_DIVERGED: persisted REF_UPDATED but ref returned to old SHA",
                    )
                    .await;
                return Err(GitError::Diverged(
                    "persisted REF_UPDATED but ref returned to old SHA; no automatic rewrite"
                        .into(),
                ));
            }
            if let Err(error) =
                compare_and_swap_ref(repo, &intent.target_ref, &intent.expected_sha, new_sha)
            {
                let _ = store
                    .mark_merge_recovery_required(project_id, intent_id, &error.to_string())
                    .await;
                return Err(error);
            }
        } else if current != *new_sha {
            let _ = store
                .mark_merge_recovery_required(
                    project_id,
                    intent_id,
                    &format!("MERGE_DIVERGED: unexpected ref {current}"),
                )
                .await;
            return Err(GitError::Diverged(format!(
                "intent {} observed unexpected writer {} (descendants also require writer audit)",
                intent.intent_id, current
            )));
        }
        store
            .confirm_merge(project_id, intent_id, new_sha, value)
            .await
            .map_err(|reason| GitError::CommitInProgress {
                intent_id: intent_id.into(),
                new_sha: new_sha.clone(),
                reason,
            })
    }
}
