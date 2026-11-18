//! Explicit Linux namespace plus Landlock write fencing. No trusted-profile fallback.
use crate::ProcessSpec;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxProfile {
    pub bwrap_program: PathBuf,
    pub bwrap_sha256: String,
    pub guard_program: PathBuf,
    pub guard_sha256: String,
    /// Only approved runtime/oracle/config files and directories; no implicit host root/home.
    pub readonly_paths: Vec<PathBuf>,
    pub network_allowed: bool,
}
#[derive(Debug, Clone)]
pub struct SandboxMount {
    pub source: PathBuf,
    pub target: PathBuf,
}
#[derive(Debug, Clone)]
pub struct SandboxInstance {
    pub workspace: PathBuf,
    pub write_set: Vec<String>,
    pub allow_git_metadata: bool,
    /// Controller-derived session/cache mounts, never arbitrary executor input.
    pub writable_mounts: Vec<SandboxMount>,
}
pub fn landlock_abi() -> Result<i64> {
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        )
    };
    if version < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(version)
}
fn digest_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 16384];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn string(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("sandbox paths must be UTF-8")?
        .to_owned())
}
fn checked_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("absolute sandbox mount required");
    }
    Ok(fs::canonicalize(path)?)
}
fn relative(path: &str) -> Result<(&str, bool)> {
    // A single canonical suffix is an already-authorized directory prefix.
    // Strip exactly one: repeated or internal slashes still fail normalization.
    let directory = path.ends_with('/');
    let concrete = path.strip_suffix('/').unwrap_or(path);
    if concrete.is_empty()
        || concrete.contains(['\\', '\0', '*', '?', ':'])
        || Path::new(concrete).is_absolute()
        || Path::new(concrete)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || concrete.split('/').any(|c| c.is_empty() || c == ".")
    {
        bail!("concrete normalized sandbox write path required");
    }
    if concrete == ".git" || concrete.starts_with(".git/") {
        bail!("Git metadata permission is separate from code write set");
    }
    Ok((concrete, directory))
}
/// Preallocates exact new files and consumes canonical directory-prefix grants.
/// Exact files permit only in-place updates. A trailing '/' permits mutations
/// within that existing real directory, including same-directory atomic replace.
/// Missing directory scopes fail closed; preparation must create them explicitly.
pub fn sandbox_command(
    mut spec: ProcessSpec,
    profile: &SandboxProfile,
    instance: &SandboxInstance,
) -> Result<ProcessSpec> {
    if landlock_abi()? < 3 {
        bail!("Landlock ABI3 required; no weak truncation fallback");
    }
    for (path, digest) in [
        (&profile.bwrap_program, &profile.bwrap_sha256),
        (&profile.guard_program, &profile.guard_sha256),
    ] {
        if !path.is_absolute() || digest_file(path)? != *digest {
            bail!("sandbox executable pin mismatch");
        }
    }
    let workspace = checked_absolute(&instance.workspace)?;
    if checked_absolute(&spec.cwd)? != workspace {
        bail!("sandbox cwd differs from private workspace");
    }
    let mut args = vec![
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--die-with-parent".into(),
        "--disable-userns".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
    ];
    if !profile.network_allowed {
        args.push("--unshare-net".into());
    }
    for path in &profile.readonly_paths {
        let canonical = checked_absolute(path)?;
        if canonical == Path::new("/")
            || canonical == Path::new("/home")
            || canonical == Path::new("/proc")
            || canonical == Path::new("/sys")
        {
            bail!("broad host root/home/proc/sys exposure is forbidden");
        }
        args.extend(["--ro-bind".into(), string(path)?, string(path)?]);
    }
    args.extend([
        "--ro-bind".into(),
        string(&profile.guard_program)?,
        string(&profile.guard_program)?,
        "--ro-bind".into(),
        string(&workspace)?,
        string(&workspace)?,
    ]);
    let mut guard = vec!["--allow-dir".into(), "/tmp".into()];
    if instance.allow_git_metadata {
        let git = workspace.join(".git");
        if !fs::symlink_metadata(&git)?.is_dir() {
            bail!("sandbox requires independent Git metadata directory");
        }
        args.extend(["--bind".into(), string(&git)?, string(&git)?]);
        guard.extend(["--allow-dir".into(), string(&git)?]);
    }
    for write in &instance.write_set {
        let (write, directory) = relative(write)?;
        let path = workspace.join(write);
        let mut current = workspace.clone();
        for component in Path::new(write).components() {
            current.push(component);
            if let Ok(metadata) = fs::symlink_metadata(&current) {
                if metadata.file_type().is_symlink() {
                    bail!("sandbox write symlink refused");
                }
            }
        }
        if directory {
            let metadata = fs::symlink_metadata(&path)
                .context("declared sandbox directory must already exist")?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("directory-prefix write scope requires a real directory");
            }
        } else if path.exists() {
            if !fs::symlink_metadata(&path)?.is_file() {
                bail!("exact-file write scope cannot grant a directory or special file");
            }
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            file.sync_all()?;
        }
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&workspace) {
            bail!("sandbox write escapes workspace");
        }
        args.extend(["--bind".into(), string(&path)?, string(&path)?]);
        guard.extend([
            if directory {
                "--allow-dir"
            } else {
                "--allow-file"
            }
            .into(),
            string(&path)?,
        ]);
    }
    for mount in &instance.writable_mounts {
        let source = checked_absolute(&mount.source)?;
        if source.starts_with(&workspace)
            || workspace.starts_with(&source)
            || mount.target.starts_with(&workspace)
            || workspace.starts_with(&mount.target)
        {
            bail!("runtime scratch/session mount cannot overlap private candidate or Git metadata");
        }
        for readonly in profile
            .readonly_paths
            .iter()
            .chain(std::iter::once(&profile.guard_program))
        {
            if readonly.starts_with(&mount.target) {
                bail!(
                    "writable runtime mount would mask an approved readonly input/runtime object"
                );
            }
        }
        if !mount.target.is_absolute()
            || mount.target == Path::new("/")
            || mount.target == Path::new("/home")
            || mount.target == workspace
            || mount.target == Path::new("/proc")
            || mount.target == Path::new("/sys")
        {
            bail!("invalid writable runtime namespace target");
        }
        let bind = if source == Path::new("/dev/null") || mount.target == Path::new("/dev/null") {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = fs::symlink_metadata(&mount.source)?;
            if mount.source != Path::new("/dev/null")
                || source != Path::new("/dev/null")
                || mount.target != Path::new("/dev/null")
                || metadata.file_type().is_symlink()
                || !metadata.file_type().is_char_device()
                || metadata.rdev() != libc::makedev(1, 3)
            {
                bail!("output discard mount requires the exact null character device");
            }
            // Plain bwrap --bind remounts with MS_NODEV: the character inode
            // remains visible but open() fails. Enable device access only for
            // this checked null inode; every other mount keeps MS_NODEV.
            "--dev-bind"
        } else {
            "--bind"
        };
        args.extend([bind.into(), string(&source)?, string(&mount.target)?]);
        guard.extend([
            if source.is_dir() {
                "--allow-dir"
            } else {
                "--allow-file"
            }
            .into(),
            string(&mount.target)?,
        ]);
    }
    args.extend([
        "--chdir".into(),
        string(&workspace)?,
        "--".into(),
        string(&profile.guard_program)?,
    ]);
    args.extend(guard);
    args.push("--".into());
    args.push(string(&spec.program)?);
    args.extend(spec.args);
    spec.program = profile.bwrap_program.clone();
    spec.args = args;
    Ok(spec)
}

pub fn restrict_writes(files: &[PathBuf], directories: &[PathBuf]) -> Result<()> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
    };
    if landlock_abi()? < 3 {
        bail!("Landlock ABI3 unavailable");
    }
    const WRITE: u64 = 1 << 1;
    const TRUNCATE: u64 = 1 << 14;
    const WRITES: u64 = WRITE | ((1u64 << 13) - (1u64 << 4)) | (1u64 << 13) | TRUNCATE;
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct Beneath {
        allowed_access: u64,
        parent_fd: i32,
    }
    let attr = Ruleset {
        handled_access_fs: WRITES,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<Ruleset>(),
            0u32,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let ruleset = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    for (paths, rights) in [(files, WRITE | TRUNCATE), (directories, WRITES)] {
        for path in paths {
            let text = CString::new(path.as_os_str().as_bytes())?;
            let raw = unsafe { libc::open(text.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let parent = unsafe { OwnedFd::from_raw_fd(raw) };
            let rule = Beneath {
                allowed_access: rights,
                parent_fd: parent.as_raw_fd(),
            };
            if unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    1u32,
                    &rule,
                    0u32,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
