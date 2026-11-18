//! Attempt-scoped cgroup v2 fencing inside an owned delegated systemd service.
//! No root/shared-tree writes and no permission or controller fallback.
use crate::{Journal, LaunchIntent, boot_id, durable_json};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, RawFd},
    },
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CgroupDelegation {
    pub unit_name: String,
    pub root_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhysicalCgroupLimits {
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub memory_max_bytes: u64,
    pub memory_swap_max_bytes: u64,
    pub pids_max: u64,
    pub memory_oom_group: bool,
}
impl PhysicalCgroupLimits {
    pub fn validate(&self) -> Result<()> {
        if self.cpu_quota_us < 1000
            || !(1000..=1_000_000).contains(&self.cpu_period_us)
            || self.cpu_quota_us > i64::MAX as u64
            || self.memory_max_bytes == 0
            || self.memory_max_bytes > i64::MAX as u64
            || self.pids_max == 0
            || self.pids_max > i64::MAX as u64
            || self.memory_swap_max_bytes != 0
            || !self.memory_oom_group
        {
            bail!("positive finite CPU/memory/pids limits, swap=0 and group OOM are required");
        }
        Ok(())
    }
    fn files(&self) -> [(&'static str, String); 5] {
        [
            (
                "cpu.max",
                format!("{} {}", self.cpu_quota_us, self.cpu_period_us),
            ),
            ("memory.max", self.memory_max_bytes.to_string()),
            ("memory.swap.max", "0".into()),
            ("pids.max", self.pids_max.to_string()),
            ("memory.oom.group", "1".into()),
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalFenceRequest {
    pub project_id: String,
    pub delegation: CgroupDelegation,
    pub limits: PhysicalCgroupLimits,
    pub resource_binding_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupFenceIdentity {
    pub schema_version: String,
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub execution_id: String,
    pub boot_id: String,
    pub owner_uid: u32,
    pub delegation: CgroupDelegation,
    pub mount_id: u64,
    pub mount_path: PathBuf,
    pub mount_device: u64,
    pub root_inode: u64,
    pub leaf_path: PathBuf,
    pub leaf_inode: u64,
    pub limits: PhysicalCgroupLimits,
    pub resource_binding_sha256: String,
    pub identity_sha256: String,
}
impl CgroupFenceIdentity {
    pub fn limits_readback(&self) -> Result<BTreeMap<String, String>> {
        self.limits
            .files()
            .into_iter()
            .map(|(name, _)| Ok((name.to_owned(), read(&self.leaf_path, name)?)))
            .collect()
    }
    pub fn digest(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .context("physical identity must be an object")?
            .remove("identity_sha256");
        Ok(hash(&serde_json::to_vec(&value)?))
    }
    pub fn validate_record(&self) -> Result<()> {
        self.limits.validate()?;
        crate::safe_id(&self.project_id)?;
        crate::safe_id(&self.attempt_id)?;
        uuid::Uuid::parse_str(&self.execution_id)?;
        if self.schema_version != "forgeflow.cgroup-fence.v1"
            || self.generation < 1
            || !digest_ok(&self.resource_binding_sha256)
            || self.identity_sha256 != self.digest()?
        {
            bail!("invalid or changed physical cgroup identity");
        }
        Ok(())
    }
}

pub struct PreparedCgroupFence {
    pub identity: CgroupFenceIdentity,
    procs: File,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn digest_ok(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|v| v.is_ascii_hexdigit())
}
fn read(path: &Path, name: &str) -> Result<String> {
    Ok(fs::read_to_string(path.join(name))?.trim().to_owned())
}
fn write_control(path: &Path, name: &str, value: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path.join(name))?;
    file.write_all(value.as_bytes())?;
    Ok(())
}
fn owned_directory(path: &Path) -> Result<fs::Metadata> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        bail!("cgroup path must be absolute, canonical and unsymlinked");
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!("cgroup directory is not delegated to this UID");
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let encoded = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::statfs(encoded.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if stat.f_type as u64 != 0x63677270 {
        bail!("physical resource root is not cgroup v2");
    }
    Ok(metadata)
}
fn mount_for(path: &Path) -> Result<(u64, PathBuf)> {
    let mut candidates = Vec::new();
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let (left, right) = line.split_once(" - ").context("invalid mountinfo")?;
        let fields: Vec<_> = left.split_whitespace().collect();
        if right.split_whitespace().next() != Some("cgroup2") || fields.len() < 6 {
            continue;
        }
        // Private service paths contain no escaped path bytes. Do not guess a
        // different mount mapping if this namespace exposes a non-root view.
        if fields[3] != "/" || fields[4].contains('\\') {
            continue;
        }
        let mount = PathBuf::from(fields[4]);
        if path.starts_with(&mount) {
            candidates.push((fields[0].parse::<u64>()?, mount));
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(_, p)| p.as_os_str().len())
        .context("no canonical whole-tree cgroup2 mount")
}
fn current_group() -> Result<String> {
    fs::read_to_string("/proc/self/cgroup")?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .context("unified current cgroup membership missing")
}
fn verifier_unit_name(name: &str) -> bool {
    name == "forgeflow-control.service"
        || name
            .strip_prefix("forgeflow-control-")
            .and_then(|name| name.strip_suffix(".service"))
            .is_some_and(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

/// Validate the launcher-discovered delegation of this authority process.
/// Never accepts a Worker's subtree or an arbitrary application slice.
pub fn validate_verifier_delegation(value: &CgroupDelegation) -> Result<()> {
    if !verifier_unit_name(&value.unit_name) {
        bail!("a strict dedicated ForgeFlow control service is required");
    }
    validate_delegation(value)?;
    let available = read(&value.root_path, "cgroup.controllers")?;
    if ["cpu", "memory", "pids"].iter().any(|controller| {
        !available
            .split_whitespace()
            .any(|value| value == *controller)
    }) {
        bail!("required verifier delegated controllers are unavailable");
    }
    Ok(())
}
fn validate_delegation(value: &CgroupDelegation) -> Result<(u64, PathBuf, fs::Metadata)> {
    let worker =
        value.unit_name.starts_with("forgeflow-worker-") && value.unit_name.ends_with(".service");
    if !(worker || verifier_unit_name(&value.unit_name))
        || !value
            .unit_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || value.root_path.file_name().and_then(|v| v.to_str()) != Some(&value.unit_name)
    {
        bail!("a dedicated ForgeFlow delegated service is required");
    }
    let metadata = owned_directory(&value.root_path)?;
    let (mount_id, mount_path) = mount_for(&value.root_path)?;
    let relative = value.root_path.strip_prefix(&mount_path)?;
    let expected = format!(
        "/{}/supervisor",
        relative.to_str().context("cgroup path must be UTF-8")?
    );
    if current_group()? != expected
        || !read(&value.root_path, "cgroup.procs")?.is_empty()
        || read(&value.root_path, "cgroup.type")? != "domain"
    {
        bail!("Worker must be in its dedicated supervisor leaf and delegated root must be empty");
    }
    Ok((mount_id, mount_path, metadata))
}

impl PreparedCgroupFence {
    pub fn prepare(
        request: PhysicalFenceRequest,
        intent: &LaunchIntent,
        journal: &Journal,
    ) -> Result<Self> {
        request.limits.validate()?;
        crate::safe_id(&request.project_id)?;
        if !digest_ok(&request.resource_binding_sha256) || intent.boot_id != boot_id()? {
            bail!("physical reservation digest or boot identity missing");
        }
        if journal.path("cgroup-fence.json").exists() {
            bail!("existing physical fence requires recovery, never relaunch");
        }
        let (mount_id, mount_path, root) = validate_delegation(&request.delegation)?;
        let available = read(&request.delegation.root_path, "cgroup.controllers")?;
        for controller in ["cpu", "memory", "pids"] {
            if !available
                .split_whitespace()
                .any(|value| value == controller)
            {
                bail!("required delegated controller {controller} unavailable");
            }
        }
        write_control(
            &request.delegation.root_path,
            "cgroup.subtree_control",
            "+cpu +memory +pids",
        )?;
        let enabled = read(&request.delegation.root_path, "cgroup.subtree_control")?;
        if ["cpu", "memory", "pids"]
            .iter()
            .any(|c| !enabled.split_whitespace().any(|value| value == *c))
        {
            bail!("delegated controller activation was not confirmed");
        }
        let name = format!(
            "attempt-{}",
            hash(&serde_json::to_vec(&(
                &request.project_id,
                &intent.attempt_id,
                intent.generation,
                &intent.execution_id
            ))?)
        );
        let leaf_path = request.delegation.root_path.join(name);
        fs::create_dir(&leaf_path).context("physical attempt leaf must be exclusively new")?;
        let leaf = owned_directory(&leaf_path)?;
        for (name, value) in request.limits.files() {
            write_control(&leaf_path, name, &value)?;
        }
        let mut identity = CgroupFenceIdentity {
            schema_version: "forgeflow.cgroup-fence.v1".into(),
            project_id: request.project_id,
            attempt_id: intent.attempt_id.clone(),
            generation: intent.generation,
            execution_id: intent.execution_id.clone(),
            boot_id: intent.boot_id.clone(),
            owner_uid: unsafe { libc::geteuid() },
            delegation: request.delegation,
            mount_id,
            mount_path,
            mount_device: root.dev(),
            root_inode: root.ino(),
            leaf_path,
            leaf_inode: leaf.ino(),
            limits: request.limits,
            resource_binding_sha256: request.resource_binding_sha256,
            identity_sha256: String::new(),
        };
        identity.identity_sha256 = identity.digest()?;
        let procs = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(identity.leaf_path.join("cgroup.procs"))?;
        let fence = Self { identity, procs };
        fence.validate_live()?;
        if fence.populated()? {
            bail!("new physical leaf unexpectedly populated");
        }
        journal.record_cgroup_fence(&fence.identity)?;
        Ok(fence)
    }
    pub fn restore(journal: &Journal) -> Result<Option<Self>> {
        let Some(identity) = journal.cgroup_fence()? else {
            return Ok(None);
        };
        let procs = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(identity.leaf_path.join("cgroup.procs"))?;
        let fence = Self { identity, procs };
        fence.validate_live()?;
        Ok(Some(fence))
    }
    pub fn validate_live(&self) -> Result<()> {
        self.identity.validate_record()?;
        let (mount_id, mount_path, root) = validate_delegation(&self.identity.delegation)?;
        let leaf = owned_directory(&self.identity.leaf_path)?;
        if self.identity.boot_id != boot_id()?
            || self.identity.owner_uid != unsafe { libc::geteuid() }
            || mount_id != self.identity.mount_id
            || mount_path != self.identity.mount_path
            || root.dev() != self.identity.mount_device
            || root.ino() != self.identity.root_inode
            || leaf.dev() != self.identity.mount_device
            || leaf.ino() != self.identity.leaf_inode
            || self.identity.leaf_path.parent()
                != Some(self.identity.delegation.root_path.as_path())
        {
            bail!(
                "physical cgroup boot/mount/inode/ownership changed; quarantine without signalling"
            );
        }
        for (name, value) in self.identity.limits.files() {
            if read(&self.identity.leaf_path, name)? != value {
                bail!("physical limit {name} changed; quarantine");
            }
        }
        Ok(())
    }
    pub fn attachment_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }
    pub fn populated(&self) -> Result<bool> {
        let events = read(&self.identity.leaf_path, "cgroup.events")?;
        match events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(false),
            Some("1") => Ok(true),
            _ => bail!("physical populated state unavailable"),
        }
    }
    pub fn kill(&self) -> Result<()> {
        self.validate_live()?;
        write_control(&self.identity.leaf_path, "cgroup.kill", "1")
    }
    pub fn snapshot(&self) -> BTreeMap<String, String> {
        [
            "cpu.stat",
            "memory.current",
            "memory.peak",
            "memory.events",
            "pids.current",
            "pids.events",
            "cgroup.events",
            "cgroup.procs",
        ]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                read(&self.identity.leaf_path, name).unwrap_or_else(|_| "UNAVAILABLE".into()),
            )
        })
        .collect()
    }
    pub fn verify_membership(&self, pid: u32, journal: &Journal) -> Result<()> {
        self.validate_live()?;
        let expected = format!(
            "/{}",
            self.identity
                .leaf_path
                .strip_prefix(&self.identity.mount_path)?
                .to_str()
                .context("invalid cgroup path")?
        );
        let observed = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        if !observed
            .lines()
            .any(|line| line == format!("0::{expected}"))
        {
            bail!("child did not attach to its frozen physical leaf before exec");
        }
        durable_json(
            &journal.path("cgroup-membership.json"),
            &serde_json::json!({"identity_sha256":self.identity.identity_sha256,
            "pid":pid,"observed_at":chrono::Utc::now(),"unified_membership":expected,"snapshot":self.snapshot()}),
        )
    }
    pub fn record_stop(&self, journal: &Journal) -> Result<bool> {
        self.validate_live()?;
        let populated = self.populated()?;
        durable_json(
            &journal.path("cgroup-stop.json"),
            &serde_json::json!({"schema_version":"forgeflow.cgroup-stop.v1",
            "identity_sha256":self.identity.identity_sha256,"boot_id":self.identity.boot_id,"leaf_inode":self.identity.leaf_inode,
            "observed_at":chrono::Utc::now(),"populated":populated,"process_exit_confirmed":!populated,"snapshot":self.snapshot()}),
        )?;
        Ok(!populated)
    }
}

/// Only getpid/write and stack arithmetic run after fork. The preopened FD is
/// CLOEXEC, so the author never inherits permission to move itself or siblings.
pub unsafe fn attach_before_exec(fd: RawFd) -> std::io::Result<()> {
    let mut pid = unsafe { libc::getpid() } as u32;
    let mut bytes = [0_u8; 24];
    let mut at = bytes.len() - 1;
    bytes[at] = b'\n';
    loop {
        at -= 1;
        bytes[at] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    loop {
        let count = unsafe { libc::write(fd, bytes[at..].as_ptr().cast(), bytes.len() - at) };
        if count == (bytes.len() - at) as isize {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if count < 0 && error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(if count < 0 {
            error
        } else {
            std::io::Error::from_raw_os_error(libc::EIO)
        });
    }
}
