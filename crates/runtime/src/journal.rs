use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const LAUNCH_AUTHORITY_SCHEMA: &str = "forgeflow.launch-authority.v2";

/// The create-new launch fence and the complete pre-spawn record are one inode.
/// Environment values and stdin bytes are hashed in memory and never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAuthority {
    pub schema_version: String,
    pub intent: LaunchIntent,
    pub command_sha256: String,
    pub environment_sha256: String,
    pub stdin_sha256: String,
    pub working_directory_sha256: String,
    pub environment_key_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_fence_sha256: Option<String>,
    pub binding_sha256: String,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl LaunchAuthority {
    fn binding(&self) -> Result<String> {
        if let Some(physical) = &self.physical_fence_sha256 {
            return Ok(sha256(&serde_json::to_vec(&(
                &self.schema_version,
                &self.intent,
                &self.command_sha256,
                &self.environment_sha256,
                &self.stdin_sha256,
                &self.working_directory_sha256,
                &self.environment_key_names,
                physical,
            ))?));
        }
        Ok(sha256(&serde_json::to_vec(&(
            &self.schema_version,
            &self.intent,
            &self.command_sha256,
            &self.environment_sha256,
            &self.stdin_sha256,
            &self.working_directory_sha256,
            &self.environment_key_names,
        ))?))
    }

    fn validate(&self) -> Result<()> {
        if !matches!(
            (
                self.schema_version.as_str(),
                self.physical_fence_sha256.is_some()
            ),
            (LAUNCH_AUTHORITY_SCHEMA, false) | ("forgeflow.launch-authority.v3", true)
        ) {
            bail!("unsupported launch authority schema");
        }
        uuid::Uuid::parse_str(&self.intent.execution_id)?;
        if self.intent.execution_id == self.intent.operation_id || self.intent.generation < 1 {
            bail!("invalid launch authority identity");
        }
        for value in [
            &self.command_sha256,
            &self.environment_sha256,
            &self.stdin_sha256,
            &self.working_directory_sha256,
            &self.binding_sha256,
        ] {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("invalid launch authority digest");
            }
        }
        if self.binding_sha256 != self.binding()? {
            bail!("launch authority binding digest mismatch");
        }
        if self
            .physical_fence_sha256
            .as_ref()
            .is_some_and(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("invalid physical launch binding digest");
        }
        Ok(())
    }

    fn from_spec(intent: &LaunchIntent, spec: &crate::ProcessSpec) -> Result<Self> {
        let mut environment = spec.env.clone();
        environment.insert("FORGEFLOW_ATTEMPT_ID".into(), intent.attempt_id.clone());
        environment.insert("FORGEFLOW_OPERATION_ID".into(), intent.operation_id.clone());
        environment.insert("FORGEFLOW_EXECUTION_ID".into(), intent.execution_id.clone());
        let mut authority = Self {
            schema_version: LAUNCH_AUTHORITY_SCHEMA.into(),
            intent: intent.clone(),
            command_sha256: sha256(&serde_json::to_vec(&(&spec.program, &spec.args))?),
            environment_sha256: sha256(&serde_json::to_vec(&environment)?),
            stdin_sha256: sha256(&spec.stdin),
            working_directory_sha256: sha256(&serde_json::to_vec(&spec.cwd)?),
            environment_key_names: spec.env.keys().cloned().collect(),
            physical_fence_sha256: None,
            binding_sha256: String::new(),
        };
        authority.binding_sha256 = authority.binding()?;
        authority.validate()?;
        Ok(authority)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchIntent {
    #[serde(default)]
    pub execution_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub boot_id: String,
    pub workspace: PathBuf,
    pub prompt_sha256: String,
    pub created_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub pgid: i32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub attempt_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchReceipt {
    #[serde(default)]
    pub execution_id: String,
    pub intent: LaunchIntent,
    pub process: ProcessIdentity,
    pub launched_at: String,
    pub command_program: PathBuf,
    pub command_args: Vec<String>,
    pub environment_key_names: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopEvidence {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub reason: String,
    pub process_exit_confirmed: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub notification_overflow: u64,
    pub log_error: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDisposition {
    NeverLaunched,
    Completed,
    RecoveryRequired(String),
}

pub fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}
pub fn safe_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || value == "."
        || value == ".."
    {
        bail!("unsafe identity");
    }
    Ok(())
}
/// Atomic replace plus file and containing-directory fsync. Secrets never enter this journal.
pub fn durable_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("journal has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
#[derive(Debug, Clone)]
pub struct Journal {
    pub directory: PathBuf,
}
impl Journal {
    pub fn cgroup_fence(&self) -> Result<Option<crate::CgroupFenceIdentity>> {
        let bytes = match fs::read(self.path("cgroup-fence.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let identity: crate::CgroupFenceIdentity = serde_json::from_slice(&bytes)?;
        identity.validate_record()?;
        Ok(Some(identity))
    }
    pub fn record_cgroup_fence(&self, identity: &crate::CgroupFenceIdentity) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        identity.validate_record()?;
        fs::create_dir_all(&self.directory)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(self.path("cgroup-fence.json"))?;
        file.write_all(&serde_json::to_vec(identity)?)?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    /// A v2 authority is valid independently of its later compatibility projection.
    /// Empty locks belong to the old protocol. Any nonempty malformed lock is
    /// uncertain authority, never permission to launch again.
    pub fn launch_authority(&self) -> Result<Option<LaunchAuthority>> {
        let bytes = match fs::read(self.path("launch.lock")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if bytes.is_empty() {
            return Ok(None);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .context("partial launch authority remains quarantined")?;
        let authority: LaunchAuthority = serde_json::from_value(value.clone())?;
        authority.validate()?;
        if let Some(expected) = &authority.physical_fence_sha256 {
            let physical = self
                .cgroup_fence()?
                .context("bound physical fence missing; quarantine")?;
            if &physical.identity_sha256 != expected
                || physical.attempt_id != authority.intent.attempt_id
                || physical.generation != authority.intent.generation
                || physical.execution_id != authority.intent.execution_id
                || physical.boot_id != authority.intent.boot_id
            {
                bail!("physical fence differs from durable launch authority");
            }
        } else if self.path("cgroup-fence.json").exists() {
            bail!("physical fence is not bound to the launch authority");
        }
        if serde_json::to_value(&authority)? != value {
            bail!("launch authority has unrecognized fields");
        }
        Ok(Some(authority))
    }

    fn check_execution_identity(&self, execution_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(execution_id).context("execution identity invalid")?;
        // Read the existing binding once. Calling execution_id() here repeated
        // metadata checks and could enter its identity-allocation fallback;
        // authority creation must only compare an existing identity.
        let bytes = match fs::read(self.path("execution-id.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let bound_id = value
            .get("execution_id")
            .and_then(|value| value.as_str())
            .context("execution identity missing")?;
        uuid::Uuid::parse_str(bound_id).context("execution identity invalid")?;
        if bound_id != execution_id {
            bail!("launch execution identity differs from durable record");
        }
        Ok(())
    }

    pub fn execution_id(&self) -> Result<String> {
        let path = self.path("execution-id.json");
        if path.exists() {
            let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
            let id = value
                .get("execution_id")
                .and_then(|v| v.as_str())
                .context("execution identity missing")?;
            uuid::Uuid::parse_str(id).context("execution identity invalid")?;
            return Ok(id.to_owned());
        }
        if let Some(authority) = self.launch_authority()? {
            return Ok(authority.intent.execution_id);
        }
        // Legacy identity records may predate execution-id.json. Preserve their
        // existing identity rather than allocate a second one during recovery.
        for name in ["launch-intent.json", "launch-receipt.json"] {
            if self.path(name).exists() {
                let value: serde_json::Value = serde_json::from_slice(&fs::read(self.path(name))?)?;
                let id = value
                    .get("execution_id")
                    .and_then(|value| value.as_str())
                    .context("legacy execution identity missing; quarantine")?;
                uuid::Uuid::parse_str(id).context("legacy execution identity invalid")?;
                return Ok(id.to_owned());
            }
        }
        if self.path("launch.lock").exists() {
            bail!("legacy launch fence has no bound execution identity; quarantine");
        }
        fs::create_dir_all(&self.directory)?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&serde_json::to_vec(
            &serde_json::json!({"execution_id":id}),
        )?)?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        Ok(id)
    }
    pub fn new(root: &Path, attempt_id: &str) -> Result<Self> {
        safe_id(attempt_id)?;
        Ok(Self {
            directory: root.join(attempt_id),
        })
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }
    pub fn disposition(&self) -> Result<RecoveryDisposition> {
        let authority = match self.launch_authority() {
            Ok(authority) => authority,
            Err(error) => {
                return Ok(RecoveryDisposition::RecoveryRequired(error.to_string()));
            }
        };
        if self.path("launch-intent.json").exists() {
            let intent = match fs::read(self.path("launch-intent.json"))
                .map_err(anyhow::Error::from)
                .and_then(|bytes| {
                    serde_json::from_slice::<LaunchIntent>(&bytes).map_err(Into::into)
                }) {
                Ok(intent) => intent,
                Err(error) => {
                    return Ok(RecoveryDisposition::RecoveryRequired(error.to_string()));
                }
            };
            if intent.execution_id.is_empty() || intent.execution_id == intent.operation_id {
                return Ok(RecoveryDisposition::RecoveryRequired(
                    "execution identity unbound or aliases operation".into(),
                ));
            }
            if let Some(authority) = &authority {
                if serde_json::to_value(&intent)? != serde_json::to_value(&authority.intent)? {
                    return Ok(RecoveryDisposition::RecoveryRequired(
                        "compatibility intent differs from launch authority".into(),
                    ));
                }
            }
        }
        if self.path("launch-receipt.json").exists() {
            if let Err(error) = self.receipt() {
                return Ok(RecoveryDisposition::RecoveryRequired(error.to_string()));
            }
        }
        if self.path("stop.json").exists() {
            let stop: StopEvidence = serde_json::from_slice(&fs::read(self.path("stop.json"))?)?;
            if self.path("cgroup-fence.json").exists() {
                let physical = (|| -> Result<()> {
                    let identity = self.cgroup_fence()?.context("physical fence missing")?;
                    let recorded: serde_json::Value =
                        serde_json::from_slice(&fs::read(self.path("cgroup-stop.json"))?)?;
                    if identity.boot_id != boot_id()?
                        || recorded["schema_version"] != "forgeflow.cgroup-stop.v1"
                        || recorded["identity_sha256"] != identity.identity_sha256
                        || recorded["boot_id"] != identity.boot_id
                        || recorded["leaf_inode"] != identity.leaf_inode
                        || recorded["populated"] != false
                        || recorded["process_exit_confirmed"] != true
                    {
                        bail!("physical stop proof missing or changed");
                    }
                    match fs::symlink_metadata(&identity.leaf_path) {
                        Err(error)
                            if error.kind() == std::io::ErrorKind::NotFound
                                && stop.process_exit_confirmed =>
                        {
                            // systemd may remove a closed private unit after the
                            // authentic same-boot empty-tree stop was persisted.
                            // Only this positive closure permits absent-path
                            // inspection; live/missing proof and replaced paths
                            // still remain quarantined.
                            return Ok(());
                        }
                        Err(error) => return Err(error.into()),
                        Ok(_) => {}
                    }
                    crate::PreparedCgroupFence::restore(self).and_then(|value| {
                        value.context("physical fence missing").and_then(|fence| {
                            if fence.populated()? {
                                bail!("physical descendants remain populated");
                            }
                            Ok(())
                        })
                    })
                })();
                if let Err(error) = physical {
                    return Ok(RecoveryDisposition::RecoveryRequired(error.to_string()));
                }
            }
            return Ok(if stop.process_exit_confirmed {
                RecoveryDisposition::Completed
            } else {
                RecoveryDisposition::RecoveryRequired("stop is unconfirmed".into())
            });
        }
        if self.path("launch-intent.json").exists()
            || self.path("launch.lock").exists()
            || self.path("launch-receipt.json").exists()
            || self.path("cgroup-fence.json").exists()
        {
            return Ok(RecoveryDisposition::RecoveryRequired(
                "launch intent exists: receipt absence cannot prove no launch".into(),
            ));
        }
        Ok(RecoveryDisposition::NeverLaunched)
    }
    /// Create-new lock holds exclusive local launch authority until process settlement.
    /// A crash leaves the lock behind deliberately: restart must reconcile, never unlink blindly.
    pub fn record_intent(&self, intent: &LaunchIntent) -> Result<()> {
        if self.path("launch-intent.json").exists()
            || self.path("launch-receipt.json").exists()
            || self.path("stop.json").exists()
        {
            bail!("prior launch evidence exists; reconciliation required");
        }
        fs::create_dir_all(&self.directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        }
        self.check_execution_identity(&intent.execution_id)?;
        // This retained compatibility entrypoint records intent without a process
        // binding. The actual supervisor always uses record_bound_intent instead.
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path("launch.lock"))?;
        lock.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        durable_json(&self.path("launch-intent.json"), intent)
    }

    /// One create-new file is both the fence and complete bound pre-spawn intent.
    /// The historical lock pathname makes old and new supervisors contend for
    /// the same fence. Do not unlink on error: partial persistence is UNKNOWN.
    pub fn record_bound_intent(
        &self,
        intent: &LaunchIntent,
        spec: &crate::ProcessSpec,
    ) -> Result<()> {
        let authority = LaunchAuthority::from_spec(intent, spec)?;
        self.record_bound_authority(intent, authority)
    }
    pub fn record_bound_intent_physical(
        &self,
        intent: &LaunchIntent,
        spec: &crate::ProcessSpec,
        physical: &crate::CgroupFenceIdentity,
    ) -> Result<()> {
        physical.validate_record()?;
        let mut authority = LaunchAuthority::from_spec(intent, spec)?;
        authority.schema_version = "forgeflow.launch-authority.v3".into();
        authority.physical_fence_sha256 = Some(physical.identity_sha256.clone());
        authority.binding_sha256 = authority.binding()?;
        authority.validate()?;
        self.record_bound_authority(intent, authority)
    }
    fn record_bound_authority(
        &self,
        intent: &LaunchIntent,
        authority: LaunchAuthority,
    ) -> Result<()> {
        self.check_execution_identity(&intent.execution_id)?;
        if self.path("launch-intent.json").exists()
            || self.path("launch-receipt.json").exists()
            || self.path("stop.json").exists()
        {
            bail!("prior launch evidence exists; reconciliation required");
        }
        let mut newly_created_parents = Vec::new();
        let mut directory = self.directory.as_path();
        while !directory.exists() {
            let parent = directory
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            newly_created_parents.push(parent.to_path_buf());
            directory = parent;
        }
        fs::create_dir_all(&self.directory)?;
        let bytes = serde_json::to_vec(&authority)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        }
        let mut file = options.open(self.path("launch.lock"))?;
        file.write_all(&bytes)?;
        // This is a derived cache, not an independent authority. Publishing its
        // bytes before the single directory fsync avoids a second durability
        // barrier on every launch. Missing/torn cache bytes can be reconstructed
        // from the checksummed authority; a conflicting valid cache is refused.
        let mut cache_options = OpenOptions::new();
        cache_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            cache_options.mode(0o600);
        }
        let mut cache = cache_options.open(self.path("launch-intent.json"))?;
        cache.write_all(&serde_json::to_vec(intent)?)?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        // Workers normally create and durably populate the attempt directory
        // during preparation. Standalone supervision also persists a new parent
        // directory entry before it may spawn.
        for parent in newly_created_parents {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn ensure_intent_cache(&self, authority: &LaunchAuthority) -> Result<()> {
        let expected = serde_json::to_value(&authority.intent)?;
        let actual = match fs::read(self.path("launch-intent.json")) {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).ok(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        match actual {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => bail!("existing compatibility intent differs from launch authority"),
            None => durable_json(&self.path("launch-intent.json"), &expected),
        }
    }

    pub fn record_receipt(&self, receipt: &LaunchReceipt) -> Result<()> {
        if let Some(authority) = self.launch_authority()? {
            self.validate_receipt(&receipt, &authority)?;
            self.ensure_intent_cache(&authority)?;
        }
        if self.path("launch-receipt.json").exists() {
            let existing: serde_json::Value =
                serde_json::from_slice(&fs::read(self.path("launch-receipt.json"))?)?;
            if existing != serde_json::to_value(receipt)? {
                bail!("launch receipt is immutable; conflicting receipt quarantined");
            }
            return Ok(());
        }
        durable_json(&self.path("launch-receipt.json"), receipt)
    }
    pub fn record_stop(&self, stop: &StopEvidence) -> Result<()> {
        durable_json(&self.path("stop.json"), stop)
    }
    pub fn receipt(&self) -> Result<LaunchReceipt> {
        let receipt: LaunchReceipt =
            serde_json::from_slice(&fs::read(self.path("launch-receipt.json"))?)?;
        uuid::Uuid::parse_str(&receipt.execution_id)
            .context("receipt execution identity invalid")?;
        if receipt.execution_id != receipt.intent.execution_id
            || receipt.execution_id == receipt.intent.operation_id
            || receipt.process.attempt_id != receipt.intent.attempt_id
            || receipt.process.boot_id != receipt.intent.boot_id
        {
            bail!("legacy or inconsistent receipt identity; quarantine");
        }
        if let Some(authority) = self.launch_authority()? {
            self.validate_receipt(&receipt, &authority)?;
            self.ensure_intent_cache(&authority)?;
        }
        Ok(receipt)
    }

    fn validate_receipt(&self, receipt: &LaunchReceipt, authority: &LaunchAuthority) -> Result<()> {
        if receipt.execution_id != authority.intent.execution_id
            || serde_json::to_value(&receipt.intent)? != serde_json::to_value(&authority.intent)?
            || receipt.process.attempt_id != authority.intent.attempt_id
            || receipt.process.boot_id != authority.intent.boot_id
            || receipt.environment_key_names != authority.environment_key_names
            || sha256(&serde_json::to_vec(&(
                &receipt.command_program,
                &receipt.command_args,
            ))?) != authority.command_sha256
        {
            bail!("launch receipt differs from complete bound launch authority");
        }
        Ok(())
    }
}
