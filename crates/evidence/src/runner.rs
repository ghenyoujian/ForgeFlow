use crate::{
    ArtifactBinding, ArtifactVerificationReceipt, EvidenceBinding, EvidenceError,
    VerificationReceipt, sha256,
};
use forgeflow_runtime::{
    Journal, LaunchIntent, PhysicalFenceRequest, ProcessSpec, SupervisionLimits, boot_id,
    durable_json, supervise, supervise_physical,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio::sync::{mpsc, watch};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRole {
    Author,
    Consumer,
    Independent,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    Positive,
    Negative,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Passed,
    Failed,
    Skipped,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCase {
    pub name: String,
    pub kind: CaseKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundInput {
    pub path: PathBuf,
    pub sha256: String,
}

/// Server-classified read-only business data, not an oracle or author permission.
/// This accompanies execution and never changes the admitted VerificationPlan.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectInputResolution {
    pub original_path: PathBuf,
    pub logical_path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub execution_source: PathBuf,
    pub context_artifact_id: String,
    pub context_sha256: String,
    pub classification_recipe_sha256: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct SubjectFileIdentity {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Clone, Debug, Serialize)]
struct SubjectInputSnapshot {
    resolution: SubjectInputResolution,
    original_identity: SubjectFileIdentity,
    execution_identity: SubjectFileIdentity,
}

type SubjectResolver<'a> = dyn Fn(&CommandSpec, &Path) -> Result<Vec<SubjectInputResolution>, EvidenceError>
    + Send
    + Sync
    + 'a;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub role: VerificationRole,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub executable_hash: String,
    pub bound_inputs: Vec<BoundInput>,
    pub report_path: String,
    pub expected_cases: Vec<ExpectedCase>,
    pub timeout_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationPlan {
    pub plan_id: String,
    pub task_revision: u64,
    pub contract_version: String,
    pub input_hash: String,
    pub environment_profile: String,
    pub oracle_id: String,
    pub verifier_id: String,
    pub author_id: String,
    pub commands: Vec<CommandSpec>,
}
impl VerificationPlan {
    pub fn digest(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("serializable registered verification plan"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhysicalVerificationCommand {
    pub index: usize,
    pub role: VerificationRole,
    pub execution_id: String,
    pub process_attempt_id: String,
}

/// The authority registers this exact manifest before the runner may borrow
/// the already-held pool. Synthetic process markers isolate verifier recovery
/// from the original author; parent identity remains explicit in this mapping.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalVerificationContext {
    pub schema_version: String,
    pub parent_attempt_id: String,
    pub generation: i64,
    pub operation_id: String,
    pub verifier_root: PathBuf,
    pub registration_id: String,
    pub verification_plan_id: String,
    pub verification_plan_hash: String,
    pub physical_request: PhysicalFenceRequest,
    pub commands: Vec<PhysicalVerificationCommand>,
}
impl PhysicalVerificationContext {
    pub fn new(
        parent_attempt_id: &str,
        generation: i64,
        operation_id: &str,
        artifact_root: &Path,
        registration_id: &str,
        plan: &VerificationPlan,
        physical_request: PhysicalFenceRequest,
    ) -> Result<Self, EvidenceError> {
        let context = Self {
            schema_version: "forgeflow.physical-verification.v1".into(),
            parent_attempt_id: parent_attempt_id.into(),
            generation,
            operation_id: operation_id.into(),
            verifier_root: fs::canonicalize(artifact_root).map_err(invalid)?,
            registration_id: registration_id.into(),
            verification_plan_id: plan.plan_id.clone(),
            verification_plan_hash: plan.digest(),
            physical_request,
            commands: plan
                .commands
                .iter()
                .enumerate()
                .map(|(index, command)| PhysicalVerificationCommand {
                    index,
                    role: command.role,
                    execution_id: uuid::Uuid::new_v4().to_string(),
                    process_attempt_id: format!("verify-{}-{index}", uuid::Uuid::new_v4()),
                })
                .collect(),
        };
        context.validate(plan, artifact_root, parent_attempt_id, generation)?;
        Ok(context)
    }

    pub fn validate(
        &self,
        plan: &VerificationPlan,
        artifact_root: &Path,
        parent_attempt_id: &str,
        generation: i64,
    ) -> Result<(), EvidenceError> {
        self.validate_identity()?;
        if self.parent_attempt_id != parent_attempt_id
            || self.generation != generation
            || self.verifier_root != fs::canonicalize(artifact_root).map_err(invalid)?
            || self.verification_plan_id != plan.plan_id
            || self.verification_plan_hash != plan.digest()
            || self.commands.len() != plan.commands.len()
            || self
                .commands
                .iter()
                .zip(&plan.commands)
                .any(|(identity, command)| identity.role != command.role)
        {
            return Err(EvidenceError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), EvidenceError> {
        for id in [
            &self.parent_attempt_id,
            &self.operation_id,
            &self.registration_id,
            &self.physical_request.project_id,
        ] {
            forgeflow_runtime::safe_id(id).map_err(invalid)?;
        }
        self.physical_request.limits.validate().map_err(invalid)?;
        let digest = &self.physical_request.resource_binding_sha256;
        if self.schema_version != "forgeflow.physical-verification.v1"
            || self.generation <= 0
            || !self.verifier_root.is_absolute()
            || self.verification_plan_id.is_empty()
            || self.verification_plan_hash.len() != 64
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.commands.is_empty()
            || self.commands.len() > 32
        {
            return Err(invalid("invalid physical verification context"));
        }
        let mut executions = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        for (index, command) in self.commands.iter().enumerate() {
            uuid::Uuid::parse_str(&command.execution_id).map_err(invalid)?;
            forgeflow_runtime::safe_id(&command.process_attempt_id).map_err(invalid)?;
            if command.index != index
                || command.execution_id == self.operation_id
                || !command.process_attempt_id.starts_with("verify-")
                || command.process_attempt_id == self.parent_attempt_id
                || !executions.insert(&command.execution_id)
                || !attempts.insert(&command.process_attempt_id)
            {
                return Err(invalid(
                    "physical verifier command identities differ or alias",
                ));
            }
        }
        Ok(())
    }
}

fn persist_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), EvidenceError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let parent = path
        .parent()
        .ok_or_else(|| invalid("journal parent missing"))?;
    fs::create_dir_all(parent).map_err(invalid)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(invalid)?;
    file.write_all(&serde_json::to_vec(value).map_err(invalid)?)
        .map_err(invalid)?;
    file.sync_all().map_err(invalid)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(invalid)?;
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    pub name: String,
    pub kind: CaseKind,
    pub outcome: CaseOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredReport {
    pub binding: EvidenceBinding,
    pub oracle_id: String,
    pub cases: Vec<CaseResult>,
}
fn invalid(e: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Invalid(e.to_string())
}
fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn report_location(root: &Path, relative: &str) -> Result<PathBuf, EvidenceError> {
    if !safe_relative(relative) {
        return Err(invalid("unsafe report path"));
    }
    let path = Path::new(relative);
    let mut parent = root.to_path_buf();
    if let Some(components) = path.parent() {
        for component in components.components() {
            parent.push(component.as_os_str());
            match fs::symlink_metadata(&parent) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(invalid("report parent contains symlink or non-directory"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&parent).map_err(invalid)?
                }
                Err(error) => return Err(invalid(error)),
            }
        }
    }
    let target = root.join(path);
    match fs::symlink_metadata(&target) {
        Ok(_) => return Err(invalid("preexisting report cannot prove this execution")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(invalid(error)),
    }
    Ok(target)
}
fn subject_file(
    path: &Path,
    expected_bytes: u64,
    expected_hash: &str,
    immutable: bool,
) -> Result<SubjectFileIdentity, EvidenceError> {
    use std::{
        io::Read,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(invalid)? != path
        || expected_bytes > 64 * 1024 * 1024
    {
        return Err(invalid("subject file path or byte bound is invalid"));
    }
    // Hold directory descriptors and reject every link, including ancestors.
    // The /proc/self/fd links are our own opened directories, never caller paths.
    let mut directory = fs::File::open("/").map_err(invalid)?;
    let components: Vec<_> = path.components().skip(1).collect();
    let mut opened = None;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(invalid("subject path is not normalized"));
        };
        let next = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        let last = index + 1 == components.len();
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o400000 | if last { 0o4000 } else { 0o200000 })
            .open(next)
            .map_err(invalid)?;
        if last {
            opened = Some(file);
            break;
        }
        directory = file;
    }
    let mut file = opened.ok_or_else(|| invalid("subject leaf missing"))?;
    let identity = |metadata: &fs::Metadata| SubjectFileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        bytes: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    };
    let before = file.metadata().map_err(invalid)?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() != expected_bytes
        || immutable && before.mode() & 0o222 != 0
    {
        return Err(invalid(
            "subject file is not an exact immutable regular input",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(expected_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    let after = file.metadata().map_err(invalid)?;
    if identity(&before) != identity(&after)
        || bytes.len() as u64 != expected_bytes
        || sha256(&bytes) != expected_hash
    {
        return Err(invalid("subject bytes or descriptor identity changed"));
    }
    Ok(identity(&after))
}

fn capture_subject_inputs(
    command: &CommandSpec,
    cwd: &Path,
    resolutions: Vec<SubjectInputResolution>,
) -> Result<Vec<SubjectInputSnapshot>, EvidenceError> {
    let digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut originals = BTreeSet::new();
    let mut copies = BTreeSet::new();
    let mut captured = Vec::new();
    for resolution in resolutions {
        let logical = resolution
            .logical_path
            .to_str()
            .ok_or_else(|| invalid("subject logical path must be UTF-8"))?;
        if !safe_relative(logical)
            || resolution.original_path != cwd.join(&resolution.logical_path)
            || !resolution.original_path.starts_with(cwd)
            || resolution.execution_source.starts_with(cwd)
            || !digest(&resolution.sha256)
            || !digest(&resolution.context_sha256)
            || !digest(&resolution.classification_recipe_sha256)
            || resolution.context_artifact_id.is_empty()
            || resolution.context_artifact_id.len() > 256
            || !originals.insert(resolution.original_path.clone())
            || !copies.insert(resolution.execution_source.clone())
        {
            return Err(invalid(
                "subject mapping is unsafe, duplicated or lacks trusted provenance",
            ));
        }
        let bound = command.bound_inputs.iter().any(|input| {
            let path = if input.path.is_absolute() {
                input.path.clone()
            } else {
                cwd.join(&input.path)
            };
            path == resolution.original_path && input.sha256 == resolution.sha256
        });
        if !bound {
            return Err(invalid(
                "subject projection does not match an admitted bound input",
            ));
        }
        let original_identity = subject_file(
            &resolution.original_path,
            resolution.bytes,
            &resolution.sha256,
            false,
        )?;
        let execution_identity = subject_file(
            &resolution.execution_source,
            resolution.bytes,
            &resolution.sha256,
            true,
        )?;
        captured.push(SubjectInputSnapshot {
            resolution,
            original_identity,
            execution_identity,
        });
    }
    Ok(captured)
}

fn verify_subject_inputs(inputs: &[SubjectInputSnapshot]) -> Result<(), EvidenceError> {
    for input in inputs {
        let r = &input.resolution;
        if subject_file(&r.original_path, r.bytes, &r.sha256, false)? != input.original_identity
            || subject_file(&r.execution_source, r.bytes, &r.sha256, true)?
                != input.execution_identity
        {
            return Err(invalid(
                "subject projection identity changed after trusted resolution",
            ));
        }
    }
    Ok(())
}

fn verify_subject_mounts(
    spec: &ProcessSpec,
    inputs: &[SubjectInputSnapshot],
) -> Result<(), EvidenceError> {
    if inputs.is_empty() {
        return Ok(());
    }
    let end = spec
        .args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| {
            invalid("projected subjects require an explicit guarded command delimiter")
        })?;
    let args = &spec.args[..end];
    for input in inputs {
        let r = &input.resolution;
        let source = r
            .execution_source
            .to_str()
            .ok_or_else(|| invalid("subject source must be UTF-8"))?;
        let target = r
            .original_path
            .to_str()
            .ok_or_else(|| invalid("subject target must be UTF-8"))?;
        let matches: Vec<_> = args
            .windows(3)
            .enumerate()
            .filter_map(|(index, part)| {
                (part[0] == "--ro-bind" && part[1] == source && part[2] == target).then_some(index)
            })
            .collect();
        if matches.len() != 1 {
            return Err(invalid(
                "subject needs exactly one immutable read-only execution mount",
            ));
        }
        let mounted = matches[0];
        for (index, arg) in args.iter().enumerate().skip(mounted + 3) {
            let target_index = match arg.as_str() {
                "--ro-bind" | "--bind" | "--ro-bind-try" | "--bind-try" | "--dev-bind"
                | "--dev-bind-try" | "--symlink" => Some(index + 2),
                "--tmpfs" | "--dir" | "--dev" | "--proc" | "--ro-bind-data" | "--bind-data" => {
                    Some(index + if arg.ends_with("-data") { 2 } else { 1 })
                }
                _ => None,
            };
            if target_index
                .and_then(|index| args.get(index))
                .is_some_and(|target| r.original_path.starts_with(Path::new(target)))
            {
                return Err(invalid(
                    "a later guarded mount hides the immutable subject projection",
                ));
            }
        }
    }
    Ok(())
}

fn runtime_handoff_files(root: &Path) -> Result<BTreeSet<PathBuf>, EvidenceError> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(invalid)? {
        let entry = entry.map_err(invalid)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name
            .strip_prefix("verifier-runtime-handoff-")
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_ok() {
            paths.insert(entry.path());
        }
    }
    Ok(paths)
}

fn verify_inputs(
    command: &CommandSpec,
    cwd: &Path,
    subjects: &[SubjectInputSnapshot],
) -> Result<(), EvidenceError> {
    if !command.program.is_absolute() {
        return Err(invalid("registered program must be absolute"));
    }
    let program = fs::canonicalize(&command.program).map_err(invalid)?;
    if sha256(&fs::read(&program).map_err(invalid)?) != command.executable_hash {
        return Err(invalid("registered executable digest mismatch"));
    }
    if command.role == VerificationRole::Independent && program.starts_with(cwd) {
        return Err(invalid(
            "independent verifier program is inside candidate write tree",
        ));
    }
    if ["sh", "bash", "dash", "zsh"]
        .contains(&program.file_name().and_then(|v| v.to_str()).unwrap_or(""))
        && command.args.iter().any(|v| v == "-c")
    {
        return Err(invalid(
            "register a versioned script; shell command strings are not supported",
        ));
    }
    for input in &command.bound_inputs {
        let path = if input.path.is_absolute() {
            input.path.clone()
        } else {
            cwd.join(&input.path)
        };
        let path = fs::canonicalize(path).map_err(invalid)?;
        if command.role == VerificationRole::Independent && path.starts_with(cwd) {
            if !subjects.iter().any(|subject| {
                subject.resolution.original_path == path
                    && subject.resolution.sha256 == input.sha256
            }) {
                return Err(invalid(
                    "independent verifier input is inside candidate write tree",
                ));
            }
        }
        if sha256(&fs::read(path).map_err(invalid)?) != input.sha256 {
            return Err(invalid("registered verifier input digest mismatch"));
        }
    }
    verify_subject_inputs(subjects)?;
    Ok(())
}

/// Execute a server-registered plan; never accept an executor's supplied PASS receipt.
/// Each command writes a StructuredReport to FORGEFLOW_REPORT_PATH. The plan fixes
/// exact case names/kinds; raw process logs and stop evidence are retained on errors.
pub async fn execute_verification(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &EvidenceBinding,
    artifact_root: &Path,
) -> Result<VerificationReceipt, EvidenceError> {
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    execute_verification_with_cancel(plan, cwd, binding, artifact_root, cancel_rx).await
}
pub async fn execute_verification_with_cancel(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &EvidenceBinding,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
) -> Result<VerificationReceipt, EvidenceError> {
    execute_verification_with_guard(plan, cwd, binding, artifact_root, cancellation, |spec| {
        Ok(spec)
    })
    .await
}
pub async fn execute_verification_with_guard<F>(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &EvidenceBinding,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: F,
) -> Result<VerificationReceipt, EvidenceError>
where
    F: Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync,
{
    execute_verification_with_guard_and_physical(
        plan,
        cwd,
        binding,
        artifact_root,
        cancellation,
        guard,
        None,
    )
    .await
}

pub async fn execute_verification_with_guard_and_physical<F>(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &EvidenceBinding,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: F,
    physical: Option<&PhysicalVerificationContext>,
) -> Result<VerificationReceipt, EvidenceError>
where
    F: Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync,
{
    execute_verification_with_guard_and_physical_and_subjects(
        plan,
        cwd,
        binding,
        artifact_root,
        cancellation,
        guard,
        physical,
        |_: &CommandSpec, _: &Path| Ok(Vec::new()),
    )
    .await
}

/// Only a trusted server classifier may resolve immutable business subjects.
/// Ordinary callers retain the original independent-oracle input prohibition.
pub async fn execute_verification_with_guard_and_physical_and_subjects<F, R>(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &EvidenceBinding,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: F,
    physical: Option<&PhysicalVerificationContext>,
    subject_resolver: R,
) -> Result<VerificationReceipt, EvidenceError>
where
    F: Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync,
    R: Fn(&CommandSpec, &Path) -> Result<Vec<SubjectInputResolution>, EvidenceError> + Send + Sync,
{
    let facts = BindingFacts {
        attempt_id: binding.attempt_id.clone(),
        task_revision: binding.task_revision,
        generation: binding.generation,
        verification_plan_id: binding.verification_plan_id.clone(),
        verification_plan_hash: binding.verification_plan_hash.clone(),
        contract_version: binding.contract_version.clone(),
        input_hash: binding.input_hash.clone(),
        source_hash: binding.source_hash.clone(),
        artifact_path: None,
    };
    let value = execute_plan(
        plan,
        cwd,
        &serde_json::to_value(binding).map_err(invalid)?,
        &facts,
        artifact_root,
        cancellation,
        &guard,
        physical,
        &subject_resolver,
    )
    .await?;
    let receipt: VerificationReceipt = serde_json::from_value(value).map_err(invalid)?;
    receipt.validate(binding, true)?;
    receipt.validate_log(artifact_root)?;
    Ok(receipt)
}
pub async fn execute_artifact_verification(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &ArtifactBinding,
    artifact_path: &Path,
    artifact_root: &Path,
) -> Result<ArtifactVerificationReceipt, EvidenceError> {
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    execute_artifact_verification_with_cancel(
        plan,
        cwd,
        binding,
        artifact_path,
        artifact_root,
        cancel_rx,
    )
    .await
}
pub async fn execute_artifact_verification_with_cancel(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &ArtifactBinding,
    artifact_path: &Path,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
) -> Result<ArtifactVerificationReceipt, EvidenceError> {
    execute_artifact_verification_with_guard(
        plan,
        cwd,
        binding,
        artifact_path,
        artifact_root,
        cancellation,
        |spec| Ok(spec),
    )
    .await
}
pub async fn execute_artifact_verification_with_guard<F>(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &ArtifactBinding,
    artifact_path: &Path,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: F,
) -> Result<ArtifactVerificationReceipt, EvidenceError>
where
    F: Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync,
{
    execute_artifact_verification_with_guard_and_physical(
        plan,
        cwd,
        binding,
        artifact_path,
        artifact_root,
        cancellation,
        guard,
        None,
    )
    .await
}

pub async fn execute_artifact_verification_with_guard_and_physical<F>(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &ArtifactBinding,
    artifact_path: &Path,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: F,
    physical: Option<&PhysicalVerificationContext>,
) -> Result<ArtifactVerificationReceipt, EvidenceError>
where
    F: Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync,
{
    execute_artifact_verification_with_guard_and_physical_and_subjects(
        plan,
        cwd,
        binding,
        artifact_path,
        artifact_root,
        cancellation,
        guard,
        physical,
        |_: &CommandSpec, _: &Path| Ok(Vec::new()),
    )
    .await
}

pub async fn execute_artifact_verification_with_guard_and_physical_and_subjects<F, R>(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &ArtifactBinding,
    artifact_path: &Path,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: F,
    physical: Option<&PhysicalVerificationContext>,
    subject_resolver: R,
) -> Result<ArtifactVerificationReceipt, EvidenceError>
where
    F: Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync,
    R: Fn(&CommandSpec, &Path) -> Result<Vec<SubjectInputResolution>, EvidenceError> + Send + Sync,
{
    let artifact_path = fs::canonicalize(artifact_path).map_err(invalid)?;
    let bytes = fs::read(&artifact_path).map_err(invalid)?;
    if bytes.is_empty() || sha256(&bytes) != binding.artifact_hash {
        return Err(EvidenceError::BindingMismatch);
    }
    let facts = BindingFacts {
        attempt_id: binding.attempt_id.clone(),
        task_revision: binding.task_revision,
        generation: binding.generation,
        verification_plan_id: binding.verification_plan_id.clone(),
        verification_plan_hash: binding.verification_plan_hash.clone(),
        contract_version: binding.contract_version.clone(),
        input_hash: binding.input_hash.clone(),
        source_hash: binding.artifact_hash.clone(),
        artifact_path: Some(artifact_path.clone()),
    };
    let value = execute_plan(
        plan,
        cwd,
        &serde_json::to_value(binding).map_err(invalid)?,
        &facts,
        artifact_root,
        cancellation,
        &guard,
        physical,
        &subject_resolver,
    )
    .await?;
    let receipt: ArtifactVerificationReceipt = serde_json::from_value(value).map_err(invalid)?;
    receipt.validate(binding, true)?;
    receipt.validate_log(artifact_root)?;
    receipt.validate_artifact(&artifact_path)?;
    Ok(receipt)
}
struct BindingFacts {
    attempt_id: String,
    task_revision: u64,
    generation: i64,
    verification_plan_id: String,
    verification_plan_hash: String,
    contract_version: String,
    input_hash: String,
    source_hash: String,
    artifact_path: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReport {
    binding: serde_json::Value,
    oracle_id: String,
    cases: Vec<CaseResult>,
}
async fn execute_plan(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &serde_json::Value,
    facts: &BindingFacts,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: &(dyn Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync),
    physical: Option<&PhysicalVerificationContext>,
    subject_resolver: &SubjectResolver<'_>,
) -> Result<serde_json::Value, EvidenceError> {
    if let Some(context) = physical {
        context.validate(plan, artifact_root, &facts.attempt_id, facts.generation)?;
        persist_new_json(
            &context
                .verifier_root
                .join("verification-physical-context.json"),
            context,
        )?;
    }
    let execution = execute_plan_inner(
        plan,
        cwd,
        binding,
        facts,
        artifact_root,
        cancellation,
        guard,
        physical,
        subject_resolver,
    )
    .await;
    if let Some(context) = physical {
        // Returning from the awaited sequencer closes future launch rights.
        // A panic/drop before this durable record deliberately remains UNKNOWN.
        seal_physical_execution(context)?;
    }
    execution
}

fn never_started(journal: &Journal) -> Result<bool, EvidenceError> {
    if [
        "launch.lock",
        "launch-intent.json",
        "launch-receipt.json",
        "cgroup-fence.json",
        "cgroup-membership.json",
        "cgroup-stop.json",
        "stdout.ndjson",
        "stderr.log",
    ]
    .iter()
    .any(|name| journal.path(name).exists())
    {
        return Ok(false);
    }
    match journal.disposition().map_err(invalid)? {
        forgeflow_runtime::RecoveryDisposition::NeverLaunched => Ok(true),
        forgeflow_runtime::RecoveryDisposition::Completed => {
            let stop: forgeflow_runtime::StopEvidence = read_json(&journal.path("stop.json"))?;
            Ok(stop.process_exit_confirmed && stop.reason == "cancelled_before_launch")
        }
        forgeflow_runtime::RecoveryDisposition::RecoveryRequired(_) => Ok(false),
    }
}

fn seal_physical_execution(context: &PhysicalVerificationContext) -> Result<(), EvidenceError> {
    let mut unused = Vec::new();
    for command in &context.commands {
        let journal = Journal::new(
            &context.verifier_root.join("verification-runs"),
            &command.process_attempt_id,
        )
        .map_err(invalid)?;
        if never_started(&journal)? {
            confirm_absent_command_leaf(context, command)?;
            unused.push(command.execution_id.clone());
        }
    }
    persist_new_json(
        &context
            .verifier_root
            .join("verification-physical-closed.json"),
        &serde_json::json!({"context":context,"runner_closed":true,"unused_execution_ids":unused}),
    )
}

fn confirm_absent_command_leaf(
    context: &PhysicalVerificationContext,
    command: &PhysicalVerificationCommand,
) -> Result<(), EvidenceError> {
    // Runtime prepares this deterministic private leaf before persisting its
    // fence. Absence of a journal must never hide that pre-intent crash window.
    let identity = (
        &context.physical_request.project_id,
        &command.process_attempt_id,
        context.generation,
        &command.execution_id,
    );
    let name = format!(
        "attempt-{}",
        sha256(&serde_json::to_vec(&identity).map_err(invalid)?)
    );
    let path = context.physical_request.delegation.root_path.join(name);
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(invalid(error)),
        Ok(_) => Err(invalid(
            "unused command has an unbound physical leaf; quarantine",
        )),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, EvidenceError> {
    serde_json::from_slice(&fs::read(path).map_err(invalid)?).map_err(invalid)
}

async fn execute_plan_inner(
    plan: &VerificationPlan,
    cwd: &Path,
    binding: &serde_json::Value,
    facts: &BindingFacts,
    artifact_root: &Path,
    cancellation: watch::Receiver<bool>,
    guard: &(dyn Fn(ProcessSpec) -> Result<ProcessSpec, EvidenceError> + Send + Sync),
    physical: Option<&PhysicalVerificationContext>,
    subject_resolver: &SubjectResolver<'_>,
) -> Result<serde_json::Value, EvidenceError> {
    if facts.verification_plan_id != plan.plan_id
        || facts.verification_plan_hash != plan.digest()
        || facts.task_revision != plan.task_revision
        || facts.contract_version != plan.contract_version
        || facts.input_hash != plan.input_hash
    {
        return Err(EvidenceError::BindingMismatch);
    }
    if plan.plan_id.trim().is_empty()
        || plan.oracle_id.trim().is_empty()
        || plan.author_id == plan.verifier_id
    {
        return Err(invalid("missing registered plan or independent identity"));
    }
    let roles: BTreeSet<_> = plan.commands.iter().map(|c| c.role).collect();
    if plan.commands.len() > 32 {
        return Err(invalid("verification command budget exceeded"));
    }
    if ![
        VerificationRole::Author,
        VerificationRole::Consumer,
        VerificationRole::Independent,
    ]
    .iter()
    .all(|r| roles.contains(r))
    {
        return Err(invalid(
            "author, consumer and independent commands are all required",
        ));
    }
    let cwd = fs::canonicalize(cwd).map_err(invalid)?;
    fs::create_dir_all(artifact_root).map_err(invalid)?;
    let root = fs::canonicalize(artifact_root).map_err(invalid)?;
    if let Some(context) = physical {
        context.validate(plan, &root, &facts.attempt_id, facts.generation)?;
        forgeflow_runtime::validate_verifier_delegation(&context.physical_request.delegation)
            .map_err(invalid)?;
    }
    let mut report_paths = BTreeSet::new();
    let mut command_roles = Vec::with_capacity(plan.commands.len());
    let mut command_subjects = Vec::with_capacity(plan.commands.len());
    for command in &plan.commands {
        // This reserved environment value comes from the registered role, not from
        // verifier configuration. Reject every conflict before launching any role.
        let role = serde_json::to_value(command.role).map_err(invalid)?;
        let role = role
            .as_str()
            .ok_or_else(|| invalid("registered verification role must be a string"))?;
        if command
            .env
            .get("FORGEFLOW_VERIFICATION_ROLE")
            .is_some_and(|value| value != role)
        {
            return Err(invalid(
                "reserved FORGEFLOW_VERIFICATION_ROLE differs from registered command role",
            ));
        }
        command_roles.push(role.to_owned());
        if !safe_relative(&command.report_path)
            || !report_paths.insert(command.report_path.clone())
            || command.timeout_seconds == 0
            || command.timeout_seconds > 3600
            || command.expected_cases.is_empty()
        {
            return Err(invalid(
                "invalid command report, deadline or business denominator",
            ));
        }
        let names: BTreeSet<_> = command
            .expected_cases
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        if names.len() != command.expected_cases.len() || names.iter().any(|n| n.trim().is_empty())
        {
            return Err(invalid("duplicate or empty expected case"));
        }
        let subjects = capture_subject_inputs(command, &cwd, subject_resolver(command, &cwd)?)?;
        verify_inputs(command, &cwd, &subjects)?;
        command_subjects.push(subjects);
        if command.expected_cases.len() > 100_000 {
            return Err(invalid("verification case budget exceeded"));
        }
        if command.role == VerificationRole::Independent
            && (!command
                .expected_cases
                .iter()
                .any(|c| c.kind == CaseKind::Positive)
                || !command
                    .expected_cases
                    .iter()
                    .any(|c| c.kind == CaseKind::Negative))
        {
            return Err(invalid(
                "independent oracle requires positive and negative cases",
            ));
        }
    }
    let mut log = Vec::new();
    if command_subjects.iter().any(|inputs| !inputs.is_empty()) {
        let proof = serde_json::json!({"schema_version":"forgeflow.verification-subject-projection.v1",
            "binding":binding,"verification_plan_hash":plan.digest(),"cwd":cwd,
            "commands":plan.commands.iter().zip(&command_subjects).enumerate().map(|(index,(command,subjects))|
                serde_json::json!({"index":index,"command_hash":sha256(&serde_json::to_vec(command).expect("serializable command")),"subjects":subjects})).collect::<Vec<_>>()});
        persist_new_json(&root.join("verification-subject-inputs.json"), &proof)?;
        log.extend_from_slice(&serde_json::to_vec(&serde_json::json!({"subject_projection_sha256":sha256(&serde_json::to_vec(&proof).map_err(invalid)?),"proof":proof})).map_err(invalid)?);
        log.push(b'\n');
    }
    let mut total: u64 = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut positive = 0;
    let mut negative = 0;
    let mut exit_code = 0;
    let mut argv: Vec<String> = Vec::new();
    for (index, command) in plan.commands.iter().enumerate() {
        if *cancellation.borrow() {
            return Err(invalid("verification cancelled or authority revoked"));
        }
        let report_path = report_location(&root, &command.report_path)?;
        let operation = physical
            .map(|context| context.operation_id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let process_attempt = physical
            .map(|context| context.commands[index].process_attempt_id.clone())
            .unwrap_or_else(|| format!("verify-{operation}-{index}"));
        let journal =
            Journal::new(&root.join("verification-runs"), &process_attempt).map_err(invalid)?;
        if let Some(context) = physical {
            persist_new_json(
                &journal.path("verification-command.json"),
                &serde_json::json!({"context":context,"command":context.commands[index]}),
            )?;
        }
        let mut env = command.env.clone();
        env.insert(
            "FORGEFLOW_VERIFICATION_ROLE".into(),
            command_roles[index].clone(),
        );
        env.insert(
            "FORGEFLOW_REPORT_PATH".into(),
            report_path.to_string_lossy().into(),
        );
        env.insert(
            "FORGEFLOW_EVIDENCE_BINDING".into(),
            serde_json::to_string(binding).map_err(invalid)?,
        );
        env.insert("FORGEFLOW_SOURCE_HASH".into(), facts.source_hash.clone());
        if let Some(path) = &facts.artifact_path {
            env.insert(
                "FORGEFLOW_ARTIFACT_PATH".into(),
                path.to_string_lossy().into(),
            );
        }

        let spec = ProcessSpec {
            program: command.program.clone(),
            args: command.args.clone(),
            env,
            cwd: cwd.clone(),
            stdin: Vec::new(),
        };
        let handoffs_before = runtime_handoff_files(&root)?;
        let spec = guard(spec)?;
        let mut runtime_handoffs = Vec::new();
        for path in runtime_handoff_files(&root)?.difference(&handoffs_before) {
            let metadata = fs::symlink_metadata(path).map_err(invalid)?;
            if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
                return Err(invalid(
                    "runtime handoff sidecar is not a bounded regular file",
                ));
            }
            let bytes = fs::read(path).map_err(invalid)?;
            let digest = sha256(&bytes);
            let identity = subject_file(path, bytes.len() as u64, &digest, false)?;
            let proof: serde_json::Value = serde_json::from_slice(&bytes).map_err(invalid)?;
            if proof["schema_version"] != "forgeflow.native-verifier-runtime-handoff.v1"
                || proof["verification_plan_hash"] != plan.digest()
                || proof["verification_plan_id"] != plan.plan_id
                || proof["command_index"].as_u64() != Some(index as u64)
                || proof["command_snapshot"] != serde_json::to_value(command).map_err(invalid)?
                || proof["readonly"] != true
                || proof["original_command_unchanged"] != true
            {
                return Err(invalid(
                    "runtime handoff sidecar differs from the original registered command",
                ));
            }
            log.extend_from_slice(&serde_json::to_vec(&serde_json::json!({"schema_version":"forgeflow.verifier-runtime-handoff-log.v1",
                "relative_path":path.strip_prefix(&root).map_err(invalid)?,"sha256":digest,"bytes":bytes.len(),
                "verification_plan_hash":plan.digest(),"command_index":index})).map_err(invalid)?);
            log.push(b'\n');
            runtime_handoffs.push((path.clone(), bytes.len() as u64, digest, identity));
        }
        verify_subject_mounts(&spec, &command_subjects[index])?;
        verify_inputs(command, &cwd, &command_subjects[index])?;
        log.extend_from_slice(
            format!("actual launch {} {:?}\n", spec.program.display(), spec.args).as_bytes(),
        );
        let intent = LaunchIntent {
            execution_id: match physical {
                Some(context) => context.commands[index].execution_id.clone(),
                None => journal.execution_id().map_err(invalid)?,
            },
            operation_id: operation,
            attempt_id: process_attempt,
            generation: facts.generation,
            worker_id: plan.verifier_id.clone(),
            boot_id: boot_id().map_err(invalid)?,
            workspace: cwd.clone(),
            prompt_sha256: sha256(&serde_json::to_vec(binding).map_err(invalid)?),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let cancel_rx = cancellation.clone();
        let (notice_tx, mut notice_rx) = mpsc::channel(64);
        let (launched_tx, _launched_rx) = watch::channel(None);
        let drain = tokio::spawn(async move { while notice_rx.recv().await.is_some() {} });
        let limits = SupervisionLimits {
            timeout: Duration::from_secs(command.timeout_seconds),
            term_grace: Duration::from_secs(1),
            kill_grace: Duration::from_secs(1),
            max_log_bytes: 16 * 1024 * 1024,
        };
        let launch_journal = journal.clone();
        let physical_request = physical.map(|context| context.physical_request.clone());
        let supervision = tokio::spawn(async move {
            match physical_request {
                Some(request) => {
                    supervise_physical(
                        spec,
                        intent,
                        launch_journal,
                        limits,
                        cancel_rx,
                        notice_tx,
                        launched_tx,
                        request,
                    )
                    .await
                }
                None => {
                    supervise(
                        spec,
                        intent,
                        launch_journal,
                        limits,
                        cancel_rx,
                        notice_tx,
                        launched_tx,
                    )
                    .await
                }
            }
        });
        let stop = supervision.await.map_err(invalid)?.map_err(invalid);
        let _ = drain.await;
        let stop = stop?;
        if physical.is_some() {
            if !matches!(
                journal.disposition().map_err(invalid)?,
                forgeflow_runtime::RecoveryDisposition::Completed
            ) {
                return Err(invalid(
                    "physical verification settlement is unconfirmed; quarantine",
                ));
            }
            for name in [
                "verification-command.json",
                "launch.lock",
                "launch-receipt.json",
                "cgroup-fence.json",
                "cgroup-membership.json",
                "cgroup-stop.json",
            ] {
                if journal.path(name).exists() {
                    log.extend_from_slice(name.as_bytes());
                    log.push(b'\n');
                    log.extend_from_slice(&fs::read(journal.path(name)).map_err(invalid)?);
                    log.push(b'\n');
                }
            }
        }
        log.extend_from_slice(
            format!(
                "command {index} role {:?}: {} {:?}\n",
                command.role,
                command.program.display(),
                command.args
            )
            .as_bytes(),
        );
        log.extend_from_slice(&serde_json::to_vec(&stop).map_err(invalid)?);
        log.push(b'\n');
        for name in ["stdout.ndjson", "stderr.log"] {
            if let Ok(bytes) = fs::read(journal.path(name)) {
                log.extend(bytes);
                log.push(b'\n');
            }
        }
        if !stop.process_exit_confirmed || stop.log_error.is_some() {
            return Err(invalid(
                "verification process or log settlement unconfirmed",
            ));
        }
        if *cancellation.borrow() || stop.reason != "executor_exited" {
            return Err(invalid(format!(
                "verification interrupted: {}",
                stop.reason
            )));
        }
        if stop.exit_code != Some(0) {
            exit_code = stop.exit_code.unwrap_or(1).max(1);
        }
        let canonical_report = fs::canonicalize(&report_path).map_err(invalid)?;
        if !canonical_report.starts_with(&root) {
            return Err(invalid("report escapes artifact root"));
        }
        if fs::metadata(&canonical_report).map_err(invalid)?.len() > 8 * 1024 * 1024 {
            return Err(invalid("structured report byte budget exceeded"));
        }
        let raw = fs::read(&canonical_report).map_err(invalid)?;
        let report: RawReport = serde_json::from_slice(&raw).map_err(invalid)?;
        log.extend_from_slice(&raw);
        log.push(b'\n');
        if report.binding != *binding {
            return Err(EvidenceError::BindingMismatch);
        }
        if report.oracle_id != plan.oracle_id || report.cases.len() != command.expected_cases.len()
        {
            return Err(invalid("oracle or business denominator mismatch"));
        }
        let expected: BTreeMap<_, _> = command
            .expected_cases
            .iter()
            .map(|c| (c.name.as_str(), c.kind))
            .collect();
        let mut seen = BTreeSet::new();
        let mut local_executed = 0;
        let mut local_positive = 0;
        let mut local_negative = 0;
        for case in report.cases {
            if !seen.insert(case.name.clone())
                || expected.get(case.name.as_str()) != Some(&case.kind)
            {
                return Err(invalid("unregistered or duplicate business case"));
            }
            total += 1;
            if case.outcome != CaseOutcome::Skipped {
                local_executed += 1;
                match case.kind {
                    CaseKind::Positive => local_positive += 1,
                    CaseKind::Negative => local_negative += 1,
                }
            }
            match case.outcome {
                CaseOutcome::Skipped => skipped += 1,
                CaseOutcome::Failed => {
                    failed += 1;
                    match case.kind {
                        CaseKind::Positive => positive += 1,
                        CaseKind::Negative => negative += 1,
                    }
                }
                CaseOutcome::Passed => match case.kind {
                    CaseKind::Positive => positive += 1,
                    CaseKind::Negative => negative += 1,
                },
            }
        }
        if local_executed == 0
            || (command.role == VerificationRole::Independent
                && (local_positive == 0 || local_negative == 0))
        {
            return Err(invalid(
                "required verifier has no executed business oracle cases",
            ));
        }
        verify_inputs(command, &cwd, &command_subjects[index])?;
        for (path, bytes, digest, identity) in runtime_handoffs {
            if subject_file(&path, bytes, &digest, false)? != identity {
                return Err(invalid(
                    "runtime handoff sidecar changed during verification",
                ));
            }
        }
        argv.push(command.program.to_string_lossy().into());
        argv.extend(command.args.clone());
    }
    let log_path = "verification-raw.log";
    if *cancellation.borrow() {
        return Err(invalid(
            "verification authority revoked before receipt freeze",
        ));
    }
    let log_hash = sha256(&log);
    let receipt = serde_json::json!({"binding":binding,"environment_profile":plan.environment_profile,"command":argv,"exit_code":exit_code,"total":total,"failed":failed,"skipped":skipped,"positive_cases":positive,"negative_cases":negative,"oracle_id":plan.oracle_id,"verifier_id":plan.verifier_id,"author_id":plan.author_id,"independent":true,"log_path":log_path,"log_hash":log_hash});
    use std::io::Write;
    let mut raw_log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join(log_path))
        .map_err(invalid)?;
    raw_log.write_all(&log).map_err(invalid)?;
    raw_log.sync_all().map_err(invalid)?;
    durable_json(&root.join("verification-receipt.json"), &receipt).map_err(invalid)?;
    Ok(receipt)
}

/// Return durable process settlement proofs, including failed verification runs.
/// The caller must keep allocations quarantined if any launch lacks a confirmed stop.
pub fn verification_stop_evidence(
    artifact_root: &Path,
) -> Result<Vec<forgeflow_runtime::StopEvidence>, EvidenceError> {
    let root = fs::canonicalize(artifact_root).map_err(invalid)?;
    if root.join("verification-physical-context.json").exists() {
        verification_physical_stop_evidence(&root)?;
    }
    let journals = root.join("verification-runs");
    if !journals.exists() {
        return Ok(Vec::new());
    }
    let mut evidence = Vec::new();
    for entry in fs::read_dir(journals).map_err(invalid)? {
        let path = fs::canonicalize(entry.map_err(invalid)?.path()).map_err(invalid)?;
        if !path.starts_with(&root) {
            return Err(invalid("verification journal escapes root"));
        }
        let journal = Journal {
            directory: path.clone(),
        };
        match journal.disposition().map_err(invalid)? {
            forgeflow_runtime::RecoveryDisposition::NeverLaunched => continue,
            forgeflow_runtime::RecoveryDisposition::Completed => {}
            forgeflow_runtime::RecoveryDisposition::RecoveryRequired(reason) => {
                return Err(invalid(format!(
                    "verification process is unconfirmed; keep quarantined: {reason}"
                )));
            }
        }
        let stop: forgeflow_runtime::StopEvidence =
            serde_json::from_slice(&fs::read(path.join("stop.json")).map_err(invalid)?)
                .map_err(invalid)?;
        if !stop.process_exit_confirmed {
            return Err(invalid(
                "verification process stop is unconfirmed; keep quarantined",
            ));
        }
        evidence.push(stop);
    }
    Ok(evidence)
}

/// Validate all preselected commands against the durable registered mapping,
/// bound runtime authority and physical empty-tree proof. Unused commands need
/// the awaited sequencer's explicit negative seal, never a directory guess.
pub fn verification_physical_stop_evidence(
    artifact_root: &Path,
) -> Result<Vec<serde_json::Value>, EvidenceError> {
    let root = fs::canonicalize(artifact_root).map_err(invalid)?;
    let context: PhysicalVerificationContext =
        read_json(&root.join("verification-physical-context.json"))?;
    context.validate_identity()?;
    if context.verifier_root != root {
        return Err(EvidenceError::BindingMismatch);
    }
    let context_value = serde_json::to_value(&context).map_err(invalid)?;
    let sealed: serde_json::Value = read_json(&root.join("verification-physical-closed.json"))?;
    if sealed["context"] != context_value || sealed["runner_closed"] != true {
        return Err(invalid("physical verifier sequencer is not durably closed"));
    }
    let unused: BTreeSet<String> = sealed["unused_execution_ids"]
        .as_array()
        .ok_or_else(|| invalid("physical verifier unused command seal missing"))?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid unused execution identity"))
        })
        .collect::<Result<_, _>>()?;
    let expected_ids: BTreeSet<_> = context
        .commands
        .iter()
        .map(|command| command.execution_id.clone())
        .collect();
    if !unused.is_subset(&expected_ids) {
        return Err(invalid(
            "unused command seal contains unregistered identity",
        ));
    }
    let directory = root.join("verification-runs");
    let allowed: BTreeSet<_> = context
        .commands
        .iter()
        .map(|command| command.process_attempt_id.as_str())
        .collect();
    if directory.exists() {
        for entry in fs::read_dir(&directory).map_err(invalid)? {
            let entry = entry.map_err(invalid)?;
            if !allowed.contains(entry.file_name().to_str().unwrap_or(""))
                || entry.file_type().map_err(invalid)?.is_symlink()
            {
                return Err(invalid("unregistered physical verifier journal"));
            }
        }
    }
    let mut evidence = Vec::with_capacity(context.commands.len());
    for command in &context.commands {
        let journal = Journal::new(&directory, &command.process_attempt_id).map_err(invalid)?;
        if journal.directory.exists()
            && fs::canonicalize(&journal.directory).map_err(invalid)? != journal.directory
        {
            return Err(invalid(
                "physical verifier journal is not its canonical owned path",
            ));
        }
        let command_value = serde_json::to_value(command).map_err(invalid)?;
        if unused.contains(&command.execution_id) {
            if !never_started(&journal)? {
                return Err(invalid(
                    "sealed unused command has launch effects; quarantine",
                ));
            }
            confirm_absent_command_leaf(&context, command)?;
            if journal.path("verification-command.json").exists() {
                let mapping: serde_json::Value =
                    read_json(&journal.path("verification-command.json"))?;
                if mapping["context"] != context_value || mapping["command"] != command_value {
                    return Err(EvidenceError::BindingMismatch);
                }
            }
            evidence.push(serde_json::json!({"context":context,"command":command,
                "status":"NEVER_LAUNCHED","runner_closed":true,"unused_closed":true,
                "launch_authority":null,"launch_receipt":null,"physical_fence":null,
                "physical_membership":null,"physical_stop":null,"stop":null}));
            continue;
        }
        let mapping: serde_json::Value = read_json(&journal.path("verification-command.json"))?;
        if mapping["context"] != context_value || mapping["command"] != command_value {
            return Err(EvidenceError::BindingMismatch);
        }
        if !matches!(
            journal.disposition().map_err(invalid)?,
            forgeflow_runtime::RecoveryDisposition::Completed
        ) {
            return Err(invalid(
                "physical verifier process stop is unconfirmed; quarantine",
            ));
        }
        let authority = journal
            .launch_authority()
            .map_err(invalid)?
            .ok_or_else(|| invalid("physical verifier durable launch authority missing"))?;
        let receipt = if journal.path("launch-receipt.json").exists() {
            Some(journal.receipt().map_err(invalid)?)
        } else {
            None
        };
        let fence = journal
            .cgroup_fence()
            .map_err(invalid)?
            .ok_or_else(|| invalid("physical verifier fence missing"))?;
        let membership: Option<serde_json::Value> =
            if journal.path("cgroup-membership.json").exists() {
                Some(read_json(&journal.path("cgroup-membership.json"))?)
            } else {
                None
            };
        let physical_stop: serde_json::Value = read_json(&journal.path("cgroup-stop.json"))?;
        let stop: forgeflow_runtime::StopEvidence = read_json(&journal.path("stop.json"))?;
        let request = &context.physical_request;
        let intent = &authority.intent;
        let membership_path = fence
            .leaf_path
            .strip_prefix(&fence.mount_path)
            .map_err(invalid)?;
        let expected_membership = format!("/{}", membership_path.to_string_lossy());
        let pre_exec_stopped = match (&receipt, &membership) {
            (Some(receipt), Some(membership)) => {
                if receipt.intent.execution_id != command.execution_id
                    || membership["identity_sha256"] != fence.identity_sha256
                    || membership["pid"] != receipt.process.pid
                    || membership["unified_membership"] != expected_membership
                {
                    return Err(invalid("physical verifier launch membership differs"));
                }
                false
            }
            (None, None) => {
                // These are the runtime's actual before-exec branches. Every
                // other missing or half-missing receipt remains UNKNOWN.
                if !(stop.reason == "cancelled_before_launch"
                    || stop
                        .reason
                        .strip_prefix("spawn_failed: ")
                        .is_some_and(|reason| !reason.is_empty()))
                    || journal.path("stdout.ndjson").exists()
                    || journal.path("stderr.log").exists()
                    || stop.stdout_bytes != 0
                    || stop.stderr_bytes != 0
                    || stop.log_error.is_some()
                {
                    return Err(invalid(
                        "missing physical verifier launch is not a proven pre-exec stop",
                    ));
                }
                true
            }
            _ => {
                return Err(invalid(
                    "partial physical verifier launch receipt; quarantine",
                ));
            }
        };
        if intent.attempt_id != command.process_attempt_id
            || intent.execution_id != command.execution_id
            || intent.operation_id != context.operation_id
            || intent.generation != context.generation
            || intent.boot_id != fence.boot_id
            || fence.project_id != request.project_id
            || fence.attempt_id != command.process_attempt_id
            || fence.execution_id != command.execution_id
            || fence.generation != context.generation
            || fence.delegation != request.delegation
            || fence.limits != request.limits
            || fence.resource_binding_sha256 != request.resource_binding_sha256
            || authority.physical_fence_sha256.as_deref() != Some(fence.identity_sha256.as_str())
            || physical_stop["identity_sha256"] != fence.identity_sha256
            || physical_stop["snapshot"]["cgroup.procs"] != ""
            // Runtime records the physical stop before reaping exited tasks.
            // pids.current may still include those tasks; the bound populated
            // proof and empty procs establish absence of live descendants.
            || !physical_stop["snapshot"]["cgroup.events"]
                .as_str()
                .is_some_and(|events| events.lines().any(|line| line == "populated 0")
                    && !events.lines().any(|line| line == "populated 1"))
            || !stop.process_exit_confirmed
        {
            return Err(invalid(
                "physical verifier launch/membership/stop differs from registered command",
            ));
        }
        evidence.push(serde_json::json!({"context":context,"command":command,
            "status":"STOPPED","runner_closed":true,"unused_closed":false,
            "pre_exec_stopped":pre_exec_stopped,
            "launch_authority":authority,"launch_receipt":receipt,"physical_fence":fence,
            "physical_membership":membership,"physical_stop":physical_stop,"stop":stop}));
    }
    Ok(evidence)
}

/// Restart reconciliation only settles authenticated old verifier groups; it never relaunches.
pub async fn reconcile_verification_runs(
    artifact_root: &Path,
) -> Result<Vec<forgeflow_runtime::StopEvidence>, EvidenceError> {
    reconcile_registered_verification_runs(artifact_root, None).await
}

/// Only the authority startup phase, after its instance lock and before HTTP
/// or scheduling starts, may close unconsumed registered launch rights here.
/// Reconciliation never reruns commands or clears uncertain launch fences.
pub async fn reconcile_registered_verification_runs(
    artifact_root: &Path,
    physical: Option<&PhysicalVerificationContext>,
) -> Result<Vec<forgeflow_runtime::StopEvidence>, EvidenceError> {
    let root = fs::canonicalize(artifact_root).map_err(invalid)?;
    if let Some(context) = physical {
        context.validate_identity()?;
        if context.verifier_root != root {
            return Err(EvidenceError::BindingMismatch);
        }
        let mapping_path = root.join("verification-physical-context.json");
        if mapping_path.exists() {
            let existing: serde_json::Value = read_json(&mapping_path)?;
            if existing != serde_json::to_value(context).map_err(invalid)? {
                return Err(EvidenceError::BindingMismatch);
            }
        } else {
            persist_new_json(&mapping_path, context)?;
        }
    }
    let directory = root.join("verification-runs");
    if !directory.exists() {
        if let Some(context) = physical {
            if !root.join("verification-physical-closed.json").exists() {
                seal_physical_execution(context)?;
            }
            verification_physical_stop_evidence(&root)?;
        }
        return Ok(Vec::new());
    }
    let mut stops = Vec::new();
    for entry in fs::read_dir(&directory).map_err(invalid)? {
        let entry = entry.map_err(invalid)?;
        if let Some(context) = physical {
            if entry.file_type().map_err(invalid)?.is_symlink()
                || !context.commands.iter().any(|command| {
                    entry.file_name().to_str() == Some(command.process_attempt_id.as_str())
                })
            {
                return Err(invalid("unregistered physical verifier recovery journal"));
            }
        }
        let path = fs::canonicalize(entry.path()).map_err(invalid)?;
        if !path.starts_with(&root) {
            return Err(invalid("verification journal escapes registered root"));
        }
        let journal = Journal { directory: path };
        match journal.disposition().map_err(invalid)? {
            forgeflow_runtime::RecoveryDisposition::NeverLaunched => {}
            forgeflow_runtime::RecoveryDisposition::Completed => stops.push(
                serde_json::from_slice(&fs::read(journal.path("stop.json")).map_err(invalid)?)
                    .map_err(invalid)?,
            ),
            forgeflow_runtime::RecoveryDisposition::RecoveryRequired(_) => {
                let stop = forgeflow_runtime::reconcile(&journal, Duration::from_secs(1))
                    .await
                    .map_err(invalid)?;
                if !stop.process_exit_confirmed {
                    return Err(invalid(
                        "old verifier group is not confirmed stopped; quarantine",
                    ));
                }
                stops.push(stop);
            }
        }
    }
    if let Some(context) = physical {
        if !root.join("verification-physical-closed.json").exists() {
            seal_physical_execution(context)?;
        }
        verification_physical_stop_evidence(&root)?;
    }
    Ok(stops)
}

#[cfg(test)]
mod subject_projection_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// One parameterized safety check for the exact new exception; no model,
    /// process or business-case success is simulated by this fixture.
    #[test]
    fn subject_projection_requires_exact_immutable_mapping_and_keeps_oracle_ban() {
        for case in [
            "allowed",
            "unexpected",
            "logical_escape",
            "sha",
            "bytes",
            "copy_in_candidate",
            "copy_symlink",
            "unprojected_oracle",
            "original_replaced",
            "copy_replaced",
            "mount_shadow",
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let cwd = temporary.path().join("candidate");
            let outside = temporary.path().join("trusted");
            fs::create_dir(&cwd).unwrap();
            fs::create_dir(&outside).unwrap();
            let original = cwd.join("business.json");
            let copy = outside.join("subject.json");
            let bytes = b"{\"subject\":1}\n";
            fs::write(&original, bytes).unwrap();
            fs::write(&copy, bytes).unwrap();
            fs::set_permissions(&copy, fs::Permissions::from_mode(0o400)).unwrap();
            let program = fs::canonicalize("/usr/bin/true").unwrap();
            let mut command = CommandSpec {
                role: VerificationRole::Independent,
                program: program.clone(),
                args: Vec::new(),
                env: BTreeMap::new(),
                executable_hash: sha256(&fs::read(&program).unwrap()),
                bound_inputs: vec![BoundInput {
                    path: "business.json".into(),
                    sha256: sha256(bytes),
                }],
                report_path: "report.json".into(),
                expected_cases: Vec::new(),
                timeout_seconds: 1,
            };
            let mut resolution = SubjectInputResolution {
                original_path: original.clone(),
                logical_path: "business.json".into(),
                sha256: sha256(bytes),
                bytes: bytes.len() as u64,
                execution_source: copy.clone(),
                context_artifact_id: "fixture-context".into(),
                context_sha256: "1".repeat(64),
                classification_recipe_sha256: "2".repeat(64),
            };
            match case {
                "unexpected" => {
                    command.bound_inputs.clear();
                }
                "logical_escape" => {
                    resolution.logical_path = "../business.json".into();
                }
                "sha" => {
                    resolution.sha256 = "0".repeat(64);
                }
                "bytes" => {
                    resolution.bytes += 1;
                }
                "copy_in_candidate" => {
                    resolution.execution_source = original.clone();
                }
                "copy_symlink" => {
                    let link = outside.join("alias.json");
                    symlink(&copy, &link).unwrap();
                    resolution.execution_source = link;
                }
                "unprojected_oracle" => {
                    let oracle = cwd.join("oracle.py");
                    fs::write(&oracle, b"oracle").unwrap();
                    command.bound_inputs.push(BoundInput {
                        path: "oracle.py".into(),
                        sha256: sha256(b"oracle"),
                    });
                }
                _ => {}
            }
            let captured = capture_subject_inputs(&command, &cwd, vec![resolution]);
            if [
                "unexpected",
                "logical_escape",
                "sha",
                "bytes",
                "copy_in_candidate",
                "copy_symlink",
            ]
            .contains(&case)
            {
                assert!(captured.is_err(), "{case}");
                continue;
            }
            let captured = captured.unwrap();
            if case == "unprojected_oracle" {
                assert!(verify_inputs(&command, &cwd, &captured).is_err());
                continue;
            }
            assert!(
                verify_inputs(&command, &cwd, &[]).is_err(),
                "default API must keep its inside-candidate ban"
            );
            verify_inputs(&command, &cwd, &captured).unwrap();
            if ["original_replaced", "copy_replaced"].contains(&case) {
                let target = if case == "original_replaced" {
                    &original
                } else {
                    &copy
                };
                let replacement = outside.join("replacement");
                fs::write(&replacement, bytes).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
                fs::rename(replacement, target).unwrap();
                assert!(
                    verify_inputs(&command, &cwd, &captured).is_err(),
                    "same bytes cannot replace the captured inode: {case}"
                );
                continue;
            }
            let mut spec = ProcessSpec {
                program: "/usr/bin/bwrap".into(),
                args: vec![
                    "--ro-bind".into(),
                    cwd.to_string_lossy().into(),
                    cwd.to_string_lossy().into(),
                    "--ro-bind".into(),
                    copy.to_string_lossy().into(),
                    original.to_string_lossy().into(),
                    "--".into(),
                    program.to_string_lossy().into(),
                ],
                cwd: cwd.clone(),
                env: BTreeMap::new(),
                stdin: Vec::new(),
            };
            verify_subject_mounts(&spec, &captured).unwrap();
            if case == "mount_shadow" {
                spec.args.splice(
                    6..6,
                    [
                        "--ro-bind".into(),
                        cwd.to_string_lossy().into(),
                        cwd.to_string_lossy().into(),
                    ],
                );
                assert!(verify_subject_mounts(&spec, &captured).is_err());
            }
        }
    }
}
