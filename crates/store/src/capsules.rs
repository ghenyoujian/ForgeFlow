//! Optional Capsule metadata over ordinary Attempt authority. No launch, lease,
//! state machine or profile/envelope copies are created here.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path, sync::OnceLock};

const POLICY_SCHEMA: &str = "forgeflow.capsule-policy.v1";
const ENVIRONMENT_SCHEMA: &str = "forgeflow.capsule-environment.v1";
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> StoreError {
    err("CAPSULE_QUALIFICATION_REQUIRED", message)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsulePolicyRequest {
    pub schema_version: String,
    pub executor_profile_id: String,
    pub resource_profile_id: String,
    pub model_route_id: String,
    pub mode: DriverMode,
    pub team_write_policy: TeamWritePolicy,
    pub qualification_ref: ArtifactRef,
}
impl CapsulePolicyRequest {
    fn validate(&self) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA
            || [
                &self.executor_profile_id,
                &self.resource_profile_id,
                &self.model_route_id,
            ]
            .iter()
            .any(|id| id.trim().is_empty() || id.len() > 512 || id.contains('\0'))
        {
            return Err(invalid(
                "bounded policy identity and supported schema required",
            ));
        }
        if !matches!(self.mode, DriverMode::DshHeadless | DriverMode::ClaudeLeaf) {
            return Err(err(
                "CAPSULE_MODE_UNQUALIFIED",
                "managed Team and Workflow qualification is not implemented",
            ));
        }
        if self.team_write_policy == TeamWritePolicy::DisjointAttested {
            return Err(err(
                "CAPSULE_MODE_UNQUALIFIED",
                "per-member disjoint isolation is not qualified",
            ));
        }
        let reference = &self.qualification_ref;
        if reference.artifact_id.trim().is_empty()
            || reference.artifact_id.len() > 512
            || reference.artifact_id.contains('\0')
            || reference.artifact_id.starts_with('/')
            || reference.artifact_id.starts_with('\\')
            || reference.artifact_id.as_bytes().get(1) == Some(&b':')
            || reference.sha256.len() != 64
            || !reference
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid(
                "bounded artifact identity and lowercase SHA256 required; runtime paths are not artifact IDs",
            ));
        }
        Ok(())
    }
}

/// Exact environment required by the qualification artifact. Its public hashes
/// reveal no profile contents, credential references or runtime paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleEnvironment {
    pub schema_version: String,
    pub executor_profile_sha256: String,
    pub resource_profile_sha256: String,
    pub model_route_sha256: String,
    pub control_build_sha256: String,
    pub operating_system: String,
    pub architecture: String,
    pub kernel_release: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleContextRequest {
    pub executor_profile_id: String,
    pub resource_profile_id: String,
    pub model_route_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsuleBusinessSeal {
    schema_version: String,
    project_id: String,
    attempt_id: String,
    generation: i64,
    integrated_sha: String,
}

fn value_hash(value: &Value) -> Result<String> {
    // serde_json's default Map is ordered; recursively round-tripping through
    // BTreeMap also preserves this rule if preserve_order is enabled elsewhere.
    fn ordered(v: &Value) -> Value {
        match v {
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, v)| (k.clone(), ordered(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(ordered).collect()),
            _ => v.clone(),
        }
    }
    Ok(forgeflow_planner::sha256(&serde_json::to_vec(&ordered(
        value,
    ))?))
}

fn file_hash(path: &Path) -> std::result::Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|_| "pinned executable is unreadable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "pinned executable metadata unavailable")?;
    if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
        return Err("pinned executable must be a bounded regular file".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| "pinned executable read failed")?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

async fn environment(bindings: &Value) -> Result<CapsuleEnvironment> {
    static BUILD: OnceLock<std::result::Result<String, String>> = OnceLock::new();
    let build = tokio::task::spawn_blocking(|| {
        BUILD
            .get_or_init(|| {
                let path = std::env::current_exe()
                    .map_err(|_| "control executable identity unavailable".to_owned())?;
                file_hash(&path)
            })
            .clone()
    })
    .await
    .map_err(|_| invalid("control executable identity task failed"))?
    .map_err(invalid)?;
    let kernel_release = tokio::fs::read_to_string("/proc/sys/kernel/osrelease")
        .await
        .map_err(|_| invalid("kernel identity unavailable"))?;
    if kernel_release.len() > 512 {
        return Err(invalid("kernel identity exceeds bound"));
    }
    Ok(CapsuleEnvironment {
        schema_version: ENVIRONMENT_SCHEMA.into(),
        executor_profile_sha256: crate::execution_bindings::profile_digest(
            &bindings["executor_profile"],
        )?,
        resource_profile_sha256: value_hash(&bindings["resource_profile"])?,
        model_route_sha256: value_hash(&bindings["model_route"])?,
        control_build_sha256: build,
        operating_system: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        kernel_release: kernel_release.trim().into(),
    })
}

async fn profile_bindings(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    executor: &str,
    resource: &str,
    route: &str,
) -> Result<Value> {
    let mut bindings = serde_json::Map::new();
    for (collection, key, id) in [
        ("executor_profiles", "executor_profile", executor),
        ("resource_profiles", "resource_profile", resource),
        ("model_routes", "model_route", route),
    ] {
        let value: Value = sqlx::query_scalar("SELECT data-'revision' FROM documents WHERE project_id=$1 AND collection=$2 AND document_id=$3 FOR SHARE")
            .bind(project).bind(collection).bind(id).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("NOT_FOUND", "same-project execution configuration not found"))?;
        if value["id"].as_str() != Some(id) {
            return Err(invalid("execution configuration identity differs"));
        }
        bindings.insert(key.into(), value);
    }
    Ok(Value::Object(bindings))
}

async fn artifact_bytes(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    reference: &ArtifactRef,
) -> Result<Vec<u8>> {
    let descriptor: Value = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2 FOR SHARE")
        .bind(project).bind(&reference.artifact_id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| invalid("same-project qualification artifact is not registered"))?;
    if descriptor["sha256"].as_str() != Some(reference.sha256.as_str())
        || descriptor
            .get("artifact_id")
            .is_some_and(|id| id.as_str() != Some(reference.artifact_id.as_str()))
    {
        return Err(invalid(
            "registered qualification artifact digest or identity differs",
        ));
    }
    let path = descriptor["path"]
        .as_str()
        .filter(|p| Path::new(p).is_absolute())
        .ok_or_else(|| invalid("qualification artifact has no absolute registered storage path"))?
        .to_owned();
    let expected = reference.sha256.clone();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)
            .map_err(|_| invalid("qualification artifact is unreadable"))?;
        if !file
            .metadata()
            .map_err(|_| invalid("qualification artifact metadata unavailable"))?
            .is_file()
        {
            return Err(invalid("qualification artifact is not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("qualification artifact read failed"))?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES || forgeflow_planner::sha256(&bytes) != expected
        {
            return Err(invalid(
                "qualification artifact bytes exceed bound or differ from digest",
            ));
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| invalid("qualification artifact read task failed"))?
}

fn require_checks(probe: &DriverProbeResult, resume: bool, gateway: bool) -> Result<()> {
    if probe.evidence_class != EvidenceClass::RealModel {
        return Err(invalid(
            "managed qualification requires actual real-model evidence",
        ));
    }
    let mut required = vec![
        CapabilityId::ExecutableIdentity,
        CapabilityId::VersionHelp,
        CapabilityId::StartHeadless,
        CapabilityId::StructuredEvents,
        CapabilityId::ProcessCancel,
        CapabilityId::TranscriptReplay,
        CapabilityId::VerifiedWriteIsolation,
        CapabilityId::BusinessE2e,
    ];
    if resume {
        required.push(CapabilityId::SessionResume);
    }
    if gateway {
        required.push(CapabilityId::ModelEgressEnforced);
    }
    if required.iter().any(|id| {
        !probe.checks.iter().any(|check| {
            check.check_id == *id
                && check.status == VerificationStatus::Verified
                && !check.evidence_refs.is_empty()
        })
    }) {
        return Err(invalid(
            "required exact-mode capability is not VERIFIED with evidence",
        ));
    }
    Ok(())
}

async fn validate_business_seal(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    probe: &DriverProbeResult,
    profile_digest: &str,
) -> Result<()> {
    let check = probe
        .checks
        .iter()
        .find(|check| check.check_id == CapabilityId::BusinessE2e)
        .ok_or_else(|| invalid("real business qualification evidence missing"))?;
    for reference in &check.evidence_refs {
        let bytes = artifact_bytes(tx, project, reference).await?;
        // Other originals may accompany the canonical seal. They still have
        // their registered byte hashes checked below; only this typed seal can
        // link a VERIFIED claim to existing successful business authority.
        let Ok(seal) = serde_json::from_slice::<CapsuleBusinessSeal>(&bytes) else {
            continue;
        };
        if seal.schema_version != "forgeflow.capsule-business-seal.v1"
            || seal.project_id != project
            || seal.generation <= 0
        {
            continue;
        }
        let row = sqlx::query("SELECT a.envelope,a.data,m.data AS merge_data FROM attempts a JOIN merge_intents m ON m.project_id=a.project_id AND m.attempt_id=a.attempt_id AND m.generation=a.generation WHERE a.project_id=$1 AND a.attempt_id=$2 AND a.generation=$3 AND a.state='SUCCEEDED' AND m.state IN ('FINALIZED','COMMITTED')")
            .bind(project).bind(&seal.attempt_id).bind(seal.generation).fetch_optional(&mut **tx).await?;
        let Some(row) = row else {
            continue;
        };
        let data: Value = row.try_get("data")?;
        let merge: Value = row.try_get("merge_data")?;
        let envelope: ExecutionEnvelope = decode(row.try_get("envelope")?)?;
        let source = crate::execution_bindings::load(&mut **tx, project, &seal.attempt_id).await?;
        let kind = match probe.driver_id {
            ExecutorDriverId::ClaudeCode => "CLAUDE_CODE_LEAF",
            ExecutorDriverId::Dsh => "DSH_HEADLESS",
        };
        if envelope.command.is_none()
            && envelope.generation == seal.generation
            && merge["integrated_sha"].as_str() == Some(seal.integrated_sha.as_str())
            && seal.integrated_sha.len() == 40
            && seal.integrated_sha.bytes().all(|b| b.is_ascii_hexdigit())
            && data["result"]["evidence"]["executor_kind"].as_str() == Some(kind)
            && crate::execution_bindings::profile_digest(&source["executor_profile"])?
                == profile_digest
        {
            return Ok(());
        }
    }
    Err(invalid(
        "business qualification is not linked to an existing same-project successful native leaf and finalized integration",
    ))
}

async fn validate_qualification(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    policy: &CapsulePolicyRequest,
    bindings: &Value,
    resume: bool,
    gateway: bool,
) -> Result<(DriverProbeResult, CapsuleEnvironment)> {
    policy.validate()?;
    let profile = &bindings["executor_profile"];
    let driver = match profile["kind"].as_str() {
        Some("CLAUDE_CODE_LEAF") => ExecutorDriverId::ClaudeCode,
        None | Some("DSH_HEADLESS") => ExecutorDriverId::Dsh,
        _ => {
            return Err(err(
                "CAPSULE_MODE_UNQUALIFIED",
                "only explicit headless leaf profiles are supported",
            ));
        }
    };
    if driver != policy.mode.driver_id() || profile["id"] != policy.executor_profile_id {
        return Err(invalid(
            "policy driver differs from frozen executor profile",
        ));
    }
    let raw = artifact_bytes(tx, project, &policy.qualification_ref).await?;
    let probe: DriverProbeResult = serde_json::from_slice(&raw)
        .map_err(|_| invalid("qualification artifact is not a strict DriverProbeResult"))?;
    probe.validate()?;
    let context = environment(bindings).await?;
    if probe.driver_id != driver
        || probe.mode != policy.mode
        || probe.executor_profile_sha256.as_deref()
            != Some(context.executor_profile_sha256.as_str())
        || probe.observed_at > db_now(tx).await? + chrono::Duration::minutes(5)
    {
        return Err(invalid(
            "qualification driver, mode, profile or observation time differs",
        ));
    }
    require_checks(&probe, resume, gateway)?;
    validate_business_seal(tx, project, &probe, &context.executor_profile_sha256).await?;
    let environment_bytes = artifact_bytes(tx, project, &probe.environment_ref).await?;
    let observed: CapsuleEnvironment = serde_json::from_slice(&environment_bytes)
        .map_err(|_| invalid("qualification environment is not a strict CapsuleEnvironment"))?;
    if observed != context {
        return Err(invalid(
            "qualification environment differs from current build, OS, guard profiles or model route",
        ));
    }
    let pins = probe
        .artifact_pins_ref
        .as_ref()
        .ok_or_else(|| invalid("qualification must pin runtime/plugin/config manifest"))?;
    let pins_raw = artifact_bytes(tx, project, pins).await?;
    let pins_value: Value = serde_json::from_slice(&pins_raw)
        .map_err(|_| invalid("artifact pin manifest is not JSON"))?;
    if !profile["artifact_pins"].is_array() || pins_value != profile["artifact_pins"] {
        return Err(invalid(
            "runtime/plugin/config manifest differs from frozen profile pins",
        ));
    }
    let program = profile["program"]
        .as_str()
        .filter(|p| Path::new(p).is_absolute())
        .ok_or_else(|| invalid("frozen executable requires an absolute path"))?
        .to_owned();
    let program_copy = program.clone();
    let executable = tokio::task::spawn_blocking(move || file_hash(Path::new(&program_copy)))
        .await
        .map_err(|_| invalid("executable identity task failed"))?
        .map_err(invalid)?;
    if probe.executable_sha256.as_deref() != Some(executable.as_str())
        || !profile["artifact_pins"].as_array().is_some_and(|pins| {
            pins.iter().any(|pin| {
                pin["path"].as_str() == Some(program.as_str())
                    && pin["sha256"].as_str() == Some(executable.as_str())
            })
        })
    {
        return Err(invalid(
            "current executable differs from qualification or frozen pins",
        ));
    }
    let mut refs = BTreeMap::new();
    refs.insert(
        probe.command_results_ref.artifact_id.clone(),
        probe.command_results_ref.clone(),
    );
    for reference in probe.checks.iter().flat_map(|c| &c.evidence_refs) {
        if let Some(prior) = refs.insert(reference.artifact_id.clone(), reference.clone()) {
            if prior.sha256 != reference.sha256 {
                return Err(invalid("qualification contains conflicting artifact pins"));
            }
        }
    }
    let mut bytes = raw.len() + environment_bytes.len() + pins_raw.len();
    for reference in refs.values() {
        bytes = bytes
            .checked_add(artifact_bytes(tx, project, reference).await?.len())
            .ok_or_else(|| invalid("qualification evidence size overflow"))?;
        if bytes > MAX_EVIDENCE_BYTES {
            return Err(invalid("qualification evidence exceeds total bound"));
        }
    }
    Ok((probe, context))
}

impl Store {
    pub async fn capsule_context(
        &self,
        project: &str,
        request: &CapsuleContextRequest,
    ) -> Result<CapsuleEnvironment> {
        // The reference is not used here: context is discovery, never a claim of
        // qualification. No artifact, policy, Attempt or event is persisted.
        let mut tx = self.pool.begin().await?;
        let bindings = profile_bindings(
            &mut tx,
            project,
            &request.executor_profile_id,
            &request.resource_profile_id,
            &request.model_route_id,
        )
        .await?;
        let context = environment(&bindings).await?;
        tx.commit().await?;
        Ok(context)
    }

    pub async fn register_capsule_policy(
        &self,
        identity: CommandIdentity,
        project: &str,
        policy: CapsulePolicyRequest,
    ) -> Result<Value> {
        policy.validate()?;
        let request = serde_json::json!({"project_id":project,"policy":policy});
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        if let Some(mut receipt) = replay(
            &mut tx,
            &identity.actor_id,
            "register_capsule_policy",
            &identity.idempotency_key,
            &request,
        )
        .await?
        {
            receipt["replayed"] = Value::Bool(true);
            tx.commit().await?;
            return Ok(receipt);
        }
        project_lock(&mut tx, project).await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='capsule_policies' AND document_id=$2)")
            .bind(project).bind(&policy.executor_profile_id).fetch_one(&mut *tx).await?;
        if exists {
            return Err(err(
                "IMMUTABLE_PROFILE",
                "Capsule policy is append only; register a new executor profile ID",
            ));
        }
        let bindings = profile_bindings(
            &mut tx,
            project,
            &policy.executor_profile_id,
            &policy.resource_profile_id,
            &policy.model_route_id,
        )
        .await?;
        let (_, context) =
            validate_qualification(&mut tx, project, &policy, &bindings, false, false).await?;
        let value = serde_json::json!({"policy":policy,"environment":context,"registered_at":db_now(&mut tx).await?,"revision":1});
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'capsule_policies',$2,1,$3)")
            .bind(project).bind(&policy.executor_profile_id).bind(&value).execute(&mut *tx).await?;
        let operation = id();
        event(&mut tx, project, &policy.executor_profile_id, 1, "capsule_policy.registered", serde_json::json!({"executor_profile_id":policy.executor_profile_id,"qualification_ref":policy.qualification_ref})).await?;
        let receipt = serde_json::json!({"operation_id":operation,"replayed":false,"data":value,"authorization_granted":false});
        save_replay(
            &mut tx,
            &identity.actor_id,
            "register_capsule_policy",
            &identity.idempotency_key,
            &operation,
            &request,
            &receipt,
        )
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }

    pub async fn capsule_policies(
        &self,
        project: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Value> {
        self.get_project(project).await?;
        let limit = limit.clamp(1, 200);
        let mut rows: Vec<(String,Value)> = sqlx::query_as("SELECT document_id,data FROM documents WHERE project_id=$1 AND collection='capsule_policies' AND ($2::text IS NULL OR document_id>$2) ORDER BY document_id LIMIT $3")
            .bind(project).bind(after).bind(i64::from(limit)+1).fetch_all(&self.pool).await?;
        let more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next = if more {
            rows.last().map(|(id, _)| id.clone())
        } else {
            None
        };
        let items: Vec<_> = rows.into_iter().map(|(_, v)| v).collect();
        Ok(serde_json::json!({"items":items,"next_cursor":next,"authorization_granted":false}))
    }

    pub async fn capsules(&self, project: &str, after: Option<&str>, limit: u32) -> Result<Value> {
        self.get_project(project).await?;
        let limit = limit.clamp(1, 200);
        let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('project_id',project_id,'attempt_id',attempt_id,'task_id',task_id,'task_revision',task_revision,'attempt_state',state,'attempt_revision',revision,'binding_status',CASE WHEN execution_bindings ? 'capsule' THEN 'BOUND_UNCHECKED' ELSE 'UNBOUND' END,'capsule',execution_bindings->'capsule') FROM attempts WHERE project_id=$1 AND ($2::text IS NULL OR attempt_id>$2) ORDER BY attempt_id LIMIT $3")
            .bind(project).bind(after).bind(i64::from(limit)+1).fetch_all(&self.pool).await?;
        let more = rows.len() > limit as usize;
        let mut items: Vec<_> = rows.into_iter().take(limit as usize).collect();
        for item in &mut items {
            if !item["capsule"].is_null() {
                let binding: CapsuleBinding = decode(item["capsule"].clone())?;
                binding.validate()?;
                item["capsule"] = json(&binding)?;
            }
        }
        let next = if more {
            items.last().and_then(|v| v["attempt_id"].as_str())
        } else {
            None
        };
        Ok(serde_json::json!({"items":items,"next_cursor":next,"authorization_granted":false}))
    }

    pub async fn attempt_capsule(&self, project: &str, attempt: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT data,envelope,execution_bindings->'capsule' AS capsule,executor_profile_sha256 FROM attempts WHERE project_id=$1 AND attempt_id=$2 FOR SHARE")
            .bind(project).bind(attempt).fetch_optional(&mut *tx).await?
            .ok_or_else(|| err("NOT_FOUND", "same-project Attempt not found"))?;
        let a: Attempt = decode(row.try_get("data")?)?;
        let raw: Option<Value> = row.try_get("capsule")?;
        let Some(raw) = raw else {
            tx.commit().await?;
            return Ok(
                serde_json::json!({"project_id":project,"attempt_id":attempt,"task_id":a.task_id,"task_revision":a.task_revision,"attempt_state":a.state,"attempt_revision":a.revision,"binding_status":"UNBOUND","capsule":null,"authorization_granted":false}),
            );
        };
        let envelope: ExecutionEnvelope = decode(row.try_get("envelope")?)?;
        let binding: CapsuleBinding = decode(raw)?;
        let digest: Option<String> = row.try_get("executor_profile_sha256")?;
        let digest = digest.ok_or_else(|| {
            invalid("bound Capsule requires the admitted frozen profile reference")
        })?;
        if envelope.project_id != project
            || envelope.attempt_id != attempt
            || envelope.generation != a.generation
            || envelope.lease_id != a.lease_id
            || envelope.worker_id != a.worker_id
            || envelope.task_id != a.task_id
            || envelope.task_revision != a.task_revision
            || envelope.operation_id != a.operation_id
        {
            return Err(err(
                "CAPSULE_IDENTITY_MISMATCH",
                "stored envelope differs from canonical Attempt",
            ));
        }
        binding.validate_against(&envelope, &digest)?;
        // Resolving CAS validates original profile bytes and same-project identity.
        let bindings = crate::execution_bindings::load(&mut tx, project, attempt).await?;
        let policy_mode = match bindings["executor_profile"]["kind"].as_str() {
            Some("CLAUDE_CODE_LEAF") => DriverMode::ClaudeLeaf,
            None | Some("DSH_HEADLESS") => DriverMode::DshHeadless,
            _ => {
                return Err(err(
                    "CAPSULE_MODE_UNQUALIFIED",
                    "bound profile is not a supported leaf",
                ));
            }
        };
        if binding.driver_id != policy_mode.driver_id()
            || binding.execution_kind != ExecutionKind::ManagedLeaf
        {
            return Err(err(
                "CAPSULE_IDENTITY_MISMATCH",
                "stored Capsule driver or mode differs from profile",
            ));
        }
        let root: Option<String> = sqlx::query_scalar("SELECT upstream_session_id FROM native_sessions WHERE project_id=$1 AND attempt_id=$2 AND worker_id=$3 AND generation=$4")
            .bind(project).bind(attempt).bind(&a.worker_id).bind(a.generation).fetch_optional(&mut *tx).await?;
        let active: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_lifecycles WHERE project_id=$1 AND attempt_id=$2 AND worker_id=$3 AND generation=$4 AND disposed_at IS NULL AND state<>'RELEASED'")
            .bind(project).bind(attempt).bind(&a.worker_id).bind(a.generation).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(
            serde_json::json!({"project_id":project,"attempt_id":attempt,"task_id":a.task_id,"task_revision":a.task_revision,"attempt_state":a.state,"attempt_revision":a.revision,"binding_status":"BOUND_IDENTITY_CHECKED","capsule":binding,"native_root_session_id":root,"occupied_native_lifecycles":active,"authorization_granted":false,"qualification_revalidated":false}),
        )
    }

    pub async fn check_capsule(&self, project: &str, binding: &CapsuleBinding) -> Result<Value> {
        binding.validate()?;
        if binding.envelope_ref.project_id != project {
            return Err(err(
                "CAPSULE_IDENTITY_MISMATCH",
                "Capsule reference belongs to another project",
            ));
        }
        let view = self
            .attempt_capsule(project, &binding.envelope_ref.attempt_id)
            .await?;
        if view["capsule"] != json(binding)? {
            return Err(err(
                "CAPSULE_IDENTITY_MISMATCH",
                "supplied Capsule differs from immutable admitted binding",
            ));
        }
        Ok(
            serde_json::json!({"capsule_id":binding.capsule_id,"valid_binding":true,"authorization_granted":false,"qualification_revalidated":false,"checked_at":Utc::now()}),
        )
    }
}

/// Called inside the ordinary admission transaction after envelope materialization
/// and before CAS/Attempt/Lease/Outbox insertion. Absence preserves legacy bytes.
pub(crate) async fn freeze_binding_tx(
    tx: &mut Transaction<'_, Postgres>,
    envelope: &ExecutionEnvelope,
    bindings: &mut Value,
) -> Result<()> {
    let record: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='capsule_policies' AND document_id=$2 FOR SHARE")
        .bind(&envelope.project_id).bind(&envelope.executor_profile_id).fetch_optional(&mut **tx).await?;
    let Some(record) = record else {
        return Ok(());
    };
    let policy: CapsulePolicyRequest = decode(record["policy"].clone())?;
    if envelope.command.is_some()
        || policy.executor_profile_id != envelope.executor_profile_id
        || policy.resource_profile_id != envelope.resource_profile_id
        || policy.model_route_id != envelope.model_route_id
    {
        return Err(invalid(
            "Capsule policy does not bind this native execution configuration",
        ));
    }
    let (_, context) = validate_qualification(
        tx,
        &envelope.project_id,
        &policy,
        bindings,
        envelope.resume_session_id.is_some(),
        envelope.enforcement.model_budget_mode == ModelBudgetMode::GatewayEnforced,
    )
    .await?;
    if record["environment"] != json(&context)? {
        return Err(invalid(
            "registered Capsule policy environment no longer applies",
        ));
    }
    let binding = CapsuleBinding {
        schema_version: CAPSULE_SCHEMA_V1.into(),
        capsule_id: format!("capsule:{}", envelope.attempt_id),
        envelope_ref: ExecutionEnvelopeRef::from_envelope(envelope)?,
        driver_id: policy.mode.driver_id(),
        execution_kind: ExecutionKind::ManagedLeaf,
        executor_profile_sha256: context.executor_profile_sha256,
        qualification_ref: policy.qualification_ref,
        team_write_policy: policy.team_write_policy,
    };
    binding.validate_against(envelope, &binding.executor_profile_sha256)?;
    bindings["capsule"] = json(&binding)?;
    Ok(())
}
