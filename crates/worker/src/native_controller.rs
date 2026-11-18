//! Private native RPC transport. PostgreSQL, never this relay, issues grants.
use crate::{ControlClient, ManagedDshConfig, persist_bytes};
use anyhow::{Context, Result, bail};
use forgeflow_domain::ExecutionEnvelope;
use forgeflow_executors::{HeadlessProfile, sha256};
use forgeflow_runtime::{Journal, durable_json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

pub const SCHEMA: &str = "forgeflow.dsh-bridge.v2";
pub const MAX_FRAME_BYTES: usize = 65536;
pub const SOCKET_ALIAS: &str = "/tmp/forgeflow/controller.sock";
pub const PATCH_ALIAS: &str = "/tmp/forgeflow/managed.patch.json";
pub const PRESET_ALIAS: &str = "/tmp/forgeflow/preset.patch.yml";
pub const BRIDGE_ALIAS: &str = "/tmp/forgeflow/managed-bridge.mjs";
pub const CONTEXT_ALIAS_ROOT: &str = "/tmp/forgeflow/context";
pub(crate) const MAX_NATIVE_RPC_TIMEOUT_MS: u64 = 60_000;

/// Standard output discard is not a source-tree write grant. Bind only the
/// checked null character device so the outer write guard grants that inode,
/// never the device directory or a caller-selected host path.
pub(crate) fn native_null_output_mount() -> Result<forgeflow_runtime::SandboxMount> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = PathBuf::from("/dev/null");
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_char_device()
        || metadata.rdev() != 0x0103 // Linux null device: major 1, minor 3.
        || std::fs::canonicalize(&path)? != path
    {
        bail!("native output discard requires the exact null character device");
    }
    Ok(forgeflow_runtime::SandboxMount {
        source: path.clone(),
        target: path,
    })
}

/// Canonical admission freezes this from the digest-bound position anchor and
/// the real planning card. It is never inferred from prompt text or native
/// environment. Different roots retain independent worktrees and write sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeRootBinding {
    pub schema_version: String,
    pub project_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub input_digest: String,
    pub owner_id: String,
    pub team_id: String,
    pub position_id: String,
    pub preset_id: String,
    pub catalog_sha256: String,
    pub planning_card_id: String,
}

impl NativeRootBinding {
    pub(crate) fn validate_identity(
        &self,
        envelope: &ExecutionEnvelope,
        input_digest: &str,
    ) -> Result<()> {
        if self.schema_version != "forgeflow.native-root-binding.v1"
            || self.project_id != envelope.project_id
            || self.task_id != envelope.task_id
            || self.task_revision != envelope.task_revision
            || self.input_digest != input_digest
            || !forgeflow_domain::valid_digest(&self.input_digest)
            || !forgeflow_domain::valid_digest(&self.catalog_sha256)
            || self.owner_id.is_empty()
            || self.team_id.is_empty()
            || self.planning_card_id.is_empty()
        {
            bail!("native root binding differs from frozen task identity or semantics");
        }
        Ok(())
    }
}

fn derive_native_root_preset(
    profile: &HeadlessProfile,
    config: &ManagedDshConfig,
    envelope: &ExecutionEnvelope,
    source: &[u8],
    binding: Option<&NativeRootBinding>,
) -> Result<Vec<u8>> {
    let manifest: Value = serde_json::from_slice(&pinned_bytes(profile, &config.mode_manifest)?)?;
    match manifest
        .get("native_root_binding_policy")
        .filter(|value| !value.is_null())
    {
        None => {}
        Some(value) if value == "IMPORTED_PLANNING_ROLE_V1" => {
            if binding.is_none() {
                bail!(
                    "managed native profile requires an immutable admitted task-position binding"
                );
            }
        }
        Some(_) => bail!("unrecognized frozen native root binding policy"),
    }
    let Some(binding) = binding else {
        return Ok(source.to_vec());
    };
    binding.validate_identity(envelope, &binding.input_digest)?;
    if manifest["schema_version"] != "forgeflow.dsh-mode.v3"
        || manifest["id"] != config.mode_id
        || manifest["role_catalog"]["path"] != "agent-roles.json"
    {
        bail!("task-selected native root requires the frozen v3 role catalog");
    }
    let catalog_path = config
        .mode_manifest
        .parent()
        .context("native role bundle missing")?
        .join("agent-roles.json");
    let bytes = pinned_bytes(profile, &catalog_path)?;
    if sha256(&bytes) != binding.catalog_sha256 {
        bail!("native root binding references a different frozen role catalog");
    }
    let catalog: Value = serde_json::from_slice(&bytes)?;
    if catalog["schema_version"] != "forgeflow.agent-roles.v1"
        || catalog["project_id"] != binding.project_id
    {
        bail!("native root binding references a different project role catalog");
    }
    let row = catalog["roster"]
        .as_array()
        .context("native role roster missing")?
        .iter()
        .find(|row| row["position_id"] == binding.position_id)
        .context("native root position is absent from its frozen catalog")?;
    if row["owner_id"] != binding.owner_id
        || row["owner_team_id"] != binding.team_id
        || row["preset_id"] != binding.preset_id
        || row["model_route"] != manifest["model_policy"]["route_id"]
    {
        bail!("native root role Owner, team, preset or model differs from frozen task binding");
    }
    let mut rows: Value = serde_json::from_slice(source)
        .context("task-selected native root requires a frozen JSON preset patch")?;
    let mut matches = 0;
    for patch in rows
        .as_array_mut()
        .context("native preset patch must be an array")?
    {
        for entry in patch
            .get_mut("insert")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if entry["id"] != "forgeflow-team-binding" {
                continue;
            }
            matches += 1;
            let config = entry["config"]
                .as_object_mut()
                .context("native Team binding configuration missing")?;
            if config.get("schema_version").and_then(Value::as_str)
                != Some("forgeflow.dsh-team-binding.v1")
                || config
                    .get("require_fresh_for_role_change")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                bail!("native Team selection configuration differs from its pinned contract");
            }
            let selected = config
                .get("bindings")
                .and_then(Value::as_array)
                .context("native Team binding roster missing")?
                .iter()
                .find(|value| value["position_id"] == binding.position_id)
                .context("native root position is absent from actual preset binding rows")?;
            if selected["preset_id"] != binding.preset_id
                || selected["owner_team_id"] != binding.team_id
                || selected["teammate_name"] != row["teammate_name"]
            {
                bail!("native preset binding row differs from the frozen role catalog");
            }
            // Only this per-attempt selector is derived. The source preset,
            // all 62 registered definitions, model configuration and sandbox
            // policy remain identical to the admitted executor registration.
            config.insert(
                "default_root_position_id".into(),
                json!(binding.position_id),
            );
        }
    }
    if matches != 1 {
        bail!("exactly one pinned native Team binding plugin is required");
    }
    serde_json::to_vec(&rows).map_err(Into::into)
}

/// These are bounded transport capacities, never admission rights. The same
/// immutable profile/binding already checked by the Worker supplies the count;
/// PostgreSQL still authorizes every Agent lifecycle and model dispatch.
pub(crate) struct NativeTransportLimits {
    pub rpc_connections: usize,
    pub model_connections: usize,
}

pub(crate) fn transport_limits(
    journal: &Journal,
    envelope: &ExecutionEnvelope,
) -> Result<NativeTransportLimits> {
    let path = journal.path("execution-bindings.json");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Old journal callers have no physical/profile authority here.
            // Keep their bounded historical transport without claiming scale.
            return Ok(NativeTransportLimits {
                rpc_connections: 16,
                model_connections: 16,
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("native transport bindings must be a regular journal file");
    }
    let bindings: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let resource = bindings
        .get("resource_profile")
        .filter(|v| v.is_object())
        .context("native transport resource profile missing")?;
    if resource["id"].as_str() != Some(envelope.resource_profile_id.as_str()) {
        bail!("native transport profile differs from immutable envelope");
    }
    let Some(policy) = resource.get("native_child_policy").filter(|v| !v.is_null()) else {
        return Ok(NativeTransportLimits {
            rpc_connections: 16,
            model_connections: 16,
        });
    };
    if policy["schema_version"] != "forgeflow.native-child-policy.v1" {
        bail!("native transport child policy schema differs");
    }
    let live = policy["max_live_agents"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= u64::from(u32::MAX))
        .context("native transport requires finite live Agent capacity")?;
    let mut models = policy["model_inflight_limit"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= u64::from(u32::MAX))
        .context("native transport requires finite model capacity")?;
    if let Some(raw) = bindings.get("physical_resources").filter(|v| !v.is_null()) {
        let pool: forgeflow_domain::PhysicalResourceBinding = serde_json::from_value(raw.clone())?;
        pool.verify()?;
        let enabled = policy["enabled"]
            .as_bool()
            .context("native transport child enablement missing")?;
        let children = if enabled { live - 1 } else { 0 };
        let child: forgeflow_domain::ResourceVector =
            serde_json::from_value(policy["child_resources"].clone())?;
        if pool.resource_profile_id != envelope.resource_profile_id
            || u64::from(pool.max_concurrent_children) != children
            || pool.native_child_resources != child
            || serde_json::to_value(&pool.physical_limits)? != resource["physical_limits"]
        {
            bail!("native transport capacity differs from the frozen physical pool");
        }
        // A whole model response owns one relay connection. A smaller wire cap
        // would strand an admitted request before its canonical dispatch.
        models = models.min(pool.reserved_resources.provider_inflight);
        if models == 0 {
            bail!("native model transport has no immutable provider reservation");
        }
    } else if resource
        .get("physical_limits")
        .is_some_and(|v| !v.is_null())
    {
        bail!("native transport physical reservation missing");
    }
    // One lifecycle/model exchange per Agent plus observation and cancellation
    // exchanges can overlap. Do not turn the former fixed 16 sockets into a
    // hidden lower Agent limit. The bridge separately orders observations.
    let rpc = live
        .checked_mul(2)
        .and_then(|v| v.checked_add(4))
        .context("native RPC transport capacity overflow")?
        .max(16);
    let bounded = |value: u64| -> Result<usize> {
        let value = usize::try_from(value).context("native transport capacity exceeds platform")?;
        if value > Semaphore::MAX_PERMITS {
            bail!("native transport capacity exceeds bounded semaphore");
        }
        Ok(value)
    };
    Ok(NativeTransportLimits {
        rpc_connections: bounded(rpc)?,
        model_connections: bounded(models)?,
    })
}

/// Bounded diagnostic identity; never carries a token, URL or response body.
#[derive(Debug)]
pub(crate) struct NativeRpcFailure {
    pub phase: &'static str,
    pub code: &'static str,
    pub http_status: Option<u16>,
    pub canonical_code: Option<String>,
}
impl std::fmt::Display for NativeRpcFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.code, self.phase)
    }
}
impl std::error::Error for NativeRpcFailure {}

fn validate_project_roster(manifest: &Value, catalog: &Value, patch: &Value) -> Result<()> {
    let roster = catalog["roster"]
        .as_array()
        .filter(|r| !r.is_empty() && r.len() <= 10_000)
        .context("managed mode requires a nonempty bounded project roster")?;
    if catalog["schema_version"] != "forgeflow.agent-roles.v1"
        || catalog["positions"].as_u64() != Some(roster.len() as u64)
        || manifest["role_catalog"]["planned_positions"] != catalog["positions"]
        || manifest["role_catalog"]["specialized_presets"] != catalog["positions"]
        || manifest["model_policy"]["route_id"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        bail!("managed project role count or model policy differs from pinned mode");
    }
    let teams = catalog["teams"]
        .as_array()
        .filter(|t| !t.is_empty() && t.len() <= roster.len())
        .context("managed mode requires declared project owner teams")?;
    let mut team_counts = std::collections::BTreeMap::new();
    for team in teams {
        let owner = team["owner_id"]
            .as_str()
            .context("managed v3 team owner missing")?;
        let identity = team["team_id"]
            .as_str()
            .context("managed v3 team identity missing")?;
        let planned = team["planned_agents"]
            .as_u64()
            .filter(|count| *count > 0 && *count <= roster.len() as u64)
            .context("managed v3 team position count missing")?;
        if team_counts
            .insert((owner, identity), (planned, 0_u64))
            .is_some()
        {
            bail!("managed v3 team identity duplicated");
        }
    }
    let declared_presets: std::collections::BTreeSet<&str> = patch
        .as_array()
        .context("managed preset patch must be an array")?
        .iter()
        .filter_map(|row| row["insert"].as_array())
        .flatten()
        .filter(|row| row["name"] == "@deepseek-ai/dsh-agent-preset")
        .filter_map(|row| row["config"]["id"].as_str())
        .collect();
    let mut positions = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    let mut presets = std::collections::BTreeSet::new();
    for row in roster {
        let position = row["position_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("managed v3 position identity missing")?;
        let name = row["teammate_name"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("managed v3 teammate name missing")?;
        let preset = row["preset_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("managed v3 specialized preset identity missing")?;
        if !positions.insert(position)
            || !names.insert(name)
            || !presets.insert(preset)
            || row["model_route"] != manifest["model_policy"]["route_id"]
            || !declared_presets.contains(preset)
            || !matches!(
                row["generic_preset_id"].as_str(),
                Some(
                    "forgeflow-lead-v1"
                        | "forgeflow-owner-v1"
                        | "forgeflow-implementer-v1"
                        | "forgeflow-verifier-v1"
                )
            )
        {
            bail!("managed v3 role identities, preset mapping or model route differ");
        }
        let owner = row["owner_id"]
            .as_str()
            .context("managed v3 position owner missing")?;
        let team = row["owner_team_id"]
            .as_str()
            .context("managed v3 position team missing")?;
        let (_, actual) = team_counts
            .get_mut(&(owner, team))
            .context("managed v3 position belongs to an undeclared owner team")?;
        *actual += 1;
    }
    if team_counts
        .values()
        .any(|(planned, actual)| planned != actual)
    {
        bail!("managed v3 owner team counts differ from the actual declared roster");
    }
    Ok(())
}

fn pinned_bytes(profile: &HeadlessProfile, path: &std::path::Path) -> Result<Vec<u8>> {
    if !path.is_absolute() || !std::fs::symlink_metadata(path)?.is_file() {
        bail!("managed reference must be an absolute regular file");
    }
    let canonical = std::fs::canonicalize(path)?;
    let pin = profile
        .artifact_pins
        .iter()
        .find(|pin| std::fs::canonicalize(&pin.path).ok().as_ref() == Some(&canonical))
        .context("managed mode reference is outside frozen executor pins")?;
    let bytes = std::fs::read(path)?;
    if sha256(&bytes) != pin.sha256 {
        bail!("managed mode source pin changed");
    }
    Ok(bytes)
}

/// Doctor is a frozen observation of the exact runtime and inputs, never a
/// declaration of native child, gateway or financial qualification.
pub fn verify_managed(profile: &HeadlessProfile, config: &ManagedDshConfig) -> Result<()> {
    profile.verify_identity()?;
    // Concurrent admitted agents can wait behind an atomic planning mutation.
    // The frozen profile may allow a longer finite wait; every grant still comes
    // from canonical authority and cancellation/lease renewal run independently.
    if !(1..=MAX_NATIVE_RPC_TIMEOUT_MS).contains(&config.rpc_timeout_ms)
        || profile.profile_name != "headless"
    {
        bail!("managed headless profile or bounded RPC timeout invalid");
    }
    let entrypoint = profile
        .prefix_args
        .first()
        .context("managed native entrypoint missing")?;
    pinned_bytes(profile, std::path::Path::new(entrypoint))?;
    let manifest: Value = serde_json::from_slice(&pinned_bytes(profile, &config.mode_manifest)?)?;
    let v3 = manifest["schema_version"] == "forgeflow.dsh-mode.v3";
    if !(manifest["schema_version"] == "forgeflow.dsh-mode.v2" || v3)
        || manifest["id"] != config.mode_id
        || manifest["managed_bridge"]["protocol"] != SCHEMA
    {
        bail!("managed mode manifest identity or protocol mismatch");
    }
    if v3 {
        if manifest["native_profile"] != "headless"
            || manifest["default_preset_id"] != "forgeflow-lead-v1"
            || manifest["role_catalog"]["path"] != "agent-roles.json"
            || manifest["role_catalog"]["binding_plugin"] != "team-binding.mjs"
            || manifest["role_catalog"]["generic_presets"] != 4
            || manifest["model_policy"]["other_models_allowed"] != false
        {
            bail!("managed v3 mode differs from the reviewed role/preset contract");
        }
        let bundle = config
            .mode_manifest
            .parent()
            .context("managed v3 bundle directory missing")?;
        let catalog: Value =
            serde_json::from_slice(&pinned_bytes(profile, &bundle.join("agent-roles.json"))?)?;
        pinned_bytes(profile, &bundle.join("team-binding.mjs"))?;
        let patch: Value = serde_json::from_slice(&pinned_bytes(profile, &config.preset_patch)?)?;
        validate_project_roster(&manifest, &catalog, &patch)?;
    }
    pinned_bytes(profile, &config.preset_patch)?;
    pinned_bytes(profile, &config.bridge_plugin)?;
    let credentials = pinned_bytes(profile, &config.credentials)?;
    if let Some(relay) = &config.model_relay {
        relay.validate()?;
        pinned_bytes(profile, &relay.transport_loader)?;
        if let Some(path) = &relay.provider_policy_path {
            let policy: Value = serde_json::from_slice(&pinned_bytes(profile, path)?)?;
            if policy["schema_version"] != "forgeflow.native-provider-policy.v1"
                || policy["id"].as_str() != relay.provider_policy_id.as_deref()
                || policy["provider"] != "newapi"
                || policy["model"] != "glm-5.3"
                || policy["api"] != "anthropic-messages"
                || policy["thinking_type"] != "enabled"
                || policy["effort"] != "max"
                || policy["max_output_tokens"] != 131072
                || policy["input"] != json!(["text"])
            {
                bail!("frozen native provider policy identity or functional values differ");
            }
        }
        let dummy: Value = serde_json::from_slice(&credentials)
            .context("strict relay credentials must be the pinned dummy JSON document")?;
        if dummy != dummy_credentials() {
            bail!("strict relay profile cannot contain provider credentials");
        }
    }
    let rows: Value =
        serde_json::from_slice(&pinned_bytes(profile, &config.selected_model_config)?)?;
    let rows = rows
        .as_array()
        .context("selected model configuration must be a JSON row array")?;
    let ids: std::collections::BTreeSet<_> =
        rows.iter().filter_map(|row| row["id"].as_str()).collect();
    if rows.len() != 2
        || ids != std::collections::BTreeSet::from(["agent-default-model", "llm-pi-ai"])
        || rows
            .iter()
            .any(|row| row["disabled"] == true || row.get("insert").is_some())
    {
        bail!("managed source must contain only the two distinct selected model rows");
    }
    if config
        .model_relay
        .as_ref()
        .is_some_and(|relay| relay.provider_policy_id.is_some())
    {
        let selected = rows
            .iter()
            .find(|row| row["id"] == "agent-default-model")
            .context("frozen provider policy selected model missing")?;
        if selected["config"]["provider"] != "newapi"
            || selected["config"]["model"] != "glm-5.3"
            || !matches!(
                profile.model_route_id.as_str(),
                "newapi/glm-5.3" | "newapi/glm-5.3-max.v1"
            )
        {
            bail!("frozen GLM Max policy cannot select a different provider/model route");
        }
    }
    let doctor: Value = serde_json::from_slice(&pinned_bytes(profile, &config.doctor)?)?;
    if doctor["schema_version"] != "forgeflow.managed-doctor.v1"
        || doctor["mode_id"] != config.mode_id
        || doctor["executor_profile_id"] != profile.id
        || doctor["native_profile"] != profile.profile_name
        || doctor["bridge_schema_version"] != SCHEMA
        || doctor["exit_code"] != 0
        || doctor["composition_sha256"]
            .as_str()
            .is_none_or(|s| s.len() != 64)
    {
        bail!("managed doctor receipt differs from mode/runtime identity");
    }
    let package = std::path::Path::new(
        doctor["runtime_package"]
            .as_str()
            .context("doctor runtime package missing")?,
    );
    let package: Value = serde_json::from_slice(&pinned_bytes(profile, package)?)?;
    if package["version"].as_str().is_none() || package["version"] != doctor["runtime_version"] {
        bail!("managed doctor native package version changed");
    }
    let pins = doctor["artifact_sha256"]
        .as_object()
        .context("doctor artifact inventory missing")?;
    let doctor_path = std::fs::canonicalize(&config.doctor)?;
    let mut frozen_files = std::collections::BTreeMap::new();
    for pin in &profile.artifact_pins {
        let path = std::fs::canonicalize(&pin.path)?;
        if path == doctor_path {
            continue;
        }
        if pins
            .get(path.to_str().context("managed pin path must be UTF-8")?)
            .and_then(Value::as_str)
            != Some(pin.sha256.as_str())
        {
            bail!("managed doctor artifact inventory differs from frozen input pins");
        }
        frozen_files.insert(
            path.to_str()
                .context("managed pin path must be UTF-8")?
                .to_owned(),
            pin.sha256.as_str(),
        );
    }
    if v3
        || config
            .model_relay
            .as_ref()
            .is_some_and(|relay| relay.provider_policy_id.is_some())
    {
        let receipt = doctor["sdk_runtime_closure"]
            .as_object()
            .context("managed v3/GLM Max requires a frozen installed SDK dependency closure")?;
        let manifest_path = receipt
            .get("manifest_path")
            .and_then(Value::as_str)
            .context("installed SDK closure manifest path missing")?;
        let bytes = pinned_bytes(profile, std::path::Path::new(manifest_path))?;
        if receipt.get("manifest_sha256").and_then(Value::as_str) != Some(sha256(&bytes).as_str()) {
            bail!("installed SDK closure receipt/manifest hash differs");
        }
        let closure: Value = serde_json::from_slice(&bytes)?;
        if closure["schema_version"] != "forgeflow.installed-runtime-closure.v1"
            || closure["resolution"] != "INSTALLED_NODE_PACKAGE_RUNTIME_DEPENDENCIES"
            || [
                "seed_package",
                "resolution",
                "package_count",
                "file_count",
                "total_bytes",
                "missing_optional_dependencies",
            ]
            .iter()
            .any(|key| receipt.get(*key) != closure.get(*key))
        {
            bail!("installed SDK closure metadata differs from its frozen receipt");
        }
        let files = closure["files"]
            .as_object()
            .context("installed SDK closure file inventory missing")?;
        let packages = closure["packages"]
            .as_array()
            .context("installed SDK closure package inventory missing")?;
        if closure["file_count"].as_u64() != Some(files.len() as u64)
            || closure["package_count"].as_u64() != Some(packages.len() as u64)
        {
            bail!("installed SDK closure inventory counts differ");
        }
        let mut total_bytes = 0_u64;
        for (path, entry) in files {
            if !std::path::Path::new(path).is_absolute()
                || entry["sha256"].as_str() != frozen_files.get(path).copied()
            {
                bail!("installed SDK runtime file is outside its frozen executor inventory");
            }
            total_bytes = total_bytes
                .checked_add(
                    entry["bytes"]
                        .as_u64()
                        .context("installed SDK file byte count missing")?,
                )
                .context("installed SDK byte count overflow")?;
        }
        if closure["total_bytes"].as_u64() != Some(total_bytes) {
            bail!("installed SDK closure byte count differs");
        }
        let mut critical = std::collections::BTreeSet::new();
        for package in packages {
            let root = package["path"]
                .as_str()
                .context("installed SDK package root missing")?;
            let package_path = std::path::Path::new(root).join("package.json");
            let path = package_path
                .to_str()
                .context("installed SDK package path must be UTF-8")?;
            if !package_path.is_absolute()
                || package["package_sha256"].as_str() != frozen_files.get(path).copied()
                || files.get(path).is_none()
            {
                bail!("installed SDK package identity is outside the frozen closure");
            }
            if matches!(
                package["name"].as_str(),
                Some("@earendil-works/pi-ai" | "@anthropic-ai/sdk")
            ) {
                let actual: Value = serde_json::from_slice(&std::fs::read(&package_path)?)?;
                if actual["name"] != package["name"] || actual["version"] != package["version"] {
                    bail!("installed SDK critical package metadata changed");
                }
                if package["name"] == "@earendil-works/pi-ai" && closure["seed_package"] != root {
                    bail!("installed SDK seed differs from the actual pi-ai package");
                }
                critical.insert(package["name"].as_str().unwrap());
            }
        }
        if critical
            != std::collections::BTreeSet::from(["@earendil-works/pi-ai", "@anthropic-ai/sdk"])
        {
            bail!("installed SDK closure omits the selected pi-ai or Anthropic runtime");
        }
    }
    Ok(())
}

pub(crate) struct ManagedAttempt {
    pub home: PathBuf,
    pub patch: PathBuf,
    pub package: PathBuf,
    pub profile_patch: PathBuf,
    pub preset: PathBuf,
    pub bridge: PathBuf,
    pub transport_loader: Option<PathBuf>,
    pub provider_policy: Option<PathBuf>,
}

fn dummy_credentials() -> Value {
    json!({"version":1,"refs":{"FORGEFLOW_MODEL_RELAY_DUMMY":"forgeflow-relay-no-provider-secret"}})
}

/// Preserve the approved model's native schema while selecting exactly one
/// streaming Anthropic route. Its external URL and key belong only to gateway.
fn relay_model_config(
    bytes: &[u8],
    config: &ManagedDshConfig,
    envelope: &ExecutionEnvelope,
) -> Result<Vec<u8>> {
    let relay = config
        .model_relay
        .as_ref()
        .context("strict relay config missing")?;
    let mut rows: Value = serde_json::from_slice(bytes)?;
    let rows = rows.as_array_mut().context("selected model rows missing")?;
    let selected = rows
        .iter()
        .find(|row| row["id"] == "agent-default-model")
        .context("selected route missing")?;
    let provider = selected["config"]["provider"]
        .as_str()
        .context("selected provider missing")?
        .to_owned();
    let model = selected["config"]["model"]
        .as_str()
        .context("selected model missing")?
        .to_owned();
    let versioned_glm_max = relay.provider_policy_id.as_deref() == Some("glm-5.3-max.v1")
        && relay.provider_policy_path.is_some()
        && provider == "newapi"
        && model == "glm-5.3"
        && envelope.model_route_id == "newapi/glm-5.3-max.v1";
    if envelope.model_route_id != format!("{provider}/{model}") && !versioned_glm_max {
        bail!("strict model route differs from frozen provider/model");
    }
    let provider_row = rows
        .iter_mut()
        .find(|row| row["id"] == "llm-pi-ai")
        .context("native provider row missing")?;
    let providers = provider_row["config"]["providers"]
        .as_object()
        .context("native provider routes missing")?;
    let approved = providers
        .get(&provider)
        .context("approved native provider missing")?;
    if approved["api"] != "anthropic-messages" {
        bail!("strict relay qualifies Anthropic Messages only");
    }
    let native_model = approved["models"]
        .as_array()
        .context("explicit approved native model required")?
        .iter()
        .find(|m| m["id"].as_str() == Some(model.as_str()))
        .context("approved native model missing")?
        .clone();
    let mut native_model = native_model
        .as_object()
        .context("native model must be an object")?
        .clone();
    // These provider fields are route/auth overrides, never model metadata.
    for key in ["headers", "baseURL", "baseUrl", "apiKey", "authToken"] {
        native_model.remove(key);
    }
    let mut safe = serde_json::Map::new();
    for key in [
        "displayName",
        "compat",
        "defaultInput",
        "defaultContextWindow",
        "defaultMaxTokens",
        "reasoning",
        "thinkingBudgets",
        "cacheRetention",
        "streamIdleTimeoutMs",
        "timeoutMs",
        "maxRequestImageBytes",
        "requestImagePixelBudget",
        "requestImageMaxBytes",
    ] {
        if let Some(value) = approved.get(key) {
            safe.insert(key.into(), value.clone());
        }
    }
    safe.insert("api".into(), json!("anthropic-messages"));
    safe.insert("baseURL".into(), json!(relay.sdk_origin));
    safe.insert("apiKeyEnv".into(), json!("FORGEFLOW_MODEL_RELAY_DUMMY"));
    safe.insert("transport".into(), json!("sse"));
    safe.insert("models".into(), json!([native_model]));
    provider_row["config"] = json!({"providers":{provider:Value::Object(safe)}});
    serde_json::to_vec(rows).map_err(Into::into)
}
pub(crate) fn prepare_managed_home(
    profile: &HeadlessProfile,
    config: &ManagedDshConfig,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    home: PathBuf,
    sandboxed: bool,
    root_binding: Option<&NativeRootBinding>,
    runtime_workspace_root: &std::path::Path,
) -> Result<ManagedAttempt> {
    verify_managed(profile, config)?;
    if !runtime_workspace_root.is_absolute() {
        bail!("native exact-write binding requires the actual absolute isolated worktree");
    }
    let workspace_metadata = std::fs::symlink_metadata(runtime_workspace_root)?;
    if !workspace_metadata.is_dir() || workspace_metadata.file_type().is_symlink() {
        bail!("native exact-write binding requires a regular isolated worktree directory");
    }
    let runtime_workspace_root = std::fs::canonicalize(runtime_workspace_root)?;
    for path in &envelope.write_set {
        forgeflow_domain::validate_relative_path(path)?;
    }
    if home.exists() {
        bail!("managed attempt home already exists; no configuration reuse");
    }
    std::fs::create_dir_all(&home)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    let selected_model = pinned_bytes(profile, &config.selected_model_config)?;
    let model = if config.model_relay.is_some() {
        relay_model_config(&selected_model, config, envelope)?
    } else {
        selected_model.clone()
    };
    let credentials = if config.model_relay.is_some() {
        serde_json::to_vec(&dummy_credentials())?
    } else {
        pinned_bytes(profile, &config.credentials)?
    };
    persist_bytes(&home.join("cordis.patch.yml"), &model)?;
    persist_bytes(&home.join(".credentials.yaml"), &credentials)?;
    let profile_home = home.join("profiles/headless");
    std::fs::create_dir_all(&profile_home)?;
    let package = profile_home.join("package.json");
    persist_bytes(
        &package,
        &serde_json::to_vec(
            &json!({"name":"forgeflow-managed-native-attempt","private":true,
        "dependencies":{},"dsh":{"profile":{"bundles":["@deepseek-ai/dsh-base","@deepseek-ai/dsh-headless"]}}}),
        )?,
    )?;
    let profile_patch = profile_home.join("cordis.patch.yml");
    persist_bytes(&profile_patch, b"[]\n")?;
    persist_bytes(&profile_home.join("cordis.yml"), b"[]\n")?;
    for name in ["sessions", "storages"] {
        std::fs::create_dir(home.join(name))?;
    }
    let preset = home.join("managed-preset.patch.yml");
    let bridge = home.join("managed-bridge.mjs");
    let source_preset = pinned_bytes(profile, &config.preset_patch)?;
    let derived_preset =
        derive_native_root_preset(profile, config, envelope, &source_preset, root_binding)?;
    persist_bytes(&preset, &derived_preset)?;
    persist_bytes(&bridge, &pinned_bytes(profile, &config.bridge_plugin)?)?;
    let transport_loader = if let Some(relay) = &config.model_relay {
        let target = home.join("model-transport.mjs");
        persist_bytes(&target, &pinned_bytes(profile, &relay.transport_loader)?)?;
        Some(target)
    } else {
        None
    };
    let provider_policy = if let Some(path) = config
        .model_relay
        .as_ref()
        .and_then(|relay| relay.provider_policy_path.as_ref())
    {
        let target = home.join("provider-policy.json");
        persist_bytes(&target, &pinned_bytes(profile, path)?)?;
        Some(target)
    } else {
        None
    };
    let patch = journal.path("managed-native.patch.json");
    let socket = if sandboxed {
        PathBuf::from(SOCKET_ALIAS)
    } else {
        journal.path("native-rpc/controller.sock")
    };
    let bridge_name = if sandboxed {
        PathBuf::from(BRIDGE_ALIAS)
    } else {
        bridge.clone()
    };
    let mut bridge_config = json!({"socket_path":socket,"rpc_timeout_ms":config.rpc_timeout_ms,
            "project_id":envelope.project_id,"task_id":envelope.task_id,
            "attempt_id":envelope.attempt_id,"generation":envelope.generation});
    let exact_write_binding = json!({
        "schema_version":"forgeflow.exact-leaf-write.v1",
        "workspace_root":runtime_workspace_root,
        "write_set":envelope.write_set,
    });
    bridge_config["exact_write_binding"] = exact_write_binding.clone();
    if let Some(relay) = &config.model_relay {
        bridge_config["model_relay"] = relay.bridge_config();
    }
    let generated = json!([{"insert":[{"id":"forgeflow-managed-children","name":bridge_name,"config":bridge_config}]}]);
    durable_json(&patch, &generated)?;
    durable_json(
        &journal.path("managed-native-config.json"),
        &json!({
        "mode_id":config.mode_id,"bridge_schema_version":SCHEMA,"home":home,
        "selected_model_config_sha256":sha256(&model),"credentials_sha256":sha256(&credentials),
        "source_selected_model_config_sha256":sha256(&selected_model),"model_transport":config.model_relay,
        "native_root_binding":root_binding,"source_preset_sha256":sha256(&source_preset),
        "derived_preset_sha256":sha256(&derived_preset),
        "exact_write_binding":exact_write_binding,
        "package_sha256":sha256(&std::fs::read(&package)?),"bridge_patch_sha256":sha256(&serde_json::to_vec(&generated)?),
        "configuration_authority":"FROZEN_SELECTED_MODEL_ONLY","qualification":"INCONCLUSIVE"}),
    )?;
    Ok(ManagedAttempt {
        home,
        patch,
        package,
        profile_patch,
        preset,
        bridge,
        transport_loader,
        provider_policy,
    })
}

pub(crate) fn mount_native_aliases(
    spec: &mut forgeflow_runtime::ProcessSpec,
    prepared: &ManagedAttempt,
    socket: &std::path::Path,
    model_socket: Option<&std::path::Path>,
) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    if !std::fs::symlink_metadata(socket)?.file_type().is_socket() {
        bail!("native alias source is not an owned Unix socket");
    }
    let separator = spec
        .args
        .iter()
        .position(|arg| arg == "--")
        .context("sandbox command separator missing")?;
    let path = |path: &std::path::Path| -> Result<String> {
        Ok(path
            .to_str()
            .context("native sandbox path must be UTF-8")?
            .to_owned())
    };
    // An independent readonly mount also prevents replacing the alias directory
    // from writable /tmp and spoofing a controller after native startup.
    let mut overlays = vec![
        "--size".into(),
        "65536".into(),
        "--tmpfs".into(),
        "/tmp/forgeflow".into(),
        "--ro-bind".into(),
        path(socket)?,
        SOCKET_ALIAS.into(),
        "--ro-bind".into(),
        path(&prepared.patch)?,
        PATCH_ALIAS.into(),
    ];
    overlays.extend([
        "--ro-bind".into(),
        path(&prepared.preset)?,
        PRESET_ALIAS.into(),
        "--ro-bind".into(),
        path(&prepared.bridge)?,
        BRIDGE_ALIAS.into(),
    ]);
    for file in [&prepared.package, &prepared.profile_patch] {
        overlays.extend(["--ro-bind".into(), path(file)?, path(file)?]);
    }
    match (&prepared.transport_loader, model_socket) {
        (Some(loader), Some(socket)) => {
            if !std::fs::symlink_metadata(socket)?.file_type().is_socket() {
                bail!("model relay alias is not an owned Unix socket");
            }
            overlays.extend([
                "--ro-bind".into(),
                path(socket)?,
                crate::model_relay::SOCKET_ALIAS.into(),
                "--ro-bind".into(),
                path(loader)?,
                crate::model_relay::LOADER_ALIAS.into(),
            ]);
        }
        (None, None) => {}
        _ => bail!("strict model transport loader/socket pairing missing"),
    }
    if let Some(policy) = &prepared.provider_policy {
        if prepared.transport_loader.is_none() || model_socket.is_none() {
            bail!("strict provider policy requires a paired model transport");
        }
        overlays.extend([
            "--ro-bind".into(),
            path(policy)?,
            crate::model_relay::PROVIDER_POLICY_ALIAS.into(),
        ]);
    }
    let journal = prepared
        .patch
        .parent()
        .context("native alias journal directory missing")?;
    let manifest_path = journal.join("context-manifest.json");
    match std::fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("native context manifest must be a regular journal file");
            }
            let bytes = std::fs::read(&manifest_path)?;
            let envelope_path = journal.join("envelope.json");
            let envelope_metadata = std::fs::symlink_metadata(&envelope_path)?;
            if !envelope_metadata.is_file() || envelope_metadata.file_type().is_symlink() {
                bail!("native context envelope must be a regular journal file");
            }
            let envelope: ExecutionEnvelope =
                serde_json::from_slice(&std::fs::read(envelope_path)?)?;
            if sha256(&bytes) != envelope.context_manifest.sha256 {
                bail!("native context manifest differs from its frozen execution envelope");
            }
            let manifest: forgeflow_domain::ContextManifest = serde_json::from_slice(&bytes)?;
            let root = journal.join("context-artifacts");
            let mut seen = std::collections::BTreeSet::new();
            let mut total_bytes = 0usize;
            if !manifest.artifact_inputs.is_empty() {
                let metadata = std::fs::symlink_metadata(&root)?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    bail!("native context artifact directory must be a private journal directory");
                }
                overlays.extend(["--dir".into(), CONTEXT_ALIAS_ROOT.into()]);
            }
            for input in &manifest.artifact_inputs {
                forgeflow_domain::validate_relative_path(&input.logical_path)?;
                if !seen.insert(&input.logical_path)
                    || !forgeflow_domain::valid_digest(&input.artifact.sha256)
                {
                    bail!("native context artifact identity invalid or duplicated");
                }
                let identity = sha256(input.logical_path.as_bytes());
                let source = root.join(&identity);
                let metadata = std::fs::symlink_metadata(&source)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("native context artifact must be a regular verified input file");
                }
                let bytes = std::fs::read(&source)?;
                total_bytes = total_bytes
                    .checked_add(bytes.len())
                    .context("native context byte count overflow")?;
                if total_bytes > 32 * 1024 * 1024 || sha256(&bytes) != input.artifact.sha256 {
                    bail!("native context artifact digest or byte budget changed before mount");
                }
                // Expose only this declared, checked object. The private journal,
                // Worker environment and credential parent remain outside the
                // namespace. This stable alias does not alter the write set.
                overlays.extend([
                    "--ro-bind".into(),
                    path(&source)?,
                    format!("{CONTEXT_ALIAS_ROOT}/{identity}"),
                ]);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Legacy callers without a context manifest keep the old aliases;
            // production preparation always validates its frozen manifest.
        }
        Err(error) => return Err(error.into()),
    }
    overlays.extend(["--remount-ro".into(), "/tmp/forgeflow".into()]);
    spec.args.splice(separator..separator, overlays);
    Ok(())
}

/// Owns one exact attempt's socket. Closing transport cannot release allocation.
pub struct NativeController {
    pub socket_path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

/// Linux resolves the bind pathname through the open private directory while
/// creating the socket at its ordinary journal path. The descriptor alias is
/// only a bind input; mounts, durable records and cleanup keep the real path.
#[cfg(target_os = "linux")]
pub(crate) fn bind_private_socket(directory: &std::path::Path, name: &str) -> Result<UnixListener> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    };

    let expected = std::fs::symlink_metadata(directory)?;
    if !expected.is_dir() || expected.permissions().mode() & 0o777 != 0o700 {
        bail!("native RPC directory is not a private directory");
    }
    let directory_fd = std::fs::File::open(directory)?;
    let opened = directory_fd.metadata()?;
    if !opened.is_dir() || (opened.dev(), opened.ino()) != (expected.dev(), expected.ino()) {
        bail!("native RPC directory changed before socket bind");
    }
    let alias_directory = PathBuf::from(format!("/proc/self/fd/{}", directory_fd.as_raw_fd()));
    let alias_metadata = std::fs::metadata(&alias_directory)
        .context("native RPC directory descriptor alias unavailable")?;
    if (alias_metadata.dev(), alias_metadata.ino()) != (opened.dev(), opened.ino()) {
        bail!("native RPC directory descriptor alias identity changed");
    }
    if !matches!(name, "controller.sock" | "model.sock") {
        bail!("unknown private socket name");
    }
    let bind_path = alias_directory.join(name);
    if bind_path.as_os_str().len() > 100 {
        bail!("native Unix socket bind alias exceeds bounded platform path");
    }
    let listener = UnixListener::bind(&bind_path)
        .context("bind native RPC through private directory descriptor")?;
    let current = std::fs::symlink_metadata(directory)?;
    if !current.is_dir()
        || current.permissions().mode() & 0o777 != 0o700
        || (current.dev(), current.ino()) != (opened.dev(), opened.ino())
    {
        bail!("native RPC directory changed during socket bind");
    }
    let canonical_socket = std::fs::symlink_metadata(directory.join(name))?;
    let bound_socket = std::fs::symlink_metadata(&bind_path)?;
    if !canonical_socket.file_type().is_socket()
        || (canonical_socket.dev(), canonical_socket.ino())
            != (bound_socket.dev(), bound_socket.ino())
    {
        bail!("native RPC bound socket differs from journal path");
    }
    // File closes here, after bind and identity checks, before child startup.
    Ok(listener)
}

impl Drop for NativeController {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
impl NativeController {
    pub async fn start(
        client: ControlClient,
        envelope: ExecutionEnvelope,
        journal: Journal,
        timeout: Duration,
    ) -> Result<Self> {
        if timeout < Duration::from_millis(1)
            || timeout > Duration::from_millis(MAX_NATIVE_RPC_TIMEOUT_MS)
        {
            bail!("native RPC timeout must be 1ms..60s");
        }
        let limits = transport_limits(&journal, &envelope)?;
        if journal.path("native-controller.json").exists() {
            bail!("native controller journal already exists; canonical reconciliation required");
        }
        let directory = journal.path("native-rpc");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let socket_path = directory.join("controller.sock");
        let listener = if socket_path.as_os_str().len() <= 100 {
            UnixListener::bind(&socket_path)?
        } else {
            #[cfg(target_os = "linux")]
            {
                bind_private_socket(&directory, "controller.sock")?
            }
            #[cfg(not(target_os = "linux"))]
            bail!("native Unix socket path exceeds bounded platform path");
        };
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        durable_json(
            &journal.path("native-controller.json"),
            &json!({"schema_version":SCHEMA,"project_id":envelope.project_id,
                "task_id":envelope.task_id,"attempt_id":envelope.attempt_id,
                "generation":envelope.generation,"worker_id":envelope.worker_id,
                "execution_id":journal.execution_id()?,"socket_path":socket_path,
                "state":"TRANSPORT_BOUND","allocation_authority":"CANONICAL_POSTGRESQL",
                "transport_connection_limit":limits.rpc_connections}),
        )?;
        let slots = Arc::new(Semaphore::new(limits.rpc_connections));
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{
                        let Ok((stream, _))=accepted else {break;};
                        let Ok(permit)=slots.clone().try_acquire_owned() else {
                            // Dropping a saturated connection fails closed with no queued work.
                            continue;
                        };
                        let client=client.clone();
                        let envelope=envelope.clone();
                        let journal=journal.clone();
                        connections.spawn(async move {
                            let _permit=permit;
                            serve(stream,&client,&envelope,&journal,timeout).await;
                        });
                    }
                    _=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        Ok(Self { socket_path, task })
    }
}

fn validate_request<'a>(envelope: &ExecutionEnvelope, request: &'a Value) -> Result<&'a str> {
    let fields = request.as_object().context("RPC must be an object")?;
    if fields.get("schema_version").and_then(Value::as_str) != Some(SCHEMA)
        || fields.get("project_id").and_then(Value::as_str) != Some(envelope.project_id.as_str())
        || fields.get("task_id").and_then(Value::as_str) != Some(envelope.task_id.as_str())
        || fields.get("attempt_id").and_then(Value::as_str) != Some(envelope.attempt_id.as_str())
        || fields.get("generation").and_then(Value::as_i64) != Some(envelope.generation)
    {
        bail!("NATIVE_IDENTITY_MISMATCH");
    }
    let rpc_id = fields
        .get("rpc_id")
        .and_then(Value::as_str)
        .context("RPC_ID_REQUIRED")?;
    uuid::Uuid::parse_str(rpc_id).context("RPC_ID_INVALID")?;
    let operation = fields
        .get("operation")
        .and_then(Value::as_str)
        .context("RPC_OPERATION_REQUIRED")?;
    if !matches!(
        operation,
        "admit" | "model_request" | "model_settle" | "release" | "poll" | "cancel_ack" | "observe"
    ) {
        bail!("NATIVE_OPERATION_FORBIDDEN");
    }
    Ok(rpc_id)
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > MAX_FRAME_BYTES {
            bail!("RPC_FRAME_TOO_LARGE");
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .context("RPC_FRAME_INCOMPLETE")?;
    if bytes[newline + 1..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        bail!("RPC_MULTIPLE_FRAMES");
    }
    bytes.truncate(newline);
    Ok(bytes)
}

async fn serve(
    mut stream: UnixStream,
    client: &ControlClient,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    timeout: Duration,
) {
    let started = std::time::Instant::now();
    let mut phase = "frame_read";
    let mut identity: Option<(String, String)> = None;
    let exchange = async {
        let bytes = read_frame(&mut stream).await?;
        phase = "request_validation";
        let request: Value = serde_json::from_slice(&bytes)?;
        let rpc_id = validate_request(envelope, &request)?;
        identity = Some((
            rpc_id.to_owned(),
            request["operation"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned(),
        ));
        #[cfg(test)]
        tests::record_rpc_phase(rpc_id, "request_validated", started);
        if request["operation"] != "poll" {
            phase = "request_journal";
            let path = journal.path(&format!("native-rpc/request-{rpc_id}.json"));
            let recorded = request.clone();
            #[cfg(test)]
            let rpc_trace_id = rpc_id.to_owned();
            tokio::task::spawn_blocking(move || -> Result<()> {
                #[cfg(test)]
                tests::record_rpc_phase(&rpc_trace_id, "journal_start", started);
                #[cfg(test)]
                tests::wait_journal_hold(&rpc_trace_id);
                // Per-UUID atomic first publication preserves the first request
                // even for concurrent duplicate deliveries. Unrelated Agent RPCs
                // can fsync in parallel instead of sharing one serial disk lock.
                // This record never grants; every replay asks canonical authority.
                crate::attempt_preparation::durable_first_json(&path, &recorded)?;
                let metadata = std::fs::symlink_metadata(&path)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("RPC_REQUEST_JOURNAL_INVALID");
                }
                let previous: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                if previous != recorded {
                    bail!("RPC_IDEMPOTENCY_CONFLICT");
                }
                #[cfg(test)]
                tests::record_rpc_phase(&rpc_trace_id, "journal_finished", started);
                Ok(())
            })
            .await??;
        }
        // Poll has no grant, state mutation, or replayable snapshot. Validate
        // every identity and ask live canonical authority on each exchange;
        // persisting every liveness read would grow journals throughout a run.
        phase = "canonical_http";
        #[cfg(test)]
        tests::record_rpc_phase(rpc_id, "canonical_http_started", started);
        let response = client.native_rpc(envelope, rpc_id, &bytes, timeout).await?;
        #[cfg(test)]
        tests::record_rpc_phase(rpc_id, "canonical_http_finished", started);
        phase = "canonical_response_schema";
        if response.get("ok").and_then(Value::as_bool).is_none()
            || response.get("generation").and_then(Value::as_i64) != Some(envelope.generation)
        {
            bail!("RPC_INVALID_CANONICAL_RESPONSE");
        }
        Ok::<Value, anyhow::Error>(response)
    };
    let (response, failure) = match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(value)) => (value, None),
        Ok(Err(error)) => {
            let typed = error.downcast_ref::<NativeRpcFailure>();
            let code = typed
                .map(|v| v.code)
                .unwrap_or(if phase == "request_journal" {
                    "NATIVE_CONTROLLER_JOURNAL_ERROR"
                } else {
                    "NATIVE_CONTROLLER_PROTOCOL_REJECTED"
                });
            let record = json!({"phase":typed.map(|v| v.phase).unwrap_or(phase), "code":code,
                "http_status":typed.and_then(|v| v.http_status),
                "canonical_code":typed.and_then(|v| v.canonical_code.clone())});
            (
                json!({"ok":false,"generation":envelope.generation,"code":code}),
                Some(record),
            )
        }
        Err(_) => (
            json!({"ok":false,"generation":envelope.generation,"code":"NATIVE_CONTROLLER_TIMEOUT"}),
            Some(
                json!({"phase":phase,"code":"NATIVE_CONTROLLER_TIMEOUT","http_status":null,"canonical_code":null}),
            ),
        ),
    };
    #[cfg(test)]
    if let Some((rpc_id, _)) = &identity {
        tests::record_rpc_phase(rpc_id, "reply_ready", started);
    }
    let failure_task = failure.and_then(|mut record| {
        identity.map(|(rpc_id, operation)| {
            record["schema_version"] = json!("forgeflow.native-rpc-failure.v1");
            record["rpc_id"] = json!(rpc_id);
            record["operation"] = json!(operation);
            record["attempt_id"] = json!(envelope.attempt_id);
            record["generation"] = json!(envelope.generation);
            record["elapsed_ms"] = json!(started.elapsed().as_secs_f64() * 1000.0);
            let name = if operation == "poll" {
                // Preserve the first actual failed read, with bounded storage
                // even if a disconnected native process continues to poll.
                "native-rpc/poll-first-failure.json".to_owned()
            } else {
                format!("native-rpc/failure-{rpc_id}.json")
            };
            let path = journal.path(&name);
            tokio::task::spawn_blocking(move || {
                // Retain the first failed exchange for an exact retried UUID.
                if !path.exists() {
                    crate::attempt_preparation::durable_first_json(&path, &record)?;
                }
                Ok::<(), anyhow::Error>(())
            })
        })
    });
    if let Ok(mut bytes) = serde_json::to_vec(&response) {
        if bytes.len() <= MAX_FRAME_BYTES {
            bytes.push(b'\n');
            let _ =
                tokio::time::timeout(Duration::from_millis(250), stream.write_all(&bytes)).await;
        }
    }
    // The native client parses on socket EOF. Failure-journal fsync must not
    // extend its bounded reply time after the response has been written.
    drop(stream);
    if let Some(task) = failure_task {
        if !matches!(task.await, Ok(Ok(()))) {
            tracing::warn!("bounded native RPC failure journal could not persist");
        }
    }
}

/// A restarted worker never rebinds or adopts the old RPC namespace. Cleanup
/// follows the supervisor's fingerprint-bound stop, without allocating/releasing.
pub fn reconcile_transport(journal: &Journal, process_exit_confirmed: bool) -> Result<()> {
    let path = journal.path("native-controller.json");
    if !path.exists() {
        return Ok(());
    }
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let envelope: ExecutionEnvelope =
        serde_json::from_slice(&std::fs::read(journal.path("envelope.json"))?)?;
    if record["project_id"] != envelope.project_id
        || record["task_id"] != envelope.task_id
        || record["attempt_id"] != envelope.attempt_id
        || record["generation"] != envelope.generation
        || record["worker_id"] != envelope.worker_id
        || record["execution_id"] != journal.execution_id()?
    {
        bail!("native controller journal identity changed; transport retained for recovery");
    }
    record["state"] = json!(if process_exit_confirmed {
        "PROCESS_STOPPED_AWAITING_CANONICAL_RECONCILIATION"
    } else {
        "QUARANTINED"
    });
    durable_json(&path, &record)?;
    if process_exit_confirmed {
        match std::fs::remove_file(journal.path("native-rpc/controller.sock")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn project_roster_supports_128_without_fixed_owner_team_count() {
        let n = 128;
        let manifest = serde_json::json!({"role_catalog":{"planned_positions":n,"specialized_presets":n},
            "model_policy":{"route_id":"provider/model"}});
        let mut catalog = serde_json::json!({"schema_version":"forgeflow.agent-roles.v1","positions":n,
            "teams":[{"owner_id":"owner","team_id":"team","planned_agents":n}],
            "roster":(0..n).map(|i|serde_json::json!({"position_id":format!("agent-{i}"),
                "teammate_name":format!("member-{i}"),"preset_id":format!("preset-{i}"),
                "generic_preset_id":"forgeflow-implementer-v1","owner_id":"owner","owner_team_id":"team",
                "model_route":"provider/model"})).collect::<Vec<_>>()});
        let patch = serde_json::json!([{"insert":(0..n).map(|i|serde_json::json!({
            "name":"@deepseek-ai/dsh-agent-preset","config":{"id":format!("preset-{i}")}})).collect::<Vec<_>>()}]);
        assert!(super::validate_project_roster(&manifest, &catalog, &patch).is_ok());
        catalog["teams"][0]["planned_agents"] = serde_json::json!(127);
        assert!(super::validate_project_roster(&manifest, &catalog, &patch).is_err());
        catalog["teams"][0]["planned_agents"] = serde_json::json!(128);
        catalog["roster"][127] = catalog["roster"][0].clone();
        assert!(super::validate_project_roster(&manifest, &catalog, &patch).is_err());
    }

    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    // Test-only monotonic observations. No additional journal or production I/O.
    static RPC_PHASES: std::sync::OnceLock<Mutex<std::collections::BTreeMap<String, Vec<Value>>>> =
        std::sync::OnceLock::new();
    pub(super) fn record_rpc_phase(rpc_id: &str, phase: &'static str, started: std::time::Instant) {
        let mut map = RPC_PHASES
            .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
            .lock()
            .unwrap();
        if map.len() >= 128 && !map.contains_key(rpc_id) {
            return;
        }
        let values = map.entry(rpc_id.to_owned()).or_default();
        if values.len() < 16 {
            values.push(json!({"phase":phase,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0}));
        }
    }
    struct JournalHold {
        released: Mutex<bool>,
        changed: std::sync::Condvar,
    }
    static JOURNAL_HOLDS: std::sync::OnceLock<
        Mutex<std::collections::BTreeMap<String, Arc<JournalHold>>>,
    > = std::sync::OnceLock::new();
    struct JournalHoldGuard {
        rpc_id: String,
        hold: Arc<JournalHold>,
    }
    impl JournalHoldGuard {
        fn new(rpc_id: &str) -> Self {
            let hold = Arc::new(JournalHold {
                released: Mutex::new(false),
                changed: std::sync::Condvar::new(),
            });
            JOURNAL_HOLDS
                .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
                .lock()
                .unwrap()
                .insert(rpc_id.to_owned(), hold.clone());
            Self {
                rpc_id: rpc_id.to_owned(),
                hold,
            }
        }
        fn release(&self) {
            *self.hold.released.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.hold.changed.notify_all();
        }
    }
    impl Drop for JournalHoldGuard {
        fn drop(&mut self) {
            self.release();
            JOURNAL_HOLDS
                .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.rpc_id);
        }
    }
    pub(super) fn wait_journal_hold(rpc_id: &str) {
        let hold = JOURNAL_HOLDS
            .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
            .lock()
            .unwrap()
            .remove(rpc_id);
        if let Some(hold) = hold {
            let released = hold.released.lock().unwrap();
            // RAII releases even on assertion panic; a finite fallback also prevents an abandoned test thread.
            let _released = hold
                .changed
                .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                .unwrap();
        }
    }
    async fn rpc_diagnostic(
        api: &FakeApi,
        journal: &Journal,
        request: &Value,
        reply: &Value,
    ) -> Value {
        let rpc_id = request["rpc_id"].as_str().unwrap();
        let path = if request["operation"] == "poll" {
            journal.path("native-rpc/poll-first-failure.json")
        } else {
            journal.path(&format!("native-rpc/failure-{rpc_id}.json"))
        };
        if reply["ok"] == false {
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while !path.exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
        }
        let mut failure = serde_json::Map::new();
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                for field in [
                    "phase",
                    "code",
                    "http_status",
                    "canonical_code",
                    "elapsed_ms",
                ] {
                    if let Some(value) = value.get(field) {
                        failure.insert(field.into(), value.clone());
                    }
                }
            }
        }
        let phases = RPC_PHASES
            .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
            .lock()
            .unwrap()
            .get(rpc_id)
            .cloned()
            .unwrap_or_default();
        let http = api
            .observations
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["rpc_id"] == request["rpc_id"])
            .take(16)
            .cloned()
            .collect::<Vec<_>>();
        json!({"reply":{"ok":reply.get("ok"),"code":reply.get("code"),"generation":reply.get("generation")},"failure":failure,
            "worker_monotonic_phases":phases,"fake_http_monotonic":http,"fake_http_requests":api.requests.lock().unwrap().len(),"request_journal_exists":journal.path(&format!("native-rpc/request-{rpc_id}.json")).exists()})
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_context_alias_reads_pinned_input_and_denies_writes_or_private_parent() {
        use forgeflow_domain::{ArtifactRef, ContextArtifactInput, ContextManifest};
        use forgeflow_runtime::{ProcessSpec, SandboxInstance, SandboxProfile, sandbox_command};
        use std::collections::BTreeMap;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixListener;

        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let mut envelope = crate::tests::liveness_envelope();
        let journal =
            Journal::new(&temp.path().join("private-journals"), &envelope.attempt_id).unwrap();
        std::fs::create_dir_all(&journal.directory).unwrap();
        std::fs::set_permissions(&journal.directory, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let logical = "source-artifacts/contract-design.md";
        let identity = sha256(logical.as_bytes());
        let input_bytes = b"immutable-source-context-v1\n";
        let context = journal.path("context-artifacts");
        std::fs::create_dir(&context).unwrap();
        let source = context.join(&identity);
        std::fs::write(&source, input_bytes).unwrap();
        let manifest = ContextManifest {
            files: vec![],
            mandatory_paths: vec![logical.into()],
            artifact_inputs: vec![ContextArtifactInput {
                logical_path: logical.into(),
                artifact: ArtifactRef {
                    artifact_id: "actual-context-fixture".into(),
                    sha256: sha256(input_bytes),
                },
            }],
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        envelope.context_manifest.sha256 = sha256(&bytes);
        std::fs::write(journal.path("context-manifest.json"), bytes).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let host_secret = journal.path("worker.env");
        std::fs::write(&host_secret, b"private-parent-must-not-be-mounted").unwrap();
        let home = temp.path().join("managed-home");
        std::fs::create_dir(&home).unwrap();
        let prepared = ManagedAttempt {
            home: home.clone(),
            patch: journal.path("managed-native.patch.json"),
            package: home.join("package.json"),
            profile_patch: home.join("profile.patch.json"),
            preset: home.join("preset.patch.json"),
            bridge: home.join("bridge.mjs"),
            transport_loader: None,
            provider_policy: None,
        };
        for file in [
            &prepared.patch,
            &prepared.package,
            &prepared.profile_patch,
            &prepared.preset,
            &prepared.bridge,
        ] {
            std::fs::write(file, b"[]\n").unwrap();
        }
        let socket_path = journal.path("controller.sock");
        let socket_directory = std::fs::File::open(&journal.directory).unwrap();
        let socket_bind_path = format!(
            "/proc/self/fd/{}/controller.sock",
            socket_directory.as_raw_fd()
        );
        let _socket = UnixListener::bind(socket_bind_path).unwrap();
        let guard = std::env::var_os("FORGEFLOW_SANDBOX_GUARD_TEST_PROGRAM")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("forgeflow-sandbox-guard")
            });
        let bwrap = PathBuf::from("/usr/bin/bwrap");
        let sandbox = SandboxProfile {
            bwrap_sha256: sha256(&std::fs::read(&bwrap).unwrap()),
            bwrap_program: bwrap,
            guard_sha256: sha256(&std::fs::read(&guard).expect(
                "build the actual sandbox guard or set FORGEFLOW_SANDBOX_GUARD_TEST_PROGRAM",
            )),
            guard_program: guard,
            readonly_paths: vec!["/usr".into(), "/bin".into(), "/lib".into(), "/lib64".into()],
            network_allowed: false,
        };
        let alias = format!("{CONTEXT_ALIAS_ROOT}/{identity}");
        let script = "import pathlib,sys,os,stat\np=pathlib.Path(sys.argv[1])\nassert p.read_bytes()==b'immutable-source-context-v1\\n'\ns=os.stat('/dev/null')\nassert stat.S_ISCHR(s.st_mode) and (os.major(s.st_rdev),os.minor(s.st_rdev))==(1,3)\nwith open('/dev/null','wb') as sink:assert sink.write(b'discard-output')==14\nfor operation in (lambda:p.write_bytes(b'corrupt'),lambda:(p.parent/'undeclared.md').write_bytes(b'corrupt'),lambda:pathlib.Path(sys.argv[2]).read_bytes(),lambda:pathlib.Path('/dev/undeclared-device-file').write_bytes(b'corrupt')):\n try:operation()\n except OSError:pass\n else:raise AssertionError('readonly context, private parent or device-directory boundary failed')\nprint('READ_ONLY_CONTEXT_BOUNDARY_OK')";
        let original = ProcessSpec {
            program: "/usr/bin/python3".into(),
            args: vec![
                "-I".into(),
                "-B".into(),
                "-c".into(),
                script.into(),
                alias,
                host_secret.to_string_lossy().into_owned(),
            ],
            env: BTreeMap::new(),
            cwd: workspace.clone(),
            stdin: vec![],
        };
        let base = sandbox_command(
            original,
            &sandbox,
            &SandboxInstance {
                workspace: workspace.clone(),
                write_set: vec![],
                allow_git_metadata: false,
                writable_mounts: vec![native_null_output_mount().unwrap()],
            },
        )
        .unwrap();
        let mut mounted = base.clone();
        mount_native_aliases(&mut mounted, &prepared, &socket_path, None).unwrap();
        let output = std::process::Command::new(&mounted.program)
            .args(&mounted.args)
            .env_clear()
            .current_dir(&workspace)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "actual readonly alias sandbox failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"READ_ONLY_CONTEXT_BOUNDARY_OK\n");
        assert_eq!(std::fs::read(&source).unwrap(), input_bytes);
        assert_eq!(
            std::fs::read(&host_secret).unwrap(),
            b"private-parent-must-not-be-mounted"
        );
        std::fs::write(&source, b"changed-before-mount").unwrap();
        let mut changed = base;
        assert!(mount_native_aliases(&mut changed, &prepared, &socket_path, None).is_err());
    }

    #[test]
    fn transport_capacity_uses_frozen_pool_and_rejects_profile_drift() {
        use forgeflow_domain::{PhysicalLimitsPolicy, PhysicalResourceBinding, ResourceVector};
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        let root = ResourceVector {
            active_slot: 1,
            coding_slot: 1,
            cpu_units: 1000,
            memory_bytes: 512 * 1024 * 1024,
            provider_inflight: 1,
            ..Default::default()
        };
        let child = ResourceVector {
            active_slot: 1,
            coding_slot: 1,
            cpu_units: 125,
            memory_bytes: 64 * 1024 * 1024,
            provider_inflight: 1,
            ..Default::default()
        };
        let physical = PhysicalLimitsPolicy {
            schema_version: "forgeflow.physical-limits.v1".into(),
            required: true,
            cpu_units_per_cpu: 1000,
            period_us: 100000,
            pids_max: 256,
            swap_max_bytes: 0,
            memory_oom_group: true,
        };
        for live in [25, 58] {
            let pool = PhysicalResourceBinding::new(
                envelope.resource_profile_id.clone(),
                root.clone(),
                child.clone(),
                live - 1,
                physical.clone(),
            )
            .unwrap();
            let mut bindings = json!({
                "resource_profile": {
                    "id": envelope.resource_profile_id,
                    "physical_limits": physical,
                    "native_child_policy": {
                        "schema_version": "forgeflow.native-child-policy.v1",
                        "enabled": true,
                        "max_live_agents": live,
                        "model_inflight_limit": 20,
                        "child_resources": child,
                    }
                },
                "physical_resources": pool,
            });
            let path = journal.path("execution-bindings.json");
            durable_json(&path, &bindings).unwrap();
            let limits = transport_limits(&journal, &envelope).unwrap();
            assert_eq!(limits.rpc_connections, live as usize * 2 + 4);
            assert_eq!(limits.model_connections, 20);
            bindings["resource_profile"]["native_child_policy"]["max_live_agents"] =
                json!(live + 1);
            durable_json(&path, &bindings).unwrap();
            assert!(transport_limits(&journal, &envelope).is_err());
            bindings["resource_profile"]["native_child_policy"]["max_live_agents"] = json!(live);
            bindings["physical_resources"]["reservation_sha256"] = json!("0".repeat(64));
            durable_json(&path, &bindings).unwrap();
            assert!(transport_limits(&journal, &envelope).is_err());
        }
    }
    struct FakeApi {
        url: String,
        requests: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
        response: Arc<Mutex<Value>>,
        delay: Arc<AtomicU64>,
        status: Arc<AtomicU64>,
        observations: Arc<Mutex<Vec<Value>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for FakeApi {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl FakeApi {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let response = Arc::new(Mutex::new(
                json!({"ok":true,"generation":1,"revoked":false}),
            ));
            let delay = Arc::new(AtomicU64::new(0));
            let status = Arc::new(AtomicU64::new(200));
            let observations = Arc::new(Mutex::new(Vec::new()));
            let trace = observations.clone();
            let clock = std::time::Instant::now();
            let reply_status = status.clone();
            let recorded = requests.clone();
            let answer = response.clone();
            let latency = delay.clone();
            let task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted=listener.accept()=>{
                            let (mut socket,_)=accepted.unwrap();
                            let recorded=recorded.clone();let answer=answer.clone();let latency=latency.clone();let reply_status=reply_status.clone();let trace=trace.clone();
                            let accepted_ms=clock.elapsed().as_secs_f64()*1000.0;
                            connections.spawn(async move {
                                let mut bytes=Vec::new();let mut buffer=[0;4096];
                                let end=loop {
                                    let count=socket.read(&mut buffer).await.unwrap();if count==0{return;}
                                    bytes.extend_from_slice(&buffer[..count]);
                                    if let Some(at)=bytes.windows(4).position(|row|row==b"\r\n\r\n") {break at+4;}
                                    assert!(bytes.len()<65536);
                                };
                                let headers=String::from_utf8(bytes[..end].to_vec()).unwrap();
                                let length=headers.lines().find_map(|line|{let (name,value)=line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length").then(||value.trim().parse::<usize>().unwrap())}).unwrap_or(0);
                                while bytes.len()<end+length {
                                    let count=socket.read(&mut buffer).await.unwrap();if count==0{return;}
                                    bytes.extend_from_slice(&buffer[..count]);
                                }
                                recorded.lock().unwrap().push((headers,bytes[end..end+length].to_vec()));
                                let rpc_id=serde_json::from_slice::<Value>(&bytes[end..end+length]).ok().and_then(|v|v["rpc_id"].as_str().map(str::to_owned)).unwrap_or_default();
                                let delay_ms=latency.load(Ordering::SeqCst);
                                {let mut trace=trace.lock().unwrap();if trace.len()<512 {trace.push(json!({"rpc_id":rpc_id,"phase":"request_received","accepted_ms":accepted_ms,"elapsed_ms":clock.elapsed().as_secs_f64()*1000.0,"delay_ms":delay_ms}));}}
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                let body=serde_json::to_vec(&*answer.lock().unwrap()).unwrap();
                                let status=reply_status.load(Ordering::SeqCst);
                                let header=format!("HTTP/1.1 {} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",status,body.len());
                                let headers_written=socket.write_all(header.as_bytes()).await.is_ok();let body_written=socket.write_all(&body).await.is_ok();
                                {let mut trace=trace.lock().unwrap();if trace.len()<512 {trace.push(json!({"rpc_id":rpc_id,"phase":"response_written","elapsed_ms":clock.elapsed().as_secs_f64()*1000.0,"status":status,"headers_written":headers_written,"body_written":body_written,"body_bytes":body.len()}));}}
                            });
                        }
                        _=connections.join_next(),if !connections.is_empty()=>{}
                    }
                }
            });
            Self {
                url,
                requests,
                response,
                delay,
                status,
                observations,
                task,
            }
        }
    }
    fn request(envelope: &ExecutionEnvelope) -> Value {
        json!({"schema_version":SCHEMA,"rpc_id":uuid::Uuid::new_v4(),"operation":"observe",
            "event":"workflow/start","value":{},
            "project_id":envelope.project_id,"task_id":envelope.task_id,"attempt_id":envelope.attempt_id,"generation":envelope.generation})
    }
    fn poll_request(envelope: &ExecutionEnvelope) -> Value {
        json!({"schema_version":SCHEMA,"rpc_id":uuid::Uuid::new_v4(),"operation":"poll",
            "project_id":envelope.project_id,"task_id":envelope.task_id,"attempt_id":envelope.attempt_id,"generation":envelope.generation})
    }
    /// Handler persistence/replay fixture only. It does not prove socket admission or real Store qualification.
    async fn call_handler_with_default_budget(
        client: &ControlClient,
        envelope: &ExecutionEnvelope,
        journal: &Journal,
        value: &Value,
    ) -> Value {
        let (mut writer, stream) = UnixStream::pair().unwrap();
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        let exchange = async {
            writer.write_all(&bytes).await.unwrap();
            writer.shutdown().await.unwrap();
            let mut reply = Vec::new();
            writer.read_to_end(&mut reply).await.unwrap();
            serde_json::from_slice::<Value>(&reply).unwrap()
        };
        let ((), reply) = tokio::join!(
            serve(
                stream,
                client,
                envelope,
                journal,
                Duration::from_millis(crate::default_native_rpc_timeout())
            ),
            exchange
        );
        reply
    }
    async fn exchange(path: &std::path::Path, bytes: &[u8]) -> Value {
        let mut socket = UnixStream::connect(path).await.unwrap();
        socket.write_all(bytes).await.unwrap();
        socket.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&response).unwrap()
    }
    async fn call(path: &std::path::Path, value: &Value) -> Value {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        exchange(path, &bytes).await
    }

    fn managed_fixture(root: &std::path::Path) -> (HeadlessProfile, ManagedDshConfig) {
        let files=[("node",b"pinned-native-executable".to_vec()),("entry.js",b"pinned-native-entrypoint".to_vec()),
            ("mode.json",serde_json::to_vec(&json!({"schema_version":"forgeflow.dsh-mode.v2","id":"mode-test","managed_bridge":{"protocol":SCHEMA}})).unwrap()),
            ("preset.yml",b"[]\n".to_vec()),("bridge.mjs",b"pinned-managed-plugin".to_vec()),
            ("model.json",serde_json::to_vec(&json!([{"id":"agent-default-model","config":{"provider":"selected","model":"selected"}},{"id":"llm-pi-ai","config":{}}])).unwrap()),
            ("credentials.yml",b"test-provider: private-test-credential\n".to_vec()),
            ("runtime-package.json",b"{\"version\":\"1.2.3\"}".to_vec())];
        let mut pins = Vec::new();
        let mut inventory = serde_json::Map::new();
        for (name, bytes) in files {
            let path = root.join(name);
            std::fs::write(&path, &bytes).unwrap();
            let digest = sha256(&bytes);
            inventory.insert(
                std::fs::canonicalize(&path)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                json!(digest),
            );
            pins.push(forgeflow_executors::ArtifactPin {
                path,
                sha256: digest,
            });
        }
        let doctor = root.join("doctor.json");
        let bytes=serde_json::to_vec(&json!({"schema_version":"forgeflow.managed-doctor.v1","mode_id":"mode-test",
            "executor_profile_id":"profile-test","native_profile":"headless","bridge_schema_version":SCHEMA,"exit_code":0,
            "composition_sha256":"a".repeat(64),"runtime_package":root.join("runtime-package.json"),"runtime_version":"1.2.3","artifact_sha256":inventory})).unwrap();
        std::fs::write(&doctor, &bytes).unwrap();
        pins.push(forgeflow_executors::ArtifactPin {
            path: doctor.clone(),
            sha256: sha256(&bytes),
        });
        let profile = HeadlessProfile {
            id: "profile-test".into(),
            program: root.join("node"),
            prefix_args: vec![root.join("entry.js").to_string_lossy().into_owned()],
            home: root.join("source-home"),
            profile_name: "headless".into(),
            artifact_pins: pins,
            resume_verified: false,
            model_route_id: "route-test".into(),
            gateway_coverage_verified: false,
        };
        std::fs::create_dir(&profile.home).unwrap();
        std::fs::write(
            profile.home.join("personal-unused.yml"),
            b"must-not-be-copied",
        )
        .unwrap();
        let config = ManagedDshConfig {
            mode_id: "mode-test".into(),
            mode_manifest: root.join("mode.json"),
            preset_patch: root.join("preset.yml"),
            bridge_plugin: root.join("bridge.mjs"),
            selected_model_config: root.join("model.json"),
            credentials: root.join("credentials.yml"),
            doctor,
            rpc_timeout_ms: 500,
            model_relay: None,
        };
        (profile, config)
    }

    #[test]
    fn managed_home_copies_selected_inputs_and_rejects_source_or_runtime_drift() {
        let temp = tempfile::tempdir().unwrap();
        let (mut profile, config) = managed_fixture(temp.path());
        verify_managed(&profile, &config).unwrap();
        let envelope = crate::tests::liveness_envelope();
        let journal = Journal::new(&temp.path().join("journals"), &envelope.attempt_id).unwrap();
        let prepared = prepare_managed_home(
            &profile,
            &config,
            &envelope,
            &journal,
            temp.path().join("private-home"),
            true,
            None,
            temp.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(prepared.home.join("cordis.patch.yml")).unwrap(),
            std::fs::read(&config.selected_model_config).unwrap()
        );
        assert!(!prepared.home.join("personal-unused.yml").exists());
        let patch: Value =
            serde_json::from_slice(&std::fs::read(&prepared.patch).unwrap()).unwrap();
        assert_eq!(patch[0]["insert"][0]["name"], BRIDGE_ALIAS);
        assert_eq!(patch[0]["insert"][0]["config"]["socket_path"], SOCKET_ALIAS);
        assert_eq!(
            patch[0]["insert"][0]["config"]["attempt_id"],
            envelope.attempt_id
        );
        assert!(
            prepare_managed_home(
                &profile,
                &config,
                &envelope,
                &journal,
                prepared.home,
                true,
                None,
                temp.path(),
            )
            .is_err()
        );
        let original = std::fs::read(&config.selected_model_config).unwrap();
        std::fs::write(&config.selected_model_config, b"[]").unwrap();
        assert!(verify_managed(&profile, &config).is_err());
        std::fs::write(&config.selected_model_config, original).unwrap();
        let mut doctor: Value =
            serde_json::from_slice(&std::fs::read(&config.doctor).unwrap()).unwrap();
        doctor["runtime_version"] = json!("wrong-version");
        let bytes = serde_json::to_vec(&doctor).unwrap();
        std::fs::write(&config.doctor, &bytes).unwrap();
        profile
            .artifact_pins
            .iter_mut()
            .find(|pin| pin.path == config.doctor)
            .unwrap()
            .sha256 = sha256(&bytes);
        assert!(verify_managed(&profile, &config).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unix_rpc_long_private_data_root_preserves_canonical_socket_and_reconciliation() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{FileTypeExt, MetadataExt},
        };

        let api = FakeApi::start().await;
        let temp = tempfile::tempdir().unwrap();
        let root = temp
            .path()
            .join(format!("private-worker-data-{}", "x".repeat(120)));
        let mut envelope = crate::tests::liveness_envelope();
        envelope.attempt_id = uuid::Uuid::new_v4().to_string();
        let journal = Journal::new(&root, &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let controller = NativeController::start(
            ControlClient::new(&api.url, "private-test-worker-token".into()).unwrap(),
            envelope.clone(),
            journal.clone(),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        let actual_socket = journal.path("native-rpc/controller.sock");
        assert!(actual_socket.as_os_str().len() > 108);
        assert_eq!(controller.socket_path, actual_socket);
        let directory = std::fs::File::open(actual_socket.parent().unwrap()).unwrap();
        assert_eq!(
            directory.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        let client_alias = PathBuf::from(format!(
            "/proc/self/fd/{}/controller.sock",
            directory.as_raw_fd()
        ));
        assert!(client_alias.as_os_str().len() <= 100);
        let socket = std::fs::symlink_metadata(&actual_socket).unwrap();
        let alias_socket = std::fs::symlink_metadata(&client_alias).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            (socket.dev(), socket.ino()),
            (alias_socket.dev(), alias_socket.ino())
        );
        let mut record: Value =
            serde_json::from_slice(&std::fs::read(journal.path("native-controller.json")).unwrap())
                .unwrap();
        assert_eq!(record["socket_path"], json!(actual_socket));
        assert_eq!(record["attempt_id"], envelope.attempt_id);
        assert_eq!(record["generation"], envelope.generation);
        assert_eq!(record["execution_id"], journal.execution_id().unwrap());
        assert_eq!(record["state"], "TRANSPORT_BOUND");
        assert!(
            NativeController::start(
                ControlClient::new(&api.url, "private-test-worker-token".into()).unwrap(),
                envelope.clone(),
                journal.clone(),
                Duration::from_millis(500),
            )
            .await
            .is_err()
        );
        // This case qualifies long-path transport and scope, independently of first-publication disk latency.
        let original = poll_request(&envelope);
        for field in ["project_id", "task_id", "attempt_id"] {
            let mut wrong = original.clone();
            wrong[field] = json!("other");
            assert_eq!(call(&client_alias, &wrong).await["ok"], false);
        }
        let mut stale = original.clone();
        stale["generation"] = json!(2);
        assert_eq!(call(&client_alias, &stale).await["ok"], false);
        assert!(api.requests.lock().unwrap().is_empty());
        let reply = call(&client_alias, &original).await;
        let diagnostic = rpc_diagnostic(&api, &journal, &original, &reply).await;
        assert_eq!(reply["ok"], true, "bounded_rpc_diagnostic={diagnostic}");
        {
            let requests = api.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].0.starts_with(&format!(
                "POST /api/v1/attempts/{}/native-controller ",
                envelope.attempt_id
            )));
            assert_eq!(requests[0].1, serde_json::to_vec(&original).unwrap());
        }
        let rpc_id = original["rpc_id"].as_str().unwrap();
        assert!(
            !journal
                .path(&format!("native-rpc/request-{rpc_id}.json"))
                .exists(),
            "poll must not create a mutation intent journal"
        );
        drop(directory);
        assert!(actual_socket.exists());
        controller.task.abort();
        tokio::task::yield_now().await;
        reconcile_transport(&journal, false).unwrap();
        assert!(actual_socket.exists());
        record =
            serde_json::from_slice(&std::fs::read(journal.path("native-controller.json")).unwrap())
                .unwrap();
        assert_eq!(record["state"], "QUARANTINED");
        assert_eq!(record["socket_path"], json!(actual_socket));
        reconcile_transport(&journal, true).unwrap();
        assert!(!actual_socket.exists());
        record =
            serde_json::from_slice(&std::fs::read(journal.path("native-controller.json")).unwrap())
                .unwrap();
        assert_eq!(
            record["state"],
            "PROCESS_STOPPED_AWAITING_CANONICAL_RECONCILIATION"
        );
        drop(controller);
    }

    #[tokio::test]
    async fn unix_rpc_is_private_identity_bound_and_replays_only_through_canonical_api() {
        let api = FakeApi::start().await;
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let client = ControlClient::new(&api.url, "private-test-worker-token".into()).unwrap();
        let controller = NativeController::start(
            client,
            envelope.clone(),
            journal.clone(),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::metadata(controller.socket_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&controller.socket_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let original = request(&envelope);
        for field in ["project_id", "task_id", "attempt_id"] {
            let mut wrong = original.clone();
            wrong[field] = json!("other");
            assert_eq!(call(&controller.socket_path, &wrong).await["ok"], false);
        }
        let mut stale = original.clone();
        stale["generation"] = json!(2);
        assert_eq!(call(&controller.socket_path, &stale).await["ok"], false);
        for operation in ["root_release", "revoke", "process_stop"] {
            let mut denied = original.clone();
            denied["operation"] = json!(operation);
            assert_eq!(call(&controller.socket_path, &denied).await["ok"], false);
        }
        assert!(api.requests.lock().unwrap().is_empty());
        assert_eq!(call(&controller.socket_path, &original).await["ok"], true);
        assert_eq!(call(&controller.socket_path, &original).await["ok"], true);
        {
            let requests = api.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(
                requests[0]
                    .0
                    .starts_with("POST /api/v1/attempts/attempt-live/native-controller ")
            );
            assert!(
                requests[0]
                    .0
                    .to_ascii_lowercase()
                    .contains("x-forgeflow-worker-id: worker-live")
            );
            assert_eq!(requests[0].1, serde_json::to_vec(&original).unwrap());
            assert_eq!(requests[0].1, requests[1].1);
        }
        let mut changed = original.clone();
        changed["operation"] = json!("release");
        assert_eq!(call(&controller.socket_path, &changed).await["ok"], false);
        assert_eq!(api.requests.lock().unwrap().len(), 2);
        let poll = json!({"schema_version":SCHEMA,"rpc_id":uuid::Uuid::new_v4(),"operation":"poll",
            "project_id":envelope.project_id,"task_id":envelope.task_id,"attempt_id":envelope.attempt_id,"generation":envelope.generation});
        assert_eq!(call(&controller.socket_path, &poll).await["revoked"], false);
        *api.response.lock().unwrap() = json!({"ok":true,"generation":1,"revoked":true});
        // The same poll UUID is a fresh authenticated read, never a cached
        // authority response or a durable frame. Mutations above stay fenced.
        assert_eq!(call(&controller.socket_path, &poll).await["revoked"], true);
        assert_eq!(api.requests.lock().unwrap().len(), 4);
        assert!(
            !journal
                .path(&format!(
                    "native-rpc/request-{}.json",
                    poll["rpc_id"].as_str().unwrap()
                ))
                .exists()
        );
        let path = controller.socket_path.clone();
        drop(controller);
        reconcile_transport(&journal, false).unwrap();
        assert!(!path.exists());
        assert_eq!(
            serde_json::from_slice::<Value>(
                &std::fs::read(journal.path("native-controller.json")).unwrap()
            )
            .unwrap()["state"],
            "QUARANTINED"
        );
    }

    #[tokio::test]
    async fn unix_rpc_fresh_journal_timeout_retains_intent_and_replay_rechecks_canonical() {
        let api = FakeApi::start().await;
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let client = ControlClient::new(&api.url, "private-test-worker-token".into()).unwrap();
        let controller = NativeController::start(
            client.clone(),
            envelope.clone(),
            journal.clone(),
            Duration::from_millis(150),
        )
        .await
        .unwrap();
        let original = request(&envelope);
        let rpc_id = original["rpc_id"].as_str().unwrap();
        let hold = JournalHoldGuard::new(rpc_id);
        let started = tokio::time::Instant::now();
        let reply = call(&controller.socket_path, &original).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["code"], "NATIVE_CONTROLLER_TIMEOUT");
        for field in [
            "allocation_id",
            "request_grant_id",
            "admission",
            "resources",
        ] {
            assert!(reply.get(field).is_none());
        }
        let diagnostic = rpc_diagnostic(&api, &journal, &original, &reply).await;
        assert_eq!(
            diagnostic["failure"]["phase"], "request_journal",
            "bounded_rpc_diagnostic={diagnostic}"
        );
        assert_eq!(diagnostic["fake_http_requests"], 0);
        let intent = journal.path(&format!("native-rpc/request-{rpc_id}.json"));
        assert!(
            !intent.exists(),
            "held fresh publication must not expose an intent yet"
        );
        hold.release();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let finished = RPC_PHASES
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .get(rpc_id)
                    .is_some_and(|phases| {
                        phases
                            .iter()
                            .any(|value| value["phase"] == "journal_finished")
                    });
                if finished {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let original_bytes = std::fs::read(&intent).unwrap();
        assert_eq!(original_bytes, serde_json::to_vec(&original).unwrap());
        assert!(
            api.requests.lock().unwrap().is_empty(),
            "completion of an expired local publication must not send HTTP"
        );
        // This is a handler-only persistence/replay test using the unchanged product default 2000ms.
        // It does not assert that fresh durable mutations fit a 150ms transport budget.
        assert_eq!(crate::default_native_rpc_timeout(), 2000);
        let reply = call_handler_with_default_budget(&client, &envelope, &journal, &original).await;
        assert_eq!(
            reply["ok"],
            true,
            "bounded_rpc_diagnostic={}",
            rpc_diagnostic(&api, &journal, &original, &reply).await
        );
        assert_eq!(api.requests.lock().unwrap().len(), 1);
        *api.response.lock().unwrap() =
            json!({"ok":false,"generation":envelope.generation,"revoked":true});
        let replay =
            call_handler_with_default_budget(&client, &envelope, &journal, &original).await;
        assert_eq!(replay["ok"], false);
        assert_eq!(
            replay["revoked"], true,
            "same UUID must ask live canonical authority, not return the previous grant"
        );
        assert_eq!(api.requests.lock().unwrap().len(), 2);
        let mut stale = original.clone();
        stale["generation"] = json!(2);
        assert_eq!(
            call_handler_with_default_budget(&client, &envelope, &journal, &stale).await["ok"],
            false
        );
        let mut changed = original.clone();
        changed["value"] = json!({"changed":true});
        let refused =
            call_handler_with_default_budget(&client, &envelope, &journal, &changed).await;
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["code"], "NATIVE_CONTROLLER_JOURNAL_ERROR");
        assert_eq!(
            api.requests.lock().unwrap().len(),
            2,
            "stale generation or changed same-UUID payload must not ask canonical authority"
        );
        assert_eq!(std::fs::read(intent).unwrap(), original_bytes);
        drop(hold);
        drop(controller);
        reconcile_transport(&journal, true).unwrap();
    }

    #[tokio::test]
    async fn unix_rpc_bounds_http_delays_stale_responses_and_frames_without_local_grants() {
        let api = FakeApi::start().await;
        let temp = tempfile::tempdir().unwrap();
        let envelope = crate::tests::liveness_envelope();
        let journal = Journal::new(temp.path(), &envelope.attempt_id).unwrap();
        durable_json(&journal.path("envelope.json"), &envelope).unwrap();
        let controller = NativeController::start(
            ControlClient::new(&api.url, "private-test-worker-token".into()).unwrap(),
            envelope.clone(),
            journal.clone(),
            Duration::from_millis(150),
        )
        .await
        .unwrap();
        api.delay.store(1500, Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        // Poll intentionally has no mutation journal: this oracle isolates the HTTP deadline.
        // Fresh mutation durability and its timeout are exercised independently below.
        let delayed = poll_request(&envelope);
        let reply = call(&controller.socket_path, &delayed).await;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["code"], "NATIVE_CONTROLLER_TIMEOUT");
        let delayed_path = journal.path("native-rpc/poll-first-failure.json");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !delayed_path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let diagnostic: Value =
            serde_json::from_slice(&std::fs::read(&delayed_path).unwrap()).unwrap();
        assert_eq!(diagnostic["rpc_id"], delayed["rpc_id"]);
        assert_eq!(diagnostic["code"], "NATIVE_CONTROLLER_TIMEOUT");
        assert_eq!(diagnostic["phase"], "canonical_http");
        assert_eq!(
            api.requests.lock().unwrap().len(),
            1,
            "slow-HTTP oracle must actually reach HTTP"
        );
        assert!(diagnostic["elapsed_ms"].as_f64().unwrap() <= 1000.0);
        assert!(started.elapsed() < Duration::from_secs(1));
        // Each HTTP failure uses its own journal because poll-first-failure is immutable.
        let stale_api = FakeApi::start().await;
        let mut stale_envelope = envelope.clone();
        stale_envelope.attempt_id = uuid::Uuid::new_v4().to_string();
        let stale_journal =
            Journal::new(&temp.path().join("stale-case"), &stale_envelope.attempt_id).unwrap();
        durable_json(&stale_journal.path("envelope.json"), &stale_envelope).unwrap();
        let stale_controller = NativeController::start(
            ControlClient::new(&stale_api.url, "private-test-worker-token".into()).unwrap(),
            stale_envelope.clone(),
            stale_journal.clone(),
            Duration::from_millis(150),
        )
        .await
        .unwrap();
        *stale_api.response.lock().unwrap() =
            json!({"ok":true,"generation":2,"allocation_id":"untrusted"});
        let stale_request = poll_request(&stale_envelope);
        let stale_reply = call(&stale_controller.socket_path, &stale_request).await;
        assert_eq!(stale_reply["ok"], false);
        assert_eq!(
            stale_reply["code"],
            "NATIVE_CONTROLLER_RESPONSE_INVALID",
            "bounded_rpc_diagnostic={}",
            rpc_diagnostic(&stale_api, &stale_journal, &stale_request, &stale_reply).await
        );
        assert!(stale_reply.get("allocation_id").is_none());
        let rejected_api = FakeApi::start().await;
        let mut rejected_envelope = envelope.clone();
        rejected_envelope.attempt_id = uuid::Uuid::new_v4().to_string();
        let rejected_journal = Journal::new(
            &temp.path().join("rejected-case"),
            &rejected_envelope.attempt_id,
        )
        .unwrap();
        durable_json(&rejected_journal.path("envelope.json"), &rejected_envelope).unwrap();
        let rejected_controller = NativeController::start(
            ControlClient::new(&rejected_api.url, "private-test-worker-token".into()).unwrap(),
            rejected_envelope.clone(),
            rejected_journal.clone(),
            Duration::from_millis(150),
        )
        .await
        .unwrap();
        rejected_api.status.store(409, Ordering::SeqCst);
        *rejected_api.response.lock().unwrap() = json!({"code":"NATIVE_IDENTITY_STALE","message":"private-test-worker-token secret body"});
        let rejected = poll_request(&rejected_envelope);
        let reply = call(&rejected_controller.socket_path, &rejected).await;
        let diagnostic = rpc_diagnostic(&rejected_api, &rejected_journal, &rejected, &reply).await;
        assert_eq!(
            reply["code"], "NATIVE_CONTROLLER_CANONICAL_REJECTED",
            "bounded_rpc_diagnostic={diagnostic}"
        );
        let rejected_path = rejected_journal.path("native-rpc/poll-first-failure.json");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !rejected_path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let raw = std::fs::read(&rejected_path).unwrap();
        let diagnostic: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(diagnostic["http_status"], 409);
        assert_eq!(diagnostic["canonical_code"], "NATIVE_IDENTITY_STALE");
        assert_eq!(diagnostic["phase"], "canonical_http_status");
        assert!(
            !String::from_utf8(raw)
                .unwrap()
                .contains("private-test-worker-token")
        );
        let count = rejected_api.requests.lock().unwrap().len();
        let mut frame = vec![b' '; MAX_FRAME_BYTES + 1];
        frame.push(b'\n');
        assert_eq!(
            exchange(&rejected_controller.socket_path, &frame).await["ok"],
            false
        );
        let value = serde_json::to_string(&request(&rejected_envelope)).unwrap();
        assert_eq!(
            exchange(
                &rejected_controller.socket_path,
                format!("{value}\n{value}\n").as_bytes()
            )
            .await["ok"],
            false
        );
        assert_eq!(rejected_api.requests.lock().unwrap().len(), count);
        drop(controller);
        reconcile_transport(&journal, true).unwrap();
        assert!(
            NativeController::start(
                ControlClient::new(&api.url, "private-test-worker-token".into()).unwrap(),
                envelope,
                journal,
                Duration::from_millis(150)
            )
            .await
            .is_err()
        );
    }
}
