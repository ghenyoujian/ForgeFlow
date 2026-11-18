//! PostgreSQL authority for in-process DSH collaboration.
//! Children share the parent task Owner, write set and independent verifier.
//! These reservations do not establish per-child OS isolation or monetary budgets.
use super::*;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeChildPolicy {
    pub schema_version: String,
    pub enabled: bool,
    pub max_live_agents: u32,
    pub max_lifecycles: u32,
    pub max_delegation_depth: u32,
    pub model_inflight_limit: u32,
    pub child_resources: ResourceVector,
}
impl Default for NativeChildPolicy {
    fn default() -> Self {
        Self {
            schema_version: "forgeflow.native-child-policy.v1".into(),
            enabled: false,
            max_live_agents: 1,
            max_lifecycles: 1,
            max_delegation_depth: 0,
            model_inflight_limit: 1,
            child_resources: ResourceVector::default(),
        }
    }
}
impl NativeChildPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != "forgeflow.native-child-policy.v1"
            || self.max_live_agents == 0
            || self.max_lifecycles == 0
            || self.max_lifecycles < self.max_live_agents
            || self.model_inflight_limit == 0
            || (self.enabled
                && (self.max_delegation_depth == 0 || self.child_resources.active_slot == 0))
        {
            return Err(err(
                "NATIVE_POLICY_INVALID",
                "finite native lifecycle, depth, model and complete child resource bounds required",
            ));
        }
        for (_, amount) in self.child_resources.dimensions() {
            i64v(amount)?;
        }
        Ok(())
    }
}
/// Derive the complete reservation from immutable configuration, never current
/// task state at native launch. Absence means legacy separately charged children.
pub(crate) fn physical_binding_from_profile(
    profile: &Value,
    profile_id: &str,
    root: &ResourceVector,
) -> Result<Option<PhysicalResourceBinding>> {
    let Some(limits) = profile.get("physical_limits") else {
        return Ok(None);
    };
    if profile.get("id").and_then(Value::as_str) != Some(profile_id) {
        return Err(err(
            "PHYSICAL_POLICY_INVALID",
            "resource profile identity mismatch",
        ));
    }
    let limits: PhysicalLimitsPolicy = decode(limits.clone())?;
    let policy = match profile.get("native_child_policy") {
        Some(value) => decode::<NativeChildPolicy>(value.clone())?,
        None => NativeChildPolicy::default(),
    };
    policy.validate()?;
    let children = if policy.enabled {
        policy.max_live_agents - 1
    } else {
        0
    };
    Ok(Some(PhysicalResourceBinding::new(
        profile_id.to_owned(),
        root.clone(),
        policy.child_resources,
        children,
        limits,
    )?))
}

pub(crate) async fn physical_pool(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    envelope: &ExecutionEnvelope,
) -> Result<Option<PhysicalResourceBinding>> {
    let bindings: Value =
        sqlx::query_scalar("SELECT execution_bindings FROM attempts WHERE attempt_id=$1")
            .bind(&a.attempt_id)
            .fetch_one(&mut **tx)
            .await?;
    let profile = &bindings["resource_profile"];
    let Some(raw) = bindings.get("physical_resources") else {
        if profile.get("physical_limits").is_some() {
            return Err(err(
                "PHYSICAL_BINDING_MISSING",
                "required physical pool was not frozen at admission",
            ));
        }
        return Ok(None);
    };
    let pool: PhysicalResourceBinding = decode(raw.clone())?;
    pool.verify()?;
    let expected = physical_binding_from_profile(
        profile,
        &envelope.resource_profile_id,
        &pool.root_resources,
    )?
    .ok_or_else(|| {
        err(
            "PHYSICAL_BINDING_MISMATCH",
            "physical pool requires frozen physical policy",
        )
    })?;
    if expected != pool {
        return Err(err(
            "PHYSICAL_BINDING_MISMATCH",
            "native loan policy differs from immutable reservation",
        ));
    }
    // Each ancestor contains the same complete vector; summing ancestors would
    // invent capacity. Quarantine is held, but cannot grant fresh child rights.
    let rows = sqlx::query("SELECT scope_id,dimension,amount,state FROM resource_allocations WHERE attempt_id=$1 AND state<>'RELEASED' ORDER BY scope_id,dimension FOR SHARE")
        .bind(&a.attempt_id).fetch_all(&mut **tx).await?;
    let mut scopes =
        std::collections::BTreeMap::<String, std::collections::BTreeMap<String, u64>>::new();
    for row in rows {
        if !matches!(row.get::<String, _>("state").as_str(), "RESERVED" | "HELD") {
            return Err(err(
                "RESOURCE_LEDGER_CORRUPT",
                "physical pool is quarantined or not launchable",
            ));
        }
        let amount = u64::try_from(row.get::<i64, _>("amount"))
            .map_err(|_| err("RESOURCE_LEDGER_CORRUPT", "physical allocation is negative"))?;
        let amounts = scopes.entry(row.get("scope_id")).or_default();
        let amount_entry = amounts.entry(row.get("dimension")).or_default();
        *amount_entry = amount_entry
            .checked_add(amount)
            .ok_or_else(|| err("RESOURCE_LEDGER_CORRUPT", "physical allocation overflow"))?;
    }
    let expected: std::collections::BTreeMap<String, u64> = pool
        .reserved_resources
        .dimensions()
        .into_iter()
        .filter(|(_, amount)| *amount > 0)
        .map(|(dim, amount)| (dim.to_owned(), amount))
        .collect();
    let task: TaskCard = decode(sqlx::query_scalar::<_, Value>("SELECT data FROM task_revisions WHERE project_id=$1 AND task_id=$2 AND task_revision=$3")
        .bind(&a.project_id).bind(&a.task_id).bind(i64v(a.task_revision)?).fetch_one(&mut **tx).await?)?;
    let expected_scopes: BTreeSet<String> = sqlx::query_scalar("WITH RECURSIVE selected AS (SELECT scope_id,parent_scope_id FROM resource_scopes WHERE (project_id IS NULL AND worker_id IS NULL) OR worker_id=$3 OR (project_id=$1 AND (team_id IS NULL OR team_id IN(SELECT ancestor_id FROM owner_closure WHERE project_id=$1 AND descendant_id=$2))) UNION SELECT s.scope_id,s.parent_scope_id FROM resource_scopes s JOIN selected c ON s.scope_id=c.parent_scope_id) SELECT DISTINCT scope_id FROM selected ORDER BY scope_id")
        .bind(&a.project_id).bind(&task.team_id).bind(&a.worker_id).fetch_all(&mut **tx).await?.into_iter().collect();
    if scopes.is_empty()
        || scopes.keys().cloned().collect::<BTreeSet<_>>() != expected_scopes
        || scopes.values().any(|amounts| amounts != &expected)
    {
        return Err(err(
            "RESOURCE_LEDGER_CORRUPT",
            "every scope must hold the exact whole-attempt pool",
        ));
    }
    Ok(Some(pool))
}

/// Trusted Worker stop facts must close the exact frozen physical fence. These
/// are scoped remote observations, not a claim that PostgreSQL observes hardware.
/// Durable positive facts remain valid after the empty leaf/unit is removed.
pub(crate) async fn validate_physical_stop(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    evidence: &Value,
    outcome_execution_id: Option<&str>,
) -> Result<bool> {
    let bindings: Value =
        sqlx::query_scalar("SELECT execution_bindings FROM attempts WHERE attempt_id=$1")
            .bind(&a.attempt_id)
            .fetch_one(&mut **tx)
            .await?;
    if bindings["resource_profile"]
        .get("physical_limits")
        .is_none()
    {
        return Ok(false);
    }
    let invalid = || {
        err(
            "PROCESS_EXIT_UNCONFIRMED",
            "required physical pool needs matching frozen fence and positive raw empty cgroup stop",
        )
    };
    let pool: PhysicalResourceBinding = decode(
        bindings
            .get("physical_resources")
            .cloned()
            .ok_or_else(invalid)?,
    )?;
    pool.verify()?;
    let expected = physical_binding_from_profile(
        &bindings["resource_profile"],
        &pool.resource_profile_id,
        &pool.root_resources,
    )?
    .ok_or_else(invalid)?;
    if pool != expected {
        return Err(invalid());
    }
    let fence = &evidence["physical_fence"];
    let stop = &evidence["physical_stop"];
    let launch = &evidence["launch_receipt"];
    let never_launched = evidence["never_launched"] == true && launch.is_null();
    let intent = if never_launched {
        &evidence["launch_intent"]
    } else {
        &launch["intent"]
    };
    let execution = evidence["execution_id"].as_str().ok_or_else(invalid)?;
    let limits = serde_json::json!({"cpu_quota_us":pool.cpu_quota_us,"cpu_period_us":pool.physical_limits.period_us,
        "memory_max_bytes":pool.memory_max_bytes,"memory_swap_max_bytes":pool.physical_limits.swap_max_bytes,
        "pids_max":pool.physical_limits.pids_max,"memory_oom_group":pool.physical_limits.memory_oom_group});
    let raw_events = stop
        .pointer("/snapshot/cgroup.events")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let populated: Vec<_> = raw_events
        .lines()
        .filter_map(|line| line.trim().strip_prefix("populated "))
        .collect();
    if !fence.is_object()
        || fence["schema_version"] != "forgeflow.cgroup-fence.v1"
        || fence["project_id"].as_str() != Some(a.project_id.as_str())
        || fence["attempt_id"].as_str() != Some(a.attempt_id.as_str())
        || fence["generation"].as_i64() != Some(a.generation)
        || fence["resource_binding_sha256"].as_str() != Some(pool.reservation_sha256.as_str())
        || fence["limits"] != limits
        || fence["execution_id"].as_str() != Some(execution)
        || Uuid::parse_str(execution).is_err()
        || execution == a.operation_id
        || outcome_execution_id.is_some_and(|id| id != execution)
        || intent["execution_id"].as_str() != Some(execution)
        || intent["operation_id"].as_str() != Some(a.operation_id.as_str())
        || intent["attempt_id"].as_str() != Some(a.attempt_id.as_str())
        || intent["generation"].as_i64() != Some(a.generation)
        || intent["worker_id"].as_str() != Some(a.worker_id.as_str())
        || fence["boot_id"].as_str().is_none_or(|id| id.is_empty())
        || fence["boot_id"] != intent["boot_id"]
        || fence["leaf_inode"].as_u64().is_none_or(|inode| inode == 0)
        || fence["root_inode"].as_u64().is_none_or(|inode| inode == 0)
        || fence["mount_id"].as_u64().is_none_or(|id| id == 0)
        || fence["mount_device"].as_u64().is_none()
        || fence["owner_uid"]
            .as_u64()
            .is_none_or(|uid| uid > u32::MAX as u64)
        || ["leaf_path", "mount_path"].into_iter().any(|k| {
            fence[k]
                .as_str()
                .is_none_or(|path| !std::path::Path::new(path).is_absolute())
        })
        || stop["schema_version"] != "forgeflow.cgroup-stop.v1"
        || stop["identity_sha256"] != fence["identity_sha256"]
        || stop["boot_id"] != fence["boot_id"]
        || stop["leaf_inode"] != fence["leaf_inode"]
        || stop["populated"] != false
        || stop["process_exit_confirmed"] != true
        || populated != vec!["0"]
        || stop
            .pointer("/snapshot/cgroup.procs")
            .and_then(Value::as_str)
            .is_none_or(|raw| !raw.trim().is_empty())
        || stop["observed_at"]
            .as_str()
            .is_none_or(|at| DateTime::parse_from_rfc3339(at).is_err())
    {
        return Err(invalid());
    }
    if !never_launched
        && (launch["execution_id"].as_str() != Some(execution)
            || launch["process"]["attempt_id"].as_str() != Some(a.attempt_id.as_str())
            || launch["process"]["boot_id"] != fence["boot_id"]
            || launch["process"]["pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
            || launch["process"]["pgid"].as_u64() != launch["process"]["pid"].as_u64()
            || launch["process"]["start_ticks"]
                .as_u64()
                .is_none_or(|ticks| ticks == 0))
    {
        return Err(invalid());
    }
    let mut hash_value = fence.clone();
    hash_value
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("identity_sha256");
    if fence["identity_sha256"].as_str()
        != Some(forgeflow_evidence::sha256(&serde_json::to_vec(&hash_value)?).as_str())
    {
        return Err(invalid());
    }
    let original: Option<Value> = sqlx::query_scalar("SELECT payload->'payload' FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 AND payload->>'kind'='RUNNING' ORDER BY event_id LIMIT 1")
        .bind(&a.project_id).bind(&a.attempt_id).fetch_optional(&mut **tx).await?;
    if original
        .as_ref()
        .is_some_and(|original| never_launched || original != launch)
    {
        return Err(invalid());
    }
    Ok(true)
}

fn verifier_error(message: impl Into<String>) -> StoreError {
    err("PROCESS_EXIT_UNCONFIRMED", message)
}

async fn verifier_plan_and_pool(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<(
    ExecutionEnvelope,
    forgeflow_evidence::VerificationPlan,
    Option<PhysicalResourceBinding>,
)> {
    let row = sqlx::query("SELECT envelope,execution_bindings FROM attempts WHERE attempt_id=$1")
        .bind(&a.attempt_id)
        .fetch_one(&mut **tx)
        .await?;
    let envelope: ExecutionEnvelope = decode(row.get("envelope"))?;
    let bindings: Value = row.get("execution_bindings");
    let plan: forgeflow_evidence::VerificationPlan = decode(bindings["verification_plan"].clone())?;
    let pool = if bindings["resource_profile"]
        .get("physical_limits")
        .is_some()
    {
        let pool: PhysicalResourceBinding = decode(bindings["physical_resources"].clone())?;
        pool.verify()?;
        if physical_binding_from_profile(
            &bindings["resource_profile"],
            &envelope.resource_profile_id,
            &pool.root_resources,
        )? != Some(pool.clone())
        {
            return Err(verifier_error("verifier pool differs from frozen profile"));
        }
        Some(pool)
    } else {
        None
    };
    Ok((envelope, plan, pool))
}

fn validate_verifier_grant(
    a: &Attempt,
    root: &Value,
    plan: &forgeflow_evidence::VerificationPlan,
    pool: Option<&PhysicalResourceBinding>,
) -> Result<Option<forgeflow_evidence::PhysicalVerificationContext>> {
    let raw = root.get("physical_grant").filter(|v| !v.is_null());
    let Some(pool) = pool else {
        if raw.is_some() {
            return Err(verifier_error(
                "legacy profile cannot grant physical pool custody",
            ));
        }
        return Ok(None);
    };
    let context: forgeflow_evidence::PhysicalVerificationContext = decode(
        raw.cloned()
            .ok_or_else(|| verifier_error("required physical verifier grant missing"))?,
    )?;
    let path = root["verifier_root"]
        .as_str()
        .ok_or_else(|| verifier_error("verifier root identity missing"))?;
    context
        .validate(
            plan,
            std::path::Path::new(path),
            &a.attempt_id,
            a.generation,
        )
        .map_err(|e| verifier_error(e.to_string()))?;
    let limits = serde_json::json!({"cpu_quota_us":pool.cpu_quota_us,"cpu_period_us":pool.physical_limits.period_us,
        "memory_max_bytes":pool.memory_max_bytes,"memory_swap_max_bytes":pool.physical_limits.swap_max_bytes,
        "pids_max":pool.physical_limits.pids_max,"memory_oom_group":pool.physical_limits.memory_oom_group});
    if context.physical_request.project_id != a.project_id
        || context.physical_request.resource_binding_sha256 != pool.reservation_sha256
        || json(&context.physical_request.limits)? != limits
        || root["operation_id"].as_str() != Some(context.operation_id.as_str())
        || root["attempt_id"].as_str() != Some(a.attempt_id.as_str())
    {
        return Err(verifier_error(
            "verifier grant differs from exact frozen pool or operation",
        ));
    }
    Ok(Some(context))
}

fn validate_verifier_physical_evidence(
    context: &forgeflow_evidence::PhysicalVerificationContext,
    plan: &forgeflow_evidence::VerificationPlan,
    evidence: &Value,
) -> Result<()> {
    let items = evidence
        .as_array()
        .ok_or_else(|| verifier_error("physical verifier evidence array missing"))?;
    if items.len() != context.commands.len() || items.is_empty() {
        return Err(verifier_error(
            "physical settlement must account for every registered command",
        ));
    }
    let context_value = json(context)?;
    let expected_limits = json(&context.physical_request.limits)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| verifier_error(e.to_string()))?;
    for (item, command) in items.iter().zip(&context.commands) {
        if item["context"] != context_value
            || item["command"] != json(command)?
            || item["runner_closed"] != true
        {
            return Err(verifier_error(
                "physical evidence differs from registered command manifest or closed runner",
            ));
        }
        if item["status"] == "NEVER_LAUNCHED" {
            if item["unused_closed"] != true
                || [
                    "launch_authority",
                    "launch_receipt",
                    "physical_fence",
                    "physical_membership",
                    "physical_stop",
                    "stop",
                ]
                .iter()
                .any(|field| !item[*field].is_null())
            {
                return Err(verifier_error(
                    "unlaunched command needs an explicit closed unused grant with no launch facts",
                ));
            }
            continue;
        }
        if item["status"] != "STOPPED" || item["stop"]["process_exit_confirmed"] != true {
            return Err(verifier_error(
                "verifier command lacks positive process settlement",
            ));
        }
        let fence = &item["physical_fence"];
        let stop = &item["physical_stop"];
        let launch = &item["launch_receipt"];
        let never_executed = launch.is_null()
            && item["physical_membership"].is_null()
            && item["pre_exec_stopped"] == true
            && item["stop"]["reason"].as_str().is_some_and(|reason| {
                reason == "cancelled_before_launch"
                    || reason
                        .strip_prefix("spawn_failed: ")
                        .is_some_and(|error| !error.trim().is_empty())
            });
        let intent = if never_executed {
            &item["launch_authority"]["intent"]
        } else {
            &launch["intent"]
        };
        let raw = stop
            .pointer("/snapshot/cgroup.events")
            .and_then(Value::as_str)
            .ok_or_else(|| verifier_error("raw verifier cgroup events missing"))?;
        let populated: Vec<_> = raw
            .lines()
            .filter_map(|line| line.trim().strip_prefix("populated "))
            .collect();
        if fence["schema_version"] != "forgeflow.cgroup-fence.v1"
            || fence["project_id"] != context.physical_request.project_id
            || fence["attempt_id"] != command.process_attempt_id
            || fence["generation"].as_i64() != Some(context.generation)
            || fence["execution_id"] != command.execution_id
            || fence["resource_binding_sha256"] != context.physical_request.resource_binding_sha256
            || fence["delegation"] != json(&context.physical_request.delegation)?
            || fence["limits"] != expected_limits
            || fence["boot_id"].as_str() != Some(boot.trim())
            || fence["leaf_inode"].as_u64().is_none_or(|inode| inode == 0)
            || fence["root_inode"].as_u64().is_none_or(|inode| inode == 0)
            || fence["mount_id"].as_u64().is_none_or(|id| id == 0)
            || fence["mount_device"].as_u64().is_none()
            || fence["owner_uid"]
                .as_u64()
                .is_none_or(|uid| uid > u32::MAX as u64)
            || ["leaf_path", "mount_path"].iter().any(|key| {
                fence[*key]
                    .as_str()
                    .is_none_or(|path| !std::path::Path::new(path).is_absolute())
            })
            || (!never_executed && launch["execution_id"] != command.execution_id)
            || intent["execution_id"] != command.execution_id
            || intent["attempt_id"] != command.process_attempt_id
            || intent["operation_id"] != context.operation_id
            || intent["generation"].as_i64() != Some(context.generation)
            || intent["worker_id"] != plan.verifier_id
            || intent["boot_id"] != fence["boot_id"]
            || (!never_executed
                && (launch["process"]["attempt_id"] != command.process_attempt_id
                    || launch["process"]["boot_id"] != fence["boot_id"]
                    || launch["process"]["pid"]
                        .as_u64()
                        .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
                    || launch["process"]["pgid"].as_u64() != launch["process"]["pid"].as_u64()
                    || launch["process"]["start_ticks"]
                        .as_u64()
                        .is_none_or(|ticks| ticks == 0)))
            || item["launch_authority"]["intent"] != *intent
            || item["launch_authority"]["physical_fence_sha256"] != fence["identity_sha256"]
            || stop["schema_version"] != "forgeflow.cgroup-stop.v1"
            || stop["identity_sha256"] != fence["identity_sha256"]
            || stop["boot_id"] != fence["boot_id"]
            || stop["leaf_inode"] != fence["leaf_inode"]
            || stop["process_exit_confirmed"] != true
            || stop["populated"] != false
            || populated != vec!["0"]
            || stop
                .pointer("/snapshot/cgroup.procs")
                .and_then(Value::as_str)
                .is_none_or(|raw| !raw.trim().is_empty())
            || stop["observed_at"]
                .as_str()
                .is_none_or(|at| DateTime::parse_from_rfc3339(at).is_err())
        {
            return Err(verifier_error(
                "verifier stop does not close the exact registered physical fence",
            ));
        }
        let mut hash_value = fence.clone();
        hash_value
            .as_object_mut()
            .ok_or_else(|| verifier_error("physical fence must be an object"))?
            .remove("identity_sha256");
        if fence["identity_sha256"].as_str()
            != Some(forgeflow_evidence::sha256(&serde_json::to_vec(&hash_value)?).as_str())
        {
            return Err(verifier_error("verifier physical fence hash mismatch"));
        }
    }
    Ok(())
}

async fn validate_verifier_settlement(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    root: &Value,
    settled: &Value,
) -> Result<()> {
    let path = root["verifier_root"]
        .as_str()
        .ok_or_else(|| verifier_error("verifier root missing"))?;
    if settled["attempt_id"] != a.attempt_id
        || settled["registered_operation_id"] != root["operation_id"]
        || settled["verifier_root"] != root["verifier_root"]
        || !matches!(
            settled["status"].as_str(),
            Some("STOPPED" | "NEVER_LAUNCHED")
        )
    {
        return Err(verifier_error(
            "verifier settlement differs from registered root",
        ));
    }
    let required: bool = sqlx::query_scalar("SELECT COALESCE((execution_bindings->'resource_profile') ? 'physical_limits',false) FROM attempts WHERE attempt_id=$1")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if !required {
        if root
            .get("physical_grant")
            .is_some_and(|grant| !grant.is_null())
        {
            return Err(verifier_error(
                "legacy profile cannot grant physical verifier custody",
            ));
        }
        let stops = forgeflow_evidence::verification_stop_evidence(std::path::Path::new(path))
            .map_err(|e| verifier_error(e.to_string()))?;
        if stops.is_empty() && settled["status"] != "NEVER_LAUNCHED" {
            return Err(verifier_error(
                "empty legacy journals require explicit unlaunched acknowledgment",
            ));
        }
        return Ok(());
    }
    let (_, plan, pool) = verifier_plan_and_pool(tx, a).await?;
    if let Some(context) = validate_verifier_grant(a, root, &plan, pool.as_ref())? {
        if settled["registration_id"] != context.registration_id
            || !matches!(
                settled["source"].as_str(),
                Some("COMPLETED_AWAITED_RUNNER" | "STARTUP_FINGERPRINT_RECONCILIATION")
            )
        {
            return Err(verifier_error(
                "physical settlement requires exact registered closed runner acknowledgment",
            ));
        }
        let observed =
            forgeflow_evidence::verification_physical_stop_evidence(std::path::Path::new(path))
                .map_err(|e| verifier_error(e.to_string()))?;
        if settled["physical_evidence"] != json(&observed)? {
            return Err(verifier_error(
                "submitted physical facts differ from durable original verifier journals",
            ));
        }
        validate_verifier_physical_evidence(&context, &plan, &settled["physical_evidence"])?;
        let never_launched = observed
            .iter()
            .all(|item| item["status"] == "NEVER_LAUNCHED");
        if (settled["status"] == "NEVER_LAUNCHED") != never_launched {
            return Err(verifier_error(
                "phase stop classification differs from actual command closure",
            ));
        }
    } else {
        let stops = forgeflow_evidence::verification_stop_evidence(std::path::Path::new(path))
            .map_err(|e| verifier_error(e.to_string()))?;
        if stops.is_empty() && settled["status"] != "NEVER_LAUNCHED" {
            return Err(verifier_error(
                "empty legacy journals require explicit unlaunched acknowledgment",
            ));
        }
    }
    Ok(())
}

/// Registration, merge decision and final release share the existing authority
/// locks. A registered but unclosed service retains the original reservation.
pub(crate) async fn require_verifier_roots_settled(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<()> {
    let roots: Vec<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='VERIFIER_PROCESS_ROOT' AND data->>'attempt_id'=$2 ORDER BY document_id FOR SHARE")
        .bind(&a.project_id).bind(&a.attempt_id).fetch_all(&mut **tx).await?;
    for root in roots {
        let settled: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='VERIFIER_PROCESS_SETTLED' AND data->>'attempt_id'=$2 AND data->>'registered_operation_id'=$3 AND data->>'verifier_root'=$4 ORDER BY document_id LIMIT 1 FOR SHARE")
            .bind(&a.project_id).bind(&a.attempt_id).bind(root["operation_id"].as_str()).bind(root["verifier_root"].as_str()).fetch_optional(&mut **tx).await?;
        validate_verifier_settlement(
            tx,
            a,
            &root,
            &settled.ok_or_else(|| {
                verifier_error("verifier service is registered but not settled; keep capacity")
            })?,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn validate_verifier_document(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    document_id: &str,
    value: &Value,
) -> Result<()> {
    let attempt_id = bounded_string(value, "attempt_id", 128)?;
    let a = attempt_lock(tx, project, &attempt_id).await?;
    if value["kind"] == "VERIFIER_PROCESS_SETTLED" {
        let root: Value = if value.get("registration_id").is_some() {
            let registration = bounded_string(value, "registration_id", 256)?;
            sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='operations' AND document_id=$2 AND data->>'kind'='VERIFIER_PROCESS_ROOT' FOR SHARE")
                .bind(project).bind(&registration).fetch_optional(&mut **tx).await?
        } else {
            // Older startup recovery facts did not carry a registration ID.
            // Only a frozen legacy root may use that exact op/path lookup.
            sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='operations' AND data->>'kind'='VERIFIER_PROCESS_ROOT' AND data->>'attempt_id'=$2 AND data->>'operation_id'=$3 AND data->>'verifier_root'=$4 AND COALESCE(data->'physical_grant','null'::jsonb)='null'::jsonb ORDER BY document_id LIMIT 1 FOR SHARE")
                .bind(project).bind(&a.attempt_id).bind(value["registered_operation_id"].as_str()).bind(value["verifier_root"].as_str()).fetch_optional(&mut **tx).await?
        }.ok_or_else(|| verifier_error("original verifier registration missing"))?;
        return validate_verifier_settlement(tx, &a, &root, value).await;
    }
    if !matches!(a.state, AttemptState::Verifying | AttemptState::ReviewReady) {
        return Err(err(
            "ILLEGAL_TRANSITION",
            "verifier registration requires a stopped author before merge or cancellation",
        ));
    }
    valid_lease(tx, &a, a.generation, &a.worker_id).await?;
    require_verifier_roots_settled(tx, &a).await?;
    if Store::collaboration_pending_in_transaction(tx, &a.attempt_id).await? {
        return Err(err(
            "NATIVE_EFFECT_UNCONFIRMED",
            "native effects must close before borrowing the physical pool",
        ));
    }
    let inflight: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM model_request_permit WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED'))")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if inflight {
        return Err(err(
            "MODEL_EFFECT_UNCONFIRMED",
            "unsettled model effects prevent verifier launch",
        ));
    }
    let (envelope, plan, pool) = verifier_plan_and_pool(tx, &a).await?;
    if let Some(context) = validate_verifier_grant(&a, value, &plan, pool.as_ref())? {
        if context.registration_id != document_id {
            return Err(verifier_error(
                "physical grant registration ID differs from immutable document",
            ));
        }
        let held = physical_pool(tx, &a, &envelope)
            .await?
            .ok_or_else(|| verifier_error("held physical pool missing"))?;
        if Some(&held) != pool.as_ref() {
            return Err(verifier_error("physical pool ledger or binding changed"));
        }
        let returned: Value = sqlx::query_scalar("SELECT payload FROM worker_event_ids WHERE project_id=$1 AND attempt_id=$2 AND payload ? 'outcome' ORDER BY event_id LIMIT 1 FOR SHARE")
            .bind(project).bind(&a.attempt_id).fetch_optional(&mut **tx).await?.ok_or_else(|| verifier_error("immutable author WorkerResult stop missing"))?;
        let returned: WorkerResult = decode(returned)?;
        if returned.generation != a.generation
            || returned.worker_id != a.worker_id
            || returned.outcome.completion_reason != "EXECUTOR_COMPLETED"
            || returned.outcome.exit_code != Some(0)
            || !validate_physical_stop(
                tx,
                &a,
                &returned.evidence,
                Some(&returned.outcome.execution_id),
            )
            .await?
        {
            return Err(verifier_error(
                "author did not positively close its original whole physical pool",
            ));
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|e| verifier_error(e.to_string()))?;
        if returned.evidence["physical_fence"]["boot_id"].as_str() != Some(boot.trim()) {
            return Err(verifier_error(
                "verifier cannot borrow a different host or boot's Worker reservation",
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Rpc {
    raw: Value,
    rpc_id: Uuid,
    project: String,
    task: String,
    attempt: String,
    generation: i64,
    operation: String,
}
fn bounded_string(v: &Value, key: &str, max: usize) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max)
        .map(str::to_owned)
        .ok_or_else(|| err("NATIVE_RPC_INVALID", format!("bounded {key} required")))
}
fn uuid_field(v: &Value, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&bounded_string(v, key, 36)?)
        .map_err(|_| err("NATIVE_RPC_INVALID", format!("{key} must be UUID")))
}
fn exact_fields(v: &Value, required: &[&str], optional: &[&str]) -> Result<()> {
    let object = v
        .as_object()
        .ok_or_else(|| err("NATIVE_RPC_INVALID", "object required"))?;
    if required.iter().any(|f| !object.contains_key(*f))
        || object
            .keys()
            .any(|f| !required.contains(&f.as_str()) && !optional.contains(&f.as_str()))
    {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "missing or unknown operation field",
        ));
    }
    Ok(())
}
impl Rpc {
    fn parse(raw: Value) -> Result<Self> {
        if serde_json::to_vec(&raw)?.len() > 65536 {
            return Err(err("NATIVE_RPC_INVALID", "RPC exceeds 64 KiB"));
        }
        let operation = bounded_string(&raw, "operation", 32)?;
        let base = [
            "schema_version",
            "rpc_id",
            "operation",
            "project_id",
            "task_id",
            "attempt_id",
            "generation",
        ];
        let extra: &[&str] = match operation.as_str() {
            "admit" => &[
                "native_session_id",
                "parent_session_id",
                "source",
                "delegation_depth",
                "origin",
                "agent_options",
            ],
            "model_request" => &[
                "native_session_id",
                "allocation_id",
                "request_id",
                "provider",
                "model",
                "max_output_tokens",
                "purpose",
            ],
            "model_settle" => &[
                "native_session_id",
                "allocation_id",
                "request_id",
                "request_grant_id",
                "usage",
                "usage_complete",
                "finish_reason",
            ],
            "release" => &["native_session_id", "allocation_id", "reason"],
            "poll" => &[],
            "cancel_ack" => &["reason", "active_model_requests", "sessions"],
            "observe" => &["event", "value"],
            _ => {
                return Err(err(
                    "NATIVE_RPC_INVALID",
                    "operation is not a bridge operation",
                ));
            }
        };
        let fields: Vec<_> = base.iter().chain(extra).copied().collect();
        exact_fields(&raw, &fields, &[])?;
        if raw["schema_version"] != "forgeflow.dsh-bridge.v2" {
            return Err(err("NATIVE_RPC_INVALID", "strict RPC v2 required"));
        }
        let generation = raw["generation"]
            .as_i64()
            .filter(|g| *g > 0)
            .ok_or_else(|| err("NATIVE_RPC_INVALID", "positive integer generation required"))?;
        Ok(Self {
            rpc_id: uuid_field(&raw, "rpc_id")?,
            project: bounded_string(&raw, "project_id", 256)?,
            task: bounded_string(&raw, "task_id", 256)?,
            attempt: bounded_string(&raw, "attempt_id", 256)?,
            generation,
            operation,
            raw,
        })
    }
    fn reply(&self) -> Value {
        serde_json::json!({"ok":true,"generation":self.generation})
    }
}

impl Store {
    /// Called only by a trusted authenticated Worker sidecar. The model process
    /// receives the private socket, never this Worker credential or database access.
    pub async fn collaboration_rpc(&self, worker_id: &str, request: Value) -> Result<Value> {
        let rpc = Rpc::parse(request)?;
        // Poll is an authenticated read, never a resource or model grant. Do not
        // create a durable UUID ledger row, take global mutation locks or append
        // events for a periodic read. At 58 processes the former 200ms path
        // would otherwise create hundreds of millions of rows in fourteen days.
        if rpc.operation == "poll" {
            return poll_native_readonly(&self.pool, worker_id, &rpc).await;
        }
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let project = project_lock(&mut tx, &rpc.project).await?;
        let attempt = attempt_lock(&mut tx, &rpc.project, &rpc.attempt).await?;
        if attempt.task_id != rpc.task
            || attempt.generation != rpc.generation
            || attempt.worker_id != worker_id
        {
            return Err(err(
                "LEASE_STALE",
                "exact parent task, generation and Worker binding required",
            ));
        }
        let active_operation = matches!(rpc.operation.as_str(), "admit" | "model_request");
        if active_operation {
            valid_lease(&mut tx, &attempt, rpc.generation, worker_id).await?;
            let native_revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND revoked AND state<>'RELEASED')")
                .bind(&attempt.attempt_id).fetch_one(&mut *tx).await?;
            if native_revoked {
                return Err(err(
                    "NATIVE_IDENTITY_STALE",
                    "native collaboration grants were revoked or quarantined",
                ));
            }
            if project.authority_mode != AuthorityMode::Managed
                || project.paused
                || project.archived
                || !matches!(
                    attempt.state,
                    AttemptState::Starting | AttemptState::Running
                )
            {
                return Err(err(
                    "NATIVE_ADMISSION_BLOCKED",
                    "active claimed parent execution required",
                ));
            }
            let claimed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbox o JOIN attempts a ON a.project_id=o.project_id AND a.operation_id=o.operation_id JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id WHERE o.project_id=$1 AND o.operation_id=$2 AND o.kind='attempt.start' AND o.claimed_by=$3 AND o.delivered_at IS NOT NULL AND o.payload->>'project_id'=a.project_id AND o.payload->>'task_id'=a.task_id AND o.payload->>'attempt_id'=a.attempt_id AND o.payload->>'operation_id'=a.operation_id AND o.payload->>'lease_id'=a.lease_id AND o.payload->>'worker_id'=a.worker_id AND o.payload->'generation'=to_jsonb(a.generation) AND t.task_revision=a.task_revision)")
                .bind(&rpc.project).bind(&attempt.operation_id).bind(worker_id).fetch_one(&mut *tx).await?;
            if !claimed {
                return Err(err(
                    "NATIVE_ADMISSION_BLOCKED",
                    "Worker has not claimed parent start",
                ));
            }
            let paused: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks t JOIN owner_closure c ON c.project_id=t.project_id AND c.descendant_id=t.team_id JOIN owner_nodes n ON n.project_id=c.project_id AND n.owner_id=c.ancestor_id WHERE t.project_id=$1 AND t.task_id=$2 AND n.paused)")
                .bind(&rpc.project).bind(&rpc.task).fetch_one(&mut *tx).await?;
            if paused {
                return Err(err(
                    "NATIVE_ADMISSION_BLOCKED",
                    "parent team ancestor paused",
                ));
            }
        }
        let replay_row = sqlx::query(
            "SELECT request,response,worker_id FROM native_bridge_rpc WHERE rpc_id=$1 FOR UPDATE",
        )
        .bind(rpc.rpc_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = replay_row {
            if row.get::<Value, _>("request") != rpc.raw
                || row.get::<String, _>("worker_id") != worker_id
            {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "RPC UUID reused with another request or Worker",
                ));
            }
            let response: Value = row.get("response");
            if active_operation {
                let allocation: Option<String> = if rpc.operation == "admit" {
                    response["allocation_id"].as_str().map(str::to_owned)
                } else {
                    sqlx::query_scalar("SELECT allocation_id FROM native_model_requests WHERE request_grant_id=$1 AND attempt_id=$2 AND status='ADMITTED'")
                        .bind(response["request_grant_id"].as_str()).bind(&rpc.attempt).fetch_optional(&mut *tx).await?
                };
                let active = if let Some(allocation) = allocation {
                    native_lineage_live(&mut tx, &allocation).await?
                } else {
                    false
                };
                if !active {
                    return Err(err(
                        "NATIVE_IDENTITY_STALE",
                        "replayed grant was disposed, settled, quarantined or revoked",
                    ));
                }
            }
            tx.commit().await?;
            return Ok(response);
        }
        let response = match rpc.operation.as_str() {
            "admit" => admit_native(&mut tx, &attempt, &rpc).await?,
            "model_request" => model_request(&mut tx, &attempt, &rpc).await?,
            "model_settle" => model_settle(&mut tx, &attempt, &rpc).await?,
            "release" => release_native(&mut tx, &attempt, &rpc).await?,
            "cancel_ack" => cancel_ack(&mut tx, &rpc).await?,
            "observe" => observe_native(&mut tx, &rpc).await?,
            _ => unreachable!(),
        };
        sqlx::query("INSERT INTO native_bridge_rpc(rpc_id,project_id,attempt_id,generation,worker_id,operation,request,response) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(rpc.rpc_id).bind(&rpc.project).bind(&rpc.attempt).bind(rpc.generation).bind(worker_id).bind(&rpc.operation).bind(&rpc.raw).bind(&response).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(response)
    }
    /// Parent terminal/release and model cleanup must reuse this exact pending predicate.
    pub async fn collaboration_pending_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        attempt_id: &str,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_child_allocations WHERE attempt_id=$1 AND state<>'RELEASED') OR EXISTS(SELECT 1 FROM native_model_requests WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED'))")
            .bind(attempt_id).fetch_one(&mut **tx).await?)
    }
    /// Revocation closes every child/model grant while conservatively retaining capacity.
    pub async fn collaboration_revoke_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        attempt_id: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE native_child_lifecycles SET revoked=true,state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'")
            .bind(attempt_id).execute(&mut **tx).await?;
        sqlx::query("UPDATE native_child_allocations SET state='QUARANTINED' WHERE attempt_id=$1 AND state<>'RELEASED'")
            .bind(attempt_id).execute(&mut **tx).await?;
        Ok(())
    }
    /// Only call AFTER validating trusted Worker evidence of actual parent process
    /// stop. Native idle, missing PID, plugin unload and cancel_ack cannot call this.
    /// Child reservations still require their own native_disposed acknowledgement.
    /// This compatibility entry point never asserts a whole-pool physical stop.
    pub async fn collaboration_process_stopped_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        a: &Attempt,
    ) -> Result<()> {
        Self::collaboration_process_stop_tx(tx, a, false).await
    }
    /// Validate the frozen whole-attempt fence before closing orphan native
    /// lifecycles. No caller-provided boolean or mere parent PID absence can
    /// authorize descendant stop. Legacy profiles retain root-only semantics.
    pub(crate) async fn collaboration_process_stopped_with_evidence_in_transaction(
        tx: &mut Transaction<'_, Postgres>,
        a: &Attempt,
        evidence: &Value,
        outcome_execution_id: Option<&str>,
    ) -> Result<()> {
        let physical_pool_stopped =
            validate_physical_stop(tx, a, evidence, outcome_execution_id).await?;
        Self::collaboration_process_stop_tx(tx, a, physical_pool_stopped).await
    }
    async fn collaboration_process_stop_tx(
        tx: &mut Transaction<'_, Postgres>,
        a: &Attempt,
        physical_pool_stopped: bool,
    ) -> Result<()> {
        Self::collaboration_revoke_in_transaction(tx, &a.attempt_id).await?;
        let stopped: Vec<String> = sqlx::query_scalar("UPDATE native_child_lifecycles SET process_stopped_at=COALESCE(process_stopped_at,clock_timestamp()) WHERE attempt_id=$1 AND generation=$2 AND worker_id=$3 AND (borrowed_parent_reservation OR $4) AND state<>'RELEASED' RETURNING allocation_id")
            .bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).bind(physical_pool_stopped).fetch_all(&mut **tx).await?;
        // Mark the entire proven-stopped tree before finalizing any node. Each
        // child finalization walks ancestors, so return ordering is immaterial.
        for allocation in stopped {
            finalize_disposed(tx, &allocation).await?;
        }
        Ok(())
    }
}
async fn poll_native_readonly(pool: &sqlx::PgPool, worker_id: &str, rpc: &Rpc) -> Result<Value> {
    // One database statement observes the current attempt state and revocation
    // predicates together. Immutable parent identity is checked before reply.
    let row = sqlx::query("SELECT a.data, (a.state NOT IN ('STARTING','RUNNING') OR EXISTS(SELECT 1 FROM leases l JOIN tasks t ON t.project_id=l.project_id AND t.task_id=$3 WHERE l.attempt_id=a.attempt_id AND (l.revoked_at IS NOT NULL OR l.expires_at<=clock_timestamp() OR t.fence_epoch<>$4)) OR EXISTS(SELECT 1 FROM native_child_lifecycles n WHERE n.attempt_id=a.attempt_id AND n.revoked AND n.state<>'RELEASED')) AS revoked FROM attempts a WHERE a.project_id=$1 AND a.attempt_id=$2")
        .bind(&rpc.project).bind(&rpc.attempt).bind(&rpc.task).bind(rpc.generation)
        .fetch_optional(pool).await?.ok_or_else(|| err("NOT_FOUND", "attempt not found"))?;
    let attempt: Attempt = decode(row.get("data"))?;
    if attempt.task_id != rpc.task
        || attempt.generation != rpc.generation
        || attempt.worker_id != worker_id
    {
        return Err(err(
            "LEASE_STALE",
            "exact parent task, generation and Worker binding required",
        ));
    }
    // Preserve conflict checks against historical durable UUIDs. Fresh polls
    // are read-only identities: retries ask for current revocation, not a cached
    // earlier liveness reply and not an idempotent mutation receipt.
    if let Some(previous) =
        sqlx::query("SELECT request,worker_id FROM native_bridge_rpc WHERE rpc_id=$1")
            .bind(rpc.rpc_id)
            .fetch_optional(pool)
            .await?
    {
        if previous.get::<Value, _>("request") != rpc.raw
            || previous.get::<String, _>("worker_id") != worker_id
        {
            return Err(err(
                "IDEMPOTENCY_CONFLICT",
                "RPC UUID reused with another durable request or Worker",
            ));
        }
    }
    let mut reply = rpc.reply();
    reply["revoked"] = Value::Bool(row.get("revoked"));
    Ok(reply)
}
async fn frozen(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
) -> Result<(NativeChildPolicy, Value, ExecutionEnvelope)> {
    let row = sqlx::query("SELECT execution_bindings,envelope FROM attempts WHERE attempt_id=$1")
        .bind(&a.attempt_id)
        .fetch_one(&mut **tx)
        .await?;
    let bindings: Value = row.get("execution_bindings");
    let policy = match bindings
        .get("resource_profile")
        .and_then(|v| v.get("native_child_policy"))
    {
        Some(p) => decode::<NativeChildPolicy>(p.clone())?,
        None => NativeChildPolicy::default(),
    };
    policy.validate()?;
    let route = bindings
        .get("model_route")
        .cloned()
        .ok_or_else(|| err("NATIVE_ROUTE_INVALID", "frozen model route required"))?;
    let envelope: ExecutionEnvelope = decode(row.get("envelope"))?;
    envelope.validate()?;
    if envelope.project_id != a.project_id
        || envelope.task_id != a.task_id
        || envelope.task_revision != a.task_revision
        || envelope.attempt_id != a.attempt_id
        || envelope.lease_id != a.lease_id
        || envelope.worker_id != a.worker_id
        || envelope.generation != a.generation
        || envelope.operation_id != a.operation_id
        || !envelope
            .allowed_effects
            .contains(&AllowedEffect::RequestApprovedModel)
    {
        return Err(err(
            "NATIVE_MODEL_EFFECT_DENIED",
            "exact frozen parent binding and approved model effect required",
        ));
    }
    // Direct observation remains a weaker legacy mode. Gateway enforcement uses
    // the same native budget grant; envelope.validate checks its coverage claim.
    // Neither mode establishes financial/usage completeness qualification.
    if !matches!(
        envelope.enforcement.model_budget_mode,
        ModelBudgetMode::DirectObserved | ModelBudgetMode::GatewayEnforced
    ) {
        return Err(err(
            "NATIVE_MODE_UNQUALIFIED",
            "native bridge requires direct_observed or gateway_enforced accounting",
        ));
    }
    let deadline = DateTime::parse_from_rfc3339(&envelope.deadline_at)
        .map_err(|_| err("NATIVE_POLICY_INVALID", "frozen attempt deadline invalid"))?;
    if deadline.with_timezone(&Utc) <= db_now(tx).await? {
        return Err(err("LEASE_STALE", "parent execution deadline expired"));
    }
    Ok((policy, route, envelope))
}
async fn admit_native(tx: &mut Transaction<'_, Postgres>, a: &Attempt, rpc: &Rpc) -> Result<Value> {
    let (policy, route, envelope) = frozen(tx, a).await?;
    let pool = physical_pool(tx, a, &envelope).await?;
    let revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND revoked AND state<>'RELEASED')")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if revoked {
        return Err(err(
            "NATIVE_IDENTITY_STALE",
            "native collaboration admission was revoked or quarantined",
        ));
    }
    let native = bounded_string(&rpc.raw, "native_session_id", 256)?;
    let parent = match &rpc.raw["parent_session_id"] {
        Value::Null => None,
        Value::String(s) if !s.is_empty() && s.len() <= 256 => Some(s.clone()),
        _ => {
            return Err(err(
                "NATIVE_LINEAGE_INVALID",
                "parent session must be null or bounded identity",
            ));
        }
    };
    if parent.is_some() && !policy.enabled {
        return Err(err(
            "NATIVE_CHILD_DENIED",
            "frozen resource profile did not explicitly allow children",
        ));
    }
    let source = bounded_string(&rpc.raw, "source", 16)?;
    if !["startup", "resume", "clear", "compact"].contains(&source.as_str()) {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "unsupported native lifecycle source",
        ));
    }
    let depth = rpc.raw["delegation_depth"].as_u64().ok_or_else(|| {
        err(
            "NATIVE_LINEAGE_INVALID",
            "integer root-relative depth required",
        )
    })?;
    if !rpc.raw["origin"].is_null() && rpc.raw["origin"] != "subagent" {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "native origin must be null or subagent",
        ));
    }
    exact_fields(
        &rpc.raw["agent_options"],
        &[],
        &[
            "provider",
            "model",
            "preset_id",
            "position_id",
            "owner_team_id",
            "native_team_id",
            "team_name",
        ],
    )?;
    for key in [
        "provider",
        "model",
        "preset_id",
        "position_id",
        "owner_team_id",
        "native_team_id",
        "team_name",
    ] {
        if let Some(value) = rpc.raw["agent_options"].get(key) {
            if !value.is_null()
                && !value
                    .as_str()
                    .is_some_and(|v| !v.is_empty() && v.len() <= 256)
            {
                return Err(err(
                    "NATIVE_RPC_INVALID",
                    "bounded observed native route required",
                ));
            }
        }
    }
    let provider = bounded_string(&route, "provider", 256)?;
    let model = bounded_string(&route, "model", 256)?;
    let cap = route["max_output_tokens"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or_else(|| err("NATIVE_ROUTE_INVALID", "finite output cap required"))?;
    i64v(cap)?;
    if envelope.max_model_requests == 0 {
        return Err(err(
            "NATIVE_MODEL_BUDGET_EXHAUSTED",
            "parent has no native model request budget",
        ));
    }
    let previous = sqlx::query("SELECT allocation_id,parent_session_id,delegation_depth,lifecycle_number,disposed_at,state FROM native_child_lifecycles WHERE attempt_id=$1 AND native_session_id=$2 ORDER BY lifecycle_number DESC LIMIT 1 FOR UPDATE")
        .bind(&a.attempt_id).bind(&native).fetch_optional(&mut **tx).await?;
    let mut lifecycle_number = 1_i64;
    if let Some(previous) = previous {
        if previous
            .get::<Option<DateTime<Utc>>, _>("disposed_at")
            .is_none()
            || (!parent.is_none() && previous.get::<String, _>("state") != "RELEASED")
        {
            return Err(err(
                "NATIVE_LIFECYCLE_ACTIVE",
                "previous native lifecycle must be actually disposed and settled",
            ));
        }
        if previous.get::<Option<String>, _>("parent_session_id") != parent
            || previous.get::<i64, _>("delegation_depth") != i64v(depth)?
            || source != "resume"
        {
            return Err(err(
                "NATIVE_LINEAGE_INVALID",
                "cold resume preserves exact prior lineage and requires resume source",
            ));
        }
        lifecycle_number = previous
            .get::<i64, _>("lifecycle_number")
            .checked_add(1)
            .ok_or_else(|| err("NATIVE_POLICY_INVALID", "lifecycle integer overflow"))?;
    }
    let counts = sqlx::query("SELECT count(*) AS total,count(*) FILTER(WHERE disposed_at IS NULL AND state<>'RELEASED') AS live FROM native_child_lifecycles WHERE attempt_id=$1")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if counts.get::<i64, _>("total") >= i64::from(policy.max_lifecycles)
        || counts.get::<i64, _>("live") >= i64::from(policy.max_live_agents)
    {
        return Err(err(
            "NATIVE_CAPACITY_EXHAUSTED",
            "finite lifecycle or live Agent limit exhausted",
        ));
    }
    let (parent_allocation, root) = if let Some(parent) = &parent {
        if !policy.enabled {
            return Err(err(
                "NATIVE_CHILD_DENIED",
                "frozen resource profile did not explicitly allow children",
            ));
        }
        let p = sqlx::query("SELECT allocation_id,root_session_id,delegation_depth,revoked,state,disposed_at FROM native_child_lifecycles WHERE attempt_id=$1 AND generation=$2 AND worker_id=$3 AND native_session_id=$4 AND disposed_at IS NULL AND state<>'RELEASED' FOR UPDATE")
            .bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).bind(parent).fetch_optional(&mut **tx).await?
            .ok_or_else(|| err("NATIVE_LINEAGE_INVALID", "exact live parent lifecycle required"))?;
        if p.get::<bool, _>("revoked")
            || p.get::<String, _>("state") != "HELD"
            || depth != p.get::<i64, _>("delegation_depth") as u64 + 1
            || depth > u64::from(policy.max_delegation_depth)
            || parent == &native
        {
            return Err(err(
                "NATIVE_LINEAGE_INVALID",
                "child depth or live parent binding invalid",
            ));
        }
        if !native_lineage_live(tx, &p.get::<String, _>("allocation_id")).await? {
            return Err(err(
                "NATIVE_LINEAGE_INVALID",
                "every ancestor must be live before admitting another child",
            ));
        }
        (
            Some(p.get::<String, _>("allocation_id")),
            p.get::<String, _>("root_session_id"),
        )
    } else {
        if depth != 0 {
            return Err(err(
                "NATIVE_LINEAGE_INVALID",
                "root delegation depth must be zero",
            ));
        }
        let bound: Option<String> = sqlx::query_scalar(
            "SELECT upstream_session_id FROM native_sessions WHERE attempt_id=$1 FOR UPDATE",
        )
        .bind(&a.attempt_id)
        .fetch_optional(&mut **tx)
        .await?;
        if bound.as_ref().is_some_and(|s| s != &native) {
            return Err(err(
                "NATIVE_LINEAGE_INVALID",
                "root session differs from exact canonical native session",
            ));
        }
        if bound.is_none() {
            sqlx::query("INSERT INTO native_sessions(upstream_session_id,project_id,attempt_id,generation,worker_id) VALUES($1,$2,$3,$4,$5)")
                .bind(&native).bind(&a.project_id).bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).execute(&mut **tx).await?;
        }
        let reserved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_allocations WHERE attempt_id=$1 AND dimension='active_slot' AND amount>0 AND state IN('RESERVED','HELD'))")
            .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
        if !reserved {
            return Err(err(
                "RESOURCE_LEDGER_CORRUPT",
                "root must borrow an existing parent reservation",
            ));
        }
        (None, native.clone())
    };
    if parent.is_some() {
        if let Some(pool) = &pool {
            // Disposed but unsettled/quarantined children retain their loans.
            let held: i64 = sqlx::query_scalar("SELECT count(*) FROM native_child_lifecycles WHERE attempt_id=$1 AND parent_session_id IS NOT NULL AND state<>'RELEASED'")
                .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
            if held >= i64::from(pool.max_concurrent_children) {
                return Err(err(
                    "NATIVE_CAPACITY_EXHAUSTED",
                    "physical pool loans include unsettled children",
                ));
            }
        }
    }
    let allocation = id();
    sqlx::query("INSERT INTO native_child_lifecycles(allocation_id,project_id,task_id,attempt_id,generation,worker_id,native_session_id,parent_session_id,parent_allocation_id,root_session_id,delegation_depth,lifecycle_number,source,borrowed_parent_reservation,provider,model,max_output_tokens,admission,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'HELD')")
        .bind(&allocation).bind(&a.project_id).bind(&a.task_id).bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).bind(&native).bind(&parent).bind(&parent_allocation).bind(root).bind(i64v(depth)?).bind(lifecycle_number).bind(source).bind(parent.is_none()).bind(&provider).bind(&model).bind(i64v(cap)?).bind(&rpc.raw).execute(&mut **tx).await?;
    if parent.is_some() && pool.is_none() {
        reserve_child(tx, a, &allocation, &policy.child_resources).await?;
    }
    event(tx, &a.project_id, &allocation, lifecycle_number as u64, "native_child.admitted", serde_json::json!({"attempt_id":a.attempt_id,"generation":a.generation,"native_session_id":native,"parent_session_id":parent,"borrowed_parent_reservation":parent.is_none(),"owner_and_write_set":"PARENT_TASK","qualification":"CANONICAL_DIRECT_OBSERVED_ONLY","resource_accounting":if pool.is_some() {"UPFRONT_NATIVE_POOL"} else {"LEGACY_PER_CHILD"},"physical_reservation_sha256":pool.as_ref().map(|p| &p.reservation_sha256)})).await?;
    let mut reply = rpc.reply();
    reply["allocation_id"] = allocation.into();
    reply["provider"] = provider.into();
    reply["model"] = model.into();
    reply["max_output_tokens"] = cap.into();
    reply["resource_accounting"] = if pool.is_some() {
        "UPFRONT_NATIVE_POOL"
    } else {
        "LEGACY_PER_CHILD"
    }
    .into();
    if let Some(pool) = pool {
        reply["physical_reservation_sha256"] = pool.reservation_sha256.into();
        reply["borrowed_resources"] = serde_json::to_value(if parent.is_some() {
            &pool.native_child_resources
        } else {
            &pool.root_resources
        })?;
    }
    Ok(reply)
}
async fn reserve_child(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    allocation: &str,
    resource: &ResourceVector,
) -> Result<()> {
    // Match ordinary admission's global, project, ancestor team and Worker selection.
    let scopes: Vec<String> = sqlx::query_scalar("WITH RECURSIVE selected AS (SELECT s.scope_id,s.parent_scope_id FROM resource_scopes s JOIN tasks t ON t.project_id=$1 AND t.task_id=$2 WHERE (s.project_id IS NULL AND s.worker_id IS NULL) OR s.worker_id=$3 OR (s.project_id=$1 AND (s.team_id IS NULL OR s.team_id IN(SELECT ancestor_id FROM owner_closure WHERE project_id=$1 AND descendant_id=t.team_id))) UNION SELECT s.scope_id,s.parent_scope_id FROM resource_scopes s JOIN selected c ON s.scope_id=c.parent_scope_id) SELECT DISTINCT scope_id FROM selected ORDER BY scope_id")
        .bind(&a.project_id).bind(&a.task_id).bind(&a.worker_id).fetch_all(&mut **tx).await?;
    let coverage: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_scopes WHERE project_id IS NULL AND worker_id IS NULL) AND EXISTS(SELECT 1 FROM resource_scopes WHERE project_id=$1 AND team_id IS NULL) AND EXISTS(SELECT 1 FROM resource_scopes WHERE worker_id=$3) AND NOT EXISTS(SELECT 1 FROM tasks t JOIN owner_closure c ON c.project_id=t.project_id AND c.descendant_id=t.team_id WHERE t.project_id=$1 AND t.task_id=$2 AND NOT EXISTS(SELECT 1 FROM resource_scopes s WHERE s.project_id=c.project_id AND s.team_id=c.ancestor_id))")
        .bind(&a.project_id).bind(&a.task_id).bind(&a.worker_id).fetch_one(&mut **tx).await?;
    if scopes.is_empty() || !coverage {
        return Err(err(
            "RESOURCE_POLICY_INCOMPLETE",
            "complete global/project/team-ancestor/Worker coverage required",
        ));
    }
    for scope in scopes {
        let paused: bool =
            sqlx::query_scalar("SELECT paused FROM resource_scopes WHERE scope_id=$1 FOR UPDATE")
                .bind(&scope)
                .fetch_one(&mut **tx)
                .await?;
        if paused {
            return Err(err(
                "NATIVE_ADMISSION_BLOCKED",
                "native child resource scope paused",
            ));
        }
        for (dimension, amount) in resource.dimensions() {
            let limit = sqlx::query("SELECT hard_limit,allocated FROM resource_limits WHERE scope_id=$1 AND dimension=$2 FOR UPDATE")
                .bind(&scope).bind(dimension).fetch_optional(&mut **tx).await?
                .ok_or_else(|| err("RESOURCE_POLICY_INCOMPLETE", "all seven resource dimensions required"))?;
            let amount = i64v(amount)?;
            if limit
                .get::<i64, _>("allocated")
                .checked_add(amount)
                .is_none_or(|sum| sum > limit.get::<i64, _>("hard_limit"))
            {
                return Err(err(
                    "RESOURCE_CAPACITY_EXHAUSTED",
                    format!("{scope}/{dimension} exhausted or draining"),
                ));
            }
            if amount == 0 {
                continue;
            }
            sqlx::query("UPDATE resource_limits SET allocated=allocated+$3 WHERE scope_id=$1 AND dimension=$2")
                .bind(&scope).bind(dimension).bind(amount).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO native_child_allocations(resource_allocation_id,allocation_id,project_id,attempt_id,scope_id,dimension,amount,state) VALUES($1,$2,$3,$4,$5,$6,$7,'HELD')")
                .bind(id()).bind(allocation).bind(&a.project_id).bind(&a.attempt_id).bind(&scope).bind(dimension).bind(amount).execute(&mut **tx).await?;
        }
    }
    Ok(())
}
async fn native_lock(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    rpc: &Rpc,
) -> Result<sqlx::postgres::PgRow> {
    let native = bounded_string(&rpc.raw, "native_session_id", 256)?;
    let allocation = bounded_string(&rpc.raw, "allocation_id", 36)?;
    let row = sqlx::query("SELECT * FROM native_child_lifecycles WHERE allocation_id=$1 AND project_id=$2 AND attempt_id=$3 AND generation=$4 AND worker_id=$5 AND native_session_id=$6 FOR UPDATE")
        .bind(allocation).bind(&a.project_id).bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).bind(native).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("NATIVE_IDENTITY_STALE", "exact allocation/native/parent binding required"))?;
    Ok(row)
}
async fn native_lineage_live(tx: &mut Transaction<'_, Postgres>, allocation: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("WITH RECURSIVE ancestry AS (SELECT allocation_id,parent_allocation_id,state,revoked,disposed_at,process_stopped_at FROM native_child_lifecycles WHERE allocation_id=$1 UNION SELECT p.allocation_id,p.parent_allocation_id,p.state,p.revoked,p.disposed_at,p.process_stopped_at FROM native_child_lifecycles p JOIN ancestry c ON p.allocation_id=c.parent_allocation_id) SELECT EXISTS(SELECT 1 FROM ancestry) AND NOT EXISTS(SELECT 1 FROM ancestry WHERE state<>'HELD' OR revoked OR disposed_at IS NOT NULL OR process_stopped_at IS NOT NULL)")
        .bind(allocation).fetch_one(&mut **tx).await?)
}
async fn model_request(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    rpc: &Rpc,
) -> Result<Value> {
    let lifecycle = native_lock(tx, a, rpc).await?;
    if lifecycle.get::<bool, _>("revoked")
        || lifecycle.get::<String, _>("state") != "HELD"
        || lifecycle
            .get::<Option<DateTime<Utc>>, _>("disposed_at")
            .is_some()
    {
        return Err(err(
            "NATIVE_IDENTITY_STALE",
            "native model grant is revoked or disposed",
        ));
    }
    if !native_lineage_live(tx, &lifecycle.get::<String, _>("allocation_id")).await? {
        return Err(err(
            "NATIVE_IDENTITY_STALE",
            "every native ancestor must remain live for new model dispatch",
        ));
    }
    let globally_revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND revoked AND state<>'RELEASED')")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if globally_revoked {
        return Err(err(
            "NATIVE_IDENTITY_STALE",
            "native collaboration model admission was revoked or quarantined",
        ));
    }
    let request_id = uuid_field(&rpc.raw, "request_id")?.to_string();
    let provider = bounded_string(&rpc.raw, "provider", 256)?;
    let model = bounded_string(&rpc.raw, "model", 256)?;
    let cap = rpc.raw["max_output_tokens"]
        .as_i64()
        .filter(|v| *v > 0)
        .ok_or_else(|| err("NATIVE_ROUTE_INVALID", "finite native output cap required"))?;
    let purpose = bounded_string(&rpc.raw, "purpose", 32)?;
    if !["conversation", "compaction", "session-title"].contains(&purpose.as_str()) {
        return Err(err("NATIVE_RPC_INVALID", "unqualified model purpose"));
    }
    if provider != lifecycle.get::<String, _>("provider")
        || model != lifecycle.get::<String, _>("model")
        || cap != lifecycle.get::<i64, _>("max_output_tokens")
    {
        return Err(err(
            "NATIVE_ROUTE_INVALID",
            "native provider/model/output differs from frozen grant",
        ));
    }
    let existing = sqlx::query(
        "SELECT request,request_grant_id,status FROM native_model_requests WHERE request_id=$1 FOR UPDATE",
    )
    .bind(&request_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = existing {
        let mut old: Value = row.get("request");
        let mut new = rpc.raw.clone();
        old.as_object_mut().unwrap().remove("rpc_id");
        new.as_object_mut().unwrap().remove("rpc_id");
        if old != new {
            return Err(err("IDEMPOTENCY_CONFLICT", "model request UUID reused"));
        }
        if row.get::<String, _>("status") != "ADMITTED" {
            return Err(err(
                "NATIVE_IDENTITY_STALE",
                "settled or unknown request UUID cannot dispatch again",
            ));
        }
        let mut reply = rpc.reply();
        reply["request_grant_id"] = row.get::<String, _>("request_grant_id").into();
        return Ok(reply);
    }
    let (policy, _, envelope) = frozen(tx, a).await?;
    let counts = sqlx::query("SELECT (SELECT count(*) FROM native_model_requests WHERE attempt_id=$1)+(SELECT count(*) FROM model_request_permit WHERE attempt_id=$1) AS total, (SELECT count(*) FROM native_model_requests WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED'))+(SELECT count(*) FROM model_request_permit WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED')) AS inflight")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    let reserved_inflight: i64 = sqlx::query_scalar("SELECT COALESCE(min(reserved),0)::bigint FROM (SELECT scope_id,sum(amount)::bigint AS reserved FROM (SELECT scope_id,amount FROM resource_allocations WHERE attempt_id=$1 AND dimension='provider_inflight' AND state<>'RELEASED' UNION ALL SELECT scope_id,amount FROM native_child_allocations WHERE attempt_id=$1 AND dimension='provider_inflight' AND state<>'RELEASED') r GROUP BY scope_id) scopes")
        .bind(&a.attempt_id).fetch_one(&mut **tx).await?;
    if counts.get::<i64, _>("inflight") >= reserved_inflight {
        return Err(err(
            "NATIVE_MODEL_BUDGET_EXHAUSTED",
            "canonical provider_inflight reservation exhausted",
        ));
    }
    if counts.get::<i64, _>("total") >= i64::from(envelope.max_model_requests)
        || counts.get::<i64, _>("inflight") >= i64::from(policy.model_inflight_limit)
    {
        return Err(err(
            "NATIVE_MODEL_BUDGET_EXHAUSTED",
            "all primary and auxiliary calls consume parent total and inflight limits",
        ));
    }
    let grant = id();
    sqlx::query("INSERT INTO native_model_requests(request_id,request_grant_id,project_id,attempt_id,generation,worker_id,allocation_id,native_session_id,provider,model,max_output_tokens,purpose,request,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'ADMITTED')")
        .bind(request_id).bind(&grant).bind(&a.project_id).bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).bind(lifecycle.get::<String,_>("allocation_id")).bind(lifecycle.get::<String,_>("native_session_id")).bind(provider).bind(model).bind(cap).bind(purpose).bind(&rpc.raw).execute(&mut **tx).await?;
    let mut reply = rpc.reply();
    reply["request_grant_id"] = grant.into();
    Ok(reply)
}
async fn model_settle(tx: &mut Transaction<'_, Postgres>, a: &Attempt, rpc: &Rpc) -> Result<Value> {
    let lifecycle = native_lock(tx, a, rpc).await?;
    let request = uuid_field(&rpc.raw, "request_id")?.to_string();
    let grant = uuid_field(&rpc.raw, "request_grant_id")?.to_string();
    let row = sqlx::query("SELECT settlement,dispatched_at,dispatch_transport_settlement FROM native_model_requests WHERE request_id=$1 AND request_grant_id=$2 AND allocation_id=$3 AND attempt_id=$4 AND generation=$5 AND worker_id=$6 FOR UPDATE")
        .bind(&request).bind(&grant).bind(lifecycle.get::<String,_>("allocation_id")).bind(&a.attempt_id).bind(a.generation).bind(&a.worker_id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("NATIVE_IDENTITY_STALE", "settlement differs from exact model grant"))?;
    let caller_complete = rpc.raw["usage_complete"]
        .as_bool()
        .ok_or_else(|| err("NATIVE_RPC_INVALID", "explicit usage completeness required"))?;
    let finish = bounded_string(&rpc.raw, "finish_reason", 64)?;
    // Native code cannot release an active Gateway stream or invent provider
    // usage completeness. Direct-observed legacy grants retain their old path.
    let transport = row.get::<Option<Value>, _>("dispatch_transport_settlement");
    let dispatched = row
        .get::<Option<DateTime<Utc>>, _>("dispatched_at")
        .is_some();
    if dispatched && transport.is_none() {
        return Err(err(
            "NATIVE_TRANSPORT_PENDING",
            "trusted Gateway transport closure required before native settlement",
        ));
    }
    let (complete, usage_value) = if dispatched {
        let transport = transport.as_ref().unwrap();
        (
            transport["outcome"] == "RESPONSE_BODY_COMPLETED"
                && transport["usage_complete"].as_bool() == Some(true),
            transport.get("usage").cloned().unwrap_or(Value::Null),
        )
    } else {
        (caller_complete, rpc.raw["usage"].clone())
    };
    let usage = &usage_value;
    if !usage.is_null() && (!usage.is_object() || serde_json::to_vec(usage)?.len() > 16384) {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "bounded native usage object or null required",
        ));
    }
    let valid_usage = usage.as_object().is_some_and(|fields| {
        let input = fields.get("inputTokens").and_then(Value::as_u64);
        let output = fields.get("outputTokens").and_then(Value::as_u64);
        let numeric = fields.values().all(|value| value.as_u64().is_some());
        let reasoning_valid = fields
            .get("reasoningTokens")
            .and_then(Value::as_u64)
            .is_none_or(|reasoning| output.is_some_and(|output| reasoning <= output));
        input.is_some() && output.is_some() && numeric && reasoning_valid
    });
    if complete && !valid_usage {
        return Err(err(
            "NATIVE_USAGE_INCOMPLETE",
            "mandatory numeric native usage counters required",
        ));
    }
    // Installed native adapters can emit all-zero placeholders when upstream
    // usage is missing. Presence of native keys is not proof of known usage.
    let observed_total = [
        "inputTokens",
        "outputTokens",
        "cacheReadTokens",
        "cacheWriteTokens",
    ]
    .into_iter()
    .try_fold(0_u64, |total, key| {
        total.checked_add(usage.get(key).and_then(Value::as_u64).unwrap_or(0))
    });
    let complete = complete
        && valid_usage
        && !["abandoned", "aborted", "error"].contains(&finish.as_str())
        && observed_total.is_some_and(|total| {
            total > 0
                && usage
                    .get("totalTokens")
                    .and_then(Value::as_u64)
                    .is_none_or(|native| native == total)
        });
    if let Some(mut old) = row.get::<Option<Value>, _>("settlement") {
        let mut new = rpc.raw.clone();
        old.as_object_mut().unwrap().remove("rpc_id");
        new.as_object_mut().unwrap().remove("rpc_id");
        if old != new {
            return Err(err(
                "IDEMPOTENCY_CONFLICT",
                "protected settlement is immutable",
            ));
        }
        return Ok(rpc.reply());
    }
    sqlx::query("UPDATE native_model_requests SET status=$2,usage=$3,usage_complete=$4,settlement=$5,settled_at=clock_timestamp() WHERE request_id=$1")
        .bind(request).bind(if complete { "SETTLED" } else { "QUARANTINED" }).bind(if usage.is_null() { None } else { Some(usage.clone()) }).bind(complete).bind(&rpc.raw).execute(&mut **tx).await?;
    // Raw usage and UNKNOWN financial status are retained; no zero-cost inference.
    if !complete {
        sqlx::query("UPDATE native_child_lifecycles SET state='QUARANTINED',revoked=true WHERE allocation_id=$1 AND state<>'RELEASED'")
            .bind(lifecycle.get::<String,_>("allocation_id")).execute(&mut **tx).await?;
        sqlx::query("UPDATE native_child_allocations SET state='QUARANTINED' WHERE allocation_id=$1 AND state<>'RELEASED'")
            .bind(lifecycle.get::<String,_>("allocation_id")).execute(&mut **tx).await?;
    } else {
        finalize_disposed(tx, &lifecycle.get::<String, _>("allocation_id")).await?;
    }
    Ok(rpc.reply())
}
async fn release_native(
    tx: &mut Transaction<'_, Postgres>,
    a: &Attempt,
    rpc: &Rpc,
) -> Result<Value> {
    let lifecycle = native_lock(tx, a, rpc).await?;
    if bounded_string(&rpc.raw, "reason", 64)? != "native_disposed" {
        return Err(err(
            "NATIVE_DISPOSAL_UNCONFIRMED",
            "only actual native_disposed acknowledgement can release a child",
        ));
    }
    let allocation = lifecycle.get::<String, _>("allocation_id");
    sqlx::query("UPDATE native_child_lifecycles SET disposed_at=COALESCE(disposed_at,clock_timestamp()) WHERE allocation_id=$1")
        .bind(&allocation).execute(&mut **tx).await?;
    finalize_disposed(tx, &allocation).await?;
    // A root acknowledgement is recorded but never frees the borrowed parent reservation.
    Ok(rpc.reply())
}
// Order-independent closure: a durable native-disposed or trusted process-stop
// acknowledgement is finalized when the last complete protected settlement arrives.
async fn finalize_disposed(tx: &mut Transaction<'_, Postgres>, allocation: &str) -> Result<()> {
    let mut current = Some(allocation.to_owned());
    while let Some(allocation) = current.take() {
        let lifecycle = sqlx::query("SELECT borrowed_parent_reservation,disposed_at,process_stopped_at,state,parent_allocation_id FROM native_child_lifecycles WHERE allocation_id=$1 FOR UPDATE")
            .bind(&allocation).fetch_one(&mut **tx).await?;
        let parent = lifecycle.get::<Option<String>, _>("parent_allocation_id");
        if lifecycle.get::<String, _>("state") == "RELEASED" {
            current = parent;
            continue;
        }
        let borrowed = lifecycle.get::<bool, _>("borrowed_parent_reservation");
        // Descendant process_stopped_at can only be written by the validated
        // required physical whole-pool stop path, never the legacy root stop.
        let process_stopped = lifecycle
            .get::<Option<DateTime<Utc>>, _>("process_stopped_at")
            .is_some();
        let disposed = lifecycle
            .get::<Option<DateTime<Utc>>, _>("disposed_at")
            .is_some();
        let acknowledged = process_stopped || (!borrowed && disposed);
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_model_requests WHERE allocation_id=$1 AND status IN('ADMITTED','QUARANTINED')) OR EXISTS(SELECT 1 FROM native_child_lifecycles WHERE parent_allocation_id=$1 AND state<>'RELEASED')")
            .bind(&allocation).fetch_one(&mut **tx).await?;
        if pending && (acknowledged || disposed) {
            sqlx::query(
                "UPDATE native_child_lifecycles SET state='QUARANTINED' WHERE allocation_id=$1",
            )
            .bind(&allocation)
            .execute(&mut **tx)
            .await?;
            sqlx::query("UPDATE native_child_allocations SET state='QUARANTINED' WHERE allocation_id=$1 AND state<>'RELEASED'")
                .bind(&allocation).execute(&mut **tx).await?;
            break;
        }
        if !acknowledged {
            break;
        }
        let reason = if borrowed {
            "trusted_worker_process_stopped"
        } else if process_stopped {
            "trusted_worker_physical_pool_stopped"
        } else {
            "native_disposed"
        };
        let rows = sqlx::query("UPDATE native_child_allocations SET state='RELEASED',released_at=clock_timestamp(),release_reason=$2 WHERE allocation_id=$1 AND state<>'RELEASED' RETURNING scope_id,dimension,amount")
            .bind(&allocation).bind(reason).fetch_all(&mut **tx).await?;
        for row in rows {
            let changed = sqlx::query("UPDATE resource_limits SET allocated=allocated-$3 WHERE scope_id=$1 AND dimension=$2 AND allocated>=$3")
                .bind(row.get::<String,_>("scope_id")).bind(row.get::<String,_>("dimension")).bind(row.get::<i64,_>("amount")).execute(&mut **tx).await?.rows_affected();
            if changed != 1 {
                return Err(err(
                    "RESOURCE_LEDGER_CORRUPT",
                    "child release exceeds occupied canonical capacity",
                ));
            }
        }
        sqlx::query("UPDATE native_child_lifecycles SET state='RELEASED',released_at=clock_timestamp(),release_reason=$2 WHERE allocation_id=$1")
            .bind(&allocation).bind(reason).execute(&mut **tx).await?;
        current = parent;
    }
    Ok(())
}
async fn cancel_ack(tx: &mut Transaction<'_, Postgres>, rpc: &Rpc) -> Result<Value> {
    bounded_string(&rpc.raw, "reason", 128)?;
    if rpc.raw["active_model_requests"].as_u64() != Some(0) {
        return Err(err(
            "NATIVE_QUIESCENCE_UNCONFIRMED",
            "zero model requests required",
        ));
    }
    let sessions = rpc.raw["sessions"]
        .as_array()
        .filter(|v| v.len() <= 1024)
        .ok_or_else(|| err("NATIVE_RPC_INVALID", "bounded sessions array required"))?;
    let mut reported = BTreeSet::new();
    for session in sessions {
        exact_fields(session, &["native_session_id", "status"], &[])?;
        if session["status"] != "idle"
            || !reported.insert(bounded_string(session, "native_session_id", 256)?)
        {
            return Err(err(
                "NATIVE_QUIESCENCE_UNCONFIRMED",
                "exact unique idle sessions required",
            ));
        }
    }
    let active: BTreeSet<String> = sqlx::query_scalar("SELECT native_session_id FROM native_child_lifecycles WHERE attempt_id=$1 AND disposed_at IS NULL AND state<>'RELEASED'")
        .bind(&rpc.attempt).fetch_all(&mut **tx).await?.into_iter().collect();
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_model_requests WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED')) OR EXISTS(SELECT 1 FROM model_request_permit WHERE attempt_id=$1 AND status IN('ADMITTED','QUARANTINED'))")
        .bind(&rpc.attempt).fetch_one(&mut **tx).await?;
    if active != reported || pending {
        return Err(err(
            "NATIVE_QUIESCENCE_UNCONFIRMED",
            "session omissions or unsettled model requests retain capacity",
        ));
    }
    event(
        tx,
        &rpc.project,
        &rpc.attempt,
        rpc.generation as u64,
        "native_child.quiescence_observed",
        rpc.raw.clone(),
    )
    .await?;
    Ok(rpc.reply())
}
async fn observe_native(tx: &mut Transaction<'_, Postgres>, rpc: &Rpc) -> Result<Value> {
    let kind = bounded_string(&rpc.raw, "event", 64)?;
    if ![
        "tool/call",
        "assistant/message",
        "assistant/attempt",
        "turn/end",
        "team/member",
        "team/task",
        "team/message/queued",
        "team/message/delivered",
        "agent-preset/selected",
        "agent/status",
        "tool-workflow/run-start",
        "tool-workflow/agent-start",
        "tool-workflow/agent-end",
        "tool-workflow/run-end",
        "subagent/start",
        "subagent/end",
        "workflow/start",
        "workflow/phase",
        "workflow/end",
        "workflow/agent-start",
        "workflow/agent-end",
    ]
    .contains(&kind.as_str())
    {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "native event is not in bounded observation contract",
        ));
    }
    exact_fields(
        &rpc.raw["value"],
        &[],
        &[
            "native_session_id",
            "seq",
            "callId",
            "name",
            "usage",
            "runId",
            "childId",
            "stopReason",
            "outcome",
            "reason",
            "assistant_text_sha256",
            "interrupted",
            "id",
            "provider",
            "local",
            "parentSessionId",
            "teamId",
            "member",
            "task",
            "label",
            "phase",
            "memberSeq",
            "preset_id",
            "position_id",
            "status",
            "messageId",
            "targetId",
            "senderId",
        ],
    )?;
    for key in [
        "teamId",
        "preset_id",
        "position_id",
        "messageId",
        "targetId",
        "senderId",
    ] {
        if rpc.raw["value"].get(key).is_some() {
            bounded_string(&rpc.raw["value"], key, 256)?;
        }
    }
    for key in ["label", "phase"] {
        if rpc.raw["value"].get(key).is_some() {
            bounded_string(&rpc.raw["value"], key, 4096)?;
        }
    }
    if let Some(sequence) = rpc.raw["value"].get("memberSeq") {
        if !sequence.as_u64().is_some_and(|n| n > 0) {
            return Err(err(
                "NATIVE_RPC_INVALID",
                "positive native Workflow member sequence required",
            ));
        }
    }
    let value = &rpc.raw["value"];
    if kind.starts_with("team/")
        && value.get("teamId").is_some()
        && value["teamId"] != value["native_session_id"]
    {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "native Team records belong to their admitted Lead session",
        ));
    }
    if kind == "team/member" && (value.get("member").is_some() || value.get("teamId").is_some()) {
        exact_fields(
            value,
            &["native_session_id", "seq", "teamId", "member"],
            &[],
        )?;
        let member = &value["member"];
        exact_fields(
            member,
            &["id", "name", "provider", "context", "phase"],
            &["position_id", "preset_id"],
        )?;
        for key in ["id", "name", "provider", "position_id", "preset_id"] {
            if member.get(key).is_some() {
                bounded_string(member, key, 256)?;
            }
        }
        if !matches!(
            member["phase"].as_str(),
            Some("provisioning" | "active" | "failed")
        ) || !matches!(member["context"].as_str(), Some("fresh" | "fork"))
        {
            return Err(err(
                "NATIVE_RPC_INVALID",
                "native Team member phase/context required",
            ));
        }
    } else if kind == "team/task" && (value.get("task").is_some() || value.get("teamId").is_some())
    {
        exact_fields(value, &["native_session_id", "seq", "teamId", "task"], &[])?;
        let task = &value["task"];
        exact_fields(
            task,
            &[
                "id",
                "revision",
                "status",
                "blockedByCount",
                "writeScopesCount",
            ],
            &["ownerId"],
        )?;
        bounded_string(task, "id", 256)?;
        if task.get("ownerId").is_some() {
            bounded_string(task, "ownerId", 256)?;
        }
        if !task["revision"].as_u64().is_some_and(|n| n > 0)
            || !matches!(
                task["status"].as_str(),
                Some("pending" | "in_progress" | "completed" | "deleted")
            )
            || task["blockedByCount"].as_u64().is_none()
            || task["writeScopesCount"].as_u64().is_none()
        {
            return Err(err(
                "NATIVE_RPC_INVALID",
                "bounded native Team task snapshot required",
            ));
        }
    } else if kind == "team/message/queued" {
        exact_fields(
            value,
            &[
                "native_session_id",
                "seq",
                "teamId",
                "messageId",
                "targetId",
                "senderId",
            ],
            &[],
        )?;
    } else if kind == "team/message/delivered" {
        exact_fields(
            value,
            &[
                "native_session_id",
                "seq",
                "teamId",
                "messageId",
                "targetId",
            ],
            &[],
        )?;
    } else if kind == "agent-preset/selected" {
        exact_fields(
            value,
            &["native_session_id", "seq", "preset_id"],
            &["position_id"],
        )?;
    } else if kind == "agent/status" {
        exact_fields(value, &["native_session_id", "status"], &[])?;
        if !matches!(value["status"].as_str(), Some("idle" | "running")) {
            return Err(err(
                "NATIVE_RPC_INVALID",
                "native whole-Agent status required",
            ));
        }
    }
    if value.get("seq").is_some() && value["seq"].as_u64().is_none() {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "native observation sequence must be an integer",
        ));
    }
    if kind == "tool/call" {
        exact_fields(
            &rpc.raw["value"],
            &["native_session_id", "seq", "callId", "name"],
            &[],
        )?;
        bounded_string(&rpc.raw["value"], "native_session_id", 256)?;
        bounded_string(&rpc.raw["value"], "callId", 256)?;
        bounded_string(&rpc.raw["value"], "name", 128)?;
        if rpc.raw["value"]["seq"].as_u64().is_none() {
            return Err(err(
                "NATIVE_RPC_INVALID",
                "tool observation sequence must be an integer",
            ));
        }
    }
    // Source observations may name a disposed-but-admitted lifecycle while its
    // ordered tail drains. They may never name an invented session identity.
    if value.get("native_session_id").is_some() {
        let native = bounded_string(value, "native_session_id", 256)?;
        let attributed: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM native_child_lifecycles WHERE attempt_id=$1 AND native_session_id=$2)")
            .bind(&rpc.attempt).bind(native).fetch_one(&mut **tx).await?;
        if !attributed {
            return Err(err(
                "NATIVE_IDENTITY_STALE",
                "native observation must name an admitted lifecycle",
            ));
        }
    }
    if serde_json::to_vec(&rpc.raw["value"])?.len() > 16384 {
        return Err(err(
            "NATIVE_RPC_INVALID",
            "native observation exceeds bound",
        ));
    }
    event(
        tx,
        &rpc.project,
        &rpc.attempt,
        rpc.generation as u64,
        "native_child.observed",
        serde_json::json!({"event":kind,"value":rpc.raw["value"],"grants_authority":false}),
    )
    .await?;
    Ok(rpc.reply())
}
