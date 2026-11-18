//! Minimal ECP Phase 6 resource and cost runtime.
//!
//! The 0019 tables are deliberately an additive boundary. Logical quota
//! accounting is enforced here when a profile supplies a numeric limit;
//! physical limits are retained as observations and never treated as an OS
//! or cgroup guarantee. Unknown provider usage keeps a reservation held.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceProfileInput {
    pub profile_id: String,
    pub profile_version: String,
    pub logical_limits: Value,
    pub physical_limits: Value,
    #[serde(default = "default_enforcement_status")]
    pub enforcement_status: String,
    pub source_sha256: String,
}
fn default_enforcement_status() -> String {
    "UNKNOWN".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetReservationInput {
    pub reservation_id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    pub dimension: String,
    pub amount: f64,
    pub authorization_epoch: i64,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CostLedgerInput {
    pub ledger_id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub reservation_id: Option<String>,
    #[serde(default)]
    pub provider_request_id: Option<String>,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub estimated_cost: Option<f64>,
    #[serde(default)]
    pub settled_cost: Option<f64>,
    #[serde(default)]
    pub usage: Value,
    pub settlement_status: String,
    #[serde(default)]
    pub source_sha256: Option<String>,
}
fn default_currency() -> String {
    "UNKNOWN".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseRevocationInput {
    pub revocation_id: String,
    #[serde(default)]
    pub lease_id: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    pub generation: i64,
    pub reason_code: String,
    pub source_sha256: String,
}

fn ensure_resource_id(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(err("VALIDATION_ERROR", format!("invalid {label}")));
    }
    Ok(())
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_amount(value: Option<f64>, label: &str) -> Result<()> {
    if let Some(value) = value {
        if !value.is_finite() || value < 0.0 {
            return Err(err("VALIDATION_ERROR", format!("invalid {label}")));
        }
    }
    Ok(())
}

async fn owner_tx(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    workspace: &str,
) -> Result<String> {
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL FOR SHARE")
        .bind(workspace).bind(account).fetch_optional(&mut **tx).await?;
    if role.as_deref() != Some("OWNER") {
        return Err(err(
            "FORBIDDEN",
            "workspace owner required for resource governance",
        ));
    }
    let principal = format!("human:{account}");
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=$1 AND workspace_id=$2 AND kind='HUMAN' AND status='ACTIVE')")
        .bind(&principal).bind(workspace).fetch_one(&mut **tx).await?;
    if !active {
        return Err(err("FORBIDDEN", "workspace owner principal is not active"));
    }
    Ok(principal)
}
async fn project_in_workspace(
    tx: &mut Transaction<'_, Postgres>,
    project: &Option<String>,
    workspace: &str,
) -> Result<()> {
    if let Some(project) = project {
        let bound: Option<String> =
            sqlx::query_scalar("SELECT workspace_id FROM project_workspaces WHERE project_id=$1")
                .bind(project)
                .fetch_optional(&mut **tx)
                .await?;
        if bound.as_deref() != Some(workspace) {
            return Err(err("FORBIDDEN", "project is outside workspace"));
        }
    }
    Ok(())
}

impl Store {
    pub async fn create_ecp_resource_profile(
        &self,
        account: &str,
        workspace: &str,
        input: ResourceProfileInput,
    ) -> Result<Value> {
        ensure_resource_id(&input.profile_id, "profile_id")?;
        ensure_resource_id(&input.profile_version, "profile_version")?;
        if !input.logical_limits.is_object() || !input.physical_limits.is_object() {
            return Err(err(
                "VALIDATION_ERROR",
                "logical_limits and physical_limits must be JSON objects",
            ));
        }
        if !matches!(
            input.enforcement_status.as_str(),
            "ENFORCED" | "OBSERVED" | "UNKNOWN" | "BLOCKED"
        ) || !valid_digest(&input.source_sha256)
        {
            return Err(err(
                "VALIDATION_ERROR",
                "invalid enforcement status or source SHA-256",
            ));
        }
        let mut tx = self.pool.begin().await?;
        owner_tx(&mut tx, account, workspace).await?;
        let inserted: Option<Value> = sqlx::query_scalar("INSERT INTO ecp_resource_profiles(profile_id,workspace_id,profile_version,logical_limits,physical_limits,enforcement_status,source_sha256) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(profile_id) DO NOTHING RETURNING jsonb_build_object('profile_id',profile_id,'workspace_id',workspace_id,'profile_version',profile_version,'logical_limits',logical_limits,'physical_limits',physical_limits,'enforcement_status',enforcement_status,'source_sha256',source_sha256,'revision',revision,'replayed',false)")
            .bind(&input.profile_id).bind(workspace).bind(&input.profile_version).bind(&input.logical_limits).bind(&input.physical_limits).bind(&input.enforcement_status).bind(&input.source_sha256).fetch_optional(&mut *tx).await?;
        let value = if let Some(value) = inserted {
            value
        } else {
            sqlx::query_scalar("SELECT jsonb_build_object('profile_id',profile_id,'workspace_id',workspace_id,'profile_version',profile_version,'logical_limits',logical_limits,'physical_limits',physical_limits,'enforcement_status',enforcement_status,'source_sha256',source_sha256,'revision',revision,'replayed',true) FROM ecp_resource_profiles WHERE profile_id=$1 AND workspace_id=$2 AND profile_version=$3 AND logical_limits=$4 AND physical_limits=$5 AND enforcement_status=$6 AND source_sha256=$7")
                .bind(&input.profile_id).bind(workspace).bind(&input.profile_version).bind(&input.logical_limits).bind(&input.physical_limits).bind(&input.enforcement_status).bind(&input.source_sha256).fetch_optional(&mut *tx).await?.ok_or_else(|| err("IDEMPOTENCY_CONFLICT", "profile identity is immutable"))?
        };
        tx.commit().await?;
        Ok(value)
    }

    pub async fn reserve_ecp_budget(
        &self,
        account: &str,
        workspace: &str,
        input: BudgetReservationInput,
    ) -> Result<Value> {
        ensure_resource_id(&input.reservation_id, "reservation_id")?;
        ensure_resource_id(&input.dimension, "dimension")?;
        if input.idempotency_key.len() < 16 || input.idempotency_key.len() > 128 {
            return Err(err("VALIDATION_ERROR", "idempotency key length is invalid"));
        }
        if !matches!(
            input.dimension.as_str(),
            "active_slot"
                | "coding_slot"
                | "cpu_units"
                | "memory_bytes"
                | "gpu_units"
                | "provider_inflight"
                | "model_tokens"
                | "model_cost"
        ) || !input.amount.is_finite()
            || input.amount <= 0.0
            || input.authorization_epoch <= 0
        {
            return Err(err("VALIDATION_ERROR", "invalid budget reservation"));
        }
        let mut tx = self.pool.begin().await?;
        let owner = owner_tx(&mut tx, account, workspace).await?;
        project_in_workspace(&mut tx, &input.project_id, workspace).await?;
        if let Some(principal) = &input.principal_id {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=$1 AND status='ACTIVE' AND (workspace_id=$2 OR (kind='HUMAN' AND account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$2 AND revoked_at IS NULL))))")
                .bind(principal).bind(workspace).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(err(
                    "FORBIDDEN",
                    "reservation principal is outside workspace",
                ));
            }
        }
        let owner_epoch: i64 = sqlx::query_scalar(
            "SELECT authorization_epoch FROM principals WHERE principal_id=$1 FOR SHARE",
        )
        .bind(&owner)
        .fetch_one(&mut *tx)
        .await?;
        if owner_epoch != input.authorization_epoch {
            return Err(err("STALE_AUTHORIZATION", "authorization epoch is stale"));
        }
        if let Some(profile) = &input.profile_id {
            let exceeds: Option<bool> = sqlx::query_scalar("SELECT CASE WHEN jsonb_typeof(logical_limits->$2)='number' THEN COALESCE((SELECT SUM(reserved_amount) FROM ecp_budget_reservations WHERE profile_id=$1 AND dimension=$2 AND state IN ('RESERVED','HELD') AND NOT (idempotency_key=$5 AND workspace_id=$4)),0)+$3::numeric > (logical_limits->$2 #>> '{}')::numeric ELSE false END FROM ecp_resource_profiles WHERE profile_id=$1 AND workspace_id=$4 FOR UPDATE")
                .bind(profile).bind(&input.dimension).bind(input.amount).bind(workspace).bind(&input.idempotency_key).fetch_optional(&mut *tx).await?;
            match exceeds {
                None => return Err(err("NOT_FOUND", "resource profile not found")),
                Some(true) => {
                    return Err(err("CAPACITY_EXCEEDED", "logical resource limit exceeded"));
                }
                Some(false) => {}
            }
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('reservation_id',reservation_id,'workspace_id',workspace_id,'project_id',project_id,'principal_id',principal_id,'attempt_id',attempt_id,'profile_id',profile_id,'dimension',dimension,'amount',amount,'reserved_amount',reserved_amount,'state',state,'authorization_epoch',authorization_epoch,'idempotency_key',idempotency_key,'replayed',true) FROM ecp_budget_reservations WHERE workspace_id=$1 AND idempotency_key=$2 AND dimension=$3 FOR UPDATE")
            .bind(workspace).bind(&input.idempotency_key).bind(&input.dimension).fetch_optional(&mut *tx).await? {
            let same: bool = sqlx::query_scalar("SELECT amount=$4::numeric AND ($5::text IS NULL OR profile_id=$5) FROM ecp_budget_reservations WHERE workspace_id=$1 AND idempotency_key=$2 AND dimension=$3")
                .bind(workspace).bind(&input.idempotency_key).bind(&input.dimension).bind(input.amount).bind(&input.profile_id).fetch_one(&mut *tx).await?;
            if !same { return Err(err("IDEMPOTENCY_CONFLICT", "budget key already has another reservation")); }
            tx.commit().await?; return Ok(existing);
        }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_budget_reservations(reservation_id,workspace_id,project_id,principal_id,attempt_id,profile_id,dimension,amount,reserved_amount,state,idempotency_key,authorization_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,'RESERVED',$9,$10) RETURNING jsonb_build_object('reservation_id',reservation_id,'workspace_id',workspace_id,'project_id',project_id,'principal_id',principal_id,'attempt_id',attempt_id,'profile_id',profile_id,'dimension',dimension,'amount',amount,'reserved_amount',reserved_amount,'state',state,'authorization_epoch',authorization_epoch,'idempotency_key',idempotency_key,'replayed',false)")
            .bind(&input.reservation_id).bind(workspace).bind(&input.project_id).bind(&input.principal_id).bind(&input.attempt_id).bind(&input.profile_id).bind(&input.dimension).bind(input.amount).bind(&input.idempotency_key).bind(input.authorization_epoch).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn record_ecp_cost(
        &self,
        account: &str,
        workspace: &str,
        input: CostLedgerInput,
    ) -> Result<Value> {
        ensure_resource_id(&input.ledger_id, "ledger_id")?;
        if input.currency.trim().is_empty() || !input.usage.is_object() {
            return Err(err(
                "VALIDATION_ERROR",
                "currency and object usage are required",
            ));
        }
        if !matches!(
            input.settlement_status.as_str(),
            "ADMITTED" | "SETTLED" | "PARTIAL" | "UNKNOWN" | "QUARANTINED" | "REJECTED"
        ) {
            return Err(err("VALIDATION_ERROR", "invalid settlement status"));
        }
        valid_amount(input.estimated_cost, "estimated_cost")?;
        valid_amount(input.settled_cost, "settled_cost")?;
        if let Some(source) = &input.source_sha256 {
            if !valid_digest(source) {
                return Err(err("VALIDATION_ERROR", "invalid source SHA-256"));
            }
        }
        let mut tx = self.pool.begin().await?;
        owner_tx(&mut tx, account, workspace).await?;
        project_in_workspace(&mut tx, &input.project_id, workspace).await?;
        if let Some(provider) = &input.provider_request_id {
            if let Some(value) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('ledger_id',ledger_id,'workspace_id',workspace_id,'project_id',project_id,'attempt_id',attempt_id,'reservation_id',reservation_id,'provider_request_id',provider_request_id,'currency',currency,'estimated_cost',estimated_cost,'settled_cost',settled_cost,'usage',usage,'settlement_status',settlement_status,'source_sha256',source_sha256,'replayed',true) FROM ecp_cost_ledger WHERE workspace_id=$1 AND provider_request_id=$2 FOR UPDATE")
                .bind(workspace).bind(provider).fetch_optional(&mut *tx).await? { tx.commit().await?; return Ok(value); }
        }
        if let Some(value) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('ledger_id',ledger_id,'workspace_id',workspace_id,'project_id',project_id,'attempt_id',attempt_id,'reservation_id',reservation_id,'provider_request_id',provider_request_id,'currency',currency,'estimated_cost',estimated_cost,'settled_cost',settled_cost,'usage',usage,'settlement_status',settlement_status,'source_sha256',source_sha256,'replayed',true) FROM ecp_cost_ledger WHERE ledger_id=$1 AND workspace_id=$2 FOR UPDATE")
            .bind(&input.ledger_id).bind(workspace).fetch_optional(&mut *tx).await? { tx.commit().await?; return Ok(value); }
        if let Some(reservation) = &input.reservation_id {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ecp_budget_reservations WHERE reservation_id=$1 AND workspace_id=$2)").bind(reservation).bind(workspace).fetch_one(&mut *tx).await?;
            if !exists {
                return Err(err("NOT_FOUND", "budget reservation not found"));
            }
        }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_cost_ledger(ledger_id,workspace_id,project_id,attempt_id,reservation_id,provider_request_id,currency,estimated_cost,settled_cost,usage,settlement_status,source_sha256,settled_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $11='SETTLED' THEN clock_timestamp() ELSE NULL END) RETURNING jsonb_build_object('ledger_id',ledger_id,'workspace_id',workspace_id,'project_id',project_id,'attempt_id',attempt_id,'reservation_id',reservation_id,'provider_request_id',provider_request_id,'currency',currency,'estimated_cost',estimated_cost,'settled_cost',settled_cost,'usage',usage,'settlement_status',settlement_status,'source_sha256',source_sha256,'settled_at',settled_at,'replayed',false)")
            .bind(&input.ledger_id).bind(workspace).bind(&input.project_id).bind(&input.attempt_id).bind(&input.reservation_id).bind(&input.provider_request_id).bind(&input.currency).bind(input.estimated_cost).bind(input.settled_cost).bind(&input.usage).bind(&input.settlement_status).bind(&input.source_sha256).fetch_one(&mut *tx).await?;
        if let Some(reservation) = &input.reservation_id {
            let next_state = match input.settlement_status.as_str() {
                "SETTLED" => "SETTLED",
                "REJECTED" => "QUARANTINED",
                _ => "HELD",
            };
            sqlx::query("UPDATE ecp_budget_reservations SET state=$2,reserved_amount=CASE WHEN $2='SETTLED' THEN 0 ELSE reserved_amount END,released_at=CASE WHEN $2='SETTLED' THEN clock_timestamp() ELSE released_at END WHERE reservation_id=$1 AND workspace_id=$3")
                .bind(reservation).bind(next_state).bind(workspace).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(value)
    }

    pub async fn revoke_ecp_lease(
        &self,
        account: &str,
        workspace: &str,
        input: LeaseRevocationInput,
    ) -> Result<Value> {
        ensure_resource_id(&input.revocation_id, "revocation_id")?;
        ensure_resource_id(&input.reason_code, "reason_code")?;
        if input.generation <= 0 || !valid_digest(&input.source_sha256) {
            return Err(err("VALIDATION_ERROR", "invalid lease revocation"));
        }
        if input.lease_id.is_none() && input.principal_id.is_none() {
            return Err(err(
                "VALIDATION_ERROR",
                "lease_id or principal_id is required",
            ));
        }
        let mut tx = self.pool.begin().await?;
        owner_tx(&mut tx, account, workspace).await?;
        if let Some(principal) = &input.principal_id {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=$1 AND (workspace_id=$2 OR (kind='HUMAN' AND account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$2 AND revoked_at IS NULL))))").bind(principal).bind(workspace).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(err(
                    "FORBIDDEN",
                    "revocation principal is outside workspace",
                ));
            }
        }
        if let Some(value) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('revocation_id',revocation_id,'workspace_id',workspace_id,'lease_id',lease_id,'principal_id',principal_id,'generation',generation,'reason_code',reason_code,'status',status,'source_sha256',source_sha256,'created_at',created_at,'observed_at',observed_at,'replayed',true) FROM ecp_lease_revocations WHERE revocation_id=$1 AND workspace_id=$2 FOR UPDATE").bind(&input.revocation_id).bind(workspace).fetch_optional(&mut *tx).await? { tx.commit().await?; return Ok(value); }
        let mut status = "REQUESTED";
        let mut lease_id = input.lease_id.clone();
        if let Some(lease) = &input.lease_id {
            let row = sqlx::query("SELECT l.generation FROM leases l JOIN project_workspaces pw ON pw.project_id=l.project_id WHERE l.lease_id=$1 AND pw.workspace_id=$2 FOR UPDATE").bind(lease).bind(workspace).fetch_optional(&mut *tx).await?;
            match row {
                Some(row) => {
                    let generation: i64 = row.try_get("generation")?;
                    if generation == input.generation {
                        sqlx::query("UPDATE leases SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE lease_id=$1").bind(lease).execute(&mut *tx).await?;
                        status = "OBSERVED";
                    } else {
                        status = "UNKNOWN";
                    }
                }
                None => {
                    status = "UNKNOWN";
                    lease_id = None;
                }
            }
        }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_lease_revocations(revocation_id,workspace_id,lease_id,principal_id,generation,reason_code,status,source_sha256,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $7='OBSERVED' THEN clock_timestamp() ELSE NULL END) RETURNING jsonb_build_object('revocation_id',revocation_id,'workspace_id',workspace_id,'lease_id',lease_id,'principal_id',principal_id,'generation',generation,'reason_code',reason_code,'status',status,'source_sha256',source_sha256,'created_at',created_at,'observed_at',observed_at,'replayed',false)")
            .bind(&input.revocation_id).bind(workspace).bind(&lease_id).bind(&input.principal_id).bind(input.generation).bind(&input.reason_code).bind(status).bind(&input.source_sha256).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }
}
