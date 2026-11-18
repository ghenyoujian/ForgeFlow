//! ECP Phase 2 registry: discovery and frozen profile identity, separate from grants.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegistrationInput {
    pub principal_id: String,
    pub display_name: String,
    #[serde(default)]
    pub executor_kinds: Vec<String>,
    #[serde(default)]
    pub project_set: Vec<String>,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutorProfileInput {
    pub profile_id: String,
    pub registration_id: String,
    pub provider: String,
    pub profile_version: String,
    pub binary_digest: String,
    pub adapter_digest: String,
    pub configuration_digest: String,
    pub capabilities: Value,
    pub support_status: String,
    pub evidence_status: String,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Store {
    pub async fn register_agent(
        &self,
        account: &str,
        workspace: &str,
        input: AgentRegistrationInput,
    ) -> Result<Value> {
        if input.request_key.len() < 16
            || input.request_key.len() > 128
            || input.display_name.trim().is_empty()
            || input.executor_kinds.is_empty()
        {
            return Err(err(
                "VALIDATION_ERROR",
                "agent registration requires a request key, name and executor kind",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL FOR SHARE",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        if role.as_deref() != Some("OWNER") {
            return Err(err("FORBIDDEN", "workspace owner required"));
        }
        let owner = format!("human:{account}");
        let principal_ok: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=$1 AND status='ACTIVE' AND (workspace_id=$2 OR (kind='HUMAN' AND account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$2 AND revoked_at IS NULL))))").bind(&input.principal_id).bind(workspace).fetch_one(&mut *tx).await?;
        if !principal_ok {
            return Err(err(
                "NOT_FOUND",
                "agent principal is not active in this workspace",
            ));
        }
        if let Some(value) = sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('registration_id',registration_id,'principal_id',principal_id,'display_name',display_name,'executor_kinds',executor_kinds,'project_set',project_set,'status',status,'revision',revision,'replayed',true) FROM agent_registrations WHERE workspace_id=$1 AND principal_id=$2 AND request_key=$3 FOR SHARE").bind(workspace).bind(&input.principal_id).bind(&input.request_key).fetch_optional(&mut *tx).await? {
            tx.commit().await?; return Ok(value);
        }
        let registration_id = id();
        let value: Value=sqlx::query_scalar("INSERT INTO agent_registrations(registration_id,workspace_id,principal_id,owner_principal_id,display_name,executor_kinds,project_set,request_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING jsonb_build_object('registration_id',registration_id,'workspace_id',workspace_id,'principal_id',principal_id,'owner_principal_id',owner_principal_id,'display_name',display_name,'executor_kinds',executor_kinds,'project_set',project_set,'status',status,'revision',revision,'replayed',false)").bind(&registration_id).bind(workspace).bind(&input.principal_id).bind(owner).bind(&input.display_name).bind(json!(input.executor_kinds)).bind(json!(input.project_set)).bind(&input.request_key).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn freeze_executor_profile(
        &self,
        account: &str,
        workspace: &str,
        input: ExecutorProfileInput,
    ) -> Result<Value> {
        if input.profile_id.trim().is_empty()
            || input.provider.trim().is_empty()
            || !valid_digest(&input.binary_digest)
            || !valid_digest(&input.adapter_digest)
            || !valid_digest(&input.configuration_digest)
            || !input.capabilities.is_object()
        {
            return Err(err(
                "VALIDATION_ERROR",
                "profile identity and capability digests are required",
            ));
        }
        if !matches!(
            input.support_status.as_str(),
            "SUPPORTED" | "PARTIAL" | "UNSUPPORTED" | "UNKNOWN"
        ) || !matches!(
            input.evidence_status.as_str(),
            "VERIFIED" | "FAILED" | "INCONCLUSIVE" | "NOT_RUN" | "BLOCKED"
        ) {
            return Err(err(
                "VALIDATION_ERROR",
                "unsupported profile or evidence status",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL FOR SHARE",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        if role.as_deref() != Some("OWNER") {
            return Err(err("FORBIDDEN", "workspace owner required"));
        }
        let registration_exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_registrations WHERE registration_id=$1 AND workspace_id=$2 AND status<>'REVOKED')").bind(&input.registration_id).bind(workspace).fetch_one(&mut *tx).await?;
        if !registration_exists {
            return Err(err("NOT_FOUND", "agent registration is unavailable"));
        }
        let inserted: Option<Value> = sqlx::query_scalar("INSERT INTO executor_profile_registry(profile_id,workspace_id,registration_id,provider,profile_version,binary_digest,adapter_digest,configuration_digest,capabilities,support_status,evidence_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(profile_id) DO NOTHING RETURNING jsonb_build_object('profile_id',profile_id,'workspace_id',workspace_id,'registration_id',registration_id,'provider',provider,'profile_version',profile_version,'binary_digest',binary_digest,'adapter_digest',adapter_digest,'configuration_digest',configuration_digest,'capabilities',capabilities,'support_status',support_status,'evidence_status',evidence_status,'status',status,'revision',revision)").bind(&input.profile_id).bind(workspace).bind(&input.registration_id).bind(&input.provider).bind(&input.profile_version).bind(&input.binary_digest).bind(&input.adapter_digest).bind(&input.configuration_digest).bind(&input.capabilities).bind(&input.support_status).bind(&input.evidence_status).fetch_optional(&mut *tx).await?;
        let value = if let Some(value) = inserted {
            value
        } else {
            sqlx::query_scalar("SELECT jsonb_build_object('profile_id',profile_id,'workspace_id',workspace_id,'registration_id',registration_id,'provider',provider,'profile_version',profile_version,'binary_digest',binary_digest,'adapter_digest',adapter_digest,'configuration_digest',configuration_digest,'capabilities',capabilities,'support_status',support_status,'evidence_status',evidence_status,'status',status,'revision',revision) FROM executor_profile_registry WHERE profile_id=$1 AND workspace_id=$2")
                .bind(&input.profile_id).bind(workspace).fetch_optional(&mut *tx).await?
                .ok_or_else(|| err("OBJECT_EXISTS", "executor profile identity belongs to another workspace"))?
        };
        tx.commit().await?;
        Ok(value)
    }

    pub async fn registry_snapshot(&self, account: &str, workspace: &str) -> Result<Value> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&self.pool)
        .await?;
        if role.is_none() {
            return Err(err("FORBIDDEN", "workspace membership required"));
        }
        let agents:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('registration_id',registration_id,'principal_id',principal_id,'display_name',display_name,'executor_kinds',executor_kinds,'project_set',project_set,'status',status,'revision',revision) FROM agent_registrations WHERE workspace_id=$1 ORDER BY created_at,registration_id").bind(workspace).fetch_all(&self.pool).await?;
        let profiles:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('profile_id',profile_id,'registration_id',registration_id,'provider',provider,'profile_version',profile_version,'binary_digest',binary_digest,'adapter_digest',adapter_digest,'configuration_digest',configuration_digest,'capabilities',capabilities,'support_status',support_status,'evidence_status',evidence_status,'status',status,'revision',revision) FROM executor_profile_registry WHERE workspace_id=$1 ORDER BY created_at,profile_id").bind(workspace).fetch_all(&self.pool).await?;
        Ok(json!({"agents":agents,"profiles":profiles,"qualification":"discovery_only"}))
    }
}
