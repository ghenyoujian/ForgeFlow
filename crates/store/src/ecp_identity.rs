//! ECP immutable principals and capability grants.
//! This module is additive to the 0014 account/network compatibility surface.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrantInput {
    pub principal_id: String,
    pub parent_grant_id: Option<String>,
    pub action_set: Vec<String>,
    #[serde(default)]
    pub project_set: Vec<String>,
    #[serde(default)]
    pub write_set: Vec<String>,
    #[serde(default)]
    pub executor_set: Vec<String>,
    #[serde(default)]
    pub budget: Value,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub request_key: String,
}

fn subset(child: &[String], parent: &Value) -> bool {
    let Some(values) = parent.as_array() else {
        return false;
    };
    let allowed: BTreeSet<&str> = values.iter().filter_map(Value::as_str).collect();
    child.iter().all(|value| allowed.contains(value.as_str()))
}

fn budget_subset(child: &Value, parent: &Value) -> bool {
    let (Some(child), Some(parent)) = (child.as_object(), parent.as_object()) else {
        return false;
    };
    child.iter().all(|(key, value)| {
        let Some(parent_value) = parent.get(key) else {
            return false;
        };
        match (value.as_f64(), parent_value.as_f64()) {
            (Some(child), Some(parent)) => child <= parent,
            _ => value == parent_value,
        }
    })
}

impl Store {
    pub async fn principal_for_account(&self, account: &str) -> Result<Option<Value>> {
        Ok(sqlx::query_scalar(
            "SELECT jsonb_build_object('principal_id',principal_id,'kind',kind,'account_id',account_id,'workspace_id',workspace_id,'display_name',display_name,'status',status,'authorization_epoch',authorization_epoch,'revision',revision) FROM principals WHERE account_id=$1 AND kind='HUMAN'",
        )
        .bind(account)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn workspace_principals(&self, workspace: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar(
            "SELECT jsonb_build_object('principal_id',principal_id,'kind',kind,'account_id',account_id,'integration_id',integration_id,'network_agent_id',network_agent_id,'workspace_id',workspace_id,'display_name',display_name,'status',status,'authorization_epoch',authorization_epoch,'revision',revision) FROM principals WHERE workspace_id=$1 OR (kind='HUMAN' AND account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$1 AND revoked_at IS NULL)) ORDER BY created_at,principal_id",
        )
        .bind(workspace)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn workspace_capability_grants(
        &self,
        account: &str,
        workspace: &str,
    ) -> Result<Vec<Value>> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&self.pool)
        .await?;
        if !matches!(role.as_deref(), Some("OWNER" | "EDITOR")) {
            return Err(err(
                "FORBIDDEN",
                "workspace capability read requires an editor",
            ));
        }
        Ok(sqlx::query_scalar(
            "SELECT jsonb_build_object('grant_id',grant_id,'workspace_id',workspace_id,'principal_id',principal_id,'issuer_principal_id',issuer_principal_id,'parent_grant_id',parent_grant_id,'action_set',action_set,'project_set',project_set,'write_set',write_set,'executor_set',executor_set,'budget',budget,'authorization_epoch',authorization_epoch,'revision',revision,'expires_at',expires_at,'revoked_at',revoked_at,'created_at',created_at) FROM capability_grants WHERE workspace_id=$1 ORDER BY created_at,grant_id",
        )
        .bind(workspace).fetch_all(&self.pool).await?)
    }

    pub async fn create_capability_grant(
        &self,
        account: &str,
        workspace: &str,
        input: CapabilityGrantInput,
    ) -> Result<Value> {
        if input.request_key.trim().len() < 16
            || input.request_key.len() > 128
            || input.action_set.is_empty()
        {
            return Err(err(
                "VALIDATION_ERROR",
                "capability grant requires a request key and action set",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let actor_role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL FOR SHARE",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        if actor_role.as_deref() != Some("OWNER") {
            return Err(err(
                "FORBIDDEN",
                "only a workspace owner may issue capabilities",
            ));
        }
        let issuer = format!("human:{account}");
        let target: Option<(String, String, i64)> = sqlx::query_as("SELECT principal_id,status,authorization_epoch FROM principals WHERE principal_id=$1 AND (workspace_id=$2 OR (kind='HUMAN' AND account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$2 AND revoked_at IS NULL))) FOR SHARE")
            .bind(&input.principal_id).bind(workspace).fetch_optional(&mut *tx).await?;
        let Some((principal_id, status, epoch)) = target else {
            return Err(err("NOT_FOUND", "principal is outside this workspace"));
        };
        if status != "ACTIVE" {
            return Err(err("FORBIDDEN", "principal is revoked or quarantined"));
        }
        let action_json = json!(input.action_set);
        let project_json = json!(input.project_set);
        let write_json = json!(input.write_set);
        let executor_json = json!(input.executor_set);
        let budget = if input.budget.is_null() {
            json!({})
        } else {
            input.budget
        };
        if let Some(parent_id) = &input.parent_grant_id {
            let parent: Option<(String, Value, Value, Value, Value, Value)> = sqlx::query_as("SELECT workspace_id,action_set,project_set,write_set,executor_set,budget FROM capability_grants WHERE grant_id=$1 AND workspace_id=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE")
                .bind(parent_id).bind(workspace).fetch_optional(&mut *tx).await?;
            let Some((
                parent_workspace,
                parent_actions,
                parent_projects,
                parent_writes,
                parent_executors,
                parent_budget,
            )) = parent
            else {
                return Err(err("FORBIDDEN", "parent capability is not active"));
            };
            if parent_workspace != workspace
                || !subset(&input.action_set, &parent_actions)
                || !subset(&input.project_set, &parent_projects)
                || !subset(&input.write_set, &parent_writes)
                || !subset(&input.executor_set, &parent_executors)
                || !budget_subset(&budget, &parent_budget)
            {
                return Err(err(
                    "CAPABILITY_ESCALATION",
                    "child capability exceeds its parent scope or budget",
                ));
            }
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('grant_id',grant_id,'principal_id',principal_id,'action_set',action_set,'project_set',project_set,'write_set',write_set,'executor_set',executor_set,'budget',budget,'authorization_epoch',authorization_epoch,'revision',revision,'replayed',true) FROM capability_grants WHERE workspace_id=$1 AND principal_id=$2 AND request_key=$3 FOR SHARE")
            .bind(workspace).bind(&principal_id).bind(&input.request_key).fetch_optional(&mut *tx).await? {
            if existing["action_set"] != action_json || existing["project_set"] != project_json || existing["write_set"] != write_json || existing["executor_set"] != executor_json || existing["budget"] != budget {
                return Err(err("IDEMPOTENCY_CONFLICT", "capability request key already has another payload"));
            }
            tx.commit().await?;
            return Ok(existing);
        }
        let grant_id = id();
        let revision = 1_i64;
        let value: Value = sqlx::query_scalar("INSERT INTO capability_grants(grant_id,workspace_id,principal_id,issuer_principal_id,parent_grant_id,action_set,project_set,write_set,executor_set,budget,authorization_epoch,revision,request_key,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING jsonb_build_object('grant_id',grant_id,'workspace_id',workspace_id,'principal_id',principal_id,'issuer_principal_id',issuer_principal_id,'parent_grant_id',parent_grant_id,'action_set',action_set,'project_set',project_set,'write_set',write_set,'executor_set',executor_set,'budget',budget,'authorization_epoch',authorization_epoch,'revision',revision,'expires_at',expires_at,'replayed',false)")
            .bind(&grant_id).bind(workspace).bind(&principal_id).bind(&issuer).bind(&input.parent_grant_id).bind(&action_json).bind(&project_json).bind(&write_json).bind(&executor_json).bind(&budget).bind(epoch).bind(revision).bind(&input.request_key).bind(input.expires_at).fetch_one(&mut *tx).await?;
        let event_id = id();
        sqlx::query("INSERT INTO workspace_security_events(event_id,workspace_id,principal_id,kind,object_id,object_revision,payload) VALUES($1,$2,$3,'CAPABILITY_GRANTED',$4,$5,$6)")
            .bind(&event_id).bind(workspace).bind(&principal_id).bind(&grant_id).bind(revision).bind(&value).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspace_security_outbox(outbox_id,event_id,workspace_id,kind,payload) VALUES($1,$2,$3,'CAPABILITY_GRANTED',$4)")
            .bind(id()).bind(&event_id).bind(workspace).bind(&value).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn revoke_capability_grant(
        &self,
        account: &str,
        workspace: &str,
        grant: &str,
        expected_revision: i64,
    ) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        if role.as_deref() != Some("OWNER") {
            return Err(err(
                "FORBIDDEN",
                "only a workspace owner may revoke capabilities",
            ));
        }
        let row: Option<(String, i64)> = sqlx::query_as("SELECT principal_id,revision FROM capability_grants WHERE grant_id=$1 AND workspace_id=$2 FOR UPDATE")
            .bind(grant).bind(workspace).fetch_optional(&mut *tx).await?;
        let Some((principal, revision)) = row else {
            return Err(err("NOT_FOUND", "capability grant not found"));
        };
        if revision != expected_revision {
            return Err(err(
                "REVISION_CONFLICT",
                "capability grant revision changed",
            ));
        }
        let next = revision + 1;
        let value: Value = sqlx::query_scalar("UPDATE capability_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revision=$3 WHERE grant_id=$1 AND workspace_id=$2 RETURNING jsonb_build_object('grant_id',grant_id,'principal_id',principal_id,'revision',revision,'revoked_at',revoked_at)")
            .bind(grant).bind(workspace).bind(next).fetch_one(&mut *tx).await?;
        let event_id = id();
        sqlx::query("INSERT INTO workspace_security_events(event_id,workspace_id,principal_id,kind,object_id,object_revision,payload) VALUES($1,$2,$3,'CAPABILITY_REVOKED',$4,$5,$6)")
            .bind(&event_id).bind(workspace).bind(&principal).bind(grant).bind(next).bind(&value).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspace_security_outbox(outbox_id,event_id,workspace_id,kind,payload) VALUES($1,$2,$3,'CAPABILITY_REVOKED',$4)")
            .bind(id()).bind(&event_id).bind(workspace).bind(&value).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn child_scopes_are_strict_subsets() {
        assert!(subset(
            &["project.read".into()],
            &json!(["project.read", "project.write"])
        ));
        assert!(!subset(&["project.write".into()], &json!(["project.read"])));
        assert!(budget_subset(
            &json!({"requests": 5}),
            &json!({"requests": 10})
        ));
        assert!(!budget_subset(
            &json!({"requests": 11}),
            &json!({"requests": 10})
        ));
    }
}
