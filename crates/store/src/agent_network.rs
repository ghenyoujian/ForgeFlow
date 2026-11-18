//! Durable peer communication. A delivery receipt is never execution evidence.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMessageInput {
    pub client_message_id: String,
    pub recipient_agent_id: String,
    #[serde(default)]
    pub sender_agent_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    pub parts: Vec<Value>,
}
const MESSAGE_VIEW: &str = "jsonb_build_object('sequence',sequence,'message_id',message_id,'project_id',project_id,'sender_account_id',sender_account_id,'sender_agent_id',sender_agent_id,'recipient_agent_id',recipient_agent_id,'client_message_id',client_message_id,'thread_id',thread_id,'reply_to',reply_to,'parts',parts,'trace_id',trace_id,'created_at',created_at,'received_at',received_at)";
impl Store {
    pub async fn create_agent_integration(
        &self,
        account: &str,
        workspace: &str,
        project: &str,
        name: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        lock_network_member(&mut tx, account, workspace, project, true).await?;
        let integration_id = id();
        let value = sqlx::query_scalar("INSERT INTO agent_integrations(integration_id,account_id,workspace_id,project_id,name) VALUES ($1,$2,$3,$4,$5) RETURNING jsonb_build_object('integration_id',integration_id,'project_id',project_id,'name',name,'created_at',created_at)")
            .bind(&integration_id).bind(account).bind(workspace).bind(project).bind(name).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO principals(principal_id,kind,integration_id,account_id,workspace_id,display_name) VALUES ($1,'CONNECTOR',$2,$3,$4,$5) ON CONFLICT (principal_id) DO UPDATE SET status='ACTIVE',display_name=EXCLUDED.display_name")
            .bind(format!("connector:{integration_id}")).bind(&integration_id).bind(account).bind(workspace).bind(name).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }
    pub async fn agent_integrations(&self, account: &str, project: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('integration_id',integration_id,'name',name,'disabled_at',disabled_at,'created_at',created_at) FROM agent_integrations WHERE account_id=$1 AND project_id=$2 ORDER BY created_at DESC LIMIT 100")
            .bind(account).bind(project).fetch_all(&self.pool).await?)
    }
    pub async fn disable_agent_integration(
        &self,
        account: &str,
        workspace: &str,
        project: &str,
        integration: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // Use the same lock order as sends and member changes. Once revocation
        // confirms, a subsequent send cannot commit to this recipient.
        lock_network_member(&mut tx, account, workspace, project, true).await?;
        sqlx::query("UPDATE agent_integrations SET disabled_at=COALESCE(disabled_at,now()) WHERE integration_id=$1 AND account_id=$2 AND project_id=$3").bind(integration).bind(account).bind(project).execute(&mut *tx).await?;
        let connector_principal = format!("connector:{integration}");
        let revision: i64 = sqlx::query_scalar("UPDATE principals SET status='REVOKED',authorization_epoch=authorization_epoch+1,revision=revision+1 WHERE principal_id=$1 RETURNING revision")
            .bind(&connector_principal).fetch_optional(&mut *tx).await?.unwrap_or(1);
        sqlx::query("UPDATE principals SET status='REVOKED',authorization_epoch=authorization_epoch+1,revision=revision+1 WHERE integration_id=$1 AND kind='NATIVE_AGENT'")
            .bind(integration).execute(&mut *tx).await?;
        let payload =
            json!({"integration_id":integration,"project_id":project,"revision":revision});
        let event_id = id();
        sqlx::query("INSERT INTO workspace_security_events(event_id,workspace_id,principal_id,kind,object_id,object_revision,payload) VALUES($1,$2,$3,'CONNECTOR_REVOKED',$4,$5,$6)")
            .bind(&event_id).bind(workspace).bind(&connector_principal).bind(integration).bind(revision).bind(&payload).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspace_security_outbox(outbox_id,event_id,workspace_id,kind,payload) VALUES($1,$2,$3,'CONNECTOR_REVOKED',$4)")
            .bind(id()).bind(&event_id).bind(workspace).bind(&payload).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn integration_scope(
        &self,
        account: &str,
        integration: &str,
    ) -> Result<Option<(String, String)>> {
        Ok(sqlx::query_as("SELECT i.workspace_id,i.project_id FROM agent_integrations i JOIN workspace_members m USING(workspace_id,account_id) WHERE i.integration_id=$1 AND i.account_id=$2 AND i.disabled_at IS NULL AND m.revoked_at IS NULL AND m.role IN ('OWNER','EDITOR')")
            .bind(integration).bind(account).fetch_optional(&self.pool).await?)
    }
    pub async fn register_network_agent(
        &self,
        account: &str,
        workspace: &str,
        project: &str,
        integration: &str,
        native: &str,
        name: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        lock_network_member(&mut tx, account, workspace, project, true).await?;
        check_integration_tx(&mut tx, account, project, integration).await?;
        let agent_id = sqlx::query_scalar::<_, String>("INSERT INTO network_agents(agent_id,integration_id,account_id,workspace_id,project_id,native_agent_id,name) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(integration_id,native_agent_id) DO UPDATE SET name=EXCLUDED.name,last_seen_at=now() RETURNING agent_id")
            .bind(id()).bind(integration).bind(account).bind(workspace).bind(project).bind(native).bind(name).fetch_one(&mut *tx).await?;
        let value = sqlx::query_scalar("SELECT jsonb_build_object('agent_id',agent_id,'account_id',account_id,'project_id',project_id,'native_agent_id',native_agent_id,'name',name,'last_seen_at',last_seen_at,'identity_source','dsh_connector_registration') FROM network_agents WHERE agent_id=$1")
            .bind(&agent_id).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO principals(principal_id,kind,network_agent_id,integration_id,account_id,workspace_id,display_name) VALUES ($1,'NATIVE_AGENT',$2,$3,$4,$5,$6) ON CONFLICT (principal_id) DO UPDATE SET status='ACTIVE',display_name=EXCLUDED.display_name")
            .bind(format!("agent:{agent_id}")).bind(&agent_id).bind(integration).bind(account).bind(workspace).bind(name).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }
    pub async fn network_agents(&self, project: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('agent_id',a.agent_id,'account_id',a.account_id,'owner_name',u.display_name,'name',a.name,'last_seen_at',a.last_seen_at,'available',i.disabled_at IS NULL AND m.revoked_at IS NULL AND m.role IN ('OWNER','EDITOR'),'identity_source','dsh_connector_registration') FROM network_agents a JOIN accounts u USING(account_id) JOIN agent_integrations i USING(integration_id) LEFT JOIN workspace_members m ON m.workspace_id=a.workspace_id AND m.account_id=a.account_id WHERE a.project_id=$1 ORDER BY a.created_at,a.agent_id LIMIT 2000")
            .bind(project).fetch_all(&self.pool).await?)
    }
    pub async fn send_network_message(
        &self,
        account: &str,
        workspace: &str,
        project: &str,
        integration: Option<&str>,
        input: NetworkMessageInput,
    ) -> Result<Value> {
        if input.client_message_id.is_empty()
            || input.client_message_id.len() > 128
            || input.parts.is_empty()
            || input.parts.len() > 16
            || serde_json::to_vec(&input)?.len() > 32768
            || input.thread_id.as_ref().is_some_and(|t| t.len() > 128)
        {
            return Err(err(
                "VALIDATION_ERROR",
                "message requires an id and 1–16 parts, at most 32 KiB",
            ));
        }
        for part in &input.parts {
            let valid = match part.get("kind").and_then(Value::as_str) {
                Some("text") => {
                    part.get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|t| !t.trim().is_empty())
                        && part.as_object().is_some_and(|v| v.len() == 2)
                }
                Some("data") => {
                    part.get("data").is_some_and(Value::is_object)
                        && part.as_object().is_some_and(|v| v.len() == 2)
                }
                _ => false,
            };
            if !valid {
                return Err(err(
                    "VALIDATION_ERROR",
                    "parts must be text or structured data; no executable or remote-file parts",
                ));
            }
        }
        let digest = forgeflow_planner::sha256(&serde_json::to_vec(&input)?);
        let mut tx = self.pool.begin().await?;
        // Workspace row lock also orders commits before allocating cursor sequences.
        lock_network_member(&mut tx, account, workspace, project, true).await?;
        if let Some(integration) = integration {
            check_integration_tx(&mut tx, account, project, integration).await?;
        }
        match (&input.sender_agent_id, integration) {
            (Some(sender), Some(integration)) => {
                let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_agents WHERE agent_id=$1 AND integration_id=$2 AND account_id=$3 AND project_id=$4)")
                    .bind(sender).bind(integration).bind(account).bind(project).fetch_one(&mut *tx).await?;
                if !valid {
                    return Err(err("FORBIDDEN", "sender does not belong to this connector"));
                }
            }
            (None, None) => {}
            _ => {
                return Err(err(
                    "FORBIDDEN",
                    "connector messages require their own registered sender; user messages have no agent sender",
                ));
            }
        }
        // Replaying an accepted message is a read of its durable result. The
        // recipient may since have disconnected; current sender authority is
        // still checked above, but delivery availability must not erase success.
        if let Some(row) = sqlx::query("SELECT request_hash,message_id FROM agent_messages WHERE sender_account_id=$1 AND project_id=$2 AND client_message_id=$3")
            .bind(account).bind(project).bind(&input.client_message_id).fetch_optional(&mut *tx).await? {
            if row.try_get::<String,_>("request_hash")? != digest { return Err(err("IDEMPOTENCY_CONFLICT","client message id already used with another message")); }
            let value = sqlx::query_scalar(&format!("SELECT {MESSAGE_VIEW} || '{{\"replayed\":true}}'::jsonb FROM agent_messages WHERE message_id=$1"))
                .bind(row.try_get::<String,_>("message_id")?).fetch_one(&mut *tx).await?;
            tx.commit().await?; return Ok(value);
        }
        let recipient: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_agents a JOIN agent_integrations i USING(integration_id) JOIN workspace_members m ON m.workspace_id=a.workspace_id AND m.account_id=a.account_id WHERE a.agent_id=$1 AND a.project_id=$2 AND i.disabled_at IS NULL AND m.revoked_at IS NULL AND m.role IN ('OWNER','EDITOR'))")
            .bind(&input.recipient_agent_id).bind(project).fetch_one(&mut *tx).await?;
        if !recipient {
            return Err(err("NOT_FOUND", "recipient is unavailable in this project"));
        }
        let mut inherited_thread = None;
        if let Some(reply) = &input.reply_to {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_messages WHERE message_id=$1 AND project_id=$2 AND ($3::text IS NULL OR thread_id=$3))")
                .bind(reply).bind(project).bind(&input.thread_id).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(err(
                    "VALIDATION_ERROR",
                    "reply must reference this project's thread",
                ));
            }
            inherited_thread = Some(
                sqlx::query_scalar::<_, String>(
                    "SELECT thread_id FROM agent_messages WHERE message_id=$1",
                )
                .bind(reply)
                .fetch_one(&mut *tx)
                .await?,
            );
        }
        let message = id();
        let thread = input
            .thread_id
            .clone()
            .or(inherited_thread)
            .unwrap_or_else(|| message.clone());
        let value = sqlx::query_scalar(&format!("INSERT INTO agent_messages(message_id,workspace_id,project_id,sender_account_id,sender_agent_id,recipient_agent_id,client_message_id,request_hash,thread_id,reply_to,parts,trace_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING {MESSAGE_VIEW} || '{{\"replayed\":false}}'::jsonb"))
            .bind(&message).bind(workspace).bind(project).bind(account).bind(input.sender_agent_id).bind(input.recipient_agent_id).bind(input.client_message_id).bind(digest).bind(thread).bind(input.reply_to).bind(json!(input.parts)).bind(id()).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(value)
    }
    pub async fn network_messages(
        &self,
        project: &str,
        integration: Option<&str>,
        agent: Option<&str>,
        after: i64,
        before: Option<i64>,
        latest: bool,
    ) -> Result<Value> {
        if after < 0 || before.is_some_and(|value| value <= 0) {
            return Err(err("INVALID_CURSOR", "cursor must be non-negative"));
        }
        if (latest || before.is_some()) && after != 0 || latest && before.is_some() {
            return Err(err(
                "INVALID_CURSOR",
                "choose after, before or latest, not multiple directions",
            ));
        }
        let reverse = latest || before.is_some();
        let order = if reverse { "DESC" } else { "ASC" };
        let mut values: Vec<Value> = sqlx::query_scalar(&format!("SELECT {MESSAGE_VIEW} FROM agent_messages WHERE project_id=$1 AND sequence>$2 AND ($3::text IS NULL OR recipient_agent_id IN (SELECT agent_id FROM network_agents WHERE integration_id=$3)) AND ($4::text IS NULL OR recipient_agent_id=$4) AND ($5::bigint IS NULL OR sequence<$5) ORDER BY sequence {order} LIMIT 101"))
            .bind(project).bind(after).bind(integration).bind(agent).bind(before).fetch_all(&self.pool).await?;
        let has_more = values.len() > 100;
        values.truncate(100);
        if reverse {
            values.reverse();
        }
        let cursor = values
            .last()
            .and_then(|v| v["sequence"].as_i64())
            .unwrap_or(after);
        Ok(
            json!({"previous_cursor":values.first().and_then(|v|v["sequence"].as_i64()),"items":values,"next_cursor":cursor,"has_more":has_more,"direction":if reverse{"older"}else{"newer"},"delivery":"at_least_once","visibility":"project_members","protocol":"forgeflow.agent-network.v1"}),
        )
    }
    pub async fn acknowledge_network_message(
        &self,
        account: &str,
        workspace: &str,
        project: &str,
        integration: &str,
        message: &str,
        recipient: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        lock_network_member(&mut tx, account, workspace, project, true).await?;
        check_integration_tx(&mut tx, account, project, integration).await?;
        let value = sqlx::query_scalar(&format!("UPDATE agent_messages SET received_at=COALESCE(received_at,now()) WHERE message_id=$1 AND project_id=$2 AND recipient_agent_id=$5 AND recipient_agent_id IN (SELECT agent_id FROM network_agents WHERE integration_id=$3 AND account_id=$4) RETURNING {MESSAGE_VIEW}"))
            .bind(message).bind(project).bind(integration).bind(account).bind(recipient).fetch_optional(&mut *tx).await?.ok_or_else(||err("NOT_FOUND","message unavailable in this connector inbox"))?;
        tx.commit().await?;
        Ok(value)
    }
}
async fn lock_network_member(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    workspace: &str,
    project: &str,
    writable: bool,
) -> Result<()> {
    sqlx::query("SELECT workspace_id FROM workspaces WHERE workspace_id=$1 FOR UPDATE")
        .bind(workspace)
        .execute(&mut **tx)
        .await?;
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspace_members m JOIN project_workspaces p USING(workspace_id) WHERE m.workspace_id=$1 AND m.account_id=$2 AND m.revoked_at IS NULL AND p.project_id=$3 AND (NOT $4 OR m.role IN ('OWNER','EDITOR')))")
        .bind(workspace).bind(account).bind(project).bind(writable).fetch_one(&mut **tx).await?;
    if !valid {
        return Err(err(
            "FORBIDDEN",
            "project membership does not permit this operation",
        ));
    }
    Ok(())
}
async fn check_integration_tx(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    project: &str,
    integration: &str,
) -> Result<()> {
    let valid: Option<String> = sqlx::query_scalar("SELECT integration_id FROM agent_integrations WHERE integration_id=$1 AND account_id=$2 AND project_id=$3 AND disabled_at IS NULL FOR SHARE")
        .bind(integration).bind(account).bind(project).fetch_optional(&mut **tx).await?;
    if valid.is_none() {
        return Err(err(
            "FORBIDDEN",
            "connector revoked or outside this project",
        ));
    }
    Ok(())
}
