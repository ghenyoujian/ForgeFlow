//! Minimal durable ECP messaging runtime over the 0017 tables.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationInput {
    pub conversation_id: String,
    pub project_id: Option<String>,
    pub participant_principal_ids: Vec<String>,
    pub request_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_request_keys_are_bounded_and_printable() {
        assert!(ensure_request_key(&"r".repeat(16)).is_ok());
        assert!(ensure_request_key(&"r".repeat(128)).is_ok());
        assert!(ensure_request_key("too-short").is_err());
        assert!(ensure_request_key(&format!("{}\n", "r".repeat(15))).is_err());
        assert!(ensure_request_key(&"r".repeat(129)).is_err());
    }

    #[test]
    fn receipt_generation_is_optional_but_fail_closed_when_present() {
        assert_eq!(optional_receipt_generation(&json!({})).unwrap(), None);
        assert_eq!(
            optional_receipt_generation(&json!({"generation": null})).unwrap(),
            None
        );
        assert_eq!(
            optional_receipt_generation(&json!({"generation": 3})).unwrap(),
            Some(3)
        );
        assert!(optional_receipt_generation(&json!({"generation": 0})).is_err());
        assert!(optional_receipt_generation(&json!({"generation": -1})).is_err());
        assert!(optional_receipt_generation(&json!({"generation": "3"})).is_err());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadInput {
    pub thread_id: String,
    pub task_id: Option<String>,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageInput {
    pub thread_id: String,
    pub message_kind: String,
    pub client_request_id: String,
    pub payload: Value,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub causation_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptInput {
    pub request_key: String,
    pub receipt_kind: String,
    #[serde(default)]
    pub data: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointInput {
    pub acknowledged_sequence: i64,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryClaimInput {
    pub generation: i64,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryFailureInput {
    pub generation: i64,
    pub request_key: String,
    pub error_code: String,
    #[serde(default = "default_retry_limit")]
    pub max_attempts: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationRevokeInput {
    pub request_key: String,
    pub reason_code: String,
}

fn default_retry_limit() -> i64 {
    3
}

fn ensure_id(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(err("VALIDATION_ERROR", format!("invalid {label}")));
    }
    Ok(())
}

fn ensure_request_key(value: &str) -> Result<()> {
    if !(16..=128).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(err(
            "VALIDATION_ERROR",
            "request_key must contain 16..128 printable characters",
        ));
    }
    Ok(())
}

/// Extract the optional attempt generation carried by a durable delivery
/// receipt. Older clients may omit it; when present it is a reserved integer
/// field used to fence a receipt against a newer delivery attempt.
fn optional_receipt_generation(data: &Value) -> Result<Option<i64>> {
    match data.get("generation") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|generation| *generation >= 1)
            .map(Some)
            .ok_or_else(|| {
                err(
                    "VALIDATION_ERROR",
                    "receipt generation must be a positive integer",
                )
            }),
    }
}

impl Store {
    async fn human_principal_tx(
        tx: &mut Transaction<'_, Postgres>,
        account: &str,
        workspace: &str,
    ) -> Result<String> {
        let principal = format!("human:{account}");
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals p JOIN workspace_members m ON m.account_id=p.account_id WHERE p.principal_id=$1 AND p.kind='HUMAN' AND p.status='ACTIVE' AND m.workspace_id=$2 AND m.revoked_at IS NULL)")
            .bind(&principal).bind(workspace).fetch_one(&mut **tx).await?;
        if !active {
            return Err(err("FORBIDDEN", "workspace principal is not active"));
        }
        Ok(principal)
    }

    pub async fn create_ecp_conversation(
        &self,
        account: &str,
        workspace: &str,
        input: ConversationInput,
    ) -> Result<Value> {
        ensure_id(&input.conversation_id, "conversation_id")?;
        ensure_request_key(&input.request_key)?;
        if input.participant_principal_ids.is_empty() {
            return Err(err("VALIDATION_ERROR", "conversation needs a participant"));
        }
        let mut tx = self.pool.begin().await?;
        let owner = Self::human_principal_tx(&mut tx, account, workspace).await?;
        if let Some(project) = &input.project_id {
            let bound: Option<String> = sqlx::query_scalar(
                "SELECT workspace_id FROM project_workspaces WHERE project_id=$1",
            )
            .bind(project)
            .fetch_optional(&mut *tx)
            .await?;
            if bound.as_deref() != Some(workspace) {
                return Err(err("FORBIDDEN", "project is outside workspace"));
            }
        }
        // Serialize creation by conversation identity. A retry is accepted
        // only when its durable command receipt has the same request key.
        if let Some(existing_owner) = sqlx::query_scalar::<_, String>(
            "SELECT created_by_principal_id FROM ecp_conversations WHERE conversation_id=$1 FOR UPDATE",
        )
        .bind(&input.conversation_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            if existing_owner != owner {
                return Err(err("FORBIDDEN", "conversation is owned by another principal"));
            }
            if let Some(existing) = sqlx::query_scalar::<_, Value>(
                "SELECT result FROM ecp_conversation_commands WHERE conversation_id=$1 AND principal_id=$2 AND command_kind='CREATE' AND request_key=$3 FOR SHARE",
            )
            .bind(&input.conversation_id)
            .bind(&owner)
            .bind(&input.request_key)
            .fetch_optional(&mut *tx)
            .await?
            {
                tx.commit().await?;
                return Ok(existing);
            }
            return Err(err(
                "IDEMPOTENCY_CONFLICT",
                "conversation ID already exists for another request",
            ));
        }
        let participants: Vec<String> = std::iter::once(owner.clone())
            .chain(input.participant_principal_ids.into_iter())
            .collect();
        let mut unique = std::collections::BTreeSet::new();
        let conversation: Value = sqlx::query_scalar("INSERT INTO ecp_conversations(conversation_id,workspace_id,project_id,created_by_principal_id) VALUES($1,$2,$3,$4) RETURNING jsonb_build_object('conversation_id',conversation_id,'workspace_id',workspace_id,'project_id',project_id,'status',status,'revision',revision,'replayed',false)")
            .bind(&input.conversation_id).bind(workspace).bind(&input.project_id).bind(&owner).fetch_one(&mut *tx).await?;
        for principal in participants {
            if !unique.insert(principal.clone()) {
                continue;
            }
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals p WHERE p.principal_id=$1 AND p.status='ACTIVE' AND (p.workspace_id=$2 OR (p.kind='HUMAN' AND p.account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$2 AND revoked_at IS NULL))))")
                .bind(&principal).bind(workspace).fetch_one(&mut *tx).await?;
            if !valid {
                return Err(err(
                    "FORBIDDEN",
                    "conversation participant is outside workspace",
                ));
            }
            sqlx::query("INSERT INTO ecp_conversation_participants(conversation_id,principal_id,role) VALUES($1,$2,$3) ON CONFLICT(conversation_id,principal_id) DO UPDATE SET revoked_at=NULL")
                .bind(&input.conversation_id).bind(&principal).bind(if principal==owner {"OWNER"} else {"MEMBER"}).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO ecp_conversation_commands(command_id,conversation_id,principal_id,command_kind,request_key,result) VALUES($1,$2,$3,'CREATE',$4,$5)")
            .bind(id())
            .bind(&input.conversation_id)
            .bind(&owner)
            .bind(&input.request_key)
            .bind(&conversation)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(conversation)
    }

    pub async fn create_ecp_thread(
        &self,
        account: &str,
        conversation: &str,
        input: ThreadInput,
    ) -> Result<Value> {
        ensure_id(&input.thread_id, "thread_id")?;
        ensure_request_key(&input.request_key)?;
        let mut tx = self.pool.begin().await?;
        let workspace: String = sqlx::query_scalar(
            // Serialize thread creation per conversation so concurrent retries
            // cannot race between the command lookup and thread insert.
            "SELECT workspace_id FROM ecp_conversations WHERE conversation_id=$1 FOR UPDATE",
        )
        .bind(conversation)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "conversation not found"))?;
        let principal = Self::human_principal_tx(&mut tx, account, &workspace).await?;
        let member: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ecp_conversation_participants WHERE conversation_id=$1 AND principal_id=$2 AND revoked_at IS NULL)").bind(conversation).bind(&principal).fetch_one(&mut *tx).await?;
        if !member {
            return Err(err("FORBIDDEN", "conversation participant required"));
        }

        if let Some(existing) = sqlx::query_scalar::<_, Value>(
            "SELECT result FROM ecp_conversation_commands WHERE conversation_id=$1 AND principal_id=$2 AND command_kind='CREATE_THREAD' AND request_key=$3 FOR SHARE",
        )
        .bind(conversation)
        .bind(&principal)
        .bind(&input.request_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            if existing["thread_id"] != input.thread_id
                || existing["task_id"] != json!(input.task_id)
            {
                return Err(err(
                    "IDEMPOTENCY_CONFLICT",
                    "thread request key already has another payload",
                ));
            }
            let mut replay = existing;
            replay["replayed"] = json!(true);
            tx.commit().await?;
            return Ok(replay);
        }

        if let Some(existing_conversation) = sqlx::query_scalar::<_, String>(
            "SELECT conversation_id FROM ecp_threads WHERE thread_id=$1 FOR UPDATE",
        )
        .bind(&input.thread_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            return Err(if existing_conversation == conversation {
                err(
                    "IDEMPOTENCY_CONFLICT",
                    "thread identity already exists without a matching command receipt",
                )
            } else {
                err("FORBIDDEN", "thread belongs to another conversation")
            });
        }

        let value: Value=sqlx::query_scalar("INSERT INTO ecp_threads(thread_id,conversation_id,task_id) VALUES($1,$2,$3) RETURNING jsonb_build_object('thread_id',thread_id,'conversation_id',conversation_id,'task_id',task_id,'revision',revision,'replayed',false)")
            .bind(&input.thread_id).bind(conversation).bind(&input.task_id).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO ecp_conversation_commands(command_id,conversation_id,principal_id,command_kind,request_key,result) VALUES($1,$2,$3,'CREATE_THREAD',$4,$5)")
            .bind(id())
            .bind(conversation)
            .bind(&principal)
            .bind(&input.request_key)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn send_ecp_message(
        &self,
        account: &str,
        conversation: &str,
        input: MessageInput,
    ) -> Result<Value> {
        ensure_id(&input.thread_id, "thread_id")?;
        ensure_id(&input.client_request_id, "client_request_id")?;
        if input.client_request_id.len() < 16
            || !input.payload.is_object()
            || input.message_kind.is_empty()
            || input.message_kind.len() > 128
        {
            return Err(err("VALIDATION_ERROR", "invalid message envelope"));
        }
        let payload_bytes = serde_json::to_vec(&input.payload)?;
        if payload_bytes.len() > 262144 {
            return Err(err("VALIDATION_ERROR", "message payload exceeds 256 KiB"));
        }
        let hash = forgeflow_planner::sha256(&payload_bytes);
        let mut tx = self.pool.begin().await?;
        let (workspace, status, next): (String,String,i64)=sqlx::query_as("SELECT workspace_id,status,next_sequence FROM ecp_conversations WHERE conversation_id=$1 FOR UPDATE").bind(conversation).fetch_optional(&mut *tx).await?.ok_or_else(||err("NOT_FOUND","conversation not found"))?;
        if status != "OPEN" {
            return Err(err("FORBIDDEN", "conversation is not open"));
        }
        let sender = Self::human_principal_tx(&mut tx, account, &workspace).await?;
        let member:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ecp_conversation_participants WHERE conversation_id=$1 AND principal_id=$2 AND revoked_at IS NULL)").bind(conversation).bind(&sender).fetch_one(&mut *tx).await?;
        if !member {
            return Err(err("FORBIDDEN", "conversation participant required"));
        }
        let thread_ok: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ecp_threads WHERE thread_id=$1 AND conversation_id=$2)",
        )
        .bind(&input.thread_id)
        .bind(conversation)
        .fetch_one(&mut *tx)
        .await?;
        if !thread_ok {
            return Err(err("NOT_FOUND", "thread not found"));
        }
        if let Some(existing)=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('message_id',message_id,'conversation_id',conversation_id,'thread_id',thread_id,'sequence',sequence,'payload',payload,'payload_sha256',payload_sha256,'replayed',true) FROM ecp_messages WHERE conversation_id=$1 AND sender_principal_id=$2 AND client_request_id=$3 FOR SHARE").bind(conversation).bind(&sender).bind(&input.client_request_id).fetch_optional(&mut *tx).await? {
            if existing["payload_sha256"]!=hash { return Err(err("IDEMPOTENCY_CONFLICT", "message request id already has another payload")); }
            tx.commit().await?; return Ok(existing);
        }
        let message_id = id();
        let value:Value=sqlx::query_scalar("INSERT INTO ecp_messages(message_id,workspace_id,project_id,conversation_id,thread_id,sender_principal_id,message_kind,schema_version,sequence,correlation_id,causation_id,client_request_id,payload,payload_sha256,provenance,expires_at) SELECT $1,c.workspace_id,c.project_id,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13 FROM ecp_conversations c WHERE c.conversation_id=$2 RETURNING jsonb_build_object('message_id',message_id,'workspace_id',workspace_id,'project_id',project_id,'conversation_id',conversation_id,'thread_id',thread_id,'sender_principal_id',sender_principal_id,'message_kind',message_kind,'sequence',sequence,'client_request_id',client_request_id,'payload',payload,'payload_sha256',payload_sha256,'created_at',created_at,'replayed',false)")
            .bind(&message_id).bind(conversation).bind(&input.thread_id).bind(&sender).bind(&input.message_kind).bind(next).bind(&input.correlation_id).bind(&input.causation_id).bind(&input.client_request_id).bind(&input.payload).bind(&hash).bind(json!({"source":"human"})).bind(input.expires_at).fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE ecp_conversations SET next_sequence=next_sequence+1,revision=revision+1 WHERE conversation_id=$1").bind(conversation).execute(&mut *tx).await?;
        let recipients:Vec<String>=sqlx::query_scalar("SELECT principal_id FROM ecp_conversation_participants WHERE conversation_id=$1 AND revoked_at IS NULL AND principal_id<>$2").bind(conversation).bind(&sender).fetch_all(&mut *tx).await?;
        for recipient in recipients {
            let delivery = id();
            sqlx::query("INSERT INTO ecp_deliveries(delivery_id,message_id,recipient_principal_id) VALUES($1,$2,$3)").bind(&delivery).bind(&message_id).bind(&recipient).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO ecp_message_outbox(outbox_id,delivery_id,message_id,kind,payload) VALUES($1,$2,$3,'MESSAGE_CREATED',$4)").bind(id()).bind(&delivery).bind(&message_id).bind(&value).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(value)
    }

    pub async fn list_ecp_messages(
        &self,
        account: &str,
        conversation: &str,
        after: i64,
        limit: i64,
    ) -> Result<Value> {
        let limit = limit.clamp(1, 100);
        let (workspace, next_sequence, status): (String, i64, String) = sqlx::query_as(
            "SELECT workspace_id,next_sequence,status FROM ecp_conversations WHERE conversation_id=$1",
        )
        .bind(conversation)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "conversation not found"))?;
        if after < 0 || after >= next_sequence {
            return Err(err(
                "CURSOR_INVALID",
                "cursor is ahead of the durable conversation sequence",
            ));
        }
        if status == "REVOKED" {
            return Err(err("FORBIDDEN", "conversation has been revoked"));
        }
        let principal = format!("human:{account}");
        let member:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ecp_conversation_participants WHERE conversation_id=$1 AND principal_id=$2 AND revoked_at IS NULL)").bind(conversation).bind(&principal).fetch_one(&self.pool).await?;
        if !member {
            return Err(err("FORBIDDEN", "conversation participant required"));
        }
        let items:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('message_id',message_id,'workspace_id',workspace_id,'project_id',project_id,'conversation_id',conversation_id,'thread_id',thread_id,'sender_principal_id',sender_principal_id,'message_kind',message_kind,'sequence',sequence,'client_request_id',client_request_id,'payload',payload,'payload_sha256',payload_sha256,'created_at',created_at) FROM ecp_messages WHERE conversation_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3").bind(conversation).bind(after.max(0)).bind(limit).fetch_all(&self.pool).await?;
        let checkpoint: i64 = sqlx::query_scalar(
            "SELECT acknowledged_sequence FROM ecp_inbox_checkpoints WHERE conversation_id=$1 AND principal_id=$2",
        )
        .bind(conversation)
        .bind(&principal)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(0);
        Ok(
            json!({"items":items,"after":after,"next_cursor":items.last().and_then(|v|v["sequence"].as_i64()),"has_more":items.len() as i64==limit,"checkpoint":checkpoint,"workspace_id":workspace}),
        )
    }

    pub async fn ack_ecp_delivery(
        &self,
        account: &str,
        delivery: &str,
        input: ReceiptInput,
    ) -> Result<Value> {
        ensure_request_key(&input.request_key)?;
        if !matches!(
            input.receipt_kind.as_str(),
            "RECEIVED" | "READ" | "PROCESSING" | "PROCESSED" | "REJECTED"
        ) {
            return Err(err("VALIDATION_ERROR", "invalid receipt kind"));
        }
        let data = if input.data.is_null() {
            json!({})
        } else {
            input.data
        };
        if !data.is_object() {
            return Err(err("VALIDATION_ERROR", "receipt data must be an object"));
        }
        let receipt_generation = optional_receipt_generation(&data)?;
        let data_sha256 = forgeflow_planner::sha256(&serde_json::to_vec(&data)?);
        let mut tx = self.pool.begin().await?;
        let principal = format!("human:{account}");
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ecp_deliveries WHERE delivery_id=$1 AND recipient_principal_id=$2 FOR UPDATE)").bind(delivery).bind(&principal).fetch_one(&mut *tx).await?;
        if !valid {
            return Err(err("FORBIDDEN", "delivery recipient required"));
        }
        if let Some((existing_kind, existing_hash, existing_result)) = sqlx::query_as::<_, (String, String, Value)>("SELECT receipt_kind,data_sha256,result FROM ecp_delivery_receipt_commands WHERE delivery_id=$1 AND principal_id=$2 AND request_key=$3 FOR SHARE")
            .bind(delivery).bind(&principal).bind(&input.request_key).fetch_optional(&mut *tx).await? {
            if existing_kind != input.receipt_kind || existing_hash != data_sha256 {
                return Err(err("IDEMPOTENCY_CONFLICT", "delivery receipt request key already has another payload"));
            }
            let mut replay = existing_result;
            replay["replayed"] = json!(true);
            tx.commit().await?;
            return Ok(replay);
        }
        // The field is optional for backwards compatibility, but consumers
        // that provide it must acknowledge the currently fenced attempt. The
        // delivery row lock above serializes this check with claim/recovery.
        if let Some(generation) = receipt_generation {
            let current_generation: Option<i64> = sqlx::query_scalar(
                "SELECT generation FROM ecp_delivery_attempts WHERE delivery_id=$1 ORDER BY attempt_number DESC LIMIT 1 FOR SHARE",
            )
            .bind(delivery)
            .fetch_optional(&mut *tx)
            .await?;
            if current_generation != Some(generation) {
                return Err(err(
                    "STALE_GENERATION",
                    "delivery receipt generation is no longer current",
                ));
            }
        }
        let revision:i64=sqlx::query_scalar("SELECT COALESCE(MAX(receipt_revision),0)+1 FROM ecp_delivery_receipts WHERE delivery_id=$1 AND receipt_kind=$2").bind(delivery).bind(&input.receipt_kind).fetch_one(&mut *tx).await?;
        let value:Value=sqlx::query_scalar("INSERT INTO ecp_delivery_receipts(receipt_id,delivery_id,receipt_kind,principal_id,receipt_revision,data) VALUES($1,$2,$3,$4,$5,$6) RETURNING jsonb_build_object('receipt_id',receipt_id,'delivery_id',delivery_id,'receipt_kind',receipt_kind,'principal_id',principal_id,'receipt_revision',receipt_revision,'created_at',created_at)").bind(id()).bind(delivery).bind(&input.receipt_kind).bind(&principal).bind(revision).bind(&data).fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE ecp_deliveries SET state=CASE WHEN $2='RECEIVED' OR $2='READ' THEN 'ACKED' ELSE state END,acked_at=CASE WHEN $2='RECEIVED' OR $2='READ' THEN COALESCE(acked_at,clock_timestamp()) ELSE acked_at END WHERE delivery_id=$1").bind(delivery).bind(&input.receipt_kind).execute(&mut *tx).await?;
        if matches!(input.receipt_kind.as_str(), "RECEIVED" | "READ") {
            let (conversation, sequence): (String, i64) = sqlx::query_as(
                "SELECT m.conversation_id,m.sequence FROM ecp_deliveries d JOIN ecp_messages m ON m.message_id=d.message_id WHERE d.delivery_id=$1",
            )
            .bind(delivery)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO ecp_inbox_checkpoints(conversation_id,principal_id,acknowledged_sequence) VALUES($1,$2,$3) ON CONFLICT(conversation_id,principal_id) DO UPDATE SET acknowledged_sequence=GREATEST(ecp_inbox_checkpoints.acknowledged_sequence,EXCLUDED.acknowledged_sequence),updated_at=clock_timestamp()")
                .bind(&conversation).bind(&principal).bind(sequence).execute(&mut *tx).await?;
            sqlx::query("UPDATE ecp_conversation_participants SET last_ack_sequence=GREATEST(last_ack_sequence,$3) WHERE conversation_id=$1 AND principal_id=$2")
                .bind(&conversation).bind(&principal).bind(sequence).execute(&mut *tx).await?;
        }
        let mut result = value;
        result["replayed"] = json!(false);
        sqlx::query("INSERT INTO ecp_delivery_receipt_commands(command_id,delivery_id,principal_id,request_key,receipt_kind,data_sha256,result) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(id()).bind(delivery).bind(&principal).bind(&input.request_key).bind(&input.receipt_kind).bind(&data_sha256).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn checkpoint_ecp_inbox(
        &self,
        account: &str,
        conversation: &str,
        input: CheckpointInput,
    ) -> Result<Value> {
        ensure_request_key(&input.request_key)?;
        if input.acknowledged_sequence < 0 {
            return Err(err(
                "VALIDATION_ERROR",
                "acknowledged_sequence must be non-negative",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let (workspace, next_sequence, status, owner): (String, i64, String, String) = sqlx::query_as(
            "SELECT workspace_id,next_sequence,status,created_by_principal_id FROM ecp_conversations WHERE conversation_id=$1 FOR UPDATE",
        ).bind(conversation).fetch_optional(&mut *tx).await?.ok_or_else(|| err("NOT_FOUND", "conversation not found"))?;
        if status == "REVOKED" {
            return Err(err("FORBIDDEN", "conversation has been revoked"));
        }
        let principal = Self::human_principal_tx(&mut tx, account, &workspace).await?;
        let member: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ecp_conversation_participants WHERE conversation_id=$1 AND principal_id=$2 AND revoked_at IS NULL)")
            .bind(conversation).bind(&principal).fetch_one(&mut *tx).await?;
        if !member {
            return Err(err("FORBIDDEN", "conversation participant required"));
        }
        if input.acknowledged_sequence >= next_sequence {
            return Err(err(
                "CURSOR_INVALID",
                "checkpoint is ahead of the durable conversation sequence",
            ));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT result FROM ecp_checkpoint_commands WHERE conversation_id=$1 AND principal_id=$2 AND request_key=$3 FOR SHARE")
            .bind(conversation).bind(&principal).bind(&input.request_key).fetch_optional(&mut *tx).await? {
            tx.commit().await?;
            return Ok(existing);
        }
        sqlx::query("INSERT INTO ecp_inbox_checkpoints(conversation_id,principal_id,acknowledged_sequence) VALUES($1,$2,$3) ON CONFLICT(conversation_id,principal_id) DO UPDATE SET acknowledged_sequence=GREATEST(ecp_inbox_checkpoints.acknowledged_sequence,EXCLUDED.acknowledged_sequence),updated_at=clock_timestamp()")
            .bind(conversation).bind(&principal).bind(input.acknowledged_sequence).execute(&mut *tx).await?;
        sqlx::query("UPDATE ecp_conversation_participants SET last_ack_sequence=GREATEST(last_ack_sequence,$3) WHERE conversation_id=$1 AND principal_id=$2")
            .bind(conversation).bind(&principal).bind(input.acknowledged_sequence).execute(&mut *tx).await?;
        let result = json!({"conversation_id":conversation,"principal_id":principal,"acknowledged_sequence":input.acknowledged_sequence,"owner":owner,"replayed":false});
        sqlx::query("INSERT INTO ecp_checkpoint_commands(command_id,conversation_id,principal_id,request_key,acknowledged_sequence,result) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(id()).bind(conversation).bind(&principal).bind(&input.request_key).bind(input.acknowledged_sequence).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn claim_ecp_delivery(
        &self,
        account: &str,
        delivery: &str,
        input: DeliveryClaimInput,
    ) -> Result<Value> {
        ensure_request_key(&input.request_key)?;
        if input.generation < 1 {
            return Err(err("VALIDATION_ERROR", "generation must be positive"));
        }
        let mut tx = self.pool.begin().await?;
        let (workspace, state, attempts, recipient, conversation_status, outbox_id): (String, String, i64, String, String, String) = sqlx::query_as("SELECT m.workspace_id,d.state,d.attempt_count,d.recipient_principal_id,c.status,o.outbox_id FROM ecp_deliveries d JOIN ecp_messages m ON m.message_id=d.message_id JOIN ecp_conversations c ON c.conversation_id=m.conversation_id JOIN ecp_message_outbox o ON o.delivery_id=d.delivery_id AND o.kind='MESSAGE_CREATED' WHERE d.delivery_id=$1 FOR UPDATE OF d,o")
            .bind(delivery).fetch_optional(&mut *tx).await?.ok_or_else(|| err("NOT_FOUND", "delivery not found"))?;
        let principal = Self::human_principal_tx(&mut tx, account, &workspace).await?;
        if recipient != principal {
            return Err(err("FORBIDDEN", "delivery recipient required"));
        }
        if conversation_status == "REVOKED" || state == "REVOKED" {
            return Err(err("FORBIDDEN", "delivery has been revoked"));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT result FROM ecp_delivery_commands WHERE delivery_id=$1 AND command_kind='CLAIM' AND request_key=$2 FOR SHARE")
            .bind(delivery).bind(&input.request_key).fetch_optional(&mut *tx).await? { tx.commit().await?; return Ok(existing); }
        if matches!(state.as_str(), "ACKED" | "DEAD_LETTER" | "EXPIRED") {
            return Err(err("CONFLICT", "delivery is no longer claimable"));
        }
        let last_generation: Option<i64> = sqlx::query_scalar("SELECT generation FROM ecp_delivery_attempts WHERE delivery_id=$1 ORDER BY attempt_number DESC LIMIT 1 FOR SHARE")
            .bind(delivery).fetch_optional(&mut *tx).await?;
        if state == "IN_FLIGHT" {
            if last_generation.is_some_and(|generation| input.generation <= generation) {
                return Err(err(
                    "STALE_GENERATION",
                    "an active delivery attempt owns this generation",
                ));
            }
            sqlx::query("UPDATE ecp_delivery_attempts SET state='UNCONFIRMED',completed_at=clock_timestamp(),error_code='LEASE_LOST' WHERE delivery_id=$1 AND attempt_number=$2")
                .bind(delivery).bind(attempts).execute(&mut *tx).await?;
        }
        let attempt_number = attempts + 1;
        let attempt_id = id();
        sqlx::query("INSERT INTO ecp_delivery_attempts(delivery_attempt_id,delivery_id,attempt_number,generation,state) VALUES($1,$2,$3,$4,'CLAIMED')")
            .bind(&attempt_id).bind(delivery).bind(attempt_number).bind(input.generation).execute(&mut *tx).await?;
        // Public consumers receive a bounded lease as well.  Leaving this at
        // `clock_timestamp()` makes the dispatcher reclaim the freshly claimed
        // delivery on its next scan, before the consumer can submit RECEIVED.
        sqlx::query("UPDATE ecp_deliveries SET state='IN_FLIGHT',attempt_count=$2,first_sent_at=COALESCE(first_sent_at,clock_timestamp()),next_attempt_at=clock_timestamp()+make_interval(secs=>$3) WHERE delivery_id=$1")
            .bind(delivery)
            .bind(attempt_number)
            .bind(crate::ecp_delivery_claim::DEFAULT_CLAIM_VISIBILITY_SECONDS as i32)
            .execute(&mut *tx)
            .await?;
        // A recipient claim is also a durable outbox handoff.  Keep this in
        // the same transaction as the delivery/attempt mutation so a queue
        // consumer cannot observe a claimed delivery with a pending outbox.
        sqlx::query("UPDATE ecp_message_outbox SET delivered_at=COALESCE(delivered_at,clock_timestamp()),claimed_by=$2 WHERE outbox_id=$1")
            .bind(&outbox_id)
            .bind(&principal)
            .execute(&mut *tx)
            .await?;
        let result = json!({"delivery_id":delivery,"attempt_id":attempt_id,"attempt_number":attempt_number,"generation":input.generation,"state":"IN_FLIGHT","replayed":false});
        sqlx::query("INSERT INTO ecp_delivery_commands(command_id,delivery_id,command_kind,request_key,generation,result) VALUES($1,$2,'CLAIM',$3,$4,$5)")
            .bind(id()).bind(delivery).bind(&input.request_key).bind(input.generation).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn fail_ecp_delivery(
        &self,
        account: &str,
        delivery: &str,
        input: DeliveryFailureInput,
    ) -> Result<Value> {
        ensure_request_key(&input.request_key)?;
        ensure_id(&input.error_code, "error_code")?;
        if input.generation < 1 || !(1..=100).contains(&input.max_attempts) {
            return Err(err(
                "VALIDATION_ERROR",
                "invalid generation or max_attempts",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let (workspace, state, attempts, recipient): (String, String, i64, String) = sqlx::query_as("SELECT m.workspace_id,d.state,d.attempt_count,d.recipient_principal_id FROM ecp_deliveries d JOIN ecp_messages m ON m.message_id=d.message_id WHERE d.delivery_id=$1 FOR UPDATE")
            .bind(delivery).fetch_optional(&mut *tx).await?.ok_or_else(|| err("NOT_FOUND", "delivery not found"))?;
        let principal = Self::human_principal_tx(&mut tx, account, &workspace).await?;
        if recipient != principal {
            return Err(err("FORBIDDEN", "delivery recipient required"));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT result FROM ecp_delivery_commands WHERE delivery_id=$1 AND command_kind='FAIL' AND request_key=$2 FOR SHARE")
            .bind(delivery).bind(&input.request_key).fetch_optional(&mut *tx).await? { tx.commit().await?; return Ok(existing); }
        let current_generation: Option<i64> = sqlx::query_scalar("SELECT generation FROM ecp_delivery_attempts WHERE delivery_id=$1 ORDER BY attempt_number DESC LIMIT 1 FOR SHARE").bind(delivery).fetch_optional(&mut *tx).await?;
        if current_generation != Some(input.generation) {
            return Err(err(
                "STALE_GENERATION",
                "delivery attempt generation is no longer current",
            ));
        }
        if matches!(
            state.as_str(),
            "ACKED" | "REVOKED" | "DEAD_LETTER" | "EXPIRED"
        ) {
            return Err(err(
                "CONFLICT",
                "delivery cannot be failed in its current state",
            ));
        }
        sqlx::query("UPDATE ecp_delivery_attempts SET state='FAILED',completed_at=clock_timestamp(),error_code=$2 WHERE delivery_id=$1 AND generation=$3 AND attempt_number=$4")
            .bind(delivery).bind(&input.error_code).bind(input.generation).bind(attempts).execute(&mut *tx).await?;
        let dead = attempts >= input.max_attempts;
        if dead {
            sqlx::query("UPDATE ecp_deliveries SET state='DEAD_LETTER',last_error_code=$2 WHERE delivery_id=$1").bind(delivery).bind(&input.error_code).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO ecp_dead_letters(dead_letter_id,delivery_id,reason_code,failure_count,data) VALUES($1,$2,$3,$4,$5)").bind(id()).bind(delivery).bind(&input.error_code).bind(attempts).bind(json!({"generation":input.generation})).execute(&mut *tx).await?;
        } else {
            let delay = 1_i64 << attempts.min(6);
            sqlx::query("UPDATE ecp_deliveries SET state='RETRY_WAIT',next_attempt_at=clock_timestamp()+make_interval(secs=>$2),last_error_code=$3 WHERE delivery_id=$1").bind(delivery).bind(delay as i32).bind(&input.error_code).execute(&mut *tx).await?;
        }
        let result = json!({"delivery_id":delivery,"generation":input.generation,"attempt_number":attempts,"state":if dead {"DEAD_LETTER"} else {"RETRY_WAIT"},"error_code":input.error_code,"replayed":false});
        sqlx::query("INSERT INTO ecp_delivery_commands(command_id,delivery_id,command_kind,request_key,generation,result) VALUES($1,$2,'FAIL',$3,$4,$5)").bind(id()).bind(delivery).bind(&input.request_key).bind(input.generation).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn revoke_ecp_conversation(
        &self,
        account: &str,
        conversation: &str,
        input: ConversationRevokeInput,
    ) -> Result<Value> {
        ensure_request_key(&input.request_key)?;
        ensure_id(&input.reason_code, "reason_code")?;
        let mut tx = self.pool.begin().await?;
        let (workspace, status, owner): (String, String, String) = sqlx::query_as("SELECT workspace_id,status,created_by_principal_id FROM ecp_conversations WHERE conversation_id=$1 FOR UPDATE").bind(conversation).fetch_optional(&mut *tx).await?.ok_or_else(|| err("NOT_FOUND", "conversation not found"))?;
        let principal = Self::human_principal_tx(&mut tx, account, &workspace).await?;
        if principal != owner {
            return Err(err("FORBIDDEN", "conversation owner required"));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT result FROM ecp_conversation_commands WHERE conversation_id=$1 AND principal_id=$2 AND command_kind='REVOKE' AND request_key=$3 FOR SHARE").bind(conversation).bind(&principal).bind(&input.request_key).fetch_optional(&mut *tx).await? { tx.commit().await?; return Ok(existing); }
        if status == "REVOKED" {
            return Err(err("CONFLICT", "conversation is already revoked"));
        }
        sqlx::query("UPDATE ecp_conversations SET status='REVOKED',revision=revision+1,archived_at=clock_timestamp() WHERE conversation_id=$1").bind(conversation).execute(&mut *tx).await?;
        let count: i64 = sqlx::query_scalar("WITH changed AS (UPDATE ecp_deliveries d SET state='REVOKED',last_error_code=$2 FROM ecp_messages m WHERE d.message_id=m.message_id AND m.conversation_id=$1 AND d.state IN ('PENDING','IN_FLIGHT','RETRY_WAIT','UNCONFIRMED') RETURNING 1) SELECT count(*) FROM changed").bind(conversation).bind(&input.reason_code).fetch_one(&mut *tx).await?;
        let result = json!({"conversation_id":conversation,"status":"REVOKED","revoked_deliveries":count,"reason_code":input.reason_code,"replayed":false});
        sqlx::query("INSERT INTO ecp_conversation_commands(command_id,conversation_id,principal_id,command_kind,request_key,result) VALUES($1,$2,$3,'REVOKE',$4,$5)").bind(id()).bind(conversation).bind(&principal).bind(&input.request_key).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}
