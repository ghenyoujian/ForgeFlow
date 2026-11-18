//! Compact template results reference their already-committed, immutable PUT_FLOW receipt.
use crate::{Result, Store, err};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

pub const TEMPLATE_ASSEMBLY_RESULT_V2: &str = "forgeflow.execution-template-result.v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFlowReference {
    pub project_id: String,
    pub flow_revision: u64,
    pub revision: u64,
    pub input_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBindingReceiptReference {
    pub operation_id: String,
    pub flow_sha256: String,
    pub context_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateAssemblyReferences {
    pub flow_ref: TemplateFlowReference,
    pub binding_receipt: TemplateBindingReceiptReference,
}

struct BindingReceipt {
    actor_id: String,
    operation: String,
    idempotency_key: String,
    operation_id: String,
    request: Value,
    response: Value,
}

struct BindingSnapshot {
    references: TemplateAssemblyReferences,
    flow: Value,
    context: Value,
}

fn invalid(message: &str) -> crate::StoreError {
    err("TEMPLATE_RECEIPT_INVALID", message)
}

fn digest(value: &Value) -> Result<String> {
    Ok(forgeflow_planner::sha256(&serde_json::to_vec(value)?))
}

fn snapshot(
    project: &str,
    template_operation: &str,
    binding_operation: &str,
    receipt: BindingReceipt,
) -> Result<BindingSnapshot> {
    if receipt.actor_id != "template-service"
        || receipt.operation != "catalog"
        || receipt.idempotency_key != format!("{template_operation}:flow-binding")
        || receipt.operation_id != binding_operation
        || receipt.response["operation_id"].as_str() != Some(binding_operation)
        || receipt.request["kind"].as_str() != Some("PUT_FLOW")
    {
        return Err(invalid(
            "template binding receipt has a different command identity",
        ));
    }
    let payload = &receipt.request["payload"];
    let requested_flow = &payload["flow"];
    let flow = &receipt.response["value"];
    let context = &payload["context"];
    let flow_revision = flow["flow_revision"]
        .as_u64()
        .ok_or_else(|| invalid("template receipt lacks its Flow revision"))?;
    let revision = flow["revision"]
        .as_u64()
        .ok_or_else(|| invalid("template receipt lacks its object revision"))?;
    let input_digest = flow["input_digest"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("template receipt lacks its input digest"))?;
    if project.is_empty()
        || requested_flow["project_id"].as_str() != Some(project)
        || flow["project_id"].as_str() != Some(project)
        || requested_flow["flow_revision"].as_u64() != Some(flow_revision)
        || requested_flow["input_digest"].as_str() != Some(input_digest)
        || payload["expected_revision"]
            .as_u64()
            .and_then(|value| value.checked_add(1))
            != Some(revision)
        || !flow["tasks"].is_array()
        || !context.is_object()
    {
        return Err(invalid(
            "template binding receipt has a different project or Flow binding",
        ));
    }
    Ok(BindingSnapshot {
        references: TemplateAssemblyReferences {
            flow_ref: TemplateFlowReference {
                project_id: project.into(),
                flow_revision,
                revision,
                input_digest: input_digest.into(),
            },
            binding_receipt: TemplateBindingReceiptReference {
                operation_id: binding_operation.into(),
                flow_sha256: digest(flow)?,
                context_sha256: digest(context)?,
            },
        },
        flow: flow.clone(),
        context: context.clone(),
    })
}

impl Store {
    async fn template_binding_snapshot(
        &self,
        project: &str,
        template_operation: &str,
        binding_operation: &str,
    ) -> Result<BindingSnapshot> {
        if template_operation.len() != 32
            || !template_operation
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || uuid::Uuid::parse_str(binding_operation).is_err()
        {
            return Err(invalid("invalid template operation reference"));
        }
        // Do not expose a generic receipt reader or expand its service allowlist.
        // The original template operation, service actor and command kind all bind this lookup.
        let row = sqlx::query("SELECT actor_id,operation,idempotency_key,operation_id,request,response FROM idempotency_records WHERE operation_id=$1 AND actor_id='template-service' AND operation='catalog' AND idempotency_key=$2")
            .bind(binding_operation)
            .bind(format!("{template_operation}:flow-binding"))
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| invalid("immutable template binding receipt is unavailable"))?;
        snapshot(
            project,
            template_operation,
            binding_operation,
            BindingReceipt {
                actor_id: row.try_get("actor_id")?,
                operation: row.try_get("operation")?,
                idempotency_key: row.try_get("idempotency_key")?,
                operation_id: row.try_get("operation_id")?,
                request: row.try_get("request")?,
                response: row.try_get("response")?,
            },
        )
    }

    /// Derive digests from the committed JSONB receipt, not from a mutable current Flow row.
    pub async fn template_assembly_references(
        &self,
        project: &str,
        template_operation: &str,
        binding_operation: &str,
    ) -> Result<TemplateAssemblyReferences> {
        Ok(self
            .template_binding_snapshot(project, template_operation, binding_operation)
            .await?
            .references)
    }

    /// Reconstruct only this operation's original snapshots; fail closed on missing or changed history.
    pub async fn resolve_template_assembly_references(
        &self,
        project: &str,
        template_operation: &str,
        references: &TemplateAssemblyReferences,
    ) -> Result<(Value, Value)> {
        let saved = self
            .template_binding_snapshot(
                project,
                template_operation,
                &references.binding_receipt.operation_id,
            )
            .await?;
        if saved.references != *references {
            return Err(invalid(
                "template snapshot identity or content digest differs from its receipt",
            ));
        }
        Ok((saved.flow, saved.context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn receipt() -> BindingReceipt {
        BindingReceipt {
            actor_id: "template-service".into(),
            operation: "catalog".into(),
            idempotency_key: "operation:flow-binding".into(),
            operation_id: "binding".into(),
            request: json!({"kind":"PUT_FLOW","payload":{
                "flow":{"project_id":"p","flow_revision":7,"input_digest":"semantic-digest"},
                "expected_revision":4,"context":{"task_specs":{"original":{"outcome":"original"}}}
            }}),
            response: json!({"operation_id":"binding","value":{
                "project_id":"p","flow_revision":7,"revision":5,
                "input_digest":"semantic-digest","tasks":[{"task_id":"original"}]
            }}),
        }
    }

    #[test]
    fn template_receipt_rejects_other_authorities_and_changed_snapshots() {
        let original = snapshot("p", "operation", "binding", receipt()).unwrap();
        for change in 0..6 {
            let mut wrong = receipt();
            match change {
                0 => wrong.actor_id = "other-service".into(),
                1 => wrong.idempotency_key = "another-operation:flow-binding".into(),
                2 => wrong.request["kind"] = json!("PUT_DOCUMENT"),
                3 => wrong.request["payload"]["flow"]["project_id"] = json!("other-project"),
                4 => wrong.response["operation_id"] = json!("other-binding"),
                _ => wrong.response["value"]["revision"] = json!(6),
            }
            assert!(snapshot("p", "operation", "binding", wrong).is_err());
        }
        let mut changed = receipt();
        changed.request["payload"]["context"]["task_specs"]["original"]["outcome"] =
            json!("changed");
        let changed = snapshot("p", "operation", "binding", changed).unwrap();
        assert_ne!(original.references, changed.references);
        assert_eq!(
            original.context["task_specs"]["original"]["outcome"],
            "original"
        );
        assert_eq!(original.flow["revision"], 5);
        assert!(snapshot("other-project", "operation", "binding", receipt()).is_err());
    }
}
