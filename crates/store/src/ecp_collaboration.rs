//! Minimal durable collaboration runtime for the ECP Phase 4 tables.
//!
//! The tables in migration 0018 model collaboration facts rather than
//! execution.  Each command validates authority and emits its outbox fact in
//! the same PostgreSQL transaction as the authoritative row.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssignmentInput {
    pub assignment_id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    pub assignee_principal_id: String,
    #[serde(default)]
    pub parent_grant_id: Option<String>,
    #[serde(default)]
    pub parent_assignment_id: Option<String>,
    pub action_set: Vec<String>,
    #[serde(default)]
    pub project_set: Vec<String>,
    #[serde(default)]
    pub write_set: Vec<String>,
    #[serde(default)]
    pub executor_set: Vec<String>,
    #[serde(default)]
    pub budget: Value,
    #[serde(default)]
    pub expected_revision: Option<i64>,
    pub request_key: String,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssignmentTransitionInput {
    pub expected_revision: i64,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalInput {
    pub proposal_id: String,
    pub assignment_id: String,
    pub base_revision: i64,
    pub payload: Value,
    #[serde(default)]
    pub write_set: Vec<String>,
    #[serde(default)]
    pub budget: Value,
    #[serde(default)]
    pub status: Option<String>,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewInput {
    pub review_id: String,
    pub proposal_id: String,
    pub decision: String,
    pub expected_revision: i64,
    #[serde(default)]
    pub evidence: Value,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionInput {
    pub decision_id: String,
    pub proposal_id: String,
    pub outcome: String,
    pub expected_revision: i64,
    #[serde(default)]
    pub revision: Option<i64>,
    pub reason: String,
    #[serde(default)]
    pub evidence: Value,
    pub request_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationInput {
    pub escalation_id: String,
    #[serde(default)]
    pub assignment_id: Option<String>,
    #[serde(default)]
    pub proposal_id: Option<String>,
    pub reason_code: String,
    #[serde(default)]
    pub details: Value,
    pub request_key: String,
}

fn ensure_id(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(err("VALIDATION_ERROR", format!("invalid {label}")));
    }
    Ok(())
}
fn ensure_request_key(value: &str) -> Result<()> {
    if value.len() < 16 || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(err(
            "VALIDATION_ERROR",
            "request_key must contain 16..128 printable characters",
        ));
    }
    Ok(())
}
fn ensure_json_object(value: &Value, label: &str) -> Result<()> {
    if !value.is_object() {
        return Err(err(
            "VALIDATION_ERROR",
            format!("{label} must be an object"),
        ));
    }
    Ok(())
}
fn ensure_set(values: &[String], label: &str) -> Result<()> {
    if values.iter().any(|v| v.trim().is_empty() || v.len() > 512) {
        return Err(err("VALIDATION_ERROR", format!("invalid {label}")));
    }
    Ok(())
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
            (Some(c), Some(p)) => c <= p,
            _ => value == parent_value,
        }
    })
}

async fn actor_principal(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    workspace: &str,
    owner_only: bool,
) -> Result<(String, String)> {
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL FOR SHARE")
        .bind(workspace).bind(account).fetch_optional(&mut **tx).await?;
    let allowed = if owner_only {
        role.as_deref() == Some("OWNER")
    } else {
        matches!(role.as_deref(), Some("OWNER" | "EDITOR"))
    };
    if !allowed {
        return Err(err("FORBIDDEN", "workspace editor authority required"));
    }
    let principal = format!("human:{account}");
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=$1 AND kind='HUMAN' AND status='ACTIVE' AND account_id=$2)")
        .bind(&principal).bind(account).fetch_one(&mut **tx).await?;
    if !active {
        return Err(err("FORBIDDEN", "workspace principal is not active"));
    }
    Ok((principal, role.unwrap_or_default()))
}
async fn principal_in_workspace(
    tx: &mut Transaction<'_, Postgres>,
    principal: &str,
    workspace: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM principals p WHERE p.principal_id=$1 AND p.status='ACTIVE' AND (p.workspace_id=$2 OR (p.kind='HUMAN' AND p.account_id IN (SELECT account_id FROM workspace_members WHERE workspace_id=$2 AND revoked_at IS NULL))))")
        .bind(principal).bind(workspace).fetch_one(&mut **tx).await?)
}
async fn outbox(
    tx: &mut Transaction<'_, Postgres>,
    workspace: &str,
    object_id: &str,
    kind: &str,
    payload: &Value,
) -> Result<()> {
    sqlx::query("INSERT INTO ecp_collaboration_outbox(outbox_id,workspace_id,object_id,kind,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(object_id,kind) DO NOTHING")
        .bind(id()).bind(workspace).bind(object_id).bind(kind).bind(payload).execute(&mut **tx).await?;
    Ok(())
}

impl Store {
    pub async fn create_ecp_assignment(
        &self,
        account: &str,
        workspace: &str,
        input: AssignmentInput,
    ) -> Result<Value> {
        ensure_id(&input.assignment_id, "assignment_id")?;
        ensure_id(&input.assignee_principal_id, "assignee_principal_id")?;
        ensure_request_key(&input.request_key)?;
        if input.action_set.is_empty() {
            return Err(err("VALIDATION_ERROR", "action_set cannot be empty"));
        }
        ensure_set(&input.action_set, "action_set")?;
        ensure_set(&input.project_set, "project_set")?;
        ensure_set(&input.write_set, "write_set")?;
        ensure_set(&input.executor_set, "executor_set")?;
        let budget = if input.budget.is_null() {
            json!({})
        } else {
            input.budget.clone()
        };
        ensure_json_object(&budget, "budget")?;
        let action_json = json!(input.action_set);
        let project_json = json!(input.project_set);
        let write_json = json!(input.write_set);
        let executor_json = json!(input.executor_set);
        let mut tx = self.pool.begin().await?;
        let (issuer, _) = actor_principal(&mut tx, account, workspace, false).await?;
        if let Some(project) = &input.project_id {
            let bound: Option<String> = sqlx::query_scalar(
                "SELECT workspace_id FROM project_workspaces WHERE project_id=$1 FOR SHARE",
            )
            .bind(project)
            .fetch_optional(&mut *tx)
            .await?;
            if bound.as_deref() != Some(workspace) {
                return Err(err("FORBIDDEN", "project is outside workspace"));
            }
        }
        if !principal_in_workspace(&mut tx, &input.assignee_principal_id, workspace).await? {
            return Err(err("FORBIDDEN", "assignee is outside this workspace"));
        }
        if let Some(parent) = &input.parent_grant_id {
            let scope: Option<(String, Value, Value, Value, Value, Value)> = sqlx::query_as("SELECT workspace_id,action_set,project_set,write_set,executor_set,budget FROM capability_grants WHERE grant_id=$1 AND workspace_id=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE").bind(parent).bind(workspace).fetch_optional(&mut *tx).await?;
            let Some((parent_workspace, actions, projects, writes, executors, parent_budget)) =
                scope
            else {
                return Err(err("FORBIDDEN", "parent capability is not active"));
            };
            if parent_workspace != workspace
                || !subset(&input.action_set, &actions)
                || !subset(&input.project_set, &projects)
                || !subset(&input.write_set, &writes)
                || !subset(&input.executor_set, &executors)
                || !budget_subset(&budget, &parent_budget)
            {
                return Err(err(
                    "CAPABILITY_ESCALATION",
                    "assignment exceeds its parent capability",
                ));
            }
        }
        if let Some(parent) = &input.parent_assignment_id {
            let scope: Option<(String, Value, Value, Value, Value, Value, i64)> = sqlx::query_as("SELECT workspace_id,action_set,project_set,write_set,executor_set,budget,revision FROM ecp_assignments WHERE assignment_id=$1 FOR SHARE").bind(parent).fetch_optional(&mut *tx).await?;
            let Some((parent_workspace, actions, projects, writes, executors, parent_budget, _)) =
                scope
            else {
                return Err(err("NOT_FOUND", "parent assignment not found"));
            };
            if parent_workspace != workspace
                || !subset(&input.action_set, &actions)
                || !subset(&input.project_set, &projects)
                || !subset(&input.write_set, &writes)
                || !subset(&input.executor_set, &executors)
                || !budget_subset(&budget, &parent_budget)
            {
                return Err(err(
                    "CAPABILITY_ESCALATION",
                    "child assignment exceeds parent write set or budget",
                ));
            }
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('assignment_id',assignment_id,'workspace_id',workspace_id,'project_id',project_id,'task_id',task_id,'issuer_principal_id',issuer_principal_id,'assignee_principal_id',assignee_principal_id,'parent_grant_id',parent_grant_id,'action_set',action_set,'project_set',project_set,'write_set',write_set,'executor_set',executor_set,'budget',budget,'status',status,'revision',revision,'request_key',request_key,'expires_at',expires_at,'replayed',true) FROM ecp_assignments WHERE workspace_id=$1 AND issuer_principal_id=$2 AND request_key=$3 FOR SHARE").bind(workspace).bind(&issuer).bind(&input.request_key).fetch_optional(&mut *tx).await? {
            if existing["assignment_id"] != input.assignment_id || existing["project_id"] != json!(input.project_id) || existing["task_id"] != json!(input.task_id) || existing["assignee_principal_id"] != input.assignee_principal_id || existing["parent_grant_id"] != json!(input.parent_grant_id) || existing["action_set"] != action_json || existing["project_set"] != project_json || existing["write_set"] != write_json || existing["executor_set"] != executor_json || existing["budget"] != budget || existing["expires_at"] != json!(input.expires_at) { return Err(err("IDEMPOTENCY_CONFLICT", "assignment request key already has another payload")); }
            tx.commit().await?; return Ok(existing);
        }
        if sqlx::query_scalar::<_, String>(
            "SELECT assignment_id FROM ecp_assignments WHERE assignment_id=$1 FOR SHARE",
        )
        .bind(&input.assignment_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
        {
            return Err(err("OBJECT_EXISTS", "assignment identity already exists"));
        }
        if input
            .expected_revision
            .is_some_and(|revision| revision != 1)
        {
            return Err(err(
                "REVISION_CONFLICT",
                "a new assignment must start at revision one",
            ));
        }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_assignments(assignment_id,workspace_id,project_id,task_id,issuer_principal_id,assignee_principal_id,parent_grant_id,action_set,project_set,write_set,executor_set,budget,request_key,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING jsonb_build_object('assignment_id',assignment_id,'workspace_id',workspace_id,'project_id',project_id,'task_id',task_id,'issuer_principal_id',issuer_principal_id,'assignee_principal_id',assignee_principal_id,'parent_grant_id',parent_grant_id,'action_set',action_set,'project_set',project_set,'write_set',write_set,'executor_set',executor_set,'budget',budget,'status',status,'revision',revision,'request_key',request_key,'expires_at',expires_at,'replayed',false)").bind(&input.assignment_id).bind(workspace).bind(&input.project_id).bind(&input.task_id).bind(&issuer).bind(&input.assignee_principal_id).bind(&input.parent_grant_id).bind(&action_json).bind(&project_json).bind(&write_json).bind(&executor_json).bind(&budget).bind(&input.request_key).bind(input.expires_at).fetch_one(&mut *tx).await?;
        outbox(
            &mut tx,
            workspace,
            &input.assignment_id,
            "ASSIGNMENT_CREATED",
            &value,
        )
        .await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn accept_ecp_assignment(
        &self,
        account: &str,
        assignment: &str,
        input: AssignmentTransitionInput,
    ) -> Result<Value> {
        ensure_id(assignment, "assignment_id")?;
        ensure_request_key(&input.request_key)?;
        if input.expected_revision < 1 {
            return Err(err(
                "VALIDATION_ERROR",
                "expected_revision must be positive",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let workspace: String = sqlx::query_scalar(
            "SELECT workspace_id FROM ecp_assignments WHERE assignment_id=$1 FOR UPDATE",
        )
        .bind(assignment)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "assignment not found"))?;
        let (actor, _) = actor_principal(&mut tx, account, &workspace, false).await?;
        let (assignee, status, revision, issuer): (String, String, i64, String) = sqlx::query_as("SELECT assignee_principal_id,status,revision,issuer_principal_id FROM ecp_assignments WHERE assignment_id=$1 FOR UPDATE").bind(assignment).fetch_one(&mut *tx).await?;
        if assignee != actor && issuer != actor {
            return Err(err(
                "FORBIDDEN",
                "only assignment assignee or issuer may accept",
            ));
        }
        if revision != input.expected_revision {
            return Err(err("REVISION_CONFLICT", "assignment revision changed"));
        }
        if status == "ACCEPTED" {
            let prior: Option<Value> = sqlx::query_scalar("SELECT payload FROM ecp_collaboration_outbox WHERE object_id=$1 AND kind='ASSIGNMENT_ACCEPTED' AND payload->>'request_key'=$2 FOR SHARE").bind(assignment).bind(&input.request_key).fetch_optional(&mut *tx).await?;
            if prior.is_some() {
                let value: Value = sqlx::query_scalar("SELECT jsonb_build_object('assignment_id',assignment_id,'workspace_id',workspace_id,'assignee_principal_id',assignee_principal_id,'status',status,'revision',revision,'replayed',true) FROM ecp_assignments WHERE assignment_id=$1").bind(assignment).fetch_one(&mut *tx).await?;
                tx.commit().await?;
                return Ok(value);
            }
            return Err(err("ALREADY_ACCEPTED", "assignment is already accepted"));
        }
        if status != "OFFERED" {
            return Err(err(
                "CONFLICT",
                "assignment cannot be accepted in its current state",
            ));
        }
        let value: Value = sqlx::query_scalar("UPDATE ecp_assignments SET status='ACCEPTED',revision=revision+1 WHERE assignment_id=$1 RETURNING jsonb_build_object('assignment_id',assignment_id,'workspace_id',workspace_id,'assignee_principal_id',assignee_principal_id,'status',status,'revision',revision,'replayed',false)").bind(assignment).fetch_one(&mut *tx).await?;
        outbox(
            &mut tx,
            &workspace,
            assignment,
            "ASSIGNMENT_ACCEPTED",
            &json!({"request_key": input.request_key, "data": value}),
        )
        .await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn create_ecp_proposal(&self, account: &str, input: ProposalInput) -> Result<Value> {
        ensure_id(&input.proposal_id, "proposal_id")?;
        ensure_id(&input.assignment_id, "assignment_id")?;
        ensure_request_key(&input.request_key)?;
        ensure_json_object(&input.payload, "payload")?;
        ensure_set(&input.write_set, "write_set")?;
        let budget = if input.budget.is_null() {
            json!({})
        } else {
            input.budget.clone()
        };
        ensure_json_object(&budget, "budget")?;
        if input.base_revision < 1 {
            return Err(err("VALIDATION_ERROR", "base_revision must be positive"));
        }
        let status = input.status.clone().unwrap_or_else(|| "DRAFT".into());
        if !matches!(status.as_str(), "DRAFT" | "SUBMITTED") {
            return Err(err("VALIDATION_ERROR", "invalid proposal status"));
        }
        let payload_sha256 = forgeflow_planner::sha256(&serde_json::to_vec(&input.payload)?);
        let mut tx = self.pool.begin().await?;
        let assignment: Option<(String, Option<String>, Value, Value, i64, String, String)> = sqlx::query_as("SELECT workspace_id,project_id,write_set,budget,revision,issuer_principal_id,assignee_principal_id FROM ecp_assignments WHERE assignment_id=$1 AND status NOT IN ('REVOKED','EXPIRED') FOR UPDATE").bind(&input.assignment_id).fetch_optional(&mut *tx).await?;
        let Some((
            workspace,
            project_id,
            parent_write,
            parent_budget,
            assignment_revision,
            issuer,
            assignee,
        )) = assignment
        else {
            return Err(err("NOT_FOUND", "active assignment not found"));
        };
        let (actor, role) = actor_principal(&mut tx, account, &workspace, false).await?;
        if actor != issuer && actor != assignee && role != "OWNER" {
            return Err(err(
                "FORBIDDEN",
                "only assignment issuer, assignee or workspace owner may propose",
            ));
        }
        if !subset(&input.write_set, &parent_write) || !budget_subset(&budget, &parent_budget) {
            return Err(err(
                "CAPABILITY_ESCALATION",
                "proposal exceeds assignment write set or budget",
            ));
        }
        if input.base_revision != assignment_revision {
            return Err(err("REVISION_CONFLICT", "assignment revision changed"));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('proposal_id',proposal_id,'assignment_id',assignment_id,'workspace_id',workspace_id,'project_id',project_id,'author_principal_id',author_principal_id,'base_revision',base_revision,'payload',payload,'payload_sha256',payload_sha256,'write_set',write_set,'budget',budget,'status',status,'revision',revision,'replayed',true) FROM ecp_proposals WHERE proposal_id=$1 FOR SHARE").bind(&input.proposal_id).fetch_optional(&mut *tx).await? {
            if existing["payload_sha256"] != payload_sha256 || existing["author_principal_id"] != actor || existing["assignment_id"] != input.assignment_id || existing["base_revision"] != input.base_revision || existing["write_set"] != json!(input.write_set) || existing["budget"] != budget || existing["status"] != status { return Err(err("IDEMPOTENCY_CONFLICT", "proposal identity has another payload")); }
            tx.commit().await?; return Ok(existing);
        }
        if sqlx::query_scalar::<_, String>("SELECT proposal_id FROM ecp_proposals WHERE assignment_id=$1 AND revision=$2 FOR SHARE").bind(&input.assignment_id).bind(input.base_revision).fetch_optional(&mut *tx).await?.is_some() { return Err(err("REVISION_CONFLICT", "assignment revision already has a proposal")); }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_proposals(proposal_id,assignment_id,workspace_id,project_id,author_principal_id,base_revision,payload,payload_sha256,write_set,budget,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING jsonb_build_object('proposal_id',proposal_id,'assignment_id',assignment_id,'workspace_id',workspace_id,'project_id',project_id,'author_principal_id',author_principal_id,'base_revision',base_revision,'payload',payload,'payload_sha256',payload_sha256,'write_set',write_set,'budget',budget,'status',status,'revision',revision,'replayed',false)").bind(&input.proposal_id).bind(&input.assignment_id).bind(&workspace).bind(&project_id).bind(&actor).bind(input.base_revision).bind(&input.payload).bind(&payload_sha256).bind(json!(input.write_set)).bind(&budget).bind(&status).fetch_one(&mut *tx).await?;
        outbox(
            &mut tx,
            &workspace,
            &input.proposal_id,
            "PROPOSAL_CREATED",
            &json!({"request_key": input.request_key, "data": value}),
        )
        .await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn create_ecp_review(&self, account: &str, input: ReviewInput) -> Result<Value> {
        ensure_id(&input.review_id, "review_id")?;
        ensure_id(&input.proposal_id, "proposal_id")?;
        ensure_request_key(&input.request_key)?;
        if !matches!(
            input.decision.as_str(),
            "APPROVE" | "REJECT" | "REQUEST_CHANGES"
        ) {
            return Err(err("VALIDATION_ERROR", "invalid review decision"));
        }
        if input.expected_revision < 1 {
            return Err(err(
                "VALIDATION_ERROR",
                "expected_revision must be positive",
            ));
        }
        let evidence = if input.evidence.is_null() {
            json!({})
        } else {
            input.evidence.clone()
        };
        ensure_json_object(&evidence, "evidence")?;
        let mut tx = self.pool.begin().await?;
        let proposal: Option<(String, String, i64)> = sqlx::query_as("SELECT workspace_id,author_principal_id,revision FROM ecp_proposals WHERE proposal_id=$1 FOR UPDATE").bind(&input.proposal_id).fetch_optional(&mut *tx).await?;
        let Some((workspace, author, revision)) = proposal else {
            return Err(err("NOT_FOUND", "proposal not found"));
        };
        let (actor, _) = actor_principal(&mut tx, account, &workspace, false).await?;
        if actor == author {
            return Err(err(
                "FORBIDDEN",
                "proposal author cannot supply its independent review",
            ));
        }
        if revision != input.expected_revision {
            return Err(err("REVISION_CONFLICT", "proposal revision changed"));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('review_id',review_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'reviewer_principal_id',reviewer_principal_id,'decision',decision,'expected_revision',expected_revision,'evidence',evidence,'replayed',true) FROM ecp_reviews WHERE review_id=$1 FOR SHARE").bind(&input.review_id).fetch_optional(&mut *tx).await? { if existing["proposal_id"] != input.proposal_id || existing["decision"] != input.decision || existing["expected_revision"] != input.expected_revision || existing["evidence"] != evidence { return Err(err("IDEMPOTENCY_CONFLICT", "review identity has another payload")); } tx.commit().await?; return Ok(existing); }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('review_id',review_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'reviewer_principal_id',reviewer_principal_id,'decision',decision,'expected_revision',expected_revision,'evidence',evidence,'replayed',true) FROM ecp_reviews WHERE proposal_id=$1 AND reviewer_principal_id=$2 AND expected_revision=$3 FOR SHARE").bind(&input.proposal_id).bind(&actor).bind(input.expected_revision).fetch_optional(&mut *tx).await? { if existing["decision"] != input.decision || existing["evidence"] != evidence { return Err(err("IDEMPOTENCY_CONFLICT", "review already recorded with another outcome")); } tx.commit().await?; return Ok(existing); }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_reviews(review_id,proposal_id,workspace_id,reviewer_principal_id,decision,expected_revision,evidence) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING jsonb_build_object('review_id',review_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'reviewer_principal_id',reviewer_principal_id,'decision',decision,'expected_revision',expected_revision,'evidence',evidence,'replayed',false)").bind(&input.review_id).bind(&input.proposal_id).bind(&workspace).bind(&actor).bind(&input.decision).bind(input.expected_revision).bind(&evidence).fetch_one(&mut *tx).await?;
        outbox(
            &mut tx,
            &workspace,
            &input.review_id,
            "REVIEW_RECORDED",
            &json!({"request_key": input.request_key, "data": value}),
        )
        .await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn create_ecp_decision(&self, account: &str, input: DecisionInput) -> Result<Value> {
        ensure_id(&input.decision_id, "decision_id")?;
        ensure_id(&input.proposal_id, "proposal_id")?;
        ensure_request_key(&input.request_key)?;
        if !matches!(
            input.outcome.as_str(),
            "APPROVE" | "REJECT" | "REQUEST_CHANGES"
        ) || input.reason.trim().is_empty()
        {
            return Err(err(
                "VALIDATION_ERROR",
                "invalid decision outcome or reason",
            ));
        }
        if input.expected_revision < 1 {
            return Err(err(
                "VALIDATION_ERROR",
                "expected_revision must be positive",
            ));
        }
        let decision_revision = input.revision.unwrap_or(input.expected_revision);
        if decision_revision != input.expected_revision || decision_revision < 1 {
            return Err(err(
                "REVISION_CONFLICT",
                "decision revision must match proposal revision",
            ));
        }
        let evidence = if input.evidence.is_null() {
            json!({})
        } else {
            input.evidence.clone()
        };
        ensure_json_object(&evidence, "evidence")?;
        let mut tx = self.pool.begin().await?;
        let proposal: Option<(String, i64)> = sqlx::query_as(
            "SELECT workspace_id,revision FROM ecp_proposals WHERE proposal_id=$1 FOR UPDATE",
        )
        .bind(&input.proposal_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((workspace, proposal_revision)) = proposal else {
            return Err(err("NOT_FOUND", "proposal not found"));
        };
        let (actor, _) = actor_principal(&mut tx, account, &workspace, true).await?;
        if proposal_revision != input.expected_revision {
            return Err(err("REVISION_CONFLICT", "proposal revision changed"));
        }
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('decision_id',decision_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'issuer_principal_id',issuer_principal_id,'outcome',outcome,'expected_revision',expected_revision,'revision',revision,'reason',reason,'evidence',evidence,'replayed',true) FROM ecp_decisions WHERE decision_id=$1 FOR SHARE").bind(&input.decision_id).fetch_optional(&mut *tx).await? { if existing["proposal_id"] != input.proposal_id || existing["outcome"] != input.outcome || existing["expected_revision"] != input.expected_revision || existing["revision"] != decision_revision || existing["reason"] != input.reason || existing["evidence"] != evidence { return Err(err("IDEMPOTENCY_CONFLICT", "decision identity has another payload")); } tx.commit().await?; return Ok(existing); }
        if sqlx::query_scalar::<_, String>(
            "SELECT decision_id FROM ecp_decisions WHERE proposal_id=$1 AND revision=$2 FOR SHARE",
        )
        .bind(&input.proposal_id)
        .bind(decision_revision)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
        {
            return Err(err(
                "REVISION_CONFLICT",
                "proposal revision already has a formal decision",
            ));
        }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_decisions(decision_id,proposal_id,workspace_id,issuer_principal_id,outcome,expected_revision,revision,reason,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING jsonb_build_object('decision_id',decision_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'issuer_principal_id',issuer_principal_id,'outcome',outcome,'expected_revision',expected_revision,'revision',revision,'reason',reason,'evidence',evidence,'replayed',false)").bind(&input.decision_id).bind(&input.proposal_id).bind(&workspace).bind(&actor).bind(&input.outcome).bind(input.expected_revision).bind(decision_revision).bind(&input.reason).bind(&evidence).fetch_one(&mut *tx).await?;
        let next_status = match input.outcome.as_str() {
            "APPROVE" => "APPROVED",
            "REJECT" => "REJECTED",
            _ => "CHANGES_REQUESTED",
        };
        sqlx::query("UPDATE ecp_proposals SET status=$2 WHERE proposal_id=$1")
            .bind(&input.proposal_id)
            .bind(next_status)
            .execute(&mut *tx)
            .await?;
        outbox(
            &mut tx,
            &workspace,
            &input.decision_id,
            "DECISION_RECORDED",
            &json!({"request_key": input.request_key, "data": value}),
        )
        .await?;
        tx.commit().await?;
        Ok(value)
    }

    pub async fn create_ecp_escalation(
        &self,
        account: &str,
        input: EscalationInput,
    ) -> Result<Value> {
        ensure_id(&input.escalation_id, "escalation_id")?;
        ensure_request_key(&input.request_key)?;
        if input.assignment_id.is_some() == input.proposal_id.is_some() {
            return Err(err(
                "VALIDATION_ERROR",
                "exactly one escalation target is required",
            ));
        }
        if input.reason_code.trim().is_empty() {
            return Err(err("VALIDATION_ERROR", "reason_code is required"));
        }
        let details = if input.details.is_null() {
            json!({})
        } else {
            input.details.clone()
        };
        ensure_json_object(&details, "details")?;
        let mut tx = self.pool.begin().await?;
        let workspace: String = if let Some(assignment) = &input.assignment_id {
            sqlx::query_scalar(
                "SELECT workspace_id FROM ecp_assignments WHERE assignment_id=$1 FOR UPDATE",
            )
            .bind(assignment)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "assignment not found"))?
        } else {
            sqlx::query_scalar(
                "SELECT workspace_id FROM ecp_proposals WHERE proposal_id=$1 FOR UPDATE",
            )
            .bind(input.proposal_id.as_ref().unwrap())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "proposal not found"))?
        };
        let (actor, _) = actor_principal(&mut tx, account, &workspace, false).await?;
        if let Some(existing) = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('escalation_id',escalation_id,'assignment_id',assignment_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'raised_by_principal_id',raised_by_principal_id,'reason_code',reason_code,'details',details,'status',status,'revision',revision,'replayed',true) FROM ecp_escalations WHERE escalation_id=$1 FOR SHARE").bind(&input.escalation_id).fetch_optional(&mut *tx).await? { if existing["assignment_id"] != json!(input.assignment_id) || existing["proposal_id"] != json!(input.proposal_id) || existing["reason_code"] != input.reason_code || existing["details"] != details { return Err(err("IDEMPOTENCY_CONFLICT", "escalation identity has another payload")); } tx.commit().await?; return Ok(existing); }
        let value: Value = sqlx::query_scalar("INSERT INTO ecp_escalations(escalation_id,assignment_id,proposal_id,workspace_id,raised_by_principal_id,reason_code,details) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING jsonb_build_object('escalation_id',escalation_id,'assignment_id',assignment_id,'proposal_id',proposal_id,'workspace_id',workspace_id,'raised_by_principal_id',raised_by_principal_id,'reason_code',reason_code,'details',details,'status',status,'revision',revision,'replayed',false)").bind(&input.escalation_id).bind(&input.assignment_id).bind(&input.proposal_id).bind(&workspace).bind(&actor).bind(&input.reason_code).bind(&details).fetch_one(&mut *tx).await?;
        outbox(
            &mut tx,
            &workspace,
            &input.escalation_id,
            "ESCALATION_RAISED",
            &json!({"request_key": input.request_key, "data": value}),
        )
        .await?;
        tx.commit().await?;
        Ok(value)
    }
}
