//! Owner-reviewed, versioned decisions with one narrowly defined policy effect.
use crate::*;

impl Store {
    /// Legacy generic decision documents remain readable through documents APIs,
    /// but cannot acquire authority merely by claiming the new schema string.
    pub async fn list_decisions(&self, project: &str) -> Result<Vec<Decision>> {
        self.get_project(project).await?;
        let rows: Vec<Value> = sqlx::query_scalar("SELECT d.data FROM documents d WHERE d.project_id=$1 AND d.collection='decisions' AND d.data->>'schema_version'=$2 AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='decision_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data) ORDER BY d.document_id")
            .bind(project).bind(DECISION_INBOX_SCHEMA).fetch_all(&self.pool).await?;
        rows.into_iter().map(decode).collect()
    }
    pub async fn get_decision(&self, project: &str, decision: &str) -> Result<Decision> {
        let value: Option<Value> = sqlx::query_scalar("SELECT d.data FROM documents d WHERE d.project_id=$1 AND d.collection='decisions' AND d.document_id=$2 AND d.data->>'schema_version'=$3 AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='decision_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data)")
            .bind(project).bind(decision).bind(DECISION_INBOX_SCHEMA).fetch_optional(&self.pool).await?;
        decode(value.ok_or_else(|| {
            err(
                "NOT_FOUND",
                "verified decision not found; legacy documents are not actionable",
            )
        })?)
    }
}

fn text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(err(
            "DECISION_INVALID",
            "nonempty decision explanation up to 4096 bytes required",
        ));
    }
    Ok(())
}

async fn policy_lock(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    scope: &str,
) -> Result<ResourcePolicy> {
    let row = sqlx::query("SELECT data,revision,paused FROM resource_scopes WHERE scope_id=$1 AND project_id=$2 AND worker_id IS NULL FOR UPDATE")
        .bind(scope).bind(project).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("DECISION_SCOPE_DENIED", "existing same-project resource policy required; no global or Worker scope"))?;
    let policy: ResourcePolicy = decode(row.get("data"))?;
    if policy.scope_id != scope
        || policy.project_id.as_deref() != Some(project)
        || policy.worker_id.is_some()
        || policy.revision != row.get::<i64, _>("revision") as u64
        || policy.paused != row.get::<bool, _>("paused")
    {
        return Err(err(
            "DECISION_SCOPE_DENIED",
            "canonical policy identity differs",
        ));
    }
    Ok(policy)
}

async fn decision_lock(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    id: &str,
    revision: u64,
) -> Result<Decision> {
    let row = sqlx::query("SELECT d.data,d.revision FROM documents d WHERE d.project_id=$1 AND d.collection='decisions' AND d.document_id=$2 AND d.data->>'schema_version'=$3 AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='decision_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data) FOR UPDATE OF d")
        .bind(project).bind(id).bind(DECISION_INBOX_SCHEMA).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("NOT_FOUND", "verified decision not found"))?;
    let decision: Decision = decode(row.get("data"))?;
    if decision.project_id != project
        || decision.decision_id != id
        || decision.revision != revision
        || row.get::<i64, _>("revision") != i64v(revision)?
    {
        return Err(err("REVISION_CONFLICT", "decision revision changed"));
    }
    Ok(decision)
}

async fn persist(
    tx: &mut Transaction<'_, Postgres>,
    d: &Decision,
    previous: Option<u64>,
    kind: &str,
) -> Result<()> {
    let value = json(d)?;
    if let Some(previous) = previous {
        let changed = sqlx::query("UPDATE documents SET revision=$4,data=$5 WHERE project_id=$1 AND collection='decisions' AND document_id=$2 AND revision=$3")
            .bind(&d.project_id).bind(&d.decision_id).bind(i64v(previous)?).bind(i64v(d.revision)?).bind(&value)
            .execute(&mut **tx).await?.rows_affected();
        if changed != 1 {
            return Err(err("REVISION_CONFLICT", "decision compare-and-set lost"));
        }
    } else {
        sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'decisions',$2,$3,$4)")
            .bind(&d.project_id).bind(&d.decision_id).bind(i64v(d.revision)?).bind(&value).execute(&mut **tx).await?;
    }
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'decision_history',$2,$3,$4)")
        .bind(&d.project_id).bind(format!("{}:{}", d.decision_id, d.revision)).bind(i64v(d.revision)?).bind(&value).execute(&mut **tx).await?;
    event(tx, &d.project_id, &d.decision_id, d.revision, kind, value).await
}

pub(crate) async fn apply_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    command: DecisionCommand,
    actor: &str,
) -> Result<Value> {
    // HTTP authenticates the Owner. Service principals cannot use the narrow
    // typed authority command, even through internal generic command plumbing.
    if actor.trim().is_empty()
        || actor.starts_with("worker-service")
        || matches!(
            actor,
            "scheduler-service" | "verification-service" | "recovery-service" | "internal"
        )
    {
        return Err(err(
            "DECISION_OWNER_REQUIRED",
            "authenticated Owner review required",
        ));
    }
    let project = match &command {
        DecisionCommand::OpenPausedPolicy { project_id, .. }
        | DecisionCommand::Acknowledge { project_id, .. }
        | DecisionCommand::Defer { project_id, .. }
        | DecisionCommand::Resolve { project_id, .. } => project_id,
    };
    let p = project_lock(tx, project).await?;
    if p.authority_mode != AuthorityMode::Managed || p.archived {
        return Err(err(
            "DECISION_SCOPE_DENIED",
            "nonarchived managed project required",
        ));
    }
    match command {
        DecisionCommand::OpenPausedPolicy {
            project_id,
            scope_id,
            expected_policy_revision,
            note,
        } => {
            text(&note)?;
            let policy = policy_lock(tx, &project_id, &scope_id).await?;
            if !policy.paused || policy.revision != expected_policy_revision {
                return Err(err(
                    "REVISION_CONFLICT",
                    "bound resource policy must still be paused at expected revision",
                ));
            }
            let existing: Option<Value> = sqlx::query_scalar("SELECT d.data FROM documents d WHERE d.project_id=$1 AND d.collection='decisions' AND d.data->>'schema_version'=$2 AND d.data->>'cause'='PAUSED_RESOURCE_POLICY' AND d.data->'policy'->>'scope_id'=$3 AND d.data->'policy'->'revision'=to_jsonb($4::bigint) AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='decision_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data) ORDER BY d.document_id LIMIT 1")
                .bind(&project_id).bind(DECISION_INBOX_SCHEMA).bind(&scope_id).bind(i64v(expected_policy_revision)?)
                .fetch_optional(&mut **tx).await?;
            if let Some(existing) = existing {
                let decision: Decision = decode(existing)?;
                return json(&DecisionOutcome {
                    decision,
                    policy,
                    created: false,
                    policy_changed: false,
                });
            }
            let rows = sqlx::query("SELECT t.task_id,t.task_revision,d.revision AS queue_revision FROM documents d JOIN tasks t ON t.project_id=d.project_id AND t.task_id=d.document_id WHERE d.project_id=$1 AND d.collection='queue_entries' AND d.data->>'status'='QUEUED' AND d.data->'task_revision'=to_jsonb(t.task_revision) AND t.state='READY_FOR_ADMISSION' AND ($2::text IS NULL OR EXISTS(SELECT 1 FROM owner_closure c WHERE c.project_id=t.project_id AND c.descendant_id=t.team_id AND c.ancestor_id=$2)) AND NOT EXISTS(SELECT 1 FROM attempts a WHERE a.project_id=t.project_id AND a.task_id=t.task_id AND a.task_revision=t.task_revision AND a.terminal_at IS NULL) ORDER BY t.task_id")
                .bind(&project_id).bind(&policy.team_id).fetch_all(&mut **tx).await?;
            if rows.is_empty() {
                return Err(err(
                    "DECISION_CAUSE_NOT_OBSERVED",
                    "paused policy must bind real current queued tasks within its scope",
                ));
            }
            let blocked_tasks = rows
                .into_iter()
                .map(|row| DecisionBlockedTask {
                    task_id: row.get("task_id"),
                    task_revision: row.get::<i64, _>("task_revision") as u64,
                    queue_revision: row.get::<i64, _>("queue_revision") as u64,
                })
                .collect();
            let now = db_now(tx).await?;
            let decision = Decision {
                schema_version: DECISION_INBOX_SCHEMA.into(),
                decision_id: id(),
                project_id,
                cause: DecisionCause::PausedResourcePolicy,
                state: DecisionState::Open,
                policy: policy.clone(),
                blocked_tasks,
                note,
                created_by: actor.into(),
                created_at: now,
                updated_at: now,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: None,
                resolved_at: None,
                revisit_at: None,
                resolution_reason: None,
                revision: 1,
            };
            persist(tx, &decision, None, "decision.opened").await?;
            json(&DecisionOutcome {
                decision,
                policy,
                created: true,
                policy_changed: false,
            })
        }
        DecisionCommand::Acknowledge {
            project_id,
            decision_id,
            expected_revision,
            note,
        } => {
            text(&note)?;
            let mut decision =
                decision_lock(tx, &project_id, &decision_id, expected_revision).await?;
            if decision.state != DecisionState::Open {
                return Err(err(
                    "DECISION_STATE_CONFLICT",
                    "only OPEN decision can be acknowledged",
                ));
            }
            let policy = policy_lock(tx, &project_id, &decision.policy.scope_id).await?;
            let now = db_now(tx).await?;
            decision.state = DecisionState::Acknowledged;
            decision.acknowledged_by = Some(actor.into());
            decision.acknowledged_at = Some(now);
            decision.updated_at = now;
            decision.note = note;
            decision.revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| err("REVISION_CONFLICT", "decision revision overflow"))?;
            persist(
                tx,
                &decision,
                Some(expected_revision),
                "decision.acknowledged",
            )
            .await?;
            json(&DecisionOutcome {
                decision,
                policy,
                created: false,
                policy_changed: false,
            })
        }
        DecisionCommand::Defer {
            project_id,
            decision_id,
            expected_revision,
            revisit_at,
            reason,
        } => {
            text(&reason)?;
            let mut decision =
                decision_lock(tx, &project_id, &decision_id, expected_revision).await?;
            if !matches!(
                decision.state,
                DecisionState::Open | DecisionState::Acknowledged
            ) {
                return Err(err(
                    "DECISION_STATE_CONFLICT",
                    "only OPEN/ACKNOWLEDGED decision can be deferred",
                ));
            }
            let policy = policy_lock(tx, &project_id, &decision.policy.scope_id).await?;
            let now = db_now(tx).await?;
            if revisit_at <= now || revisit_at > now + chrono::Duration::days(366) {
                return Err(err(
                    "DECISION_INVALID",
                    "explicit future revisit time within one year required",
                ));
            }
            decision.state = DecisionState::Deferred;
            decision.revisit_at = Some(revisit_at);
            decision.resolution_reason = Some(reason);
            decision.updated_at = now;
            decision.revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| err("REVISION_CONFLICT", "decision revision overflow"))?;
            persist(tx, &decision, Some(expected_revision), "decision.deferred").await?;
            json(&DecisionOutcome {
                decision,
                policy,
                created: false,
                policy_changed: false,
            })
        }
        DecisionCommand::Resolve {
            project_id,
            decision_id,
            expected_revision,
            expected_policy_revision,
            reason,
        } => {
            text(&reason)?;
            let mut decision =
                decision_lock(tx, &project_id, &decision_id, expected_revision).await?;
            if decision.state != DecisionState::Acknowledged {
                return Err(err(
                    "DECISION_STATE_CONFLICT",
                    "only ACKNOWLEDGED decision can resolve",
                ));
            }
            let mut policy = policy_lock(tx, &project_id, &decision.policy.scope_id).await?;
            if !policy.paused
                || policy.revision != expected_policy_revision
                || decision.policy.revision != expected_policy_revision
                || json(&policy)? != json(&decision.policy)?
            {
                return Err(err(
                    "REVISION_CONFLICT",
                    "original bound paused policy changed; resolution cannot claim unblocking",
                ));
            }
            policy.paused = false;
            // Reuse catalog policy identity/ancestry/capacity validation and its
            // normal revision/event behavior in this SAME transaction. Boxing
            // breaks the typed catalog/decision helper's async recursion.
            let policy: ResourcePolicy = decode(
                Box::pin(crate::catalog::apply_catalog(
                    tx,
                    CatalogCommand::PutResourcePolicy {
                        policy,
                        expected_revision: Some(expected_policy_revision),
                    },
                    actor,
                ))
                .await?,
            )?;
            let now = db_now(tx).await?;
            decision.state = DecisionState::Resolved;
            decision.resolved_by = Some(actor.into());
            decision.resolved_at = Some(now);
            decision.updated_at = now;
            decision.resolution_reason = Some(reason);
            decision.revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| err("REVISION_CONFLICT", "decision revision overflow"))?;
            persist(tx, &decision, Some(expected_revision), "decision.resolved").await?;
            json(&DecisionOutcome {
                decision,
                policy,
                created: false,
                policy_changed: true,
            })
        }
    }
}
