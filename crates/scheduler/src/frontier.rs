//! Queue-scoped, disposable PostgreSQL read projections, never admission authority.
//!
//! Rebuilt on every pump/handoff, including after a missed event or restart. The
//! complete active-project set still supplies the fairness anchor, all active
//! write locks and resource accounting. Only unrelated immutable payloads and
//! historical Attempt results are excluded from the scheduling read set.
use super::{ActiveWrite, PumpError, QueueEntry};
use forgeflow_domain::{AttemptState, FlowRevision, TaskCard};
use serde_json::Value;
use sqlx::{Executor, Postgres, Row};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const QUEUED_SQL: &str = "SELECT project_id,data || jsonb_build_object('revision',revision) AS data FROM documents WHERE project_id=ANY($1::text[]) AND collection='queue_entries' AND data->>'status'='QUEUED' ORDER BY project_id,document_id";
pub(super) const TASKS_SQL: &str =
    "SELECT data FROM tasks WHERE project_id=$1 AND task_id=ANY($2::text[]) ORDER BY task_id";
// Store creates these immutable identities and data from the same Attempt;
// persist_attempt only changes state/revision/result, never task_revision.
// Read the authority columns so historical result TOAST is not decompressed.
pub(super) const ATTEMPTS_SQL: &str = "SELECT jsonb_build_object('task_id',task_id,'task_revision',task_revision,'state',state) FROM attempts WHERE project_id=$1 AND task_id=ANY($2::text[]) ORDER BY created_at,attempt_id";
pub(super) const ACTIVE_WRITES_SQL: &str = "SELECT jsonb_build_object('project_id',project_id,'task_id',envelope->'task_id','paths',envelope->'write_set') FROM attempts WHERE project_id=ANY($1::text[]) AND terminal_at IS NULL ORDER BY project_id,attempt_id";
pub(super) const FLOWS_SQL: &str = "SELECT (SELECT max(flow_revision) FROM flow_revisions WHERE project_id=$1 AND state='COMMITTED') AS latest_committed,COALESCE((SELECT jsonb_agg(data ORDER BY flow_revision) FROM flow_revisions WHERE project_id=$1 AND state='COMMITTED' AND flow_revision=ANY($2::bigint[])),'[]'::jsonb) AS flows";

#[derive(Debug, serde::Deserialize)]
pub(super) struct AttemptProjection {
    pub task_id: String,
    pub task_revision: u64,
    pub state: AttemptState,
}

pub(super) async fn queued<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    projects: &[String],
) -> Result<BTreeMap<String, Vec<(QueueEntry, u64)>>, PumpError> {
    let rows = sqlx::query(QUEUED_SQL)
        .bind(projects)
        .fetch_all(executor)
        .await?;
    let mut result = BTreeMap::<String, Vec<(QueueEntry, u64)>>::new();
    for row in rows {
        let mut value: Value = row.try_get("data")?;
        let revision = value
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| PumpError::Invalid("queue revision missing".into()))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("revision");
        }
        result
            .entry(row.try_get("project_id")?)
            .or_default()
            .push((serde_json::from_value(value)?, revision));
    }
    Ok(result)
}

pub(super) fn task_ids(queued: &[(QueueEntry, u64)]) -> Vec<String> {
    queued
        .iter()
        .map(|(entry, _)| entry.task_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) async fn tasks<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    project: &str,
    task_ids: &[String],
) -> Result<Vec<TaskCard>, PumpError> {
    let rows: Vec<Value> = sqlx::query_scalar(TASKS_SQL)
        .bind(project)
        .bind(task_ids)
        .fetch_all(executor)
        .await?;
    rows.into_iter()
        .map(|value| serde_json::from_value(value).map_err(PumpError::from))
        .collect()
}

pub(super) async fn attempts<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    project: &str,
    task_ids: &[String],
) -> Result<Vec<AttemptProjection>, PumpError> {
    let rows: Vec<Value> = sqlx::query_scalar(ATTEMPTS_SQL)
        .bind(project)
        .bind(task_ids)
        .fetch_all(executor)
        .await?;
    rows.into_iter()
        .map(|value| serde_json::from_value(value).map_err(PumpError::from))
        .collect()
}

pub(super) async fn active_writes<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    projects: &[String],
) -> Result<Vec<ActiveWrite>, PumpError> {
    let rows: Vec<Value> = sqlx::query_scalar(ACTIVE_WRITES_SQL)
        .bind(projects)
        .fetch_all(executor)
        .await?;
    rows.into_iter()
        .map(|value| serde_json::from_value(value).map_err(PumpError::from))
        .collect()
}

pub(super) async fn flows<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    project: &str,
    tasks: &[TaskCard],
) -> Result<(Option<u64>, Vec<FlowRevision>), PumpError> {
    let revisions = tasks
        .iter()
        .map(|task| {
            i64::try_from(task.flow_revision)
                .map_err(|_| PumpError::Invalid("Flow revision exceeds PostgreSQL bigint".into()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    let row = sqlx::query(FLOWS_SQL)
        .bind(project)
        .bind(revisions)
        .fetch_one(executor)
        .await?;
    let latest = row
        .try_get::<Option<i64>, _>("latest_committed")?
        .map(|revision| {
            u64::try_from(revision)
                .map_err(|_| PumpError::Invalid("Flow revision precedes zero".into()))
        })
        .transpose()?;
    Ok((latest, serde_json::from_value(row.try_get("flows")?)?))
}
