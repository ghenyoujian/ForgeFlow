//! Scoped, committed hints for one Worker's dispatch and local settlement loop.
//! Hints never authorize execution or substitute for a confirmed local stop.
use super::*;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerDispatchKind {
    Terminal,
    HandoffWake,
    Cursor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDispatchFact {
    pub schema_version: String,
    pub kind: WorkerDispatchKind,
    pub project_id: String,
    pub worker_id: String,
    pub project_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AttemptState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_sha: Option<String>,
}

impl Store {
    /// One bounded read on the reserved control lane. The original project
    /// cursor advances over unrelated rows without exposing their contents.
    /// Every attempt identity comes from authority columns, never event payload.
    pub async fn worker_dispatch_events(
        &self,
        worker: &str,
        project: &str,
        after: u64,
        limit: u32,
    ) -> Result<Vec<WorkerDispatchFact>> {
        if worker.is_empty() || project.is_empty() || worker.len() > 512 || project.len() > 512 {
            return Err(err(
                "VALIDATION_ERROR",
                "worker and project identities required",
            ));
        }
        let row = sqlx::query(
            "WITH authority AS ( \
                SELECT w.project_id AS registered_project,p.event_seq AS watermark, \
                    (SELECT min(project_seq) FROM events WHERE project_id=$2) AS first_seq \
                FROM workers w JOIN projects p ON p.project_id=$2 WHERE w.worker_id=$1 \
             ), page AS MATERIALIZED ( \
                SELECT e.project_seq,e.object_id,e.object_revision,e.kind FROM events e JOIN authority s \
                    ON s.registered_project=e.project_id \
                WHERE e.project_id=$2 AND e.project_seq>$3 \
                ORDER BY e.project_seq LIMIT $4 \
             ), candidates AS ( \
                SELECT e.project_seq,a.project_id,a.worker_id,a.attempt_id,a.lease_id, \
                    a.generation,a.state,a.task_id,a.task_revision,a.operation_id, \
                    a.data->>'base_sha' AS base_sha, \
                    CASE \
                      WHEN e.kind IN('attempt.execution_returned','attempt.succeeded', \
                          'attempt.stopped','attempt.transitioned','attempt.never_dispatched', \
                          'resource.handoff') \
                        AND e.object_revision=a.revision \
                        AND a.state IN('SUCCEEDED','FAILED','CANCELLED') \
                        AND a.terminal_at IS NOT NULL AND l.revoked_at IS NOT NULL \
                        AND EXISTS(SELECT 1 FROM resource_allocations r \
                            WHERE r.attempt_id=a.attempt_id AND r.dimension='active_slot' \
                                AND r.state='RELEASED') \
                        AND NOT EXISTS(SELECT 1 FROM resource_allocations r \
                            WHERE r.attempt_id=a.attempt_id AND r.state<>'RELEASED') \
                        THEN 'TERMINAL' \
                      WHEN e.kind='attempt.leased' AND a.state IN('LEASED','STARTING') \
                        AND a.terminal_at IS NULL AND l.revoked_at IS NULL \
                        AND l.expires_at>clock_timestamp() AND t.fence_epoch=a.generation \
                        AND EXISTS(SELECT 1 FROM resource_allocations r \
                            WHERE r.attempt_id=a.attempt_id AND r.dimension='active_slot' \
                                AND r.state<>'RELEASED') \
                        THEN 'HANDOFF_WAKE' \
                    END AS fact_kind \
                FROM page e JOIN attempts a ON a.project_id=$2 AND a.worker_id=$1 \
                    AND a.attempt_id=e.object_id \
                JOIN leases l ON l.project_id=a.project_id AND l.attempt_id=a.attempt_id \
                    AND l.lease_id=a.lease_id AND l.generation=a.generation AND l.worker_id=a.worker_id \
                JOIN tasks t ON t.project_id=a.project_id AND t.task_id=a.task_id \
                WHERE e.kind IN('attempt.leased','attempt.execution_returned','attempt.succeeded', \
                    'attempt.stopped','attempt.transitioned','attempt.never_dispatched','resource.handoff') \
             ) SELECT s.registered_project,s.watermark,s.first_seq, \
                COALESCE((SELECT max(project_seq) FROM page),$3) AS scanned_through, \
                COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                    'schema_version','forgeflow.worker_dispatch.v1','kind',fact_kind, \
                    'project_id',project_id,'worker_id',worker_id,'project_seq',project_seq, \
                    'attempt_id',attempt_id,'lease_id',lease_id,'generation',generation, \
                    'state',state,'task_id',task_id,'task_revision',task_revision, \
                    'operation_id',operation_id,'base_sha',base_sha) ORDER BY project_seq) \
                    FROM candidates WHERE fact_kind IS NOT NULL),'[]'::jsonb) AS facts \
             FROM authority s",
        )
        .bind(worker)
        .bind(project)
        .bind(i64v(after)?)
        .bind(i64::from(limit.clamp(1, 512)))
        .fetch_optional(&self.control_pool)
        .await?
        .ok_or_else(|| err("WORKER_SCOPE_DENIED", "registered Worker and exact project required"))?;
        let registered: Option<String> = row.try_get("registered_project")?;
        if registered.as_deref() != Some(project) {
            return Err(err(
                "WORKER_SCOPE_DENIED",
                "Worker is registered for a different project",
            ));
        }
        let watermark = row.try_get::<i64, _>("watermark")? as u64;
        let first = row.try_get::<Option<i64>, _>("first_seq")?;
        if after > watermark
            || first.is_some_and(|first| after.saturating_add(1) < first as u64)
            || (watermark > 0 && first.is_none())
        {
            return Err(err(
                "SNAPSHOT_REQUIRED",
                "dispatch cursor is ahead of authority or outside retained events",
            ));
        }
        let scanned = row.try_get::<i64, _>("scanned_through")? as u64;
        let mut facts: Vec<WorkerDispatchFact> = decode(row.try_get("facts")?)?;
        if scanned > after && facts.last().is_none_or(|fact| fact.project_seq < scanned) {
            facts.push(WorkerDispatchFact {
                schema_version: "forgeflow.worker_dispatch.v1".into(),
                kind: WorkerDispatchKind::Cursor,
                project_id: project.into(),
                worker_id: worker.into(),
                project_seq: scanned,
                attempt_id: None,
                lease_id: None,
                generation: None,
                state: None,
                task_id: None,
                task_revision: None,
                operation_id: None,
                base_sha: None,
            });
        }
        Ok(facts)
    }
}
