//! Read-only maintenance projections. These never release custody or change attempts.
use crate::*;
use serde_json::json;

impl Store {
    pub async fn recovery_items(
        &self,
        project: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Page<Value>> {
        let limit = limit.clamp(1, 500);
        let mut rows: Vec<Value> = sqlx::query_scalar(r#"
            WITH facts AS (
              SELECT a.*, p.data->>'name' AS project_name, w.heartbeat_at,
                l.expires_at, l.revoked_at,
                (SELECT count(*) FROM native_model_requests n WHERE n.attempt_id=a.attempt_id AND n.status IN ('ADMITTED','QUARANTINED')) AS native_pending,
                (SELECT count(*) FROM model_request_permit m WHERE m.attempt_id=a.attempt_id AND m.status IN ('ADMITTED','QUARANTINED')) AS gateway_pending,
                (SELECT count(*) FROM resource_allocations r WHERE r.attempt_id=a.attempt_id AND r.state<>'RELEASED') +
                (SELECT count(*) FROM native_child_allocations r WHERE r.attempt_id=a.attempt_id AND r.state<>'RELEASED') AS held_allocations,
                COALESCE((SELECT jsonb_agg(jsonb_build_object(
                  'intent_id',m.intent_id,'state',m.state,'revision',m.revision,
                  'target_ref',m.target_ref,'candidate_sha',m.data->'candidate_sha',
                  'integrated_sha',m.data->'integrated_sha',
                  'commit_decided',m.data#>'{receipt,commit_decided}') ORDER BY m.intent_id)
                  FROM merge_intents m WHERE m.attempt_id=a.attempt_id
                  AND m.state IN ('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED')),'[]'::jsonb) AS merges
              FROM attempts a JOIN projects p USING(project_id)
              LEFT JOIN workers w ON w.worker_id=a.worker_id
              LEFT JOIN leases l ON l.lease_id=a.lease_id
              WHERE ($1::text IS NULL OR a.project_id=$1)
                AND ($2::text IS NULL OR a.attempt_id>$2)
            )
            SELECT jsonb_build_object(
              'project_id',project_id,'project_name',project_name,'task_id',task_id,
              'attempt_id',attempt_id,'state',state,'revision',revision,'generation',generation,
              'worker_id',worker_id,'created_at',created_at,'terminal_at',terminal_at,
              'last_worker_heartbeat_at',heartbeat_at,
              'worker_heartbeat_stale',heartbeat_at IS NULL OR heartbeat_at<statement_timestamp()-interval '120 seconds',
              'heartbeat_stale_after_seconds',120,
              'lease_expires_at',expires_at,'lease_revoked_at',revoked_at,
              'pending_native_model_request_count',native_pending,
              'pending_gateway_model_request_count',gateway_pending,
              'held_allocation_count',held_allocations,'merge_intents',merges,
              'process_status','UNKNOWN',
              'reasons',to_jsonb(array_remove(ARRAY[
                CASE WHEN state='RECOVERY_REQUIRED' THEN 'RECOVERY_REQUIRED' END,
                CASE WHEN state='STOPPING' THEN 'STOP_UNCONFIRMED' END,
                CASE WHEN native_pending+gateway_pending>0 THEN 'MODEL_CUSTODY_PENDING' END,
                CASE WHEN jsonb_array_length(merges)>0 THEN 'INTEGRATION_UNRESOLVED' END,
                CASE WHEN state IN ('SUCCEEDED','FAILED','CANCELLED') AND held_allocations>0 THEN 'TERMINAL_CUSTODY_RETAINED' END,
                CASE WHEN state NOT IN ('SUCCEEDED','FAILED','CANCELLED') AND
                  (heartbeat_at IS NULL OR heartbeat_at<statement_timestamp()-interval '120 seconds') THEN 'WORKER_HEARTBEAT_STALE' END
              ],NULL)))
            FROM facts WHERE state IN ('RECOVERY_REQUIRED','STOPPING')
              OR native_pending+gateway_pending>0 OR jsonb_array_length(merges)>0
              OR (state IN ('SUCCEEDED','FAILED','CANCELLED') AND held_allocations>0)
              OR (state NOT IN ('SUCCEEDED','FAILED','CANCELLED') AND
                (heartbeat_at IS NULL OR heartbeat_at<statement_timestamp()-interval '120 seconds'))
            ORDER BY attempt_id LIMIT $3
        "#).bind(project).bind(after).bind(i64::from(limit)+1).fetch_all(&self.pool).await?;
        let more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next_cursor = if more {
            rows.last()
                .and_then(|row| row["attempt_id"].as_str())
                .map(str::to_owned)
        } else {
            None
        };
        Ok(Page {
            items: rows,
            next_cursor,
        })
    }

    /// A consistent read of everything which must drain before a file/DB snapshot.
    /// Quarantined model requests and retained allocations are blockers even when
    /// their author attempt is already terminal.
    pub async fn backup_readiness(&self) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let projects: Vec<Value> = sqlx::query_scalar(
            "SELECT jsonb_build_object('project_id',project_id,'name',data->>'name','root_path',data->>'root_path','authority_mode',authority_mode,'paused',paused,'archived',archived,'revision',revision) FROM projects ORDER BY project_id"
        ).fetch_all(&mut *tx).await?;
        let unsettled: Vec<Value> = sqlx::query_scalar(
            "SELECT jsonb_build_object('project_id',project_id,'attempt_id',attempt_id,'task_id',task_id,'state',state,'revision',revision) FROM attempts WHERE state NOT IN ('SUCCEEDED','FAILED','CANCELLED') ORDER BY project_id,attempt_id"
        ).fetch_all(&mut *tx).await?;
        let counts: Value = sqlx::query_scalar(r#"SELECT jsonb_build_object(
          'pending_native_model_requests',(SELECT count(*) FROM native_model_requests WHERE status IN ('ADMITTED','QUARANTINED')),
          'pending_gateway_model_requests',(SELECT count(*) FROM model_request_permit WHERE status IN ('ADMITTED','QUARANTINED')),
          'held_resource_allocations',(SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED'),
          'held_native_allocations',(SELECT count(*) FROM native_child_allocations WHERE state<>'RELEASED'),
          'held_native_lifecycles',(SELECT count(*) FROM native_child_lifecycles WHERE state<>'RELEASED'),
          'unresolved_merge_intents',(SELECT count(*) FROM merge_intents WHERE state IN ('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED'))
        )"#).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(json!({"projects":projects,"unsettled_attempts":unsettled,"custody":counts}))
    }
}
