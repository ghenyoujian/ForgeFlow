//! Small MVCC read models for planning. No execution authority or private envelopes.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Default, Deserialize, Serialize)]
pub struct TaskListFilter {
    pub q: Option<String>,
    pub owner: Option<String>,
    pub team: Option<String>,
    pub state: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct TaskCursor {
    value: String,
    id: String,
    revision: i64,
    filter: String,
}

impl Store {
    pub async fn portfolio_overview(&self) -> Result<Vec<Value>> {
        self.workspace_portfolio_overview(None).await
    }
    pub async fn workspace_portfolio_overview(
        &self,
        workspace: Option<&str>,
    ) -> Result<Vec<Value>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query_scalar(r#"SELECT jsonb_build_object(
            'project',p.data,'task_count',(SELECT count(*) FROM tasks t WHERE t.project_id=p.project_id),
            'active_attempts',(SELECT count(*) FROM attempts a WHERE a.project_id=p.project_id AND a.state NOT IN ('SUCCEEDED','FAILED','CANCELLED')),
            'succeeded_attempts',(SELECT count(*) FROM attempts a WHERE a.project_id=p.project_id AND a.state='SUCCEEDED'),
            'evidence_receipts',(SELECT count(*) FROM evidence_receipts e WHERE e.project_id=p.project_id),
            'task_progress',CASE WHEN approved.data IS NULL THEN NULL ELSE jsonb_build_object('scope','current_approved_flow','flow_revision',approved.data->'flow_revision',
                'denominator',jsonb_array_length(approved.data->'tasks'),
                'numerator',(SELECT count(*) FROM jsonb_array_elements(approved.data->'tasks') card WHERE EXISTS(SELECT 1 FROM attempts a WHERE a.project_id=p.project_id AND a.task_id=card->>'task_id' AND a.task_revision=(card->>'task_revision')::bigint AND a.state='SUCCEEDED'))) END,
            'requirement_progress',NULL,'gate_progress',NULL,'qualification','INCONCLUSIVE')
            FROM projects p LEFT JOIN LATERAL(SELECT f.data FROM flow_revisions f WHERE f.project_id=p.project_id AND f.state='COMMITTED' ORDER BY f.flow_revision DESC LIMIT 1) approved ON true
            WHERE ($1::text IS NULL OR EXISTS(SELECT 1 FROM project_workspaces w WHERE w.project_id=p.project_id AND w.workspace_id=$1)) ORDER BY p.project_id"#).bind(workspace).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn planning_context_metadata(&self, project: &str, revision: u64) -> Result<Value> {
        sqlx::query_scalar("SELECT ((CASE WHEN data ? 'value' THEN data->'value' ELSE data END)-'task_specs'-'revision')||jsonb_build_object('task_specs','{}'::jsonb) FROM documents WHERE project_id=$1 AND collection='flow_contexts' AND document_id=$2")
            .bind(project).bind(revision.to_string()).fetch_optional(&self.pool).await?
            .ok_or_else(||err("NOT_FOUND","flow context not found"))
    }
    pub async fn latest_flow_view(&self, project: &str, summary: bool) -> Result<Option<Value>> {
        let projection = if summary {
            "jsonb_build_object('project_id',project_id,'flow_revision',flow_revision,'revision',revision,'state',state,'input_digest',input_digest)"
        } else {
            "data"
        };
        Ok(sqlx::query_scalar(&format!("SELECT {projection} FROM flow_revisions WHERE project_id=$1 ORDER BY flow_revision DESC LIMIT 1")).bind(project).fetch_optional(&self.pool).await?)
    }

    /// Counts and the page use the same snapshot; cursor binds filter and version.
    pub async fn task_page(
        &self,
        project: &str,
        filter: &TaskListFilter,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Value> {
        let sort = filter.sort.as_deref().unwrap_or("task_id");
        let field = match sort {
            "task_id" => "task_id",
            "title" => "COALESCE(data->>'title','')",
            "owner_id" => "owner_id",
            "team_id" => "team_id",
            "state" => "state",
            _ => return Err(err("VALIDATION_ERROR", "unsupported task sort")),
        };
        let order = filter.order.as_deref().unwrap_or("asc");
        let (direction, comparison) = match order {
            "asc" => ("ASC", ">"),
            "desc" => ("DESC", "<"),
            _ => return Err(err("VALIDATION_ERROR", "task order must be asc or desc")),
        };
        if filter.q.as_ref().is_some_and(|q| q.len() > 512) {
            return Err(err("VALIDATION_ERROR", "search exceeds 512 bytes"));
        }
        let identity = forgeflow_planner::sha256(&serde_json::to_vec(&(project, filter))?);
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                .bind(project)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "project not found"))?;
        let after = cursor
            .map(|text| {
                serde_json::from_str::<TaskCursor>(text).map_err(|_| {
                    err(
                        "INVALID_CURSOR",
                        "task cursor must come from the same filtered list",
                    )
                })
            })
            .transpose()?;
        if after.as_ref().is_some_and(|c| c.filter != identity) {
            return Err(err("INVALID_CURSOR", "task cursor filter differs"));
        }
        if after.as_ref().is_some_and(|c| c.revision != revision) {
            return Err(err(
                "SNAPSHOT_CHANGED",
                "task list changed; return to the first page",
            ));
        }
        let predicate = "project_id=$1 AND ($2::text IS NULL OR strpos(lower(task_id||' '||COALESCE(data->>'title','')),lower($2))>0) AND ($3::text IS NULL OR owner_id=$3) AND ($4::text IS NULL OR team_id=$4) AND ($5::text IS NULL OR state=$5)";
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM tasks WHERE {predicate}"))
                .bind(project)
                .bind(&filter.q)
                .bind(&filter.owner)
                .bind(&filter.team)
                .bind(&filter.state)
                .fetch_one(&mut *tx)
                .await?;
        let limit = limit.clamp(1, 500);
        let sql = format!(
            "SELECT data,{field} AS sort_value,task_id FROM tasks WHERE {predicate} AND ($6::text IS NULL OR ({field} COLLATE \"C\", task_id COLLATE \"C\") {comparison} ($6 COLLATE \"C\",$7 COLLATE \"C\")) ORDER BY {field} COLLATE \"C\" {direction}, task_id COLLATE \"C\" {direction} LIMIT $8"
        );
        let mut rows = sqlx::query(&sql)
            .bind(project)
            .bind(&filter.q)
            .bind(&filter.owner)
            .bind(&filter.team)
            .bind(&filter.state)
            .bind(after.as_ref().map(|c| &c.value))
            .bind(after.as_ref().map(|c| &c.id))
            .bind(i64::from(limit) + 1)
            .fetch_all(&mut *tx)
            .await?;
        let more = rows.len() > limit as usize;
        if more {
            rows.pop();
        }
        let next = if more {
            rows.last()
                .map(|row| {
                    serde_json::to_string(&TaskCursor {
                        value: row.get("sort_value"),
                        id: row.get("task_id"),
                        revision,
                        filter: identity.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        let items: Vec<Value> = rows.into_iter().map(|r| r.get("data")).collect();
        let observed = db_now(&mut tx).await?;
        tx.commit().await?;
        Ok(
            json!({"data":items,"total_count":count,"next_cursor":next,"read_model_version":revision,
            "source":"postgres","observed_at":observed,"consistent_project_cursor":true}),
        )
    }

    /// Fixed set queries replace the old per-project snapshot loop.
    pub async fn resource_overview(&self) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let versions: Value = sqlx::query_scalar(
            "SELECT COALESCE(jsonb_object_agg(project_id,event_seq),'{}') FROM projects",
        )
        .fetch_one(&mut *tx)
        .await?;
        let policies: Vec<Value> =
            sqlx::query_scalar("SELECT data FROM resource_scopes ORDER BY scope_id")
                .fetch_all(&mut *tx)
                .await?;
        let usage: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(l) FROM resource_limits l ORDER BY scope_id,dimension",
        )
        .fetch_all(&mut *tx)
        .await?;
        let allocations: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(a) FROM resource_allocations a WHERE state<>'RELEASED' ORDER BY project_id,allocation_id").fetch_all(&mut *tx).await?;
        let native_allocations: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(a) FROM native_child_allocations a WHERE state<>'RELEASED' ORDER BY project_id,resource_allocation_id").fetch_all(&mut *tx).await?;
        let workers: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('worker_id',worker_id,'heartbeat_at',heartbeat_at,'reported_active_attempts',CASE WHEN jsonb_typeof(active_attempt_ids)='array' THEN jsonb_array_length(active_attempt_ids) ELSE NULL END) FROM workers ORDER BY worker_id").fetch_all(&mut *tx).await?;
        let observed = db_now(&mut tx).await?;
        tx.commit().await?;
        let observations: Value = versions
            .as_object()
            .unwrap()
            .keys()
            .map(|p| (p.clone(), json!(observed)))
            .collect();
        Ok(
            json!({"data":{"policies":policies,"usage":usage,"allocations":allocations,"native_allocations":native_allocations,"workers":workers,"allocation_scope":"unreleased"},
            "version_vector":versions,"observation_vector":observations,"source":"postgres","observed_at":observed,
            "read_model_version":null,"next_cursor":null}),
        )
    }

    pub async fn assignment_context(&self, project: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT event_seq FROM projects WHERE project_id=$1")
                .bind(project)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("NOT_FOUND", "project not found"))?;
        let teams: Vec<Value> = sqlx::query_scalar(
            "SELECT data FROM owner_nodes WHERE project_id=$1 ORDER BY owner_id",
        )
        .bind(project)
        .fetch_all(&mut *tx)
        .await?;
        let attempts: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('project_id',project_id,'task_id',task_id,'task_revision',task_revision,'attempt_id',attempt_id,'state',state,'worker_id',worker_id,'generation',generation,'created_at',created_at,'terminal_at',terminal_at) FROM attempts WHERE project_id=$1 ORDER BY created_at,attempt_id")
            .bind(project).fetch_all(&mut *tx).await?;
        let observed = db_now(&mut tx).await?;
        tx.commit().await?;
        Ok(
            json!({"project":{"project_id":project},"revision":revision,"teams":teams,"attempts":attempts,"as_of":observed,"source":"POSTGRESQL_REPEATABLE_READ"}),
        )
    }

    pub async fn planning_overview(&self, project: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT data,event_seq FROM projects WHERE project_id=$1")
            .bind(project)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "project not found"))?;
        let revision: i64 = row.get("event_seq");
        let project_data: Value = row.get("data");
        let flow: Option<Value> = sqlx::query_scalar("SELECT data-'tasks' FROM flow_revisions WHERE project_id=$1 ORDER BY flow_revision DESC LIMIT 1").bind(project).fetch_optional(&mut *tx).await?;
        let statistics: Value = sqlx::query_scalar(r#"
          WITH latest AS (SELECT data FROM flow_revisions WHERE project_id=$1 ORDER BY flow_revision DESC LIMIT 1),
          cards AS (SELECT c FROM latest,jsonb_array_elements(COALESCE(data->'tasks','[]')) c WHERE c->>'state'<>'REMOVED_FROM_PLAN'),
          covered AS (SELECT DISTINCT jsonb_array_elements_text(c->'requirement_ids') AS id FROM cards)
          SELECT jsonb_build_object('task_count',(SELECT count(*) FROM cards),
            'needs_review',(SELECT count(*) FROM cards WHERE c->>'state'='NEEDS_REVIEW'),
            'dependency_count',(SELECT COALESCE(sum(jsonb_array_length(c->'dependencies')),0) FROM cards),
            'requirements',(SELECT count(*) FROM requirements WHERE project_id=$1),
            'covered',(SELECT count(*) FROM requirements r JOIN covered ON covered.id=r.requirement_id WHERE r.project_id=$1),
            'deferred',(SELECT count(*) FROM requirements WHERE project_id=$1 AND NULLIF(data->>'deferred_reason','') IS NOT NULL),
            'uncovered',(SELECT count(*) FROM requirements r WHERE project_id=$1 AND NULLIF(data->>'deferred_reason','') IS NULL AND NOT EXISTS(SELECT 1 FROM covered WHERE id=r.requirement_id)),
            'gaps',COALESCE((SELECT jsonb_agg(g) FROM (SELECT data->>'requirement_id' AS requirement_id,data->>'title' AS title FROM requirements r WHERE project_id=$1 AND NULLIF(data->>'deferred_reason','') IS NULL AND NOT EXISTS(SELECT 1 FROM covered WHERE id=r.requirement_id) ORDER BY requirement_id LIMIT 12) g),'[]'))
        "#).bind(project).fetch_one(&mut *tx).await?;
        let capacity: Value = sqlx::query_scalar(r#"SELECT jsonb_build_object(
          'persistent_contexts',(SELECT count(*) FROM documents WHERE project_id=$1 AND collection='agent_contexts'),
          'active_attempts',(SELECT count(*) FROM attempts WHERE project_id=$1 AND terminal_at IS NULL),
          'recovery_attempts',(SELECT count(*) FROM attempts WHERE project_id=$1 AND state IN ('STOPPING','RECOVERY_REQUIRED')),
          'observed_native_sessions',(SELECT count(DISTINCT (attempt_id,native_session_id)) FROM native_child_lifecycles WHERE project_id=$1),
          'observation_scope','registered_native_lifecycles',
          'active_tiers',jsonb_build_array(1,4,10,32,64),'default_active_tier',32,'context_design_capacity',128)"#)
            .bind(project).fetch_one(&mut *tx).await?;
        let policies: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('scope_id',s.scope_id,'team_id',s.team_id,'worker_id',s.worker_id,'revision',s.revision,'paused',s.paused,'limits',s.data->'limits','usage',COALESCE((SELECT jsonb_object_agg(dimension,allocated) FROM resource_limits l WHERE l.scope_id=s.scope_id),'{}')) FROM resource_scopes s WHERE project_id=$1 OR project_id IS NULL ORDER BY s.scope_id")
            .bind(project).fetch_all(&mut *tx).await?;
        let milestones: Vec<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='milestones' ORDER BY COALESCE(data->>'due_at',data->>'target_date',data->>'target_at',data->>'deadline',''),document_id LIMIT 12").bind(project).fetch_all(&mut *tx).await?;
        let milestone_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM documents WHERE project_id=$1 AND collection='milestones'",
        )
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
        let decisions: Vec<Value> = sqlx::query_scalar("SELECT d.data FROM documents d WHERE d.project_id=$1 AND d.collection='decisions' AND d.data->>'schema_version'=$2 AND d.data->>'state'<>'RESOLVED' AND EXISTS(SELECT 1 FROM documents h WHERE h.project_id=d.project_id AND h.collection='decision_history' AND h.document_id=d.document_id||':'||d.revision::text AND h.data=d.data) ORDER BY d.document_id")
            .bind(project).bind(DECISION_INBOX_SCHEMA).fetch_all(&mut *tx).await?;
        let observed = db_now(&mut tx).await?;
        tx.commit().await?;
        Ok(
            json!({"project":project_data,"flow":flow,"statistics":statistics,"capacity":capacity,"policies":policies,
            "milestones":milestones,"milestone_count":milestone_count,"decisions":decisions,
            "revision":revision,"as_of":observed,"source":"POSTGRESQL_REPEATABLE_READ","execution_rights_granted":false}),
        )
    }
}
