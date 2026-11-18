//! Prefix-only logical event archival and snapshot-consistent hot replay.
use crate::*;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectEventArchiveReceipt {
    pub project_id: String,
    pub archived_count: u64,
    pub archived_through_seq: u64,
    pub oldest_retained_seq: Option<u64>,
    pub watermark: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventArchiveReceipt {
    pub retention_seconds: u64,
    pub limit: u32,
    pub cutoff_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub archived_count: u64,
    pub projects: Vec<ProjectEventArchiveReceipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventReplayWindow {
    pub watermark: u64,
    pub oldest_retained_seq: Option<u64>,
    pub events: Vec<DomainEvent>,
    pub expired: bool,
    pub as_of: DateTime<Utc>,
}

fn valid_batch_limit(limit: u32) -> Result<()> {
    if !(1..=1000).contains(&limit) {
        return Err(err(
            "EVENT_RETENTION_INVALID",
            "event batch limit must be in 1..1000",
        ));
    }
    Ok(())
}

impl Store {
    /// Archive at most `limit` events globally in this transaction. The first
    /// recent hot event is a barrier even if later events have older timestamps.
    /// The highest hot sequence is always retained. No original history fields,
    /// project watermark, or replay sequence are changed; no event is deleted.
    pub async fn archive_event_batch(
        &self,
        retention_seconds: u64,
        limit: u32,
    ) -> Result<EventArchiveReceipt> {
        valid_batch_limit(limit)?;
        if !(1..=315_360_000).contains(&retention_seconds) {
            return Err(err(
                "EVENT_RETENTION_INVALID",
                "retention must be in 1..315360000 seconds",
            ));
        }
        let _write_guard = self.write_guard().await?;
        let mut tx = self.pool.begin().await?;
        coordination(&mut tx).await?;
        let clock = sqlx::query("SELECT observed_at,observed_at-($1::bigint*interval '1 second') AS cutoff_at FROM (SELECT clock_timestamp() AS observed_at) clock")
            .bind(i64v(retention_seconds)?).fetch_one(&mut *tx).await?;
        let observed_at: DateTime<Utc> = clock.get("observed_at");
        let cutoff_at: DateTime<Utc> = clock.get("cutoff_at");
        // A barrier computed in sequence order prevents timestamp reordering
        // from creating hot-history holes. Selection orders each project's
        // prefix before applying the GLOBAL limit, preserving that invariant
        // across repeated bounded batches as well.
        let rows = sqlx::query("WITH frontiers AS (SELECT project_id,max(project_seq) AS last_seq,min(project_seq) FILTER(WHERE occurred_at >= $1) AS barrier_seq FROM events WHERE archived_at IS NULL GROUP BY project_id), selected AS (SELECT e.event_id FROM events e JOIN frontiers f USING(project_id) WHERE e.archived_at IS NULL AND e.project_seq<f.last_seq AND (f.barrier_seq IS NULL OR e.project_seq<f.barrier_seq) ORDER BY e.project_id,e.project_seq LIMIT $2) UPDATE events e SET archived_at=$3 FROM selected s WHERE e.event_id=s.event_id AND e.archived_at IS NULL RETURNING e.project_id,e.project_seq")
            .bind(cutoff_at).bind(i64::from(limit)).bind(observed_at).fetch_all(&mut *tx).await?;
        let mut affected: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for row in &rows {
            let project: String = row.get("project_id");
            let sequence = row.get::<i64, _>("project_seq") as u64;
            let entry = affected.entry(project).or_insert((0, 0));
            entry.0 += 1;
            entry.1 = entry.1.max(sequence);
        }
        let mut projects = Vec::with_capacity(affected.len());
        let project_ids: Vec<String> = affected.keys().cloned().collect();
        let boundaries = sqlx::query("SELECT p.project_id,p.event_seq,(SELECT min(e.project_seq) FROM events e WHERE e.project_id=p.project_id AND e.archived_at IS NULL) AS oldest_retained_seq FROM projects p WHERE p.project_id=ANY($1) ORDER BY p.project_id")
            .bind(&project_ids).fetch_all(&mut *tx).await?;
        for row in boundaries {
            let project_id: String = row.get("project_id");
            let (archived_count, archived_through_seq) =
                affected.remove(&project_id).ok_or_else(|| {
                    err(
                        "EVENT_RETENTION_INVALID",
                        "archive receipt project identity mismatch",
                    )
                })?;
            projects.push(ProjectEventArchiveReceipt {
                project_id,
                archived_count,
                archived_through_seq,
                oldest_retained_seq: row
                    .get::<Option<i64>, _>("oldest_retained_seq")
                    .map(|v| v as u64),
                watermark: row.get::<i64, _>("event_seq") as u64,
            });
        }
        tx.commit().await?;
        Ok(EventArchiveReceipt {
            retention_seconds,
            limit,
            cutoff_at,
            observed_at,
            archived_count: rows.len() as u64,
            projects,
        })
    }

    /// Head, retained boundary and replay rows share one READ ONLY REPEATABLE
    /// READ snapshot. Call for initial subscription AND each refill so a live
    /// consumer cannot silently idle across an archive or restored-head change.
    /// `expired` requires the caller to obtain a fresh snapshot/resubscribe.
    /// Existing events() remains the complete historical query.
    pub async fn event_replay_window(
        &self,
        project_id: &str,
        after: u64,
        limit: u32,
    ) -> Result<EventReplayWindow> {
        valid_batch_limit(limit)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT p.event_seq,(SELECT min(e.project_seq) FROM events e WHERE e.project_id=p.project_id AND e.archived_at IS NULL) AS oldest_retained_seq,clock_timestamp() AS as_of FROM projects p WHERE p.project_id=$1")
            .bind(project_id).fetch_optional(&mut *tx).await?
            .ok_or_else(|| err("NOT_FOUND", "project not found"))?;
        let watermark = row.get::<i64, _>("event_seq") as u64;
        let oldest_retained_seq = row
            .get::<Option<i64>, _>("oldest_retained_seq")
            .map(|v| v as u64);
        let expired = after > watermark
            || oldest_retained_seq.is_some_and(|first| after.saturating_add(1) < first)
            || (watermark > 0 && oldest_retained_seq.is_none());
        let mut events = Vec::new();
        if !expired {
            let rows = sqlx::query("SELECT * FROM events WHERE project_id=$1 AND archived_at IS NULL AND project_seq>$2 ORDER BY project_seq LIMIT $3")
                .bind(project_id).bind(i64v(after)?).bind(i64::from(limit)).fetch_all(&mut *tx).await?;
            for row in rows {
                events.push(DomainEvent {
                    event_id: row.try_get("event_id")?,
                    project_id: row.try_get("project_id")?,
                    project_seq: row.try_get::<i64, _>("project_seq")? as u64,
                    object_id: row.try_get("object_id")?,
                    object_revision: row.try_get::<i64, _>("object_revision")? as u64,
                    schema_version: row.try_get("schema_version")?,
                    kind: row.try_get("kind")?,
                    payload: row.try_get("payload")?,
                    occurred_at: row.try_get("occurred_at")?,
                });
            }
        }
        let as_of = row.get("as_of");
        tx.commit().await?;
        Ok(EventReplayWindow {
            watermark,
            oldest_retained_seq,
            events,
            expired,
            as_of,
        })
    }
}
