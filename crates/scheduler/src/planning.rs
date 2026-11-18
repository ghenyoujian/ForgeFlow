//! Deterministic, non-preemptive resource leveling. Forecasts never grant execution rights.
use chrono::{DateTime, Utc};
use forgeflow_domain::ResourceVector;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityWindow {
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningTask {
    pub task_id: String,
    pub owner_id: String,
    pub team_id: String,
    pub priority: i32,
    pub dependencies: Vec<String>,
    pub duration_hours: Option<f64>,
    pub duration_source: String,
    pub resource_request: ResourceVector,
    pub scope_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningScope {
    pub scope_id: String,
    pub limits: ResourceVector,
    pub allocated: ResourceVector,
    pub paused: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastTask {
    pub task_id: String,
    pub owner_id: String,
    pub team_id: String,
    pub planned_start: DateTime<Utc>,
    pub planned_end: DateTime<Utc>,
    pub duration_hours: f64,
    pub duration_source: String,
    pub critical_dependency_path: bool,
    pub dependency_slack_hours: f64,
    pub resource_or_calendar_wait_hours: f64,
    pub scope_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanningFinding {
    pub task_id: String,
    pub code: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forecast {
    pub algorithm: String,
    pub rows: Vec<ForecastTask>,
    pub blocked: Vec<PlanningFinding>,
    pub dependency_lower_bound_hours: Option<f64>,
    pub complete: bool,
    pub assumptions: Vec<String>,
}
#[derive(Default)]
struct Timeline {
    events: BTreeMap<i64, [i128; 7]>,
    // Relative event totals at the last queried instant. Insertions maintain it.
    cursor: Option<(i64, [i128; 7])>,
    // Conservative hints apply only to identical demand and duration, never other jobs.
    hints: BTreeMap<([u64; 7], i64), i64>,
}
fn vector(v: &ResourceVector) -> [u64; 7] {
    v.dimensions().map(|(_, value)| value)
}
fn conflict(
    timeline: &mut Timeline,
    scope: &PlanningScope,
    request: [u64; 7],
    start: i64,
    end: i64,
) -> Option<i64> {
    let (bound, mut relative) = match timeline.cursor {
        Some((time, usage)) if time <= start => (std::ops::Bound::Excluded(time), usage),
        _ => (std::ops::Bound::Unbounded, [0; 7]),
    };
    for (_, delta) in timeline
        .events
        .range((bound, std::ops::Bound::Included(start)))
    {
        for index in 0..7 {
            relative[index] += delta[index];
        }
    }
    timeline.cursor = Some((start, relative));
    let allocated = vector(&scope.allocated);
    let mut used = std::array::from_fn(|i| i128::from(allocated[i]) + relative[i]);
    let limits = vector(&scope.limits);
    let exceeded = |used: &[i128; 7]| {
        (0..7).any(|i| request[i] > 0 && used[i] + i128::from(request[i]) > i128::from(limits[i]))
    };
    if exceeded(&used) {
        return Some(
            timeline
                .events
                .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
                .next()
                .map(|(time, _)| *time)
                .unwrap_or(i64::MAX),
        );
    }
    for (time, delta) in timeline.events.range((
        std::ops::Bound::Excluded(start),
        std::ops::Bound::Excluded(end),
    )) {
        for index in 0..7 {
            used[index] += delta[index];
        }
        if exceeded(&used) {
            return Some(
                timeline
                    .events
                    .range((std::ops::Bound::Excluded(*time), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(time, _)| *time)
                    .unwrap_or(i64::MAX),
            );
        }
    }
    None
}

/// Prioritized serial schedule generation with parallel jobs whenever all vectors fit.
/// Explicit UTC windows represent working availability; a job must fit a whole window.
pub fn forecast(
    tasks: &[PlanningTask],
    scopes: &[PlanningScope],
    completed: &BTreeSet<String>,
    mut windows: Vec<AvailabilityWindow>,
) -> Result<Forecast, String> {
    if tasks.len() > 10000 || windows.is_empty() || windows.len() > 256 {
        return Err("planning size/window budget exceeded".into());
    }
    windows.sort_by_key(|window| window.start_at);
    if windows.iter().any(|w| w.end_at <= w.start_at)
        || windows.windows(2).any(|w| w[0].end_at > w[1].start_at)
        || windows.last().unwrap().end_at - windows[0].start_at > chrono::Duration::days(366)
    {
        return Err(
            "availability windows must be positive, nonoverlapping and within366days".into(),
        );
    }
    let origin = windows[0].start_at.timestamp_millis();
    let by_id: BTreeMap<_, _> = tasks.iter().map(|t| (t.task_id.clone(), t)).collect();
    if by_id.len() != tasks.len() {
        return Err("duplicate task identity".into());
    }
    let scopes: BTreeMap<_, _> = scopes.iter().map(|s| (s.scope_id.clone(), s)).collect();
    let mut indegree = BTreeMap::new();
    let mut successors = BTreeMap::<String, Vec<String>>::new();
    let mut invalid = BTreeSet::new();
    let mut blocked = Vec::new();
    for task in tasks {
        if task.dependencies.iter().collect::<BTreeSet<_>>().len() != task.dependencies.len() {
            return Err("duplicate dependency".into());
        }
        let mut count = 0;
        for dependency in &task.dependencies {
            if by_id.contains_key(dependency) {
                count += 1;
                successors
                    .entry(dependency.clone())
                    .or_default()
                    .push(task.task_id.clone());
            } else if !completed.contains(dependency) {
                invalid.insert(task.task_id.clone());
                blocked.push(PlanningFinding {
                    task_id: task.task_id.clone(),
                    code: "MISSING_PREDECESSOR".into(),
                    detail: dependency.clone(),
                });
            }
        }
        indegree.insert(task.task_id.clone(), count);
    }
    let mut ready = BTreeSet::new();
    for task in tasks {
        if indegree[&task.task_id] == 0 {
            ready.insert((-i64::from(task.priority), task.task_id.clone()));
        }
    }
    let mut order = Vec::new();
    while let Some(key) = ready.pop_first() {
        let id = key.1;
        order.push(id.clone());
        for successor in successors.get(&id).into_iter().flatten() {
            let remaining = indegree.get_mut(successor).unwrap();
            *remaining -= 1;
            if *remaining == 0 {
                ready.insert((-i64::from(by_id[successor].priority), successor.clone()));
            }
        }
    }
    if order.len() != tasks.len() {
        return Err("task dependency graph contains a cycle".into());
    }
    let mut earliest = BTreeMap::<String, i64>::new();
    let mut durations = BTreeMap::new();
    for id in &order {
        let task = by_id[id];
        let duration = match task.duration_hours {
            Some(v) if v.is_finite() && v > 0.0 && v <= 1_000_000.0 => {
                (v * 3_600_000.0).ceil() as i64
            }
            _ => {
                invalid.insert(id.clone());
                blocked.push(PlanningFinding {
                    task_id: id.clone(),
                    code: "DURATION_UNKNOWN".into(),
                    detail: "review a duration estimate; effort is not calendar duration".into(),
                });
                continue;
            }
        };
        if invalid.contains(id) || task.dependencies.iter().any(|d| invalid.contains(d)) {
            invalid.insert(id.clone());
            continue;
        }
        let start = task
            .dependencies
            .iter()
            .filter_map(|d| earliest.get(d).zip(durations.get(d)))
            .map(|(a, b)| a + b)
            .max()
            .unwrap_or(0);
        earliest.insert(id.clone(), start);
        durations.insert(id.clone(), duration);
    }
    let lower_bound = earliest
        .iter()
        .map(|(id, start)| start + durations[id])
        .max();
    let mut latest = BTreeMap::new();
    if let Some(finish) = lower_bound {
        for id in order.iter().rev().filter(|id| durations.contains_key(*id)) {
            let end = successors
                .get(id)
                .into_iter()
                .flatten()
                .filter_map(|s| latest.get(s))
                .copied()
                .min()
                .unwrap_or(finish);
            latest.insert(id.clone(), end - durations[id]);
        }
    }
    let mut timelines = BTreeMap::<String, Timeline>::new();
    let mut ends = BTreeMap::new();
    let mut rows = Vec::new();
    for id in &order {
        let task = by_id[id];
        if invalid.contains(id)
            || task
                .dependencies
                .iter()
                .any(|d| by_id.contains_key(d) && !ends.contains_key(d))
        {
            if !blocked.iter().any(|b| &b.task_id == id) {
                blocked.push(PlanningFinding {
                    task_id: id.clone(),
                    code: "PREDECESSOR_UNSCHEDULED".into(),
                    detail: "upstream estimate or allocation unavailable".into(),
                });
            }
            continue;
        }
        let demand = vector(&task.resource_request);
        if demand[0] == 0
            || task.scope_ids.is_empty()
            || task
                .scope_ids
                .iter()
                .any(|s| !scopes.contains_key(s) || scopes[s].paused)
        {
            blocked.push(PlanningFinding {
                task_id: id.clone(),
                code: "RESOURCE_SCOPE_UNQUALIFIED".into(),
                detail: "active reservation and every applicable unpaused policy required".into(),
            });
            continue;
        }
        let duration = durations[id];
        let dependency_start = task
            .dependencies
            .iter()
            .filter_map(|d| ends.get(d))
            .copied()
            .max()
            .unwrap_or(origin);
        let mut candidate = dependency_start;
        for scope in &task.scope_ids {
            if let Some(hint) = timelines
                .get(scope)
                .and_then(|t| t.hints.get(&(demand, duration)))
            {
                candidate = candidate.max(*hint);
            }
        }
        let mut assigned = None;
        for window in &windows {
            candidate = candidate.max(window.start_at.timestamp_millis());
            while candidate.saturating_add(duration) <= window.end_at.timestamp_millis() {
                let mut advance = None;
                for scope_id in &task.scope_ids {
                    let timeline = timelines.entry(scope_id.clone()).or_default();
                    if let Some(next) = conflict(
                        timeline,
                        scopes[scope_id],
                        demand,
                        candidate,
                        candidate + duration,
                    ) {
                        timeline.hints.insert((demand, duration), next);
                        advance = Some(advance.map_or(next, |prior: i64| prior.max(next)));
                    }
                }
                if let Some(next) = advance {
                    candidate = next;
                } else {
                    assigned = Some(candidate);
                    break;
                }
            }
            if assigned.is_some() {
                break;
            }
        }
        let Some(start) = assigned else {
            blocked.push(PlanningFinding {
                task_id: id.clone(),
                code: "NO_FEASIBLE_WINDOW".into(),
                detail: "current reserved resources and working windows cannot fit this vector"
                    .into(),
            });
            continue;
        };
        let end = start + duration;
        for scope_id in &task.scope_ids {
            let timeline = timelines.get_mut(scope_id).unwrap();
            for (time, sign) in [(start, 1), (end, -1)] {
                let delta = timeline.events.entry(time).or_insert([0; 7]);
                for i in 0..7 {
                    delta[i] += i128::from(demand[i]) * sign;
                }
                if let Some((cursor, usage)) = &mut timeline.cursor {
                    if time <= *cursor {
                        for i in 0..7 {
                            usage[i] += i128::from(demand[i]) * sign;
                        }
                    }
                }
            }
        }
        ends.insert(id.clone(), end);
        rows.push(ForecastTask {
            task_id: id.clone(),
            owner_id: task.owner_id.clone(),
            team_id: task.team_id.clone(),
            planned_start: DateTime::from_timestamp_millis(start).ok_or("date overflow")?,
            planned_end: DateTime::from_timestamp_millis(end).ok_or("date overflow")?,
            duration_hours: task.duration_hours.unwrap(),
            duration_source: task.duration_source.clone(),
            critical_dependency_path: latest[id] == earliest[id],
            dependency_slack_hours: (latest[id] - earliest[id]) as f64 / 3_600_000.0,
            resource_or_calendar_wait_hours: (start - dependency_start) as f64 / 3_600_000.0,
            scope_ids: task.scope_ids.clone(),
        });
    }
    Ok(Forecast {algorithm:"PRIORITIZED_NON_PREEMPTIVE_RESOURCE_LEVELING_V1".into(),complete:rows.len()==tasks.len(),rows,blocked,
        dependency_lower_bound_hours:if invalid.is_empty(){lower_bound.map(|d| d as f64/3_600_000.0)}else{None},
        assumptions:vec!["Actual held/quarantined allocations remain occupied for the whole planning window".into(),
            "Working calendars are explicit UTC availability intervals; jobs are non-preemptive".into(),
            "Reviewed effort is not converted into elapsed duration automatically".into(),
            "Dependency critical path excludes resource and calendar waits; heuristic is not an optimum proof".into(),
            "Forecast dates grant no lease, write permission, completion or model/OS qualification".into()]})
}
