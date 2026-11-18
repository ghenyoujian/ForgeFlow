//! Read-only scheduling projections. Every choice must be revalidated by Store::admit.
//! Allocated totals include RESERVED, HELD and QUARANTINED until confirmed release.
use forgeflow_domain::{ResourcePolicy, ResourceVector, TaskCard, TaskPlanningState, Team};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub mod ecp_capability_match;
pub mod planning;
mod service;
pub use service::{
    PumpConfig, PumpError, PumpResult, QueueEntry, StoreHandoffScheduler, preview_task, pump_once,
    pump_once_with_config,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSnapshot {
    pub policy: ResourcePolicy,
    pub allocated: ResourceVector,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueCandidate {
    #[serde(default)]
    pub project_id: String,
    pub task_id: String,
    #[serde(default)]
    pub root_team_id: Option<String>,
    pub priority: i32,
    pub enqueued_at_ms: u64,
    pub enqueue_sequence: u64,
    /// Scope leaves supplied from the authoritative project/team/worker assignment.
    /// Their ancestor closure is recomputed and checked below.
    pub scope_ids: Vec<String>,
    pub worker_scope_id: String,
    pub worker_id: String,
    pub has_open_attempt: bool,
    pub immutable_inputs_valid: bool,
    pub executor_capable: bool,
    pub retry_not_before_ms: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyReceipt {
    #[serde(default)]
    pub project_id: String,
    pub task_id: String,
    pub dependency_id: String,
    pub binding_id: String,
    /// True only after Store/evidence service checked the typed edge and immutable identity.
    pub valid: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveWrite {
    pub project_id: String,
    pub task_id: String,
    pub paths: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FairCursor {
    pub project_index: usize,
    pub remaining_project_turns: u32,
    pub owner_indices: BTreeMap<String, usize>,
    #[serde(default)]
    pub queue_scan_indices: BTreeMap<String, usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerInput {
    pub tasks: Vec<TaskCard>,
    pub teams: Vec<Team>,
    pub scopes: Vec<ScopeSnapshot>,
    pub candidates: Vec<QueueCandidate>,
    pub dependency_receipts: Vec<DependencyReceipt>,
    pub active_writes: Vec<ActiveWrite>,
    pub committed_flows: BTreeMap<String, u64>,
    pub project_weights: BTreeMap<String, u32>,
    pub cursor: FairCursor,
    pub now_ms: u64,
    pub aging_interval_ms: u64,
    pub candidate_window: usize,
    pub maximum_selections: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockReason {
    pub project_id: Option<String>,
    pub task_id: String,
    pub code: String,
    pub scope_id: Option<String>,
    pub dimension: Option<String>,
    pub allocated: Option<u64>,
    pub limit: Option<u64>,
    pub detail: String,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRef {
    pub project_id: String,
    pub task_id: String,
}
fn task_ref(project: &str, task: &str) -> TaskRef {
    TaskRef {
        project_id: project.into(),
        task_id: task.into(),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerDecision {
    pub selected_tasks: Vec<TaskRef>,
    pub blocked: Vec<BlockReason>,
    pub cursor: FairCursor,
    pub scanned: usize,
    pub skipped: usize,
    pub window_exhausted: bool,
}
fn dimensions(r: &ResourceVector) -> [(&'static str, u64); 7] {
    [
        ("active_slot", r.active_slot),
        ("coding_slot", r.coding_slot),
        ("cpu_units", r.cpu_units),
        ("memory_bytes", r.memory_bytes),
        ("build_permit", r.build_permit),
        ("gpu_permit", r.gpu_permit),
        ("provider_inflight", r.provider_inflight),
    ]
}
fn add_vector(a: &mut ResourceVector, b: &ResourceVector) {
    a.active_slot = a.active_slot.saturating_add(b.active_slot);
    a.coding_slot = a.coding_slot.saturating_add(b.coding_slot);
    a.cpu_units = a.cpu_units.saturating_add(b.cpu_units);
    a.memory_bytes = a.memory_bytes.saturating_add(b.memory_bytes);
    a.build_permit = a.build_permit.saturating_add(b.build_permit);
    a.gpu_permit = a.gpu_permit.saturating_add(b.gpu_permit);
    a.provider_inflight = a.provider_inflight.saturating_add(b.provider_inflight);
}
fn path_overlap(a: &str, b: &str) -> bool {
    a == b || (a.ends_with('/') && b.starts_with(a)) || (b.ends_with('/') && a.starts_with(b))
}
fn blocker(id: &str, code: &str, detail: impl Into<String>) -> BlockReason {
    BlockReason {
        project_id: None,
        task_id: id.into(),
        code: code.into(),
        scope_id: None,
        dimension: None,
        allocated: None,
        limit: None,
        detail: detail.into(),
    }
}

/// Check one complete vector without acquiring a partial resource or changing the ledger.
pub fn capacity_blockers(
    task_id: &str,
    request: &ResourceVector,
    scopes: &[ScopeSnapshot],
) -> Vec<BlockReason> {
    let mut result = vec![];
    for scope in scopes {
        if scope.policy.paused {
            let mut b = blocker(
                task_id,
                "SCOPE_PAUSED",
                "new admissions paused by resource policy",
            );
            b.scope_id = Some(scope.policy.scope_id.clone());
            result.push(b);
        }
        for (((dimension, amount), (_, used)), (_, limit)) in dimensions(request)
            .iter()
            .zip(dimensions(&scope.allocated))
            .zip(dimensions(&scope.policy.limits))
        {
            if *amount > 0 && used.checked_add(*amount).is_none_or(|total| total > limit) {
                result.push(BlockReason {
                    project_id: None,
                    task_id: task_id.into(),
                    code: if used > limit {
                        "CAPACITY_DRAINING"
                    } else {
                        "CAPACITY_EXHAUSTED"
                    }
                    .into(),
                    scope_id: Some(scope.policy.scope_id.clone()),
                    dimension: Some((*dimension).into()),
                    allocated: Some(used),
                    limit: Some(limit),
                    detail: format!(
                        "{dimension}: allocated {used}, requested {amount}, desired limit {limit}"
                    ),
                });
            }
        }
    }
    result
}
fn scope_closure(
    task: &TaskCard,
    candidate: &QueueCandidate,
    scopes: &BTreeMap<String, ScopeSnapshot>,
    teams: &BTreeMap<(String, String), Team>,
) -> Result<Vec<String>, BlockReason> {
    let mut ancestors = BTreeSet::new();
    let mut next = Some(task.team_id.clone());
    while let Some(id) = next {
        if !ancestors.insert(id.clone()) {
            return Err(blocker(
                &task.task_id,
                "TEAM_CYCLE",
                "cycle in team parent chain",
            ));
        }
        let Some(team) = teams.get(&(task.project_id.clone(), id)) else {
            return Err(blocker(
                &task.task_id,
                "TEAM_MISSING",
                "team or ancestor missing",
            ));
        };
        if team.paused {
            return Err(blocker(
                &task.task_id,
                "TEAM_PAUSED",
                format!("paused by {}", team.team_id),
            ));
        }
        next = team.parent_team_id.clone();
    }
    let Some(root) = &candidate.root_team_id else {
        return Err(blocker(
            &task.task_id,
            "OWNER_ROOT_UNBOUND",
            "root Owner must bind an explicit root team",
        ));
    };
    if !ancestors.contains(root)
        || !teams
            .get(&(task.project_id.clone(), root.clone()))
            .is_some_and(|team| team.parent_team_id.is_none())
    {
        return Err(blocker(
            &task.task_id,
            "OWNER_TEAM_MISMATCH",
            "execution team must be in the declared root Owner subtree",
        ));
    }
    let mut required = BTreeSet::new();
    for scope in scopes.values() {
        let p = &scope.policy;
        if p.project_id.is_none()
            && p.team_id.is_none()
            && p.worker_id.is_none()
            && p.parent_scope_id.is_none()
        {
            required.insert(p.scope_id.clone());
        }
        if p.project_id.as_deref() == Some(&task.project_id)
            && p.team_id.is_none()
            && p.worker_id.is_none()
        {
            required.insert(p.scope_id.clone());
        }
        if p.project_id.as_deref() == Some(&task.project_id)
            && p.team_id.as_ref().is_some_and(|t| ancestors.contains(t))
        {
            required.insert(p.scope_id.clone());
        }
    }
    if candidate.worker_scope_id.is_empty() {
        return Err(blocker(
            &task.task_id,
            "WORKER_SCOPE_MISSING",
            "target worker must have an authoritative resource scope",
        ));
    }
    required.insert(candidate.worker_scope_id.clone());
    if !scopes
        .get(&candidate.worker_scope_id)
        .is_some_and(|scope| scope.policy.worker_id.as_deref() == Some(&candidate.worker_id))
    {
        return Err(blocker(
            &task.task_id,
            "WORKER_SCOPE_MISMATCH",
            "selected worker scope must belong to the target worker",
        ));
    }
    required.extend(candidate.scope_ids.clone());
    let initial = required.clone();
    for id in initial {
        let mut seen = BTreeSet::new();
        let mut current = Some(id);
        while let Some(id) = current {
            if !seen.insert(id.clone()) {
                return Err(blocker(
                    &task.task_id,
                    "RESOURCE_SCOPE_CYCLE",
                    "resource scope ancestry is cyclic",
                ));
            }
            let Some(s) = scopes.get(&id) else {
                return Err(blocker(
                    &task.task_id,
                    "RESOURCE_SCOPE_MISSING",
                    format!("resource scope {id} absent"),
                ));
            };
            if s.policy
                .project_id
                .as_ref()
                .is_some_and(|p| p != &task.project_id)
            {
                return Err(blocker(
                    &task.task_id,
                    "RESOURCE_SCOPE_PROJECT",
                    "resource scope belongs to another project",
                ));
            }
            required.insert(id);
            current = s.policy.parent_scope_id.clone();
        }
    }
    if !scopes.values().any(|s| {
        s.policy.project_id.is_none()
            && s.policy.team_id.is_none()
            && s.policy.worker_id.is_none()
            && s.policy.parent_scope_id.is_none()
    }) || !scopes.values().any(|s| {
        s.policy.project_id.as_deref() == Some(&task.project_id)
            && s.policy.team_id.is_none()
            && s.policy.worker_id.is_none()
    }) {
        return Err(blocker(
            &task.task_id,
            "RESOURCE_SCOPE_MISSING",
            "global and project scopes required",
        ));
    }
    for team in &ancestors {
        if !scopes.values().any(|s| {
            s.policy.project_id.as_deref() == Some(&task.project_id)
                && s.policy.team_id.as_deref() == Some(team)
        }) {
            return Err(blocker(
                &task.task_id,
                "TEAM_BUDGET_MISSING",
                format!("team {team} lacks capacity policy"),
            ));
        }
    }
    Ok(required.into_iter().collect())
}

/// Weighted project round robin, then Owner rotation, then priority plus bounded aging.
/// Blocked queue heads are skipped within candidate_window. Returned vectors are projections;
/// concurrent activity can invalidate them, so admission must recheck inside its transaction.
pub fn ready_frontier(input: SchedulerInput) -> SchedulerDecision {
    let mut tasks = BTreeMap::new();
    let mut duplicate_tasks = BTreeSet::new();
    let mut projects_for_task = BTreeMap::<String, BTreeSet<String>>::new();
    for task in &input.tasks {
        let key = task_ref(&task.project_id, &task.task_id);
        if tasks.insert(key.clone(), task).is_some() {
            duplicate_tasks.insert(key);
        }
        projects_for_task
            .entry(task.task_id.clone())
            .or_default()
            .insert(task.project_id.clone());
    }
    let mut scopes = input
        .scopes
        .iter()
        .cloned()
        .map(|s| (s.policy.scope_id.clone(), s))
        .collect::<BTreeMap<_, _>>();
    let teams = input
        .teams
        .iter()
        .cloned()
        .map(|t| ((t.project_id.clone(), t.team_id.clone()), t))
        .collect::<BTreeMap<_, _>>();
    let mut queues: BTreeMap<String, BTreeMap<String, Vec<&QueueCandidate>>> = BTreeMap::new();
    let mut blocked = vec![];
    let mut normalized_candidates = Vec::new();
    for original in &input.candidates {
        let mut candidate = original.clone();
        if candidate.project_id.is_empty() {
            if let Some(projects) = projects_for_task
                .get(&candidate.task_id)
                .filter(|projects| projects.len() == 1)
            {
                candidate.project_id = projects.first().unwrap().clone();
            } else {
                blocked.push(blocker(
                    &candidate.task_id,
                    "PROJECT_REFERENCE_REQUIRED",
                    "legacy task reference is ambiguous or missing; supply explicit project_id",
                ));
                continue;
            }
        }
        let key = task_ref(&candidate.project_id, &candidate.task_id);
        let reason = if duplicate_tasks.contains(&key) {
            Some("DUPLICATE_TASK_IDENTITY")
        } else if !tasks.contains_key(&key) {
            Some("TASK_MISSING")
        } else {
            None
        };
        if let Some(code) = reason {
            let mut reason = blocker(
                &candidate.task_id,
                code,
                "candidate must identify one canonical project-scoped task",
            );
            reason.project_id = Some(candidate.project_id);
            blocked.push(reason);
            continue;
        }
        normalized_candidates.push(candidate);
    }
    for c in &normalized_candidates {
        let t = tasks[&task_ref(&c.project_id, &c.task_id)];
        queues
            .entry(t.project_id.clone())
            .or_default()
            .entry(t.owner_id.clone())
            .or_default()
            .push(c);
    }
    for owners in queues.values_mut() {
        for queue in owners.values_mut() {
            queue.sort_by(|a, b| {
                let score = |c: &QueueCandidate| {
                    i64::from(c.priority).saturating_add(if input.aging_interval_ms == 0 {
                        0
                    } else {
                        (input.now_ms.saturating_sub(c.enqueued_at_ms) / input.aging_interval_ms)
                            .min(i64::MAX as u64) as i64
                    })
                };
                score(b)
                    .cmp(&score(a))
                    .then(a.enqueued_at_ms.cmp(&b.enqueued_at_ms))
                    .then(a.enqueue_sequence.cmp(&b.enqueue_sequence))
                    .then(a.task_id.cmp(&b.task_id))
            });
        }
    }
    let projects = queues.keys().cloned().collect::<Vec<_>>();
    let mut cursor = input.cursor.clone();
    let mut selected = vec![];
    let mut examined = BTreeSet::new();
    let mut writes = input.active_writes.clone();
    let mut scanned = 0;
    if projects.is_empty() {
        return SchedulerDecision {
            selected_tasks: selected,
            blocked,
            cursor,
            scanned,
            skipped: 0,
            window_exhausted: false,
        };
    }
    cursor.project_index %= projects.len();
    let mut idle_projects = 0;
    while selected.len() < input.maximum_selections
        && scanned < input.candidate_window
        && idle_projects < projects.len()
    {
        let project = &projects[cursor.project_index];
        let owners = queues[project].keys().cloned().collect::<Vec<_>>();
        let mut owner_index = *cursor.owner_indices.get(project).unwrap_or(&0) % owners.len();
        let mut found = false;
        for _ in 0..owners.len() {
            let owner = &owners[owner_index];
            let queue = &queues[project][owner];
            let scan_key = format!("{}:{project}:{owner}", project.len());
            let start = cursor
                .queue_scan_indices
                .get(&scan_key)
                .copied()
                .unwrap_or(0)
                % queue.len();
            for offset in 0..queue.len() {
                let position = (start + offset) % queue.len();
                let c = queue[position];
                if scanned >= input.candidate_window {
                    break;
                }
                if !examined.insert(task_ref(&c.project_id, &c.task_id)) {
                    continue;
                }
                cursor
                    .queue_scan_indices
                    .insert(scan_key.clone(), (position + 1) % queue.len());
                scanned += 1;
                let t = tasks[&task_ref(&c.project_id, &c.task_id)];
                let mut reasons = vec![];
                if !matches!(t.state, TaskPlanningState::ReadyForAdmission)
                    || input.committed_flows.get(project) != Some(&t.flow_revision)
                {
                    reasons.push(blocker(
                        &t.task_id,
                        "FLOW_NOT_COMMITTED",
                        "task must be ready in current committed Flow",
                    ));
                }
                if c.has_open_attempt {
                    reasons.push(blocker(
                        &t.task_id,
                        "ATTEMPT_OPEN",
                        "allocation retained until confirmed terminal release",
                    ));
                }
                if !c.immutable_inputs_valid {
                    reasons.push(blocker(
                        &t.task_id,
                        "INPUT_DRIFT",
                        "immutable preflight inputs are stale",
                    ));
                }
                if !c.executor_capable {
                    reasons.push(blocker(
                        &t.task_id,
                        "EXECUTOR_CAPABILITY",
                        "executor profile is not qualified for requested effects",
                    ));
                }
                if c.retry_not_before_ms.is_some_and(|at| at > input.now_ms) {
                    reasons.push(blocker(
                        &t.task_id,
                        "RETRY_DELAY",
                        "retry/provider window is not ready",
                    ));
                }
                for dep in &t.dependencies {
                    if !input.dependency_receipts.iter().any(|r| {
                        (r.project_id == t.project_id
                            || (r.project_id.is_empty()
                                && projects_for_task.get(&r.task_id).is_some_and(|projects| {
                                    projects.len() == 1 && projects.contains(&t.project_id)
                                })))
                            && r.task_id == t.task_id
                            && r.dependency_id == *dep
                            && r.valid
                            && !r.binding_id.is_empty()
                    }) {
                        reasons.push(blocker(
                            &t.task_id,
                            "DEPENDENCY_EVIDENCE",
                            format!("{dep} lacks matching typed-edge evidence"),
                        ));
                    }
                }
                if writes.iter().any(|w| {
                    w.project_id == t.project_id
                        && w.paths
                            .iter()
                            .any(|a| t.write_set.iter().any(|b| path_overlap(a, b)))
                }) {
                    reasons.push(blocker(
                        &t.task_id,
                        "ACTIVE_WRITE_CONFLICT",
                        "an allocated, stopping or quarantined writer intersects this write scope",
                    ));
                }
                let closure = scope_closure(t, c, &scopes, &teams);
                match &closure {
                    Ok(ids) => {
                        let selected_scopes =
                            ids.iter().map(|id| scopes[id].clone()).collect::<Vec<_>>();
                        reasons.extend(capacity_blockers(
                            &t.task_id,
                            &t.resource_request,
                            &selected_scopes,
                        ));
                    }
                    Err(b) => reasons.push(b.clone()),
                }
                if reasons.is_empty() {
                    for id in closure.unwrap() {
                        add_vector(
                            &mut scopes.get_mut(&id).unwrap().allocated,
                            &t.resource_request,
                        )
                    }
                    selected.push(task_ref(&t.project_id, &t.task_id));
                    writes.push(ActiveWrite {
                        project_id: t.project_id.clone(),
                        task_id: t.task_id.clone(),
                        paths: t.write_set.clone(),
                    });
                    found = true;
                    break;
                } else {
                    for mut reason in reasons {
                        reason.project_id = Some(t.project_id.clone());
                        blocked.push(reason);
                    }
                }
            }
            if found {
                break;
            }
            owner_index = (owner_index + 1) % owners.len();
        }
        cursor.owner_indices.insert(
            project.clone(),
            (owner_index + usize::from(found)) % owners.len(),
        );
        if found {
            idle_projects = 0;
            if cursor.remaining_project_turns == 0 {
                cursor.remaining_project_turns = input
                    .project_weights
                    .get(project)
                    .copied()
                    .unwrap_or(1)
                    .max(1)
            }
            cursor.remaining_project_turns -= 1;
        } else {
            idle_projects += 1;
            cursor.remaining_project_turns = 0;
        }
        if cursor.remaining_project_turns == 0 {
            cursor.project_index = (cursor.project_index + 1) % projects.len();
        }
    }
    let skipped = examined.len().saturating_sub(selected.len());
    let window_exhausted =
        scanned >= input.candidate_window && examined.len() < input.candidates.len();
    SchedulerDecision {
        selected_tasks: selected,
        blocked,
        cursor,
        scanned,
        skipped,
        window_exhausted,
    }
}
