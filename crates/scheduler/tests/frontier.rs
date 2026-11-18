use forgeflow_domain::*;
use forgeflow_scheduler::*;
use std::collections::{BTreeMap, BTreeSet};
fn ids(decision: &SchedulerDecision) -> Vec<String> {
    decision
        .selected_tasks
        .iter()
        .map(|task| task.task_id.clone())
        .collect()
}
fn vector(active: u64) -> ResourceVector {
    ResourceVector {
        active_slot: active,
        coding_slot: active,
        cpu_units: active,
        memory_bytes: active * 100,
        build_permit: 0,
        gpu_permit: 0,
        provider_inflight: 0,
    }
}
fn scope(
    id: &str,
    parent: Option<&str>,
    project: Option<&str>,
    team: Option<&str>,
    limit: u64,
    allocated: u64,
) -> ScopeSnapshot {
    ScopeSnapshot {
        policy: ResourcePolicy {
            scope_id: id.into(),
            parent_scope_id: parent.map(Into::into),
            project_id: project.map(Into::into),
            team_id: team.map(Into::into),
            worker_id: if id == "worker" {
                Some("worker-01".into())
            } else {
                None
            },
            limits: vector(limit),
            revision: 1,
            paused: false,
        },
        allocated: vector(allocated),
    }
}
fn team(project: &str, id: &str, parent: Option<&str>) -> Team {
    Team {
        project_id: project.into(),
        team_id: id.into(),
        parent_team_id: parent.map(Into::into),
        name: id.into(),
        paused: false,
        revision: 1,
    }
}
fn task(project: &str, id: &str, owner: &str, team_id: &str) -> TaskCard {
    TaskCard {
        project_id: project.into(),
        task_id: id.into(),
        task_revision: 1,
        flow_revision: 1,
        title: id.into(),
        owner_id: owner.into(),
        team_id: team_id.into(),
        requirement_ids: vec![],
        read_set: vec![],
        write_set: vec![format!("src/{id}.rs")],
        dependencies: vec![],
        state: TaskPlanningState::ReadyForAdmission,
        input_digest: "immutable".into(),
        resource_request: vector(1),
        envelope: None,
        revision: 1,
    }
}
fn candidate(id: &str, priority: i32) -> QueueCandidate {
    QueueCandidate {
        project_id: "p".into(),
        task_id: id.into(),
        root_team_id: Some("root".into()),
        priority,
        enqueued_at_ms: 0,
        enqueue_sequence: 0,
        scope_ids: vec![],
        worker_scope_id: "worker".into(),
        worker_id: "worker-01".into(),
        has_open_attempt: false,
        immutable_inputs_valid: true,
        executor_capable: true,
        retry_not_before_ms: None,
    }
}
fn fixture() -> SchedulerInput {
    SchedulerInput {
        tasks: vec![],
        teams: vec![
            team("p", "root", None),
            team("p", "left", Some("root")),
            team("p", "right", Some("root")),
            team("p", "deep", Some("left")),
        ],
        scopes: vec![
            scope("global", None, None, None, 128, 0),
            scope("p", Some("global"), Some("p"), None, 128, 0),
            scope("root", Some("p"), Some("p"), Some("root"), 6, 0),
            scope("left", Some("root"), Some("p"), Some("left"), 4, 0),
            scope("right", Some("root"), Some("p"), Some("right"), 4, 0),
            scope("deep", Some("left"), Some("p"), Some("deep"), 4, 0),
            scope("worker", Some("global"), None, None, 128, 0),
        ],
        candidates: vec![],
        dependency_receipts: vec![],
        active_writes: vec![],
        committed_flows: BTreeMap::from([("p".into(), 1)]),
        project_weights: BTreeMap::new(),
        cursor: FairCursor::default(),
        now_ms: 1_000,
        aging_interval_ms: 1_000,
        candidate_window: 100,
        maximum_selections: 128,
    }
}
fn add(input: &mut SchedulerInput, t: TaskCard, priority: i32) {
    let mut queued = candidate(&t.task_id, priority);
    queued.project_id = t.project_id.clone();
    if t.project_id == "q" && t.team_id == "q-root" {
        queued.root_team_id = Some("q-root".into());
    }
    input.candidates.push(queued);
    input.tasks.push(t);
}
#[test]
fn ancestors_bound_siblings_and_four_level_teams() {
    let mut f = fixture();
    for i in 0..12 {
        add(
            &mut f,
            task(
                "p",
                &format!("t{i:02}"),
                if i % 2 == 0 { "o-left" } else { "o-right" },
                if i % 2 == 0 { "deep" } else { "right" },
            ),
            0,
        )
    }
    let d = ready_frontier(f.clone());
    assert_eq!(ids(&d).len(), 6);
    assert!(
        d.blocked
            .iter()
            .any(|b| b.scope_id.as_deref() == Some("root"))
    );
    assert_eq!(
        ids(&d)
            .iter()
            .filter(|id| id[1..].parse::<usize>().unwrap() % 2 == 0)
            .count(),
        3
    );
    // Independently recompute each ancestor's count from parent pointers, without production closure.
    let selected = ids(&d).into_iter().collect::<BTreeSet<_>>();
    let mut totals = BTreeMap::<String, u64>::new();
    for t in f.tasks.iter().filter(|t| selected.contains(&t.task_id)) {
        let mut id = Some(t.team_id.clone());
        while let Some(current) = id {
            *totals.entry(current.clone()).or_default() += 1;
            id = f
                .teams
                .iter()
                .find(|x| x.team_id == current)
                .unwrap()
                .parent_team_id
                .clone();
        }
    }
    assert!(totals["root"] <= 6);
    assert!(totals["left"] <= 4);
    assert!(totals["deep"] <= 4);
    assert!(totals["right"] <= 4);
}
#[test]
fn blocked_head_skipped_dependency_receipt_is_required() {
    let mut f = fixture();
    let mut head = task("p", "head", "owner", "left");
    head.dependencies.push("producer".into());
    add(&mut f, head, 100);
    add(&mut f, task("p", "tail", "owner", "left"), 0);
    let d = ready_frontier(f.clone());
    assert_eq!(ids(&d), vec!["tail"]);
    assert!(
        d.blocked
            .iter()
            .any(|b| b.task_id == "head" && b.code == "DEPENDENCY_EVIDENCE")
    );
    f.dependency_receipts.push(DependencyReceipt {
        project_id: "p".into(),
        task_id: "head".into(),
        dependency_id: "producer".into(),
        binding_id: "integrated:immutable-sha".into(),
        valid: true,
    });
    assert_eq!(ids(&ready_frontier(f)), vec!["head", "tail"]);
}
#[test]
fn draining_and_quarantine_never_release_implicitly() {
    let mut f = fixture();
    f.scopes
        .iter_mut()
        .find(|s| s.policy.scope_id == "root")
        .unwrap()
        .allocated = vector(7);
    add(&mut f, task("p", "waiting", "owner", "left"), 0);
    let d = ready_frontier(f.clone());
    assert!(ids(&d).is_empty());
    assert!(
        d.blocked
            .iter()
            .any(|b| b.code == "CAPACITY_DRAINING" && b.allocated == Some(7) && b.limit == Some(6))
    );
    f.scopes
        .iter_mut()
        .find(|s| s.policy.scope_id == "root")
        .unwrap()
        .allocated = vector(5);
    assert_eq!(ids(&ready_frontier(f)), vec!["waiting"]);
}
#[test]
fn vector_atomicity_and_overflow_checked_against_simple_reference() {
    let mut s = scope("g", None, None, None, 8, 3);
    s.policy.limits.gpu_permit = 1;
    s.allocated.gpu_permit = 1;
    s.policy.limits.memory_bytes = 1_000;
    s.allocated.memory_bytes = 900;
    let r = ResourceVector {
        active_slot: 1,
        memory_bytes: 200,
        gpu_permit: 1,
        ..Default::default()
    };
    let blockers = capacity_blockers("t", &r, &[s.clone()]);
    assert_eq!(blockers.len(), 2);
    let expected = r
        .dimensions()
        .iter()
        .zip(s.allocated.dimensions())
        .zip(s.policy.limits.dimensions())
        .filter(|(((_, requested), (_, used)), (_, limit))| {
            *requested > 0 && u128::from(*used) + u128::from(*requested) > u128::from(*limit)
        })
        .count();
    assert_eq!(blockers.len(), expected);
    s.policy.limits.active_slot = u64::MAX;
    s.allocated.active_slot = u64::MAX;
    assert!(
        capacity_blockers("t", &r, &[s])
            .iter()
            .any(|b| b.dimension.as_deref() == Some("active_slot"))
    );
}
#[test]
fn project_weight_and_owner_rotation_are_fair_under_continuous_supply() {
    let mut f = fixture();
    f.teams.push(team("q", "q-root", None));
    f.scopes
        .push(scope("q", Some("global"), Some("q"), None, 128, 0));
    f.scopes.push(scope(
        "q-root",
        Some("q"),
        Some("q"),
        Some("q-root"),
        128,
        0,
    ));
    for s in &mut f.scopes {
        if s.policy.scope_id == "root" {
            s.policy.limits = vector(128)
        }
    }
    f.committed_flows.insert("q".into(), 1);
    f.project_weights = BTreeMap::from([("p".into(), 2), ("q".into(), 1)]);
    for i in 0..12 {
        add(
            &mut f,
            task(
                "p",
                &format!("p{i:02}"),
                if i % 2 == 0 { "a" } else { "b" },
                "root",
            ),
            0,
        );
        add(
            &mut f,
            task("q", &format!("q{i:02}"), "q-owner", "q-root"),
            0,
        )
    }
    f.maximum_selections = 9;
    let d = ready_frontier(f);
    assert_eq!(
        ids(&d),
        vec![
            "p00", "p01", "q00", "p02", "p03", "q01", "p04", "p05", "q02"
        ]
    );
}
#[test]
fn aging_allows_old_low_priority_work() {
    let mut f = fixture();
    add(&mut f, task("p", "old", "o", "left"), 0);
    add(&mut f, task("p", "new", "o", "left"), 5);
    f.candidates[1].enqueued_at_ms = 20_000;
    f.now_ms = 20_000;
    f.maximum_selections = 1;
    assert_eq!(ids(&ready_frontier(f)), vec!["old"]);
}
#[test]
fn scan_bound_and_pause_are_explained() {
    let mut f = fixture();
    for i in 0..20 {
        let id = format!("t{i:02}");
        add(&mut f, task("p", &id, "o", "deep"), 0)
    }
    f.teams
        .iter_mut()
        .find(|t| t.team_id == "left")
        .unwrap()
        .paused = true;
    f.candidate_window = 3;
    let d = ready_frontier(f);
    assert!(ids(&d).is_empty());
    assert_eq!(d.scanned, 3);
    assert!(d.window_exhausted);
    assert!(d.blocked.iter().all(|b| b.code == "TEAM_PAUSED"));
}
#[test]
fn active_writer_and_missing_budget_cannot_be_bypassed() {
    let mut f = fixture();
    let t = task("p", "t", "o", "deep");
    f.active_writes.push(ActiveWrite {
        project_id: "p".into(),
        task_id: "quarantined".into(),
        paths: vec!["src/".into()],
    });
    add(&mut f, t, 0);
    assert!(
        ready_frontier(f.clone())
            .blocked
            .iter()
            .any(|b| b.code == "ACTIVE_WRITE_CONFLICT")
    );
    f.active_writes.clear();
    f.scopes.retain(|s| s.policy.scope_id != "left");
    assert!(
        ready_frontier(f)
            .blocked
            .iter()
            .any(|b| b.code == "TEAM_BUDGET_MISSING" || b.code == "RESOURCE_SCOPE_MISSING")
    );
}
#[test]
fn one_hundred_twenty_eight_slot_projection_rejects_next() {
    let mut f = fixture();
    for s in &mut f.scopes {
        s.policy.limits = vector(128)
    }
    for i in 0..129 {
        add(&mut f, task("p", &format!("t{i:03}"), "o", "deep"), 0)
    }
    f.candidate_window = 200;
    f.maximum_selections = 129;
    let d = ready_frontier(f);
    assert_eq!(ids(&d).len(), 128);
    assert!(
        d.blocked
            .iter()
            .any(|b| b.task_id == "t128" && b.dimension.as_deref() == Some("active_slot"))
    );
}

#[test]
fn bounded_scan_resumes_past_a_large_blocked_prefix() {
    let mut f = fixture();
    for i in 0..10 {
        let id = format!("t{i:02}");
        add(&mut f, task("p", &id, "o", "left"), 0);
        f.candidates.last_mut().unwrap().has_open_attempt = i < 9;
    }
    f.candidate_window = 3;
    f.maximum_selections = 1;
    for _ in 0..3 {
        let d = ready_frontier(f.clone());
        assert!(ids(&d).is_empty());
        assert_eq!(d.scanned, 3);
        f.cursor = d.cursor;
    }
    let d = ready_frontier(f);
    assert_eq!(ids(&d), vec!["t09"]);
}

#[test]
fn target_worker_budget_does_not_consume_unrelated_workers_and_cannot_be_spoofed() {
    let mut f = fixture();
    let mut unrelated = scope("worker-other", Some("global"), None, None, 1, 1);
    unrelated.policy.worker_id = Some("worker-02".into());
    f.scopes.push(unrelated);
    add(&mut f, task("p", "t", "o", "deep"), 0);
    assert_eq!(ids(&ready_frontier(f.clone())), vec!["t"]);
    f.candidates[0].worker_id = "worker-02".into();
    assert!(
        ready_frontier(f)
            .blocked
            .iter()
            .any(|b| b.code == "WORKER_SCOPE_MISMATCH")
    );
}

#[test]
fn project_scoped_identical_task_and_team_ids_progress_independently() {
    let mut f = fixture();
    for id in ["root", "left", "deep"] {
        f.teams.push(team(
            "q",
            id,
            match id {
                "root" => None,
                "left" => Some("root"),
                _ => Some("left"),
            },
        ));
    }
    f.scopes.extend([
        scope("q", Some("global"), Some("q"), None, 128, 0),
        scope("q-root", Some("q"), Some("q"), Some("root"), 6, 0),
        scope("q-left", Some("q-root"), Some("q"), Some("left"), 4, 0),
        scope("q-deep", Some("q-left"), Some("q"), Some("deep"), 4, 0),
    ]);
    let mut worker = scope("q-worker", Some("global"), None, None, 128, 0);
    worker.policy.worker_id = Some("worker-02".into());
    f.scopes.push(worker);
    f.committed_flows.insert("q".into(), 1);
    add(&mut f, task("p", "same", "owner", "deep"), 0);
    add(&mut f, task("q", "same", "owner", "deep"), 0);
    f.candidates[1].worker_id = "worker-02".into();
    f.candidates[1].worker_scope_id = "q-worker".into();
    let d = ready_frontier(f.clone());
    assert_eq!(
        d.selected_tasks,
        vec![
            TaskRef {
                project_id: "p".into(),
                task_id: "same".into()
            },
            TaskRef {
                project_id: "q".into(),
                task_id: "same".into()
            }
        ]
    );
    f.teams.push(team("invalid-draft", "root", None));
    let mut bad = task("invalid-draft", "same", "owner", "root");
    bad.state = TaskPlanningState::Planned;
    add(&mut f, bad, 100);
    let d = ready_frontier(f.clone());
    assert_eq!(d.selected_tasks.len(), 2);
    assert!(d.blocked.iter().any(
        |reason| reason.project_id.as_deref() == Some("invalid-draft")
            && reason.code == "FLOW_NOT_COMMITTED"
    ));
    f.candidates[0].project_id.clear();
    let d = ready_frontier(f);
    assert!(
        d.blocked
            .iter()
            .any(|reason| reason.code == "PROJECT_REFERENCE_REQUIRED")
    );
    assert_eq!(
        d.selected_tasks,
        vec![TaskRef {
            project_id: "q".into(),
            task_id: "same".into()
        }]
    );
}

#[test]
fn owner_root_cannot_escape_its_quota_by_using_an_unrelated_team() {
    let mut f = fixture();
    f.teams.push(team("p", "other-root", None));
    f.scopes.push(scope(
        "other-root",
        Some("p"),
        Some("p"),
        Some("other-root"),
        128,
        0,
    ));
    f.scopes
        .iter_mut()
        .find(|scope| scope.policy.scope_id == "root")
        .unwrap()
        .allocated = vector(6);
    add(&mut f, task("p", "escape", "owner", "other-root"), 0);
    let d = ready_frontier(f.clone());
    assert!(d.selected_tasks.is_empty());
    assert!(
        d.blocked
            .iter()
            .any(|reason| reason.code == "OWNER_TEAM_MISMATCH")
    );
    f.candidates[0].root_team_id = None;
    let d = ready_frontier(f);
    assert!(
        d.blocked
            .iter()
            .any(|reason| reason.code == "OWNER_ROOT_UNBOUND")
    );
}

#[test]
fn queue_scoped_tasks_keep_explicit_project_fairness_and_all_allocated_conflicts() {
    let mut full = fixture();
    add(&mut full, task("p", "blocked", "left-owner", "left"), 10);
    add(&mut full, task("p", "ready", "right-owner", "right"), 0);
    full.active_writes.push(ActiveWrite {
        project_id: "p".into(),
        task_id: "not-queued".into(),
        paths: vec!["src/blocked.rs".into()],
    });
    let scoped = full.clone();
    full.tasks
        .extend((0..200).map(|n| task("idle-project", &format!("history-{n}"), "idle", "root")));
    full.tasks
        .push(task("idle-project", "ready", "idle", "root"));
    let full = ready_frontier(full);
    let scoped = ready_frontier(scoped);
    assert_eq!(
        serde_json::to_value(&full).unwrap(),
        serde_json::to_value(&scoped).unwrap()
    );
    assert_eq!(ids(&scoped), vec!["ready"]);
    assert!(
        scoped
            .blocked
            .iter()
            .any(|reason| reason.code == "ACTIVE_WRITE_CONFLICT")
    );
}
