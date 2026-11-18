use chrono::{TimeZone, Utc};
use forgeflow_domain::ResourceVector;
use forgeflow_scheduler::planning::*;
use std::collections::BTreeSet;
fn task(id: &str, dependencies: &[&str], hours: Option<f64>) -> PlanningTask {
    PlanningTask {
        task_id: id.into(),
        owner_id: "owner".into(),
        team_id: "team".into(),
        priority: 0,
        dependencies: dependencies.iter().map(|s| s.to_string()).collect(),
        duration_hours: hours,
        duration_source: "INDEPENDENT_TEST_ESTIMATE".into(),
        resource_request: ResourceVector {
            active_slot: 1,
            cpu_units: 1,
            ..Default::default()
        },
        scope_ids: vec!["scope".into()],
    }
}
fn scope(capacity: u64) -> PlanningScope {
    PlanningScope {
        scope_id: "scope".into(),
        limits: ResourceVector {
            active_slot: capacity,
            cpu_units: capacity,
            ..Default::default()
        },
        allocated: Default::default(),
        paused: false,
    }
}
fn window(start: i64, end: i64) -> AvailabilityWindow {
    AvailabilityWindow {
        start_at: Utc.timestamp_opt(start * 3600, 0).unwrap(),
        end_at: Utc.timestamp_opt(end * 3600, 0).unwrap(),
    }
}
/// Independent returned-interval oracle; it does not reproduce the forecast algorithm.
fn verify(
    plan: &Forecast,
    inputs: &[PlanningTask],
    capacity: usize,
    windows: &[AvailabilityWindow],
) {
    for row in &plan.rows {
        assert!(
            windows
                .iter()
                .any(|w| w.start_at <= row.planned_start && row.planned_end <= w.end_at)
        );
        assert_eq!(
            (row.planned_end - row.planned_start).num_seconds(),
            (row.duration_hours * 3600.0) as i64
        );
        for predecessor in &inputs
            .iter()
            .find(|t| t.task_id == row.task_id)
            .unwrap()
            .dependencies
        {
            assert!(
                plan.rows
                    .iter()
                    .find(|t| &t.task_id == predecessor)
                    .unwrap()
                    .planned_end
                    <= row.planned_start
            );
        }
    }
    for time in plan
        .rows
        .iter()
        .flat_map(|r| [r.planned_start, r.planned_end])
    {
        let active = plan
            .rows
            .iter()
            .filter(|r| r.planned_start <= time && time < r.planned_end)
            .count();
        assert!(active <= capacity, "resource oversubscription at {time}");
    }
}
#[test]
fn independent_intervals_prove_parallelism_critical_path_and_calendar_leveling() {
    let tasks = vec![
        task("a", &[], Some(4.0)),
        task("b", &["a"], Some(2.0)),
        task("c", &[], Some(4.0)),
    ];
    let windows = vec![window(0, 12)];
    let plan = forecast(&tasks, &[scope(2)], &BTreeSet::new(), windows.clone()).unwrap();
    assert!(plan.complete);
    verify(&plan, &tasks, 2, &windows);
    assert_eq!(plan.dependency_lower_bound_hours, Some(6.0));
    assert!(
        plan.rows
            .iter()
            .find(|r| r.task_id == "a")
            .unwrap()
            .critical_dependency_path
    );
    assert!(
        !plan
            .rows
            .iter()
            .find(|r| r.task_id == "c")
            .unwrap()
            .critical_dependency_path
    );
    assert_eq!(
        plan.rows
            .iter()
            .find(|r| r.task_id == "c")
            .unwrap()
            .planned_start,
        windows[0].start_at
    );
    let windows = vec![window(0, 4), window(5, 12)];
    let plan = forecast(&tasks, &[scope(1)], &BTreeSet::new(), windows.clone()).unwrap();
    assert!(plan.complete);
    verify(&plan, &tasks, 1, &windows);
    assert_eq!(
        plan.rows
            .iter()
            .find(|r| r.task_id == "b")
            .unwrap()
            .planned_start,
        windows[1].start_at
    );
}
#[test]
fn unknown_duration_cycles_and_retained_allocations_cannot_invent_dates() {
    let tasks = vec![task("a", &[], None), task("b", &["a"], Some(1.0))];
    let plan = forecast(&tasks, &[scope(1)], &BTreeSet::new(), vec![window(0, 8)]).unwrap();
    assert!(!plan.complete);
    assert!(plan.rows.is_empty());
    assert_eq!(plan.dependency_lower_bound_hours, None);
    let mut occupied = scope(1);
    occupied.allocated.active_slot = 1;
    let plan = forecast(
        &[task("a", &[], Some(1.0))],
        &[occupied],
        &BTreeSet::new(),
        vec![window(0, 8)],
    )
    .unwrap();
    assert!(plan.rows.is_empty());
    assert_eq!(plan.blocked[0].code, "NO_FEASIBLE_WINDOW");
    assert!(
        forecast(
            &[task("a", &["b"], Some(1.0)), task("b", &["a"], Some(1.0))],
            &[scope(1)],
            &BTreeSet::new(),
            vec![window(0, 8)]
        )
        .is_err()
    );
}
#[test]
fn ten_thousand_task_plan_is_complete_and_preserves_peak_capacity() {
    let tasks: Vec<_> = (0..10000)
        .map(|i| task(&format!("t{i:05}"), &[], Some(1.0)))
        .collect();
    let windows = vec![window(0, 100)];
    let start = std::time::Instant::now();
    let plan = forecast(&tasks, &[scope(128)], &BTreeSet::new(), windows.clone()).unwrap();
    assert!(plan.complete);
    assert_eq!(plan.rows.len(), 10000);
    // Independent per-hour workload histogram, including all10000 jobs.
    let mut counts = std::collections::BTreeMap::new();
    for row in &plan.rows {
        *counts
            .entry(row.planned_start.timestamp() / 3600)
            .or_insert(0usize) += 1;
    }
    assert!(counts.values().all(|n| *n <= 128));
    assert_eq!(counts.values().sum::<usize>(), 10000);
    eprintln!("planning10000 elapsed_ms={}", start.elapsed().as_millis());
}

#[test]
fn nonmonotonic_placement_preserves_every_resource_dimension() {
    // Priority and dependency chains interleave long/short jobs. Later jobs can
    // be placed before already forecast jobs; an event sweep is an independent oracle.
    for seed in 0..16 {
        let mut inputs = Vec::new();
        for i in 0..96 {
            let mut t = task(
                &format!("t{i:03}"),
                &[],
                Some(((i * 17 + seed * 13) % 9 + 1) as f64 / 4.0),
            );
            t.priority = ((i * 7 + seed) % 5) as i32;
            if i > 4 && i % 3 == 0 {
                t.dependencies.push(format!("t{:03}", i - 4));
            }
            t.resource_request.memory_bytes = ((i + seed) % 3 + 1) as u64;
            t.resource_request.provider_inflight = ((i + seed) % 2) as u64;
            t.resource_request.coding_slot = u64::from(i % 4 == 0);
            t.resource_request.build_permit = u64::from(i % 5 == 0);
            t.resource_request.gpu_permit = u64::from(i % 9 == 0);
            inputs.push(t);
        }
        let mut policy = scope(4);
        policy.limits.memory_bytes = 7;
        policy.allocated.memory_bytes = 1;
        policy.limits.provider_inflight = 2;
        policy.limits.coding_slot = 2;
        policy.limits.build_permit = 1;
        policy.limits.gpu_permit = 1;
        let windows = vec![window(0, 8), window(9, 48), window(49, 96)];
        let plan = forecast(
            &inputs,
            &[policy.clone()],
            &BTreeSet::new(),
            windows.clone(),
        )
        .unwrap();
        assert!(plan.complete);
        verify(&plan, &inputs, 4, &windows);
        let by_id: std::collections::BTreeMap<_, _> =
            inputs.iter().map(|t| (&t.task_id, t)).collect();
        let mut events = Vec::new();
        for row in &plan.rows {
            events.push((row.planned_start, 1i64, row.task_id.as_str()));
            events.push((row.planned_end, -1i64, row.task_id.as_str()));
        }
        events.sort();
        let baseline = policy.allocated.dimensions().map(|(_, n)| i128::from(n));
        let mut used = baseline;
        for (_, sign, id) in events {
            let request = by_id[&id.to_owned()].resource_request.dimensions();
            for (i, (_, amount)) in request.into_iter().enumerate() {
                used[i] += i128::from(amount) * i128::from(sign);
            }
            for (i, (_, limit)) in policy.limits.dimensions().into_iter().enumerate() {
                assert!(used[i] >= 0 && used[i] <= i128::from(limit));
            }
        }
        assert_eq!(used, baseline);
    }
}
