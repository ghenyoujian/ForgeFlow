//! Matched fixture adapter into the actual production compiler. This does not
//! copy its private DAG algorithm or claim DAG-only timing equivalence.
use forgeflow_domain::TaskPlanningState;
use forgeflow_planner::{
    DependencyKind, DependencySpec, DraftRequest, RequirementFormat, canonical_task_input_digest,
    compile, normalize_requirements, rules_based_draft,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    task_id: String,
    dependencies: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: String,
    case_id: String,
    seed: u64,
    nodes: Vec<Node>,
    samples: u32,
}
fn run(request: Request) -> Result<Value, String> {
    if request.schema_version != "forgeflow.matched-dag.v1"
        || request.nodes.len() > 4096
        || request.samples == 0
        || request.samples > 128
    {
        return Err("bounded matched DAG v1 required".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    if request.nodes.iter().any(|n| {
        n.task_id.is_empty()
            || n.task_id.len() > 128
            || !ids.insert(n.task_id.clone())
            || n.dependencies.len() > 4096
    }) {
        return Err("unique bounded task IDs and dependencies required".into());
    }
    // Setup is untimed. Additional semantic scaffolding is reported explicitly.
    let text = (0..request.nodes.len().max(1))
        .map(|n| format!("- Preserve matched graph task {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = normalize_requirements("matched-spec.md", &text, RequirementFormat::Markdown)
        .map_err(|e| e.to_string())?;
    let mut draft = rules_based_draft(DraftRequest {
        project_id: "matched".into(),
        flow_revision: 1,
        source,
        owner_id: "owner".into(),
        team_id: "team".into(),
        write_set: vec![],
        execution_profile: "MATCHED_DAG_NO_EXECUTION".into(),
        verification_plan: "matched-no-business-gate".into(),
    })
    .map_err(|e| e.to_string())?;
    draft.context.owners[0].root_team_id = Some("team".into());
    draft.context.owners[0].include = vec!["outputs/".into()];
    if request.nodes.is_empty() {
        draft.flow.tasks.clear();
        draft.context.task_specs.clear();
    }
    let old_specs = std::mem::take(&mut draft.context.task_specs);
    for (node, task) in request.nodes.iter().zip(draft.flow.tasks.iter_mut()) {
        let mut spec = old_specs
            .get(&task.task_id)
            .ok_or("generated task spec missing")?
            .clone();
        task.task_id = node.task_id.clone();
        task.dependencies = node.dependencies.clone();
        task.write_set = vec![];
        task.state = TaskPlanningState::Planned;
        spec.verification_case_count = 2;
        spec.dependency_refs = node
            .dependencies
            .iter()
            .map(|dependency| DependencySpec {
                task_id: dependency.clone(),
                project_id: "matched".into(),
                kind: DependencyKind::Integrated,
                binding_id: format!("{dependency}:integrated"),
            })
            .collect();
        task.input_digest = canonical_task_input_digest(task, &spec);
        draft.context.task_specs.insert(task.task_id.clone(), spec);
    }
    let mut samples = Vec::new();
    let mut semantic_extras = std::collections::BTreeSet::new();
    for _ in 0..request.samples {
        let began = std::time::Instant::now();
        let report = compile(&draft.flow, &draft.context);
        let elapsed_ns = began.elapsed().as_nanos();
        let dag_rules = report
            .findings
            .iter()
            .filter(|finding| {
                ["DEPENDENCY_CYCLE", "DANGLING_DEPENDENCY"].contains(&finding.rule_id.as_str())
            })
            .map(|finding| finding.rule_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let duplicate_dependency = report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "DUPLICATE_DEPENDENCY");
        for finding in &report.findings {
            if !dag_rules.contains(&finding.rule_id) {
                semantic_extras.insert(finding.rule_id.clone());
            }
        }
        samples.push(json!({"accepted_common_dag":dag_rules.is_empty(),"dag_rules":dag_rules,
            "duplicate_dependency_rejected":duplicate_dependency,"full_compile_passed":report.passed,
            "full_compile_elapsed_ns":elapsed_ns,"topological_order":report.topological_order}));
    }
    Ok(
        json!({"schema_version":"forgeflow.matched-dag-result.v1","case_id":request.case_id,"seed":request.seed,
        "implementation":"forgeflow_planner::compile","timed_scope":"FULL_SEMANTIC_COMPILE",
        "dag_only_timing":false,"semantic_extra_rules":semantic_extras,"samples":samples}),
    )
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str::<Request>(&s).map_err(|e| e.to_string()))
            .and_then(run);
        println!(
            "{}",
            match result {
                Ok(value) => value,
                Err(error) => json!({"error":error}),
            }
        );
    }
}
