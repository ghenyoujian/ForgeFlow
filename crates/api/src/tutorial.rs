use super::*;
use forgeflow_planner::{CompileContext, DependencyKind, DependencySpec, OwnerTerritory, TaskSpec};
const PLAN: &str = include_str!("../../../project-packs/personal-website/plan.json");
fn json_error(error: serde_json::Error) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "TUTORIAL_INVALID",
        error.to_string(),
    )
}
#[derive(Deserialize)]
struct Guide {
    roles: Vec<Role>,
    tasks: Vec<Card>,
}
#[derive(Deserialize)]
struct Role {
    id: String,
    name: String,
    include: Vec<String>,
}
#[derive(Deserialize)]
struct Card {
    id: String,
    title: String,
    role: String,
    depends_on: Vec<String>,
    write_set: Vec<String>,
    outcome: String,
    acceptance: String,
}
pub async fn guide() -> Json<Value> {
    view_from(
        serde_json::from_str::<Value>(PLAN).expect("bundled tutorial"),
        "bundled_tutorial",
    )
}
pub async fn create_plan(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let plan: Guide = serde_json::from_str(PLAN).map_err(json_error)?;
    let mut commands = Vec::new();
    let mut context = CompileContext::default();
    for role in plan.roles {
        commands.push(CatalogCommand::CreateTeam(Team {
            project_id: project.clone(),
            team_id: role.id.clone(),
            parent_team_id: None,
            name: role.name,
            paused: false,
            revision: 1,
        }));
        let owner = OwnerTerritory {
            owner_id: role.id.clone(),
            root_team_id: Some(role.id.clone()),
            include: role.include,
            exclude: vec![],
        };
        context.owners.push(owner.clone());
        commands.push(CatalogCommand::PutDocument {
            project_id: project.clone(),
            collection: "owners".into(),
            id: role.id,
            expected_revision: None,
            value: serde_json::to_value(owner).map_err(json_error)?,
        });
    }
    let mut tasks = Vec::new();
    for card in plan.tasks {
        let requirement = Requirement {
            project_id: project.clone(),
            requirement_id: format!("site-{}", card.id),
            title: card.title.clone(),
            source_anchor: format!("personal-site#{}", card.id),
            outcome: card.outcome.clone(),
            scope: "个人网站教学草案".into(),
            acceptance: vec![card.acceptance.clone()],
            priority: 0,
            weight: 1,
            deferred_reason: None,
            revision: 1,
        };
        context.requirements.push(forgeflow_planner::Requirement {
            requirement_id: requirement.requirement_id.clone(),
            source_document: "personal-site".into(),
            anchor: card.id.clone(),
            acceptance: requirement.acceptance.join("\n"),
            priority: requirement.priority,
            deferred_reason: None,
        });
        commands.push(CatalogCommand::CreateRequirement(requirement));
        let spec = TaskSpec {
            outcome: card.outcome,
            requirement_digest_refs: Default::default(),
            design_anchors: vec![format!("personal-site#{}", card.id)],
            inputs: vec![],
            producer_inputs: vec![],
            mandatory_paths: card.write_set.clone(),
            dependency_refs: card
                .depends_on
                .iter()
                .map(|d| DependencySpec {
                    task_id: d.clone(),
                    project_id: project.clone(),
                    kind: DependencyKind::Integrated,
                    binding_id: format!("{d}:integrated"),
                })
                .collect(),
            contract_produces: vec![],
            contract_consumes: vec![],
            execution_profile: "unbound-personal-site".into(),
            verification_plan: card.acceptance,
            verification_case_count: 1,
            rollback_plan: "回退到已记录的基线提交；不覆盖其他成员的工作".into(),
            known_unknowns: vec!["部署目标与模型额度需要负责人确认".into()],
            not_proven: vec![
                "真实模型执行".into(),
                "真实网站部署".into(),
                "独立验证".into(),
            ],
            isolated_contract_probe: false,
        };
        let mut task = TaskCard {
            project_id: project.clone(),
            task_id: card.id.clone(),
            task_revision: 1,
            flow_revision: 1,
            title: card.title,
            owner_id: card.role.clone(),
            team_id: card.role,
            requirement_ids: vec![format!("site-{}", card.id)],
            read_set: vec![],
            write_set: card.write_set,
            dependencies: card.depends_on,
            state: TaskPlanningState::Planned,
            input_digest: String::new(),
            resource_request: ResourceVector {
                active_slot: 1,
                coding_slot: 1,
                cpu_units: 1,
                memory_bytes: 536870912,
                provider_inflight: 1,
                ..Default::default()
            },
            envelope: None,
            revision: 1,
        };
        task.input_digest = forgeflow_planner::canonical_task_input_digest(&task, &spec);
        context.task_specs.insert(card.id, spec);
        tasks.push(task);
    }
    let mut flow = FlowRevision {
        project_id: project.clone(),
        flow_revision: 1,
        parent_revision: None,
        state: FlowState::Draft,
        tasks,
        input_digest: "0".repeat(64),
        approved_by: None,
        revision: 1,
    };
    flow.input_digest = forgeflow_planner::semantic_digest(&flow, &context);
    commands.push(CatalogCommand::PutFlow {
        flow,
        expected_revision: None,
        context: Some(serde_json::to_value(context).map_err(json_error)?),
    });
    let receipt = s
        .store
        .install_tutorial_plan(identity(&headers, &actor)?, &project, commands)
        .await?;
    Ok(view(
        json!({"project_id":project,"flow_revision":1,"tasks":12,"roles":6,"operation_id":receipt.operation_id,"replayed":receipt.replayed,"execution":"DRAFT_ONLY","next":"preview_and_review"}),
    ))
}
pub async fn plugin_file(Path(file): Path<String>) -> Result<Response, ApiError> {
    let (mime, content) = match file.as_str() {
        "package.json" => (
            "application/json",
            include_str!("../../../plugins/dsh-forgeflow-network/package.json"),
        ),
        "index.mjs" => (
            "text/javascript",
            include_str!("../../../plugins/dsh-forgeflow-network/index.mjs"),
        ),
        "client.mjs" => (
            "text/javascript",
            include_str!("../../../plugins/dsh-forgeflow-network/client.mjs"),
        ),
        "forgeflow.mjs" => (
            "text/javascript",
            include_str!("../../../plugins/dsh-forgeflow-network/bin/forgeflow.mjs"),
        ),
        "personal-site.workflow.js" => (
            "text/javascript",
            include_str!(
                "../../../plugins/dsh-forgeflow-network/templates/personal-site.workflow.js"
            ),
        ),
        "plan.json" => ("application/json", PLAN),
        "README.md" => (
            "text/plain; charset=utf-8",
            include_str!("../../../plugins/dsh-forgeflow-network/README.md"),
        ),
        _ => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "plugin file unavailable",
            ));
        }
    };
    Ok((
        [
            ("content-type", mime),
            ("x-content-type-options", "nosniff"),
            ("content-disposition", "attachment"),
        ],
        content,
    )
        .into_response())
}
