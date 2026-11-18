//! Deterministic planning checks. These functions never issue leases or mutate a store.
use forgeflow_domain::{
    Attempt, ExecutionEnvelope, FlowRevision, FlowState, ResourceVector, TaskCard,
    TaskPlanningState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
pub const TASK_INPUT_DIGEST_ALGORITHM: &str = "forgeflow.task.input.v2";
pub const FLOW_APPROVAL_DIGEST_ALGORITHM: &str = "forgeflow.flow.approval.v2";

#[derive(Debug, Error)]
pub enum PlannerError {
    #[error("invalid requirement input: {0}")]
    InvalidInput(String),
    #[error("JSON input: {0}")]
    Json(#[from] serde_json::Error),
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequirementFormat {
    Markdown,
    Json,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub requirement_id: String,
    pub source_document: String,
    pub anchor: String,
    pub acceptance: String,
    pub priority: i32,
    pub deferred_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementDocument {
    pub source_document: String,
    pub raw_sha256: String,
    pub semantic_sha256: String,
    pub requirements: Vec<Requirement>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerTerritory {
    pub owner_id: String,
    #[serde(default)]
    pub root_team_id: Option<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputBinding {
    pub path: String,
    pub sha256: String,
    pub producer_task_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractBinding {
    pub contract_id: String,
    pub version: u64,
    pub spec_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSnapshot {
    pub contract_id: String,
    pub version: u64,
    pub spec_sha256: String,
    pub source_sha256: String,
    pub frozen: bool,
    pub required_consumers: Vec<String>,
    pub passing_consumers: Vec<String>,
    pub independent_receipt_id: Option<String>,
    pub integration_receipt_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Integrated,
    Artifact,
    ContractFrozen,
    GatePass,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencySpec {
    pub task_id: String,
    pub project_id: String,
    pub kind: DependencyKind,
    pub binding_id: String,
}
/// Approval binds an exact future producer, never a hash invented for unknown bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerInputBinding {
    pub path: String,
    pub producer_task_id: String,
    pub producer_task_revision: u64,
    pub producer_input_digest: String,
    pub dependency_binding_id: String,
    pub contract: ContractBinding,
}
/// Only native, unapproved proposals may omit redundant producer identity pins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftProducerInputProposal {
    pub path: String,
    pub producer_task_id: String,
    #[serde(default)]
    pub producer_task_revision: Option<u64>,
    #[serde(default)]
    pub producer_input_digest: Option<String>,
    pub dependency_binding_id: String,
    pub contract: ContractBinding,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftTaskProposal {
    project_id: String,
    task_id: String,
    task_revision: u64,
    flow_revision: u64,
    title: String,
    owner_id: String,
    team_id: String,
    requirement_ids: Vec<String>,
    read_set: Vec<String>,
    write_set: Vec<String>,
    dependencies: Vec<String>,
    state: TaskPlanningState,
    #[serde(default)]
    input_digest: Option<String>,
    resource_request: ResourceVector,
    envelope: Option<ExecutionEnvelope>,
    revision: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftFlowProposal {
    project_id: String,
    flow_revision: u64,
    parent_revision: Option<u64>,
    state: FlowState,
    tasks: Vec<DraftTaskProposal>,
    #[serde(default)]
    input_digest: Option<String>,
    approved_by: Option<String>,
    revision: u64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftProposalWire {
    generation_method: String,
    flow: DraftFlowProposal,
    context: serde_json::Value,
}
/// Editable proposal, never a Flow approval or a dispatchable TaskSpec.
#[derive(Debug, Clone)]
pub struct ModelDraftProposal {
    flow: DraftFlowProposal,
    pub context: CompileContext,
    producer_inputs: BTreeMap<String, Vec<DraftProducerInputProposal>>,
}
impl ModelDraftProposal {
    pub fn task_requirement_bindings(&self) -> Vec<(String, Vec<String>)> {
        self.flow
            .tasks
            .iter()
            .map(|t| (t.task_id.clone(), t.requirement_ids.clone()))
            .collect()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftProducerInputResolution {
    pub task_id: String,
    pub path: String,
    pub producer_task_id: String,
    pub producer_task_revision: u64,
    pub producer_input_digest: String,
    pub supplied_revision: bool,
    pub supplied_digest: bool,
}
#[derive(Debug, Clone)]
pub struct SealedModelDraft {
    pub draft: DraftBundle,
    pub producer_input_resolution: Vec<DraftProducerInputResolution>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftProducerInputReseal {
    pub task_id: String,
    pub path: String,
    pub producer_task_id: String,
    pub previous_task_revision: u64,
    pub previous_input_digest: String,
    pub producer_task_revision: u64,
    pub producer_input_digest: String,
}
/// Prepare an explicit, reviewable draft edit. Callers must require an operator
/// reseal action before applying the returned specification; committed meaning
/// and provided native proposal pins are never rebound by this function.
pub fn draft_producer_input_reseal(
    flow: &FlowRevision,
    context: &CompileContext,
    task_id: &str,
) -> Result<(TaskSpec, Vec<DraftProducerInputReseal>), PlannerError> {
    if flow.state != FlowState::Draft || flow.approved_by.is_some() {
        return Err(producer_input_error(
            "PRODUCER_INPUT_RESEAL: only an editable unapproved DRAFT may be resealed",
        ));
    }
    let task = flow
        .tasks
        .iter()
        .find(|t| t.task_id == task_id)
        .ok_or_else(|| producer_input_error("PRODUCER_INPUT_RESEAL: consumer missing"))?;
    let mut spec = context.task_specs.get(task_id).cloned().ok_or_else(|| {
        producer_input_error("PRODUCER_INPUT_RESEAL: consumer specification missing")
    })?;
    let mut changes = Vec::new();
    for input in &mut spec.producer_inputs {
        let producer = flow
            .tasks
            .iter()
            .find(|p| p.task_id == input.producer_task_id)
            .ok_or_else(|| {
                producer_input_error("PRODUCER_INPUT_RESEAL: declared producer missing")
            })?;
        let producer_spec = context.task_specs.get(&producer.task_id).ok_or_else(|| {
            producer_input_error("PRODUCER_INPUT_RESEAL: producer specification missing")
        })?;
        if input.producer_task_revision == 0
            || !valid_sha256(&input.producer_input_digest)
            || producer.input_digest != canonical_task_input_digest(producer, producer_spec)
            || !producer.write_set.iter().any(|w| contains(w, &input.path))
            || !producer_spec.contract_produces.contains(&input.contract)
            || !spec.contract_consumes.contains(&input.contract)
            || !spec.dependency_refs.iter().any(|d| {
                d.task_id == producer.task_id
                    && d.project_id == task.project_id
                    && matches!(d.kind, DependencyKind::Integrated)
                    && d.binding_id == input.dependency_binding_id
                    && task.dependencies.contains(&d.task_id)
            })
        {
            return Err(producer_input_error(
                "PRODUCER_INPUT_RESEAL: producer authority, exact contract or integrated dependency differs",
            ));
        }
        if input.producer_task_revision != producer.task_revision
            || input.producer_input_digest != producer.input_digest
        {
            changes.push(DraftProducerInputReseal {
                task_id: task.task_id.clone(),
                path: input.path.clone(),
                producer_task_id: producer.task_id.clone(),
                previous_task_revision: input.producer_task_revision,
                previous_input_digest: input.producer_input_digest.clone(),
                producer_task_revision: producer.task_revision,
                producer_input_digest: producer.input_digest.clone(),
            });
            input.producer_task_revision = producer.task_revision;
            input.producer_input_digest = producer.input_digest.clone();
        }
    }
    Ok((spec, changes))
}
/// Semantic details supplement the canonical task identity, never its mutable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub outcome: String,
    #[serde(default)]
    pub requirement_digest_refs: BTreeMap<String, String>,
    pub design_anchors: Vec<String>,
    pub inputs: Vec<InputBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub producer_inputs: Vec<ProducerInputBinding>,
    pub mandatory_paths: Vec<String>,
    pub dependency_refs: Vec<DependencySpec>,
    pub contract_produces: Vec<ContractBinding>,
    pub contract_consumes: Vec<ContractBinding>,
    pub execution_profile: String,
    pub verification_plan: String,
    pub verification_case_count: u64,
    pub rollback_plan: String,
    pub known_unknowns: Vec<String>,
    pub not_proven: Vec<String>,
    /// Candidate-contract probe is isolated and carries no product Gate effect.
    pub isolated_contract_probe: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CompileContext {
    pub requirements: Vec<Requirement>,
    #[serde(default)]
    pub requirement_semantic_digests: BTreeMap<String, String>,
    pub owners: Vec<OwnerTerritory>,
    pub task_specs: BTreeMap<String, TaskSpec>,
    /// Authoritative immutable snapshots supplied by the control plane, not executor claims.
    pub current_inputs: BTreeMap<String, String>,
    /// Resolved symlink targets relative to the same project root.
    pub resolved_paths: BTreeMap<String, String>,
    pub contracts: Vec<ContractSnapshot>,
    pub source_revision: String,
    pub observed_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Blocking,
    Warning,
    Info,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub subject_ref: String,
    pub evidence_refs: Vec<String>,
    pub blocked_tasks: Vec<String>,
    pub suggested_action: String,
    pub source_revision: String,
    pub observed_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    pub passed: bool,
    pub input_digest: String,
    pub digest_algorithm: String,
    pub task_input_digest_algorithm: String,
    pub topological_order: Vec<String>,
    pub coverage: BTreeMap<String, Vec<String>>,
    pub findings: Vec<Finding>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledFlow {
    pub flow: FlowRevision,
    pub check: CheckReport,
    pub semantic_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDiff {
    pub project_id: String,
    pub from_revision: u64,
    pub to_revision: u64,
    pub added_tasks: Vec<String>,
    pub removed_tasks: Vec<String>,
    pub changed_tasks: Vec<String>,
    pub changed_requirements: Vec<String>,
    pub impacted_tasks: Vec<String>,
    pub active_attempt_ids: Vec<String>,
    pub source_changed: bool,
    pub requires_full_graph_check: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftRequest {
    pub project_id: String,
    pub flow_revision: u64,
    pub source: RequirementDocument,
    pub owner_id: String,
    pub team_id: String,
    pub write_set: Vec<String>,
    pub execution_profile: String,
    pub verification_plan: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftBundle {
    /// rules_based or dsh_model_assisted; persisted as provenance, never qualification.
    pub generation_method: String,
    pub flow: FlowRevision,
    pub context: CompileContext,
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn requirement_semantic_digest(requirement: &forgeflow_domain::Requirement) -> String {
    digest(&(
        "forgeflow.requirement.semantic.v1",
        &requirement.project_id,
        &requirement.requirement_id,
        &requirement.source_anchor,
        &requirement.outcome,
        &requirement.scope,
        &requirement.acceptance,
        requirement.priority,
        requirement.weight,
        &requirement.deferred_reason,
    ))
}
fn normalized_requirement_digest(project_id: &str, requirement: &Requirement) -> String {
    requirement_semantic_digest(&forgeflow_domain::Requirement {
        project_id: project_id.into(),
        requirement_id: requirement.requirement_id.clone(),
        title: requirement.acceptance.clone(),
        source_anchor: format!("{}#{}", requirement.source_document, requirement.anchor),
        outcome: requirement.acceptance.clone(),
        scope: "imported requirement; refine before admission".into(),
        acceptance: vec![requirement.acceptance.clone()],
        priority: requirement.priority,
        weight: 1,
        deferred_reason: requirement.deferred_reason.clone(),
        revision: 1,
    })
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn digest<T: Serialize>(value: &T) -> String {
    sha256(&serde_json::to_vec(value).expect("serializable planner DTO"))
}
/// Strict recursive JSON decoding rejects duplicate keys before DTO deserialization.
pub fn strict_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, PlannerError> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    struct StrictValue(serde_json::Value);
    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = StrictValue;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON without duplicate keys")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                    Ok(StrictValue(v.into()))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                    Ok(StrictValue(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                    Ok(StrictValue(v.into()))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| StrictValue(n.into()))
                        .ok_or_else(|| E::custom("non-finite number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    Ok(StrictValue(v.into()))
                }
                fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                    Ok(StrictValue(v.into()))
                }
                fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(StrictValue(serde_json::Value::Null))
                }
                fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(StrictValue(serde_json::Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                    let mut values = vec![];
                    while let Some(v) = a.next_element::<StrictValue>()? {
                        values.push(v.0)
                    }
                    Ok(StrictValue(values.into()))
                }
                fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some(k) = a.next_key::<String>()? {
                        if values.contains_key(&k) {
                            return Err(de::Error::custom(format!("duplicate JSON key {k}")));
                        }
                        let v = a.next_value::<StrictValue>()?;
                        values.insert(k, v.0);
                    }
                    Ok(StrictValue(values.into()))
                }
            }
            de.deserialize_any(V)
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(text);
    let value = StrictValue::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(serde_json::from_value(value.0)?)
}

pub fn normalize_requirements(
    source_document: &str,
    text: &str,
    format: RequirementFormat,
) -> Result<RequirementDocument, PlannerError> {
    if source_document.trim().is_empty() || text.trim().is_empty() {
        return Err(PlannerError::InvalidInput(
            "source and content must be nonempty".into(),
        ));
    }
    let requirements: Vec<Requirement> = match format {
        RequirementFormat::Json => strict_json(text)?,
        RequirementFormat::Markdown => {
            let mut result = Vec::new();
            let mut section = String::from("document");
            for (i, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.starts_with('#') {
                    section = line.trim_start_matches('#').trim().to_owned();
                    continue;
                }
                if line.is_empty() || line.starts_with("<!--") {
                    continue;
                }
                let acceptance = line
                    .strip_prefix("- ")
                    .or_else(|| line.strip_prefix("* "))
                    .unwrap_or(line);
                result.push(Requirement {
                    requirement_id: format!("REQ-{:04}", result.len() + 1),
                    source_document: source_document.into(),
                    anchor: format!("{section}:L{}", i + 1),
                    acceptance: acceptance.into(),
                    priority: 0,
                    deferred_reason: None,
                });
            }
            result
        }
    };
    if requirements.is_empty() {
        return Err(PlannerError::InvalidInput("no requirements parsed".into()));
    }
    let mut ids = BTreeSet::new();
    for r in &requirements {
        if r.requirement_id.trim().is_empty()
            || r.anchor.trim().is_empty()
            || r.acceptance.trim().is_empty()
            || r.source_document != source_document
            || !ids.insert(&r.requirement_id)
        {
            return Err(PlannerError::InvalidInput(
                "requirement IDs, source, anchors and acceptance must be valid and unique".into(),
            ));
        }
    }
    Ok(RequirementDocument {
        source_document: source_document.into(),
        raw_sha256: sha256(text.as_bytes()),
        semantic_sha256: digest(&requirements),
        requirements,
    })
}

/// Conservative editing scaffold: one finite card per requirement, serialized when writes overlap.
/// It is explicitly rules-based and does not stand in for model-assisted decomposition.
pub fn rules_based_draft(request: DraftRequest) -> Result<DraftBundle, PlannerError> {
    for path in &request.write_set {
        normalize_path(path)?;
    }
    if request.project_id.is_empty() || request.owner_id.is_empty() || request.team_id.is_empty() {
        return Err(PlannerError::InvalidInput(
            "project, owner and team required".into(),
        ));
    }
    let mut context = CompileContext {
        requirements: request.source.requirements.clone(),
        requirement_semantic_digests: request
            .source
            .requirements
            .iter()
            .map(|r| {
                (
                    r.requirement_id.clone(),
                    normalized_requirement_digest(&request.project_id, r),
                )
            })
            .collect(),
        owners: vec![OwnerTerritory {
            owner_id: request.owner_id.clone(),
            root_team_id: None,
            include: request.write_set.clone(),
            exclude: vec![],
        }],
        source_revision: request.source.raw_sha256.clone(),
        ..Default::default()
    };
    let mut tasks = Vec::new();
    for r in &request.source.requirements {
        if r.deferred_reason.is_some() {
            continue;
        }
        let task_id = format!("TASK-{}-{}", request.project_id, r.requirement_id);
        let dependencies = if request.write_set.is_empty() {
            vec![]
        } else {
            tasks
                .last()
                .map(|t: &TaskCard| vec![t.task_id.clone()])
                .unwrap_or_default()
        };
        let spec = TaskSpec {
            outcome: r.acceptance.clone(),
            requirement_digest_refs: BTreeMap::from([(
                r.requirement_id.clone(),
                context.requirement_semantic_digests[&r.requirement_id].clone(),
            )]),
            design_anchors: vec![format!("{}#{}", r.source_document, r.anchor)],
            inputs: vec![],
            producer_inputs: vec![],
            mandatory_paths: vec![],
            dependency_refs: dependencies
                .iter()
                .map(|id| DependencySpec {
                    task_id: id.clone(),
                    project_id: request.project_id.clone(),
                    kind: DependencyKind::Integrated,
                    binding_id: format!("{id}:integrated"),
                })
                .collect(),
            contract_produces: vec![],
            contract_consumes: vec![],
            execution_profile: request.execution_profile.clone(),
            verification_plan: request.verification_plan.clone(),
            verification_case_count: 0,
            rollback_plan:
                "Preserve failed candidate and create an explicit revert task if already integrated"
                    .into(),
            known_unknowns: vec![
                "Owner must refine implementation and independent acceptance cases".into(),
            ],
            not_proven: vec!["No model-assisted decomposition or execution qualification".into()],
            isolated_contract_probe: false,
        };
        let mut task = TaskCard {
            project_id: request.project_id.clone(),
            task_id: task_id.clone(),
            task_revision: 1,
            flow_revision: request.flow_revision,
            title: r.acceptance.clone(),
            owner_id: request.owner_id.clone(),
            team_id: request.team_id.clone(),
            requirement_ids: vec![r.requirement_id.clone()],
            read_set: vec![],
            write_set: request.write_set.clone(),
            dependencies,
            state: TaskPlanningState::NeedsReview,
            input_digest: task_input_digest(&spec),
            resource_request: ResourceVector {
                active_slot: 1,
                coding_slot: u64::from(!request.write_set.is_empty()),
                ..Default::default()
            },
            envelope: None,
            revision: 1,
        };
        task.input_digest = canonical_task_input_digest(&task, &spec);
        context.task_specs.insert(task_id, spec);
        tasks.push(task);
    }
    let flow = FlowRevision {
        project_id: request.project_id,
        flow_revision: request.flow_revision,
        parent_revision: None,
        state: FlowState::Draft,
        tasks,
        input_digest: request.source.semantic_sha256,
        approved_by: None,
        revision: 1,
    };
    Ok(DraftBundle {
        generation_method: "rules_based".into(),
        flow,
        context,
    })
}
pub fn model_draft_prompt(request: &DraftRequest) -> String {
    let example = match rules_based_draft(request.clone()) {
        Ok(d) => {
            let mut example = serde_json::to_value(d).unwrap();
            example["generation_method"] = serde_json::json!("dsh_model_assisted");
            example["flow"]["input_digest"] = serde_json::Value::Null;
            for task in example["flow"]["tasks"].as_array_mut().unwrap() {
                task["input_digest"] = serde_json::Value::Null;
            }
            serde_json::to_string(&example).unwrap()
        }
        Err(error) => format!("Invalid scaffold request: {error}"),
    };
    format!(
        "Produce one JSON unapproved draft proposal with generation_method=dsh_model_assisted. This is a read-only planning operation. Never execute tasks, claim completion, approve the Flow or create leases. Use canonical task/spec fields, unique IDs, finite outcomes, explicit dependencies and independent acceptance. Keep every source requirement anchor; map or explicitly defer every requirement. Include all mandatory inputs, exact owner write scope, pinned contract versions, rollback and not_proven. Flow/task input_digest may be null or omitted: the backend computes actual semantic digests after binding authoritative requirement meaning. For an existing input, inputs contains its actual SHA256 and producer_task_id:null. Never put a future input or a placeholder hash in inputs. Unknown producer bytes instead use TaskSpec.producer_inputs with objects with path, producer_task_id, dependency_binding_id and contract fields (contract_id, version, spec_sha256 copied from the exact registered schema). Omit producer_task_revision and producer_input_digest or set them null when unresolved. The backend resolves exact producer revision and semantic digest in DAG order before review. Supplied exact pins must match and will never be silently rebound. The producer must declare that write path and exact contract_produces; the consumer must declare the path in its read_set/mandatory_paths, the exact contract_consumes and the integrated dependency. Public contract freezing or explicit isolated_contract_probe remains mandatory. Return JSON only. Request:\n{}\nProposal schema example (refine it, do not claim its verification):\n{}",
        serde_json::to_string(request).unwrap(),
        example
    )
}
pub fn model_draft_prompt_with_instruction(request: &DraftRequest, instruction: &str) -> String {
    format!(
        "{}\nUser planning instruction (proposal scope; unchanged source acceptance and authority remain mandatory):\n{}",
        model_draft_prompt(request),
        instruction
    )
}
/// One finite read-only planning card. Its planned verification cases are schema,
/// original-source anchors, declared authority and deterministic semantic compilation.
/// Store still needs trusted context snapshots, approval and a qualified execution envelope.
pub fn planning_bootstrap(
    request: &DraftRequest,
    planning_task_id: &str,
) -> Result<DraftBundle, PlannerError> {
    if planning_task_id.trim().is_empty() {
        return Err(PlannerError::InvalidInput(
            "planning task identity required".into(),
        ));
    }
    let mut read_request = request.clone();
    read_request.write_set.clear();
    let mut bundle = rules_based_draft(read_request)?;
    let Some(mut task) = bundle.flow.tasks.first().cloned() else {
        return Err(PlannerError::InvalidInput(
            "at least one non-deferred requirement must be planned".into(),
        ));
    };
    let spec=TaskSpec{requirement_digest_refs:bundle.context.requirement_semantic_digests.clone(),outcome:"Produce a source-bound DraftBundle with finite tasks, explicit dependencies, original acceptance, ownership and review findings; do not commit or execute it".into(),design_anchors:request.source.requirements.iter().map(|r|format!("{}#{}",r.source_document,r.anchor)).collect(),inputs:vec![InputBinding{path:request.source.source_document.clone(),sha256:request.source.raw_sha256.clone(),producer_task_id:None}],producer_inputs:vec![],mandatory_paths:vec![request.source.source_document.clone()],dependency_refs:vec![],contract_produces:vec![],contract_consumes:vec![],execution_profile:request.execution_profile.clone(),verification_plan:request.verification_plan.clone(),verification_case_count:4,rollback_plan:"Keep original model output and validation errors; bounded format repair uses a new counted planning attempt".into(),known_unknowns:vec!["DSH/model profile must be qualified by the actual runtime".into()],not_proven:vec!["Generated draft has no execution or product Gate qualification".into()],isolated_contract_probe:false};
    task.task_id = planning_task_id.into();
    task.title = "Generate reviewable Flow draft".into();
    task.requirement_ids = request
        .source
        .requirements
        .iter()
        .map(|r| r.requirement_id.clone())
        .collect();
    task.read_set = vec![request.source.source_document.clone()];
    task.write_set.clear();
    task.dependencies.clear();
    task.resource_request = ResourceVector {
        active_slot: 1,
        ..Default::default()
    };
    task.input_digest = canonical_task_input_digest(&task, &spec);
    bundle.flow.tasks = vec![task];
    bundle.context.task_specs = BTreeMap::from([(planning_task_id.into(), spec)]);
    bundle.context.current_inputs = BTreeMap::from([(
        request.source.source_document.clone(),
        request.source.raw_sha256.clone(),
    )]);
    bundle.generation_method = "planning_bootstrap_rules".into();
    bundle.flow.input_digest = semantic_digest(&bundle.flow, &bundle.context);
    Ok(bundle)
}
/// Bootstrap using a controlled source artifact's logical input path, while keeping
/// the original requirement source IDs/anchors unchanged for traceability.
pub fn planning_bootstrap_with_source_input(
    request: &DraftRequest,
    planning_task_id: &str,
    source_input: InputBinding,
) -> Result<DraftBundle, PlannerError> {
    normalize_path(&source_input.path)?;
    if source_input.producer_task_id.is_some() || source_input.sha256 != request.source.raw_sha256 {
        return Err(PlannerError::InvalidInput(
            "planning source artifact must match original immutable source bytes".into(),
        ));
    }
    let mut bundle = planning_bootstrap(request, planning_task_id)?;
    let task = &mut bundle.flow.tasks[0];
    let spec = bundle.context.task_specs.get_mut(planning_task_id).unwrap();
    task.read_set = vec![source_input.path.clone()];
    spec.mandatory_paths = vec![source_input.path.clone()];
    spec.inputs = vec![source_input.clone()];
    task.input_digest = canonical_task_input_digest(task, spec);
    bundle.context.current_inputs = BTreeMap::from([(source_input.path, source_input.sha256)]);
    bundle.flow.input_digest = semantic_digest(&bundle.flow, &bundle.context);
    Ok(bundle)
}
pub fn parse_model_draft(output: &str) -> Result<DraftBundle, PlannerError> {
    let bundle: DraftBundle = strict_json(output)?;
    if bundle.generation_method != "dsh_model_assisted"
        || !matches!(bundle.flow.state, FlowState::Draft)
        || bundle.flow.approved_by.is_some()
        || bundle.flow.tasks.iter().any(|t| {
            t.envelope.is_some()
                || !matches!(
                    t.state,
                    TaskPlanningState::Planned | TaskPlanningState::NeedsReview
                )
        })
    {
        return Err(PlannerError::InvalidInput(
            "model may emit only unapproved drafts without execution envelopes".into(),
        ));
    }
    Ok(bundle)
}
/// Decode an unapproved native proposal. Unknown producer bytes have no hash;
/// omitted semantic pins are resolved only after authoritative source binding.
pub fn parse_model_draft_proposal(
    output: &str,
    request: &DraftRequest,
) -> Result<ModelDraftProposal, PlannerError> {
    let mut wire: DraftProposalWire = strict_json(output)?;
    if wire.generation_method != "dsh_model_assisted"
        || wire.flow.state != FlowState::Draft
        || wire.flow.approved_by.is_some()
        || wire.flow.project_id != request.project_id
        || wire.flow.flow_revision != request.flow_revision
        || wire.flow.tasks.is_empty()
        || wire.flow.tasks.len() > 10_000
    {
        return Err(producer_input_error(
            "MODEL_DRAFT_PROPOSAL: only finite unapproved source-bound drafts are accepted",
        ));
    }
    let specs = wire
        .context
        .get_mut("task_specs")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            producer_input_error("MODEL_DRAFT_PROPOSAL: typed task specifications required")
        })?;
    let mut producer_inputs = BTreeMap::new();
    for (id, spec) in specs {
        let fields = spec.as_object_mut().ok_or_else(|| {
            producer_input_error("MODEL_DRAFT_PROPOSAL: task specification must be an object")
        })?;
        let refs: Vec<DraftProducerInputProposal> = match fields.remove("producer_inputs") {
            Some(value) => serde_json::from_value(value)?,
            None => Vec::new(),
        };
        if refs.iter().any(|r| {
            r.producer_task_revision == Some(0)
                || r.producer_input_digest
                    .as_ref()
                    .is_some_and(|v| !valid_sha256(v))
        }) {
            return Err(producer_input_error(
                "MODEL_DRAFT_PROPOSAL: omit unresolved producer pins; never supply zero revisions or placeholder hashes",
            ));
        }
        producer_inputs.insert(id.clone(), refs);
    }
    let context: CompileContext = serde_json::from_value(wire.context)?;
    if context.source_revision != request.source.raw_sha256
        || context.requirements.len() != request.source.requirements.len()
        || context.task_specs.values().any(|s| {
            s.inputs
                .iter()
                .any(|i| i.producer_task_id.is_some() || !valid_sha256(&i.sha256))
        })
    {
        return Err(producer_input_error(
            "MODEL_DRAFT_PROPOSAL: preserve source identity and actual known input hashes; future bytes use producer_inputs",
        ));
    }
    let originals = request
        .source
        .requirements
        .iter()
        .map(|r| (r.requirement_id.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for actual in &context.requirements {
        let original = originals
            .get(actual.requirement_id.as_str())
            .ok_or_else(|| producer_input_error("MODEL_DRAFT_PROPOSAL: invented requirement"))?;
        if !seen.insert(actual.requirement_id.as_str())
            || actual.source_document != original.source_document
            || actual.anchor != original.anchor
            || actual.acceptance != original.acceptance
            || actual.priority != original.priority
        {
            return Err(producer_input_error(
                "MODEL_DRAFT_PROPOSAL: changed original source anchor or acceptance",
            ));
        }
    }
    let mut ids = BTreeSet::new();
    let mut covered = BTreeSet::new();
    for task in &wire.flow.tasks {
        if !ids.insert(task.task_id.clone())
            || task.task_revision == 0
            || task.project_id != request.project_id
            || task.flow_revision != request.flow_revision
            || task.owner_id != request.owner_id
            || task.team_id != request.team_id
            || task.envelope.is_some()
            || !matches!(
                task.state,
                TaskPlanningState::Planned | TaskPlanningState::NeedsReview
            )
            || task.requirement_ids.is_empty()
            || task
                .requirement_ids
                .iter()
                .any(|id| !originals.contains_key(id.as_str()))
            || task.write_set.iter().any(|p| {
                normalize_path(p).is_err()
                    || !request.write_set.iter().any(|scope| contains(scope, p))
            })
            || task.read_set.iter().any(|p| normalize_path(p).is_err())
            || task.input_digest.as_ref().is_some_and(|v| !valid_sha256(v))
        {
            return Err(producer_input_error(
                "MODEL_DRAFT_PROPOSAL: invalid task identity, source coverage or expanded execution authority",
            ));
        }
        covered.extend(task.requirement_ids.iter().cloned());
    }
    if ids != context.task_specs.keys().cloned().collect()
        || request.source.requirements.iter().any(|r| {
            !covered.contains(&r.requirement_id)
                && r.deferred_reason.as_ref().is_none_or(|v| v.is_empty())
        })
        || wire
            .flow
            .input_digest
            .as_ref()
            .is_some_and(|v| !valid_sha256(v))
    {
        return Err(producer_input_error(
            "MODEL_DRAFT_PROPOSAL: complete finite task/source denominator and optional actual semantic hashes required",
        ));
    }
    Ok(ModelDraftProposal {
        flow: wire.flow,
        context,
        producer_inputs,
    })
}
/// Seal a proposal after current authoritative requirement/source facts replace
/// model assertions. Provided pins are compared, never rewritten. No approval,
/// envelope, artifact-byte hash, lease or dispatch authority is created here.
pub fn seal_model_draft_proposal(
    proposal: ModelDraftProposal,
    mut context: CompileContext,
) -> Result<SealedModelDraft, PlannerError> {
    let tasks = proposal
        .flow
        .tasks
        .iter()
        .map(|t| (t.task_id.clone(), t))
        .collect::<BTreeMap<_, _>>();
    let mut pending = BTreeMap::new();
    for task in &proposal.flow.tasks {
        let deps: BTreeSet<_> = task.dependencies.iter().cloned().collect();
        if deps.len() != task.dependencies.len()
            || deps
                .iter()
                .any(|id| id == &task.task_id || !tasks.contains_key(id))
        {
            return Err(producer_input_error(
                "MODEL_DRAFT_DAG: missing, duplicate or self dependency",
            ));
        }
        pending.insert(task.task_id.clone(), deps);
    }
    let mut sealed = BTreeMap::<String, TaskCard>::new();
    let mut resolutions = Vec::new();
    while !pending.is_empty() {
        let ready: Vec<_> = pending
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        if ready.is_empty() {
            return Err(producer_input_error(
                "MODEL_DRAFT_DAG_CYCLE: future producer identities cannot be resolved across a cycle",
            ));
        }
        for id in ready {
            let task = tasks[&id];
            let mut spec = context.task_specs.get(&id).cloned().ok_or_else(|| {
                producer_input_error(
                    "MODEL_DRAFT_PROPOSAL: authoritative task specification missing",
                )
            })?;
            if !spec.producer_inputs.is_empty() {
                return Err(producer_input_error(
                    "MODEL_DRAFT_PROPOSAL: canonical pins cannot be silently resealed",
                ));
            }
            let mut paths = spec
                .inputs
                .iter()
                .map(|i| i.path.clone())
                .collect::<BTreeSet<_>>();
            if paths.len() != spec.inputs.len() {
                return Err(producer_input_error(
                    "MODEL_DRAFT_PROPOSAL: duplicate known input path",
                ));
            }
            for input in &proposal.producer_inputs[&id] {
                let producer = sealed.get(&input.producer_task_id).ok_or_else(|| producer_input_error("MODEL_DRAFT_PRODUCER: producer must resolve first through declared DAG dependencies"))?;
                let producer_spec = &context.task_specs[&producer.task_id];
                if normalize_path(&input.path)? != input.path
                    || !paths.insert(input.path.clone())
                    || !task
                        .read_set
                        .iter()
                        .chain(&spec.mandatory_paths)
                        .any(|p| p == &input.path)
                    || !producer.write_set.iter().any(|w| contains(w, &input.path))
                    || !spec.contract_consumes.contains(&input.contract)
                    || !producer_spec.contract_produces.contains(&input.contract)
                    || !context.contracts.iter().any(|c| {
                        c.contract_id == input.contract.contract_id
                            && c.version == input.contract.version
                            && c.spec_sha256 == input.contract.spec_sha256
                    })
                    || !spec.dependency_refs.iter().any(|d| {
                        d.task_id == producer.task_id
                            && d.project_id == task.project_id
                            && matches!(d.kind, DependencyKind::Integrated)
                            && d.binding_id == input.dependency_binding_id
                            && task.dependencies.contains(&d.task_id)
                    })
                    || input
                        .producer_task_revision
                        .is_some_and(|v| v != producer.task_revision)
                    || input
                        .producer_input_digest
                        .as_ref()
                        .is_some_and(|v| v != &producer.input_digest)
                {
                    return Err(producer_input_error(
                        "MODEL_DRAFT_PRODUCER: supplied pin, path, integrated dependency or exact contract differs; explicit draft review is required",
                    ));
                }
                spec.producer_inputs.push(ProducerInputBinding {
                    path: input.path.clone(),
                    producer_task_id: producer.task_id.clone(),
                    producer_task_revision: producer.task_revision,
                    producer_input_digest: producer.input_digest.clone(),
                    dependency_binding_id: input.dependency_binding_id.clone(),
                    contract: input.contract.clone(),
                });
                resolutions.push(DraftProducerInputResolution {
                    task_id: id.clone(),
                    path: input.path.clone(),
                    producer_task_id: producer.task_id.clone(),
                    producer_task_revision: producer.task_revision,
                    producer_input_digest: producer.input_digest.clone(),
                    supplied_revision: input.producer_task_revision.is_some(),
                    supplied_digest: input.producer_input_digest.is_some(),
                });
            }
            let input_digest = task_meaning_digest(
                TaskMeaning {
                    project_id: &task.project_id,
                    task_id: &task.task_id,
                    task_revision: task.task_revision,
                    owner_id: &task.owner_id,
                    team_id: &task.team_id,
                    requirement_ids: &task.requirement_ids,
                    read_set: &task.read_set,
                    write_set: &task.write_set,
                    dependencies: &task.dependencies,
                    resource_request: &task.resource_request,
                },
                &spec,
            );
            if task
                .input_digest
                .as_ref()
                .is_some_and(|supplied| supplied != &input_digest)
            {
                return Err(producer_input_error(
                    "MODEL_DRAFT_PRODUCER: supplied task semantic identity differs from sealed source meaning",
                ));
            }
            sealed.insert(
                id.clone(),
                TaskCard {
                    project_id: task.project_id.clone(),
                    task_id: id.clone(),
                    task_revision: task.task_revision,
                    flow_revision: task.flow_revision,
                    title: task.title.clone(),
                    owner_id: task.owner_id.clone(),
                    team_id: task.team_id.clone(),
                    requirement_ids: task.requirement_ids.clone(),
                    read_set: task.read_set.clone(),
                    write_set: task.write_set.clone(),
                    dependencies: task.dependencies.clone(),
                    state: task.state,
                    input_digest,
                    resource_request: task.resource_request.clone(),
                    envelope: None,
                    revision: task.revision,
                },
            );
            context.task_specs.insert(id.clone(), spec);
            pending.remove(&id);
            for deps in pending.values_mut() {
                deps.remove(&id);
            }
        }
    }
    let cards: Vec<_> = proposal
        .flow
        .tasks
        .iter()
        .map(|t| sealed.remove(&t.task_id).expect("sealed finite task"))
        .collect();
    let flow_digest = flow_meaning_digest(
        &proposal.flow.project_id,
        proposal.flow.flow_revision,
        proposal.flow.parent_revision,
        &cards,
        &context,
    );
    if proposal
        .flow
        .input_digest
        .as_ref()
        .is_some_and(|v| v != &flow_digest)
    {
        return Err(producer_input_error(
            "MODEL_DRAFT_PRODUCER: supplied Flow semantic identity differs from sealed source meaning",
        ));
    }
    let flow = FlowRevision {
        project_id: proposal.flow.project_id,
        flow_revision: proposal.flow.flow_revision,
        parent_revision: proposal.flow.parent_revision,
        state: FlowState::Draft,
        tasks: cards,
        input_digest: flow_digest,
        approved_by: None,
        revision: proposal.flow.revision,
    };
    Ok(SealedModelDraft {
        draft: DraftBundle {
            generation_method: "dsh_model_assisted".into(),
            flow,
            context,
        },
        producer_input_resolution: resolutions,
    })
}
/// Bind decoded model output to the original request before saving a draft.
/// Server snapshots must replace model-supplied current_inputs/contracts/resolved_paths.
pub fn validate_model_draft(
    output: &str,
    request: &DraftRequest,
) -> Result<DraftBundle, PlannerError> {
    let bundle = parse_model_draft(output)?;
    if bundle.flow.project_id != request.project_id
        || bundle.flow.flow_revision != request.flow_revision
        || bundle.context.requirements.len() != request.source.requirements.len()
        || bundle.context.source_revision != request.source.raw_sha256
    {
        return Err(PlannerError::InvalidInput(
            "model draft changed request/source identity".into(),
        ));
    }
    let expected = request
        .source
        .requirements
        .iter()
        .map(|r| (r.requirement_id.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for actual in &bundle.context.requirements {
        let Some(original) = expected.get(actual.requirement_id.as_str()) else {
            return Err(PlannerError::InvalidInput(
                "model invented a source requirement".into(),
            ));
        };
        if !seen.insert(actual.requirement_id.as_str())
            || actual.source_document != original.source_document
            || actual.anchor != original.anchor
            || actual.acceptance != original.acceptance
            || actual.priority != original.priority
        {
            return Err(PlannerError::InvalidInput(
                "model changed source anchors or acceptance".into(),
            ));
        }
    }
    for task in &bundle.flow.tasks {
        if task.project_id != request.project_id
            || task.flow_revision != request.flow_revision
            || task.owner_id != request.owner_id
            || task.team_id != request.team_id
            || task.write_set.iter().any(|p| {
                normalize_path(p).is_err()
                    || !request.write_set.iter().any(|scope| contains(scope, p))
            })
        {
            return Err(PlannerError::InvalidInput(
                "model expanded approved task authority".into(),
            ));
        }
    }
    Ok(bundle)
}
pub fn model_repair_prompt(raw: &str, error: &str) -> String {
    format!(
        "Repair only JSON/schema formatting in the following DSH planning output. Preserve requirements, ownership, dependencies and acceptance; do not lower gates. Return JSON only. Error: {error}\nRaw output:\n{raw}"
    )
}

pub fn normalize_path(path: &str) -> Result<String, PlannerError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.contains(':')
    {
        return Err(PlannerError::InvalidInput(format!(
            "unsafe relative path {path:?}"
        )));
    }
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|p| p.is_empty() || p == ".." || p == ".")
    {
        return Err(PlannerError::InvalidInput(format!(
            "unsafe relative path {path:?}"
        )));
    }
    Ok(path.into())
}
fn contains(scope: &str, path: &str) -> bool {
    if scope.ends_with('/') {
        path.starts_with(scope)
    } else {
        scope == path
    }
}
fn overlaps(a: &str, b: &str) -> bool {
    contains(a, b) || contains(b, a)
}
pub fn task_input_digest(spec: &TaskSpec) -> String {
    digest(spec)
}
/// Complete immutable task input identity, including authority and effects.
/// Task state, row revision, runtime envelope and the digest itself are deliberately excluded.
pub fn canonical_task_input_digest(task: &TaskCard, spec: &TaskSpec) -> String {
    task_meaning_digest(
        TaskMeaning {
            project_id: &task.project_id,
            task_id: &task.task_id,
            task_revision: task.task_revision,
            owner_id: &task.owner_id,
            team_id: &task.team_id,
            requirement_ids: &task.requirement_ids,
            read_set: &task.read_set,
            write_set: &task.write_set,
            dependencies: &task.dependencies,
            resource_request: &task.resource_request,
        },
        spec,
    )
}
struct TaskMeaning<'a> {
    project_id: &'a str,
    task_id: &'a str,
    task_revision: u64,
    owner_id: &'a str,
    team_id: &'a str,
    requirement_ids: &'a [String],
    read_set: &'a [String],
    write_set: &'a [String],
    dependencies: &'a [String],
    resource_request: &'a ResourceVector,
}
fn task_meaning_digest(task: TaskMeaning<'_>, spec: &TaskSpec) -> String {
    digest(&(
        TASK_INPUT_DIGEST_ALGORITHM,
        task.project_id,
        task.task_id,
        task.task_revision,
        task.owner_id,
        task.team_id,
        task.requirement_ids,
        task.read_set,
        task.write_set,
        task.dependencies,
        task.resource_request,
        spec,
    ))
}
/// Static template approval hash belongs to the Flow, never the task input hash
/// which rendered prompts and VerificationPlan.input_hash may embed.
pub fn static_execution_template_digest(envelope: &ExecutionEnvelope) -> String {
    let mut value = serde_json::to_value(envelope).expect("canonical execution envelope");
    let fields = value.as_object_mut().expect("execution envelope object");
    for key in [
        "operation_id",
        "attempt_id",
        "lease_id",
        "generation",
        "worker_id",
        "issued_at",
        "expires_at",
        "trace_id",
        "idempotency_key",
    ] {
        fields.remove(key);
    }
    digest(&("forgeflow.execution.template.v2", value))
}

pub const PRODUCER_INPUT_RECIPE_ALGORITHM: &str = "forgeflow.producer-input.recipe.v1";
/// Derived from approved immutable objects; not an authorization to edit those objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerInputRecipe {
    pub algorithm: String,
    pub project_id: String,
    pub flow_revision: u64,
    pub task_id: String,
    pub task_revision: u64,
    pub task_input_digest: String,
    pub static_template_digest: String,
    pub approved_manifest_sha256: String,
    pub inputs: Vec<ProducerInputBinding>,
}
impl ProducerInputRecipe {
    pub fn digest(&self) -> String {
        digest(self)
    }
}
/// The store supplies registered immutable records, never request-body projections.
#[derive(Debug, Clone)]
pub struct ProducerInputEvidence {
    pub producer: TaskCard,
    pub attempt: forgeflow_domain::Attempt,
    pub receipt: forgeflow_domain::EvidenceReceipt,
    pub integration: forgeflow_domain::MergeIntent,
    pub contract: forgeflow_domain::ContractVersion,
}
/// Trusted Git observations. The store must establish ancestry with actual Git,
/// require regular blobs, and read bytes at both the accepted and selected trees.
/// This pure function cannot establish registration, ref reachability or ancestry.
#[derive(Debug, Clone)]
pub struct ProducerInputTree {
    pub base_sha: String,
    pub integrated_ancestors: BTreeSet<String>,
    pub base_inputs: BTreeMap<String, Vec<u8>>,
    pub producer_inputs: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
    /// Recomputed tracked contents, keyed by the immutable accepted commit SHA.
    /// Receipt JSON is never an authority for this observation.
    pub source_contents: BTreeMap<String, ProducerSourceContent>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerSourceContent {
    pub algorithm: String,
    pub commit_sha: String,
    pub tree_oid: String,
    pub source_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedProducerInput {
    pub path: String,
    pub sha256: String,
    pub producer_task_id: String,
    pub producer_task_revision: u64,
    pub producer_input_digest: String,
    pub producer_attempt_id: String,
    pub generation: i64,
    pub evidence_receipt_id: String,
    pub integration_receipt_id: String,
    pub integrated_sha: String,
    pub dependency_binding_id: String,
    pub contract: ContractBinding,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerInputMaterialization {
    pub recipe: ProducerInputRecipe,
    pub recipe_sha256: String,
    pub base_sha: String,
    pub manifest: forgeflow_domain::ContextManifest,
    pub manifest_sha256: String,
    pub inputs: Vec<MaterializedProducerInput>,
}
fn producer_input_error(message: impl Into<String>) -> PlannerError {
    PlannerError::InvalidInput(message.into())
}
/// Validate and derive the immutable recipe without hashing unknown file contents.
pub fn producer_input_recipe(
    task: &TaskCard,
    spec: &TaskSpec,
    approved_manifest_bytes: &[u8],
) -> Result<ProducerInputRecipe, PlannerError> {
    let frozen = task.envelope.as_ref().ok_or_else(|| {
        producer_input_error("PRODUCER_INPUT_RECIPE: approved execution template required")
    })?;
    if spec.producer_inputs.is_empty()
        || task.input_digest != canonical_task_input_digest(task, spec)
        || frozen.project_id != task.project_id
        || frozen.task_id != task.task_id
        || frozen.task_revision != task.task_revision
        || sha256(approved_manifest_bytes) != frozen.context_manifest.sha256
    {
        return Err(producer_input_error(
            "PRODUCER_INPUT_RECIPE: immutable task/template/manifest mismatch",
        ));
    }
    let manifest: forgeflow_domain::ContextManifest =
        strict_json(std::str::from_utf8(approved_manifest_bytes).map_err(|_| {
            producer_input_error("PRODUCER_INPUT_RECIPE: context manifest must be UTF8 JSON")
        })?)?;
    let mut expected = BTreeMap::new();
    for input in &spec.inputs {
        if input.producer_task_id.is_some()
            || !valid_sha256(&input.sha256)
            || normalize_path(&input.path)? != input.path
            || expected
                .insert(input.path.clone(), input.sha256.clone())
                .is_some()
        {
            return Err(producer_input_error(
                "PRODUCER_INPUT_RECIPE: known inputs require unique actual hashes",
            ));
        }
    }
    let mut actual = BTreeMap::new();
    for input in &manifest.files {
        if actual
            .insert(input.path.clone(), input.sha256.clone())
            .is_some()
        {
            return Err(producer_input_error(
                "PRODUCER_INPUT_RECIPE: duplicate manifest file",
            ));
        }
    }
    for input in &manifest.artifact_inputs {
        if actual
            .insert(input.logical_path.clone(), input.artifact.sha256.clone())
            .is_some()
        {
            return Err(producer_input_error(
                "PRODUCER_INPUT_RECIPE: duplicate manifest artifact",
            ));
        }
    }
    let required: BTreeSet<_> = task
        .read_set
        .iter()
        .chain(&spec.mandatory_paths)
        .cloned()
        .collect();
    let declared: BTreeSet<_> = spec
        .inputs
        .iter()
        .map(|i| i.path.clone())
        .chain(spec.producer_inputs.iter().map(|i| i.path.clone()))
        .collect();
    let future: BTreeSet<_> = spec
        .producer_inputs
        .iter()
        .map(|i| i.path.clone())
        .collect();
    if actual != expected
        || future.len() != spec.producer_inputs.len()
        || future
            .iter()
            .any(|p| expected.contains_key(p) || !required.contains(p))
        || !required.is_subset(&declared)
        || manifest
            .mandatory_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != required
        || frozen
            .context_manifest
            .mandatory_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != required
    {
        return Err(producer_input_error(
            "PRODUCER_INPUT_RECIPE: exact known inputs and required producer paths must be preserved",
        ));
    }
    for input in &spec.producer_inputs {
        if normalize_path(&input.path)? != input.path
            || input.producer_task_revision == 0
            || !valid_sha256(&input.producer_input_digest)
            || input.dependency_binding_id.is_empty()
            || input.contract.contract_id.is_empty()
            || input.contract.version == 0
            || !valid_sha256(&input.contract.spec_sha256)
            || !spec.contract_consumes.contains(&input.contract)
            || !spec.dependency_refs.iter().any(|d| {
                d.task_id == input.producer_task_id
                    && d.project_id == task.project_id
                    && matches!(d.kind, DependencyKind::Integrated)
                    && d.binding_id == input.dependency_binding_id
                    && task.dependencies.contains(&d.task_id)
            })
        {
            return Err(producer_input_error(
                "PRODUCER_INPUT_RECIPE: exact integrated dependency and contract required",
            ));
        }
    }
    Ok(ProducerInputRecipe {
        algorithm: PRODUCER_INPUT_RECIPE_ALGORITHM.into(),
        project_id: task.project_id.clone(),
        flow_revision: task.flow_revision,
        task_id: task.task_id.clone(),
        task_revision: task.task_revision,
        task_input_digest: task.input_digest.clone(),
        static_template_digest: static_execution_template_digest(frozen),
        approved_manifest_sha256: frozen.context_manifest.sha256.clone(),
        inputs: spec.producer_inputs.clone(),
    })
}
fn receipt_binding_matches(
    verification: &serde_json::Value,
    attempt: &forgeflow_domain::Attempt,
    candidate_sha: &str,
    integrated_sha: Option<&str>,
    input_digest: &str,
    contract_version: &str,
) -> bool {
    let binding = &verification["binding"];
    let total = verification["total"].as_u64();
    let positive = verification["positive_cases"].as_u64();
    let negative = verification["negative_cases"].as_u64();
    verification["independent"].as_bool() == Some(true)
        && verification["exit_code"].as_i64() == Some(0)
        && verification["failed"].as_u64() == Some(0)
        && verification["skipped"].as_u64() == Some(0)
        && positive.is_some_and(|v| v > 0)
        && negative.is_some_and(|v| v > 0)
        && positive.zip(negative).and_then(|(p, n)| p.checked_add(n)) == total
        && verification["verifier_id"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
        && verification["author_id"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
        && verification["verifier_id"] != verification["author_id"]
        && binding["task_revision"].as_u64() == Some(attempt.task_revision)
        && binding["attempt_id"].as_str() == Some(&attempt.attempt_id)
        && binding["generation"].as_i64() == Some(attempt.generation)
        && binding["base_sha"].as_str() == Some(&attempt.base_sha)
        && binding["candidate_sha"].as_str() == Some(candidate_sha)
        && binding["integrated_sha"].as_str() == integrated_sha
        && binding["input_hash"].as_str() == Some(input_digest)
        && binding["contract_version"].as_str() == Some(contract_version)
        && binding["source_hash"]
            .as_str()
            .is_some_and(forgeflow_domain::valid_sha)
        && binding["verification_plan_id"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
        && binding["verification_plan_hash"]
            .as_str()
            .is_some_and(valid_sha256)
}
fn producer_source_content_matches(
    integration: &forgeflow_domain::MergeIntent,
    verification: &serde_json::Value,
    integrated_sha: &str,
    actual: &ProducerSourceContent,
) -> bool {
    let Some(receipt) = integration.receipt.as_ref() else {
        return false;
    };
    actual.algorithm == "forgeflow.source-content.v1"
        && actual.commit_sha == integrated_sha
        && forgeflow_domain::valid_sha(&actual.tree_oid)
        && valid_sha256(&actual.source_sha256)
        && receipt["source_content_algorithm"].as_str() == Some(&actual.algorithm)
        && receipt["source_content_sha256"].as_str() == Some(&actual.source_sha256)
        && receipt["source_tree_oid"].as_str() == Some(&actual.tree_oid)
        && verification["binding"]["source_hash"].as_str() == Some(&actual.tree_oid)
}
/// Materialize bytes only after the store has established durable registration,
/// independent runner evidence, target-ref reachability and actual Git ancestry.
/// Known inputs are checked at the selected base; existing input drift is rejected.
pub fn materialize_producer_inputs(
    task: &TaskCard,
    spec: &TaskSpec,
    approved_manifest_bytes: &[u8],
    proofs: &[ProducerInputEvidence],
    tree: &ProducerInputTree,
) -> Result<ProducerInputMaterialization, PlannerError> {
    use forgeflow_domain::{AttemptState, MergeIntentState};
    let recipe = producer_input_recipe(task, spec, approved_manifest_bytes)?;
    if !forgeflow_domain::valid_sha(&tree.base_sha) {
        return Err(producer_input_error(
            "PRODUCER_INPUT_TREE: actual selected base required",
        ));
    }
    let mut manifest: forgeflow_domain::ContextManifest =
        serde_json::from_slice(approved_manifest_bytes)?;
    let mut expected_git: BTreeSet<_> = manifest.files.iter().map(|f| f.path.clone()).collect();
    for file in &manifest.files {
        if tree.base_inputs.get(&file.path).map(|b| sha256(b)) != Some(file.sha256.clone()) {
            return Err(producer_input_error(format!(
                "INPUT_HASH_DRIFT: approved input {} changed at selected base",
                file.path
            )));
        }
    }
    let mut inputs = Vec::new();
    let mut used_proofs = BTreeSet::new();
    for input in &spec.producer_inputs {
        let matching: Vec<_> = proofs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.producer.task_id == input.producer_task_id
                    && p.producer.task_revision == input.producer_task_revision
                    && p.contract.contract_id == input.contract.contract_id
                    && p.contract.version == input.contract.version
            })
            .collect();
        if matching.len() != 1 {
            return Err(producer_input_error(
                "PRODUCER_INPUT_EVIDENCE: missing or ambiguous exact producer proof",
            ));
        }
        let (proof_index, proof) = matching[0];
        used_proofs.insert(proof_index);
        let p = &proof.producer;
        let a = &proof.attempt;
        let r = &proof.receipt;
        let m = &proof.integration;
        let c = &proof.contract;
        let integrated = m.integrated_sha.as_deref().ok_or_else(|| {
            producer_input_error("PRODUCER_INPUT_EVIDENCE: integrated SHA missing")
        })?;
        let contract_version = format!("{}:{}", input.contract.contract_id, input.contract.version);
        let verification = m
            .receipt
            .as_ref()
            .and_then(|v| v.get("verification"))
            .ok_or_else(|| {
                producer_input_error(
                    "PRODUCER_INPUT_EVIDENCE: final integration verification missing",
                )
            })?;
        let source_content = tree.source_contents.get(integrated).ok_or_else(|| {
            producer_input_error(
                "PRODUCER_INPUT_SOURCE_CONTENT: recomputed integrated content identity missing",
            )
        })?;
        if p.project_id != task.project_id
            || p.input_digest != input.producer_input_digest
            || !p.write_set.iter().any(|w| contains(w, &input.path))
            || a.project_id != task.project_id
            || a.task_id != p.task_id
            || a.task_revision != p.task_revision
            || a.state != AttemptState::Succeeded
            || a.generation < 1
            || a.terminal_at.is_none()
            || r.project_id != task.project_id
            || r.attempt_id != a.attempt_id
            || r.generation != a.generation
            || r.receipt_id.is_empty()
            || r.input_digest != p.input_digest
            || r.candidate_sha.as_deref() != Some(&m.candidate_sha)
            || r.integrated_sha.is_some()
            || r.total == 0
            || r.failed != 0
            || r.skipped != 0
            || r.verifier_id == r.author_id
            || r.verifier_id != r.details["verifier_id"].as_str().unwrap_or("")
            || r.author_id != r.details["author_id"].as_str().unwrap_or("")
            || r.details["total"].as_u64() != Some(r.total)
            || !valid_sha256(&r.artifact.sha256)
            || r.details["log_hash"].as_str() != Some(&r.artifact.sha256)
            || !receipt_binding_matches(
                &r.details,
                a,
                &m.candidate_sha,
                None,
                &p.input_digest,
                &contract_version,
            )
            || m.project_id != task.project_id
            || m.attempt_id != a.attempt_id
            || m.generation != a.generation
            || m.intent_id.is_empty()
            || m.target_ref != "refs/heads/main"
            || !matches!(
                m.state,
                MergeIntentState::Finalized | MergeIntentState::Committed
            )
            || !forgeflow_domain::valid_sha(integrated)
            || !tree.integrated_ancestors.contains(integrated)
            || !producer_source_content_matches(m, verification, integrated, source_content)
            || !receipt_binding_matches(
                verification,
                a,
                &m.candidate_sha,
                Some(integrated),
                &p.input_digest,
                &contract_version,
            )
            || r.details["binding"]["verification_plan_id"]
                != verification["binding"]["verification_plan_id"]
            || r.details["binding"]["verification_plan_hash"]
                != verification["binding"]["verification_plan_hash"]
            || c.project_id != task.project_id
            || c.producer_task_id != p.task_id
            || c.spec_sha256 != input.contract.spec_sha256
            || !c.schema.is_object()
            || sha256(&serde_json::to_vec(&c.schema)?) != c.spec_sha256
            || (!c.source_sha256.is_empty()
                && (!valid_sha256(&c.source_sha256)
                    || c.source_sha256 != source_content.source_sha256))
            || (!spec.isolated_contract_probe
                && (!valid_sha256(&c.source_sha256)
                    || !c.frozen
                    || c.independent_receipt_id.as_deref() != Some(&r.receipt_id)
                    || c.integration_receipt_id.as_deref() != Some(&m.intent_id)
                    || c.required_consumers.is_empty()
                    || c.required_consumers
                        .iter()
                        .any(|id| !c.passing_consumers.contains(id))))
        {
            return Err(producer_input_error(format!(
                "PRODUCER_INPUT_EVIDENCE: registered proof differs from approved producer, integration or contract for {}",
                input.path
            )));
        }
        let accepted_bytes = tree
            .producer_inputs
            .get(integrated)
            .and_then(|paths| paths.get(&input.path))
            .ok_or_else(|| {
                producer_input_error("PRODUCER_INPUT_TREE: accepted producer blob missing")
            })?;
        let selected_bytes = tree.base_inputs.get(&input.path).ok_or_else(|| {
            producer_input_error("PRODUCER_INPUT_TREE: required blob missing at selected base")
        })?;
        let hash = sha256(accepted_bytes);
        if sha256(selected_bytes) != hash {
            return Err(producer_input_error(format!(
                "INPUT_HASH_DRIFT: producer output {} changed after verified integration",
                input.path
            )));
        }
        expected_git.insert(input.path.clone());
        manifest.files.push(forgeflow_domain::ContextFile {
            path: input.path.clone(),
            sha256: hash.clone(),
        });
        inputs.push(MaterializedProducerInput {
            path: input.path.clone(),
            sha256: hash,
            producer_task_id: p.task_id.clone(),
            producer_task_revision: p.task_revision,
            producer_input_digest: p.input_digest.clone(),
            producer_attempt_id: a.attempt_id.clone(),
            generation: a.generation,
            evidence_receipt_id: r.receipt_id.clone(),
            integration_receipt_id: m.intent_id.clone(),
            integrated_sha: integrated.into(),
            dependency_binding_id: input.dependency_binding_id.clone(),
            contract: input.contract.clone(),
        });
    }
    if used_proofs.len() != proofs.len()
        || expected_git != tree.base_inputs.keys().cloned().collect()
    {
        return Err(producer_input_error(
            "PRODUCER_INPUT_TREE: supplied proofs and blob scope must exactly match approved inputs",
        ));
    }
    manifest.files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest_sha256 = sha256(&serde_json::to_vec(&manifest)?);
    Ok(ProducerInputMaterialization {
        recipe_sha256: recipe.digest(),
        recipe,
        base_sha: tree.base_sha.clone(),
        manifest,
        manifest_sha256,
        inputs,
    })
}
/// Compare authority before allowing an unchanged active card into a new Flow version.
/// Only Flow binding, cosmetic row revision and equivalent planning readiness may differ.
/// The old Attempt continues to resolve its original immutable task/context snapshot.
pub fn task_binding_equivalent(
    old: &TaskCard,
    old_context: &CompileContext,
    new: &TaskCard,
    new_context: &CompileContext,
) -> bool {
    let category = |state: TaskPlanningState| match state {
        TaskPlanningState::Deferred => "deferred",
        TaskPlanningState::RemovedFromPlan => "removed",
        _ => "accepted",
    };
    if old.project_id != new.project_id
        || old.task_id != new.task_id
        || old.task_revision != new.task_revision
        || old.title != new.title
        || old.owner_id != new.owner_id
        || old.team_id != new.team_id
        || old.requirement_ids != new.requirement_ids
        || old.read_set != new.read_set
        || old.write_set != new.write_set
        || old.dependencies != new.dependencies
        || old.input_digest != new.input_digest
        || old.resource_request != new.resource_request
        || old.envelope != new.envelope
        || category(old.state) != category(new.state)
    {
        return false;
    }
    let Some(old_spec) = old_context.task_specs.get(&old.task_id) else {
        return false;
    };
    let Some(new_spec) = new_context.task_specs.get(&new.task_id) else {
        return false;
    };
    if digest(old_spec) != digest(new_spec) {
        return false;
    }
    let mut dependency_frontier = old.dependencies.clone();
    let mut checked_dependencies = BTreeSet::new();
    while let Some(id) = dependency_frontier.pop() {
        if !checked_dependencies.insert(id.clone()) {
            continue;
        }
        let a = old_context.task_specs.get(&id);
        let b = new_context.task_specs.get(&id);
        if a.is_none() || b.is_none() || digest(&a) != digest(&b) {
            return false;
        }
        if let Some(spec) = a {
            dependency_frontier.extend(
                spec.dependency_refs
                    .iter()
                    .map(|dependency| dependency.task_id.clone()),
            );
        }
    }
    for id in &old.requirement_ids {
        if old_context.requirement_semantic_digests.get(id).is_none()
            || old_context.requirement_semantic_digests.get(id)
                != new_context.requirement_semantic_digests.get(id)
            || old_spec.requirement_digest_refs.get(id)
                != old_context.requirement_semantic_digests.get(id)
            || new_spec.requirement_digest_refs.get(id)
                != new_context.requirement_semantic_digests.get(id)
        {
            return false;
        }
        let a = old_context
            .requirements
            .iter()
            .find(|r| &r.requirement_id == id);
        let b = new_context
            .requirements
            .iter()
            .find(|r| &r.requirement_id == id);
        if a.is_none() || b.is_none() || digest(&a) != digest(&b) {
            return false;
        }
    }
    let old_owner = old_context
        .owners
        .iter()
        .find(|o| o.owner_id == old.owner_id);
    let new_owner = new_context
        .owners
        .iter()
        .find(|o| o.owner_id == new.owner_id);
    if old_owner.is_none() || new_owner.is_none() || digest(&old_owner) != digest(&new_owner) {
        return false;
    }
    for path in old
        .read_set
        .iter()
        .chain(&old.write_set)
        .chain(&old_spec.mandatory_paths)
        .chain(old_spec.inputs.iter().map(|b| &b.path))
    {
        if old_context.current_inputs.get(path) != new_context.current_inputs.get(path)
            || old_context.resolved_paths.get(path) != new_context.resolved_paths.get(path)
        {
            return false;
        }
    }
    for binding in old_spec
        .contract_consumes
        .iter()
        .chain(&old_spec.contract_produces)
    {
        let a = old_context
            .contracts
            .iter()
            .find(|c| c.contract_id == binding.contract_id && c.version == binding.version);
        let b = new_context
            .contracts
            .iter()
            .find(|c| c.contract_id == binding.contract_id && c.version == binding.version);
        if digest(&a) != digest(&b) {
            let (Some(previous), Some(next)) = (a, b) else {
                return false;
            };
            // Completing the frozen contract proof does not change an already
            // delivered task's stable contract pins. Store must independently
            // match the new frozen snapshot to canonical FROZEN authority.
            if previous.frozen
                || !next.frozen
                || previous.contract_id != next.contract_id
                || previous.version != next.version
                || previous.spec_sha256 != next.spec_sha256
                || previous.source_sha256 != next.source_sha256
                || previous.required_consumers != next.required_consumers
                || !valid_sha256(&next.spec_sha256)
                || !valid_sha256(&next.source_sha256)
                || next.required_consumers.is_empty()
                || next
                    .independent_receipt_id
                    .as_deref()
                    .is_none_or(|id| id.trim().is_empty())
                || next
                    .integration_receipt_id
                    .as_deref()
                    .is_none_or(|id| id.trim().is_empty())
                || previous
                    .independent_receipt_id
                    .as_ref()
                    .is_some_and(|id| next.independent_receipt_id.as_ref() != Some(id))
                || previous
                    .integration_receipt_id
                    .as_ref()
                    .is_some_and(|id| next.integration_receipt_id.as_ref() != Some(id))
                || previous
                    .passing_consumers
                    .iter()
                    .chain(&next.required_consumers)
                    .any(|id| !next.passing_consumers.contains(id))
            {
                return false;
            }
        }
    }
    // A changed source revision is allowed only when every mandatory source input and
    // referenced requirement above preserves the actual pinned identity. Empty snapshots
    // cannot prove that a same-ID source rewrite was harmless.
    if old_context.source_revision != new_context.source_revision {
        // Referenced normalized requirements and functional digests were
        // checked above. Equal authoritative source snapshot pins also prove
        // identity when catalog metadata or unrelated requirements advance;
        // a task need not acquire a new read grant for that metadata.
        for requirement_id in &old.requirement_ids {
            let Some(requirement) = old_context
                .requirements
                .iter()
                .find(|r| &r.requirement_id == requirement_id)
            else {
                return false;
            };
            let artifact_path = format!("source-artifacts/{}.md", requirement.source_document);
            let pinned_source = old_spec.inputs.iter().any(|input| {
                input.producer_task_id.is_none()
                    && valid_sha256(&input.sha256)
                    && (input.path == requirement.source_document || input.path == artifact_path)
                    && old_context.current_inputs.get(&input.path) == Some(&input.sha256)
                    && new_context.current_inputs.get(&input.path) == Some(&input.sha256)
            });
            let catalog_source_pinned =
                [&requirement.source_document, &artifact_path]
                    .iter()
                    .any(|path| {
                        old_context.current_inputs.get(*path).is_some_and(|hash| {
                            valid_sha256(hash)
                                && new_context.current_inputs.get(*path) == Some(hash)
                        })
                    });
            // Retained removed history cannot be admitted. All its task/spec,
            // requirement meaning and previously bound inputs were checked
            // above; an absent metadata source pin grants it no execution.
            let retained_removed = old.state == TaskPlanningState::RemovedFromPlan
                && new.state == TaskPlanningState::RemovedFromPlan;
            if !pinned_source && !catalog_source_pinned && !retained_removed {
                return false;
            }
        }
    }
    true
}
/// Semantic revision identity is stable across checking timestamps, approvals and heartbeats.
pub fn semantic_digest(flow: &FlowRevision, context: &CompileContext) -> String {
    flow_meaning_digest(
        &flow.project_id,
        flow.flow_revision,
        flow.parent_revision,
        &flow.tasks,
        context,
    )
}
fn flow_meaning_digest(
    project_id: &str,
    flow_revision: u64,
    parent_revision: Option<u64>,
    tasks: &[TaskCard],
    context: &CompileContext,
) -> String {
    let task_inputs = tasks
        .iter()
        .map(|task| {
            (
                task.task_id.as_str(),
                (
                    match task.state {
                        TaskPlanningState::Deferred => "deferred",
                        TaskPlanningState::RemovedFromPlan => "removed",
                        _ => "accepted",
                    },
                    context
                        .task_specs
                        .get(&task.task_id)
                        .map(|spec| canonical_task_input_digest(task, spec)),
                    task.envelope.as_ref().map(static_execution_template_digest),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    digest(&(
        FLOW_APPROVAL_DIGEST_ALGORITHM,
        project_id,
        flow_revision,
        parent_revision,
        task_inputs,
        &context.requirements,
        &context.requirement_semantic_digests,
        &context.owners,
        &context.current_inputs,
        &context.resolved_paths,
        &context.contracts,
        &context.source_revision,
    ))
}
/// P0 change preview computes an explicit whole-graph affected closure. It never rewrites
/// old Task/Attempt identities or decides whether an active execution should be revoked.
pub fn diff_flows(
    old: &FlowRevision,
    old_context: &CompileContext,
    new: &FlowRevision,
    new_context: &CompileContext,
    attempts: &[Attempt],
) -> Result<FlowDiff, PlannerError> {
    if old.project_id != new.project_id {
        return Err(PlannerError::InvalidInput(
            "Flow comparison requires the same project".into(),
        ));
    }
    let before = old
        .tasks
        .iter()
        .map(|t| (t.task_id.as_str(), t))
        .collect::<BTreeMap<_, _>>();
    let after = new
        .tasks
        .iter()
        .map(|t| (t.task_id.as_str(), t))
        .collect::<BTreeMap<_, _>>();
    let added_tasks = after
        .keys()
        .filter(|id| !before.contains_key(**id))
        .map(|id| (*id).to_owned())
        .collect::<Vec<_>>();
    let removed_tasks = before
        .keys()
        .filter(|id| !after.contains_key(**id))
        .map(|id| (*id).to_owned())
        .collect::<Vec<_>>();
    let definition = |task: &TaskCard, context: &CompileContext| {
        digest(&(
            &task.owner_id,
            &task.team_id,
            &task.requirement_ids,
            &task.read_set,
            &task.write_set,
            &task.dependencies,
            &task.resource_request,
            context.task_specs.get(&task.task_id),
            task.envelope.as_ref().map(static_execution_template_digest),
            match task.state {
                TaskPlanningState::Deferred => "deferred",
                TaskPlanningState::RemovedFromPlan => "removed",
                _ => "accepted",
            },
        ))
    };
    let changed_tasks = after
        .iter()
        .filter_map(|(id, task)| {
            before
                .get(id)
                .filter(|old_task| {
                    definition(old_task, old_context) != definition(task, new_context)
                })
                .map(|_| (*id).to_owned())
        })
        .collect::<Vec<_>>();
    let old_requirements = old_context
        .requirements
        .iter()
        .map(|r| (r.requirement_id.as_str(), digest(r)))
        .collect::<BTreeMap<_, _>>();
    let new_requirements = new_context
        .requirements
        .iter()
        .map(|r| (r.requirement_id.as_str(), digest(r)))
        .collect::<BTreeMap<_, _>>();
    let changed_requirements = old_requirements
        .keys()
        .chain(new_requirements.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|id| {
            old_requirements.get(id) != new_requirements.get(id)
                || old_context.requirement_semantic_digests.get(*id)
                    != new_context.requirement_semantic_digests.get(*id)
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut impacted = added_tasks
        .iter()
        .chain(&removed_tasks)
        .chain(&changed_tasks)
        .cloned()
        .collect::<BTreeSet<_>>();
    for task in old.tasks.iter().chain(&new.tasks) {
        if task
            .requirement_ids
            .iter()
            .any(|r| changed_requirements.contains(r))
        {
            impacted.insert(task.task_id.clone());
        }
    }
    if old_context.owners.iter().map(digest).collect::<Vec<_>>()
        != new_context.owners.iter().map(digest).collect::<Vec<_>>()
        || old_context.current_inputs != new_context.current_inputs
        || old_context.resolved_paths != new_context.resolved_paths
        || digest(&old_context.contracts) != digest(&new_context.contracts)
    {
        impacted.extend(
            old.tasks
                .iter()
                .chain(&new.tasks)
                .map(|t| t.task_id.clone()),
        );
    }
    let mut successors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for task in old.tasks.iter().chain(&new.tasks) {
        for dep in &task.dependencies {
            successors
                .entry(dep.clone())
                .or_default()
                .insert(task.task_id.clone());
        }
    }
    let mut frontier = impacted.iter().cloned().collect::<Vec<_>>();
    while let Some(id) = frontier.pop() {
        if let Some(next) = successors.get(&id) {
            for successor in next {
                if impacted.insert(successor.clone()) {
                    frontier.push(successor.clone());
                }
            }
        }
    }
    let active_attempt_ids = attempts
        .iter()
        .filter(|attempt| {
            attempt.project_id == old.project_id
                && !attempt.state.is_terminal()
                && impacted.contains(&attempt.task_id)
        })
        .map(|attempt| attempt.attempt_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(FlowDiff {
        project_id: old.project_id.clone(),
        from_revision: old.flow_revision,
        to_revision: new.flow_revision,
        added_tasks,
        removed_tasks,
        changed_tasks,
        changed_requirements,
        impacted_tasks: impacted.into_iter().collect(),
        active_attempt_ids,
        source_changed: old_context.source_revision != new_context.source_revision,
        requires_full_graph_check: true,
    })
}
fn predecessor(ancestor: &str, task: &str, tasks: &BTreeMap<String, &TaskCard>) -> bool {
    let mut seen = BTreeSet::new();
    let mut queue = vec![task.to_owned()];
    while let Some(id) = queue.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(t) = tasks.get(&id) {
            for d in &t.dependencies {
                if d == ancestor {
                    return true;
                }
                queue.push(d.clone())
            }
        }
    }
    false
}
fn cycle_path(tasks: &BTreeMap<String, &TaskCard>) -> Vec<String> {
    let mut colors: BTreeMap<String, u8> = BTreeMap::new();
    for id in tasks.keys() {
        if colors.contains_key(id) {
            continue;
        }
        let mut stack = vec![(id.clone(), 0usize)];
        colors.insert(id.clone(), 1);
        while let Some((node, index)) = stack.last().cloned() {
            let deps = &tasks[&node].dependencies;
            if index >= deps.len() {
                colors.insert(node, 2);
                stack.pop();
                continue;
            }
            stack.last_mut().unwrap().1 += 1;
            let next = &deps[index];
            if !tasks.contains_key(next) {
                continue;
            }
            match colors.get(next) {
                Some(1) => {
                    let p = stack.iter().position(|(n, _)| n == next).unwrap();
                    let mut cycle = stack[p..]
                        .iter()
                        .map(|(n, _)| n.clone())
                        .collect::<Vec<_>>();
                    cycle.push(next.clone());
                    return cycle;
                }
                Some(2) => {}
                _ => {
                    colors.insert(next.clone(), 1);
                    stack.push((next.clone(), 0));
                }
            }
        }
    }
    vec![]
}

pub fn compile(flow: &FlowRevision, context: &CompileContext) -> CheckReport {
    let mut findings = Vec::new();
    let mut add =
        |rule: &str, subject: String, blocked: Vec<String>, evidence: Vec<String>, action: &str| {
            findings.push(Finding {
                finding_id: format!("F-{:05}", findings.len() + 1),
                rule_id: rule.into(),
                severity: Severity::Blocking,
                subject_ref: subject,
                evidence_refs: evidence,
                blocked_tasks: blocked,
                suggested_action: action.into(),
                source_revision: context.source_revision.clone(),
                observed_at: context.observed_at.clone(),
            });
        };
    let mut tasks = BTreeMap::new();
    if context.requirements.is_empty() {
        add(
            "EMPTY_REQUIREMENT_SET",
            "flow.requirements".into(),
            flow.tasks.iter().map(|t| t.task_id.clone()).collect(),
            vec![],
            "Import source requirements with preserved anchors before committing",
        );
    }
    let mut requirement_ids = BTreeSet::new();
    for requirement in &context.requirements {
        if !requirement_ids.insert(requirement.requirement_id.as_str())
            || requirement.requirement_id.is_empty()
            || requirement.source_document.is_empty()
            || requirement.anchor.is_empty()
            || requirement.acceptance.trim().is_empty()
        {
            add(
                "INVALID_REQUIREMENT",
                requirement.requirement_id.clone(),
                vec![],
                vec![],
                "Preserve unique requirement IDs, source, anchor and acceptance",
            );
        }
    }
    for t in &flow.tasks {
        if tasks.insert(t.task_id.clone(), t).is_some() {
            add(
                "DUPLICATE_TASK_ID",
                t.task_id.clone(),
                vec![t.task_id.clone()],
                vec![],
                "Assign unique stable task IDs",
            );
        }
        if t.project_id != flow.project_id || t.flow_revision != flow.flow_revision {
            add(
                "TASK_REVISION_SCOPE",
                t.task_id.clone(),
                vec![t.task_id.clone()],
                vec![],
                "Bind task to this project and Flow revision",
            );
        }
    }
    let mut indegree = BTreeMap::new();
    let mut successors: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, t) in &tasks {
        let mut count = 0;
        let mut deps = BTreeSet::new();
        for d in &t.dependencies {
            if !deps.insert(d) {
                add(
                    "DUPLICATE_DEPENDENCY",
                    id.clone(),
                    vec![id.clone()],
                    vec![d.clone()],
                    "Keep each dependency once",
                );
            }
            if tasks.contains_key(d) {
                count += 1;
                successors.entry(d.clone()).or_default().push(id.clone());
            } else {
                add(
                    "DANGLING_DEPENDENCY",
                    id.clone(),
                    vec![id.clone()],
                    vec![d.clone()],
                    "Add the referenced producer or remove the invalid edge",
                );
            }
        }
        indegree.insert(id.clone(), count);
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::new();
    while let Some(id) = ready.pop_first() {
        order.push(id.clone());
        if let Some(next) = successors.get(&id) {
            for n in next {
                let count = indegree.get_mut(n).unwrap();
                *count -= 1;
                if *count == 0 {
                    ready.insert(n.clone());
                }
            }
        }
    }
    if order.len() != tasks.len() {
        let cycle = cycle_path(&tasks);
        let blocked = indegree
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(id, _)| id.clone())
            .collect();
        add(
            "DEPENDENCY_CYCLE",
            "flow.dependencies".into(),
            blocked,
            cycle,
            "Remove a cycle edge; inspect the supplied actual cycle path",
        );
    }
    let mut coverage: BTreeMap<String, Vec<String>> = context
        .requirements
        .iter()
        .map(|r| (r.requirement_id.clone(), vec![]))
        .collect();
    let requirements_by_id = context
        .requirements
        .iter()
        .map(|r| (r.requirement_id.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    if context.requirement_semantic_digests.len() != requirements_by_id.len()
        || requirements_by_id.keys().any(|id| {
            context
                .requirement_semantic_digests
                .get(*id)
                .is_none_or(|value| !valid_sha256(value))
        })
    {
        add(
            "REQUIREMENT_SEMANTICS_UNQUALIFIED",
            "flow.requirements".into(),
            flow.tasks.iter().map(|task| task.task_id.clone()).collect(),
            vec![],
            "Bind the full authoritative requirement meanings; legacy snapshots require explicit review",
        );
    }
    let owners = context
        .owners
        .iter()
        .map(|o| (o.owner_id.as_str(), o))
        .collect::<BTreeMap<_, _>>();
    for owner in &context.owners {
        if owner
            .root_team_id
            .as_ref()
            .is_none_or(|id| id.trim().is_empty())
        {
            add(
                "OWNER_ROOT_UNBOUND",
                owner.owner_id.clone(),
                flow.tasks
                    .iter()
                    .filter(|task| task.owner_id == owner.owner_id)
                    .map(|task| task.task_id.clone())
                    .collect(),
                vec![],
                "Register an explicit root team for this Owner; legacy names cannot imply authority",
            );
        }
    }
    if owners.len() != context.owners.len() {
        add(
            "DUPLICATE_OWNER_ID",
            "flow.owners".into(),
            flow.tasks.iter().map(|t| t.task_id.clone()).collect(),
            vec![],
            "Register one authoritative territory per stable Owner ID",
        );
    }
    let mut writers: Vec<(&str, &str)> = vec![];
    let mut contract_producers = BTreeMap::<(String, u64), String>::new();
    for (id, t) in &tasks {
        if t.requirement_ids.is_empty()
            && !matches!(
                t.state,
                TaskPlanningState::Deferred | TaskPlanningState::RemovedFromPlan
            )
        {
            add(
                "TASK_REQUIREMENT_MISSING",
                id.clone(),
                vec![id.clone()],
                vec![],
                "Map this finite task to its source requirement before admission",
            );
        }
        for req in &t.requirement_ids {
            match coverage.get_mut(req) {
                Some(v) => {
                    if !matches!(
                        t.state,
                        TaskPlanningState::Deferred | TaskPlanningState::RemovedFromPlan
                    ) {
                        v.push(id.clone())
                    }
                }
                None => add(
                    "DANGLING_REQUIREMENT",
                    id.clone(),
                    vec![id.clone()],
                    vec![req.clone()],
                    "Reference an imported requirement ID",
                ),
            }
        }
        for p in t.read_set.iter().chain(&t.write_set) {
            if normalize_path(p).is_err() {
                add(
                    "UNSAFE_PATH",
                    format!("{id}.path"),
                    vec![id.clone()],
                    vec![p.clone()],
                    "Use a normalized project-relative path",
                );
            }
        }
        for p in &t.write_set {
            let target = context.resolved_paths.get(p).unwrap_or(p);
            let valid = owners.get(t.owner_id.as_str()).is_some_and(|o| {
                normalize_path(target).is_ok()
                    && !o
                        .exclude
                        .iter()
                        .any(|s| overlaps(s, target) || overlaps(s, p))
                    && o.include.iter().any(|s| contains(s, target))
                    && o.include.iter().any(|s| contains(s, p))
            });
            if !valid {
                add(
                    "OWNER_TERRITORY",
                    format!("{id}.write_set"),
                    vec![id.clone()],
                    vec![p.clone(), target.clone()],
                    "Split the task or explicitly revise Owner territory",
                );
            }
            let authorized_roots = owners
                .values()
                .filter(|owner| {
                    !owner.exclude.iter().any(|scope| overlaps(scope, target))
                        && owner.include.iter().any(|scope| contains(scope, target))
                })
                .count();
            if authorized_roots > 1 {
                add(
                    "OWNER_TERRITORY_AMBIGUOUS",
                    format!("{id}.write_set"),
                    vec![id.clone()],
                    vec![target.clone()],
                    "Resolve overlapping root Owner authority with explicit excludes or ownership transfer",
                );
            }
            writers.push((id, target));
        }
        let Some(spec) = context.task_specs.get(id) else {
            add(
                "MISSING_TASK_SPEC",
                id.clone(),
                vec![id.clone()],
                vec![],
                "Provide semantic task outcome, input and verification details",
            );
            continue;
        };
        if spec.requirement_digest_refs.len()
            != t.requirement_ids.iter().collect::<BTreeSet<_>>().len()
            || t.requirement_ids.iter().any(|requirement| {
                spec.requirement_digest_refs.get(requirement).is_none()
                    || spec.requirement_digest_refs.get(requirement)
                        != context.requirement_semantic_digests.get(requirement)
            })
        {
            add(
                "REQUIREMENT_SEMANTIC_BINDING",
                format!("{id}.requirement_digest_refs"),
                vec![id.clone()],
                t.requirement_ids.clone(),
                "Pin every mapped requirement to its complete authoritative semantic digest",
            );
        }
        if let Some(envelope) = &t.envelope {
            if envelope.executor_profile_id != spec.execution_profile
                || envelope.verification_plan_id != spec.verification_plan
                || envelope.write_set != t.write_set
            {
                add(
                    "EXECUTION_TEMPLATE_SPEC_MISMATCH",
                    format!("{id}.envelope"),
                    vec![id.clone()],
                    vec![
                        envelope.executor_profile_id.clone(),
                        envelope.verification_plan_id.clone(),
                    ],
                    "Bind the frozen template to the declared execution profile, verification plan and exact write scope",
                );
            }
        }
        for requirement_id in &t.requirement_ids {
            if let Some(requirement) = requirements_by_id.get(requirement_id.as_str()) {
                let anchor = format!("{}#{}", requirement.source_document, requirement.anchor);
                if !spec.design_anchors.contains(&anchor) {
                    add(
                        "REQUIREMENT_ANCHOR_MISSING",
                        format!("{id}.design_anchors"),
                        vec![id.clone()],
                        vec![anchor],
                        "Bind each mapped requirement to its original source anchor",
                    );
                }
            }
        }
        if spec.outcome.trim().is_empty()
            || spec.design_anchors.is_empty()
            || spec.execution_profile.trim().is_empty()
            || spec.verification_plan.trim().is_empty()
            || spec.rollback_plan.trim().is_empty()
        {
            add(
                "INCOMPLETE_TASK_SPEC",
                id.clone(),
                vec![id.clone()],
                vec![],
                "Fill outcome, design anchors, execution profile, verification and rollback",
            );
        }
        if spec.verification_case_count == 0 {
            add(
                "ZERO_CASE_VERIFICATION",
                format!("{id}.verification_plan"),
                vec![id.clone()],
                vec![spec.verification_plan.clone()],
                "Define positive and negative business verification cases",
            );
        }
        if t.input_digest != canonical_task_input_digest(t, spec) {
            add(
                "CONTEXT_DIGEST_DRIFT",
                format!("{id}.input_digest"),
                vec![id.clone()],
                vec![t.input_digest.clone(), canonical_task_input_digest(t, spec)],
                "Rebuild the immutable context from approved semantic inputs",
            );
        }
        let bindings = spec
            .inputs
            .iter()
            .map(|b| (b.path.as_str(), b))
            .collect::<BTreeMap<_, _>>();
        let producer_paths = spec
            .producer_inputs
            .iter()
            .map(|b| b.path.as_str())
            .collect::<BTreeSet<_>>();
        if bindings.len() != spec.inputs.len()
            || producer_paths.len() != spec.producer_inputs.len()
            || producer_paths.iter().any(|p| bindings.contains_key(p))
        {
            add(
                "DUPLICATE_INPUT_PATH",
                format!("{id}.inputs"),
                vec![id.clone()],
                vec![],
                "Bind each immutable input path exactly once",
            );
        }
        // Derive required inputs from canonical read scope; a self-rehashed manifest cannot delete them.
        let mandatory = t
            .read_set
            .iter()
            .chain(&spec.mandatory_paths)
            .collect::<BTreeSet<_>>();
        for p in mandatory {
            if !bindings.contains_key(p.as_str()) && !producer_paths.contains(p.as_str()) {
                add(
                    "MANDATORY_INPUT_MISSING",
                    format!("{id}.inputs"),
                    vec![id.clone()],
                    vec![p.clone()],
                    "Restore every canonical read and required input binding",
                );
            }
        }
        for b in &spec.inputs {
            if !valid_sha256(&b.sha256) {
                add(
                    "INVALID_INPUT_HASH",
                    format!("{id}.inputs"),
                    vec![id.clone()],
                    vec![b.path.clone()],
                    "Use the SHA256 of actual immutable source bytes",
                );
            }
            if normalize_path(&b.path).is_err() {
                add(
                    "UNSAFE_INPUT_PATH",
                    format!("{id}.inputs"),
                    vec![id.clone()],
                    vec![b.path.clone()],
                    "Use project-relative immutable input paths",
                );
            }
            if let Some(producer) = &b.producer_task_id {
                add(
                    "PRODUCER_INPUT_RECIPE_REQUIRED",
                    format!("{id}.inputs"),
                    vec![id.clone()],
                    vec![b.path.clone(), producer.clone()],
                    "Use an explicit producer_inputs binding; unknown future bytes never have a placeholder hash",
                );
                if !tasks.contains_key(producer)
                    || !predecessor(producer, id, &tasks)
                    || !tasks
                        .get(producer)
                        .is_some_and(|p| p.write_set.iter().any(|s| contains(s, &b.path)))
                {
                    add(
                        "FUTURE_INPUT_PRODUCER",
                        format!("{id}.inputs"),
                        vec![id.clone()],
                        vec![b.path.clone(), producer.clone()],
                        "Bind a producer in the transitive predecessor closure that declares the output",
                    );
                }
            } else if context.current_inputs.get(&b.path) != Some(&b.sha256) {
                add(
                    "INPUT_HASH_DRIFT",
                    format!("{id}.inputs"),
                    vec![id.clone()],
                    vec![b.path.clone(), b.sha256.clone()],
                    "Refresh approved immutable source identity",
                );
            }
        }
        for b in &spec.producer_inputs {
            let producer = tasks.get(&b.producer_task_id);
            let producer_spec = context.task_specs.get(&b.producer_task_id);
            let dependency = spec.dependency_refs.iter().any(|d| {
                d.task_id == b.producer_task_id
                    && d.project_id == flow.project_id
                    && matches!(d.kind, DependencyKind::Integrated)
                    && d.binding_id == b.dependency_binding_id
                    && t.dependencies.contains(&d.task_id)
            });
            if normalize_path(&b.path).is_err()
                || b.producer_task_revision == 0
                || !valid_sha256(&b.producer_input_digest)
                || b.dependency_binding_id.is_empty()
                || !dependency
                || !predecessor(&b.producer_task_id, id, &tasks)
                || !producer.is_some_and(|p| {
                    p.task_revision == b.producer_task_revision
                        && p.input_digest == b.producer_input_digest
                        && p.write_set.iter().any(|w| contains(w, &b.path))
                })
                || !t
                    .read_set
                    .iter()
                    .chain(&spec.mandatory_paths)
                    .any(|p| p == &b.path)
            {
                add(
                    "FUTURE_INPUT_PRODUCER",
                    format!("{id}.producer_inputs"),
                    vec![id.clone()],
                    vec![b.path.clone(), b.producer_task_id.clone()],
                    "Pin the exact declared integrated predecessor revision, semantic input identity and required output path",
                );
            }
            if !spec.contract_consumes.contains(&b.contract)
                || !producer_spec.is_some_and(|s| s.contract_produces.contains(&b.contract))
            {
                add(
                    "PRODUCER_INPUT_CONTRACT",
                    format!("{id}.producer_inputs"),
                    vec![id.clone()],
                    vec![
                        b.path.clone(),
                        format!("{}:{}", b.contract.contract_id, b.contract.version),
                    ],
                    "Bind the exact contract produced by that predecessor and consumed by this task",
                );
            }
        }
        let typed_deps = spec
            .dependency_refs
            .iter()
            .map(|d| d.task_id.as_str())
            .collect::<BTreeSet<_>>();
        for d in &t.dependencies {
            if !typed_deps.contains(d.as_str()) {
                add(
                    "UNTYPED_DEPENDENCY",
                    format!("{id}.dependencies"),
                    vec![id.clone()],
                    vec![d.clone()],
                    "Give this edge integrated, artifact, contract_frozen or gate_pass semantics",
                );
            }
        }
        for d in &spec.dependency_refs {
            if d.project_id != flow.project_id {
                add(
                    "CROSS_PROJECT_DEPENDENCY",
                    format!("{id}.dependencies"),
                    vec![id.clone()],
                    vec![d.project_id.clone(), d.task_id.clone()],
                    "Use an explicit versioned cross-project delivery contract",
                );
            } else if !t.dependencies.contains(&d.task_id) || d.binding_id.is_empty() {
                add(
                    "DEPENDENCY_BINDING",
                    format!("{id}.dependencies"),
                    vec![id.clone()],
                    vec![d.task_id.clone()],
                    "Bind a declared dependency to immutable evidence identity",
                );
            }
        }
        for c in spec.contract_produces.iter().chain(&spec.contract_consumes) {
            if c.contract_id.trim().is_empty() || c.version == 0 || !valid_sha256(&c.spec_sha256) {
                add(
                    "CONTRACT_IDENTITY_INVALID",
                    format!("{id}.contracts"),
                    vec![id.clone()],
                    vec![c.contract_id.clone()],
                    "Pin a stable contract ID, positive version and actual specification SHA256",
                );
            }
        }
        for c in &spec.contract_produces {
            if let Some(previous) =
                contract_producers.insert((c.contract_id.clone(), c.version), id.clone())
            {
                add(
                    "DUPLICATE_CONTRACT_PRODUCER",
                    format!("{id}.contract_produces"),
                    vec![previous, id.clone()],
                    vec![format!("{}@{}", c.contract_id, c.version)],
                    "Assign one finite producer card for each immutable contract version",
                );
            }
        }
        for c in &spec.contract_consumes {
            let snapshot = context
                .contracts
                .iter()
                .find(|s| s.contract_id == c.contract_id && s.version == c.version);
            let valid = snapshot.is_some_and(|s| {
                s.spec_sha256 == c.spec_sha256
                    && valid_sha256(&s.source_sha256)
                    && s.frozen
                    && s.independent_receipt_id
                        .as_ref()
                        .is_some_and(|r| !r.is_empty())
                    && s.integration_receipt_id
                        .as_ref()
                        .is_some_and(|r| !r.is_empty())
                    && !s.required_consumers.is_empty()
                    && s.required_consumers
                        .iter()
                        .all(|r| s.passing_consumers.contains(r))
            });
            if !valid && !spec.isolated_contract_probe {
                add(
                    "CONTRACT_NOT_FROZEN",
                    format!("{id}.contract_consumes"),
                    vec![id.clone()],
                    vec![format!("{}@{}", c.contract_id, c.version)],
                    "Complete producer, all consumer, independent and integration receipts before freezing",
                );
            }
            if spec.isolated_contract_probe
                && !snapshot.is_some_and(|s| s.spec_sha256 == c.spec_sha256)
            {
                add(
                    "CONTRACT_PROBE_IDENTITY",
                    id.clone(),
                    vec![id.clone()],
                    vec![c.contract_id.clone()],
                    "Pin the isolated probe to a known candidate contract identity",
                );
            }
        }
    }
    for r in &context.requirements {
        if coverage.get(&r.requirement_id).is_none_or(Vec::is_empty)
            && r.deferred_reason
                .as_ref()
                .is_none_or(|s| s.trim().is_empty())
        {
            add(
                "REQUIREMENT_UNCOVERED",
                r.requirement_id.clone(),
                vec![],
                vec![format!("{}#{}", r.source_document, r.anchor)],
                "Map to a finite accepted task or explicitly defer with reason",
            );
        }
    }
    writers.sort_by_key(|(id, path)| (*path, *id));
    for i in 0..writers.len() {
        let (a, ap) = writers[i];
        for &(b, bp) in &writers[i + 1..] {
            if !bp.starts_with(ap.trim_end_matches('/')) {
                break;
            }
            if a != b
                && overlaps(ap, bp)
                && !predecessor(a, b, &tasks)
                && !predecessor(b, a, &tasks)
            {
                add(
                    "WRITE_SCOPE_CONFLICT",
                    format!("{a}.write_set"),
                    vec![a.into(), b.into()],
                    vec![ap.into(), bp.into()],
                    "Serialize overlapping writes with a semantic dependency or split exact paths",
                );
            }
        }
    }
    let input_digest = semantic_digest(flow, context);
    CheckReport {
        passed: findings.is_empty(),
        input_digest,
        digest_algorithm: FLOW_APPROVAL_DIGEST_ALGORITHM.into(),
        task_input_digest_algorithm: TASK_INPUT_DIGEST_ALGORITHM.into(),
        topological_order: order,
        coverage,
        findings,
    }
}

/// Produce a new immutable approved version. Persistence and expected-revision CAS belong to Store.
pub fn freeze(
    mut flow: FlowRevision,
    context: &CompileContext,
    approved_by: &str,
    expected_revision: u64,
) -> Result<CompiledFlow, CheckReport> {
    let mut check = compile(&flow, context);
    if flow.revision != expected_revision
        || !matches!(flow.state, FlowState::Draft | FlowState::ReviewRequired)
        || approved_by.trim().is_empty()
    {
        check.passed = false;
        check.findings.push(Finding {
            finding_id: "F-FREEZE".into(),
            rule_id: "FREEZE_REVISION_OR_AUTHORITY".into(),
            severity: Severity::Blocking,
            subject_ref: "flow".into(),
            evidence_refs: vec![],
            blocked_tasks: flow.tasks.iter().map(|t| t.task_id.clone()).collect(),
            suggested_action: "Review the current editable revision and supply approval identity"
                .into(),
            source_revision: context.source_revision.clone(),
            observed_at: context.observed_at.clone(),
        });
    }
    if !check.passed {
        return Err(check);
    }
    let semantic_digest = check.input_digest.clone();
    flow.state = FlowState::Committed;
    flow.approved_by = Some(approved_by.into());
    flow.input_digest = semantic_digest.clone();
    flow.revision += 1;
    for t in &mut flow.tasks {
        if matches!(
            t.state,
            TaskPlanningState::Planned | TaskPlanningState::NeedsReview
        ) {
            t.state = TaskPlanningState::ReadyForAdmission;
        }
    }
    Ok(CompiledFlow {
        flow,
        check,
        semantic_digest,
    })
}
