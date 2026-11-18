use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub actor_id: String,
    pub idempotency_key: String,
    pub project_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub flow_revision: u64,
    pub policy_revision: u64,
    pub input_digest: String,
    pub worker_id: String,
    pub lease_seconds: u32,
    pub envelope: ExecutionEnvelope,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionReceipt {
    pub operation_id: String,
    pub attempt: Attempt,
    pub envelope: ExecutionEnvelope,
    pub replayed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionRequest {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub expected_state: AttemptState,
    pub next_state: AttemptState,
    pub reason: String,
    pub receipt: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub lease_seconds: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelRequest {
    pub actor_id: String,
    pub idempotency_key: String,
    pub project_id: String,
    pub attempt_id: String,
    pub expected_revision: u64,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandReceipt {
    pub operation_id: String,
    pub status: String,
    pub object_id: String,
    pub revision: u64,
    pub replayed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopReceipt {
    pub project_id: String,
    pub attempt_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub process_exit_confirmed: bool,
    pub evidence: Value,
}
/// Owner closes only the proven-stopped author. Every existing resource and
/// unknown model custody reservation remains charged to its original identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseAuthorRetainCustodyRequest {
    pub project_id: String,
    pub attempt_id: String,
    pub expected_revision: u64,
    pub observation_event_id: String,
    pub reason: String,
}
/// Recover local capacity from a fenced, terminal author with a trusted empty
/// physical pool. Provider reservations and unknown usage remain unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseStoppedPhysicalResourcesRequest {
    pub project_id: String,
    pub attempt_id: String,
    pub expected_revision: u64,
    pub observation_event_id: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandIdentity {
    pub actor_id: String,
    pub idempotency_key: String,
}
/// Registered planning is not an executable Flow and cannot issue a lease.
/// The control plane binds requirement and input identities when importing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningCardRegistration {
    pub task: TaskCard,
    /// TaskSpec is validated by the planning consumer, avoiding a domain dependency.
    pub spec: Value,
    #[serde(default)]
    pub metadata: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningCatalogRegistration {
    pub schema_version: String,
    pub catalog_id: String,
    pub source_revision: String,
    pub expected_card_count: u64,
    pub expected_role_count: u64,
    #[serde(default)]
    pub expected_edge_count: Option<u64>,
    pub cards: Vec<PlanningCardRegistration>,
    pub parents: Vec<Value>,
    pub roster: Vec<Value>,
    #[serde(default)]
    pub metadata: Value,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativePanelActionKind {
    Prepare,
    Start,
    Pause,
    Replan,
    Retry,
    Cancel,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePanelActionRequest {
    pub action: NativePanelActionKind,
    pub config_sha256: String,
    pub alignment_sha256: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub attempt_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintRequirement {
    pub requirement_id: String,
    pub title: String,
    pub source_anchor: String,
    pub outcome: String,
    pub scope: String,
    pub acceptance: Vec<String>,
    pub priority: i32,
    pub weight: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintTeam {
    pub team_id: String,
    pub parent_team_id: Option<String>,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintTerritory {
    pub owner_id: String,
    pub root_team_id: Option<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintRole {
    pub role_id: String,
    pub owner_id: String,
    pub team_id: String,
    pub parent_role_id: Option<String>,
    pub preset_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintInput {
    pub path: String,
    pub producer_task_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintDependency {
    pub task_id: String,
    pub kind: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintSpec {
    pub outcome: String,
    pub design_anchors: Vec<String>,
    pub mandatory_paths: Vec<String>,
    pub input_refs: Vec<NativeBlueprintInput>,
    pub dependency_refs: Vec<NativeBlueprintDependency>,
    pub contract_produces: Vec<String>,
    pub contract_consumes: Vec<String>,
    pub rollback_plan: String,
    pub known_unknowns: Vec<String>,
    pub not_proven: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintCard {
    pub task_id: String,
    pub title: String,
    pub owner_id: String,
    pub team_id: String,
    pub role_id: String,
    pub requirement_ids: Vec<String>,
    pub read_set: Vec<String>,
    pub write_set: Vec<String>,
    pub dependencies: Vec<String>,
    pub resource_request: ResourceVector,
    pub spec: NativeBlueprintSpec,
    pub execution_profile_ref: String,
    pub resource_profile_ref: String,
    pub model_route_ref: String,
    pub parent_task: String,
    pub phase: String,
    pub source_card: Value,
    pub source_card_sha256: String,
    pub source_original_card_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintSource {
    pub project_id: String,
    pub catalog_id: String,
    pub catalog_revision: u64,
    pub source_revision: String,
    pub catalog_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprint {
    pub schema_version: String,
    pub blueprint_id: String,
    pub title: String,
    pub exported_at: String,
    pub source: NativeBlueprintSource,
    pub requirements: Vec<NativeBlueprintRequirement>,
    pub teams: Vec<NativeBlueprintTeam>,
    pub owner_territories: Vec<NativeBlueprintTerritory>,
    pub roles: Vec<NativeBlueprintRole>,
    pub cards: Vec<NativeBlueprintCard>,
    pub parents: Vec<Value>,
    pub metadata: Value,
    pub execution_rights_granted: bool,
    pub runtime_bindings_exported: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintPathRule {
    pub source_prefix: String,
    pub target_prefix: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintMapping {
    pub target_catalog_id: String,
    pub requirement_ids: std::collections::BTreeMap<String, String>,
    pub team_ids: std::collections::BTreeMap<String, String>,
    pub owner_ids: std::collections::BTreeMap<String, String>,
    pub task_ids: std::collections::BTreeMap<String, String>,
    pub role_ids: std::collections::BTreeMap<String, String>,
    pub preset_ids: std::collections::BTreeMap<String, String>,
    pub path_rules: Vec<NativeBlueprintPathRule>,
    pub executor_profile_ids: std::collections::BTreeMap<String, String>,
    pub resource_profile_ids: std::collections::BTreeMap<String, String>,
    pub model_route_ids: std::collections::BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintAuthority {
    pub project_revision: u64,
    pub requirement_revisions: std::collections::BTreeMap<String, u64>,
    pub team_revisions: std::collections::BTreeMap<String, u64>,
    pub owner_revisions: std::collections::BTreeMap<String, u64>,
    pub catalog_revision: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlueprintPreviewRequest {
    pub blueprint: NativeBlueprint,
    pub mapping: NativeBlueprintMapping,
    pub expected_authority: NativeBlueprintAuthority,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CatalogCommand {
    NativeConfiguration {
        project_id: String,
        command: NativeConfigurationCommand,
    },
    AuthorizeRetainedCandidateReview {
        project_id: String,
        binding: serde_json::Value,
    },
    Decision(DecisionCommand),
    Release(ReleaseCommand),
    CreateProject(Project),
    UpdateProject {
        project: Project,
        expected_revision: u64,
    },
    CreateRequirement(Requirement),
    ImportRequirements {
        project_id: String,
        source_id: String,
        source: Value,
        requirements: Vec<Requirement>,
    },
    UpdateRequirement {
        requirement: Requirement,
        expected_revision: u64,
    },
    CreateTeam(Team),
    UpdateTeam {
        team: Team,
        expected_revision: u64,
    },
    ChangeQueuePriority {
        project_id: String,
        task_id: String,
        priority: i32,
        expected_revision: u64,
    },
    EnqueueTask {
        project_id: String,
        task_id: String,
        expected_revision: u64,
        worker_id: String,
        priority: i32,
        lease_seconds: u32,
        worker_scope_id: String,
        scope_ids: Vec<String>,
    },
    PutFlow {
        flow: FlowRevision,
        expected_revision: Option<u64>,
        context: Option<Value>,
    },
    PutFlowFromParent {
        flow: FlowRevision,
        expected_revision: Option<u64>,
        context: Value,
        parent_flow_revision: u64,
        parent_expected_revision: u64,
        expected_source_revision: String,
    },
    CommitFlow {
        project_id: String,
        flow_revision: u64,
        expected_revision: u64,
        approved_by: String,
    },
    PutDocument {
        project_id: String,
        collection: String,
        id: String,
        expected_revision: Option<u64>,
        value: Value,
    },
    RegisterPlanningCatalog {
        project_id: String,
        expected_revision: Option<u64>,
        catalog: PlanningCatalogRegistration,
    },
    RegisterNativePanelAction {
        project_id: String,
        requested_by: String,
        request_id: String,
        expected_model: String,
        catalog_id: String,
        expected_card_count: u64,
        request: NativePanelActionRequest,
    },
    SettleNativePanelAction {
        project_id: String,
        action_id: String,
        expected_revision: u64,
        status: String,
        result: Value,
    },
    PreviewNativeBlueprint {
        project_id: String,
        requested_by: String,
        request: NativeBlueprintPreviewRequest,
    },
    ImportNativeBlueprint {
        project_id: String,
        preview_id: String,
        expected_revision: u64,
        review_sha256: String,
        approved_by: String,
    },
    AcceptMilestone {
        project_id: String,
        milestone_id: String,
        expected_revision: u64,
        baseline_version: u64,
    },
    PutArtifact {
        project_id: String,
        id: String,
        path: String,
        sha256: String,
        kind: String,
        bytes: u64,
    },
    RegisterInputSnapshots {
        project_id: String,
        snapshots: Vec<Value>,
    },
    PutResourcePolicy {
        policy: ResourcePolicy,
        expected_revision: Option<u64>,
    },
}

/// Owner-reviewed native configuration versions; never execution state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum NativeConfigurationCommand {
    Save {
        draft_id: String,
        expected_revision: Option<u64>,
        base_config_sha256: String,
        spec: Value,
        requested_by: String,
    },
    Preview {
        draft_id: String,
        expected_revision: u64,
        base_config_sha256: String,
        spec_sha256: String,
        review: Value,
    },
    Publish {
        draft_id: String,
        expected_revision: u64,
        review_sha256: String,
        profile: Value,
        #[serde(default, skip_serializing_if = "Value::is_null")]
        resource_profile: Value,
        approved_by: String,
    },
    Activate {
        draft_id: String,
        expected_revision: u64,
        receipt: Value,
        resource_policies: Vec<ResourcePolicy>,
        activated_by: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub operation_id: String,
    pub value: Value,
    pub replayed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegisterRequest {
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub executor_profile_ids: Vec<String>,
    pub worker_id: String,
    pub boot_id: String,
    pub capabilities: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeatRequest {
    pub worker_id: String,
    pub boot_id: String,
    pub active_attempt_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptControl {
    pub valid: bool,
    pub cancel_requested: bool,
    pub lease_expires_at: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerEvent {
    pub event_id: String,
    pub project_id: String,
    pub attempt_id: String,
    pub lease_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub kind: String,
    pub payload: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub event_id: String,
    pub project_id: String,
    pub attempt_id: String,
    pub lease_id: String,
    pub generation: i64,
    pub worker_id: String,
    pub evidence: Value,
    pub outcome: ExecutorOutcome,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeContractRequest {
    pub actor_id: String,
    pub idempotency_key: String,
    pub project_id: String,
    pub contract_id: String,
    pub version: u64,
    pub expected_revision: u64,
    pub producer_receipt_id: String,
    pub consumer_receipt_ids: Vec<String>,
}
