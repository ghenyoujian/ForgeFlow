//! Authenticated control-plane HTTP adapter. PostgreSQL commands remain the authority.
mod agent_network;
pub mod auth;
mod author_custody;
mod capsules;
mod catalog;
mod collaboration;
mod decisions;
mod ecp_accounts;
mod ecp_bot_routes;
mod ecp_collaboration;
mod ecp_connectors;
mod ecp_identity;
mod ecp_messaging;
mod ecp_registry;
mod ecp_resources;
mod generation;
mod handoff;
mod maintenance;
mod native_blueprints;
mod native_configuration;
mod native_models;
mod native_panel;
mod operations;
mod planning;
mod project_contracts;
mod recovery;
mod releases;
mod templates;
mod tutorial;
mod worker_dispatch;
mod workers;
mod workspaces;
use auth::{Auth, Principal};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use chrono::Utc;
use forgeflow_domain::*;
use forgeflow_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub auth: Auth,
    pub data_root: PathBuf,
    pub console_dir: PathBuf,
    pub gateway: Option<Arc<forgeflow_gateway::PgRequestAuthority>>,
    pub native_gateway: Option<forgeflow_gateway::GatewayState>,
}
pub type App = Arc<AppState>;
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub DomainError);
impl ApiError {
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self(status, DomainError::new(code, message))
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}
impl From<forgeflow_store::StoreError> for ApiError {
    fn from(error: forgeflow_store::StoreError) -> Self {
        match error {
            forgeflow_store::StoreError::Domain(domain) => {
                let status = if domain.code == "FORBIDDEN" {
                    StatusCode::FORBIDDEN
                } else if domain.code == "NOT_FOUND" {
                    StatusCode::NOT_FOUND
                } else if domain.code == "SESSION_REVOKED" {
                    StatusCode::UNAUTHORIZED
                } else if domain.code == "SNAPSHOT_CHANGED"
                    || domain.code.contains("CONFLICT")
                    || domain.code.contains("STALE")
                    || domain.code.contains("CAPACITY")
                    || domain.code.contains("UNSATISFIED")
                    || domain.code.contains("ESCALATION")
                {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::UNPROCESSABLE_ENTITY
                };
                Self(status, domain)
            }
            forgeflow_store::StoreError::Database(error) => {
                tracing::error!(%error,"database operation failed");
                if let Some(database) = error.as_database_error() {
                    match database.code().as_deref() {
                        Some("23503") => {
                            return Self::new(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                "REFERENCE_NOT_FOUND",
                                "referenced team, project or object does not exist",
                            );
                        }
                        Some("23505") => {
                            return Self::new(
                                StatusCode::CONFLICT,
                                "OBJECT_EXISTS",
                                "an object with this identity already exists",
                            );
                        }
                        Some("23514") => {
                            return Self::new(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                "VALIDATION_ERROR",
                                "value violates an authoritative data invariant",
                            );
                        }
                        _ => {}
                    }
                }
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "AUTHORITY_UNAVAILABLE",
                    "database authority is temporarily unavailable",
                )
            }
            forgeflow_store::StoreError::Json(error) => {
                tracing::error!(%error,"stored contract decoding failed");
                Self::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "CONTRACT_INVALID",
                    "data does not match the frozen schema",
                )
            }
            forgeflow_store::StoreError::Migration(error) => {
                tracing::error!(%error,"database migration failed");
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SCHEMA_UNAVAILABLE",
                    "database schema requires operator recovery",
                )
            }
        }
    }
}
pub type ApiResult<T> = Result<Json<T>, ApiError>;
pub fn view(data: impl Serialize) -> Json<Value> {
    view_from(data, "postgres")
}
pub fn view_from(data: impl Serialize, source: &str) -> Json<Value> {
    let data = serde_json::to_value(data).expect("query DTO serializable");
    let revision = data.get("revision").and_then(Value::as_u64);
    Json(
        json!({"data":data,"read_model_version":revision,"observed_at":Utc::now(),"source":source,"next_cursor":null}),
    )
}

pub fn identity(headers: &HeaderMap, principal: &Principal) -> Result<CommandIdentity, ApiError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 200)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "IDEMPOTENCY_KEY_REQUIRED",
                "Idempotency-Key is required for authority commands",
            )
        })?;
    Ok(CommandIdentity {
        actor_id: principal.actor_id.clone(),
        idempotency_key: key.into(),
    })
}
pub async fn command(
    state: &App,
    headers: &HeaderMap,
    principal: &Principal,
    cmd: CatalogCommand,
) -> ApiResult<Value> {
    let receipt = state
        .store
        .execute_command(identity(headers, principal)?, cmd)
        .await?;
    Ok(Json(
        json!({"data":receipt.value,"operation_id":receipt.operation_id,"replayed":receipt.replayed,"request_id":headers.get("x-request-id").and_then(|v|v.to_str().ok()),"source":"postgres"}),
    ))
}

/// Online maintenance exposes only custody inspection and physical recovery.
/// It shares canonical Store transactions with the running control plane.
pub fn physical_recovery_router(state: App) -> Router {
    let protected = Router::new()
        .route(
            "/attempts/{attempt}/author-custody",
            get(author_custody::status),
        )
        .route(
            "/attempts/{attempt}/release-stopped-physical-resources",
            post(author_custody::release_physical),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            workspaces::guard,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.auth.clone(),
            auth::guard,
        ));
    Router::new()
        .nest("/api/v1", protected.fallback(api_missing))
        .with_state(state)
}

pub fn router(state: App) -> Router {
    let protected = Router::new()
        .route(
            "/account",
            get(workspaces::account).patch(workspaces::update_account),
        )
        .route("/account/password", post(workspaces::password))
        .route(
            "/workspaces",
            get(workspaces::list).post(workspaces::create),
        )
        .route("/workspaces/{workspace}/members", get(workspaces::members))
        .route(
            "/workspaces/{workspace}/members/{member}",
            axum::routing::patch(workspaces::change_member),
        )
        .route(
            "/workspaces/{workspace}/invitations",
            get(workspaces::invitations).post(workspaces::invite),
        )
        .route(
            "/workspaces/{workspace}/invitations/{invitation}/revoke",
            post(workspaces::revoke),
        )
        .route(
            "/workspaces/{workspace}/principals",
            get(ecp_identity::principals),
        )
        .route(
            "/workspaces/{workspace}/capability-grants",
            get(ecp_identity::grants).post(ecp_identity::create_grant),
        )
        .route(
            "/workspaces/{workspace}/capability-grants/{grant}/revoke",
            post(ecp_identity::revoke_grant),
        )
        .route(
            "/workspaces/{workspace}/registry",
            get(ecp_registry::snapshot),
        )
        .route(
            "/workspaces/{workspace}/agent-registry",
            post(ecp_registry::register),
        )
        .route(
            "/workspaces/{workspace}/executor-profiles",
            post(ecp_registry::freeze_profile),
        )
        .route(
            "/workspaces/{workspace}/resource-profiles",
            post(ecp_resources::create_profile),
        )
        .route(
            "/workspaces/{workspace}/budget-reservations",
            post(ecp_resources::reserve_budget),
        )
        .route(
            "/workspaces/{workspace}/cost-ledger",
            post(ecp_resources::record_cost),
        )
        .route(
            "/workspaces/{workspace}/lease-revocations",
            post(ecp_resources::revoke_lease),
        )
        .route(
            "/workspaces/{workspace}/conversations",
            post(ecp_messaging::create_conversation),
        )
        .route(
            "/conversations/{conversation}/threads",
            post(ecp_messaging::create_thread),
        )
        .route(
            "/conversations/{conversation}/messages",
            get(ecp_messaging::list_messages).post(ecp_messaging::send_message),
        )
        .route(
            "/deliveries/{delivery}/receipts",
            post(ecp_messaging::receipt),
        )
        .route(
            "/conversations/{conversation}/checkpoint",
            post(ecp_messaging::checkpoint),
        )
        .route(
            "/conversations/{conversation}/revoke",
            post(ecp_messaging::revoke_conversation),
        )
        .route(
            "/deliveries/{delivery}/claim",
            post(ecp_messaging::claim_delivery),
        )
        .route(
            "/deliveries/{delivery}/failure",
            post(ecp_messaging::fail_delivery),
        )
        .route(
            "/workspaces/{workspace}/assignments",
            post(ecp_collaboration::create_assignment),
        )
        .route(
            "/workspaces/{workspace}/assignments/{assignment}/accept",
            post(ecp_collaboration::accept_assignment),
        )
        .route(
            "/workspaces/{workspace}/assignments/{assignment}/proposals",
            post(ecp_collaboration::create_proposal),
        )
        .route(
            "/workspaces/{workspace}/proposals/{proposal}/reviews",
            post(ecp_collaboration::create_review),
        )
        .route(
            "/workspaces/{workspace}/proposals/{proposal}/decisions",
            post(ecp_collaboration::create_decision),
        )
        .route(
            "/workspaces/{workspace}/assignments/{assignment}/escalations",
            post(ecp_collaboration::create_assignment_escalation),
        )
        .route(
            "/workspaces/{workspace}/proposals/{proposal}/escalations",
            post(ecp_collaboration::create_proposal_escalation),
        )
        .route("/invitations/accept", post(workspaces::accept))
        .route(
            "/projects/{project}/agent-network/integrations",
            get(agent_network::integrations).post(agent_network::connect),
        )
        .route(
            "/projects/{project}/agent-network/integrations/{integration}/revoke",
            post(agent_network::revoke),
        )
        .route(
            "/projects/{project}/agent-network/integrations/{integration}/sessions",
            post(agent_network::renew),
        )
        .route(
            "/projects/{project}/agent-network/agents",
            get(agent_network::agents).post(agent_network::register),
        )
        .route(
            "/projects/{project}/agent-network/messages",
            get(agent_network::messages).post(agent_network::send),
        )
        .route(
            "/projects/{project}/agent-network/messages/{message}/receipts",
            post(agent_network::acknowledge),
        )
        .route(
            "/projects/{project}/tutorial/personal-site",
            post(tutorial::create_plan),
        )
        .route("/project-probes", post(catalog::probe_repository))
        .route(
            "/projects/{project}/contract-versions",
            get(catalog::contract_versions).post(catalog::put_contract_version),
        )
        .route("/me", get(me))
        .route(
            "/projects/{project}/releases",
            get(releases::list).post(releases::draft),
        )
        .route("/projects/{project}/phases", get(releases::phases))
        .route(
            "/projects/{project}/releases/{release}",
            get(releases::detail),
        )
        .route(
            "/projects/{project}/releases/{release}/candidates",
            post(releases::candidate),
        )
        .route(
            "/projects/{project}/releases/{release}/acceptances",
            post(releases::accept),
        )
        .route(
            "/projects/{project}/releases/{release}/exports",
            get(releases::exports).post(releases::export),
        )
        .route(
            "/projects/{project}/releases/{release}/bundle",
            get(releases::bundle),
        )
        .route(
            "/projects/{project}/releases/{release}/archives",
            post(releases::archive),
        )
        .route(
            "/projects/{project}/releases/{release}/reopenings",
            post(releases::reopen),
        )
        .route(
            "/projects/{project}/releases/{release}/manifest",
            get(releases::manifest),
        )
        .route("/decisions", get(decisions::global_list))
        .route(
            "/projects/{project}/decisions",
            get(decisions::list).post(decisions::create),
        )
        .route(
            "/projects/{project}/decisions/{decision}",
            get(decisions::detail),
        )
        .route(
            "/projects/{project}/decisions/{decision}/acknowledgments",
            post(decisions::acknowledge),
        )
        .route(
            "/projects/{project}/decisions/{decision}/deferrals",
            post(decisions::defer),
        )
        .route(
            "/projects/{project}/decisions/{decision}/resolutions",
            post(decisions::resolve),
        )
        .route("/logout", post(logout))
        .route(
            "/projects",
            get(catalog::projects).post(catalog::create_project),
        )
        .route(
            "/projects/{project}",
            get(catalog::project).patch(catalog::update_project),
        )
        .route(
            "/projects/{project}/requirements",
            get(catalog::requirements).post(catalog::create_requirement),
        )
        .route(
            "/projects/{project}/requirements/{requirement}",
            axum::routing::patch(catalog::update_requirement),
        )
        .route(
            "/projects/{project}/teams",
            get(catalog::teams).post(catalog::create_team),
        )
        .route("/projects/{project}/snapshot", get(catalog::snapshot))
        .route("/projects/{project}/planning-inputs", get(planning::inputs))
        .route(
            "/projects/{project}/planning-overview",
            get(planning::overview),
        )
        .route(
            "/projects/{project}/assignment-context",
            get(planning::assignment_context),
        )
        .route(
            "/projects/{project}/planning-scenarios",
            post(planning::scenario),
        )
        .route(
            "/projects/{project}/task-estimates",
            post(planning::estimate),
        )
        .route(
            "/projects/{project}/channel-pool",
            get(handoff::read_pool).post(handoff::configure_pool),
        )
        .route(
            "/projects/{project}/channel-pool/drain",
            post(handoff::drain_pool),
        )
        .route(
            "/projects/{project}/channel-pool/end",
            post(handoff::finish_pool),
        )
        .route(
            "/projects/{project}/event-cursor",
            get(catalog::event_cursor),
        )
        .route(
            "/projects/{project}/integration-queue",
            get(catalog::integration_queue),
        )
        .route(
            "/projects/{project}/owners",
            get(catalog::owner_territories).post(catalog::put_owner),
        )
        .route(
            "/projects/{project}/queue-entries/{task}",
            axum::routing::patch(catalog::queue_priority),
        )
        .route(
            "/projects/{project}/queue-entries",
            get(catalog::queue_entries).post(catalog::enqueue),
        )
        .route(
            "/projects/{project}/teams/{team}",
            axum::routing::patch(catalog::update_team),
        )
        .route("/projects/{project}/tasks", get(planning::task_list))
        .route("/projects/{project}/tasks/{task}", get(catalog::task))
        .route("/projects/{project}/flows", get(catalog::flows))
        .route(
            "/projects/{project}/flows/latest",
            get(catalog::latest_flow),
        )
        .route(
            "/projects/{project}/flow-generations",
            post(generation::generate),
        )
        .route(
            "/projects/{project}/flow-revisions",
            // Large reviewed DAGs include immutable envelopes and compile context.
            // Keep this increase local; other JSON routes retain Axum's default limit.
            post(catalog::put_flow).layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        .route(
            "/projects/{project}/flow-checks",
            post(catalog::check_flow_draft).layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        .route(
            "/projects/{project}/flows/{revision}",
            get(catalog::project_flow),
        )
        .route("/flows/{flow}", get(catalog::flow))
        .route("/flows/{flow}/context", get(catalog::flow_context))
        .route(
            "/flows/{flow}/context/current",
            get(catalog::current_flow_context),
        )
        .route(
            "/flows/{flow}/tasks/{task}/execution-templates",
            post(templates::bind),
        )
        .route("/flows/{flow}/checks", post(catalog::check_flow))
        .route("/flows/{flow}/commit", post(catalog::commit_flow))
        .route("/projects/{project}/attempts", get(catalog::attempts))
        .route("/operations/{operation}", get(operations::get))
        .route("/projects/{project}/operations", get(operations::list))
        .route(
            "/projects/{project}/native-panel/actions",
            get(native_panel::list).post(native_panel::request),
        )
        .route(
            "/projects/{project}/native-panel/configuration",
            get(native_configuration::context),
        )
        .route(
            "/projects/{project}/execution-configuration",
            get(native_configuration::owner_context),
        )
        .route(
            "/projects/{project}/execution-configuration/drafts",
            get(native_configuration::owner_list)
                .post(native_configuration::owner_save)
                .layer(DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route(
            "/projects/{project}/execution-configuration/validations",
            post(native_configuration::owner_validate)
                .layer(DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route(
            "/projects/{project}/native-panel/configuration/drafts",
            get(native_configuration::list).post(native_configuration::save),
        )
        .route(
            "/projects/{project}/native-panel/configuration/drafts/{draft}/preview",
            post(native_configuration::preview),
        )
        .route(
            "/projects/{project}/native-panel/configuration/drafts/{draft}/publish",
            post(native_configuration::publish),
        )
        .route(
            "/projects/{project}/native-panel/configuration/drafts/{draft}/activate",
            post(native_configuration::activate),
        )
        .route(
            "/projects/{project}/native-panel/open",
            get(native_panel::open),
        )
        .route(
            "/projects/{project}/native-panel/observations",
            get(native_panel::observations),
        )
        .route(
            "/projects/{project}/native-panel/scheduling",
            get(native_panel::scheduling),
        )
        .route(
            "/projects/{project}/native-panel/retry-policy/{task}",
            get(native_panel::retry_policy),
        )
        .route(
            "/projects/{project}/native-panel/candidate-review-sources/{source_attempt_id}",
            get(operations::candidate_review_source),
        )
        .route(
            "/projects/{project}/native-panel/candidate-reviews",
            post(operations::candidate_review),
        )
        .route(
            "/projects/{project}/native-panel/candidate-acceptances",
            get(operations::candidate_acceptances),
        )
        .route(
            "/projects/{project}/native-panel/blueprint-import-context",
            get(native_blueprints::context),
        )
        .route(
            "/projects/{project}/native-panel/blueprint-source",
            get(native_blueprints::source),
        )
        .route(
            "/projects/{project}/native-panel/blueprint-previews",
            post(native_blueprints::preview).layer(DefaultBodyLimit::max(128 * 1024 * 1024)),
        )
        .route(
            "/projects/{project}/native-panel/blueprint-reviews/{review}/import",
            post(native_blueprints::import),
        )
        .route("/attempts/{attempt}/verify", post(operations::verify))
        .route(
            "/attempts/{attempt}/verify-and-integrate",
            post(operations::verify_integrate),
        )
        .route("/attempts/{attempt}", get(catalog::attempt))
        .route("/attempts/{attempt}/cancel", post(catalog::cancel))
        .route(
            "/attempts/{attempt}/author-stop-observation",
            post(author_custody::observe),
        )
        .route(
            "/attempts/{attempt}/close-author-retain-custody",
            post(author_custody::close),
        )
        .route(
            "/attempts/{attempt}/author-custody",
            get(author_custody::status),
        )
        .route(
            "/attempts/{attempt}/release-stopped-physical-resources",
            post(author_custody::release_physical),
        )
        .route("/projects/{project}/admissions", post(catalog::admit))
        .route(
            "/projects/{project}/evidence",
            get(catalog::evidence).post(catalog::record_evidence),
        )
        .route(
            "/projects/{project}/resources",
            get(catalog::resources).post(catalog::put_policy),
        )
        .route("/projects/{project}/events", get(events))
        .route("/events", get(events_query))
        .route(
            "/projects/{project}/documents/{collection}",
            get(catalog::documents)
                .post(catalog::put_document)
                .layer(DefaultBodyLimit::max(128 * 1024 * 1024)),
        )
        .route(
            "/projects/{project}/documents/{collection}/{document}",
            get(catalog::document),
        )
        .route(
            "/projects/{project}/source-imports",
            post(catalog::import_source),
        )
        .route(
            "/projects/{project}/sources/{source}",
            get(catalog::get_source),
        )
        .route(
            "/projects/{project}/sources",
            get(catalog::sources).post(catalog::put_source),
        )
        .route(
            "/projects/{project}/contracts",
            get(catalog::contracts).post(catalog::put_contract),
        )
        .route("/projects/{project}/findings", get(catalog::findings))
        .route(
            "/projects/{project}/milestones",
            get(catalog::milestones).post(catalog::put_milestone),
        )
        .route(
            "/projects/{project}/milestones/{milestone}/accept",
            post(catalog::accept_milestone),
        )
        .route(
            "/projects/{project}/schedule",
            get(catalog::schedule).post(catalog::put_schedule),
        )
        .route("/workers/register", post(workers::register))
        .route("/workers/{worker}/heartbeat", post(workers::heartbeat))
        .route("/workers/{worker}/claim", post(workers::claim))
        .route(
            "/workers/{worker}/dispatch-events",
            get(worker_dispatch::events),
        )
        .route("/attempts/{attempt}/control", get(workers::control))
        .route("/attempts/{attempt}/bindings", get(workers::bindings))
        .route(
            "/attempts/{attempt}/execution-bindings",
            get(workers::bindings),
        )
        .route(
            "/attempts/{attempt}/heartbeat",
            post(workers::lease_heartbeat),
        )
        .route(
            "/attempts/{attempt}/worker-events",
            post(workers::worker_event),
        )
        .route(
            "/attempts/{attempt}/execution-result",
            post(workers::worker_result),
        )
        .route(
            "/attempts/{attempt}/handoff-result",
            post(handoff::worker_result),
        )
        .route(
            "/attempts/{attempt}/integration-recovery",
            post(recovery::integration_recovery),
        )
        .route(
            "/attempts/{attempt}/native-controller",
            post(collaboration::native_controller),
        )
        .route(
            "/attempts/{attempt}/native-model",
            post(native_models::forward).layer(DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route(
            "/attempts/{attempt}/gateway-scope",
            post(workers::gateway_scope),
        )
        .route(
            "/artifacts/{artifact}/content",
            get(workers::artifact_content),
        )
        .route("/attempts/{attempt}/logs", get(workers::logs))
        .route(
            "/projects/{project}/artifacts",
            post(catalog::create_artifact),
        )
        .route(
            "/projects/{project}/input-snapshots",
            post(catalog::input_snapshots),
        )
        .route(
            "/contracts/{contract}/freeze-requests",
            post(catalog::freeze_contract),
        )
        .route("/executors", get(catalog::executors))
        .route("/executors/{executor}/probe", post(catalog::probe_executor))
        .route("/portfolio", get(catalog::portfolio))
        .route(
            "/resources",
            get(catalog::all_resources).post(catalog::put_global_policy),
        )
        .route("/resource-policies", post(catalog::put_global_policy))
        .route("/resource-usage", get(catalog::resource_usage))
        .route("/queue-entries", post(catalog::enqueue_global))
        .route(
            "/projects/{project}/tasks/{task}/admission-checks",
            post(catalog::scoped_admission_checks),
        )
        .route("/tasks/{task}/retry", post(catalog::retry))
        .route(
            "/tasks/{task}/admission-checks",
            post(catalog::admission_checks),
        )
        .route("/system/info", get(system_info))
        .route("/recovery-items", get(maintenance::recovery_items))
        .route("/backup-readiness", get(maintenance::backup_readiness))
        .route("/projects/{project}/capsules", get(capsules::list))
        .route(
            "/projects/{project}/capsules/{attempt}",
            get(capsules::detail),
        )
        .route("/projects/{project}/capsule-checks", post(capsules::check))
        .route(
            "/projects/{project}/capsule-policies",
            get(capsules::policies).post(capsules::register),
        )
        .route(
            "/projects/{project}/capsule-context",
            get(capsules::context),
        )
        .route(
            "/backups",
            get(maintenance::backups).post(maintenance::create_backup),
        )
        .route("/backups/{backup}", get(maintenance::backup))
        .route(
            "/backups/{backup}/archive",
            get(maintenance::backup_archive),
        )
        .route(
            "/backups/{backup}/restore-preview",
            get(maintenance::restore_preview),
        )
        .route("/system/routes", get(route_inventory))
        .route("/openapi.json", get(openapi))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            workspaces::guard,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.auth.clone(),
            auth::guard,
        ));
    let console = state.console_dir.clone();
    Router::new()
        .route("/healthz", get(health))
        .nest(
            "/api/v1",
            protected
                .route("/session", post(login))
                .route("/registrations", post(workspaces::register))
                .route("/tutorials/personal-site", get(tutorial::guide))
                .route(
                    "/plugins/dsh-forgeflow-network/{file}",
                    get(tutorial::plugin_file),
                )
                .fallback(api_missing),
        )
        .fallback_service(
            ServeDir::new(&console).fallback(ServeFile::new(console.join("index.html"))),
        )
        .with_state(state)
}
async fn health(State(s): State<App>) -> Result<Json<Value>, ApiError> {
    s.store.list_projects().await?;
    Ok(Json(json!({"status":"ok","database":"postgres"})))
}
async fn me(
    State(s): State<App>,
    headers: HeaderMap,
    Extension(p): Extension<Principal>,
) -> ApiResult<Value> {
    if p.actor_id.starts_with("account:") {
        let actor = workspaces::current_actor(&s, &headers).await?;
        return Ok(view(
            json!({"actor_id":p.actor_id,"role":"account","csrf_token":s.auth.session_csrf(&headers),"account":s.store.account_profile(&actor.account_id).await?,"workspaces":s.store.account_workspaces(&actor.account_id).await?}),
        ));
    }
    Ok(view_from(
        json!({"actor_id":p.actor_id,"role":if p.worker{"worker"}else{"owner"}}),
        "auth.json",
    ))
}
#[derive(Deserialize)]
struct Login {
    #[serde(default)]
    email: Option<String>,
    password: String,
}
async fn login(
    State(s): State<App>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> Result<Response, ApiError> {
    if let Some(email) = body.email.filter(|v| !v.is_empty()) {
        workspaces::same_origin(&headers)?;
        return workspaces::account_login(&s, &email, body.password).await;
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if origin != format!("http://{host}") && origin != format!("https://{host}") {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "ORIGIN_REJECTED",
                "session origin must match host",
            ));
        }
    }
    let (token, csrf) = match s.auth.login(body.password).await {
        Ok(session) => session,
        Err(auth::LoginError::InvalidCredentials) => {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "invalid credentials",
            ));
        }
        Err(auth::LoginError::Throttled {
            retry_after_seconds,
        }) => {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_after_seconds.to_string())],
                Json(DomainError::new(
                    "LOGIN_THROTTLED",
                    "too many login requests; retry after the indicated delay",
                )),
            )
                .into_response());
        }
        Err(auth::LoginError::Unavailable) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_UNAVAILABLE",
                "password login is temporarily unavailable",
            ));
        }
    };
    let cookie = format!(
        "forgeflow_session={token}; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=28800"
    );
    Ok((
        [("set-cookie", cookie)],
        Json(json!({"data":{"token":token,"csrf_token":csrf,"expires_in_seconds":28800}})),
    )
        .into_response())
}
async fn logout(State(s): State<App>, headers: HeaderMap) -> Result<Response, ApiError> {
    s.auth
        .logout(&headers)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "SESSION_WRITE_FAILED", e))?;
    Ok((
        [(
            "set-cookie",
            "forgeflow_session=; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=0",
        )],
        Json(json!({"data":{"logged_out":true}})),
    )
        .into_response())
}
async fn system_info(State(s): State<App>) -> Json<Value> {
    view(
        json!({"version":env!("CARGO_PKG_VERSION"),"authority":"postgresql","data_root":s.data_root,"deployment":"single-node","qualification":"INCONCLUSIVE","remote_workers":false,"model_budget_modes":["direct_observed"],"gateway_configured":s.gateway.is_some()}),
    )
}
#[derive(Deserialize, Default)]
pub struct Cursor {
    pub after: Option<u64>,
    pub project_id: Option<String>,
}
async fn events_query(
    State(s): State<App>,
    headers: HeaderMap,
    Query(q): Query<Cursor>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let p = q.project_id.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "PROJECT_REQUIRED",
            "project_id is required; cursors are project-local",
        )
    })?;
    events(State(s), Path(p), headers, Query(q)).await
}
async fn events(
    State(s): State<App>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Query(q): Query<Cursor>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    s.store.get_project(&project).await?;
    let mut after = q.after.unwrap_or(0);
    if let Some(last) = headers.get("last-event-id").and_then(|v| v.to_str().ok()) {
        let (p, n) = last.rsplit_once(':').ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_CURSOR",
                "Last-Event-ID must contain project:sequence",
            )
        })?;
        if p != project {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "SNAPSHOT_REQUIRED",
                "cursor belongs to another project",
            ));
        }
        after = n.parse().map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_CURSOR",
                "invalid sequence",
            )
        })?;
    }
    // Watermark, hot prefix and replay rows share one authority snapshot;
    // an archive transaction cannot turn separate boundary reads into a gap.
    let initial = s.store.event_replay_window(&project, after, 100).await?;
    if initial.expired {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "SNAPSHOT_REQUIRED",
            "cursor is ahead of authority or outside retained project events; fetch a current snapshot",
        ));
    }
    let stream = futures::stream::unfold(
        (s, project, after, initial.events, false, headers),
        |(s, project, mut after, mut queued, closed, headers)| async move {
            if closed {
                return None;
            }
            loop {
                if s.auth.is_shutting_down()
                    || !workspaces::stream_permitted(&s, &headers, &project).await
                {
                    return None;
                }
                if !queued.is_empty() {
                    let e = queued.remove(0);
                    if after.checked_add(1) != Some(e.project_seq) {
                        let out = Event::default()
                            .event("stream_error")
                            .data("{\"code\":\"SNAPSHOT_REQUIRED\"}");
                        return Some((Ok(out), (s, project, after, Vec::new(), true, headers)));
                    }
                    after = e.project_seq;
                    let out = Event::default()
                        .id(format!("{}:{}", project, after))
                        .event(&e.kind)
                        .json_data(&e)
                        .unwrap_or_else(|_| Event::default().event("serialization_error"));
                    return Some((Ok(out), (s, project, after, queued, false, headers)));
                }
                match s.store.event_replay_window(&project, after, 100).await {
                    Ok(window) if window.expired => {
                        let event = Event::default()
                            .event("stream_error")
                            .data("{\"code\":\"SNAPSHOT_REQUIRED\"}");
                        return Some((Ok(event), (s, project, after, Vec::new(), true, headers)));
                    }
                    Ok(window) => queued = window.events,
                    Err(error) => {
                        tracing::error!(%error,"SSE database read failed");
                        let event = Event::default()
                            .event("stream_error")
                            .data("{\"code\":\"EVENT_READ_FAILED\"}");
                        return Some((Ok(event), (s, project, after, queued, true, headers)));
                    }
                }
                if queued.is_empty() {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

async fn api_missing() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "ENDPOINT_UNAVAILABLE",
        "this control-plane route is unavailable; no command was accepted",
    )
}

async fn route_inventory() -> Json<Value> {
    Json(serde_json::from_str(include_str!("../routes.json")).expect("compiled route inventory"))
}
async fn openapi() -> Json<Value> {
    Json(
        serde_json::from_str(include_str!("../openapi.json"))
            .expect("compiled OpenAPI route inventory"),
    )
}
