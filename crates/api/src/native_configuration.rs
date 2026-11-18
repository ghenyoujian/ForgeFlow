//! Authenticated configuration editor. Publications create new frozen profiles.
use super::*;
use std::collections::BTreeMap;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SaveRequest {
    draft_id: String,
    expected_revision: Option<u64>,
    base_config_sha256: String,
    spec: Value,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    expected_revision: u64,
    review_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerContextQuery {
    executor_profile_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRequest {
    base_config_sha256: String,
    spec: Value,
}

fn failure(code: &str, message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code, message)
}
fn identifier(id: &str) -> Result<(), ApiError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(failure(
            "NATIVE_CONFIGURATION_INVALID",
            "invalid configuration identifier",
        ));
    }
    Ok(())
}
fn owner(actor: &Principal) -> Result<(), ApiError> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "execution configuration editing requires Owner authentication",
        ));
    }
    Ok(())
}
fn offline_mode(mode: &str) -> Result<(), ApiError> {
    if !matches!(mode, "context" | "validate") {
        return Err(failure(
            "NATIVE_CONFIGURATION_OFFLINE_ONLY",
            "Owner editing supports offline context and validation only",
        ));
    }
    Ok(())
}
fn config(project: &str) -> Result<(PathBuf, Vec<u8>, Value), ApiError> {
    let map: BTreeMap<String, PathBuf> = serde_json::from_slice(&native_panel::private_bytes(
        &native_panel::configured_path("FORGEFLOW_NATIVE_DELIVERY_CONFIGS_FILE")?,
        1_048_576,
    )?)
    .map_err(|_| {
        failure(
            "NATIVE_CONFIGURATION_INVALID",
            "approved project map unavailable",
        )
    })?;
    let path = map.get(project).cloned().ok_or_else(|| {
        failure(
            "NATIVE_PANEL_PROJECT_NOT_APPROVED",
            "project is outside the reviewed panel map",
        )
    })?;
    let raw = native_panel::private_bytes(&path, 8_388_608)?;
    let value: Value = serde_json::from_slice(&raw).map_err(|_| {
        failure(
            "NATIVE_CONFIGURATION_INVALID",
            "approved configuration unavailable",
        )
    })?;
    if value["project_id"] != project {
        return Err(failure(
            "NATIVE_CONFIGURATION_INVALID",
            "project configuration identity differs",
        ));
    }
    Ok((path, raw, value))
}
async fn run_helper(
    s: &App,
    project: &str,
    mode: &str,
    draft: Option<Value>,
) -> Result<Value, ApiError> {
    run_helper_inner(s, project, mode, draft, false).await
}
async fn run_offline_helper(
    s: &App,
    project: &str,
    mode: &str,
    draft: Option<Value>,
) -> Result<Value, ApiError> {
    offline_mode(mode)?;
    run_helper_inner(s, project, mode, draft, true).await
}
async fn run_helper_inner(
    s: &App,
    project: &str,
    mode: &str,
    draft: Option<Value>,
    cleanup_offline_success: bool,
) -> Result<Value, ApiError> {
    if cleanup_offline_success {
        offline_mode(mode)?;
    }
    let (path, raw, cfg) = config(project)?;
    let helper = native_panel::configured_path("FORGEFLOW_NATIVE_CONFIGURATION_HELPER_FILE")?;
    let helper_sha =
        std::env::var("FORGEFLOW_NATIVE_CONFIGURATION_HELPER_SHA256").unwrap_or_default();
    if helper_sha.len() != 64
        || forgeflow_planner::sha256(&std::fs::read(&helper).map_err(|_| {
            failure(
                "NATIVE_CONFIGURATION_UNAVAILABLE",
                "configuration publisher unavailable",
            )
        })?) != helper_sha
    {
        return Err(failure(
            "NATIVE_CONFIGURATION_UNAVAILABLE",
            "configuration publisher identity changed",
        ));
    }
    let profile_id = draft
        .as_ref()
        .and_then(|v| v["spec"]["base_executor_profile_id"].as_str())
        .or_else(|| cfg["executor_profile_id"].as_str())
        .ok_or_else(|| failure("NATIVE_CONFIGURATION_INVALID", "base executor missing"))?;
    identifier(profile_id)?;
    let approved = cfg["executor_profile_id"] == profile_id
        || cfg["executor_profile_ids"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|v| v == profile_id));
    if !approved {
        return Err(failure(
            "NATIVE_CONFIGURATION_INVALID",
            "base executor is outside approved profiles",
        ));
    }
    let profile = s
        .store
        .get_document(project, "executor_profiles", profile_id)
        .await?;
    let resource_id = cfg["workers"]
        .as_array()
        .and_then(|workers| {
            workers
                .iter()
                .find(|worker| worker["executor_profile_id"] == profile_id)
        })
        .and_then(|worker| worker["resource_profile_id"].as_str())
        .or_else(|| cfg["resource_profile_id"].as_str())
        .ok_or_else(|| {
            failure(
                "NATIVE_CONFIGURATION_INVALID",
                "base resource profile missing",
            )
        })?;
    identifier(resource_id)?;
    let mut resource_profile = s
        .store
        .get_document(project, "resource_profiles", resource_id)
        .await?;
    if let Some(object) = resource_profile.as_object_mut() {
        object.remove("revision");
    }
    let root = s.data_root.join("native-configuration-requests");
    std::fs::create_dir_all(&root).map_err(|_| {
        failure(
            "NATIVE_CONFIGURATION_UNAVAILABLE",
            "private publisher directory unavailable",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(|_| {
            failure(
                "NATIVE_CONFIGURATION_UNAVAILABLE",
                "private publisher permissions unavailable",
            )
        })?;
    }
    let invocation = uuid::Uuid::new_v4().to_string();
    let input = root.join(format!("{invocation}.input.json"));
    let output = root.join(format!("{invocation}.output.json"));
    let mut body = json!({"mode":mode,"project_id":project,"config_path":path,"base_config_sha256":forgeflow_planner::sha256(&raw),"base_profile":profile,"base_resource_profile":resource_profile,"draft":draft,"output_path":output});
    if mode == "activate" {
        let draft = body["draft"].clone();
        let id = draft["published_executor_profile_id"]
            .as_str()
            .ok_or_else(|| {
                failure(
                    "NATIVE_CONFIGURATION_NOT_PUBLISHED",
                    "publish this version before activation",
                )
            })?;
        body["resource_policies"] = json!(s.store.resource_policies(project).await?);
        body["published_profile"] = s
            .store
            .get_document(project, "executor_profiles", id)
            .await?;
        let resource_id = draft["published_resource_profile_id"]
            .as_str()
            .ok_or_else(|| {
                failure(
                    "NATIVE_CONFIGURATION_NOT_PUBLISHED",
                    "publish a new version with its resource sandbox before activation",
                )
            })?;
        let mut published_resource = s
            .store
            .get_document(project, "resource_profiles", resource_id)
            .await?;
        if let Some(object) = published_resource.as_object_mut() {
            object.remove("revision");
        }
        let resource_sha =
            forgeflow_planner::sha256(&serde_json::to_vec(&published_resource).map_err(|_| {
                failure(
                    "NATIVE_CONFIGURATION_INVALID",
                    "published resource profile invalid",
                )
            })?);
        if draft["published_resource_profile_sha256"] != resource_sha {
            return Err(failure(
                "NATIVE_CONFIGURATION_SOURCE_STALE",
                "published resource sandbox identity changed",
            ));
        }
        body["published_resource_profile"] = published_resource;
        body["worker_binary"] = json!(native_panel::configured_path(
            "FORGEFLOW_NATIVE_CONFIGURATION_WORKER_FILE"
        )?);
        body["worker_binary_sha256"] =
            std::env::var("FORGEFLOW_NATIVE_CONFIGURATION_WORKER_SHA256")
                .unwrap_or_default()
                .into();
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input)
            .map_err(|_| {
                failure(
                    "NATIVE_CONFIGURATION_UNAVAILABLE",
                    "private publisher input unavailable",
                )
            })?;
        file.write_all(
            &serde_json::to_vec(&body)
                .map_err(|_| failure("NATIVE_CONFIGURATION_INVALID", "publisher input invalid"))?,
        )
        .map_err(|_| {
            failure(
                "NATIVE_CONFIGURATION_UNAVAILABLE",
                "publisher input write failed",
            )
        })?;
    }
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(if cleanup_offline_success { 30 } else { 180 }),
        tokio::process::Command::new("/usr/bin/python3")
            .arg(&helper)
            .arg("--input")
            .arg(&input)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        if cleanup_offline_success {
            failure(
                "NATIVE_CONFIGURATION_OFFLINE_TIMEOUT",
                "offline configuration operation timed out; saved drafts remain available",
            )
        } else {
            failure(
                "NATIVE_CONFIGURATION_PREVIEW_TIMEOUT",
                "native composition preview timed out; saved draft remains available",
            )
        }
    })?
    .map_err(|_| {
        failure(
            "NATIVE_CONFIGURATION_UNAVAILABLE",
            "configuration publisher could not start",
        )
    })?;
    if !result.status.success() {
        // The private helper writes only public error codes to its output contract.
        let error: Value = native_panel::private_bytes(&output, 16_384)
            .ok()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default();
        let code = error["error"]["code"]
            .as_str()
            .filter(|v| v.starts_with("NATIVE_CONFIGURATION_"))
            .unwrap_or("NATIVE_CONFIGURATION_PREVIEW_FAILED");
        return Err(failure(
            code,
            "native configuration rejected; reload the source or correct the selected preset/plugin settings",
        ));
    }
    let result: Value = serde_json::from_slice(&native_panel::private_bytes(&output, 8_388_608)?)
        .map_err(|_| {
        failure(
            "NATIVE_CONFIGURATION_INVALID",
            "native publisher result invalid",
        )
    })?;
    if cleanup_offline_success {
        let valid = if mode == "context" {
            result["schema_version"] == "forgeflow.native-configuration-context.v1"
                && result["project_id"] == project
                && result["base_config_sha256"] == forgeflow_planner::sha256(&raw)
                && result["spec"].is_object()
        } else {
            result["valid"] == true
        };
        if !valid {
            return Err(failure(
                "NATIVE_CONFIGURATION_INVALID",
                "offline helper returned an invalid context or validation receipt",
            ));
        }
        // These UUID-named files belong to this exact successful read/validation
        // invocation. Failed requests and all original panel preview/publish/
        // activate artifacts remain available as evidence.
        for path in [&input, &output] {
            if let Err(error) = std::fs::remove_file(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(%error, "successful offline configuration temporary-file cleanup failed");
                }
            }
        }
    }
    Ok(result)
}
async fn command(
    s: &App,
    project: &str,
    actor: &Principal,
    headers: &HeaderMap,
    cmd: NativeConfigurationCommand,
) -> ApiResult<Value> {
    let original = identity(headers, actor)?;
    let result = s
        .store
        .execute_command(
            CommandIdentity {
                actor_id: "native-configuration-service".into(),
                idempotency_key: format!(
                    "{}:{}:{}",
                    actor.actor_id, project, original.idempotency_key
                ),
            },
            CatalogCommand::NativeConfiguration {
                project_id: project.into(),
                command: cmd,
            },
        )
        .await?;
    Ok(Json(
        json!({"data":result.value,"operation_id":result.operation_id,"replayed":result.replayed,"source":"postgres"}),
    ))
}
/// Resolve uncertain HTTP commits before rechecking source files or launching
/// another preview. Exact stored request fields still protect key reuse.
async fn replay_request(
    s: &App,
    project: &str,
    actor: &Principal,
    headers: &HeaderMap,
    action: &str,
    id: &str,
    request: Value,
) -> Result<Option<Json<Value>>, ApiError> {
    let original = identity(headers, actor)?;
    let key = format!(
        "{}:{}:{}",
        actor.actor_id, project, original.idempotency_key
    );
    let Some(record) = s
        .store
        .catalog_service_receipt("native-configuration-service", &key)
        .await?
    else {
        return Ok(None);
    };
    let stored = &record["request"];
    let inner = &stored["payload"]["command"];
    if stored["payload"]["project_id"] != project
        || inner["action"] != action
        || inner["draft_id"] != id
    {
        return Err(failure(
            "IDEMPOTENCY_CONFLICT",
            "request identity belongs to a different configuration operation",
        ));
    }
    for (field, value) in request.as_object().into_iter().flatten() {
        let expected = if field == "review_sha256" && action == "ACTIVATE" {
            &record["response"]["value"]["review_sha256"]
        } else {
            &inner[field]
        };
        if field == "review_sha256" && action == "PREVIEW" && value.is_null() {
            continue;
        }
        if expected != value {
            return Err(failure(
                "IDEMPOTENCY_CONFLICT",
                "request key cannot be reused with changed configuration fields",
            ));
        }
    }
    let CatalogCommand::NativeConfiguration { command: cmd, .. } =
        serde_json::from_value(stored.clone()).map_err(|_| {
            failure(
                "NATIVE_CONFIGURATION_INVALID",
                "configuration receipt request invalid",
            )
        })?
    else {
        return Err(failure(
            "IDEMPOTENCY_CONFLICT",
            "request is not a configuration operation",
        ));
    };
    Ok(Some(command(s, project, actor, headers, cmd).await?))
}

pub async fn context(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    Ok(view(run_helper(&s, &project, "context", None).await?))
}
pub async fn list(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    Ok(view(
        s.store
            .list_documents(&project, "native_configuration_drafts")
            .await?,
    ))
}
pub async fn save(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<SaveRequest>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    save_request(&s, &project, &actor, &headers, request, false).await
}

/// Both transports persist exactly the same typed command, document collection,
/// actor/project idempotency scope, source digest and revision semantics.
async fn save_request(
    s: &App,
    project: &str,
    actor: &Principal,
    headers: &HeaderMap,
    request: SaveRequest,
    offline: bool,
) -> ApiResult<Value> {
    identifier(&request.draft_id)?;
    if let Some(result) = replay_request(
        s,
        project,
        actor,
        headers,
        "SAVE",
        &request.draft_id,
        serde_json::to_value(&request)
            .map_err(|_| failure("NATIVE_CONFIGURATION_INVALID", "request invalid"))?,
    )
    .await?
    {
        return Ok(result);
    }
    let (_, raw, _) = config(project)?;
    if forgeflow_planner::sha256(&raw) != request.base_config_sha256 {
        return Err(failure(
            "NATIVE_CONFIGURATION_SOURCE_STALE",
            "approved source changed; reload before saving",
        ));
    }
    let draft = json!({"draft_id":request.draft_id,"spec":request.spec,"base_config_sha256":request.base_config_sha256});
    if offline {
        let result = run_offline_helper(s, project, "validate", Some(draft)).await?;
        if result["valid"] != true {
            return Err(failure(
                "NATIVE_CONFIGURATION_INVALID",
                "offline validator did not confirm the editable specification",
            ));
        }
    } else {
        run_helper(s, project, "validate", Some(draft)).await?;
    }
    command(
        s,
        project,
        actor,
        headers,
        NativeConfigurationCommand::Save {
            draft_id: request.draft_id,
            expected_revision: request.expected_revision,
            base_config_sha256: request.base_config_sha256,
            spec: request.spec,
            requested_by: actor.actor_id.clone(),
        },
    )
    .await
}

/// Main Console editing needs no DSH Host or panel secret. Its helper modes are
/// deliberately restricted before any configured paths or files are read.
pub async fn owner_context(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<OwnerContextQuery>,
) -> ApiResult<Value> {
    owner(&actor)?;
    let selected = query
        .executor_profile_id
        .map(|profile| {
            identifier(&profile)?;
            Ok::<_, ApiError>(json!({"spec":{"base_executor_profile_id":profile}}))
        })
        .transpose()?;
    // Context's draft is only a reviewed-profile selector. The pinned helper
    // constructs its context from source files, never the caller's draft spec.
    let mut result = run_offline_helper(&s, &project, "context", selected).await?;
    let object = result.as_object_mut().ok_or_else(|| {
        failure(
            "NATIVE_CONFIGURATION_INVALID",
            "offline context result must be an object",
        )
    })?;
    object.insert("offline_only".into(), true.into());
    object.insert("runtime_actions_available".into(), false.into());
    object.insert("runtime_invoked".into(), false.into());
    object.insert("execution_rights_granted".into(), false.into());
    Ok(view_from(result, "postgres+pinned files"))
}

pub async fn owner_list(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    owner(&actor)?;
    Ok(view(
        s.store
            .list_documents(&project, "native_configuration_drafts")
            .await?,
    ))
}

pub async fn owner_save(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<SaveRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    save_request(&s, &project, &actor, &headers, request, true).await
}

pub async fn owner_validate(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    Json(request): Json<ValidationRequest>,
) -> ApiResult<Value> {
    owner(&actor)?;
    let (_, raw, _) = config(&project)?;
    if forgeflow_planner::sha256(&raw) != request.base_config_sha256 {
        return Err(failure(
            "NATIVE_CONFIGURATION_SOURCE_STALE",
            "approved source changed; reload before validation",
        ));
    }
    let draft = json!({"base_config_sha256":request.base_config_sha256,"spec":request.spec});
    let result = run_offline_helper(&s, &project, "validate", Some(draft)).await?;
    if result["valid"] != true {
        return Err(failure(
            "NATIVE_CONFIGURATION_INVALID",
            "offline validator did not confirm the editable specification",
        ));
    }
    Ok(view_from(
        json!({"valid":true,"native_resolution":"NOT_RUN","runtime_invoked":false,"execution_rights_granted":false}),
        "postgres+pinned files",
    ))
}
pub async fn preview(
    State(s): State<App>,
    Path((project, id)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<ReviewRequest>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    identifier(&id)?;
    if let Some(result) = replay_request(
        &s,
        &project,
        &actor,
        &headers,
        "PREVIEW",
        &id,
        serde_json::to_value(&request)
            .map_err(|_| failure("NATIVE_CONFIGURATION_INVALID", "request invalid"))?,
    )
    .await?
    {
        return Ok(result);
    }
    let draft = s
        .store
        .get_document(&project, "native_configuration_drafts", &id)
        .await?;
    let output = run_helper(&s, &project, "preview", Some(draft.clone())).await?;
    command(
        &s,
        &project,
        &actor,
        &headers,
        NativeConfigurationCommand::Preview {
            draft_id: id,
            expected_revision: request.expected_revision,
            base_config_sha256: draft["base_config_sha256"]
                .as_str()
                .unwrap_or_default()
                .into(),
            spec_sha256: draft["spec_sha256"].as_str().unwrap_or_default().into(),
            review: output["review"].clone(),
        },
    )
    .await
}
pub async fn publish(
    State(s): State<App>,
    Path((project, id)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<ReviewRequest>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    identifier(&id)?;
    if let Some(result) = replay_request(
        &s,
        &project,
        &actor,
        &headers,
        "PUBLISH",
        &id,
        serde_json::to_value(&request)
            .map_err(|_| failure("NATIVE_CONFIGURATION_INVALID", "request invalid"))?,
    )
    .await?
    {
        return Ok(result);
    }
    let draft = s
        .store
        .get_document(&project, "native_configuration_drafts", &id)
        .await?;
    if draft["review_sha256"] != request.review_sha256.as_deref().unwrap_or("") {
        return Err(failure(
            "REVISION_CONFLICT",
            "saved native preview changed; reload",
        ));
    }
    let output = run_helper(&s, &project, "publish", Some(draft)).await?;
    command(
        &s,
        &project,
        &actor,
        &headers,
        NativeConfigurationCommand::Publish {
            draft_id: id,
            expected_revision: request.expected_revision,
            review_sha256: request.review_sha256.unwrap_or_default(),
            profile: output["profile"].clone(),
            resource_profile: output["resource_profile"].clone(),
            approved_by: actor.actor_id.clone(),
        },
    )
    .await
}

pub async fn activate(
    State(s): State<App>,
    Path((project, id)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<ReviewRequest>,
) -> ApiResult<Value> {
    native_panel::authenticate(&actor, &headers)?;
    identifier(&id)?;
    if let Some(result) = replay_request(
        &s,
        &project,
        &actor,
        &headers,
        "ACTIVATE",
        &id,
        serde_json::to_value(&request)
            .map_err(|_| failure("NATIVE_CONFIGURATION_INVALID", "request invalid"))?,
    )
    .await?
    {
        return Ok(result);
    }
    let draft = s
        .store
        .get_document(&project, "native_configuration_drafts", &id)
        .await?;
    if draft["status"] != "PUBLISHED"
        || draft["review_sha256"] != request.review_sha256.as_deref().unwrap_or("")
    {
        return Err(failure(
            "NATIVE_CONFIGURATION_NOT_PUBLISHED",
            "activation requires the exact published version",
        ));
    }
    let scheduling = s.store.native_panel_scheduling(&project).await?;
    if scheduling["paused"] != true || scheduling["start_pending"] == true {
        return Err(failure(
            "NATIVE_CONFIGURATION_PAUSE_REQUIRED",
            "pause development scheduling before activating a new configuration version",
        ));
    }
    let mut output = run_helper(&s, &project, "activate", Some(draft)).await?;
    let resource_policies = serde_json::from_value(
        output
            .as_object_mut()
            .and_then(|v| v.remove("resource_policies"))
            .unwrap_or(json!([])),
    )
    .map_err(|_| {
        failure(
            "NATIVE_CONFIGURATION_INVALID",
            "Worker policy publication invalid",
        )
    })?;
    command(
        &s,
        &project,
        &actor,
        &headers,
        NativeConfigurationCommand::Activate {
            draft_id: id,
            expected_revision: request.expected_revision,
            receipt: output,
            resource_policies,
            activated_by: actor.actor_id.clone(),
        },
    )
    .await
}

#[cfg(test)]
mod offline_editor_tests {
    use super::*;

    #[test]
    fn offline_owner_gate_rejects_worker_before_private_configuration_access() {
        let actor = Principal {
            actor_id: "worker:offline-test".into(),
            worker: true,
            worker_id: Some("offline-test".into()),
            project_id: Some("project".into()),
        };
        let error = owner(&actor).unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert_eq!(error.1.code, "OWNER_REQUIRED");
    }

    #[test]
    fn offline_helper_gate_rejects_every_runtime_action_before_invocation() {
        assert!(offline_mode("context").is_ok());
        assert!(offline_mode("validate").is_ok());
        for action in [
            "preview", "publish", "activate", "start", "resume", "stop", "CONTEXT", "",
        ] {
            assert_eq!(
                offline_mode(action).unwrap_err().1.code,
                "NATIVE_CONFIGURATION_OFFLINE_ONLY"
            );
        }
    }

    #[test]
    fn offline_requests_cannot_smuggle_runtime_actions_or_replacement_context() {
        let request = json!({"base_config_sha256":"a".repeat(64),"spec":{}});
        assert!(serde_json::from_value::<ValidationRequest>(request.clone()).is_ok());
        for field in [
            "mode",
            "action",
            "review_sha256",
            "panel_key",
            "execution_rights_granted",
        ] {
            let mut changed = request.clone();
            changed[field] = "activate".into();
            assert!(serde_json::from_value::<ValidationRequest>(changed).is_err());
        }
        assert!(
            serde_json::from_value::<OwnerContextQuery>(
                json!({"executor_profile_id":"reviewed-v1"})
            )
            .is_ok()
        );
        for field in ["spec", "mode", "config_path", "base_profile"] {
            let mut changed = json!({"executor_profile_id":"reviewed-v1"});
            changed[field] = json!({"replace":"source"});
            assert!(serde_json::from_value::<OwnerContextQuery>(changed).is_err());
        }
    }
}
