//! Native DSH panel commands retain their origin through the delivery service.
use super::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path as FsPath};

pub(crate) fn private_bytes(path: &FsPath, limit: u64) -> Result<Vec<u8>, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NATIVE_PANEL_CONFIG_INVALID",
            "native panel private configuration is unavailable or invalid",
        )
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| invalid())?;
        let metadata = file.metadata().map_err(|_| invalid())?;
        if !path.is_absolute()
            || !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > limit
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() as u64 > limit {
            return Err(invalid());
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        Err(invalid())
    }
}

pub(crate) fn configured_path(name: &str) -> Result<PathBuf, ApiError> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_PANEL_NOT_CONFIGURED",
                "native panel delivery is not configured",
            )
        })
}

pub(crate) fn authenticate(actor: &Principal, headers: &HeaderMap) -> Result<(), ApiError> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "native panel commands require Owner authentication",
        ));
    }
    let key_path = configured_path("FORGEFLOW_NATIVE_PANEL_KEY_FILE")?;
    let bytes = private_bytes(&key_path, 4096)?;
    let expected = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .filter(|s| {
            (24..=4096).contains(&s.len())
                && s.is_ascii()
                && !s
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_PANEL_CONFIG_INVALID",
                "native panel authentication configuration is invalid",
            )
        })?;
    let supplied = headers
        .get("x-forgeflow-native-panel-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected_hash = Sha256::digest(expected.as_bytes());
    let supplied_hash = Sha256::digest(supplied.as_bytes());
    let difference = expected_hash
        .iter()
        .zip(supplied_hash)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b));
    if difference != 0
        || headers
            .get_all("x-forgeflow-native-panel-key")
            .iter()
            .count()
            != 1
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "NATIVE_PANEL_ORIGIN_REQUIRED",
            "this action must originate from the configured DSH native panel",
        ));
    }
    Ok(())
}

struct ApprovedDelivery {
    config_path: PathBuf,
    script_path: PathBuf,
    expected_model: String,
    catalog_id: String,
    expected_card_count: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeUiBootstrap {
    schema_version: String,
    url: String,
    port: u16,
    created_at: String,
    source: String,
}

fn native_ui_location(
    bytes: &[u8],
    expected_port: u16,
) -> Result<axum::http::HeaderValue, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NATIVE_UI_BOOTSTRAP_INVALID",
            "the native UI connection bootstrap is unavailable or invalid",
        )
    };
    let bootstrap: NativeUiBootstrap = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if bootstrap.schema_version != "forgeflow.native-ui-bootstrap.v1"
        || bootstrap.source != "ACTUAL_NATIVE_CONNECTION_AUTHENTICATED_URL"
        || bootstrap.port != expected_port
        || expected_port == 0
        || chrono::DateTime::parse_from_rfc3339(&bootstrap.created_at).is_err()
        || !bootstrap.url.is_ascii()
        || bootstrap.url.contains(['#', '\\', '\r', '\n'])
    {
        return Err(invalid());
    }
    let uri: axum::http::Uri = bootstrap.url.parse().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    let ipv4_authority = format!("127.0.0.1:{expected_port}");
    let ipv6_authority = format!("[::1]:{expected_port}");
    if uri.scheme_str() != Some("http")
        || ![ipv4_authority.as_str(), ipv6_authority.as_str()].contains(&authority.as_str())
        || authority.as_str().contains('@')
        || authority.port_u16() != Some(expected_port)
        || uri.path() != "/"
    {
        return Err(invalid());
    }
    let query = uri.query().ok_or_else(invalid)?;
    let (key, token) = query.split_once('=').ok_or_else(invalid)?;
    if key != "token" || !(24..=4096).contains(&token.len()) || token.contains('&') {
        return Err(invalid());
    }
    axum::http::HeaderValue::from_str(&bootstrap.url).map_err(|_| invalid())
}

/// Authenticated navigation uses the URL minted by the actual native host. It
/// neither creates native cookies nor returns connection credentials as JSON.
pub async fn open(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
) -> Result<Response, ApiError> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "native UI navigation requires Owner authentication",
        ));
    }
    s.store.get_project(&project).await?;
    let map: BTreeMap<String, PathBuf> = serde_json::from_slice(&private_bytes(
        &configured_path("FORGEFLOW_NATIVE_DELIVERY_CONFIGS_FILE")?,
        1_048_576,
    )?)
    .map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NATIVE_PANEL_CONFIG_INVALID",
            "native panel project configuration is invalid",
        )
    })?;
    let config_path = map.get(&project).ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "NATIVE_PANEL_PROJECT_NOT_APPROVED",
            "project has no reviewed native UI configuration",
        )
    })?;
    let config: Value =
        serde_json::from_slice(&private_bytes(config_path, 8_388_608)?).map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_PANEL_CONFIG_INVALID",
                "native panel project configuration is invalid",
            )
        })?;
    if config["project_id"].as_str() != Some(&project) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "NATIVE_PANEL_PROJECT_CONFIG_MISMATCH",
            "reviewed native UI configuration belongs to a different project",
        ));
    }
    let expected_port = std::env::var("FORGEFLOW_NATIVE_UI_PORT")
        .unwrap_or_else(|_| "19388".into())
        .parse::<u16>()
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_UI_BOOTSTRAP_INVALID",
                "native UI port configuration is invalid",
            )
        })?;
    let bytes = private_bytes(
        &configured_path("FORGEFLOW_NATIVE_UI_BOOTSTRAP_FILE")?,
        65_536,
    )?;
    let location = native_ui_location(&bytes, expected_port)?;
    Response::builder()
        .status(StatusCode::FOUND)
        .header(axum::http::header::LOCATION, location)
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header(axum::http::header::PRAGMA, "no-cache")
        .header("referrer-policy", "no-referrer")
        .body(axum::body::Body::empty())
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_UI_BOOTSTRAP_INVALID",
                "native UI navigation could not be created",
            )
        })
}

fn approved_delivery(
    project: &str,
    request: &NativePanelActionRequest,
) -> Result<ApprovedDelivery, ApiError> {
    let fail = || {
        ApiError::new(
            StatusCode::CONFLICT,
            "NATIVE_PANEL_CONFIG_STALE",
            "reviewed delivery configuration or alignment has changed; refresh the native panel",
        )
    };
    let map: BTreeMap<String, PathBuf> = serde_json::from_slice(&private_bytes(
        &configured_path("FORGEFLOW_NATIVE_DELIVERY_CONFIGS_FILE")?,
        1_048_576,
    )?)
    .map_err(|_| fail())?;
    let config_path = map.get(project).cloned().ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "NATIVE_PANEL_PROJECT_NOT_APPROVED",
            "project has no reviewed native delivery configuration",
        )
    })?;
    let config_bytes = private_bytes(&config_path, 8_388_608)?;
    let config: Value = serde_json::from_slice(&config_bytes).map_err(|_| fail())?;
    if !valid_digest(&request.config_sha256)
        || !valid_digest(&request.alignment_sha256)
        || forgeflow_planner::sha256(&config_bytes) != request.config_sha256
        || !super::project_contracts::delivery_schema(
            project,
            config["schema_version"].as_str().unwrap_or(""),
        )?
        || config["project_id"].as_str() != Some(project)
        || config["alignment_sha256"].as_str() != Some(&request.alignment_sha256)
    {
        return Err(fail());
    }
    let alignment_path = config["alignment_manifest"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(fail)?;
    let alignment = private_bytes(&alignment_path, 268_435_456)?;
    if forgeflow_planner::sha256(&alignment) != request.alignment_sha256 {
        return Err(fail());
    }
    let script_path = configured_path("FORGEFLOW_NATIVE_DELIVERY_PROGRAM")?;
    let expected_script = std::env::var("FORGEFLOW_NATIVE_DELIVERY_PROGRAM_SHA256")
        .ok()
        .filter(|h| valid_digest(h))
        .ok_or_else(fail)?;
    let script = std::fs::read(&script_path).map_err(|_| fail())?;
    if forgeflow_planner::sha256(&script) != expected_script {
        return Err(fail());
    }
    let expected_model = config["expected_provider_model_id"]
        .as_str()
        .or_else(|| config["model_id"].as_str())
        .unwrap_or("")
        .to_owned();
    let catalog_id = config["planning_catalog_id"]
        .as_str()
        .ok_or_else(fail)?
        .to_owned();
    let expected_card_count = config["expected_card_count"]
        .as_u64()
        .or_else(|| config["card_denominator"].as_u64());
    Ok(ApprovedDelivery {
        config_path,
        script_path,
        expected_model,
        catalog_id,
        expected_card_count,
    })
}

/// Internal verifier recovery consumes a real protected START and the exact
/// currently reviewed configuration. Private files alone grant no execution.
pub(crate) fn approved_verification_recovery_config(
    project: &str,
    action: &Value,
) -> Result<Value, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::CONFLICT,
            "VERIFICATION_RECOVERY_INVALID",
            "Native verification recovery configuration is unavailable or differs from its approved pins",
        )
    };
    if action["project_id"] != project
        || action["entry_source"] != "DSH_NATIVE_PANEL"
        || action["action"] != "START"
        || !matches!(action["status"].as_str(), Some("RUNNING" | "SUCCEEDED"))
    {
        return Err(invalid());
    }
    let request = NativePanelActionRequest {
        action: NativePanelActionKind::Start,
        config_sha256: action["config_sha256"]
            .as_str()
            .ok_or_else(invalid)?
            .to_owned(),
        alignment_sha256: action["alignment_sha256"]
            .as_str()
            .ok_or_else(invalid)?
            .to_owned(),
        reason: String::new(),
        attempt_id: None,
    };
    let approved = approved_delivery(project, &request)?;
    let bytes = private_bytes(&approved.config_path, 8_388_608)?;
    if forgeflow_planner::sha256(&bytes) != request.config_sha256 {
        return Err(invalid());
    }
    let config: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let policy = &config["verification_recovery_policy"];
    if policy["enabled"] != true || policy["max_once"] != 1 {
        return Err(invalid());
    }
    let manifest_path = PathBuf::from(
        policy["runtime_manifest_path"]
            .as_str()
            .ok_or_else(invalid)?,
    );
    let manifest_sha = policy["runtime_manifest_sha256"]
        .as_str()
        .filter(|sha| valid_digest(sha))
        .ok_or_else(invalid)?;
    let manifest_bytes = private_bytes(&manifest_path, 8_388_608)?;
    if forgeflow_planner::sha256(&manifest_bytes) != manifest_sha {
        return Err(invalid());
    }
    let runtime: Value = serde_json::from_slice(&manifest_bytes).map_err(|_| invalid())?;
    if runtime["schema_version"] != "forgeflow.verifier-python-runtime.v1"
        || runtime["qualification"] != "DESIGN_PREPARED_ONLY"
    {
        return Err(invalid());
    }
    let proof_path = PathBuf::from(
        policy["preflight_proof"]["path"]
            .as_str()
            .ok_or_else(invalid)?,
    );
    let proof_sha = policy["preflight_proof"]["sha256"]
        .as_str()
        .filter(|sha| valid_digest(sha))
        .ok_or_else(invalid)?;
    let proof_bytes = private_bytes(&proof_path, 8_388_608)?;
    if forgeflow_planner::sha256(&proof_bytes) != proof_sha {
        return Err(invalid());
    }
    let proof: Value = serde_json::from_slice(&proof_bytes).map_err(|_| invalid())?;
    if policy["resume_never_launched"] == true {
        let path = PathBuf::from(
            policy["resume_preflight_proof"]["path"]
                .as_str()
                .ok_or_else(invalid)?,
        );
        let hash = policy["resume_preflight_proof"]["sha256"]
            .as_str()
            .filter(|hash| valid_digest(hash))
            .ok_or_else(invalid)?;
        let bytes = private_bytes(&path, 8_388_608)?;
        if forgeflow_planner::sha256(&bytes) != hash {
            return Err(invalid());
        }
    }
    Ok(
        json!({"policy":policy,"runtime":runtime,"preflight_proof":proof,
        "config_sha256":request.config_sha256,"alignment_sha256":request.alignment_sha256,
        "native_panel_action_id":action["action_id"]}),
    )
}

/// A private provenance file identifies retained material; only the protected
/// START plus the typed Store command can authorize a new review attempt.
pub(crate) fn approved_candidate_reuse_config(
    project: &str,
    action: &Value,
) -> Result<Value, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::CONFLICT,
            "RETAINED_CANDIDATE_CONFIG_INVALID",
            "retained candidate policy differs from the protected Native START",
        )
    };
    if action["project_id"] != project
        || action["entry_source"] != "DSH_NATIVE_PANEL"
        || action["action"] != "START"
        || !matches!(action["status"].as_str(), Some("RUNNING" | "SUCCEEDED"))
    {
        return Err(invalid());
    }
    let request = NativePanelActionRequest {
        action: NativePanelActionKind::Start,
        config_sha256: action["config_sha256"]
            .as_str()
            .ok_or_else(invalid)?
            .to_owned(),
        alignment_sha256: action["alignment_sha256"]
            .as_str()
            .ok_or_else(invalid)?
            .to_owned(),
        reason: String::new(),
        attempt_id: None,
    };
    let approved = approved_delivery(project, &request)?;
    let bytes = private_bytes(&approved.config_path, 8_388_608)?;
    if forgeflow_planner::sha256(&bytes) != request.config_sha256 {
        return Err(invalid());
    }
    let config: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let policy = &config["candidate_reuse_policy"];
    if policy["enabled"] != true
        || policy["mode"] != "RETAINED_NATIVE_CANDIDATE_REVIEW"
        || policy["max_once"] != 1
        || policy["expected_cases"] != 8
        || policy["model_calls"] != 0
        || policy["old_attempt_preserved"] != true
        || policy["expected_target_task_revision"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || policy["expected_review_task_revision"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || [
            "source_attempt_id",
            "target_task_id",
            "review_task_id",
            "verification_plan_id",
            "executor_profile_id",
            "resource_profile_id",
            "model_route_id",
        ]
        .iter()
        .any(|field| policy[*field].as_str().is_none_or(str::is_empty))
        || policy["verification_plan_sha256"]
            .as_str()
            .is_none_or(|digest| !valid_digest(digest))
    {
        return Err(invalid());
    }
    let provenance_path = PathBuf::from(
        policy["source_provenance"]["path"]
            .as_str()
            .ok_or_else(invalid)?,
    );
    let provenance_sha256 = policy["source_provenance"]["sha256"]
        .as_str()
        .filter(|digest| valid_digest(digest))
        .ok_or_else(invalid)?;
    let bytes = private_bytes(&provenance_path, 8_388_608)?;
    if forgeflow_planner::sha256(&bytes) != provenance_sha256 {
        return Err(invalid());
    }
    let provenance: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if provenance["schema_version"] != "forgeflow.retained-native-candidate-source.v1"
        || provenance["project_id"] != project
        || provenance["attempt_id"] != policy["source_attempt_id"]
        || provenance["task_id"] != policy["target_task_id"]
        || !provenance["candidate"].is_object()
    {
        return Err(invalid());
    }
    Ok(json!({
        "policy": policy,
        "source_provenance": provenance,
        "source_provenance_sha256": provenance_sha256,
        "config_sha256": request.config_sha256,
        "alignment_sha256": request.alignment_sha256,
        "native_panel_action_id": action["action_id"]
    }))
}

pub async fn list(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    _headers: HeaderMap,
) -> ApiResult<Value> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "native panel action inspection requires Owner authentication",
        ));
    }
    let mut actions = s
        .store
        .list_documents(&project, "native_panel_actions")
        .await?;
    // An observation after server restart can reconcile a finished persistent
    // unit; it never restarts the unit or replays the original delivery action.
    for action in &mut actions {
        if action["action"] == "START" && action["status"] == "RUNNING" {
            if let Some(updated) = observe_finished_delivery(&s, &project, action).await? {
                *action = updated;
            }
        }
    }
    Ok(view(actions))
}

pub async fn scheduling(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "native scheduling inspection requires Owner authentication",
        ));
    }
    s.store.get_project(&project).await?;
    Ok(view(s.store.native_panel_scheduling(&project).await?))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicyQuery {
    pub task_revision: Option<u64>,
}

pub async fn retry_policy(
    State(s): State<App>,
    Path((project, task)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    Query(query): Query<RetryPolicyQuery>,
) -> ApiResult<Value> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "native retry inspection requires Owner authentication",
        ));
    }
    let current = s.store.get_task(&project, &task).await?;
    let revision = query.task_revision.unwrap_or(current.task_revision);
    if revision == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "TASK_REVISION_INVALID",
            "semantic task revision must be positive",
        ));
    }
    Ok(view(
        s.store
            .native_panel_retry_policy(&project, &task, revision)
            .await?,
    ))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ObservationQuery {
    pub cursor: Option<u64>,
    pub limit: Option<u32>,
}

/// Project event sequence is the cursor, including scanned non-observation
/// events. No lifecycle, roster or model count is synthesized into an event.
pub async fn observations(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Query(query): Query<ObservationQuery>,
) -> ApiResult<Value> {
    authenticate(&actor, &headers)?;
    let cursor = query.cursor.unwrap_or(0);
    let limit = query.limit.unwrap_or(200).clamp(1, 500);
    let events = s.store.events(&project, cursor, limit).await?;
    let after = events
        .last()
        .map(|event| event.project_seq)
        .unwrap_or(cursor);
    let scanned = events.len();
    let items:Vec<_>=events.into_iter().filter(|event|event.kind=="native_child.observed").map(|event| {
        let mut value=serde_json::Map::new();
        for key in ["native_session_id","sessionId","parent_session_id","parentSessionId","childId","runId","seq",
            "label","phase","teamId","memberSeq","preset_id","position_id","status","messageId","targetId","senderId",
            "outcome","stopReason","callId","name","provider","model"] {
            if let Some(field)=event.payload["value"].get(key) { value.insert(key.into(),field.clone()); }
        }
        for key in ["member","task"] {
            if let Some(object)=event.payload["value"][key].as_object() {
                let selected:serde_json::Map<_,_>=object.iter().filter(|(name,_)|matches!(name.as_str(),
                    "id"|"name"|"role"|"phase"|"revision"|"subject"|"status"|"ownerName"|"blockedBy"|"writeScopes"|"ready"|"preset_id"|"position_id"|"sessionId"))
                    .map(|(name,value)|(name.clone(),value.clone())).collect();
                value.insert(key.into(),Value::Object(selected));
            }
        }
        json!({"event_id":event.event_id,"project_id":event.project_id,"event_seq":event.project_seq,
            "occurred_at":event.occurred_at,"attempt_id":event.object_id,"object_revision":event.object_revision,
            "event":event.payload["event"],"value":value,"grants_authority":false,"source":"POSTGRESQL_NATIVE_OBSERVATION"})
    }).collect();
    let watermark = s.store.project_cursor(&project).await?;
    Ok(Json(
        json!({"data":items,"source":"postgres","observed_at":Utc::now(),"cursor_after":after,
        "next_cursor":if after<watermark {Some(after.to_string())}else{None},"watermark":watermark,
        "scanned_project_events":scanned,"read_model_version":watermark,"observation_count":items.len(),
        "grants_authority":false,"lifecycle_rows_used_as_events":false}),
    ))
}

pub async fn request(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<NativePanelActionRequest>,
) -> Result<Response, ApiError> {
    authenticate(&actor, &headers)?;
    let identity = identity(&headers, &actor)?;
    let approved = approved_delivery(&project, &body)?;
    let catalog = s
        .store
        .get_document(&project, "planning_catalogs", &approved.catalog_id)
        .await?;
    let denominator = catalog["card_count"]
        .as_u64()
        .filter(|count| (1..=10_000).contains(count))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "NATIVE_PANEL_DENOMINATOR_INVALID",
                "approved project has no positive registered task denominator",
            )
        })?;
    if approved
        .expected_card_count
        .is_some_and(|expected| expected != denominator)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "NATIVE_PANEL_DENOMINATOR_STALE",
            "reviewed task denominator differs from registered project planning",
        ));
    }
    let trace = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&identity.idempotency_key)
        .to_owned();
    let receipt = s
        .store
        .execute_command(
            CommandIdentity {
                actor_id: "native-panel-service".into(),
                idempotency_key: format!(
                    "native-panel:{}:{}:{}",
                    actor.actor_id, project, identity.idempotency_key
                ),
            },
            CatalogCommand::RegisterNativePanelAction {
                project_id: project.clone(),
                requested_by: actor.actor_id,
                request_id: trace,
                expected_model: approved.expected_model.clone(),
                catalog_id: approved.catalog_id.clone(),
                expected_card_count: denominator,
                request: body,
            },
        )
        .await?;
    if !receipt.replayed {
        let state = s.clone();
        let action = receipt.value.clone();
        tokio::spawn(async move {
            if let Err(error) = run_action(state, project, action, approved).await {
                tracing::error!(code=%error.1.code, "native panel action persistence or observation failed");
            }
        });
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"data":receipt.value,"operation_id":receipt.value["action_id"],
        "replayed":receipt.replayed,"source":"postgres","delivery_completion_claimed":false}),
        ),
    )
        .into_response())
}

async fn settle(
    s: &App,
    project: &str,
    action: &Value,
    status: &str,
    result: Value,
) -> Result<Value, ApiError> {
    let id = action["action_id"].as_str().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "NATIVE_PANEL_ACTION_INVALID",
            "action identity missing",
        )
    })?;
    let revision = action["revision"].as_u64().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "NATIVE_PANEL_ACTION_INVALID",
            "action revision missing",
        )
    })?;
    Ok(s.store
        .execute_command(
            CommandIdentity {
                actor_id: "native-panel-service".into(),
                idempotency_key: format!("native-panel:{id}:{revision}:{status}"),
            },
            CatalogCommand::SettleNativePanelAction {
                project_id: project.into(),
                action_id: id.into(),
                expected_revision: revision,
                status: status.into(),
                result,
            },
        )
        .await?
        .value)
}

async fn run_action(
    s: App,
    project: String,
    action: Value,
    approved: ApprovedDelivery,
) -> Result<(), ApiError> {
    let id = action["action_id"].as_str().unwrap_or("");
    let (output, timed_out, helper_pid) = match helper_output(&approved, id).await {
        Ok(output) => output,
        _ => {
            settle(
                &s,
                &project,
                &action,
                "FAILED",
                json!({"code":"NATIVE_PANEL_HELPER_OUTCOME_UNKNOWN","command_outcome_unknown":true,"helper_exit_confirmed":false,"delivery_completion_claimed":false}),
            )
            .await?;
            return Ok(());
        }
    };
    let raw_hash = forgeflow_planner::sha256(&output.stdout);
    let stderr_hash = forgeflow_planner::sha256(&output.stderr);
    preserve_output(&s.data_root, id, "stdout", &output.stdout)?;
    preserve_output(&s.data_root, id, "stderr", &output.stderr)?;
    let parsed: Option<Value> = serde_json::from_slice(&output.stdout).ok();
    let valid = !timed_out
        && output.status.success()
        && output.stdout.len() <= 1_048_576
        && parsed.as_ref().is_some_and(|v| {
            v["action_id"].as_str() == Some(id) && v["entry_source"] == "DSH_NATIVE_PANEL"
        });
    if !valid {
        settle(&s, &project, &action, "FAILED", json!({"code":"NATIVE_PANEL_HELPER_REJECTED","exit_code":output.status.code(),
            "stdout_sha256":raw_hash,"stderr_sha256":stderr_hash,"helper_pid":helper_pid,"helper_exit_confirmed":true,
            "command_outcome_unknown":timed_out,"delivery_completion_claimed":false})).await?;
        return Ok(());
    }
    let returned = parsed.unwrap();
    let mut status = returned["status"]
        .as_str()
        .filter(|v| matches!(*v, "RUNNING" | "SUCCEEDED" | "FAILED"))
        .unwrap_or("FAILED");
    let mut startup_unconfirmed = false;
    if action["action"] == "START"
        && status == "RUNNING"
        && !confirmed_started_delivery_unit(&project, &returned).await
    {
        status = "FAILED";
        startup_unconfirmed = true;
    }
    if action["action"] == "START" && status == "SUCCEEDED" {
        let denominator = action["expected_card_count"].as_u64().unwrap_or(0);
        let accepted = native_acceptance_count(
            &s,
            &project,
            action["expected_provider_model_id"].as_str().unwrap_or(""),
            action["planning_catalog_id"].as_str().unwrap_or(""),
            denominator,
        )
        .await?;
        if denominator == 0 || accepted as u64 != denominator {
            status = "FAILED";
            startup_unconfirmed = true;
        }
    }
    let mut safe = serde_json::Map::new();
    for key in [
        "action_id",
        "entry_source",
        "status",
        "operation_id",
        "unit_name",
        "actual_service_main_pid",
        "service_active_state",
        "service_sub_state",
        "scheduling_paused",
        "scheduling_start_pending",
        "scheduling_action_id",
        "scheduling_requested_sequence",
        "scheduling_source",
        "action_superseded",
        "ordinary_safety_pause_changed",
        "author_stop_or_custody_release_claimed",
        "paused",
        "cancel_requested",
        "cancelled_attempt_count",
        "cancellations",
        "prepared_task_count",
        "retry_count",
        "code",
    ] {
        if let Some(value) = returned.get(key) {
            safe.insert(key.into(), value.clone());
        }
    }
    safe.insert("stdout_sha256".into(), raw_hash.into());
    safe.insert("stderr_sha256".into(), stderr_hash.into());
    safe.insert("delivery_completion_claimed".into(), false.into());
    safe.insert("status".into(), status.into());
    if startup_unconfirmed {
        safe.insert("code".into(), "NATIVE_DELIVERY_START_UNCONFIRMED".into());
    }
    safe.insert("helper_exit_confirmed".into(), true.into());
    safe.insert("helper_pid".into(), json!(helper_pid));
    let observed = settle(&s, &project, &action, status, Value::Object(safe)).await?;
    if action["action"] == "START" && status == "RUNNING" {
        monitor_delivery(&s, &project, observed).await?;
    }
    Ok(())
}

async fn confirmed_started_delivery_unit(project: &str, result: &Value) -> bool {
    let expected = format!(
        "forgeflow-delivery-{}.service",
        &forgeflow_planner::sha256(project.as_bytes())[..24]
    );
    let Some(pid) = result["actual_service_main_pid"]
        .as_u64()
        .filter(|pid| *pid > 0)
    else {
        return false;
    };
    if result["unit_name"].as_str() != Some(&expected) || result["service_active_state"] != "active"
    {
        return false;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("/usr/bin/systemctl")
            .args([
                "--user",
                "show",
                &expected,
                "--property=MainPID",
                "--property=ActiveState",
            ])
            .output(),
    )
    .await;
    let Ok(Ok(output)) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: BTreeMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    fields.get("ActiveState").copied() == Some("active")
        && fields
            .get("MainPID")
            .and_then(|value| value.parse::<u64>().ok())
            == Some(pid)
}

async fn helper_output(
    approved: &ApprovedDelivery,
    id: &str,
) -> std::io::Result<(std::process::Output, bool, Option<u32>)> {
    use tokio::io::AsyncReadExt;
    let mut child = tokio::process::Command::new("/usr/bin/python3")
        .arg(&approved.script_path)
        .arg("panel-action")
        .arg("--config")
        .arg(&approved.config_path)
        .arg("--action-id")
        .arg(id)
        .arg("--execute")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.take(1_048_577).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.take(1_048_577).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    });
    let (status, timed_out) =
        match tokio::time::timeout(Duration::from_secs(120), child.wait()).await {
            Ok(status) => (status?, false),
            Err(_) => {
                let _ = child.start_kill();
                let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
                    .await
                    .map_err(|_| std::io::Error::other("helper exit remains unconfirmed"))??;
                (status, true)
            }
        };
    let stdout = tokio::time::timeout(Duration::from_secs(10), stdout_task)
        .await
        .map_err(|_| std::io::Error::other("helper stdout remains open"))?
        .map_err(std::io::Error::other)??;
    let stderr = tokio::time::timeout(Duration::from_secs(10), stderr_task)
        .await
        .map_err(|_| std::io::Error::other("helper stderr remains open"))?
        .map_err(std::io::Error::other)??;
    Ok((
        std::process::Output {
            status,
            stdout,
            stderr,
        },
        timed_out,
        pid,
    ))
}

fn preserve_output(root: &FsPath, id: &str, stream: &str, bytes: &[u8]) -> Result<(), ApiError> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let directory = root.join("native-panel-actions").join(id);
        std::fs::create_dir_all(&directory).map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_PANEL_EVIDENCE_UNAVAILABLE",
                "native panel original output could not be preserved",
            )
        })?;
        std::fs::set_permissions(
            directory.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "NATIVE_PANEL_EVIDENCE_UNAVAILABLE",
                "native panel original output could not be preserved",
            )
        })?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "NATIVE_PANEL_EVIDENCE_UNAVAILABLE",
                    "native panel original output could not be preserved",
                )
            },
        )?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(format!("{stream}.log")))
            .map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "NATIVE_PANEL_EVIDENCE_UNAVAILABLE",
                    "native panel original output could not be preserved",
                )
            })?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "NATIVE_PANEL_EVIDENCE_UNAVAILABLE",
                    "native panel original output could not be preserved",
                )
            })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, id, stream, bytes);
        Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NATIVE_PANEL_PLATFORM_UNSUPPORTED",
            "native panel delivery supervision requires the configured Unix service host",
        ))
    }
}

async fn monitor_delivery(s: &App, project: &str, action: Value) -> Result<(), ApiError> {
    let mut shutdown = s.auth.shutdown_receiver();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {},
            _ = shutdown.changed() => return Ok(()),
        }
        if observe_finished_delivery(s, project, &action)
            .await?
            .is_some()
        {
            return Ok(());
        }
    }
}

fn supervisor_restart_pending(properties: &BTreeMap<&str, &str>, queued_start: bool) -> bool {
    // A configured restart policy alone is not evidence of recovery. Require
    // systemd's actual restart state or a queued start job, and never conceal
    // exhausted start limits or a missing persistent unit.
    if properties.get("LoadState").copied() != Some("loaded")
        || properties.get("Restart").copied() != Some("on-failure")
        || properties.get("Result").copied() == Some("start-limit-hit")
    {
        return false;
    }
    let queued = properties
        .get("Job")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|id| id > 0);
    (queued && queued_start)
        || (properties.get("ActiveState").copied() == Some("activating")
            && properties
                .get("SubState")
                .is_some_and(|value| value.starts_with("auto-restart")))
}

async fn observe_finished_delivery(
    s: &App,
    project: &str,
    action: &Value,
) -> Result<Option<Value>, ApiError> {
    let Some(unit) = action["result"]["unit_name"].as_str().filter(|unit| {
        unit.starts_with("forgeflow-")
            && unit.ends_with(".service")
            && unit.len() <= 200
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
    }) else {
        return Ok(None);
    };
    let output = tokio::process::Command::new("/usr/bin/systemctl")
        .args([
            "--user",
            "show",
            unit,
            "--property=ActiveState",
            "--property=SubState",
            "--property=ExecMainStatus",
            "--property=Result",
            "--property=LoadState",
            "--property=Restart",
            "--property=Job",
        ])
        .output()
        .await;
    let Ok(output) = output else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let properties: BTreeMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let queued_id = properties
        .get("Job")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|id| *id > 0);
    let mut queued_start = false;
    if let Some(id) = queued_id {
        let jobs = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("/usr/bin/systemctl")
                .args([
                    "--user",
                    "list-jobs",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                ])
                .output(),
        )
        .await;
        if let Ok(Ok(output)) = jobs {
            if output.status.success() {
                queued_start = String::from_utf8_lossy(&output.stdout).lines().any(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    fields.len() >= 4
                        && fields[0].parse::<u64>().ok() == Some(id)
                        && fields[1] == unit
                        && matches!(fields[2], "start" | "restart" | "try-restart")
                });
            }
        }
    }
    if supervisor_restart_pending(&properties, queued_start) {
        return Ok(None);
    }
    if !matches!(
        properties.get("ActiveState").copied(),
        Some("inactive" | "failed")
    ) {
        return Ok(None);
    }
    let expected_model = action["expected_provider_model_id"].as_str().unwrap_or("");
    let catalog_id = action["planning_catalog_id"].as_str().unwrap_or("");
    let denominator = action["expected_card_count"].as_u64().unwrap_or(0);
    let accepted =
        native_acceptance_count(s, project, expected_model, catalog_id, denominator).await?;
    let complete = denominator > 0
        && properties.get("ExecMainStatus").copied() == Some("0")
        && accepted as u64 == denominator;
    match settle(s, project, action, if complete {"SUCCEEDED"} else {"FAILED"}, json!({
            "unit_name":unit,"observed_unit_state":properties.get("ActiveState"),
            "observed_unit_result":properties.get("Result"),"observed_exec_main_status":properties.get("ExecMainStatus"),
            "native_dsh_accepted_cards":accepted,"card_denominator":denominator,"all_cards_native_terminal_accepted":complete,
            "delivery_completion_claimed":complete,"source":"ACTUAL_SYSTEMD_UNIT_AND_POSTGRESQL"})).await {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.1.code == "REVISION_CONFLICT" => {
                Ok(Some(s.store.get_document(project,"native_panel_actions",action["action_id"].as_str().unwrap_or("")).await?))
            }
            Err(error) => Err(error),
        }
}

async fn native_acceptance_count(
    s: &App,
    project: &str,
    expected_model: &str,
    catalog_id: &str,
    denominator: u64,
) -> Result<usize, ApiError> {
    use std::collections::BTreeSet;
    let catalog = s
        .store
        .get_document(project, "planning_catalogs", catalog_id)
        .await?;
    let ids: BTreeSet<_> = catalog["task_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if denominator == 0 || ids.len() as u64 != denominator || expected_model.is_empty() {
        return Ok(0);
    }
    let snapshot = s.store.snapshot(project).await?;
    let tasks: BTreeMap<_, _> = snapshot["tasks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| Some((t["task_id"].as_str()?, t["task_revision"].as_u64()?)))
        .collect();
    let profiles: BTreeSet<_> = snapshot["attempt_native_profiles"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["executor_kind"] == "DSH_MANAGED")
        .filter_map(|p| p["attempt_id"].as_str())
        .collect();
    let model_attempts: BTreeSet<_> = snapshot["native_model_requests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["status"] == "SETTLED" && m["model"].as_str() == Some(expected_model))
        .filter_map(|m| m["attempt_id"].as_str())
        .collect();
    let mut accepted: BTreeSet<_> = snapshot["attempts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| {
            a["state"] == "SUCCEEDED"
                && a["task_id"].as_str().is_some_and(|id| {
                    ids.contains(id) && a["task_revision"].as_u64() == tasks.get(id).copied()
                })
                && a["attempt_id"]
                    .as_str()
                    .is_some_and(|id| profiles.contains(id) && model_attempts.contains(id))
        })
        .filter_map(|a| a["task_id"].as_str().map(str::to_owned))
        .collect();
    // Store projects only protected acceptances whose current source revision
    // and digest match and whose independent review and merge are finalized.
    // Credit the original Native product card, preserving its cancelled author;
    // the zero-model review is never a Native author or an extra product card.
    for receipt in s.store.retained_candidate_acceptances(project).await? {
        let source = &receipt["source"];
        let Some(task_id) = source["task_id"].as_str() else {
            continue;
        };
        let Some(attempt_id) = source["attempt_id"].as_str() else {
            continue;
        };
        if receipt["accepted"] == true
            && receipt["native_producer_lineage"] == true
            && ids.contains(task_id)
            && source["task_revision"].as_u64() == tasks.get(task_id).copied()
            && profiles.contains(attempt_id)
            && model_attempts.contains(attempt_id)
        {
            accepted.insert(task_id.to_owned());
        }
    }
    Ok(accepted.len())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn supervisor_observation_requires_actual_bounded_recovery() {
        let mut properties = BTreeMap::from([
            ("LoadState", "loaded"),
            ("Restart", "on-failure"),
            ("ActiveState", "activating"),
            ("SubState", "auto-restart"),
            ("Result", "exit-code"),
            ("Job", ""),
        ]);
        assert!(supervisor_restart_pending(&properties, false));
        properties.insert("ActiveState", "inactive");
        properties.insert("SubState", "dead");
        assert!(!supervisor_restart_pending(&properties, false));
        properties.insert("Job", "42");
        assert!(supervisor_restart_pending(&properties, true));
        assert!(!supervisor_restart_pending(&properties, false));
        properties.insert("Result", "start-limit-hit");
        assert!(!supervisor_restart_pending(&properties, true));
        properties.insert("Result", "exit-code");
        properties.insert("LoadState", "not-found");
        assert!(!supervisor_restart_pending(&properties, true));
        properties.insert("LoadState", "loaded");
        properties.insert("Restart", "no");
        assert!(!supervisor_restart_pending(&properties, true));
    }
    #[test]
    fn private_configuration_rejects_public_files_and_symlinks() {
        let root =
            std::env::temp_dir().join(format!("forgeflow-panel-private-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("key");
        std::fs::write(&path, b"fixture-not-a-live-secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_bytes(&path, 4096).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            private_bytes(&path, 4096).unwrap(),
            b"fixture-not-a-live-secret"
        );
        let alias = root.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(private_bytes(&alias, 4096).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
    #[test]
    fn native_bootstrap_redirect_only_accepts_the_pinned_local_connection() {
        let fixture = json!({"schema_version":"forgeflow.native-ui-bootstrap.v1",
            "url":"http://127.0.0.1:19388/?token=fixture-native-connection-only",
            "port":19388,"created_at":"2026-10-12T00:00:00Z",
            "source":"ACTUAL_NATIVE_CONNECTION_AUTHENTICATED_URL"});
        assert!(native_ui_location(&serde_json::to_vec(&fixture).unwrap(), 19388).is_ok());
        for url in [
            "http://example.com:19388/?token=fixture-native-connection-only",
            "http://user:pass@127.0.0.1:19388/?token=fixture-native-connection-only",
            "http://127.0.0.1:19389/?token=fixture-native-connection-only",
            "http://127.0.0.1:19388/?token=fixture-native-connection-only&redirect=https://example.com",
            "https://127.0.0.1:19388/?token=fixture-native-connection-only",
        ] {
            let mut changed = fixture.clone();
            changed["url"] = url.into();
            assert!(native_ui_location(&serde_json::to_vec(&changed).unwrap(), 19388).is_err());
        }
    }
}
