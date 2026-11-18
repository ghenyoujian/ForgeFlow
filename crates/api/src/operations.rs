use super::*;
use forgeflow_evidence::{EvidenceBinding, VerificationPlan};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    project_id: String,
    #[serde(default)]
    native_panel_action_id: Option<String>,
    #[serde(default)]
    verification_recovery: Option<VerificationRecoveryRequest>,
}

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCandidateReviewRequest {
    native_panel_action_id: String,
    source_attempt_id: String,
    target_task_id: String,
    expected_target_task_revision: u64,
    review_task_id: String,
    expected_review_task_revision: u64,
    source_provenance_sha256: String,
}

async fn retained_native_source_facts(
    s: &App,
    project: &str,
    source_attempt_id: &str,
) -> Result<Value, ApiError> {
    let invalid =
        |message: &str| ApiError::new(StatusCode::CONFLICT, "RETAINED_CANDIDATE_INVALID", message);
    if uuid::Uuid::parse_str(source_attempt_id).is_err() {
        return Err(invalid("retained source attempt identity is invalid"));
    }
    let mut source = s
        .store
        .retained_native_candidate_source(project, source_attempt_id)
        .await?;
    if source["schema_version"] != "forgeflow.retained-native-candidate-source.v1"
        || source["project_id"] != project
        || source["attempt_id"] != source_attempt_id
    {
        return Err(invalid("retained source facts have a different identity"));
    }
    let base = source["base_sha"]
        .as_str()
        .ok_or_else(|| invalid("source base is missing"))?;
    let scope = forgeflow_git::PathScope {
        owner_paths: serde_json::from_value(source["owner_paths"].clone()).map_err(json_error)?,
        write_set: serde_json::from_value(source["write_set"].clone()).map_err(json_error)?,
    };
    let worktree_root = s
        .data_root
        .join("worktrees")
        .canonicalize()
        .map_err(io_error)?;
    let worktree = worktree_root
        .join(source_attempt_id)
        .canonicalize()
        .map_err(io_error)?;
    if worktree.parent() != Some(worktree_root.as_path()) {
        return Err(invalid(
            "retained candidate directory escapes the server worktree root",
        ));
    }
    let observed =
        forgeflow_git::audit_private_worktree(&worktree, base, &scope).map_err(git_error)?;
    if observed.changes.is_empty()
        || observed
            .changes
            .iter()
            .any(|change| change.layer != "committed")
        || !observed.untracked.is_empty()
    {
        return Err(invalid(
            "retained source must be a nonempty already-frozen candidate",
        ));
    }
    let candidate = forgeflow_git::Candidate {
        base_sha: observed.base_sha.clone(),
        candidate_sha: observed.head_sha.clone(),
        diff_manifest_hash: observed.hash.clone(),
        source_hash: forgeflow_git::source_hash(&worktree, &observed.head_sha)
            .map_err(git_error)?,
        manifest: observed,
    };
    source["candidate"] = serde_json::to_value(candidate).map_err(json_error)?;
    Ok(source)
}

/// This creates a review authorization, never an execution or a success claim.
pub async fn candidate_review(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(request): Json<RetainedCandidateReviewRequest>,
) -> ApiResult<Value> {
    crate::native_panel::authenticate(&actor, &headers)?;
    let original_identity = identity(&headers, &actor)?;
    let invalid =
        |message: &str| ApiError::new(StatusCode::CONFLICT, "RETAINED_CANDIDATE_INVALID", message);
    let action = s
        .store
        .get_document(
            &project,
            "native_panel_actions",
            &request.native_panel_action_id,
        )
        .await?;
    let approved = crate::native_panel::approved_candidate_reuse_config(&project, &action)?;
    let policy = &approved["policy"];
    let requested = serde_json::to_value(&request).map_err(json_error)?;
    if [
        "source_attempt_id",
        "target_task_id",
        "expected_target_task_revision",
        "review_task_id",
        "expected_review_task_revision",
    ]
    .iter()
    .any(|field| requested[*field] != policy[*field])
        || requested["source_provenance_sha256"] != approved["source_provenance_sha256"]
        || request.source_attempt_id == request.review_task_id
        || uuid::Uuid::parse_str(&request.source_attempt_id).is_err()
    {
        return Err(invalid(
            "review request differs from the Native-approved policy",
        ));
    }
    let target_task = s.store.get_task(&project, &request.target_task_id).await?;
    let review_task = s.store.get_task(&project, &request.review_task_id).await?;
    if target_task.task_revision != request.expected_target_task_revision
        || review_task.task_revision != request.expected_review_task_revision
        || target_task.task_id == review_task.task_id
    {
        return Err(invalid(
            "source or new review task revision changed after approval",
        ));
    }
    let source = retained_native_source_facts(&s, &project, &request.source_attempt_id).await?;
    let candidate: forgeflow_git::Candidate =
        serde_json::from_value(source["candidate"].clone()).map_err(json_error)?;
    if source != approved["source_provenance"] || source["task_id"] != target_task.task_id {
        return Err(invalid(
            "pinned provenance differs from authoritative Native source facts",
        ));
    }
    let envelope = review_task
        .envelope
        .as_ref()
        .ok_or_else(|| invalid("new review task has no approved execution envelope"))?;
    let plan = decode_plan(
        s.store
            .get_document(
                &project,
                "verification_plans",
                &envelope.verification_plan_id,
            )
            .await?,
    )?;
    if envelope.session_purpose != SessionPurpose::Review
        || !envelope.write_set.is_empty()
        || !review_task.write_set.is_empty()
        || envelope.max_model_requests != 0
        || envelope.base_sha != candidate.base_sha
        || plan.task_revision != review_task.task_revision
        || plan.input_hash != review_task.input_digest
        || plan
            .commands
            .iter()
            .map(|command| command.expected_cases.len())
            .sum::<usize>()
            != 8
        || policy["verification_plan_id"] != plan.plan_id
        || policy["verification_plan_sha256"] != plan.digest()
        || policy["executor_profile_id"] != envelope.executor_profile_id
        || policy["resource_profile_id"] != envelope.resource_profile_id
        || policy["model_route_id"] != envelope.model_route_id
    {
        return Err(invalid(
            "new review envelope or eight-case verifier differs from approval",
        ));
    }
    let binding = json!({
        "schema_version": "forgeflow.retained-native-candidate.v1",
        "source_provenance_sha256": request.source_provenance_sha256,
        "source": source,
        "target": {
            "project_id": project,
            "task_id": review_task.task_id,
            "task_revision": review_task.task_revision,
            "input_digest": review_task.input_digest,
            "verification_plan_id": plan.plan_id,
            "verification_plan_hash": plan.digest(),
            "executor_profile_id": envelope.executor_profile_id,
            "resource_profile_id": envelope.resource_profile_id,
            "model_route_id": envelope.model_route_id,
            "static_execution_template_sha256": forgeflow_planner::static_execution_template_digest(envelope)
        },
        "approvals": {
            "native_panel_action_id": request.native_panel_action_id,
            "config_sha256": approved["config_sha256"],
            "alignment_sha256": approved["alignment_sha256"]
        }
    });
    let receipt = s
        .store
        .execute_command(
            CommandIdentity {
                actor_id: "native-candidate-review-service".into(),
                idempotency_key: format!(
                    "retained-candidate:{}:{}:{}",
                    actor.actor_id, project, original_identity.idempotency_key
                ),
            },
            CatalogCommand::AuthorizeRetainedCandidateReview {
                project_id: project,
                binding,
            },
        )
        .await?;
    Ok(Json(json!({
        "data": receipt.value,
        "operation_id": receipt.operation_id,
        "replayed": receipt.replayed,
        "source": "postgres"
    })))
}

/// Review tooling can pin server-derived source facts without exposing config paths.
pub async fn candidate_review_source(
    State(s): State<App>,
    Path((project, source_attempt_id)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    crate::native_panel::authenticate(&actor, &headers)?;
    Ok(view(
        retained_native_source_facts(&s, &project, &source_attempt_id).await?,
    ))
}

/// Accepted producer lineage is a projection of finalized authority facts.
pub async fn candidate_acceptances(
    State(s): State<App>,
    Path(project): Path<String>,
    Extension(actor): Extension<Principal>,
) -> ApiResult<Value> {
    if actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "retained candidate acceptances require Owner authentication",
        ));
    }
    Ok(view_from(
        s.store.retained_candidate_acceptances(&project).await?,
        "POSTGRESQL_RETAINED_NATIVE_ACCEPTANCE",
    ))
}

#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationRecoveryRequest {
    prior_operation_id: String,
    repair_id: String,
    repair_revision: u64,
    repair_sha256: String,
    preflight_proof_sha256: String,
    runtime_manifest_sha256: String,
    original_plan_sha256: String,
}

struct ApprovedVerificationRecovery {
    authorization: Value,
    runtime: Value,
}

struct RetainedNativeCandidate {
    authorization: Value,
    source_attempt_id: String,
    candidate: forgeflow_git::Candidate,
    scope: forgeflow_git::PathScope,
}

impl RetainedNativeCandidate {
    fn load(
        project: &str,
        attempt: &Attempt,
        task: &TaskCard,
        envelope: &ExecutionEnvelope,
        plan: &VerificationPlan,
        bindings: &Value,
    ) -> Result<Option<Self>, ApiError> {
        let Some(authorization) = bindings.get("retained_native_candidate") else {
            return Ok(None);
        };
        let invalid = || {
            ApiError::new(
                StatusCode::CONFLICT,
                "RETAINED_CANDIDATE_INVALID",
                "retained candidate authorization differs from the admitted review",
            )
        };
        let source = &authorization["source"];
        let target = &authorization["target"];
        let source_attempt_id = source["attempt_id"].as_str().ok_or_else(invalid)?;
        let candidate: forgeflow_git::Candidate =
            serde_json::from_value(source["candidate"].clone()).map_err(json_error)?;
        let scope = forgeflow_git::PathScope {
            owner_paths: serde_json::from_value(source["owner_paths"].clone())
                .map_err(json_error)?,
            write_set: serde_json::from_value(source["write_set"].clone()).map_err(json_error)?,
        };
        let mut hashed = authorization.clone();
        let expected_hash = hashed
            .as_object_mut()
            .and_then(|object| object.remove("authorization_sha256"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .filter(|digest| valid_digest(digest))
            .ok_or_else(invalid)?;
        if let Some(target) = hashed["target"].as_object_mut() {
            target.remove("attempt_id");
            target.remove("generation");
        }
        if authorization["schema_version"] != "forgeflow.retained-native-candidate.v1"
            || forgeflow_planner::sha256(
                &serde_json::to_vec(&json!([
                    "forgeflow.retained-review.authorization.v1",
                    hashed
                ]))
                .map_err(json_error)?,
            ) != expected_hash
            || authorization["authorization_id"]
                .as_str()
                .is_none_or(str::is_empty)
            || source["project_id"] != project
            || uuid::Uuid::parse_str(source_attempt_id).is_err()
            || source_attempt_id == attempt.attempt_id
            || source["base_sha"] != candidate.base_sha
            || candidate.base_sha != attempt.base_sha
            || candidate.manifest.base_sha != candidate.base_sha
            || candidate.manifest.head_sha != candidate.candidate_sha
            || candidate.manifest.hash != candidate.diff_manifest_hash
            || candidate.manifest.changes.is_empty()
            || candidate.manifest.changes.iter().any(|change| {
                change.layer != "committed"
                    || !scope.permits(&change.path)
                    || change
                        .old_path
                        .as_ref()
                        .is_some_and(|path| !scope.permits(path))
            })
            || !candidate.manifest.untracked.is_empty()
            || scope.owner_paths.is_empty()
            || scope.write_set.is_empty()
            || target["project_id"] != project
            || target["task_id"] != attempt.task_id
            || target["task_revision"].as_u64() != Some(attempt.task_revision)
            || target["input_digest"] != task.input_digest
            || target["verification_plan_id"] != plan.plan_id
            || target["verification_plan_hash"] != plan.digest()
            || target["executor_profile_id"] != envelope.executor_profile_id
            || target["resource_profile_id"] != envelope.resource_profile_id
            || target["model_route_id"] != envelope.model_route_id
            || target["attempt_id"] != attempt.attempt_id
            || target["generation"].as_i64() != Some(attempt.generation)
            || target["static_execution_template_sha256"]
                != forgeflow_planner::static_execution_template_digest(envelope)
            || envelope.session_purpose != SessionPurpose::Review
            || !envelope.write_set.is_empty()
            || !task.write_set.is_empty()
            || envelope.max_model_requests != 0
            || bindings["executor_profile"]["kind"] != "CONTROLLED_LIGHTWEIGHT"
            || bindings["resource_profile"]["physical_limits"]["required"] != true
        {
            return Err(invalid());
        }
        Ok(Some(Self {
            authorization: authorization.clone(),
            source_attempt_id: source_attempt_id.into(),
            candidate,
            scope,
        }))
    }

    fn lineage(&self) -> Value {
        let source = &self.authorization["source"];
        json!({
            "schema_version": "forgeflow.retained-native-candidate-lineage.v1",
            "authorization_id": self.authorization["authorization_id"],
            "authorization_sha256": self.authorization["authorization_sha256"],
            "source_provenance_sha256": self.authorization["source_provenance_sha256"],
            "source_attempt_id": source["attempt_id"],
            "source_generation": source["generation"],
            "source_task_id": source["task_id"],
            "source_task_revision": source["task_revision"],
            "source_input_digest": source["input_digest"],
            "source_base_sha": source["base_sha"],
            "source_candidate_sha": self.candidate.candidate_sha,
            "source_diff_manifest_hash": self.candidate.diff_manifest_hash,
            "source_tree_oid": self.candidate.source_hash,
            "source_native_root_binding": source["native_root_binding"],
            "source_model_request_ids": source["model_request_ids"],
            "source_model_settlement_sha256": source["model_settlement_sha256"],
            "source_physical_stop_proof_sha256": source["physical_stop_proof_sha256"],
            "source_planning_card_id": source["planning_card_id"],
            "review_execution_kind": "CONTROLLED_LIGHTWEIGHT",
            "review_model_calls": 0,
            "source_attempt_state_modified": false
        })
    }
}

impl ApprovedVerificationRecovery {
    async fn load(
        s: &App,
        project: &str,
        attempt_id: &str,
        action_id: &str,
        request: &VerificationRecoveryRequest,
    ) -> Result<Self, ApiError> {
        let invalid = |message: &str| {
            ApiError::new(
                StatusCode::CONFLICT,
                "VERIFICATION_RECOVERY_INVALID",
                message,
            )
        };
        if request.prior_operation_id.len() != 32
            || !request
                .prior_operation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || request.repair_id.trim().is_empty()
            || request.repair_revision == 0
            || !forgeflow_domain::valid_digest(&request.repair_sha256)
        {
            return Err(invalid(
                "recovery repair identity or original operation is invalid",
            ));
        }
        let action = s
            .store
            .get_document(project, "native_panel_actions", action_id)
            .await?;
        let approved =
            crate::native_panel::approved_verification_recovery_config(project, &action)?;
        let policy = &approved["policy"];
        let attempt = s.store.get_attempt(project, attempt_id).await?;
        let bindings = s.store.attempt_bindings(project, attempt_id).await?;
        let plan = decode_plan(bindings["verification_plan"].clone())?;
        let envelope: ExecutionEnvelope = serde_json::from_slice(
            &tokio::fs::read(
                s.data_root
                    .join("attempts")
                    .join(attempt_id)
                    .join("envelope.json"),
            )
            .await
            .map_err(io_error)?,
        )
        .map_err(json_error)?;
        let request_value = serde_json::to_value(request).map_err(json_error)?;
        for field in [
            "prior_operation_id",
            "repair_id",
            "repair_revision",
            "repair_sha256",
            "runtime_manifest_sha256",
            "original_plan_sha256",
        ] {
            if request_value[field] != policy[field] {
                return Err(invalid(
                    "recovery request differs from the Native-approved policy",
                ));
            }
        }
        if policy["attempt_id"] != attempt_id
            || policy["generation"].as_i64() != Some(attempt.generation)
            || policy["task_revision"].as_u64() != Some(attempt.task_revision)
            || policy["allowed_error_code"] != "VERIFICATION_FAILED"
            || policy["expected_failure_message"]
                != "VERIFIER_INVALID: independent verifier input is inside candidate write tree"
            || policy["preflight_proof"]["sha256"].as_str()
                != Some(request.preflight_proof_sha256.as_str())
            || !matches!(
                attempt.state,
                AttemptState::Verifying | AttemptState::ReviewReady | AttemptState::Succeeded
            )
            || envelope.attempt_id != attempt_id
            || envelope.project_id != project
            || envelope.generation != attempt.generation
            || envelope.task_revision != attempt.task_revision
            || plan.digest() != request.original_plan_sha256
            || plan.task_revision != attempt.task_revision
            || super::project_contracts::verification_contract(project, &plan.contract_version)?
                .is_none()
            || plan
                .commands
                .iter()
                .map(|command| command.expected_cases.len())
                .sum::<usize>()
                == 0
        {
            return Err(invalid(
                "recovery must bind the original stopped attempt and its nonempty frozen verification plan",
            ));
        }
        let receipt = s
            .store
            .catalog_service_receipt(
                "verification-service",
                &format!("{}:settled", request.prior_operation_id),
            )
            .await?
            .ok_or_else(|| invalid("original immutable verifier failure receipt is missing"))?;
        let original = &receipt["response"]["value"];
        if receipt["request"]["kind"] != "PUT_DOCUMENT"
            || receipt["request"]["payload"]["project_id"] != project
            || receipt["request"]["payload"]["collection"] != "operations"
            || receipt["request"]["payload"]["id"] != request.prior_operation_id
            || original["project_id"] != project
            || original["attempt_id"] != attempt_id
            || original["operation_id"] != request.prior_operation_id
            || original["status"] != "FAILED"
            || original["error"]["code"] != policy["allowed_error_code"]
            || original["error"]["message"] != policy["expected_failure_message"]
        {
            return Err(invalid(
                "original service receipt is not the approved verifier preflight failure",
            ));
        }
        let prefix = PathBuf::from(&envelope.artifact_prefix);
        let prior_root = if prefix.is_absolute() {
            prefix.join(&request.prior_operation_id)
        } else {
            s.data_root
                .join("artifacts")
                .join(prefix)
                .join(&request.prior_operation_id)
        };
        let context: forgeflow_evidence::PhysicalVerificationContext = serde_json::from_slice(
            &pinned_verifier_bytes(&prior_root.join("verification-physical-context.json"))
                .map_err(io_error)?,
        )
        .map_err(json_error)?;
        context
            .validate(
                &plan,
                &prior_root.canonicalize().map_err(io_error)?,
                attempt_id,
                attempt.generation,
            )
            .map_err(|error| invalid(&error.to_string()))?;
        let closed: Value = serde_json::from_slice(
            &pinned_verifier_bytes(&prior_root.join("verification-physical-closed.json"))
                .map_err(io_error)?,
        )
        .map_err(json_error)?;
        if closed["runner_closed"] != true
            || closed["context"] != serde_json::to_value(&context).map_err(json_error)?
            || closed["unused_execution_ids"].as_array().is_none_or(|ids| {
                ids.len() != plan.commands.len()
                    || context
                        .commands
                        .iter()
                        .any(|command| !ids.contains(&json!(command.execution_id)))
            })
            || std::fs::read_dir(&prior_root)
                .map_err(io_error)?
                .any(|entry| match entry {
                    Ok(entry) => !matches!(
                        entry.file_name().to_str(),
                        Some(
                            "verification-physical-context.json"
                                | "verification-physical-closed.json"
                        )
                    ),
                    Err(_) => true,
                })
        {
            return Err(invalid(
                "original verifier did not close before any case or process launch",
            ));
        }
        let mut authorization = request_value;
        let object = authorization.as_object_mut().unwrap();
        object.insert(
            "schema_version".into(),
            json!("forgeflow.native-verification-recovery.v1"),
        );
        object.insert("native_panel_action_id".into(), json!(action_id));
        object.insert("project_id".into(), json!(project));
        object.insert("attempt_id".into(), json!(attempt_id));
        object.insert("generation".into(), json!(attempt.generation));
        object.insert("task_revision".into(), json!(attempt.task_revision));
        object.insert("config_sha256".into(), approved["config_sha256"].clone());
        object.insert(
            "alignment_sha256".into(),
            approved["alignment_sha256"].clone(),
        );
        object.insert("expected_case_count".into(), json!(8));
        object.insert("max_once".into(), json!(1));
        if policy["resume_never_launched"] == true {
            object.insert("resume_never_launched".into(), json!(true));
            object.insert(
                "resume_preflight_proof_sha256".into(),
                policy["resume_preflight_proof"]["sha256"].clone(),
            );
        }
        Ok(Self {
            authorization,
            runtime: approved["runtime"].clone(),
        })
    }

    fn claim_id(&self) -> String {
        format!(
            "verification-recovery:{}",
            forgeflow_planner::sha256(
                &serde_json::to_vec(&json!([
                    "forgeflow.native-verification-recovery.claim.v1",
                    self.authorization["project_id"],
                    self.authorization["attempt_id"],
                    self.authorization["generation"],
                    self.authorization["task_revision"],
                    self.authorization["original_plan_sha256"]
                ]))
                .expect("serializable immutable recovery scope")
            )
        )
    }
}
fn operation_id(actor: &Principal, headers: &HeaderMap) -> Result<String, ApiError> {
    let key = identity(headers, actor)?;
    Ok(
        forgeflow_planner::sha256(format!("{}:{}", key.actor_id, key.idempotency_key).as_bytes())
            [..32]
            .into(),
    )
}
pub async fn verify(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ExecuteRequest>,
) -> Result<Response, ApiError> {
    start(s, attempt, actor, headers, body, false).await
}
pub async fn verify_integrate(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<ExecuteRequest>,
) -> Result<Response, ApiError> {
    start(s, attempt, actor, headers, body, true).await
}
async fn start(
    s: App,
    attempt: String,
    actor: Principal,
    headers: HeaderMap,
    body: ExecuteRequest,
    integrate: bool,
) -> Result<Response, ApiError> {
    let identity = identity(&headers, &actor)?;
    let recovery = match (&body.native_panel_action_id, &body.verification_recovery) {
        (None, None) => None,
        (Some(action), Some(request)) if !actor.worker => Some(
            ApprovedVerificationRecovery::load(&s, &body.project_id, &attempt, action, request)
                .await?,
        ),
        _ => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "VERIFICATION_RECOVERY_INVALID",
                "Native recovery requires Owner identity and both recovery authority fields",
            ));
        }
    };
    let id = recovery
        .as_ref()
        .map(ApprovedVerificationRecovery::claim_id)
        .unwrap_or(operation_id(&actor, &headers)?);
    let mut value = json!({"operation_id":id,"kind":if integrate{"VERIFY_AND_INTEGRATE"}else{"VERIFY"},"project_id":body.project_id,"attempt_id":attempt,"status":"ACCEPTED"});
    if let Some(recovery) = &recovery {
        value["verification_recovery_authorization"] = recovery.authorization.clone();
    }
    let resume = recovery
        .as_ref()
        .is_some_and(|recovery| recovery.authorization["resume_never_launched"] == true);
    if resume {
        let old = s
            .store
            .get_document(&body.project_id, "operations", &id)
            .await?;
        let failure = s
            .store
            .catalog_service_receipt("verification-service", &format!("{id}:settled"))
            .await?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "VERIFICATION_RECOVERY_INVALID",
                    "original recovery failure receipt is missing",
                )
            })?;
        let failed = &failure["response"]["value"];
        if old["revision"] != 2
            || old["status"] != "FAILED"
            || failed["operation_id"] != id
            || failed["attempt_id"] != attempt
            || failed["error"]["code"] != "PHYSICAL_BINDING_MISMATCH"
            || failed["error"]["message"] != "VERIFIER_INVALID: unsafe identity"
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "VERIFICATION_RECOVERY_INVALID",
                "only the exact never-launched unsafe-identity failure may resume",
            ));
        }
        let envelope: ExecutionEnvelope = serde_json::from_slice(
            &tokio::fs::read(
                s.data_root
                    .join("attempts")
                    .join(&attempt)
                    .join("envelope.json"),
            )
            .await
            .map_err(io_error)?,
        )
        .map_err(json_error)?;
        let prefix = PathBuf::from(&envelope.artifact_prefix);
        let root = if prefix.is_absolute() {
            prefix.join(&id)
        } else {
            s.data_root.join("artifacts").join(prefix).join(&id)
        };
        if std::fs::read_dir(&root).map_err(io_error)?.next().is_some() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "VERIFICATION_RECOVERY_INVALID",
                "recovery root is not an empty never-launched directory",
            ));
        }
        value["previous_failure_snapshot"] = old;
    }
    let command_identity = if recovery.is_some() {
        CommandIdentity {
            actor_id: "verification-recovery-service".into(),
            idempotency_key: if resume {
                format!("resume-never-launched:{id}")
            } else {
                format!("claim:{id}")
            },
        }
    } else {
        identity
    };
    let receipt = s
        .store
        .execute_command(
            command_identity,
            CatalogCommand::PutDocument {
                project_id: body.project_id.clone(),
                collection: "operations".into(),
                id: id.clone(),
                expected_revision: resume.then_some(2),
                value,
            },
        )
        .await?;
    if !receipt.replayed {
        let accepted_revision = receipt.value["revision"].as_u64().unwrap_or(1);
        let state = s.clone();
        let p = body.project_id.clone();
        let op = id.clone();
        tokio::spawn(async move {
            let result = run(state.clone(), &p, &attempt, &op, integrate).await;
            let value = match result {
                Ok(value) => {
                    json!({"operation_id":op,"project_id":p,"attempt_id":attempt,"status":"SUCCEEDED","result":value})
                }
                Err(error) => {
                    json!({"operation_id":op,"project_id":p,"attempt_id":attempt,"status":if error.1.code=="COMMIT_IN_PROGRESS"{"RECOVERY_REQUIRED"}else{"FAILED"},"error":error.1})
                }
            };
            let save = state
                .store
                .execute_command(
                    CommandIdentity {
                        actor_id: "verification-service".into(),
                        idempotency_key: if accepted_revision == 1 {
                            format!("{op}:settled")
                        } else {
                            format!("{op}:settled:rev{accepted_revision}")
                        },
                    },
                    CatalogCommand::PutDocument {
                        project_id: p,
                        collection: "operations".into(),
                        id: op,
                        expected_revision: Some(accepted_revision),
                        value,
                    },
                )
                .await;
            if let Err(error) = save {
                tracing::error!(%error,"operation settlement persistence failed");
            }
        });
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"data":receipt.value,"operation_id":id,"replayed":receipt.replayed})),
    )
        .into_response())
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationView {
    #[default]
    Full,
    Summary,
}

#[derive(Default, Deserialize)]
pub struct OperationQuery {
    #[serde(default)]
    view: OperationView,
}

pub async fn get(
    State(s): State<App>,
    Path(id): Path<String>,
    Query(query): Query<OperationQuery>,
) -> ApiResult<Value> {
    for p in s.store.list_projects().await? {
        if let Ok(mut value) = s.store.get_document(&p.project_id, "operations", &id).await {
            if value["kind"] == "EXECUTION_TEMPLATE_ASSEMBLY"
                && value["result"]["schema_version"] == forgeflow_store::TEMPLATE_ASSEMBLY_RESULT_V2
            {
                if value["project_id"].as_str() != Some(p.project_id.as_str())
                    || value["operation_id"].as_str() != Some(id.as_str())
                    || value["status"] != "SUCCEEDED"
                {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "TEMPLATE_RECEIPT_INVALID",
                        "template operation identity differs from its stored namespace",
                    ));
                }
                let references: forgeflow_store::TemplateAssemblyReferences =
                    serde_json::from_value(json!({
                        "flow_ref":value["result"]["flow_ref"],
                        "binding_receipt":value["result"]["binding_receipt"],
                    }))
                    .map_err(json_error)?;
                let (flow, context) = s
                    .store
                    .resolve_template_assembly_references(&p.project_id, &id, &references)
                    .await?;
                if matches!(query.view, OperationView::Full) {
                    let result = value["result"].as_object_mut().ok_or_else(|| {
                        ApiError::new(
                            StatusCode::CONFLICT,
                            "TEMPLATE_RECEIPT_INVALID",
                            "template result must be an object",
                        )
                    })?;
                    for field in [
                        "schema_version",
                        "flow_ref",
                        "binding_receipt",
                        "task_id",
                        "task_revision",
                    ] {
                        result.remove(field);
                    }
                    result.insert("flow".into(), flow);
                    result.insert("context".into(), context);
                }
            }
            let task_id =
                if value.get("kind").and_then(Value::as_str) == Some("DSH_FLOW_GENERATION") {
                    Some(format!("planning-{id}"))
                } else {
                    None
                };
            let attempts = s.store.list_attempts(&p.project_id).await?;
            let attempt = attempts
                .into_iter()
                .filter(|a| {
                    task_id.as_ref().is_some_and(|id| &a.task_id == id)
                        || value.get("attempt_id").and_then(Value::as_str)
                            == Some(a.attempt_id.as_str())
                })
                .max_by_key(|a| a.created_at);
            if let Some(attempt) = attempt {
                value["execution"] = json!({"project_id":attempt.project_id,"task_id":attempt.task_id,"attempt_id":attempt.attempt_id,"generation":attempt.generation,"phase":attempt.state,"source":"postgres"});
            } else if let Some(task_id) = task_id {
                if let Ok(task) = s.store.get_task(&p.project_id, &task_id).await {
                    let queue = s
                        .store
                        .get_document(&p.project_id, "queue_entries", &task_id)
                        .await
                        .ok();
                    value["execution"] = json!({"project_id":p.project_id,"task_id":task.task_id,"phase":queue.as_ref().and_then(|q|q.get("status")).cloned().unwrap_or(json!("NOT_QUEUED")),"queue":queue,"source":"postgres"});
                }
            }
            return Ok(view(value));
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "OPERATION_NOT_FOUND",
        "operation not found",
    ))
}
pub async fn list(State(s): State<App>, Path(project): Path<String>) -> ApiResult<Value> {
    Ok(view(s.store.list_documents(&project, "operations").await?))
}
pub(crate) async fn run(
    s: App,
    project: &str,
    attempt_id: &str,
    op: &str,
    integrate: bool,
) -> Result<Value, ApiError> {
    let attempt = s.store.get_attempt(project, attempt_id).await?;
    if attempt.state != AttemptState::Verifying
        && !(integrate && attempt.state == AttemptState::ReviewReady)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "ATTEMPT_NOT_VERIFYING",
            "verification requires stopped executor in VERIFYING",
        ));
    }
    let task = s.store.get_task(project, &attempt.task_id).await?;
    if task.task_revision != attempt.task_revision {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "INPUT_DRIFT",
            "task revision differs from attempt",
        ));
    }
    let envelope: ExecutionEnvelope = serde_json::from_slice(
        &tokio::fs::read(
            s.data_root
                .join("attempts")
                .join(attempt_id)
                .join("envelope.json"),
        )
        .await
        .map_err(io_error)?,
    )
    .map_err(json_error)?;
    if envelope.attempt_id != attempt_id
        || envelope.generation != attempt.generation
        || envelope.project_id != project
        || envelope.base_sha != attempt.base_sha
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "INPUT_DRIFT",
            "durable worker envelope differs from authority",
        ));
    }
    let plan = decode_plan(
        s.store
            .get_document(
                project,
                "verification_plans",
                &envelope.verification_plan_id,
            )
            .await?,
    )?;
    let bindings = s.store.attempt_bindings(project, attempt_id).await?;
    let retained =
        RetainedNativeCandidate::load(project, &attempt, &task, &envelope, &plan, &bindings)?;
    let retained_lineage = retained.as_ref().map(RetainedNativeCandidate::lineage);
    let recovery = if op.starts_with("verification-recovery:") {
        let resumed = s
            .store
            .catalog_service_receipt(
                "verification-recovery-service",
                &format!("resume-never-launched:{op}"),
            )
            .await?;
        let receipt = if let Some(resumed) = resumed {
            resumed
        } else {
            s.store
                .catalog_service_receipt("verification-recovery-service", &format!("claim:{op}"))
                .await?
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::CONFLICT,
                        "VERIFICATION_RECOVERY_INVALID",
                        "immutable recovery claim receipt is missing",
                    )
                })?
        };
        let accepted = &receipt["response"]["value"];
        if accepted["operation_id"] != op
            || accepted["project_id"] != project
            || accepted["attempt_id"] != attempt_id
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "VERIFICATION_RECOVERY_INVALID",
                "immutable recovery claim identity differs",
            ));
        }
        let authorization = &accepted["verification_recovery_authorization"];
        let mut request = serde_json::Map::new();
        for field in [
            "prior_operation_id",
            "repair_id",
            "repair_revision",
            "repair_sha256",
            "preflight_proof_sha256",
            "runtime_manifest_sha256",
            "original_plan_sha256",
        ] {
            request.insert(field.to_owned(), authorization[field].clone());
        }
        let request: VerificationRecoveryRequest =
            serde_json::from_value(Value::Object(request)).map_err(json_error)?;
        let action = authorization["native_panel_action_id"]
            .as_str()
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "VERIFICATION_RECOVERY_INVALID",
                    "immutable recovery claim Native action is missing",
                )
            })?;
        let recovery =
            ApprovedVerificationRecovery::load(&s, project, attempt_id, action, &request).await?;
        if recovery.authorization != *authorization {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "VERIFICATION_RECOVERY_INVALID",
                "Native approved recovery authority changed",
            ));
        }
        Some(recovery)
    } else {
        None
    };
    let verifier_guard =
        RegisteredVerifierGuard::load(&s, project, &envelope, &plan, &bindings, recovery.as_ref())
            .await?;
    let prefix = PathBuf::from(&envelope.artifact_prefix);
    let artifact_root = if prefix.is_absolute() {
        prefix.join(op)
    } else {
        s.data_root.join("artifacts").join(prefix).join(op)
    };
    tokio::fs::create_dir_all(&artifact_root)
        .await
        .map_err(io_error)?;
    let candidate_attempt_id = retained
        .as_ref()
        .map(|retained| retained.source_attempt_id.as_str())
        .unwrap_or(attempt_id);
    let worktree = s.data_root.join("worktrees").join(candidate_attempt_id);
    let worktree = worktree.canonicalize().map_err(io_error)?;
    if retained.is_none()
        && matches!(
            envelope.session_purpose,
            SessionPurpose::Planning | SessionPurpose::Review
        )
        && envelope.write_set.is_empty()
    {
        return run_read_only(
            s,
            project,
            attempt_id,
            op,
            attempt,
            task,
            envelope,
            plan,
            artifact_root,
            worktree,
            verifier_guard,
        )
        .await;
    }
    let scope = if let Some(retained) = &retained {
        retained.scope.clone()
    } else {
        let owner = s
            .store
            .get_document(project, "owners", &task.owner_id)
            .await?;
        let owner_paths = owner
            .get("include")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "OWNER_PATH_VIOLATION",
                    "owner include territory required",
                )
            })?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        forgeflow_git::PathScope {
            owner_paths,
            write_set: task.write_set.clone(),
        }
    };
    let metadata: Value = serde_json::from_slice(
        &tokio::fs::read(
            s.data_root
                .join("attempts")
                .join(candidate_attempt_id)
                .join("worktree.json"),
        )
        .await
        .map_err(io_error)?,
    )
    .map_err(json_error)?;
    let recorded_profile = metadata
        .get("worktree")
        .and_then(|w| w.get("isolation_profile"))
        .and_then(Value::as_str)
        .unwrap_or("LOCAL_TRUSTED_WORKTREE");
    let requested_profile = bindings
        .get("resource_profile")
        .and_then(|r| r.get("isolation_profile"))
        .and_then(Value::as_str);
    let private = recorded_profile == "PRIVATE_GIT_METADATA";
    if requested_profile == Some("PRIVATE_GIT_METADATA") && !private {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "ISOLATION_PROFILE_MISMATCH",
            "requested private Git metadata was not established by the trusted worker",
        ));
    }
    let candidate = if let Some(retained) = &retained {
        if !private {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "RETAINED_CANDIDATE_INVALID",
                "retained Native candidate requires its original private Git repository",
            ));
        }
        let observed = forgeflow_git::audit_private_worktree(&worktree, &attempt.base_sha, &scope)
            .map_err(git_error)?;
        let frozen = &retained.candidate;
        if observed.base_sha != frozen.base_sha
            || observed.head_sha != frozen.candidate_sha
            || observed.hash != frozen.diff_manifest_hash
            || observed.changes.is_empty()
            || observed
                .changes
                .iter()
                .any(|change| change.layer != "committed")
            || !observed.untracked.is_empty()
            || forgeflow_git::source_hash(&worktree, &frozen.candidate_sha).map_err(git_error)?
                != frozen.source_hash
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "RETAINED_CANDIDATE_DRIFT",
                "original retained candidate bytes or scope changed after approval",
            ));
        }
        Ok(forgeflow_git::Candidate {
            base_sha: observed.base_sha.clone(),
            candidate_sha: observed.head_sha.clone(),
            diff_manifest_hash: observed.hash.clone(),
            source_hash: frozen.source_hash.clone(),
            manifest: observed,
        })
    } else if private {
        forgeflow_git::freeze_private_candidate(
            &worktree,
            &attempt.base_sha,
            &scope,
            &format!("ForgeFlow candidate {attempt_id}"),
        )
    } else {
        forgeflow_git::freeze_candidate(
            &worktree,
            &attempt.base_sha,
            &scope,
            &format!("ForgeFlow candidate {attempt_id}"),
        )
    }
    .map_err(git_error)?;

    let binding = EvidenceBinding {
        task_revision: attempt.task_revision,
        attempt_id: attempt_id.into(),
        generation: attempt.generation,
        base_sha: attempt.base_sha.clone(),
        candidate_sha: candidate.candidate_sha.clone(),
        integrated_sha: None,
        contract_version: plan.contract_version.clone(),
        verification_plan_id: plan.plan_id.clone(),
        verification_plan_hash: plan.digest(),
        input_hash: task.input_digest.clone(),
        source_hash: candidate.source_hash.clone(),
    };
    let heartbeat_store = s.store.clone();
    let heartbeat_attempt = attempt.clone();
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let _cancellation_guard = CancellationGuard(stop_tx.clone());
    mirror_server_shutdown(&s, &stop_tx);
    let cancellation = stop_rx.clone();
    let cancel_on_stale = stop_tx.clone();
    let renewal = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {_=interval.tick()=>{if let Err(error)=heartbeat_store.heartbeat(HeartbeatRequest{project_id:heartbeat_attempt.project_id.clone(),attempt_id:heartbeat_attempt.attempt_id.clone(),generation:heartbeat_attempt.generation,worker_id:heartbeat_attempt.worker_id.clone(),lease_seconds:30}).await{tracing::error!(%error,"verification lease renewal rejected");let _=cancel_on_stale.send(true);break;}},_=stop_rx.changed()=>break}
        }
    });
    let physical_context =
        verifier_guard.physical_context(attempt_id, attempt.generation, op, &artifact_root)?;
    register_verifier_root(
        &s,
        project,
        op,
        attempt_id,
        &artifact_root,
        physical_context.as_ref(),
    )
    .await?;
    let execution = forgeflow_evidence::execute_verification_with_guard_and_physical_and_subjects(
        &plan,
        &worktree,
        &binding,
        &artifact_root,
        cancellation.clone(),
        |spec| verifier_guard.apply(spec, &artifact_root, None),
        physical_context.as_ref(),
        |command, cwd| verifier_guard.resolve_subject_inputs(command, cwd),
    )
    .await;
    settle_verifier_root(
        &s,
        project,
        op,
        attempt_id,
        &artifact_root,
        physical_context.as_ref(),
    )
    .await?;
    let receipt = match execution {
        Ok(receipt) => {
            verifier_guard.verify_runtime_assets().map_err(|error| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "VERIFICATION_FAILED",
                    error.to_string(),
                )
            })?;
            receipt
        }
        Err(error) => {
            let _ = stop_tx.send(true);
            let _ = renewal.await;
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "VERIFICATION_FAILED",
                error.to_string(),
            ));
        }
    };
    let current = if private {
        forgeflow_git::audit_private_worktree(&worktree, &attempt.base_sha, &scope)
    } else {
        forgeflow_git::audit_worktree(&worktree, &attempt.base_sha, &scope)
    }
    .map_err(git_error)?;
    if forgeflow_git::resolve(&worktree, "HEAD").map_err(git_error)? != candidate.candidate_sha
        || current.changes.iter().any(|c| c.layer != "committed")
        || !current.untracked.is_empty()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "VERIFICATION_MUTATED_CANDIDATE",
            "verification modified frozen candidate bytes",
        ));
    }
    if private {
        forgeflow_git::import_candidate(
            std::path::Path::new(&envelope.workspace_root),
            &worktree,
            &candidate,
            attempt_id,
            &scope,
        )
        .map_err(git_error)?;
    }
    let artifact_id = format!("verification-{op}");
    let path = artifact_root.join(&receipt.log_path);
    s.store
        .execute_command(
            CommandIdentity {
                actor_id: "verification-service".into(),
                idempotency_key: format!("{op}:artifact"),
            },
            CatalogCommand::PutDocument {
                project_id: project.into(),
                collection: "artifacts".into(),
                id: artifact_id.clone(),
                expected_revision: None,
                value: json!({"path":path,"sha256":receipt.log_hash}),
            },
        )
        .await?;
    let evidence = EvidenceReceipt {
        receipt_id: format!("receipt-{op}"),
        project_id: project.into(),
        attempt_id: attempt_id.into(),
        generation: attempt.generation,
        kind: "INDEPENDENT_VERIFICATION".into(),
        input_digest: task.input_digest,
        candidate_sha: Some(candidate.candidate_sha.clone()),
        integrated_sha: None,
        verifier_id: receipt.verifier_id.clone(),
        author_id: receipt.author_id.clone(),
        total: receipt.total,
        failed: receipt.failed,
        skipped: receipt.skipped,
        artifact: ArtifactRef {
            artifact_id,
            sha256: receipt.log_hash.clone(),
        },
        details: serde_json::to_value(&receipt).map_err(json_error)?,
        created_at: Utc::now(),
    };
    s.store.record_evidence(evidence.clone()).await?;
    if attempt.state == AttemptState::Verifying {
        s.store
        .transition(TransitionRequest {
            project_id: project.into(),
            attempt_id: attempt_id.into(),
            generation: attempt.generation,
            worker_id: attempt.worker_id.clone(),
            expected_state: AttemptState::Verifying,
            next_state: AttemptState::ReviewReady,
            reason: "registered independent verifier passed".into(),
            receipt: Some(
                json!({"receipt_id":evidence.receipt_id,"candidate_sha":candidate.candidate_sha}),
            ),
        })
        .await?;
    }
    if !integrate {
        let _ = stop_tx.send(true);
        let _ = renewal.await;
        let mut result = json!({"candidate":candidate,"binding":binding,"evidence":evidence});
        if let Some(lineage) = retained_lineage {
            result["retained_native_candidate"] = lineage;
        }
        return Ok(result);
    }
    let integration_path = s
        .data_root
        .join("worktrees")
        .join(format!("integration-{op}"));
    let repo = PathBuf::from(&envelope.workspace_root);
    let service = forgeflow_git::IntegrationService::default();
    let request = forgeflow_git::IntegrationRequest {
        repo: &repo,
        project_id: project,
        attempt_id,
        generation: attempt.generation,
        target_ref: "refs/heads/main",
        candidate: &candidate,
        scope: &scope,
        integration_path: &integration_path,
        binding: &binding,
    };
    let callback_state = s.clone();
    let callback_project = project.to_owned();
    let callback_op = op.to_owned();
    let callback_attempt = attempt_id.to_owned();
    let callback_generation = attempt.generation;
    let finalization = crate::handoff::PoolIntegrationStore::new(s.clone(), op);
    let integrated = service
        .integrate_async(&finalization, request, move |path, binding| async move {
            let root = forgeflow_git::integration_verification_root(&path)?;
            let physical_context = verifier_guard
                .physical_context(&callback_attempt, callback_generation, &callback_op, &root)
                .map_err(|e| forgeflow_git::GitError::Store(e.1.to_string()))?;
            register_verifier_root(
                &callback_state,
                &callback_project,
                &callback_op,
                &callback_attempt,
                &root,
                physical_context.as_ref(),
            )
            .await
            .map_err(|e| forgeflow_git::GitError::Store(e.1.to_string()))?;
            let result =
                forgeflow_evidence::execute_verification_with_guard_and_physical_and_subjects(
                    &plan,
                    &path,
                    &binding,
                    &root,
                    cancellation.clone(),
                    |spec| verifier_guard.apply(spec, &root, None),
                    physical_context.as_ref(),
                    |command, cwd| verifier_guard.resolve_subject_inputs(command, cwd),
                )
                .await
                .map_err(|e| forgeflow_git::GitError::Evidence(e.to_string()));
            verifier_guard
                .verify_runtime_assets()
                .map_err(|error| forgeflow_git::GitError::Evidence(error.to_string()))?;
            settle_verifier_root(
                &callback_state,
                &callback_project,
                &callback_op,
                &callback_attempt,
                &root,
                physical_context.as_ref(),
            )
            .await
            .map_err(|e| forgeflow_git::GitError::Store(e.1.to_string()))?;
            result
        })
        .await;
    let _ = stop_tx.send(true);
    let _ = renewal.await;
    let mut result = json!({"evidence":evidence,"integration":integrated.map_err(git_error)?});
    if let Some(lineage) = retained_lineage {
        result["retained_native_candidate"] = lineage;
    }
    if let Some(receipt) = finalization.handoff_receipt().await {
        result["handoff"] = serde_json::to_value(receipt).map_err(json_error)?;
    }
    Ok(result)
}

fn decode_plan(mut value: Value) -> Result<VerificationPlan, ApiError> {
    if let Some(object) = value.as_object_mut() {
        object.remove("revision");
    }
    serde_json::from_value(value).map_err(json_error)
}

/// Resolve policy from the admitted snapshots before selecting any verification branch.
/// A private Git object database alone never upgrades a trusted process to a sandbox.
struct RegisteredVerifierGuard {
    profile: Option<forgeflow_runtime::SandboxProfile>,
    physical: Option<forgeflow_runtime::PhysicalFenceRequest>,
    plan: VerificationPlan,
    repository: PathBuf,
    state_root: PathBuf,
    artifact_inputs: std::collections::BTreeMap<PathBuf, VerifierArtifactInput>,
    subject_authority: Option<VerifierSubjectAuthority>,
    runtime_assets: Vec<VerifierRuntimeAsset>,
    recovery_authorization: Option<Value>,
    subject_inputs: std::sync::Mutex<
        std::collections::BTreeMap<
            (PathBuf, usize),
            Vec<forgeflow_evidence::SubjectInputResolution>,
        >,
    >,
    input_scratch: std::sync::Mutex<Vec<VerifierInputScratch>>,
}
struct VerifierRuntimeAsset {
    source: PathBuf,
    target: PathBuf,
    sha256: String,
    bytes: u64,
}

fn verifier_runtime_assets(
    recovery: &ApprovedVerificationRecovery,
    plan: &VerificationPlan,
    protected: &[&std::path::Path],
) -> Result<Vec<VerifierRuntimeAsset>, ApiError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let invalid = |message: &str| {
        ApiError::new(
            StatusCode::CONFLICT,
            "VERIFICATION_RECOVERY_INVALID",
            message,
        )
    };
    let manifest = &recovery.runtime;
    let interpreter = PathBuf::from(
        manifest["interpreter"]["path"]
            .as_str()
            .ok_or_else(|| invalid("runtime interpreter path is missing"))?,
    );
    let interpreter_sha = manifest["interpreter"]["sha256"]
        .as_str()
        .filter(|sha| forgeflow_domain::valid_digest(sha))
        .ok_or_else(|| invalid("runtime interpreter digest is missing"))?;
    if !interpreter.is_absolute()
        || interpreter.canonicalize().map_err(io_error)? != interpreter
        || forgeflow_evidence::sha256(&pinned_verifier_bytes(&interpreter).map_err(io_error)?)
            != interpreter_sha
        || !plan.commands.iter().all(|command| {
            command
                .bound_inputs
                .iter()
                .any(|input| input.path == interpreter && input.sha256 == interpreter_sha)
        })
    {
        return Err(invalid(
            "runtime interpreter is not an exact externally frozen verifier input",
        ));
    }
    let prefix = interpreter
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| invalid("runtime interpreter prefix is missing"))?
        .join("lib/python3.13");
    let files = manifest["files"]
        .as_array()
        .filter(|files| !files.is_empty() && files.len() <= 2000)
        .ok_or_else(|| invalid("runtime file count is invalid"))?;
    let mut assets = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for file in files {
        let relative = file["relative_path"]
            .as_str()
            .ok_or_else(|| invalid("runtime relative path is missing"))?;
        forgeflow_domain::validate_relative_path(relative).map_err(|e| invalid(&e.to_string()))?;
        let logical = PathBuf::from(relative);
        if logical.components().any(|part| {
            part.as_os_str().to_str().is_some_and(|name| {
                matches!(name, "site-packages" | "dist-packages" | "__pycache__")
                    || name.ends_with(".pth")
                    || matches!(name, "sitecustomize.py" | "usercustomize.py")
            })
        }) || !(relative.ends_with(".py")
            || (relative.starts_with("lib-dynload/") && relative.ends_with(".so")))
        {
            return Err(invalid(
                "runtime manifest includes unapproved interpreter hooks or packages",
            ));
        }
        let source = PathBuf::from(
            file["source_path"]
                .as_str()
                .ok_or_else(|| invalid("runtime immutable source path is missing"))?,
        );
        let target = PathBuf::from(
            file["target_path"]
                .as_str()
                .ok_or_else(|| invalid("runtime namespace target is missing"))?,
        );
        let sha = file["sha256"]
            .as_str()
            .filter(|sha| forgeflow_domain::valid_digest(sha))
            .ok_or_else(|| invalid("runtime file digest is missing"))?;
        let bytes = file["bytes"]
            .as_u64()
            .filter(|bytes| *bytes <= 8 * 1024 * 1024)
            .ok_or_else(|| invalid("runtime file size is invalid"))?;
        if target != prefix.join(&logical)
            || !seen.insert(target.clone())
            || source == target
            || !source.is_absolute()
            || protected.iter().any(|root| {
                source.starts_with(root)
                    || root.starts_with(&source)
                    || target.starts_with(root)
                    || root.starts_with(&target)
            })
        {
            return Err(invalid(
                "runtime asset crosses its exact approved dependency namespace",
            ));
        }
        let metadata = open_verifier_input(&source)
            .map_err(io_error)?
            .metadata()
            .map_err(io_error)?;
        let actual = pinned_verifier_bytes(&source).map_err(io_error)?;
        if metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o400
            || actual.len() as u64 != bytes
            || forgeflow_evidence::sha256(&actual) != sha
        {
            return Err(invalid(
                "runtime immutable snapshot identity or bytes changed",
            ));
        }
        total = total
            .checked_add(bytes)
            .filter(|total| *total <= 128 * 1024 * 1024)
            .ok_or_else(|| invalid("runtime asset byte budget exceeded"))?;
        assets.push(VerifierRuntimeAsset {
            source,
            target,
            sha256: sha.to_owned(),
            bytes,
        });
    }
    if manifest["file_count"].as_u64() != Some(assets.len() as u64)
        || manifest["total_bytes"].as_u64() != Some(total)
    {
        return Err(invalid(
            "runtime manifest count or byte denominator differs",
        ));
    }
    Ok(assets)
}

struct VerifierSubjectAuthority {
    files: std::collections::BTreeMap<String, String>,
    context_artifact_id: String,
    context_sha256: String,
    classification_recipe_sha256: String,
}

fn pinned_verifier_bytes(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    const MAX_BYTES: u64 = 32 * 1024 * 1024;
    let file = open_verifier_input(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_BYTES {
        return Err(std::io::Error::other(
            "verifier input exceeds its byte budget",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_BYTES {
        return Err(std::io::Error::other(
            "verifier input size changed during read",
        ));
    }
    Ok(bytes)
}

fn exact_command_argument<'a>(
    command: &'a forgeflow_evidence::CommandSpec,
    flag: &str,
) -> Option<&'a str> {
    let mut matches = command.args.windows(2).filter(|pair| pair[0] == flag);
    let value = matches.next()?.get(1)?.as_str();
    matches.next().is_none().then_some(value)
}

impl VerifierSubjectAuthority {
    async fn load(
        s: &App,
        project: &str,
        envelope: &ExecutionEnvelope,
        plan: &VerificationPlan,
        repository: &std::path::Path,
        state_root: &std::path::Path,
    ) -> Result<Option<Self>, ApiError> {
        let invalid =
            |message: &str| ApiError::new(StatusCode::CONFLICT, "VERIFIER_INVALID", message);
        // This compatibility resolver recognizes the frozen baseline recipe's data-only
        // read_files contract. Unknown recipes retain the runner's strict candidate ban.
        let Some(contract) =
            super::project_contracts::verification_contract(project, &plan.contract_version)?
        else {
            return Ok(None);
        };
        if !plan.commands.iter().any(|command| {
            command
                .bound_inputs
                .iter()
                .any(|input| !input.path.is_absolute())
        }) {
            return Ok(None);
        }
        let Some(first) = plan.commands.first() else {
            return Ok(None);
        };
        let Some(recipe_path) = exact_command_argument(first, "--recipe") else {
            return Ok(None);
        };
        let Some(recipe_sha256) = exact_command_argument(first, "--recipe-sha256") else {
            return Ok(None);
        };
        if !forgeflow_domain::valid_digest(recipe_sha256) {
            return Err(invalid("subject classification recipe digest is invalid"));
        }
        let recipe_path = PathBuf::from(recipe_path);
        if !recipe_path.is_absolute()
            || recipe_path.canonicalize().map_err(io_error)? != recipe_path
            || recipe_path.starts_with(repository)
            || recipe_path.starts_with(state_root.join("worktrees"))
            || plan.commands.iter().any(|command| {
                exact_command_argument(command, "--recipe") != recipe_path.to_str()
                    || exact_command_argument(command, "--recipe-sha256") != Some(recipe_sha256)
                    || !command
                        .bound_inputs
                        .iter()
                        .any(|input| input.path == recipe_path && input.sha256 == recipe_sha256)
            })
        {
            return Err(invalid(
                "subject classification must use the same externally pinned frozen recipe",
            ));
        }
        let recipe_bytes = pinned_verifier_bytes(&recipe_path).map_err(io_error)?;
        if forgeflow_evidence::sha256(&recipe_bytes) != recipe_sha256 {
            return Err(invalid("subject classification recipe bytes changed"));
        }
        let recipe: Value = serde_json::from_slice(&recipe_bytes).map_err(json_error)?;
        if recipe["schema_version"].as_str() != Some(contract.recipe_schema.as_str())
            || recipe["card_type"].as_str() != Some(contract.card_type.as_str())
            || recipe["card_id"].as_str() != Some(envelope.task_id.as_str())
            || recipe["contract_version"] != plan.contract_version
            || recipe["oracle_id"] != plan.oracle_id
            || recipe["verifier_id"] != plan.verifier_id
            || recipe["acceptance_scope"].as_str() != Some(contract.acceptance_scope.as_str())
        {
            return Err(invalid(
                "frozen recipe does not classify data-only baseline subject inputs",
            ));
        }
        let artifact = s
            .store
            .get_document(project, "artifacts", &envelope.context_manifest.artifact_id)
            .await?;
        let manifest_path = PathBuf::from(
            artifact["path"]
                .as_str()
                .ok_or_else(|| invalid("admitted subject manifest artifact path is missing"))?,
        );
        if manifest_path.parent() != Some(state_root.join("artifacts").as_path())
            || artifact["sha256"].as_str() != Some(envelope.context_manifest.sha256.as_str())
        {
            return Err(invalid(
                "subject manifest must be the exact admitted immutable project artifact",
            ));
        }
        let manifest_bytes = pinned_verifier_bytes(&manifest_path).map_err(io_error)?;
        if forgeflow_evidence::sha256(&manifest_bytes) != envelope.context_manifest.sha256 {
            return Err(invalid("admitted subject context manifest bytes changed"));
        }
        let manifest: forgeflow_domain::ContextManifest =
            serde_json::from_slice(&manifest_bytes).map_err(json_error)?;
        let mut admitted = std::collections::BTreeMap::new();
        for file in manifest.files {
            forgeflow_domain::validate_relative_path(&file.path)
                .map_err(|error| invalid(&error.to_string()))?;
            if !forgeflow_domain::valid_digest(&file.sha256)
                || admitted.insert(file.path, file.sha256).is_some()
            {
                return Err(invalid(
                    "admitted subject manifest contains an invalid or duplicate file",
                ));
            }
        }
        let mut excluded = vec![recipe_path];
        let mut excluded_logical = std::collections::BTreeSet::new();
        for command in &plan.commands {
            excluded.push(command.program.canonicalize().map_err(io_error)?);
            for argument in &command.args {
                let path = PathBuf::from(argument);
                if path.is_absolute() {
                    excluded.push(path.canonicalize().map_err(io_error)?);
                } else if forgeflow_domain::validate_relative_path(argument).is_ok() {
                    excluded_logical.insert(argument.clone());
                }
            }
        }
        for role in ["author", "consumer", "independent"] {
            let definition = &recipe["roles"][role];
            if definition["mode"] != "unittest" {
                return Err(invalid(
                    "subject classification requires the frozen external unittest oracle",
                ));
            }
            for field in ["suite", "python"] {
                let path = PathBuf::from(
                    definition[field]["path"]
                        .as_str()
                        .ok_or_else(|| invalid("frozen oracle dependency path is missing"))?,
                );
                if !path.is_absolute() {
                    return Err(invalid("oracle dependencies cannot be candidate subjects"));
                }
                excluded.push(path.canonicalize().map_err(io_error)?);
            }
            // A recipe which imports candidate directories has executable subject
            // semantics and cannot inherit this data-only compatibility projection.
            if definition["import_paths"]
                .as_array()
                .is_none_or(|paths| !paths.is_empty())
            {
                return Err(invalid(
                    "candidate import paths are not data-only subject inputs",
                ));
            }
        }
        for prerequisite in recipe["prerequisites"]
            .as_array()
            .ok_or_else(|| invalid("frozen oracle prerequisite list is missing"))?
        {
            let path = PathBuf::from(
                prerequisite["path"]
                    .as_str()
                    .ok_or_else(|| invalid("frozen oracle prerequisite path is missing"))?,
            );
            if !path.is_absolute() {
                return Err(invalid("oracle prerequisites cannot be candidate subjects"));
            }
            excluded.push(path.canonicalize().map_err(io_error)?);
        }
        let mut files = std::collections::BTreeMap::new();
        for input in recipe["read_files"]
            .as_array()
            .ok_or_else(|| invalid("frozen recipe business read_files are missing"))?
        {
            let path = input["path"]
                .as_str()
                .ok_or_else(|| invalid("subject logical path is missing"))?;
            let sha = input["sha256"]
                .as_str()
                .ok_or_else(|| invalid("subject digest is missing"))?;
            forgeflow_domain::validate_relative_path(path)
                .map_err(|error| invalid(&error.to_string()))?;
            if !forgeflow_domain::valid_digest(sha)
                || admitted.get(path).map(String::as_str) != Some(sha)
                || envelope
                    .write_set
                    .iter()
                    .any(|write| forgeflow_domain::paths_overlap(path, write))
                || excluded_logical.contains(path)
                || excluded.iter().any(|oracle| oracle.ends_with(path))
                || files.insert(path.to_owned(), sha.to_owned()).is_some()
            {
                return Err(invalid(
                    "business subject differs from admitted context or overlaps author/oracle scope",
                ));
            }
        }
        if files.is_empty() {
            return Err(invalid(
                "frozen recipe has no admitted data-only business subject",
            ));
        }
        for command in &plan.commands {
            for input in &command.bound_inputs {
                if let Some(path) = input.path.to_str().filter(|_| !input.path.is_absolute()) {
                    if files.get(path) != Some(&input.sha256) {
                        return Err(invalid(
                            "candidate verifier input is not a classified admitted business subject",
                        ));
                    }
                }
            }
        }
        Ok(Some(Self {
            files,
            context_artifact_id: envelope.context_manifest.artifact_id.clone(),
            context_sha256: envelope.context_manifest.sha256.clone(),
            classification_recipe_sha256: recipe_sha256.to_owned(),
        }))
    }
}

#[derive(Clone)]
struct VerifierArtifactInput {
    artifact_id: String,
    sha256: String,
    bytes: u64,
}
impl VerifierArtifactInput {
    fn from_catalog(
        input: &forgeflow_evidence::BoundInput,
        catalog: &Value,
        bytes: u64,
    ) -> Result<Self, forgeflow_evidence::EvidenceError> {
        let id = input.path.file_name().and_then(|name| name.to_str());
        if id.is_none()
            || catalog.get("artifact_id").and_then(Value::as_str) != id
            || catalog.get("path").and_then(Value::as_str) != input.path.to_str()
            || catalog.get("sha256").and_then(Value::as_str) != Some(input.sha256.as_str())
            || catalog.get("bytes").and_then(Value::as_u64) != Some(bytes)
        {
            return Err(forgeflow_evidence::EvidenceError::Invalid(
                "frozen verifier input differs from immutable project artifact".into(),
            ));
        }
        Ok(Self {
            artifact_id: id.unwrap().into(),
            sha256: input.sha256.clone(),
            bytes,
        })
    }
}
struct VerifierInputScratch(PathBuf);
impl Drop for VerifierInputScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Walk through held directory descriptors, so replacing a path component cannot redirect
// the read. The only symlinks followed are our own /proc/self/fd directory handles.
fn open_verifier_input(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    use std::path::Component;
    // Linux O_DIRECTORY and O_NOFOLLOW; verifier isolation is Linux-only.
    const DIRECTORY: i32 = 0o200000;
    const NOFOLLOW: i32 = 0o400000;
    if !path.is_absolute() || path.canonicalize()?.as_os_str() != path.as_os_str() {
        return Err(std::io::Error::other(
            "verifier input path must be canonical",
        ));
    }
    let mut directory = std::fs::File::open("/")?;
    let components: Vec<_> = path.components().skip(1).collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::other(
                "verifier input path is not normalized",
            ));
        };
        let next = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                NOFOLLOW
                    | if index + 1 == components.len() {
                        0o4000
                    } else {
                        DIRECTORY
                    },
            )
            .open(next)?;
        if index + 1 == components.len() {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(std::io::Error::other(
                    "verifier input must be a single regular file",
                ));
            }
            return Ok(file);
        }
        directory = file;
    }
    Err(std::io::Error::other("verifier input filename missing"))
}
impl RegisteredVerifierGuard {
    async fn load(
        s: &App,
        project: &str,
        envelope: &ExecutionEnvelope,
        plan: &VerificationPlan,
        bindings: &Value,
        recovery: Option<&ApprovedVerificationRecovery>,
    ) -> Result<Self, ApiError> {
        let frozen_resource = bindings
            .get("resource_profile")
            .filter(|v| v.is_object())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "ISOLATION_PROFILE_MISMATCH",
                    "admitted resource profile snapshot missing",
                )
            })?;
        let mut current_resource = s
            .store
            .get_document(project, "resource_profiles", &envelope.resource_profile_id)
            .await?;
        if let Some(object) = current_resource.as_object_mut() {
            object.remove("revision");
        }
        let frozen_plan =
            decode_plan(bindings.get("verification_plan").cloned().ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "INPUT_DRIFT",
                    "admitted verification plan snapshot missing",
                )
            })?)?;
        if &current_resource != frozen_resource || frozen_plan.digest() != plan.digest() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "ISOLATION_PROFILE_MISMATCH",
                "current verifier policy differs from immutable admission snapshots",
            ));
        }
        let profile: Option<forgeflow_runtime::SandboxProfile> = frozen_resource
            .get("sandbox")
            .filter(|v| !v.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(json_error)?;
        let physical = if frozen_resource
            .get("physical_limits")
            .and_then(|policy| policy.get("required"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            let binding: forgeflow_domain::PhysicalResourceBinding = serde_json::from_value(
                bindings.get("physical_resources").cloned().ok_or_else(|| {
                    ApiError::new(
                        StatusCode::CONFLICT,
                        "PHYSICAL_BINDING_MISMATCH",
                        "frozen verifier resource reservation missing",
                    )
                })?,
            )
            .map_err(json_error)?;
            binding.verify().map_err(|error| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "PHYSICAL_BINDING_MISMATCH",
                    error.to_string(),
                )
            })?;
            if binding.resource_profile_id != envelope.resource_profile_id
                || serde_json::to_value(&binding.physical_limits).map_err(json_error)?
                    != frozen_resource["physical_limits"]
                || profile.is_none()
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "PHYSICAL_BINDING_MISMATCH",
                    "verifier reservation differs from admitted physical policy",
                ));
            }
            let encoded = std::env::var("FORGEFLOW_VERIFIER_CGROUP_DELEGATION").map_err(|_| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "VERIFIER_DELEGATION_REQUIRED",
                    "required physical verification needs a dedicated delegated control service",
                )
            })?;
            let delegation: forgeflow_runtime::CgroupDelegation = serde_json::from_str(&encoded)
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::CONFLICT,
                        "VERIFIER_DELEGATION_INVALID",
                        "control service delegation configuration is invalid",
                    )
                })?;
            forgeflow_runtime::validate_verifier_delegation(&delegation).map_err(|_| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "VERIFIER_DELEGATION_INVALID",
                    "control service delegation does not match its actual supervisor",
                )
            })?;
            let author: forgeflow_runtime::CgroupFenceIdentity = serde_json::from_slice(
                &tokio::fs::read(
                    s.data_root
                        .join("attempts")
                        .join(&envelope.attempt_id)
                        .join("cgroup-fence.json"),
                )
                .await
                .map_err(io_error)?,
            )
            .map_err(json_error)?;
            author.validate_record().map_err(|_| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "PHYSICAL_BINDING_MISMATCH",
                    "author physical identity is invalid",
                )
            })?;
            if author.boot_id
                != forgeflow_runtime::boot_id().map_err(|_| {
                    ApiError::new(
                        StatusCode::CONFLICT,
                        "PHYSICAL_NODE_MISMATCH",
                        "local physical boot identity is unavailable",
                    )
                })?
                || author.project_id != project
                || author.attempt_id != envelope.attempt_id
                || author.generation != envelope.generation
                || author.resource_binding_sha256 != binding.reservation_sha256
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "PHYSICAL_NODE_MISMATCH",
                    "verifier can borrow only the stopped author reservation on the same physical node",
                ));
            }
            Some(forgeflow_runtime::PhysicalFenceRequest {
                project_id: project.into(),
                delegation,
                limits: forgeflow_runtime::PhysicalCgroupLimits {
                    cpu_quota_us: binding.cpu_quota_us,
                    cpu_period_us: binding.physical_limits.period_us,
                    memory_max_bytes: binding.memory_max_bytes,
                    memory_swap_max_bytes: binding.physical_limits.swap_max_bytes,
                    pids_max: binding.physical_limits.pids_max,
                    memory_oom_group: binding.physical_limits.memory_oom_group,
                },
                resource_binding_sha256: binding.reservation_sha256,
            })
        } else {
            None
        };
        if profile.is_none()
            && frozen_resource
                .get("isolation_profile")
                .and_then(Value::as_str)
                == Some("BWRAP_LANDLOCK_EXACT")
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "ISOLATION_PROFILE_MISMATCH",
                "strong isolation requested without registered sandbox configuration",
            ));
        }
        if let Some(profile) = &profile {
            let recorded: Value = serde_json::from_slice(
                &tokio::fs::read(
                    s.data_root
                        .join("attempts")
                        .join(&envelope.attempt_id)
                        .join("sandbox.json"),
                )
                .await
                .map_err(io_error)?,
            )
            .map_err(json_error)?;
            if recorded.get("profile") != Some(&serde_json::to_value(profile).map_err(json_error)?)
                || recorded.get("isolation_profile").and_then(Value::as_str)
                    != Some("BWRAP_LANDLOCK_EXACT")
                || recorded.get("private_git").and_then(Value::as_bool) != Some(true)
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "ISOLATION_PROFILE_MISMATCH",
                    "worker sandbox configuration differs from admitted profile",
                ));
            }
            let launch: Value = serde_json::from_slice(
                &tokio::fs::read(
                    s.data_root
                        .join("attempts")
                        .join(&envelope.attempt_id)
                        .join("launch-receipt.json"),
                )
                .await
                .map_err(io_error)?,
            )
            .map_err(json_error)?;
            let args = launch.get("command_args").and_then(Value::as_array);
            let delimiter =
                args.and_then(|args| args.iter().position(|value| value.as_str() == Some("--")));
            let has_argument = |argument: &str| {
                args.zip(delimiter).is_some_and(|(args, delimiter)| {
                    args[..delimiter]
                        .iter()
                        .any(|value| value.as_str() == Some(argument))
                })
            };
            let actual_guard = args
                .zip(delimiter)
                .and_then(|(args, delimiter)| args.get(delimiter + 1))
                .and_then(Value::as_str);
            if launch.get("command_program").and_then(Value::as_str)
                != profile.bwrap_program.to_str()
                || actual_guard != profile.guard_program.to_str()
                || !["--unshare-user", "--unshare-pid", "--disable-userns"]
                    .iter()
                    .all(|argument| has_argument(argument))
                || (!profile.network_allowed && !has_argument("--unshare-net"))
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "ISOLATION_PROFILE_MISMATCH",
                    "actual author launch does not match admitted sandbox wrappers",
                ));
            }
        }
        let repository = PathBuf::from(&envelope.workspace_root)
            .canonicalize()
            .map_err(io_error)?;
        let state_root = s.data_root.canonicalize().map_err(io_error)?;
        let subject_authority = if profile.is_some() && recovery.is_some() {
            VerifierSubjectAuthority::load(s, project, envelope, plan, &repository, &state_root)
                .await?
        } else {
            None
        };
        let runtime_assets = recovery
            .map(|recovery| {
                verifier_runtime_assets(
                    recovery,
                    plan,
                    &[repository.as_path(), state_root.as_path()],
                )
            })
            .transpose()?
            .unwrap_or_default();
        let mut artifact_inputs = std::collections::BTreeMap::new();
        if profile.is_some() {
            for input in plan
                .commands
                .iter()
                .flat_map(|command| &command.bound_inputs)
            {
                // Only direct immutable catalog artifacts are eligible. All other control
                // files, directories and canonical repository paths retain the guard's ban.
                if input.path.parent() != Some(state_root.join("artifacts").as_path()) {
                    continue;
                }
                let file = open_verifier_input(&input.path).map_err(io_error)?;
                if input.path.starts_with(&repository) || repository.starts_with(&input.path) {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "VERIFIER_INVALID",
                        "verifier artifact overlaps canonical repository",
                    ));
                }
                let id = input
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        ApiError::new(
                            StatusCode::CONFLICT,
                            "VERIFIER_INVALID",
                            "verifier artifact identity missing",
                        )
                    })?;
                let catalog = s.store.get_document(project, "artifacts", id).await?;
                let artifact = VerifierArtifactInput::from_catalog(
                    input,
                    &catalog,
                    file.metadata().map_err(io_error)?.len(),
                )
                .map_err(|e| {
                    ApiError::new(StatusCode::CONFLICT, "VERIFIER_INVALID", e.to_string())
                })?;
                if artifact_inputs
                    .get(&input.path)
                    .is_some_and(|previous: &VerifierArtifactInput| previous.sha256 != input.sha256)
                {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "VERIFIER_INVALID",
                        "frozen verifier input differs from immutable project artifact",
                    ));
                }
                artifact_inputs.insert(input.path.clone(), artifact);
            }
        }
        Ok(Self {
            profile,
            physical,
            plan: plan.clone(),
            repository,
            state_root,
            artifact_inputs,
            subject_authority,
            runtime_assets,
            recovery_authorization: recovery.map(|recovery| recovery.authorization.clone()),
            subject_inputs: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            input_scratch: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn resolve_subject_inputs(
        &self,
        command: &forgeflow_evidence::CommandSpec,
        cwd: &std::path::Path,
    ) -> Result<Vec<forgeflow_evidence::SubjectInputResolution>, forgeflow_evidence::EvidenceError>
    {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        };
        let invalid = |message: String| forgeflow_evidence::EvidenceError::Invalid(message);
        let Some(authority) = &self.subject_authority else {
            return Ok(Vec::new());
        };
        let workspace = cwd
            .canonicalize()
            .map_err(|error| invalid(error.to_string()))?;
        if workspace == self.repository
            || workspace.starts_with(&self.repository)
            || self.repository.starts_with(&workspace)
        {
            return Err(invalid(
                "business subject projection cannot use canonical repository".into(),
            ));
        }
        let command_json =
            serde_json::to_value(command).map_err(|error| invalid(error.to_string()))?;
        let index = self
            .plan
            .commands
            .iter()
            .position(|frozen| serde_json::to_value(frozen).ok().as_ref() == Some(&command_json))
            .ok_or_else(|| {
                invalid("subject command absent from immutable verification plan".into())
            })?;
        let root = PathBuf::from("/tmp");
        let metadata = fs::symlink_metadata(&root).map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o1000 == 0
            || root
                .canonicalize()
                .map_err(|error| invalid(error.to_string()))?
                != root
        {
            return Err(invalid(
                "subject snapshot requires trusted sticky /tmp".into(),
            ));
        }
        let scratch = root.join(format!(
            "forgeflow-verifier-subjects-{}",
            uuid::Uuid::new_v4()
        ));
        if [&self.state_root, &self.repository, &workspace]
            .iter()
            .any(|path| scratch.starts_with(path) || path.starts_with(&scratch))
        {
            return Err(invalid("subject snapshot overlaps protected state".into()));
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&scratch)
            .map_err(|error| invalid(error.to_string()))?;
        let scratch = VerifierInputScratch(scratch);
        let mut resolutions = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for input in &command.bound_inputs {
            if input.path.is_absolute() {
                continue;
            }
            let logical = input
                .path
                .to_str()
                .ok_or_else(|| invalid("subject logical path must be UTF-8".into()))?;
            if authority.files.get(logical) != Some(&input.sha256)
                || !seen.insert(logical.to_owned())
            {
                return Err(invalid(
                    "subject input differs from its admitted classification".into(),
                ));
            }
            let original = workspace.join(&input.path);
            if original
                .canonicalize()
                .map_err(|error| invalid(error.to_string()))?
                != original
                || !original.starts_with(&workspace)
            {
                return Err(invalid(
                    "subject logical target escapes current verifier workspace".into(),
                ));
            }
            let bytes =
                pinned_verifier_bytes(&original).map_err(|error| invalid(error.to_string()))?;
            if forgeflow_evidence::sha256(&bytes) != input.sha256 {
                return Err(invalid("admitted business subject bytes changed".into()));
            }
            let source = scratch.0.join(format!("subject-{}", resolutions.len()));
            let mut copy = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&source)
                .map_err(|error| invalid(error.to_string()))?;
            copy.write_all(&bytes)
                .and_then(|()| copy.sync_all())
                .map_err(|error| invalid(error.to_string()))?;
            drop(copy);
            if pinned_verifier_bytes(&source).map_err(|error| invalid(error.to_string()))? != bytes
            {
                return Err(invalid("immutable subject snapshot bytes changed".into()));
            }
            resolutions.push(forgeflow_evidence::SubjectInputResolution {
                original_path: original,
                logical_path: input.path.clone(),
                sha256: input.sha256.clone(),
                bytes: bytes.len() as u64,
                execution_source: source,
                context_artifact_id: authority.context_artifact_id.clone(),
                context_sha256: authority.context_sha256.clone(),
                classification_recipe_sha256: authority.classification_recipe_sha256.clone(),
            });
        }
        fs::File::open(&scratch.0)
            .and_then(|file| file.sync_all())
            .map_err(|error| invalid(error.to_string()))?;
        let key = (workspace, index);
        let mut registry = self
            .subject_inputs
            .lock()
            .map_err(|_| invalid("subject snapshot registry poisoned".into()))?;
        if registry.contains_key(&key) {
            return Err(invalid(
                "subject snapshots for this frozen command were already resolved".into(),
            ));
        }
        registry.insert(key, resolutions.clone());
        self.input_scratch
            .lock()
            .map_err(|_| invalid("verifier scratch registry poisoned".into()))?
            .push(scratch);
        Ok(resolutions)
    }

    fn verify_runtime_assets(&self) -> Result<(), forgeflow_evidence::EvidenceError> {
        use std::os::unix::fs::PermissionsExt;
        for asset in &self.runtime_assets {
            let bytes = pinned_verifier_bytes(&asset.source)
                .map_err(|error| forgeflow_evidence::EvidenceError::Invalid(error.to_string()))?;
            let metadata = open_verifier_input(&asset.source)
                .and_then(|file| file.metadata())
                .map_err(|error| forgeflow_evidence::EvidenceError::Invalid(error.to_string()))?;
            if bytes.len() as u64 != asset.bytes
                || forgeflow_evidence::sha256(&bytes) != asset.sha256
                || metadata.permissions().mode() & 0o777 != 0o400
            {
                return Err(forgeflow_evidence::EvidenceError::Invalid(
                    "Native-approved runtime snapshot changed during verification".into(),
                ));
            }
        }
        Ok(())
    }

    fn physical_context(
        &self,
        attempt: &str,
        generation: i64,
        operation: &str,
        root: &std::path::Path,
    ) -> Result<Option<forgeflow_evidence::PhysicalVerificationContext>, ApiError> {
        self.physical
            .as_ref()
            .map(|request| {
                let canonical = root.canonicalize().map_err(io_error)?;
                let hash = forgeflow_evidence::sha256(canonical.to_string_lossy().as_bytes());
                let operation = physical_operation_alias(operation);
                let registration = format!("verifier-root-{operation}-{}", &hash[..16]);
                forgeflow_evidence::PhysicalVerificationContext::new(
                    attempt,
                    generation,
                    &operation,
                    &canonical,
                    &registration,
                    &self.plan,
                    request.clone(),
                )
                .map_err(|error| {
                    ApiError::new(
                        StatusCode::CONFLICT,
                        "PHYSICAL_BINDING_MISMATCH",
                        error.to_string(),
                    )
                })
            })
            .transpose()
    }

    fn apply(
        &self,
        spec: forgeflow_runtime::ProcessSpec,
        report_root: &std::path::Path,
        artifact_path: Option<&std::path::Path>,
    ) -> Result<forgeflow_runtime::ProcessSpec, forgeflow_evidence::EvidenceError> {
        use forgeflow_evidence::EvidenceError;
        use std::{
            fs,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };
        let invalid = |error: String| EvidenceError::Invalid(error);
        let Some(registered) = &self.profile else {
            return Ok(spec);
        };
        let report_root = report_root
            .canonicalize()
            .map_err(|e| invalid(e.to_string()))?;
        let (command_index, command) = self
            .plan
            .commands
            .iter()
            .enumerate()
            .find(|(_, command)| {
                command.program == spec.program
                    && command.args == spec.args
                    && spec
                        .env
                        .get("FORGEFLOW_REPORT_PATH")
                        .map(PathBuf::from)
                        .as_ref()
                        == Some(&report_root.join(&command.report_path))
                    && command
                        .env
                        .iter()
                        .all(|(key, value)| spec.env.get(key) == Some(value))
            })
            .ok_or_else(|| invalid("verifier command absent from frozen plan".into()))?;
        for executable in [&registered.bwrap_program, &registered.guard_program] {
            let metadata = fs::metadata(executable).map_err(|e| invalid(e.to_string()))?;
            let mode = metadata.permissions().mode();
            if !metadata.is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
                return Err(invalid(
                    "sandbox executable must be executable and not group/world writable".into(),
                ));
            }
        }
        // Verifiers need their pinned runtime and oracle, never the author's DSH credentials/home.
        let mut profile = registered.clone();
        let program = command
            .program
            .canonicalize()
            .map_err(|e| invalid(e.to_string()))?;
        let workspace = spec
            .cwd
            .canonicalize()
            .map_err(|e| invalid(e.to_string()))?;
        let subjects = self
            .subject_inputs
            .lock()
            .map_err(|_| invalid("subject snapshot registry poisoned".into()))?
            .get(&(workspace.clone(), command_index))
            .cloned()
            .unwrap_or_default();
        let mut oracle_inputs = Vec::new();
        let mut handoffs = std::collections::BTreeMap::new();
        let mut scratch = None;
        for input in &command.bound_inputs {
            let original = if input.path.is_absolute() {
                input.path.clone()
            } else {
                spec.cwd.join(&input.path)
            }
            .canonicalize()
            .map_err(|e| invalid(e.to_string()))?;
            if let Some(subject) = subjects
                .iter()
                .find(|subject| subject.logical_path == input.path)
            {
                if subject.original_path != original
                    || subject.sha256 != input.sha256
                    || !original.starts_with(&workspace)
                    || subject.execution_source.starts_with(&workspace)
                    || subject.execution_source.starts_with(&self.state_root)
                    || subject.execution_source.starts_with(&self.repository)
                    || subject.execution_source.starts_with(&report_root)
                {
                    return Err(invalid(
                        "subject snapshot differs from its frozen namespace binding".into(),
                    ));
                }
                for path in [&original, &subject.execution_source] {
                    let bytes = pinned_verifier_bytes(path).map_err(|e| invalid(e.to_string()))?;
                    if bytes.len() as u64 != subject.bytes
                        || forgeflow_evidence::sha256(&bytes) != subject.sha256
                    {
                        return Err(invalid(
                            "subject snapshot digest or size changed before sandbox launch".into(),
                        ));
                    }
                }
                continue;
            }
            if !input.path.is_absolute() && self.subject_authority.is_some() {
                return Err(invalid(
                    "business subject was not resolved before sandbox launch".into(),
                ));
            }
            let Some(artifact) = self.artifact_inputs.get(&input.path) else {
                oracle_inputs.push(original);
                continue;
            };
            if artifact.sha256 != input.sha256
                || original != input.path
                || original.parent() != Some(self.state_root.join("artifacts").as_path())
                || original.starts_with(&self.repository)
                || self.repository.starts_with(&original)
                || self.state_root.starts_with(&original)
                || original.starts_with(&workspace)
                || workspace.starts_with(&original)
                || original.starts_with(&report_root)
                || report_root.starts_with(&original)
                || [
                    &program,
                    &registered.guard_program,
                    &registered.bwrap_program,
                ]
                .iter()
                .any(|path| path.starts_with(&original) || original.starts_with(path))
            {
                return Err(invalid(
                    "verifier artifact handoff overlaps protected state".into(),
                ));
            }
            if handoffs.contains_key(&original) {
                continue;
            }
            if scratch.is_none() {
                use std::os::unix::fs::DirBuilderExt;
                // A controller-supplied TMPDIR may have replaceable ancestors. Use the
                // root-owned sticky Linux /tmp boundary, then expose only exact copies.
                let parent = PathBuf::from("/tmp");
                let metadata = fs::symlink_metadata(&parent).map_err(|e| invalid(e.to_string()))?;
                if !metadata.is_dir()
                    || metadata.uid() != 0
                    || metadata.permissions().mode() & 0o1000 == 0
                    || parent.canonicalize().map_err(|e| invalid(e.to_string()))? != parent
                {
                    return Err(invalid(
                        "verifier input scratch requires trusted sticky /tmp".into(),
                    ));
                }
                let root = parent.join(format!(
                    "forgeflow-verifier-inputs-{}",
                    uuid::Uuid::new_v4()
                ));
                if [&self.state_root, &self.repository, &workspace, &report_root]
                    .iter()
                    .any(|path| root.starts_with(path) || path.starts_with(&root))
                {
                    return Err(invalid(
                        "verifier input scratch overlaps protected state".into(),
                    ));
                }
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .map_err(|e| invalid(e.to_string()))?;
                scratch = Some(VerifierInputScratch(root));
            }
            use std::io::{Read, Write};
            let mut source =
                open_verifier_input(&input.path).map_err(|e| invalid(e.to_string()))?;
            let mut bytes = Vec::new();
            source
                .read_to_end(&mut bytes)
                .map_err(|e| invalid(e.to_string()))?;
            if bytes.len() as u64 != artifact.bytes
                || forgeflow_evidence::sha256(&bytes) != input.sha256
            {
                return Err(invalid(
                    "registered verifier artifact digest or size mismatch".into(),
                ));
            }
            let copy = scratch
                .as_ref()
                .unwrap()
                .0
                .join(format!("input-{}", handoffs.len()));
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&copy)
                .map_err(|e| invalid(e.to_string()))?;
            file.write_all(&bytes).map_err(|e| invalid(e.to_string()))?;
            file.sync_all().map_err(|e| invalid(e.to_string()))?;
            if forgeflow_evidence::sha256(&fs::read(&copy).map_err(|e| invalid(e.to_string()))?)
                != input.sha256
            {
                return Err(invalid("verifier artifact copy digest mismatch".into()));
            }
            handoffs.insert(original, (copy, artifact));
        }
        profile.readonly_paths.retain(|path| {
            matches!(
                path.to_str(),
                Some(
                    "/usr"
                        | "/bin"
                        | "/lib"
                        | "/lib64"
                        | "/etc/ld.so.cache"
                        | "/etc/ld.so.conf"
                        | "/etc/ld.so.conf.d"
                )
            ) || path.canonicalize().ok().is_some_and(|path| {
                program.starts_with(&path)
                    || oracle_inputs.iter().any(|input| input.starts_with(&path))
            })
        });
        if let Some(scratch) = &scratch {
            for path in &profile.readonly_paths {
                let path = path.canonicalize().map_err(|e| invalid(e.to_string()))?;
                if scratch.0.starts_with(&path) {
                    return Err(invalid(
                        "verifier runtime mount exposes private input scratch siblings".into(),
                    ));
                }
            }
        }
        profile.readonly_paths.push(command.program.clone());
        profile.readonly_paths.extend(oracle_inputs);
        profile
            .readonly_paths
            .extend(handoffs.values().map(|(copy, _)| copy.clone()));
        let artifact_path = artifact_path
            .map(std::path::Path::canonicalize)
            .transpose()
            .map_err(|e| invalid(e.to_string()))?;
        if let Some(path) = &artifact_path {
            if spec
                .env
                .get("FORGEFLOW_ARTIFACT_PATH")
                .map(PathBuf::from)
                .as_ref()
                != Some(path)
            {
                return Err(invalid(
                    "verifier artifact environment differs from controller input".into(),
                ));
            }
            profile.readonly_paths.push(path.clone());
        } else if spec.env.contains_key("FORGEFLOW_ARTIFACT_PATH") {
            return Err(invalid("unregistered verifier artifact environment".into()));
        }
        profile.readonly_paths.sort();
        profile.readonly_paths.dedup();
        for readonly in &profile.readonly_paths {
            let path = readonly
                .canonicalize()
                .map_err(|e| invalid(e.to_string()))?;
            if path.starts_with("/home") && path.components().count() <= 3 {
                return Err(invalid(
                    "verifier runtime mount exposes a complete host home".into(),
                ));
            }
            if path.starts_with(&self.repository)
                || self.repository.starts_with(&path)
                || self.state_root.starts_with(&path)
                || (path.starts_with(&self.state_root)
                    && path != workspace
                    && !path.starts_with(&workspace)
                    && artifact_path.as_ref() != Some(&path))
            {
                return Err(invalid(
                    "verifier readonly input exposes canonical repository or control state".into(),
                ));
            }
        }
        let report = PathBuf::from(
            spec.env
                .get("FORGEFLOW_REPORT_PATH")
                .ok_or_else(|| invalid("verifier report path missing".into()))?,
        );
        let parent = report
            .parent()
            .ok_or_else(|| invalid("verifier report parent missing".into()))?
            .canonicalize()
            .map_err(|e| invalid(e.to_string()))?;
        let report = parent.join(
            report
                .file_name()
                .ok_or_else(|| invalid("verifier report filename missing".into()))?,
        );
        if report.starts_with(&workspace) || report.starts_with(&self.repository) {
            return Err(invalid(
                "verifier report must be outside candidate and canonical Git".into(),
            ));
        }
        // The runner already rejected an existing report. Expose exactly this output inode;
        // other roles' reports, process journals and model-output bytes remain inaccessible.
        let output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&report)
            .map_err(|e| invalid(e.to_string()))?;
        output.sync_all().map_err(|e| invalid(e.to_string()))?;
        let instance = forgeflow_runtime::SandboxInstance {
            workspace: workspace.clone(),
            write_set: Vec::new(),
            allow_git_metadata: false,
            writable_mounts: vec![forgeflow_runtime::SandboxMount {
                source: report.clone(),
                target: report,
            }],
        };
        let mut launch = forgeflow_runtime::sandbox_command(spec, &profile, &instance)
            .map_err(|e| invalid(e.to_string()))?;
        if !self.runtime_assets.is_empty() {
            let delimiter = launch
                .args
                .iter()
                .position(|argument| argument == "--")
                .ok_or_else(|| invalid("sandbox wrapper delimiter missing".into()))?;
            let mut mounts = Vec::new();
            let mut inputs = Vec::new();
            for asset in &self.runtime_assets {
                let bytes = pinned_verifier_bytes(&asset.source)
                    .map_err(|error| invalid(error.to_string()))?;
                if bytes.len() as u64 != asset.bytes
                    || forgeflow_evidence::sha256(&bytes) != asset.sha256
                {
                    return Err(invalid(
                        "Native-approved immutable runtime dependency changed before launch".into(),
                    ));
                }
                let source = asset
                    .source
                    .to_str()
                    .ok_or_else(|| invalid("runtime source path is not UTF-8".into()))?;
                let target = asset
                    .target
                    .to_str()
                    .ok_or_else(|| invalid("runtime target path is not UTF-8".into()))?;
                if (0..delimiter.saturating_sub(2)).any(|index| {
                    matches!(
                        launch.args[index].as_str(),
                        "--bind" | "--ro-bind" | "--dev-bind"
                    ) && asset
                        .target
                        .starts_with(PathBuf::from(&launch.args[index + 2]))
                }) {
                    return Err(invalid(
                        "runtime dependency namespace has a preexisting broader mount".into(),
                    ));
                }
                mounts.extend(["--ro-bind".to_owned(), source.to_owned(), target.to_owned()]);
                inputs.push(json!({"execution_source":asset.source,"namespace_target":asset.target,"sha256":asset.sha256,"bytes":asset.bytes}));
            }
            launch.args.splice(delimiter..delimiter, mounts);
            let manifest = json!({"schema_version":"forgeflow.native-verifier-runtime-handoff.v1","verification_plan_id":self.plan.plan_id,
                "verification_plan_hash":self.plan.digest(),"command_index":command_index,"command_snapshot":command,
                "native_recovery_authorization":self.recovery_authorization,"inputs":inputs,"readonly":true,"original_command_unchanged":true});
            let path = report_root.join(format!(
                "verifier-runtime-handoff-{}.json",
                uuid::Uuid::new_v4()
            ));
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|error| invalid(error.to_string()))?;
            file.write_all(
                &serde_json::to_vec(&manifest).map_err(|error| invalid(error.to_string()))?,
            )
            .and_then(|()| file.sync_all())
            .map_err(|error| invalid(error.to_string()))?;
            fs::File::open(&report_root)
                .and_then(|file| file.sync_all())
                .map_err(|error| invalid(error.to_string()))?;
        }
        if !subjects.is_empty() {
            let delimiter = launch
                .args
                .iter()
                .position(|argument| argument == "--")
                .ok_or_else(|| invalid("sandbox wrapper delimiter missing".into()))?;
            let workspace_text = workspace
                .to_str()
                .ok_or_else(|| invalid("verifier workspace is not UTF-8".into()))?;
            if !(0..delimiter.saturating_sub(2)).any(|index| {
                launch.args[index] == "--ro-bind"
                    && launch.args[index + 1] == workspace_text
                    && launch.args[index + 2] == workspace_text
            }) {
                return Err(invalid(
                    "subject projection requires the actual readonly parent workspace mount".into(),
                ));
            }
            let mut mounts = Vec::new();
            for subject in &subjects {
                let source = subject
                    .execution_source
                    .to_str()
                    .ok_or_else(|| invalid("subject snapshot path is not UTF-8".into()))?;
                let target = subject
                    .original_path
                    .to_str()
                    .ok_or_else(|| invalid("subject namespace target is not UTF-8".into()))?;
                if (0..delimiter.saturating_sub(2)).any(|index| {
                    matches!(
                        launch.args[index].as_str(),
                        "--bind" | "--ro-bind" | "--dev-bind"
                    ) && launch.args[index + 2] == target
                }) {
                    return Err(invalid(
                        "subject namespace already has a conflicting exact mount".into(),
                    ));
                }
                mounts.extend(["--ro-bind".to_owned(), source.to_owned(), target.to_owned()]);
            }
            // The parent candidate mount occurs after runtime readonly paths. Install
            // exact subject leaves last so the parent cannot hide their frozen copies.
            launch.args.splice(delimiter..delimiter, mounts.clone());
            let manifest = json!({"schema_version":"forgeflow.verifier-subject-handoff.v1","verification_plan_id":self.plan.plan_id,
                "verification_plan_hash":self.plan.digest(),"command_index":command_index,"command_snapshot":command,
                "workspace":workspace,"inputs":subjects,"readonly_mount_arguments":mounts,"original_command_unchanged":true});
            let path = report_root.join(format!(
                "verifier-subject-handoff-{}.json",
                uuid::Uuid::new_v4()
            ));
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| invalid(e.to_string()))?;
            file.write_all(&serde_json::to_vec(&manifest).map_err(|e| invalid(e.to_string()))?)
                .and_then(|()| file.sync_all())
                .map_err(|e| invalid(e.to_string()))?;
            fs::File::open(&report_root)
                .and_then(|file| file.sync_all())
                .map_err(|e| invalid(e.to_string()))?;
        }
        if let Some(scratch) = scratch {
            // Runtime mounts normally use source == target. Replace only these exact known
            // targets before the wrapper delimiter; frozen program, argv and env stay intact.
            let delimiter = launch
                .args
                .iter()
                .position(|arg| arg == "--")
                .ok_or_else(|| invalid("sandbox wrapper delimiter missing".into()))?;
            for (target, (copy, _)) in &handoffs {
                let target = target
                    .to_str()
                    .ok_or_else(|| invalid("verifier input target is not UTF-8".into()))?;
                let copy = copy
                    .to_str()
                    .ok_or_else(|| invalid("verifier input copy is not UTF-8".into()))?;
                let mounts: Vec<_> = (0..delimiter.saturating_sub(2))
                    .filter(|index| {
                        launch.args[*index] == "--ro-bind"
                            && launch.args[*index + 1] == copy
                            && launch.args[*index + 2] == copy
                    })
                    .collect();
                if mounts.len() != 1 {
                    return Err(invalid(
                        "verifier input copy must have one exact readonly mount".into(),
                    ));
                }
                launch.args[mounts[0] + 2] = target.into();
            }
            fs::File::open(&scratch.0)
                .and_then(|file| file.sync_all())
                .map_err(|e| invalid(e.to_string()))?;
            let manifest = json!({"verification_plan_id":self.plan.plan_id,"verification_plan_hash":self.plan.digest(),"command_index":command_index,"command_snapshot":command,"report_path":instance.writable_mounts[0].source,"inputs":handoffs.iter().map(|(original,(copy,artifact))| json!({"artifact_id":artifact.artifact_id,"original_path":original,"execution_source":copy,"namespace_target":original,"sha256":artifact.sha256,"bytes":artifact.bytes})).collect::<Vec<_>>()});
            let path = report_root.join(format!(
                "verifier-input-handoff-{}.json",
                uuid::Uuid::new_v4()
            ));
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| invalid(e.to_string()))?;
            file.write_all(&serde_json::to_vec(&manifest).map_err(|e| invalid(e.to_string()))?)
                .map_err(|e| invalid(e.to_string()))?;
            file.sync_all().map_err(|e| invalid(e.to_string()))?;
            fs::File::open(&report_root)
                .and_then(|file| file.sync_all())
                .map_err(|e| invalid(e.to_string()))?;
            // Retained until the enclosing awaited runner has settled. Restart constructs a
            // new guard from the original catalog and hashes; old scratch is never adopted.
            self.input_scratch
                .lock()
                .map_err(|_| invalid("verifier scratch registry poisoned".into()))?
                .push(scratch);
        }
        Ok(launch)
    }
}
fn io_error(error: std::io::Error) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "ARTIFACT_IO_FAILED",
        error.to_string(),
    )
}
fn json_error(error: serde_json::Error) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "CONTRACT_INVALID",
        error.to_string(),
    )
}
fn git_error(error: forgeflow_git::GitError) -> ApiError {
    if let forgeflow_git::GitError::CommitInProgress {
        intent_id,
        new_sha,
        reason,
    } = error
    {
        let mut result = ApiError::new(
            StatusCode::CONFLICT,
            "COMMIT_IN_PROGRESS",
            "integration result is uncertain; recover the same durable intent before another integration",
        );
        result.1.details = json!({"intent_id":intent_id,"new_sha":new_sha,"reason":reason});
        return result;
    }
    ApiError::new(
        StatusCode::CONFLICT,
        "GIT_INTEGRATION_FAILED",
        error.to_string(),
    )
}

async fn run_read_only(
    s: App,
    project: &str,
    attempt_id: &str,
    op: &str,
    attempt: Attempt,
    task: TaskCard,
    envelope: ExecutionEnvelope,
    plan: VerificationPlan,
    artifact_root: PathBuf,
    worktree: PathBuf,
    verifier_guard: RegisteredVerifierGuard,
) -> Result<Value, ApiError> {
    let raw = tokio::fs::read(
        s.data_root
            .join("attempts")
            .join(attempt_id)
            .join("final.json"),
    )
    .await
    .map_err(io_error)?;
    if raw.is_empty() || raw.len() > 32 * 1024 * 1024 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ARTIFACT_INVALID",
            "read-only final artifact must be nonempty and bounded",
        ));
    }
    let artifact_path = artifact_root.join("model-output.json");
    tokio::fs::write(&artifact_path, &raw)
        .await
        .map_err(io_error)?;
    let artifact_hash = forgeflow_evidence::sha256(&raw);
    let binding = forgeflow_evidence::ArtifactBinding {
        task_revision: attempt.task_revision,
        attempt_id: attempt_id.into(),
        generation: attempt.generation,
        verification_plan_id: plan.plan_id.clone(),
        verification_plan_hash: plan.digest(),
        contract_version: plan.contract_version.clone(),
        input_hash: task.input_digest.clone(),
        context_hash: envelope.context_manifest.sha256,
        prompt_hash: envelope.prompt_artifact.sha256,
        artifact_hash: artifact_hash.clone(),
    };
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let _cancellation_guard = CancellationGuard(cancel_tx.clone());
    mirror_server_shutdown(&s, &cancel_tx);
    let authority = s.store.clone();
    let identity = attempt.clone();
    let signal = cancel_tx.clone();
    let renewal = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if signal.is_closed() || *signal.borrow() {
                break;
            }
            if authority
                .heartbeat(HeartbeatRequest {
                    project_id: identity.project_id.clone(),
                    attempt_id: identity.attempt_id.clone(),
                    generation: identity.generation,
                    worker_id: identity.worker_id.clone(),
                    lease_seconds: 30,
                })
                .await
                .is_err()
            {
                let _ = signal.send(true);
                break;
            }
        }
    });
    let physical_context =
        verifier_guard.physical_context(attempt_id, attempt.generation, op, &artifact_root)?;
    register_verifier_root(
        &s,
        project,
        op,
        attempt_id,
        &artifact_root,
        physical_context.as_ref(),
    )
    .await?;
    let receipt =
        forgeflow_evidence::execute_artifact_verification_with_guard_and_physical_and_subjects(
            &plan,
            &worktree,
            &binding,
            &artifact_path,
            &artifact_root,
            cancel_rx,
            |spec| verifier_guard.apply(spec, &artifact_root, Some(&artifact_path)),
            physical_context.as_ref(),
            |command, cwd| verifier_guard.resolve_subject_inputs(command, cwd),
        )
        .await;
    settle_verifier_root(
        &s,
        project,
        op,
        attempt_id,
        &artifact_root,
        physical_context.as_ref(),
    )
    .await?;
    let _ = cancel_tx.send(true);
    let _ = renewal.await;
    let receipt = receipt.map_err(|e| {
        ApiError::new(
            StatusCode::CONFLICT,
            "ARTIFACT_VERIFICATION_FAILED",
            e.to_string(),
        )
    })?;
    let artifact_id = format!("model-output-{op}");
    s.store
        .execute_command(
            CommandIdentity {
                actor_id: "verification-service".into(),
                idempotency_key: format!("{op}:output"),
            },
            CatalogCommand::PutArtifact {
                project_id: project.into(),
                id: artifact_id.clone(),
                path: artifact_path.to_string_lossy().into_owned(),
                sha256: artifact_hash.clone(),
                kind: "STRUCTURED_MODEL_OUTPUT".into(),
                bytes: raw.len() as u64,
            },
        )
        .await?;
    let evidence = EvidenceReceipt {
        receipt_id: format!("artifact-receipt-{op}"),
        project_id: project.into(),
        attempt_id: attempt_id.into(),
        generation: attempt.generation,
        kind: "STRUCTURED_ARTIFACT".into(),
        input_digest: task.input_digest,
        candidate_sha: None,
        integrated_sha: None,
        verifier_id: receipt.verifier_id.clone(),
        author_id: receipt.author_id.clone(),
        total: receipt.total,
        failed: receipt.failed,
        skipped: receipt.skipped,
        artifact: ArtifactRef {
            artifact_id,
            sha256: artifact_hash,
        },
        details: serde_json::to_value(&receipt).map_err(json_error)?,
        created_at: Utc::now(),
    };
    s.store.record_evidence(evidence.clone()).await?;
    if attempt.state == AttemptState::Verifying {
        s.store
            .transition(TransitionRequest {
                project_id: project.into(),
                attempt_id: attempt_id.into(),
                generation: attempt.generation,
                worker_id: attempt.worker_id.clone(),
                expected_state: AttemptState::Verifying,
                next_state: AttemptState::ReviewReady,
                reason: "independent structured artifact validation passed".into(),
                receipt: Some(json!({"receipt_id":evidence.receipt_id})),
            })
            .await?;
    }
    let handoff = if crate::handoff::strict_for_attempt(&s, project, &attempt).await? {
        Some(
            s.store
                .terminal_handoff(
                    forgeflow_store::HandoffRequest {
                        identity: CommandIdentity {
                            actor_id: "verification-service".into(),
                            idempotency_key: format!("{op}:readonly-handoff"),
                        },
                        terminal: forgeflow_store::TerminalAcknowledgement::CompleteReadOnly {
                            project_id: project.into(),
                            attempt_id: attempt_id.into(),
                            generation: attempt.generation,
                            worker_id: attempt.worker_id.clone(),
                            receipt_id: evidence.receipt_id.clone(),
                        },
                    },
                    &crate::handoff::scheduler(project)?,
                )
                .await?,
        )
    } else {
        None
    };
    let completed = match &handoff {
        Some(receipt) => receipt.terminal.clone(),
        None => {
            s.store
                .complete_read_only(
                    project,
                    attempt_id,
                    attempt.generation,
                    &attempt.worker_id,
                    &evidence.receipt_id,
                )
                .await?
        }
    };
    let mut result = json!({"artifact":evidence.artifact,"evidence":evidence,"attempt":completed,"delivery_kind":"READ_ONLY_ARTIFACT"});
    if let Some(receipt) = handoff {
        result["handoff"] = serde_json::to_value(receipt).map_err(json_error)?;
    }
    Ok(result)
}

struct CancellationGuard(tokio::sync::watch::Sender<bool>);
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

fn physical_operation_alias(operation: &str) -> String {
    if let Some(hash) = operation
        .strip_prefix("verification-recovery:")
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        format!("verification-recovery-{hash}")
    } else {
        operation.to_owned()
    }
}
async fn register_verifier_root(
    s: &App,
    p: &str,
    op: &str,
    attempt: &str,
    root: &std::path::Path,
    physical: Option<&forgeflow_evidence::PhysicalVerificationContext>,
) -> Result<(), ApiError> {
    let canonical = root.canonicalize().map_err(io_error)?;
    let hash = forgeflow_evidence::sha256(canonical.to_string_lossy().as_bytes());
    let physical_op = physical_operation_alias(op);
    let id = format!("verifier-root-{physical_op}-{}", &hash[..16]);
    let registered = s.store.execute_command(CommandIdentity{actor_id:"verification-service".into(),idempotency_key:id.clone()},CatalogCommand::PutDocument{project_id:p.into(),collection:"operations".into(),id,value:json!({"kind":"VERIFIER_PROCESS_ROOT","operation_id":physical_op,"ledger_operation_id":op,"attempt_id":attempt,"status":"REGISTERED","verifier_root":canonical,"physical_grant":physical}),expected_revision:None}).await?;
    if registered.replayed {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "VERIFIER_GRANT_ALREADY_REGISTERED",
            "existing verifier registration can be observed or recovered, never relaunched",
        ));
    }
    Ok(())
}

async fn settle_verifier_root(
    s: &App,
    p: &str,
    op: &str,
    attempt: &str,
    root: &std::path::Path,
    physical: Option<&forgeflow_evidence::PhysicalVerificationContext>,
) -> Result<(), ApiError> {
    let root = root.canonicalize().map_err(io_error)?;
    let stops = forgeflow_evidence::verification_stop_evidence(&root).map_err(|e| {
        ApiError::new(
            StatusCode::CONFLICT,
            "PROCESS_EXIT_UNCONFIRMED",
            e.to_string(),
        )
    })?;
    let physical_evidence = if physical.is_some() {
        forgeflow_evidence::verification_physical_stop_evidence(&root).map_err(|e| {
            ApiError::new(
                StatusCode::CONFLICT,
                "PROCESS_EXIT_UNCONFIRMED",
                e.to_string(),
            )
        })?
    } else {
        Vec::new()
    };
    let hash = forgeflow_evidence::sha256(root.to_string_lossy().as_bytes());
    let physical_op = physical_operation_alias(op);
    let registration = format!("verifier-root-{physical_op}-{}", &hash[..16]);
    let id = format!("verifier-settled-{physical_op}-{}", &hash[..16]);
    s.store.execute_command(CommandIdentity{actor_id:"verification-service".into(),idempotency_key:id.clone()},CatalogCommand::PutDocument{project_id:p.into(),collection:"operations".into(),id:id.clone(),expected_revision:None,value:json!({"kind":"VERIFIER_PROCESS_SETTLED","operation_id":id,"registered_operation_id":physical_op,"ledger_operation_id":op,"attempt_id":attempt,"registration_id":registration,"verifier_root":root,"status":if stops.is_empty(){"NEVER_LAUNCHED"}else{"STOPPED"},"never_launched":stops.is_empty(),"stop_evidence":stops,"physical_evidence":physical_evidence,"source":"COMPLETED_AWAITED_RUNNER"})}).await?;
    Ok(())
}

fn mirror_server_shutdown(s: &App, cancel: &tokio::sync::watch::Sender<bool>) {
    let mut shutdown = s.auth.shutdown_receiver();
    let signal = cancel.clone();
    tokio::spawn(async move {
        if *shutdown.borrow() {
            let _ = signal.send(true);
            return;
        }
        tokio::select! {_=shutdown.changed()=>{let _=signal.send(true);},_=signal.closed()=>{}}
    });
}

#[cfg(test)]
mod verifier_input_handoff_tests {
    use super::*;
    use forgeflow_evidence::{BoundInput, CaseKind, CommandSpec, ExpectedCase, VerificationRole};
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
    };

    struct Fixture {
        _root: VerifierInputScratch,
        guard: RegisteredVerifierGuard,
        workspace: PathBuf,
        reports: PathBuf,
        inputs: Vec<BoundInput>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("forgeflow-verifier-test-{}", uuid::Uuid::new_v4()));
            let state = root.join("state");
            let workspace = state.join("worktrees/candidate");
            let reports = state.join("reports/run");
            let repository = state.join("repositories/canonical");
            for path in [&workspace, &reports, &repository, &state.join("artifacts")] {
                fs::create_dir_all(path).unwrap();
            }
            fs::write(workspace.join("candidate.txt"), b"frozen candidate").unwrap();
            let denied = [
                state.join("secret"),
                state.join("artifacts/unbound"),
                repository.join("secret"),
                reports.join("other-report.json"),
                reports.join("other-model-output.json"),
                // Privacy canaries are unrelated host state, not runtime-owned
                // journals. Malformed journal objects have their own negative
                // test and must continue to quarantine the verifier root.
                state.join("private-journals/private-journal"),
            ];
            for path in &denied {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"private").unwrap();
            }
            let mut inputs = Vec::new();
            let mut catalog_inputs = BTreeMap::new();
            for name in ["request", "source", "authority"] {
                let path = state.join("artifacts").join(name);
                fs::write(&path, name).unwrap();
                let input = BoundInput {
                    path: path.clone(),
                    sha256: forgeflow_evidence::sha256(name.as_bytes()),
                };
                let catalog = json!({"artifact_id":name,"path":path,"sha256":input.sha256,"bytes":name.len()});
                catalog_inputs.insert(
                    path,
                    VerifierArtifactInput::from_catalog(&input, &catalog, name.len() as u64)
                        .unwrap(),
                );
                inputs.push(input);
            }
            let oracle = root.join("oracle.py");
            fs::write(&oracle, r#"import hashlib,json,os,pathlib,time
inputs=json.loads(os.environ['TEST_INPUTS'])
for raw,digest in inputs:
 p=pathlib.Path(raw)
 assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
 try:p.write_text('overwrite');raise AssertionError('input writable')
 except OSError:pass
assert {p.name for p in pathlib.Path(inputs[0][0]).parent.iterdir()}=={'request','source','authority'}
for raw in json.loads(os.environ['TEST_DENIED']):
 try:pathlib.Path(raw).read_bytes();raise AssertionError('unrelated host input readable: '+raw)
 except OSError:pass
candidate=pathlib.Path('candidate.txt')
assert candidate.read_text()=='frozen candidate'
for op in [lambda:candidate.write_text('changed'),lambda:candidate.chmod(0o777),lambda:candidate.unlink(),lambda:candidate.rename('moved.txt')]:
 try:op();raise AssertionError('candidate writable')
 except OSError:pass
report=pathlib.Path(os.environ['FORGEFLOW_REPORT_PATH'])
assert {p.name for p in report.parent.iterdir()}=={report.name}
# Under /tmp these parents are private tmpfs, created for the exact report bind.
# A same-name shadow may be writable there; Rust checks the actual host inode and
# every host sibling afterward, rather than treating namespace creation as host IO.
namespace_shadows=[]
for sibling in [report.with_name('other-report.json'),report.with_name('adjacent-output')]:
 try:
  sibling.write_text('namespace-only shadow')
  assert sibling.read_text()=='namespace-only shadow'
  namespace_shadows.append(str(sibling))
 except OSError:pass
try:os.link(candidate,report.with_name('linked-output'));raise AssertionError('candidate hardlink allowed')
except OSError:pass
for raw in json.loads(os.environ['TEST_DENIED']):
 if raw not in namespace_shadows:
  try:pathlib.Path(raw).read_bytes();raise AssertionError('unrelated host input became readable: '+raw)
  except OSError:pass
report.write_text(json.dumps({'binding':json.loads(os.environ['FORGEFLOW_EVIDENCE_BINDING']),'oracle_id':'handoff-oracle','cases':[{'name':'exact-inputs','kind':'positive','outcome':'passed'},{'name':'isolation','kind':'negative','outcome':'passed'}]}))
if os.environ.get('TEST_WAIT_FOR_DRIFT'):time.sleep(2)
print(json.dumps({'exact_inputs_readable':True,'candidate_writes_refused':True,'namespace_only_shadows':namespace_shadows}),flush=True)
"#).unwrap();
            let guard_program = std::env::var_os("FORGEFLOW_TEST_SANDBOX_GUARD")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_exe()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join("forgeflow-sandbox-guard")
                });
            let mut readonly_paths = vec![
                PathBuf::from("/usr"),
                oracle.clone(),
                state.join("artifacts"),
            ];
            for path in ["/bin", "/lib", "/lib64", "/etc/ld.so.cache"] {
                if Path::new(path).exists() {
                    readonly_paths.push(path.into());
                }
            }
            let profile = forgeflow_runtime::SandboxProfile { bwrap_program: "/usr/bin/bwrap".into(), bwrap_sha256: forgeflow_evidence::sha256(&fs::read("/usr/bin/bwrap").unwrap()), guard_sha256: forgeflow_evidence::sha256(&fs::read(&guard_program).expect("build forgeflow-sandbox-guard or set FORGEFLOW_TEST_SANDBOX_GUARD for actual isolation tests")), guard_program, readonly_paths, network_allowed: false };
            let mut commands = Vec::new();
            for (role, name) in [
                (VerificationRole::Author, "author"),
                (VerificationRole::Consumer, "consumer"),
                (VerificationRole::Independent, "independent"),
            ] {
                let mut bound_inputs = inputs.clone();
                bound_inputs.push(BoundInput {
                    path: oracle.clone(),
                    sha256: forgeflow_evidence::sha256(&fs::read(&oracle).unwrap()),
                });
                commands.push(CommandSpec {
                    role,
                    program: "/usr/bin/python3".into(),
                    args: vec![oracle.to_string_lossy().into()],
                    env: BTreeMap::from([
                        (
                            "TEST_INPUTS".into(),
                            serde_json::to_string(
                                &inputs
                                    .iter()
                                    .map(|input| (&input.path, &input.sha256))
                                    .collect::<Vec<_>>(),
                            )
                            .unwrap(),
                        ),
                        (
                            "TEST_DENIED".into(),
                            serde_json::to_string(&denied).unwrap(),
                        ),
                        ("TEST_ROLE".into(), name.into()),
                    ]),
                    executable_hash: forgeflow_evidence::sha256(
                        &fs::read("/usr/bin/python3").unwrap(),
                    ),
                    bound_inputs,
                    report_path: format!("{name}.json"),
                    expected_cases: vec![
                        ExpectedCase {
                            name: "exact-inputs".into(),
                            kind: CaseKind::Positive,
                        },
                        ExpectedCase {
                            name: "isolation".into(),
                            kind: CaseKind::Negative,
                        },
                    ],
                    timeout_seconds: 10,
                });
            }
            let plan = VerificationPlan {
                plan_id: "handoff-plan".into(),
                task_revision: 1,
                contract_version: "v1".into(),
                input_hash: "a".repeat(64),
                environment_profile: "actual-exact-handoff".into(),
                oracle_id: "handoff-oracle".into(),
                verifier_id: "independent-verifier".into(),
                author_id: "author".into(),
                commands,
            };
            Self {
                _root: VerifierInputScratch(root),
                guard: RegisteredVerifierGuard {
                    profile: Some(profile),
                    physical: None,
                    plan,
                    repository,
                    state_root: state,
                    artifact_inputs: catalog_inputs,
                    subject_authority: None,
                    runtime_assets: Vec::new(),
                    recovery_authorization: None,
                    subject_inputs: std::sync::Mutex::new(std::collections::BTreeMap::new()),
                    input_scratch: std::sync::Mutex::new(Vec::new()),
                },
                workspace,
                reports,
                inputs,
            }
        }
        fn spec(&self) -> forgeflow_runtime::ProcessSpec {
            let command = &self.guard.plan.commands[0];
            let mut env = command.env.clone();
            env.insert(
                "FORGEFLOW_REPORT_PATH".into(),
                self.reports
                    .join(&command.report_path)
                    .to_string_lossy()
                    .into(),
            );
            env.insert("FORGEFLOW_EVIDENCE_BINDING".into(), "{}".into());
            forgeflow_runtime::ProcessSpec {
                program: command.program.clone(),
                args: command.args.clone(),
                env,
                cwd: self.workspace.clone(),
                stdin: Vec::new(),
            }
        }
        fn binding(&self) -> EvidenceBinding {
            EvidenceBinding {
                task_revision: 1,
                attempt_id: "local-handoff".into(),
                generation: 1,
                base_sha: "b".repeat(40),
                candidate_sha: "c".repeat(40),
                integrated_sha: None,
                contract_version: "v1".into(),
                verification_plan_id: self.guard.plan.plan_id.clone(),
                verification_plan_hash: self.guard.plan.digest(),
                input_hash: self.guard.plan.input_hash.clone(),
                source_hash: forgeflow_evidence::sha256(b"frozen candidate"),
            }
        }
        fn host_snapshot(
            &self,
            roots: &[PathBuf],
            excluded: &[PathBuf],
        ) -> BTreeMap<PathBuf, (u64, u64, u64, u32, Option<String>)> {
            let mut pending = roots.to_vec();
            let mut snapshot = BTreeMap::new();
            while let Some(path) = pending.pop() {
                if excluded.contains(&path) {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path).unwrap();
                let digest = if metadata.is_file() {
                    Some(forgeflow_evidence::sha256(&fs::read(&path).unwrap()))
                } else {
                    None
                };
                snapshot.insert(
                    path.clone(),
                    (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.nlink(),
                        metadata.mode(),
                        digest,
                    ),
                );
                if metadata.is_dir() {
                    pending.extend(
                        fs::read_dir(path)
                            .unwrap()
                            .map(|entry| entry.unwrap().path()),
                    );
                }
            }
            snapshot
        }
        fn denied_paths(&self) -> Vec<PathBuf> {
            serde_json::from_str(&self.guard.plan.commands[0].env["TEST_DENIED"]).unwrap()
        }
        fn assert_no_host_sibling_output(&self) {
            for name in ["adjacent-output", "linked-output"] {
                assert_eq!(
                    fs::symlink_metadata(self.reports.join(name))
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::NotFound,
                    "sandbox output must not appear in the host report directory"
                );
            }
        }
    }

    #[tokio::test]
    async fn actual_handoff_retains_frozen_identity_and_exact_namespace() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let digest = fixture.guard.plan.digest();
        let launch = fixture
            .guard
            .apply(spec.clone(), &fixture.reports, None)
            .unwrap();
        assert_eq!(launch.env, spec.env);
        assert_eq!(fixture.guard.plan.digest(), digest);
        let delimiter = launch.args.iter().rposition(|arg| arg == "--").unwrap();
        assert_eq!(
            &launch.args[delimiter + 1..],
            &[vec![spec.program.to_string_lossy().into_owned()], spec.args].concat()
        );
        for input in &fixture.inputs {
            let mount = launch
                .args
                .windows(3)
                .find(|args| args[0] == "--ro-bind" && args[2] == input.path.to_str().unwrap())
                .unwrap();
            assert_ne!(mount[1], mount[2]);
            let copy = Path::new(&mount[1]);
            assert_eq!(
                fs::metadata(copy).unwrap().permissions().mode() & 0o777,
                0o400
            );
            assert_eq!(
                fs::metadata(copy.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_ne!(
                fs::metadata(copy).unwrap().ino(),
                fs::metadata(&input.path).unwrap().ino()
            );
            assert_eq!(
                forgeflow_evidence::sha256(&fs::read(copy).unwrap()),
                input.sha256
            );
        }
        assert!(!launch.args.windows(3).any(|args| args[0] == "--ro-bind"
            && args[1] == fixture.guard.state_root.join("artifacts").to_str().unwrap()));
        let report_path = fixture.reports.join("author.json");
        let report_before = fs::metadata(&report_path).unwrap();
        // Include all state/candidate/control/report siblings and controller-created
        // handoff metadata; only the exact report inode may change its bytes.
        let host_before = fixture.host_snapshot(
            std::slice::from_ref(&fixture.guard.state_root),
            std::slice::from_ref(&report_path),
        );
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(&launch.program)
                .kill_on_drop(true)
                .args(&launch.args)
                .env_clear()
                .envs(&launch.env)
                .current_dir(&launch.cwd)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(fixture.workspace.join("candidate.txt")).unwrap(),
            b"frozen candidate"
        );
        assert_eq!(
            fixture.host_snapshot(
                std::slice::from_ref(&fixture.guard.state_root),
                std::slice::from_ref(&report_path),
            ),
            host_before,
            "namespace shadow probes must leave every other host path and inode unchanged"
        );
        fixture.assert_no_host_sibling_output();
        let report_after = fs::metadata(&report_path).unwrap();
        assert_eq!(
            (report_after.dev(), report_after.ino(), report_after.nlink()),
            (
                report_before.dev(),
                report_before.ino(),
                report_before.nlink()
            )
        );
        let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(report["cases"].as_array().unwrap().len(), 2);
        println!("{}", String::from_utf8_lossy(&output.stdout));
        let manifest: Value = fs::read_dir(&fixture.reports)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("verifier-input-handoff-")
            })
            .map(|entry| serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap())
            .unwrap();
        assert_eq!(manifest["verification_plan_hash"], digest);
        assert_eq!(
            manifest["command_snapshot"],
            serde_json::to_value(&fixture.guard.plan.commands[0]).unwrap()
        );
        assert_eq!(manifest["inputs"].as_array().unwrap().len(), 3);
        let scratch: Vec<_> = fixture
            .guard
            .input_scratch
            .lock()
            .unwrap()
            .iter()
            .map(|root| root.0.clone())
            .collect();
        drop(fixture);
        assert!(scratch.iter().all(|root| !root.exists()));
    }

    #[test]
    fn handoff_rejects_control_repository_ancestors_unregistered_inputs_and_drift() {
        let mut fixture = Fixture::new();
        fixture
            .guard
            .profile
            .as_mut()
            .unwrap()
            .readonly_paths
            .push(std::env::temp_dir().canonicalize().unwrap());
        assert!(
            fixture
                .guard
                .apply(fixture.spec(), &fixture.reports, None)
                .unwrap_err()
                .to_string()
                .contains("private input scratch siblings")
        );
        fixture.guard.profile.as_mut().unwrap().readonly_paths.pop();
        for path in [
            fixture.guard.repository.clone(),
            fixture.guard.state_root.clone(),
            fixture.guard.state_root.parent().unwrap().into(),
            fixture.guard.state_root.join("secret"),
            fixture.guard.state_root.join("artifacts/unbound"),
        ] {
            fixture.guard.plan.commands[0]
                .bound_inputs
                .push(BoundInput {
                    path,
                    sha256: "0".repeat(64),
                });
            assert!(
                fixture
                    .guard
                    .apply(fixture.spec(), &fixture.reports, None)
                    .is_err()
            );
            fixture.guard.plan.commands[0].bound_inputs.pop();
        }
        let mut spec = fixture.spec();
        spec.args.push("unregistered".into());
        assert!(fixture.guard.apply(spec, &fixture.reports, None).is_err());
        let mut spec = fixture.spec();
        spec.env.insert("TEST_ROLE".into(), "changed".into());
        assert!(fixture.guard.apply(spec, &fixture.reports, None).is_err());
        fixture.guard.plan.commands[0].bound_inputs[0].sha256 = "0".repeat(64);
        assert!(
            fixture
                .guard
                .apply(fixture.spec(), &fixture.reports, None)
                .is_err()
        );
        fixture.guard.plan.commands[0].bound_inputs[0].sha256 = fixture.inputs[0].sha256.clone();
        fs::write(&fixture.inputs[0].path, b"changed").unwrap();
        assert!(
            fixture
                .guard
                .apply(fixture.spec(), &fixture.reports, None)
                .is_err()
        );
        fs::remove_file(&fixture.inputs[0].path).unwrap();
        std::os::unix::fs::symlink(&fixture.inputs[1].path, &fixture.inputs[0].path).unwrap();
        assert!(
            fixture
                .guard
                .apply(fixture.spec(), &fixture.reports, None)
                .is_err()
        );
        assert!(!fixture.reports.join("author.json").exists());
    }

    #[test]
    fn catalog_and_descriptor_checks_reject_aliases_nonfiles_and_conflicting_identity() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "forgeflow-verifier-input-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let _root = VerifierInputScratch(root.clone());
        let path = root.join("input");
        fs::write(&path, b"input").unwrap();
        let input = BoundInput {
            path: path.clone(),
            sha256: forgeflow_evidence::sha256(b"input"),
        };
        let catalog = json!({"artifact_id":"input","path":path,"sha256":input.sha256,"bytes":5});
        assert!(VerifierArtifactInput::from_catalog(&input, &catalog, 5).is_ok());
        for (key, value) in [
            ("artifact_id", json!("other-project-artifact")),
            ("path", json!(root.join("elsewhere"))),
            ("sha256", json!("0".repeat(64))),
            ("bytes", json!(6)),
        ] {
            let mut changed = catalog.clone();
            changed[key] = value;
            assert!(VerifierArtifactInput::from_catalog(&input, &changed, 5).is_err());
        }
        assert!(open_verifier_input(&root).is_err());
        std::os::unix::fs::symlink(&root, root.join("alias")).unwrap();
        assert!(open_verifier_input(&root.join("alias/input")).is_err());
        fs::hard_link(&path, root.join("linked")).unwrap();
        assert!(open_verifier_input(&path).is_err());
    }

    #[tokio::test]
    async fn runner_rechecks_original_inputs_after_actual_handoff() {
        let mut fixture = Fixture::new();
        fixture.guard.plan.commands[0]
            .env
            .insert("TEST_WAIT_FOR_DRIFT".into(), "1".into());
        let denied_before = fixture.host_snapshot(&fixture.denied_paths(), &[]);
        let source = fixture.inputs[0].path.clone();
        let report = fixture.reports.join("author.json");
        let mutation = tokio::spawn(async move {
            for _ in 0..200 {
                if fs::metadata(&report).is_ok_and(|metadata| metadata.len() > 0) {
                    fs::write(&source, b"changed").unwrap();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("actual oracle did not produce its report before drift injection");
        });
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let result = forgeflow_evidence::execute_verification_with_guard(
            &fixture.guard.plan,
            &fixture.workspace,
            &fixture.binding(),
            &fixture.reports,
            rx,
            |spec| fixture.guard.apply(spec, &fixture.reports, None),
        )
        .await;
        mutation.await.unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("registered verifier input digest mismatch")
        );
        assert_eq!(
            fixture.host_snapshot(&fixture.denied_paths(), &[]),
            denied_before
        );
        fixture.assert_no_host_sibling_output();
        assert_eq!(
            fs::read(fixture.workspace.join("candidate.txt")).unwrap(),
            b"frozen candidate"
        );
        let report: Value =
            serde_json::from_slice(&fs::read(fixture.reports.join("author.json")).unwrap())
                .unwrap();
        assert_eq!(
            report["binding"],
            serde_json::to_value(fixture.binding()).unwrap()
        );
        assert!(
            report["cases"]
                .as_array()
                .unwrap()
                .iter()
                .all(|case| case["outcome"] == "passed")
        );
        assert!(!fixture.reports.join("verification-receipt.json").exists());
        let stops = forgeflow_evidence::verification_stop_evidence(&fixture.reports).unwrap();
        assert_eq!(
            stops.len(),
            1,
            "input drift must prevent later roles from launching"
        );
        assert!(stops[0].process_exit_confirmed);
        assert_eq!(stops[0].exit_code, Some(0));
        assert_eq!(stops[0].signal, None);
        assert_eq!(stops[0].reason, "executor_exited");
        assert!(stops[0].log_error.is_none());
        assert!(!fixture.reports.join("consumer.json").exists());
        assert!(!fixture.reports.join("independent.json").exists());
    }

    #[test]
    fn malformed_verifier_journal_objects_remain_quarantined() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "forgeflow-malformed-verifier-journal-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(root.join("verification-runs")).unwrap();
        let _root = VerifierInputScratch(root.clone());
        let malformed = root.join("verification-runs/private-journal");
        fs::write(&malformed, b"private").unwrap();
        let before = fs::symlink_metadata(&malformed).unwrap();
        let error = forgeflow_evidence::verification_stop_evidence(&root).unwrap_err();
        assert!(error.to_string().contains("keep quarantined"));
        assert_eq!(fs::read(&malformed).unwrap(), b"private");
        let after = fs::symlink_metadata(&malformed).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.nlink(), after.mode()),
            (before.dev(), before.ino(), before.nlink(), before.mode())
        );
        assert!(!root.join("verification-receipt.json").exists());
    }
}
