//! Owner-authorized continuation of an existing durable Git commit decision.
//! No author, model, candidate creation, or verification command runs here.
use super::*;
use async_trait::async_trait;
use forgeflow_git::{IntegrationService, IntegrationStore};
use std::{collections::BTreeSet, path::Path as FsPath};

static RUNNING: tokio::sync::Mutex<BTreeSet<String>> =
    tokio::sync::Mutex::const_new(BTreeSet::new());

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRecoveryRequest {
    pub project_id: String,
    pub intent_id: String,
    pub expected_intent_revision: u64,
    pub reason: String,
}

pub async fn integration_recovery(
    State(state): State<App>,
    axum::extract::Path(attempt): axum::extract::Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<IntegrationRecoveryRequest>,
) -> Result<Response, ApiError> {
    if actor.worker || !matches!(actor.actor_id.as_str(), "owner" | "owner-service") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "integration recovery requires Owner authorization",
        ));
    }
    if body.project_id.is_empty()
        || body.expected_intent_revision == 0
        || body.reason.trim().is_empty()
        || body.reason.len() > 2000
        || uuid::Uuid::parse_str(&attempt).is_err()
        || uuid::Uuid::parse_str(&body.intent_id).is_err()
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "exact project/attempt/intent, positive expected intent revision and a nonblank reason of at most 2000 bytes are required",
        ));
    }
    let identity = identity(&headers, &actor)?;
    let operation = forgeflow_planner::sha256(
        format!(
            "{}:integration-recovery:{}",
            identity.actor_id, identity.idempotency_key
        )
        .as_bytes(),
    )[..32]
        .to_owned();
    // The Store command checks expected intent revision and irreversible commit
    // decision together with the operation registration in one transaction.
    let registered = state
        .store
        .authorize_integration_recovery(
            identity,
            &body.project_id,
            &attempt,
            &body.intent_id,
            body.expected_intent_revision,
            &body.reason,
            &operation,
        )
        .await?;
    let current = state
        .store
        .get_document(&body.project_id, "operations", &operation)
        .await?;
    let response_value = current.clone();
    if current.get("status").and_then(Value::as_str) == Some("ACCEPTED") {
        let intent_before: MergeIntent =
            serde_json::from_value(current.get("intent_before").cloned().ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "RECOVERY_BINDING_MISMATCH",
                    "recovery authorization lacks its frozen intent",
                )
            })?)
            .map_err(|error| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "RECOVERY_BINDING_MISMATCH",
                    error.to_string(),
                )
            })?;
        if RUNNING.lock().await.insert(operation.clone()) {
            let state = state.clone();
            let operation = operation.clone();
            let project = body.project_id.clone();
            tokio::spawn(async move {
                let result = run(&state, &operation, &intent_before).await;
                let outcome = match result {
                    Ok(value) => json!({"status":"SUCCEEDED","result":value}),
                    Err(error) => json!({"status":"RECOVERY_REQUIRED","error":error.1}),
                };
                if let Err(error) = state
                    .store
                    .settle_integration_recovery(
                        CommandIdentity {
                            actor_id: "recovery-service".into(),
                            idempotency_key: format!("{operation}:settled"),
                        },
                        &project,
                        &operation,
                        1,
                        outcome,
                    )
                    .await
                {
                    tracing::error!(%error, %operation, "integration recovery operation settlement failed; replay can reconcile the same durable intent");
                }
                RUNNING.lock().await.remove(&operation);
            });
        }
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "data":response_value,"operation_id":operation,"replayed":registered.replayed,
            "source":"postgres"
        })),
    )
        .into_response())
}

struct RecoveryStore {
    state: App,
    delegate: crate::handoff::PoolIntegrationStore,
    authorized: MergeIntent,
}
impl RecoveryStore {
    fn check(&self, intent: &MergeIntent) -> Result<(), String> {
        let authorized = &self.authorized;
        if intent.project_id != authorized.project_id
            || intent.intent_id != authorized.intent_id
            || intent.attempt_id != authorized.attempt_id
            || intent.generation != authorized.generation
            || intent.target_ref != authorized.target_ref
            || intent.expected_sha != authorized.expected_sha
            || intent.candidate_sha != authorized.candidate_sha
            || intent.integrated_sha != authorized.integrated_sha
        {
            return Err("RECOVERY_BINDING_MISMATCH: frozen commit decision changed".into());
        }
        for key in [
            "new_sha",
            "verification",
            "verification_receipt_hash",
            "artifact_root",
        ] {
            if intent.receipt.as_ref().and_then(|value| value.get(key))
                != authorized.receipt.as_ref().and_then(|value| value.get(key))
            {
                return Err("RECOVERY_BINDING_MISMATCH: frozen Git evidence changed".into());
            }
        }
        if !matches!(
            intent.state,
            MergeIntentState::CommitDecided
                | MergeIntentState::RefUpdated
                | MergeIntentState::RecoveryRequired
                | MergeIntentState::Finalized
        ) || intent
            .receipt
            .as_ref()
            .and_then(|value| value.get("commit_decided"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(
                "RECOVERY_NOT_DECIDED: only an irreversible durable commit decision may continue"
                    .into(),
            );
        }
        if intent.revision < authorized.revision {
            return Err("REVISION_CONFLICT: intent predates Owner authorization".into());
        }
        Ok(())
    }
}

#[async_trait]
impl IntegrationStore for RecoveryStore {
    async fn prepare_merge(&self, _: MergeIntent) -> Result<MergeIntent, String> {
        Err("recovery cannot prepare a new integration".into())
    }
    async fn decide_merge(&self, _: &str, _: &str, _: u64) -> Result<MergeIntent, String> {
        Err("recovery cannot create a commit decision".into())
    }
    async fn get_merge_intent(&self, project: &str, intent: &str) -> Result<MergeIntent, String> {
        if project != self.authorized.project_id || intent != self.authorized.intent_id {
            return Err("RECOVERY_BINDING_MISMATCH: recovery scope differs".into());
        }
        let value = self
            .state
            .store
            .get_merge_intent(project, intent)
            .await
            .map_err(|error| error.to_string())?;
        self.check(&value)?;
        // This check runs inside the actual IntegrationService repository lane.
        // A replay after finalization must verify retained disk evidence because
        // the integrator's finalized fast path intentionally performs no writes.
        if value.state == MergeIntentState::Finalized {
            verify_finalized_snapshot(&self.state, &value).await?;
        }
        Ok(value)
    }
    async fn confirm_merge(
        &self,
        project: &str,
        intent: &str,
        sha: &str,
        receipt: Value,
    ) -> Result<MergeIntent, String> {
        if project != self.authorized.project_id
            || intent != self.authorized.intent_id
            || self.authorized.integrated_sha.as_deref() != Some(sha)
        {
            return Err("RECOVERY_BINDING_MISMATCH: confirmation scope differs".into());
        }
        // The existing adapter preserves ACTIVE atomic handoff and only permits
        // ordinary release under the Owner-authorized DRAINING policy.
        self.delegate
            .confirm_merge(project, intent, sha, receipt)
            .await
    }
    async fn pending_merges(
        &self,
        project: &str,
        target: &str,
    ) -> Result<Vec<MergeIntent>, String> {
        self.delegate.pending_merges(project, target).await
    }
    async fn abort_merge(&self, _: &str, _: &str, _: &str) -> Result<MergeIntent, String> {
        Err("recovery cannot abort a durable commit decision".into())
    }
    async fn mark_merge_recovery_required(
        &self,
        project: &str,
        intent: &str,
        reason: &str,
    ) -> Result<MergeIntent, String> {
        if project != self.authorized.project_id || intent != self.authorized.intent_id {
            return Err("RECOVERY_BINDING_MISMATCH: failure scope differs".into());
        }
        self.delegate
            .mark_merge_recovery_required(project, intent, reason)
            .await
    }
}

async fn verify_finalized_snapshot(state: &App, intent: &MergeIntent) -> Result<(), String> {
    let project = state
        .store
        .get_project(&intent.project_id)
        .await
        .map_err(|error| error.to_string())?;
    let repo = FsPath::new(&project.root_path);
    let sha = intent
        .integrated_sha
        .as_deref()
        .ok_or("finalized intent lacks integrated SHA")?;
    let mut value = intent
        .receipt
        .clone()
        .ok_or("finalized intent lacks frozen receipt")?;
    value
        .as_object_mut()
        .ok_or("invalid frozen receipt")?
        .remove("commit_decided");
    value.as_object_mut().unwrap().remove("ref_updated");
    let verification: forgeflow_evidence::VerificationReceipt =
        serde_json::from_value(value["verification"].clone()).map_err(|error| error.to_string())?;
    if value["new_sha"] != sha
        || value["verification_receipt_hash"] != verification.digest()
        || verification.binding.attempt_id != intent.attempt_id
        || verification.binding.generation != intent.generation
        || verification.binding.candidate_sha != intent.candidate_sha
        || verification.binding.integrated_sha.as_deref() != Some(sha)
        || verification.binding.source_hash
            != forgeflow_git::source_hash(repo, sha).map_err(|error| error.to_string())?
    {
        return Err("finalized frozen receipt binding differs".into());
    }
    verification
        .validate(&verification.binding, true)
        .map_err(|error| error.to_string())?;
    let root = PathBuf::from(
        value["artifact_root"]
            .as_str()
            .ok_or("missing frozen artifact root")?,
    )
    .canonicalize()
    .map_err(|error| error.to_string())?;
    if root
        != repo
            .canonicalize()
            .map_err(|error| error.to_string())?
            .join("forgeflow-evidence")
            .join(&intent.intent_id)
    {
        return Err("frozen artifact root escapes controller-only intent snapshot".into());
    }
    verification
        .validate_log(&root)
        .map_err(|error| error.to_string())?;
    let disk: Value = serde_json::from_slice(
        &tokio::fs::read(root.join("forgeflow-verification.json"))
            .await
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if disk != value {
        return Err("frozen verification snapshot bytes differ".into());
    }
    let head =
        forgeflow_git::resolve(repo, &intent.target_ref).map_err(|error| error.to_string())?;
    if !forgeflow_git::is_ancestor(repo, sha, &head).map_err(|error| error.to_string())? {
        return Err("finalized commit is absent from authoritative target history".into());
    }
    let attempt = state
        .store
        .get_attempt(&intent.project_id, &intent.attempt_id)
        .await
        .map_err(|error| error.to_string())?;
    if attempt.state != AttemptState::Succeeded || attempt.generation != intent.generation {
        return Err("finalized attempt identity/state differs".into());
    }
    Ok(())
}

async fn run(state: &App, operation: &str, authorized: &MergeIntent) -> Result<Value, ApiError> {
    let project = state.store.get_project(&authorized.project_id).await?;
    if project.authority_mode != AuthorityMode::Managed {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "RECOVERY_SCOPE_INVALID",
            "integration recovery requires the registered managed repository",
        ));
    }
    let adapter = RecoveryStore {
        state: state.clone(),
        delegate: crate::handoff::PoolIntegrationStore::new(state.clone(), operation),
        authorized: authorized.clone(),
    };
    let result = IntegrationService::default()
        .recover(
            &adapter,
            FsPath::new(&project.root_path),
            &authorized.project_id,
            &authorized.intent_id,
        )
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::CONFLICT,
                "INTEGRATION_RECOVERY_REQUIRED",
                error.to_string(),
            )
        })?;
    let mut value = json!({"integration":result,"original_intent_id":authorized.intent_id,
        "author_reexecuted":false,"model_requests_started":0,"verification_commands_rerun":0,
        "evidence_source":"ORIGINAL_DURABLE_INTEGRATION_SNAPSHOT"});
    if let Some(handoff) = adapter.delegate.handoff_receipt().await {
        value["handoff"] = serde_json::to_value(handoff).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "RECOVERY_RESULT_INVALID",
                error.to_string(),
            )
        })?;
    }
    Ok(value)
}
