//! Authenticated Worker transport for an already issued native model grant.
//! Store consumption precedes all upstream DNS/socket work. Native SDK settlement
//! remains distinct from the trusted transport closure and provider usage record.
use super::*;
use axum::body::Bytes;
use forgeflow_gateway::{ModelRequestPermit, NativeTransportObservation, NativeTransportObserver};
use forgeflow_store::native_model_dispatch::{
    NativeModelDispatchReceipt, NativeModelDispatchRequest, NativeModelTransportObservation,
};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModelQuery {
    project_id: String,
}

fn header(headers: &HeaderMap, name: &str, max: usize) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_owned)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "NATIVE_DISPATCH_INVALID",
                "bounded native grant headers required",
            )
        })
}

struct TransportObserver {
    store: Store,
    receipt: NativeModelDispatchReceipt,
}
#[async_trait::async_trait]
impl NativeTransportObserver for TransportObserver {
    async fn observe(&self, observation: NativeTransportObservation) -> Result<(), String> {
        if observation.request_id != self.receipt.request_id {
            return Err("native transport observation identity differs".into());
        }
        let r = &self.receipt;
        self.store
            .record_native_transport_observation(NativeModelTransportObservation {
                project_id: r.project_id.clone(),
                attempt_id: r.attempt_id.clone(),
                generation: r.generation,
                worker_id: r.worker_id.clone(),
                native_session_id: r.native_session_id.clone(),
                allocation_id: r.allocation_id.clone(),
                request_id: r.request_id.clone(),
                request_grant_id: r.request_grant_id.clone(),
                body_sha256: r.body_sha256.clone(),
                outcome: observation.outcome,
                upstream_status: observation.upstream_status,
                received_bytes: observation.received_bytes,
                usage: observation.usage,
                usage_complete: observation.usage_complete,
            })
            .await
            .map_err(|_| "native transport closure persistence failed".into())
    }
}

pub async fn forward(
    State(s): State<App>,
    Path(attempt): Path<String>,
    Query(query): Query<NativeModelQuery>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !actor.worker || actor.worker_id.is_none() || actor.project_id.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_AUTH_REQUIRED",
            "native model transport requires a scoped Worker credential",
        ));
    }
    if s.auth.is_shutting_down() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVER_DRAINING",
            "native model dispatch stops during drain",
        ));
    }
    let worker = header(&headers, "x-forgeflow-worker-id", 256)?;
    let project = header(&headers, "x-forgeflow-project-id", 256)?;
    s.auth
        .worker_scope(&actor, Some(&worker), Some(&project))
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", e))?;
    if query.project_id != project {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_SCOPE_DENIED",
            "project query and native transport header differ",
        ));
    }
    let actual = crate::workers::authorized_attempt(&s, &actor, &project, &attempt).await?;
    if actual.worker_id != worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_SCOPE_DENIED",
            "native transport Worker differs from assigned attempt",
        ));
    }
    let gateway = s.native_gateway.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NATIVE_GATEWAY_REQUIRED",
            "approved native model gateway is not configured",
        )
    })?;
    if body.len() > 8 * 1024 * 1024 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "NATIVE_DISPATCH_INVALID",
            "native model body exceeds transport budget",
        ));
    }
    let payload: Value =
        forgeflow_planner::strict_json(std::str::from_utf8(&body).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "NATIVE_DISPATCH_INVALID",
                "native model body must be UTF8 JSON",
            )
        })?)
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "NATIVE_DISPATCH_INVALID",
                "native model body must be strict JSON",
            )
        })?;
    let model = payload
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty() && m.len() <= 256 && m.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "NATIVE_DISPATCH_INVALID",
                "bounded model identity required",
            )
        })?;
    let cap = payload
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "NATIVE_DISPATCH_INVALID",
                "positive integer max_tokens required",
            )
        })?;
    if payload.get("stream") != Some(&Value::Bool(true))
        || gateway.native_model.as_deref() != Some(model)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "NATIVE_ROUTE_INVALID",
            "native stream/model differs from configured gateway",
        ));
    }
    let hash = format!("{:x}", Sha256::digest(&body));
    if header(&headers, "x-forgeflow-body-sha256", 64)? != hash {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "NATIVE_DISPATCH_INVALID",
            "native transport body hash differs",
        ));
    }
    let generation = header(&headers, "x-forgeflow-generation", 32)?
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "NATIVE_DISPATCH_INVALID",
                "positive generation required",
            )
        })?;
    let request = NativeModelDispatchRequest {
        project_id: project,
        attempt_id: attempt,
        generation,
        worker_id: worker,
        native_session_id: header(&headers, "x-forgeflow-native-session-id", 256)?,
        allocation_id: header(&headers, "x-forgeflow-native-allocation-id", 256)?,
        request_id: header(&headers, "x-forgeflow-native-request-id", 256)?,
        request_grant_id: header(&headers, "x-forgeflow-native-grant-id", 256)?,
        provider: header(&headers, "x-forgeflow-native-provider", 256)?,
        model: model.into(),
        max_output_tokens: cap,
        route_id: gateway.route_id.clone(),
        body_sha256: hash,
    };
    let mut forwarded = HeaderMap::new();
    for name in [
        "anthropic-version",
        "anthropic-beta",
        "accept",
        "anthropic-dangerous-direct-browser-access",
    ] {
        if let Some(value) = headers.get(name) {
            if value.as_bytes().len() > 4096 {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "NATIVE_DISPATCH_INVALID",
                    "provider header exceeds transport budget",
                ));
            }
            forwarded.insert(name, value.clone());
        }
    }
    // Only this transaction creates connection rights; replay/lease/lineage and
    // immutable native provider/model/cap/route checks are canonical Store rules.
    let receipt = s
        .store
        .consume_native_dispatch(request)
        .await
        .map_err(|e| match e {
            forgeflow_store::StoreError::Domain(domain)
                if domain.code == "NATIVE_DISPATCH_ALREADY_CONSUMED" =>
            {
                ApiError(StatusCode::CONFLICT, domain)
            }
            other => other.into(),
        })?;
    let permit = ModelRequestPermit {
        request_id: receipt.request_id.clone(),
        attempt_id: receipt.attempt_id.clone(),
        route_id: receipt.route_id.clone(),
        model: receipt.model.clone(),
        generation: receipt.generation,
    };
    let observer = Arc::new(TransportObserver {
        store: s.store.clone(),
        receipt,
    });
    Ok(forgeflow_gateway::forward_native(gateway, forwarded, body, permit, observer).await)
}
