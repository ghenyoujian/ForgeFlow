//! A single frozen wire protocol: Anthropic Messages streaming reverse proxy.
//! Durable admission is supplied by the authority; absence of admission fails closed.
mod postgres;
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use futures::StreamExt;
pub use postgres::{GatewayBudgetLimits, PgRequestAuthority};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

/// Opt-in, server-private measurements of the exact wire. These receipts are
/// observations, never model admission/settlement or business acceptance.
struct WireReceipt {
    directory: std::path::PathBuf,
    request_id: String,
    body_sha256: String,
    upstream_request_ids: std::collections::BTreeMap<String, String>,
}
impl WireReceipt {
    fn capture(
        permit: &ModelRequestPermit,
        headers: &HeaderMap,
        body: &[u8],
    ) -> std::io::Result<Option<Self>> {
        let Some(directory) = std::env::var_os("FORGEFLOW_MODEL_WIRE_RECEIPTS_DIR") else {
            return Ok(None);
        };
        Self::capture_in(std::path::PathBuf::from(directory), permit, headers, body).map(Some)
    }
    fn capture_in(
        directory: std::path::PathBuf,
        permit: &ModelRequestPermit,
        headers: &HeaderMap,
        body: &[u8],
    ) -> std::io::Result<Self> {
        if !directory.is_absolute()
            || directory
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || permit.request_id.is_empty()
            || permit.request_id.len() > 256
            || !permit
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(std::io::Error::other(
                "invalid private wire receipt location or identity",
            ));
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "private wire receipt directory required",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(std::io::Error::other(
                    "wire receipt directory must be private",
                ));
            }
        }
        #[cfg(not(unix))]
        return Err(std::io::Error::other(
            "private wire receipts require a Unix permission boundary",
        ));
        let payload: Value = serde_json::from_slice(body)
            .map_err(|_| std::io::Error::other("invalid wire receipt JSON"))?;
        let receipt = Self {
            directory,
            request_id: permit.request_id.clone(),
            body_sha256: format!("{:x}", Sha256::digest(body)),
            upstream_request_ids: std::collections::BTreeMap::new(),
        };
        let known = |value: Option<&Value>, allowed: &[&str]| {
            value
                .and_then(Value::as_str)
                .map(|s| {
                    if allowed.contains(&s) {
                        s
                    } else {
                        "UNRECOGNIZED"
                    }
                })
                .map(str::to_owned)
        };
        // Every copied value is an authority identity, count, hash, or a fixed
        // control enum. Header values, messages, tools and thinking text never
        // enter this measurement, including provider error bodies.
        let header_names = [
            "anthropic-version",
            "anthropic-beta",
            "accept",
            "anthropic-dangerous-direct-browser-access",
        ]
        .into_iter()
        .filter(|name| headers.contains_key(*name))
        .collect::<Vec<_>>();
        let value = serde_json::json!({
            "schema_version":"forgeflow.model-wire-request.v1",
            "request_id":permit.request_id,"attempt_id":permit.attempt_id,
            "generation":permit.generation,"route_id":permit.route_id,"model":permit.model,
            "captured_at":chrono::Utc::now().to_rfc3339(),
            "body_sha256":receipt.body_sha256,"body_bytes":body.len(),
            "max_tokens":payload.get("max_tokens").and_then(Value::as_u64),
            "stream":payload.get("stream").and_then(Value::as_bool),
            "thinking_type":known(payload.pointer("/thinking/type"), &["enabled","disabled","adaptive","between_tools"]),
            "thinking_budget_tokens":payload.pointer("/thinking/budget_tokens").and_then(Value::as_u64),
            "output_effort":known(payload.pointer("/output_config/effort"), &["none","minimal","low","medium","high","xhigh","max","ultra"]),
            "reasoning_effort":known(payload.get("reasoning_effort"), &["none","minimal","low","medium","high","xhigh","max","ultra"]),
            "message_count":payload.get("messages").and_then(Value::as_array).map(Vec::len),
            "tool_count":payload.get("tools").and_then(Value::as_array).map(Vec::len),
            "header_names":header_names
        });
        receipt.write("request", &value)?;
        Ok(receipt)
    }
    fn write(&self, kind: &str, value: &Value) -> std::io::Result<()> {
        use std::io::Write;
        let path = self
            .directory
            .join(format!("{}.{}.json", self.request_id, kind));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // Exclusive creation rejects an existing file or symlink; immutable
        // original receipts are never overwritten by retries/recovery.
        let mut file = options.open(path)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()
    }
    fn response(&self, settlement: &RequestSettlement, meter: &UsageMeter) -> std::io::Result<()> {
        let usage = settlement
            .usage
            .as_ref()
            .and_then(Value::as_object)
            .map(|values| {
                [
                    "input_tokens",
                    "output_tokens",
                    "cache_read_input_tokens",
                    "cache_creation_input_tokens",
                    "reasoning_tokens",
                    "total_tokens",
                ]
                .into_iter()
                .filter_map(|name| {
                    values
                        .get(name)
                        .and_then(Value::as_u64)
                        .map(|value| (name.to_owned(), Value::from(value)))
                })
                .collect::<serde_json::Map<String, Value>>()
            });
        self.write("response", &serde_json::json!({
            "schema_version":"forgeflow.model-wire-response.v1",
            "request_id":self.request_id,"body_sha256":self.body_sha256,
            "upstream_request_ids":self.upstream_request_ids,
            "response_body_sha256":format!("{:x}", meter.response_hasher.clone().finalize()),
            "captured_at":chrono::Utc::now().to_rfc3339(),
            "outcome":settlement.outcome,"upstream_status":settlement.upstream_status,
            "received_bytes":settlement.received_bytes,"usage":usage,
            "usage_completeness":settlement.usage_completeness,
            "message_stop":meter.message_stop,"stop_reason":meter.stop_reason,
            "thinking_utf8_bytes":meter.thinking_bytes,"text_utf8_bytes":meter.text_bytes,
            "tool_use_blocks":meter.tool_use_blocks,"tool_input_json_utf8_bytes":meter.tool_input_bytes,
            "provider_error_events":meter.provider_error_events,"meter_incomplete":meter.incomplete
        }))
    }
    fn observe_upstream_request_ids(&mut self, headers: &HeaderMap) {
        // Correlation identifiers only. No generic header map, authentication,
        // provider bodies or error text enter the private receipt.
        for name in [
            "request-id",
            "x-request-id",
            "x-oneapi-request-id",
            "x-newapi-request-id",
        ] {
            if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()).filter(|v| {
                !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| b.is_ascii_graphic())
            }) {
                self.upstream_request_ids.insert(name.into(), value.into());
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRequestPermit {
    pub request_id: String,
    pub attempt_id: String,
    pub route_id: String,
    pub model: String,
    pub generation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSettlement {
    pub request_id: String,
    pub outcome: String,
    pub upstream_status: Option<u16>,
    pub received_bytes: u64,
    /// Provider usage is a measurement; missing usage never means zero cost.
    pub usage: Option<Value>,
    pub usage_completeness: String,
}

#[derive(Debug, Clone)]
pub struct AdmissionDenied {
    pub code: String,
    pub status: StatusCode,
}

#[async_trait]
pub trait RequestAuthority: Send + Sync {
    /// Must atomically validate scope token, active lease/generation, frozen route/model,
    /// request count/window/project/global budget, and inflight reservation before returning.
    async fn admit(
        &self,
        scoped_token: &str,
        route_id: &str,
        model: &str,
    ) -> Result<ModelRequestPermit, AdmissionDenied>;
    /// Must be idempotent by request_id. Count remains charged after uncertain upstream results.
    async fn settle(&self, settlement: RequestSettlement) -> Result<(), String>;
}

/// Transport closure for an already issued native grant. This is not model
/// admission, usage settlement or permission to release native allocations.
#[derive(Debug, Clone)]
pub struct NativeTransportObservation {
    pub request_id: String,
    pub outcome: String,
    pub upstream_status: Option<u16>,
    pub received_bytes: u64,
    pub usage: Option<Value>,
    pub usage_complete: bool,
}
#[async_trait]
pub trait NativeTransportObserver: Send + Sync {
    async fn observe(&self, observation: NativeTransportObservation) -> Result<(), String>;
}

#[derive(Clone)]
pub struct GatewayState {
    pub authority: Arc<dyn RequestAuthority>,
    pub route_id: String,
    /// An exact frozen /v1/messages URL; redirects are prohibited.
    pub upstream_messages_url: String,
    /// Present only when the server explicitly freezes this model for native relay.
    pub native_model: Option<String>,
    /// Injected server-side by a secret resolver. Never inherited by the Worker.
    upstream_key: Arc<String>,
    client: reqwest::Client,
}

impl GatewayState {
    pub fn new(
        authority: Arc<dyn RequestAuthority>,
        route_id: String,
        upstream_messages_url: String,
        upstream_key: String,
        timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(timeout)
            .build()?;
        Ok(Self {
            authority,
            route_id,
            upstream_messages_url,
            native_model: None,
            upstream_key: Arc::new(upstream_key),
            client,
        })
    }
    pub fn with_native_model(mut self, model: String) -> Self {
        self.native_model = Some(model);
        self
    }
}

pub fn router(state: GatewayState) -> Router {
    Router::new()
        .route("/v1/messages", post(messages))
        .with_state(state)
}

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({"error":{"type":code,"message":code}})),
    )
        .into_response()
}

/// RAII keeps the inflight request reserved while bytes stream. Drop on client cancellation
/// asynchronously records a conservative settlement; authority recovery reconciles interrupted DB writes.
struct SettlementGuard {
    authority: Option<Arc<dyn RequestAuthority>>,
    native_observer: Option<Arc<dyn NativeTransportObserver>>,
    settlement: Option<RequestSettlement>,
    meter: UsageMeter,
    wire_receipt: Option<WireReceipt>,
}
impl SettlementGuard {
    async fn record(&self, settlement: RequestSettlement) -> Result<(), String> {
        if let Some(receipt) = &self.wire_receipt {
            receipt
                .response(&settlement, &self.meter)
                .map_err(|_| "private wire response receipt persistence failed".to_owned())?;
        }
        if let Some(authority) = &self.authority {
            authority.settle(settlement).await
        } else if let Some(observer) = &self.native_observer {
            observer.observe(native_observation(settlement)).await
        } else {
            Err("missing transport observation authority".into())
        }
    }
}
fn native_observation(settlement: RequestSettlement) -> NativeTransportObservation {
    let mut usage = serde_json::Map::new();
    if let Some(values) = settlement.usage.as_ref().and_then(Value::as_object) {
        for (provider, canonical) in [
            ("input_tokens", "inputTokens"),
            ("output_tokens", "outputTokens"),
            ("cache_read_input_tokens", "cacheReadTokens"),
            ("cache_creation_input_tokens", "cacheWriteTokens"),
            ("reasoning_tokens", "reasoningTokens"),
            ("total_tokens", "totalTokens"),
        ] {
            if let Some(value) = values.get(provider).filter(|v| v.as_u64().is_some()) {
                usage.insert(canonical.into(), value.clone());
            }
        }
    }
    let complete = settlement.outcome == "RESPONSE_BODY_COMPLETED"
        && settlement.usage_completeness == "PROVIDER_REPORTED_STREAM_COMPLETE"
        && usage.contains_key("inputTokens")
        && usage.contains_key("outputTokens");
    NativeTransportObservation {
        request_id: settlement.request_id,
        outcome: if settlement.outcome == "RESPONSE_BODY_COMPLETED" {
            "RESPONSE_BODY_COMPLETED"
        } else {
            "RESPONSE_INTERRUPTED"
        }
        .into(),
        upstream_status: settlement.upstream_status,
        received_bytes: settlement.received_bytes,
        usage: if usage.is_empty() {
            None
        } else {
            Some(Value::Object(usage))
        },
        usage_complete: complete,
    }
}

#[derive(Default)]
struct UsageMeter {
    line: Vec<u8>,
    usage: serde_json::Map<String, Value>,
    message_stop: bool,
    overflow: bool,
    incomplete: bool,
    stop_reason: Option<String>,
    thinking_bytes: u64,
    text_bytes: u64,
    tool_use_blocks: u64,
    tool_input_bytes: u64,
    provider_error_events: u64,
    other_content_blocks: u64,
    response_hasher: Sha256,
}
impl UsageMeter {
    fn observe(&mut self, bytes: &[u8]) {
        self.response_hasher.update(bytes);
        for byte in bytes {
            if *byte == b'\n' {
                if !self.overflow {
                    let content = self.line.strip_prefix(b"data: ").unwrap_or(&self.line);
                    if let Ok(event) = serde_json::from_slice::<Value>(content) {
                        if let Some(reason) = event
                            .pointer("/delta/stop_reason")
                            .or_else(|| event.pointer("/message/stop_reason"))
                            .and_then(Value::as_str)
                        {
                            self.stop_reason = Some(
                                if [
                                    "end_turn",
                                    "max_tokens",
                                    "stop_sequence",
                                    "tool_use",
                                    "pause_turn",
                                    "refusal",
                                    "model_context_window_exceeded",
                                ]
                                .contains(&reason)
                                {
                                    reason
                                } else {
                                    "UNRECOGNIZED"
                                }
                                .to_owned(),
                            );
                        }
                        if event.get("type").and_then(Value::as_str) == Some("content_block_start")
                        {
                            let block_type =
                                event.pointer("/content_block/type").and_then(Value::as_str);
                            self.tool_use_blocks += u64::from(matches!(
                                block_type,
                                Some("tool_use" | "server_tool_use")
                            ));
                            self.other_content_blocks += u64::from(!matches!(
                                block_type,
                                Some("text" | "thinking" | "tool_use" | "server_tool_use")
                            ));
                            if let Some(value) = event
                                .pointer("/content_block/thinking")
                                .and_then(Value::as_str)
                            {
                                self.thinking_bytes =
                                    self.thinking_bytes.saturating_add(value.len() as u64);
                            }
                            if let Some(value) =
                                event.pointer("/content_block/text").and_then(Value::as_str)
                            {
                                self.text_bytes =
                                    self.text_bytes.saturating_add(value.len() as u64);
                            }
                        }
                        if event
                            .pointer("/message/content")
                            .and_then(Value::as_array)
                            .is_some_and(|blocks| !blocks.is_empty())
                        {
                            // A compatible provider may place initial content in
                            // message_start. Preserve a conservative nonempty
                            // signal rather than misclassifying it as empty.
                            self.other_content_blocks += 1;
                        }
                        if event.get("type").and_then(Value::as_str) == Some("error") {
                            self.provider_error_events += 1;
                        }
                        for (path, count) in [
                            ("/delta/thinking", &mut self.thinking_bytes),
                            ("/delta/text", &mut self.text_bytes),
                            ("/delta/partial_json", &mut self.tool_input_bytes),
                        ] {
                            if let Some(value) = event.pointer(path).and_then(Value::as_str) {
                                *count = count.saturating_add(value.len() as u64);
                            }
                        }
                        if let Some(values) = event
                            .pointer("/message/usage")
                            .or_else(|| event.get("usage"))
                            .and_then(Value::as_object)
                        {
                            self.usage.extend(values.clone());
                        }
                        self.message_stop |=
                            event.get("type").and_then(Value::as_str) == Some("message_stop");
                    }
                }
                self.line.clear();
                self.overflow = false;
            } else if self.line.len() < 65536 {
                self.line.push(*byte);
            } else {
                self.overflow = true;
                self.incomplete = true;
            }
        }
    }
    fn apply(&self, settlement: &mut RequestSettlement) {
        if !self.usage.is_empty() {
            settlement.usage = Some(Value::Object(self.usage.clone()));
        }
        settlement.usage_completeness = if settlement.outcome != "PROVIDER_EMPTY_RESPONSE"
            && self.message_stop
            && !self.usage.is_empty()
            && !self.incomplete
        {
            "PROVIDER_REPORTED_STREAM_COMPLETE"
        } else {
            "UNKNOWN_OR_PARTIAL"
        }
        .into();
    }
    /// Called only after the actual upstream body reaches normal EOF. A
    /// provider's zero counters remain recorded as reported measurements; an
    /// empty reply does not establish complete usage or authorize release.
    fn completed_outcome(&self, native: bool) -> &'static str {
        if native && !self.message_stop {
            "PROVIDER_FINISH_NOT_OBSERVED"
        } else if self.message_stop
            && !self.incomplete
            && self.provider_error_events == 0
            && self.text_bytes == 0
            && self.thinking_bytes == 0
            && self.tool_use_blocks == 0
            && self.tool_input_bytes == 0
            && self.other_content_blocks == 0
            && self.usage.get("input_tokens").and_then(Value::as_u64) == Some(0)
            && self.usage.get("output_tokens").and_then(Value::as_u64) == Some(0)
            && self.usage.values().all(|value| value.as_u64() == Some(0))
        {
            "PROVIDER_EMPTY_RESPONSE"
        } else {
            "RESPONSE_BODY_COMPLETED"
        }
    }
}
impl Drop for SettlementGuard {
    fn drop(&mut self) {
        if let Some(mut settlement) = self.settlement.take() {
            if settlement.outcome == "STREAMING" {
                settlement.outcome = "CLIENT_DISCONNECTED_OR_STREAM_DROPPED".into();
            } else if settlement.outcome == "CONNECTING" {
                settlement.outcome = "CLIENT_DISCONNECTED_DURING_CONNECT".into();
            }
            self.meter.apply(&mut settlement);
            let authority = self.authority.clone();
            let observer = self.native_observer.clone();
            let wire_ok = self
                .wire_receipt
                .as_ref()
                .map(|receipt| receipt.response(&settlement, &self.meter))
                .transpose()
                .is_ok();
            tokio::spawn(async move {
                if !wire_ok {
                    // Missing audit persistence never fabricates zero usage or
                    // a transport close. The existing authority recovery owns
                    // this conservative unresolved request.
                    return;
                }
                if let Some(authority) = authority {
                    let _ = authority.settle(settlement).await;
                } else if let Some(observer) = observer {
                    // A failed/cancelled durability write leaves the grant active;
                    // native authority must never infer closure from missing evidence.
                    let _ = observer.observe(native_observation(settlement)).await;
                }
            });
        }
    }
}

async fn messages(State(state): State<GatewayState>, headers: HeaderMap, body: Bytes) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()));
    let Some(token) = token.filter(|v| !v.is_empty()) else {
        return error(StatusCode::UNAUTHORIZED, "MISSING_SCOPE_TOKEN");
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return error(StatusCode::BAD_REQUEST, "INVALID_MODEL_REQUEST"),
    };
    let Some(model) = payload.get("model").and_then(Value::as_str) else {
        return error(StatusCode::BAD_REQUEST, "MISSING_MODEL");
    };
    // No sockets or DNS work occur until authority has granted the request permit.
    let permit = match state.authority.admit(token, &state.route_id, model).await {
        Ok(p) => p,
        Err(e) => return error(e.status, &e.code),
    };
    if permit.route_id != state.route_id || permit.model != model {
        let _ = state
            .authority
            .settle(RequestSettlement {
                request_id: permit.request_id,
                outcome: "AUTHORITY_CONTRACT_MISMATCH".into(),
                upstream_status: None,
                received_bytes: 0,
                usage: None,
                usage_completeness: "UNKNOWN".into(),
            })
            .await;
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AUTHORITY_CONTRACT_MISMATCH",
        );
    }
    let wire_receipt = match WireReceipt::capture(&permit, &headers, &body) {
        Ok(receipt) => receipt,
        Err(_) => {
            let _ = state
                .authority
                .settle(RequestSettlement {
                    request_id: permit.request_id,
                    outcome: "WIRE_RECEIPT_PREPARATION_FAILED".into(),
                    upstream_status: None,
                    received_bytes: 0,
                    usage: None,
                    usage_completeness: "UNKNOWN".into(),
                })
                .await;
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "WIRE_RECEIPT_PREPARATION_FAILED",
            );
        }
    };
    let guard = SettlementGuard {
        authority: Some(state.authority.clone()),
        native_observer: None,
        meter: UsageMeter::default(),
        wire_receipt,
        settlement: Some(RequestSettlement {
            request_id: permit.request_id,
            outcome: "CONNECTING".into(),
            upstream_status: None,
            received_bytes: 0,
            usage: None,
            usage_completeness: "UNKNOWN".into(),
        }),
    };
    forward(state, headers, body, guard).await
}

/// Called only after canonical native dispatch-once authority has consumed the
/// exact grant. Never calls RequestAuthority::admit or RequestAuthority::settle.
pub async fn forward_native(
    state: GatewayState,
    headers: HeaderMap,
    body: Bytes,
    permit: ModelRequestPermit,
    observer: Arc<dyn NativeTransportObserver>,
) -> Response {
    if permit.route_id != state.route_id
        || state.native_model.as_deref() != Some(permit.model.as_str())
    {
        let _ = observer
            .observe(NativeTransportObservation {
                request_id: permit.request_id,
                outcome: "RESPONSE_INTERRUPTED".into(),
                upstream_status: None,
                received_bytes: 0,
                usage: None,
                usage_complete: false,
            })
            .await;
        return error(StatusCode::CONFLICT, "NATIVE_ROUTE_INVALID");
    }
    let wire_receipt = match WireReceipt::capture(&permit, &headers, &body) {
        Ok(receipt) => receipt,
        Err(_) => {
            let _ = observer
                .observe(NativeTransportObservation {
                    request_id: permit.request_id,
                    outcome: "RESPONSE_INTERRUPTED".into(),
                    upstream_status: None,
                    received_bytes: 0,
                    usage: None,
                    usage_complete: false,
                })
                .await;
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "WIRE_RECEIPT_PREPARATION_FAILED",
            );
        }
    };
    let guard = SettlementGuard {
        authority: None,
        native_observer: Some(observer),
        meter: UsageMeter::default(),
        wire_receipt,
        settlement: Some(RequestSettlement {
            request_id: permit.request_id,
            outcome: "CONNECTING".into(),
            upstream_status: None,
            received_bytes: 0,
            usage: None,
            usage_completeness: "UNKNOWN".into(),
        }),
    };
    forward(state, headers, body, guard).await
}

async fn forward(
    state: GatewayState,
    headers: HeaderMap,
    body: Bytes,
    mut guard: SettlementGuard,
) -> Response {
    let mut upstream_request = state
        .client
        .post(&state.upstream_messages_url)
        .header("x-api-key", state.upstream_key.as_str())
        .header("content-type", "application/json")
        .body(body);
    for name in [
        "anthropic-version",
        "anthropic-beta",
        "accept",
        "anthropic-dangerous-direct-browser-access",
    ] {
        if let Some(value) = headers.get(name) {
            upstream_request = upstream_request.header(name, value);
        }
    }
    let upstream = match upstream_request.send().await {
        Ok(r) => r,
        Err(_) => {
            guard.settlement.as_mut().unwrap().outcome = "UPSTREAM_CONNECTION_FAILED".into();
            return error(StatusCode::BAD_GATEWAY, "UPSTREAM_CONNECTION_FAILED");
        }
    };
    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    if let Some(receipt) = &mut guard.wire_receipt {
        receipt.observe_upstream_request_ids(&upstream_headers);
    }
    guard.settlement.as_mut().unwrap().upstream_status = Some(status.as_u16());
    guard.settlement.as_mut().unwrap().outcome = "STREAMING".into();
    let upstream_stream = upstream.bytes_stream();
    let stream = futures::stream::unfold(
        (Some(Box::pin(upstream_stream)), guard),
        |(mut stream, mut guard)| async move {
            if guard.settlement.is_none() {
                return None;
            }
            let Some(mut upstream) = stream.take() else {
                return None;
            };
            match upstream.next().await {
                Some(Ok(bytes)) => {
                    guard.settlement.as_mut().unwrap().received_bytes += bytes.len() as u64;
                    if guard.settlement.as_ref().unwrap().received_bytes > 64 * 1024 * 1024 {
                        drop(upstream);
                        let mut settlement = guard.settlement.take().unwrap();
                        settlement.outcome = "RESPONSE_LIMIT_EXCEEDED".into();
                        let _ = guard.record(settlement).await;
                        return Some((
                            Err(std::io::Error::other(
                                "upstream response exceeds transport budget",
                            )),
                            (None, guard),
                        ));
                    }
                    guard.meter.observe(&bytes);
                    Some((Ok::<_, std::io::Error>(bytes), (Some(upstream), guard)))
                }
                Some(Err(_)) => {
                    drop(upstream);
                    let mut settlement = guard.settlement.take().unwrap();
                    settlement.outcome = "UPSTREAM_STREAM_FAILED".into();
                    guard.meter.apply(&mut settlement);
                    let _ = guard.record(settlement).await;
                    Some((
                        Err(std::io::Error::other("upstream response stream failed")),
                        (None, guard),
                    ))
                }
                None => {
                    drop(upstream);
                    let mut settlement = guard.settlement.take().unwrap();
                    if settlement.outcome == "STREAMING" {
                        settlement.outcome = guard
                            .meter
                            .completed_outcome(guard.native_observer.is_some())
                            .into();
                    }
                    guard.meter.apply(&mut settlement);
                    if guard.record(settlement).await.is_err() {
                        return Some((
                            Err(std::io::Error::other(
                                "request settlement persistence failed",
                            )),
                            (None, guard),
                        ));
                    }
                    None
                }
            }
        },
    );
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    for name in [
        "content-type",
        "retry-after",
        "request-id",
        "x-request-id",
        "anthropic-ratelimit-requests-remaining",
        "anthropic-ratelimit-requests-reset",
    ] {
        if let Some(value) = upstream_headers.get(name) {
            response.headers_mut().insert(name, value.clone());
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    struct Denied(AtomicUsize);
    #[async_trait]
    impl RequestAuthority for Denied {
        async fn admit(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<ModelRequestPermit, AdmissionDenied> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AdmissionDenied {
                code: "WAITING_MODEL_BUDGET".into(),
                status: StatusCode::TOO_MANY_REQUESTS,
            })
        }
        async fn settle(&self, _: RequestSettlement) -> Result<(), String> {
            panic!("no permit must not settle")
        }
    }
    #[tokio::test]
    async fn denied_request_never_connects_upstream() {
        let authority = Arc::new(Denied(AtomicUsize::new(0)));
        let state = GatewayState::new(
            authority.clone(),
            "route".into(),
            "http://127.0.0.1:1/v1/messages".into(),
            "server-only".into(),
            Duration::from_secs(1),
        )
        .unwrap();
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("authorization", "Bearer scope")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"model":"frozen","messages":[]}"#))
            .unwrap();
        assert_eq!(
            router(state).oneshot(request).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(authority.0.load(Ordering::SeqCst), 1);
    }

    #[derive(Default)]
    struct Admitted(tokio::sync::Mutex<Vec<RequestSettlement>>);
    #[async_trait]
    impl RequestAuthority for Admitted {
        async fn admit(
            &self,
            token: &str,
            route: &str,
            model: &str,
        ) -> Result<ModelRequestPermit, AdmissionDenied> {
            assert_eq!(token, "attempt-scoped");
            Ok(ModelRequestPermit {
                request_id: "request-1".into(),
                attempt_id: "attempt-1".into(),
                route_id: route.into(),
                model: model.into(),
                generation: 3,
            })
        }
        async fn settle(&self, settlement: RequestSettlement) -> Result<(), String> {
            self.0.lock().await.push(settlement);
            Ok(())
        }
    }
    #[tokio::test]
    async fn actual_stream_transfers_bytes_and_settles_provider_usage() {
        async fn upstream(headers: HeaderMap, body: Bytes) -> Response {
            assert_eq!(headers["x-api-key"], "upstream-secret");
            assert!(headers.get("authorization").is_none());
            assert_eq!(headers["anthropic-version"], "2023-06-01");
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["model"],
                "frozen"
            );
            ([("content-type","text/event-stream")],"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7}}}\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\ndata: {\"type\":\"message_stop\"}\n\n").into_response()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/messages", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/v1/messages", post(upstream)),
            )
            .await
            .unwrap();
        });
        let authority = Arc::new(Admitted::default());
        let state = GatewayState::new(
            authority.clone(),
            "route".into(),
            url,
            "upstream-secret".into(),
            Duration::from_secs(5),
        )
        .unwrap();
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("x-api-key", "attempt-scoped")
            .header("anthropic-version", "2023-06-01")
            .body(Body::from(
                r#"{"model":"frozen","stream":true,"messages":[]}"#,
            ))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("message_stop"));
        let receipts = authority.0.lock().await;
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, "RESPONSE_BODY_COMPLETED");
        assert_eq!(receipts[0].usage.as_ref().unwrap()["input_tokens"], 7);
        assert_eq!(receipts[0].usage.as_ref().unwrap()["output_tokens"], 3);
        server.abort();
    }

    #[test]
    fn usage_meter_handles_network_chunk_boundaries() {
        let mut meter = UsageMeter::default();
        meter.observe(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_");
        meter.observe(b"tokens\":4}}\n\ndata: {\"type\":\"message_stop\"}\n");
        assert_eq!(meter.usage["output_tokens"], 4);
        assert!(meter.message_stop);
    }

    #[test]
    fn completed_empty_provider_reply_keeps_usage_unknown() {
        let bytes = b"data: {\"type\":\"message_start\",\"message\":{\"content\":[],\"usage\":{\"input_tokens\":0,\"cache_read_input_tokens\":0}}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\ndata: {\"type\":\"message_stop\"}\n\n";
        let mut meter = UsageMeter::default();
        for chunk in bytes.chunks(7) {
            meter.observe(chunk);
        }
        let mut settlement = RequestSettlement {
            request_id: "empty-provider-1".into(),
            outcome: meter.completed_outcome(true).into(),
            upstream_status: Some(200),
            received_bytes: bytes.len() as u64,
            usage: None,
            usage_completeness: "UNKNOWN".into(),
        };
        assert_eq!(settlement.outcome, "PROVIDER_EMPTY_RESPONSE");
        meter.apply(&mut settlement);
        assert_eq!(settlement.usage_completeness, "UNKNOWN_OR_PARTIAL");
        assert_eq!(settlement.usage.as_ref().unwrap()["input_tokens"], 0);
        let observation = native_observation(settlement);
        // Existing Store transport vocabulary remains unchanged. This is not
        // a business success, zero-cost proof, or allocation release receipt.
        assert_eq!(observation.outcome, "RESPONSE_INTERRUPTED");
        assert!(!observation.usage_complete);
        meter
            .usage
            .insert("cache_read_input_tokens".into(), Value::from(1));
        assert_eq!(meter.completed_outcome(true), "RESPONSE_BODY_COMPLETED");
        meter
            .usage
            .insert("cache_read_input_tokens".into(), Value::from(0));
        meter.tool_use_blocks = 1;
        assert_eq!(meter.completed_outcome(true), "RESPONSE_BODY_COMPLETED");
        meter.tool_use_blocks = 0;
        meter.message_stop = false;
        assert_eq!(
            meter.completed_outcome(true),
            "PROVIDER_FINISH_NOT_OBSERVED"
        );
    }

    #[test]
    #[cfg(unix)]
    fn private_wire_receipt_measures_controls_and_stream_without_content() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("forgeflow-wire-receipt-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let permit = ModelRequestPermit {
            request_id: "receipt-1".into(),
            attempt_id: "attempt-1".into(),
            route_id: "newapi/glm-5.3".into(),
            model: "glm-5.3".into(),
            generation: 1,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "private-key".parse().unwrap());
        headers.insert("anthropic-version", "2023-06-01".parse().unwrap());
        let body = br#"{"model":"glm-5.3","stream":true,"max_tokens":131072,"thinking":{"type":"enabled"},"output_config":{"effort":"max"},"messages":[{"role":"user","content":"private-prompt"}]}"#;
        let mut receipt =
            WireReceipt::capture_in(directory.clone(), &permit, &headers, body).unwrap();
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            "x-oneapi-request-id",
            "20261011-upstream-id".parse().unwrap(),
        );
        upstream_headers.insert("authorization", "private-key".parse().unwrap());
        receipt.observe_upstream_request_ids(&upstream_headers);
        let request_path = directory.join("receipt-1.request.json");
        let request = std::fs::read_to_string(&request_path).unwrap();
        assert!(!request.contains("private-key"));
        assert!(!request.contains("private-prompt"));
        let request: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(request["thinking_type"], "enabled");
        assert_eq!(request["output_effort"], "max");
        assert_eq!(request["max_tokens"], 131072);
        assert_eq!(
            std::fs::metadata(request_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Retry cannot overwrite the immutable original receipt.
        assert!(WireReceipt::capture_in(directory.clone(), &permit, &headers, body).is_err());
        let mut meter = UsageMeter::default();
        let stream = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":9,\"unsafe_provider_field\":\"private-key\"}}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"thinking\":\"private-thinking\"}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"α\"}}\n\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"input\":{\"secret\":\"private-key\"}}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"partial_json\":\"{\\\"x\\\":1}\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{\"output_tokens\":4}}\n\ndata: {\"type\":\"message_stop\"}\n\n";
        for chunk in stream.as_bytes().chunks(7) {
            meter.observe(chunk);
        }
        let mut settlement = RequestSettlement {
            request_id: "receipt-1".into(),
            outcome: "RESPONSE_BODY_COMPLETED".into(),
            upstream_status: Some(200),
            received_bytes: stream.len() as u64,
            usage: None,
            usage_completeness: "UNKNOWN".into(),
        };
        meter.apply(&mut settlement);
        receipt.response(&settlement, &meter).unwrap();
        let response = std::fs::read_to_string(directory.join("receipt-1.response.json")).unwrap();
        assert!(!response.contains("private-thinking"));
        assert!(!response.contains("private-key"));
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            response["upstream_request_ids"]["x-oneapi-request-id"],
            "20261011-upstream-id"
        );
        assert!(
            response["upstream_request_ids"]
                .get("authorization")
                .is_none()
        );
        assert_eq!(
            response["response_body_sha256"],
            format!("{:x}", Sha256::digest(stream.as_bytes()))
        );
        assert_eq!(response["stop_reason"], "max_tokens");
        assert_eq!(response["thinking_utf8_bytes"], 16);
        assert_eq!(response["text_utf8_bytes"], 2);
        assert_eq!(response["tool_use_blocks"], 1);
        assert_eq!(response["tool_input_json_utf8_bytes"], 7);
        assert_eq!(response["usage"]["input_tokens"], 9);
        assert!(response["usage"].get("unsafe_provider_field").is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
