//! Strict, per-attempt model egress. The canonical server consumes each native
//! grant before connecting upstream; this transport never grants or settles it.
use crate::ControlClient;
use anyhow::{Context, Result, bail};
use forgeflow_domain::ExecutionEnvelope;
use forgeflow_executors::sha256;
use forgeflow_runtime::{Journal, durable_json};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
};

pub const SCHEMA: &str = "forgeflow.model-uds.v1";
pub const SOCKET_ALIAS: &str = "/tmp/forgeflow/model.sock";
pub const LOADER_ALIAS: &str = "/tmp/forgeflow/model-transport.mjs";
pub const PROVIDER_POLICY_ALIAS: &str = "/tmp/forgeflow/provider-policy.json";
pub const SDK_ORIGIN: &str = "http://forgeflow-model.invalid";
const MAX_HEADER: usize = 65536;
const MAX_BODY: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRelayConfig {
    pub schema_version: String,
    pub transport_loader: PathBuf,
    pub sdk_origin: String,
    pub max_request_bytes: u64,
    pub response_idle_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_policy_path: Option<PathBuf>,
}
impl ModelRelayConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA
            || self.sdk_origin != SDK_ORIGIN
            || !self.transport_loader.is_absolute()
            || self.max_request_bytes == 0
            || self.max_request_bytes > MAX_BODY
            || !(1000..=1_800_000).contains(&self.response_idle_timeout_ms)
        {
            bail!("strict model relay configuration invalid");
        }
        match (&self.provider_policy_id, &self.provider_policy_path) {
            (None, None) => {}
            (Some(id), Some(path)) if id == "glm-5.3-max.v1" && path.is_absolute() => {}
            _ => bail!("strict model relay provider policy must have a known paired identity/path"),
        }
        Ok(())
    }
    pub fn bridge_config(&self) -> Value {
        let mut value = json!({"schema_version":SCHEMA,"socket_path":SOCKET_ALIAS,"sdk_origin":self.sdk_origin,
            "max_request_bytes":self.max_request_bytes,"response_idle_timeout_ms":self.response_idle_timeout_ms});
        if let Some(id) = &self.provider_policy_id {
            value["provider_policy_id"] = json!(id);
            value["provider_policy_path"] = json!(PROVIDER_POLICY_ALIAS);
        }
        value
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: String,
    project_id: String,
    task_id: String,
    attempt_id: String,
    generation: i64,
    native_session_id: String,
    allocation_id: String,
    request_id: String,
    request_grant_id: String,
    provider: String,
    model: String,
    max_output_tokens: u64,
    method: String,
    url: String,
    body_bytes: u64,
    body_sha256: String,
    headers: Vec<(String, String)>,
}
fn ascii_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'\r' && b != b'\n')
}
fn validate(
    request: &Request,
    body: &[u8],
    envelope: &ExecutionEnvelope,
    config: &ModelRelayConfig,
) -> Result<()> {
    if request.schema_version != SCHEMA
        || request.project_id != envelope.project_id
        || request.task_id != envelope.task_id
        || request.attempt_id != envelope.attempt_id
        || request.generation != envelope.generation
        || request.method != "POST"
        || request.url != format!("{SDK_ORIGIN}/v1/messages")
        || request.body_bytes == 0
        || request.body_bytes > config.max_request_bytes
        || request.body_bytes != body.len() as u64
        || request.body_sha256 != sha256(body)
        || !ascii_id(&request.native_session_id)
        || !ascii_id(&request.provider)
        || !ascii_id(&request.model)
        || request.max_output_tokens == 0
    {
        bail!("MODEL_RELAY_SCOPE_INVALID");
    }
    for value in [
        &request.allocation_id,
        &request.request_id,
        &request.request_grant_id,
    ] {
        uuid::Uuid::parse_str(value).context("MODEL_RELAY_GRANT_INVALID")?;
    }
    let payload: Value = serde_json::from_slice(body).context("MODEL_RELAY_BODY_INVALID")?;
    if payload["model"].as_str() != Some(request.model.as_str())
        || payload["max_tokens"].as_u64() != Some(request.max_output_tokens)
        || payload["stream"] != true
    {
        bail!("MODEL_RELAY_BODY_SCOPE_INVALID");
    }
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in &request.headers {
        let name = name.to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "anthropic-version"
                | "anthropic-beta"
                | "content-type"
                | "accept"
                | "anthropic-dangerous-direct-browser-access"
        ) || !seen.insert(name)
            || value.len() > 4096
            || !value.is_ascii()
            || value.contains(['\r', '\n', '\0'])
        {
            bail!("MODEL_RELAY_HEADER_INVALID");
        }
    }
    Ok(())
}

#[derive(Debug, Default, Serialize)]
pub struct RelayStop {
    pub accepted_connections: u64,
    pub completed_responses: u64,
    pub interrupted_or_rejected_connections: u64,
    pub active_connections: u64,
    pub authority: &'static str,
}
/// The listener and all response tasks remain owned until explicit shutdown.
/// Its closure is a transport observation; never a model/provider stop proof.
pub struct ModelRelay {
    pub socket_path: PathBuf,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<RelayStop>>,
    journal: Journal,
}
impl ModelRelay {
    pub async fn start(
        client: ControlClient,
        envelope: ExecutionEnvelope,
        journal: Journal,
        config: ModelRelayConfig,
    ) -> Result<Self> {
        config.validate()?;
        let limits = crate::native_controller::transport_limits(&journal, &envelope)?;
        if journal.path("model-relay.json").exists() {
            bail!("prior model relay requires canonical reconciliation; no rebind");
        }
        let directory = journal.path("model-relay");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let socket_path = directory.join("model.sock");
        let listener = crate::native_controller::bind_private_socket(&directory, "model.sock")?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        durable_json(
            &journal.path("model-relay.json"),
            &json!({"schema_version":SCHEMA,
            "project_id":envelope.project_id,"attempt_id":envelope.attempt_id,"generation":envelope.generation,
            "execution_id":journal.execution_id()?,"socket_path":socket_path,"state":"TRANSPORT_BOUND",
            "authority":"CANONICAL_NATIVE_GRANT_ONLY","config":config,
            "transport_connection_limit":limits.model_connections}),
        )?;
        // Never inherit the control client's short telemetry timeout, redirects,
        // proxy environment or transparent retries into model transport.
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let (shutdown, mut receiver) = watch::channel(false);
        let task_journal = journal.clone();
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(limits.model_connections));
            let mut connections = tokio::task::JoinSet::new();
            let mut facts = RelayStop {
                authority: "TRANSPORT_ONLY_NOT_PROVIDER_STOP",
                ..Default::default()
            };
            loop {
                tokio::select! {
                    _=receiver.changed()=>break,
                    accepted=listener.accept()=>{
                        let Ok((stream,_))=accepted else {break};
                        let Ok(permit)=slots.clone().try_acquire_owned() else { continue };
                        facts.accepted_connections+=1;
                        let (client,http,envelope,journal,config,cancel)=(client.clone(),http.clone(),envelope.clone(),task_journal.clone(),config.clone(),receiver.clone());
                        connections.spawn(async move {let _permit=permit;serve(stream,&client,&http,&envelope,&journal,&config,cancel).await.is_ok()});
                    },
                    result=connections.join_next(),if !connections.is_empty()=>{
                        if matches!(result,Some(Ok(true))) {facts.completed_responses+=1;} else {facts.interrupted_or_rejected_connections+=1;}
                    }
                }
            }
            drop(listener);
            // A shared cancellation observation drops every outstanding reqwest
            // response and awaits the actual task. Unknown upstream work remains
            // held by the independent gateway/native authority.
            while let Some(result) = connections.join_next().await {
                if matches!(result, Ok(true)) {
                    facts.completed_responses += 1;
                } else {
                    facts.interrupted_or_rejected_connections += 1;
                }
            }
            facts.active_connections = 0;
            facts
        });
        Ok(Self {
            socket_path,
            shutdown,
            task: Some(task),
            journal,
        })
    }
    pub async fn finish(mut self) -> Result<RelayStop> {
        self.shutdown.send_replace(true);
        let facts = self
            .task
            .take()
            .context("model relay task missing")?
            .await
            .context("model relay task failed")?;
        let path = self.journal.path("model-relay-stop.json");
        let recorded = serde_json::to_value(&facts)?;
        tokio::task::spawn_blocking(move || durable_json(&path, &recorded)).await??;
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(facts)
    }
}
impl Drop for ModelRelay {
    fn drop(&mut self) {
        // Do not abort handlers or manufacture stop facts: let the owning task
        // close every connection and conservative gateway reservation normally.
        self.shutdown.send_replace(true);
    }
}

async fn serve(
    mut stream: UnixStream,
    control: &ControlClient,
    http: &reqwest::Client,
    envelope: &ExecutionEnvelope,
    journal: &Journal,
    config: &ModelRelayConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let exchange = async {
        let read = async {
            let size = stream.read_u32().await? as usize;
            if size == 0 || size > MAX_HEADER {
                bail!("MODEL_RELAY_METADATA_TOO_LARGE")
            }
            let mut header = vec![0u8; size];
            stream.read_exact(&mut header).await?;
            let request: Request = serde_json::from_slice(&header)?;
            if request.body_bytes == 0 || request.body_bytes > config.max_request_bytes {
                bail!("MODEL_RELAY_BODY_TOO_LARGE")
            }
            let mut body = vec![0; request.body_bytes as usize];
            stream.read_exact(&mut body).await?;
            validate(&request, &body, envelope, config)?;
            Ok::<_, anyhow::Error>((request, body))
        };
        let (request, body) = tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .context("MODEL_RELAY_REQUEST_TIMEOUT")??;
        let record_path = journal.path(&format!("model-relay/request-{}.json", request.request_id));
        let record = json!({"schema_version":SCHEMA,"project_id":request.project_id,"attempt_id":request.attempt_id,
            "generation":request.generation,"request_id":request.request_id,"request_grant_id":request.request_grant_id,
            "allocation_id":request.allocation_id,"native_session_id":request.native_session_id,
            "provider":request.provider,"model":request.model,"max_output_tokens":request.max_output_tokens,
            "body_sha256":request.body_sha256,"body_bytes":request.body_bytes,"received_at":chrono::Utc::now().to_rfc3339()});
        tokio::task::spawn_blocking(move || -> Result<()> {
            // Exclusive local admission is only a replay fence, never the
            // canonical dispatch decision. Crash leaves it closed deliberately.
            let lock = record_path.with_extension("lock");
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(lock)?;
            file.sync_all()?;
            durable_json(&record_path, &record)
        })
        .await??;
        let mut url = control.url(&["attempts", &envelope.attempt_id, "native-model"])?;
        url.query_pairs_mut()
            .append_pair("project_id", &envelope.project_id);
        let mut outgoing = http
            .post(url)
            .bearer_auth(&control.token)
            .header("content-type", "application/json")
            .header("x-forgeflow-worker-id", &envelope.worker_id)
            .header("x-forgeflow-project-id", &envelope.project_id)
            .header("x-forgeflow-generation", envelope.generation.to_string())
            .header("x-forgeflow-native-session-id", &request.native_session_id)
            .header("x-forgeflow-native-allocation-id", &request.allocation_id)
            .header("x-forgeflow-native-request-id", &request.request_id)
            .header("x-forgeflow-native-grant-id", &request.request_grant_id)
            .header("x-forgeflow-native-provider", &request.provider)
            .header("x-forgeflow-body-sha256", &request.body_sha256)
            .body(body);
        for (name, value) in &request.headers {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "anthropic-version"
                    | "anthropic-beta"
                    | "accept"
                    | "anthropic-dangerous-direct-browser-access"
            ) {
                outgoing = outgoing.header(name.as_str(), value.as_str());
            }
        }
        let idle = Duration::from_millis(config.response_idle_timeout_ms);
        let (mut reader, mut writer) = stream.split();
        let mut unexpected = [0u8; 1];
        let response = tokio::select! {
            response=tokio::time::timeout(idle,outgoing.send())=>response.context("MODEL_RELAY_UPSTREAM_HEADER_TIMEOUT")??,
            _=reader.read(&mut unexpected)=>bail!("MODEL_RELAY_CLIENT_CANCELLED_OR_EXTRA_BYTES"),
        };
        let status = response.status().as_u16();
        let names = [
            "content-type",
            "retry-after",
            "request-id",
            "x-request-id",
            "anthropic-ratelimit-requests-limit",
            "anthropic-ratelimit-requests-remaining",
            "anthropic-ratelimit-requests-reset",
            "anthropic-ratelimit-tokens-limit",
            "anthropic-ratelimit-tokens-remaining",
            "anthropic-ratelimit-tokens-reset",
        ];
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                if names.contains(&k.as_str()) {
                    v.to_str()
                        .ok()
                        .filter(|v| v.len() <= 4096)
                        .map(|v| (k.to_string(), v.to_owned()))
                } else {
                    None
                }
            })
            .collect();
        let header = serde_json::to_vec(
            &json!({"schema_version":SCHEMA,"status":status,"headers":headers}),
        )?;
        if header.len() > MAX_HEADER {
            bail!("MODEL_RELAY_RESPONSE_HEADER_TOO_LARGE")
        }
        tokio::time::timeout(idle, async {
            writer.write_u32(header.len() as u32).await?;
            writer.write_all(&header).await
        })
        .await??;
        let mut chunks = response.bytes_stream();
        loop {
            let next = tokio::select! {
                next=tokio::time::timeout(idle,chunks.next())=>next.context("MODEL_RELAY_UPSTREAM_IDLE_TIMEOUT")?,
                _=reader.read(&mut unexpected)=>bail!("MODEL_RELAY_CLIENT_CANCELLED_OR_EXTRA_BYTES"),
            };
            let Some(chunk) = next else { break };
            let chunk = chunk?;
            for bytes in chunk.chunks(MAX_HEADER) {
                if bytes.is_empty() {
                    continue;
                }
                tokio::time::timeout(idle, async {
                    writer.write_u32(bytes.len() as u32).await?;
                    writer.write_all(bytes).await
                })
                .await??;
            }
        }
        tokio::time::timeout(idle, async {
            writer.write_u32(0).await?;
            writer.shutdown().await
        })
        .await
        .context("MODEL_RELAY_RESPONSE_CLOSE_TIMEOUT")??;
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result=exchange=>result,
        _=shutdown.changed()=>bail!("MODEL_RELAY_SHUTDOWN"),
    }
}
