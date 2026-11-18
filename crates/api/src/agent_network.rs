use super::*;
use workspaces::Access;

pub async fn integrations(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(a): Extension<Access>,
) -> ApiResult<Value> {
    Ok(view(
        s.store.agent_integrations(&a.actor.account_id, &p).await?,
    ))
}
pub async fn connect(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(a): Extension<Access>,
    Json(body): Json<workspaces::Name>,
) -> ApiResult<Value> {
    if body.name.trim().is_empty() || body.name.len() > 80 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "connector name required, up to 80 bytes",
        ));
    }
    let mut value = s
        .store
        .create_agent_integration(&a.actor.account_id, &a.workspace, &p, body.name.trim())
        .await?;
    let mut actor = a.actor.clone();
    actor.integration_id = value["integration_id"].as_str().map(str::to_owned);
    let (token, _) = s
        .auth
        .issue_account_session(actor)
        .map_err(workspaces::login_error)?;
    // The connector token is returned once, while its durable registration
    // receipt carries only a digest and explicit NOT_QUALIFIED status. This
    // binds the transport credential to the workspace/project scope without
    // turning connector registration into executor qualification.
    let registration = crate::ecp_connectors::registration_receipt(
        &format!(
            "connector:{}",
            value["integration_id"].as_str().unwrap_or_default()
        ),
        &a.workspace,
        &p,
        token.as_bytes(),
    )
    .map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "REGISTRATION_RECEIPT_INVALID",
            error,
        )
    })?;
    value["registration"] = serde_json::to_value(registration).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "REGISTRATION_RECEIPT_SERIALIZE_FAILED",
            error.to_string(),
        )
    })?;
    value["token"] = json!(token);
    value["expires_in_seconds"] = json!(28800);
    value["workspace_id"] = json!(a.workspace);
    value["protocol"] = json!("forgeflow.agent-network.v1");
    Ok(view(value))
}
pub async fn revoke(
    State(s): State<App>,
    Path((p, i)): Path<(String, String)>,
    Extension(a): Extension<Access>,
) -> ApiResult<Value> {
    s.store
        .disable_agent_integration(&a.actor.account_id, &a.workspace, &p, &i)
        .await?;
    Ok(view(json!({"revoked":true})))
}
pub async fn renew(
    State(s): State<App>,
    Path((p, i)): Path<(String, String)>,
    Extension(a): Extension<Access>,
) -> ApiResult<Value> {
    if s.store
        .integration_scope(&a.actor.account_id, &i)
        .await?
        .as_ref()
        != Some(&(a.workspace.clone(), p.clone()))
    {
        return Err(workspaces::forbidden(
            "connector is revoked or outside this project",
        ));
    }
    let mut actor = a.actor;
    actor.integration_id = Some(i.clone());
    let (token, _) = s
        .auth
        .issue_account_session(actor)
        .map_err(workspaces::login_error)?;
    Ok(view(
        json!({"integration_id":i,"project_id":p,"workspace_id":a.workspace,"token":token,"expires_in_seconds":28800,"protocol":"forgeflow.agent-network.v1","identity_preserved":true}),
    ))
}
pub async fn agents(State(s): State<App>, Path(p): Path<String>) -> ApiResult<Value> {
    Ok(view(s.store.network_agents(&p).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    native_agent_id: String,
    name: String,
}
pub async fn register(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(a): Extension<Access>,
    Json(body): Json<Register>,
) -> ApiResult<Value> {
    let integration =
        a.actor.integration_id.as_deref().ok_or_else(|| {
            workspaces::forbidden("agent registration requires a project connector")
        })?;
    if body.native_agent_id.is_empty()
        || body.native_agent_id.len() > 256
        || body.name.trim().is_empty()
        || body.name.len() > 80
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "invalid native agent identity or name",
        ));
    }
    Ok(view(
        s.store
            .register_network_agent(
                &a.actor.account_id,
                &a.workspace,
                &p,
                integration,
                &body.native_agent_id,
                body.name.trim(),
            )
            .await?,
    ))
}
pub async fn send(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(a): Extension<Access>,
    Json(body): Json<forgeflow_store::NetworkMessageInput>,
) -> ApiResult<Value> {
    Ok(view(
        s.store
            .send_network_message(
                &a.actor.account_id,
                &a.workspace,
                &p,
                a.actor.integration_id.as_deref(),
                body,
            )
            .await?,
    ))
}
#[derive(Deserialize, Default)]
pub struct Inbox {
    after: Option<i64>,
    before: Option<i64>,
    latest: Option<bool>,
    agent_id: Option<String>,
}
pub async fn messages(
    State(s): State<App>,
    Path(p): Path<String>,
    Extension(a): Extension<Access>,
    Query(q): Query<Inbox>,
) -> ApiResult<Value> {
    if (q.after.is_some() && (q.before.is_some() || q.latest == Some(true)))
        || (q.before.is_some() && q.latest == Some(true))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_CURSOR",
            "choose after, before or latest, not multiple directions",
        ));
    }
    Ok(view(
        s.store
            .network_messages(
                &p,
                a.actor.integration_id.as_deref(),
                q.agent_id.as_deref(),
                q.after.unwrap_or(0),
                q.before,
                q.latest.unwrap_or(false),
            )
            .await?,
    ))
}
#[derive(Deserialize)]
pub struct Receipt {
    recipient_agent_id: String,
}
pub async fn acknowledge(
    State(s): State<App>,
    Path((p, m)): Path<(String, String)>,
    Extension(a): Extension<Access>,
    Json(body): Json<Receipt>,
) -> ApiResult<Value> {
    let integration = a.actor.integration_id.as_deref().ok_or_else(|| {
        workspaces::forbidden("only the recipient connector can acknowledge receipt")
    })?;
    Ok(view(
        s.store
            .acknowledge_network_message(
                &a.actor.account_id,
                &a.workspace,
                &p,
                integration,
                &m,
                &body.recipient_agent_id,
            )
            .await?,
    ))
}
