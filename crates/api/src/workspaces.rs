use super::*;
use axum::{
    body::{Body, to_bytes},
    extract::{FromRequestParts, MatchedPath, Request},
    middleware::Next,
};
use std::collections::HashMap;
fn json_error(error: serde_json::Error) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "VALIDATION_ERROR",
        error.to_string(),
    )
}

#[derive(Clone, Debug)]
pub struct Access {
    pub actor: auth::SessionActor,
    pub workspace: String,
}
pub fn forbidden(message: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "FORBIDDEN", message)
}
pub fn login_error(error: auth::LoginError) -> ApiError {
    match error {
        auth::LoginError::InvalidCredentials => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "邮箱或密码不正确",
        ),
        auth::LoginError::Throttled { .. } => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "LOGIN_THROTTLED",
            "登录或注册请求过于频繁，请稍后重试",
        ),
        auth::LoginError::Unavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_UNAVAILABLE",
            "账号服务暂时不可用",
        ),
    }
}
pub fn same_origin(headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if origin != format!("http://{host}") && origin != format!("https://{host}") {
            return Err(forbidden("request origin must match host"));
        }
    }
    Ok(())
}
pub fn session_response(token: String, csrf: String, extra: Value) -> Response {
    let cookie = format!(
        "forgeflow_session={token}; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=28800"
    );
    ([("set-cookie",cookie)],Json(json!({"data":{"token":token,"csrf_token":csrf,"expires_in_seconds":28800,"account":extra}}))).into_response()
}
fn text(value: &str, max: usize, label: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            format!("invalid {label}"),
        ));
    }
    Ok(value.into())
}
pub fn email(value: &str) -> Result<String, ApiError> {
    let value = text(value, 254, "email")?.to_lowercase();
    if !value.is_ascii()
        || value.contains(char::is_whitespace)
        || value.matches('@').count() != 1
        || !value
            .split('@')
            .nth(1)
            .is_some_and(|s| s.contains('.') && !s.starts_with('.') && !s.ends_with('.'))
        || value.starts_with('@')
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "请输入有效邮箱",
        ));
    }
    Ok(value)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    email: String,
    display_name: String,
    password: String,
}
pub async fn register(
    State(s): State<App>,
    headers: HeaderMap,
    Json(body): Json<Registration>,
) -> Result<Response, ApiError> {
    same_origin(&headers)?;
    if s.auth.is_shutting_down() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVER_DRAINING",
            "service is stopping",
        ));
    }
    let email = email(&body.email)?;
    let name = text(&body.display_name, 80, "display name")?;
    if !(12..=4096).contains(&body.password.len()) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_LENGTH",
            "密码至少需要 12 个字符",
        ));
    }
    let hash = s
        .auth
        .hash_account_password(body.password)
        .await
        .map_err(login_error)?;
    let account = s.store.register_account(&email, &name, &hash).await?;
    let actor = auth::SessionActor {
        account_id: account["account_id"].as_str().unwrap().into(),
        session_epoch: 1,
        integration_id: None,
    };
    let (token, csrf) = s.auth.issue_account_session(actor).map_err(login_error)?;
    Ok(session_response(token, csrf, account))
}
pub async fn account_login(
    s: &App,
    email_value: &str,
    password: String,
) -> Result<Response, ApiError> {
    let email = email_value.trim().to_lowercase();
    let credentials = s.store.account_credentials(&email).await?;
    s.auth
        .verify_account_password(password, credentials.as_ref().map(|v| v.1.clone()))
        .await
        .map_err(login_error)?;
    let (account, _, epoch) =
        credentials.ok_or_else(|| login_error(auth::LoginError::InvalidCredentials))?;
    let (token, csrf) = s
        .auth
        .issue_account_session(auth::SessionActor {
            account_id: account.clone(),
            session_epoch: epoch,
            integration_id: None,
        })
        .map_err(login_error)?;
    Ok(session_response(
        token,
        csrf,
        s.store.account_profile(&account).await?,
    ))
}
pub async fn current_actor(s: &App, headers: &HeaderMap) -> Result<auth::SessionActor, ApiError> {
    let actor = s
        .auth
        .session_actor(headers)
        .ok_or_else(|| forbidden("personal account required"))?;
    s.store
        .require_account_session_epoch(&actor.account_id, actor.session_epoch)
        .await
        .map_err(|error| match error {
            forgeflow_store::StoreError::Domain(domain) if domain.code == "SESSION_REVOKED" => {
                super::ecp_accounts::session_revoked()
            }
            other => ApiError::from(other),
        })?;
    Ok(actor)
}
pub async fn guard(State(s): State<App>, req: Request, next: Next) -> Response {
    match authorize(&s, req).await {
        Ok(Authorized::Continue(req)) => next.run(req).await,
        Ok(Authorized::Response(response)) => response,
        Err(error) => error.into_response(),
    }
}
enum Authorized {
    Continue(Request),
    Response(Response),
}
async fn authorize(s: &App, mut req: Request) -> Result<Authorized, ApiError> {
    let Some(principal) = req.extensions().get::<Principal>().cloned() else {
        return Err(forbidden("authentication middleware missing"));
    };
    if !principal.actor_id.starts_with("account:") {
        if req
            .extensions()
            .get::<MatchedPath>()
            .is_some_and(|path| path.as_str().contains("/agent-network/"))
        {
            return Err(forbidden(
                "agent communication requires a personal account or project connector",
            ));
        }
        return Ok(Authorized::Continue(req));
    }
    let actor = current_actor(s, req.headers()).await?;
    let matched = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let route = matched.strip_prefix("/api/v1").unwrap_or(&matched);
    let method = req.method().as_str().to_owned();
    let read = matches!(method.as_str(), "GET" | "HEAD");
    let integration = actor.integration_id.as_deref();
    if integration.is_none()
        && (matches!(
            route,
            "/me"
                | "/logout"
                | "/account"
                | "/account/password"
                | "/workspaces"
                | "/invitations/accept"
        ) || route.starts_with("/workspaces/"))
    {
        return Ok(Authorized::Continue(req));
    }
    let mut scope = if let Some(integration) = integration {
        s.store
            .integration_scope(&actor.account_id, integration)
            .await?
            .map(|v| v.0)
            .ok_or_else(|| forbidden("connector revoked or membership changed"))?
    } else {
        req.headers()
            .get("x-forgeflow-workspace")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    if scope.is_empty() {
        scope = s
            .store
            .account_workspaces(&actor.account_id)
            .await?
            .first()
            .and_then(|v| v["workspace_id"].as_str())
            .unwrap_or("")
            .to_owned();
    }
    let role = s
        .store
        .workspace_role(&actor.account_id, &scope)
        .await?
        .ok_or_else(|| forbidden("workspace membership required"))?;
    let access = Access {
        actor: actor.clone(),
        workspace: scope.clone(),
    };
    let (mut parts, body) = req.into_parts();
    let params = Path::<HashMap<String, String>>::from_request_parts(&mut parts, s)
        .await
        .map(|p| p.0)
        .unwrap_or_default();
    req = Request::from_parts(parts, body);
    let project = params.get("project").cloned().or_else(|| {
        params
            .get("flow")
            .and_then(|v| v.rsplit_once(':').map(|v| v.0.to_owned()))
    });
    if integration.is_some()
        && (!route.starts_with("/projects/{project}/agent-network/")
            || route.contains("/integrations"))
    {
        return Err(forbidden(
            "connector grants only agent registration, directory, inbox, messages and receipts",
        ));
    }
    if let Some(project) = &project {
        if s.store.project_workspace(project).await?.as_deref() != Some(&scope) {
            return Err(forbidden("project is outside the selected workspace"));
        }
        if let Some(integration) = integration {
            if s.store
                .integration_scope(&actor.account_id, integration)
                .await?
                .as_ref()
                .map(|v| v.1.as_str())
                != Some(project)
            {
                return Err(forbidden("connector belongs to another project"));
            }
        }
        if let Some(collection) = params.get("collection") {
            if !matches!(
                collection.as_str(),
                "owners"
                    | "flow_contexts"
                    | "schedules"
                    | "task_estimates"
                    | "agent_contexts"
                    | "agent_positions"
                    | "delivery_settings"
                    | "planning_cards"
                    | "planning_catalogs"
                    | "planning_views"
                    | "findings"
                    | "contracts"
                    | "contract_versions"
                    | "sources"
                    | "milestones"
                    | "queue_entries"
                    | "operations"
                    | "artifacts"
            ) {
                return Err(forbidden(
                    "this document collection requires the deployment administrator",
                ));
            }
        }
        // Host configuration, model setup and recovery remain deployment-admin operations.
        if route.contains("/native-")
            || route.contains("/execution-configuration")
            || route.contains("/capsule")
            || route.contains("/blueprint")
            || route.contains("/releases")
            || route.contains("/integration-queue")
        {
            return Err(forbidden(
                "this operation requires the deployment administrator",
            ));
        }
        if !read && role == "VIEWER" {
            return Err(forbidden("此工作区为只读权限，请联系所有者调整角色"));
        }
        if !read && !allowed_project_write(route) {
            return Err(forbidden(
                "this operation requires the deployment administrator",
            ));
        }
        // Resource writes can alter shared admission authority; keep them admin-only.
        if !read && route.ends_with("/resources") {
            return Err(forbidden(
                "resource policy changes require the deployment administrator",
            ));
        }
        if !read {
            let (parts, body) = req.into_parts();
            let bytes = to_bytes(body, 32 * 1024 * 1024).await.map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "BODY_TOO_LARGE",
                    "request body exceeds limit",
                )
            })?;
            // Uploading a body can outlive logout, session expiry or password
            // rotation. Recheck the credential before dispatching its command.
            if s.auth.session_actor(&parts.headers).is_none() {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "SESSION_REVOKED",
                    "登录已失效，请重新登录后重试",
                ));
            }
            current_actor(s, &parts.headers).await?;
            if !matches!(
                s.store
                    .workspace_role(&actor.account_id, &scope)
                    .await?
                    .as_deref(),
                Some("OWNER" | "EDITOR")
            ) {
                return Err(forbidden("工作区权限已变化，请刷新工作区后重试"));
            }
            if !bytes.is_empty() {
                let json: Value = serde_json::from_slice(&bytes).map_err(json_error)?;
                validate_project_references(&json, project)?;
                if route == "/projects/{project}" {
                    let old = s.store.get_project(project).await?;
                    if json["project"]["root_path"] != old.root_path
                        || json["project"]["authority_mode"]
                            != serde_json::to_value(old.authority_mode).map_err(json_error)?
                    {
                        return Err(forbidden(
                            "managed repository location cannot be changed by a workspace member",
                        ));
                    }
                }
                if let Some(collection) = params.get("collection") {
                    if !matches!(
                        collection.as_str(),
                        "schedules" | "flow_contexts" | "planning_views" | "task_estimates"
                    ) {
                        return Err(forbidden(
                            "collection is maintained by authoritative services",
                        ));
                    }
                }
            }
            req = Request::from_parts(parts, Body::from(bytes));
        }
    } else if integration.is_none()
        && (route.starts_with("/conversations/")
            || route.starts_with("/deliveries/")
            || route == "/workspaces/{workspace}/assignments"
            || route.starts_with("/assignments/")
            || route.starts_with("/proposals/"))
    {
        if !read && role == "VIEWER" {
            return Err(forbidden("此工作区为只读权限，请联系所有者调整角色"));
        }
    } else if read && integration.is_none() && matches!(route, "/resource-usage" | "/resources") {
        let mut data = s.store.workspace_resource_overview(&scope).await?;
        if route == "/resources" {
            return Ok(Authorized::Response(
                view(data["policies"].clone()).into_response(),
            ));
        }
        let memory = tokio::fs::read_to_string("/proc/meminfo").await.ok();
        let bytes = |name: &str| {
            memory.as_deref().and_then(|text| {
                text.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    if key != name {
                        return None;
                    }
                    value
                        .split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()?
                        .checked_mul(1024)
                })
            })
        };
        data["host_memory"] = json!({"total_bytes":bytes("MemTotal"),"available_bytes":bytes("MemAvailable"),"source":if memory.is_some(){"PROC_MEMINFO"}else{"UNAVAILABLE"},"observed_at":Utc::now()});
        return Ok(Authorized::Response(view(data).into_response()));
    } else if read && integration.is_none() && matches!(route, "/projects" | "/portfolio") {
        let projects = s.store.workspace_projects(&scope).await?;
        if route == "/projects" {
            return Ok(Authorized::Response(view(projects).into_response()));
        }
        let rows = s.store.workspace_portfolio_overview(Some(&scope)).await?;
        return Ok(Authorized::Response(view(rows).into_response()));
    } else if !(route == "/projects"
        && method == "POST"
        && role != "VIEWER"
        && integration.is_none())
    {
        return Err(forbidden(
            "account access requires a workspace-scoped project route",
        ));
    }
    let mut principal = principal;
    principal.actor_id = format!("account:{}@workspace:{}", actor.account_id, scope);
    req.extensions_mut().insert(principal);
    req.extensions_mut().insert(access);
    Ok(Authorized::Continue(req))
}
fn allowed_project_write(route: &str) -> bool {
    route.starts_with("/projects/{project}/agent-network/")
        || matches!(
            route,
            "/projects/{project}"
                | "/projects/{project}/requirements"
                | "/projects/{project}/requirements/{requirement}"
                | "/projects/{project}/teams"
                | "/projects/{project}/teams/{team}"
                | "/projects/{project}/owners"
                | "/projects/{project}/planning-scenarios"
                | "/projects/{project}/task-estimates"
                | "/projects/{project}/flow-revisions"
                | "/projects/{project}/flow-checks"
                | "/flows/{flow}/checks"
                | "/flows/{flow}/commit"
                | "/projects/{project}/source-imports"
                | "/projects/{project}/sources"
                | "/projects/{project}/contracts"
                | "/projects/{project}/contract-versions"
                | "/projects/{project}/milestones"
                | "/projects/{project}/schedule"
                | "/projects/{project}/documents/{collection}"
                | "/projects/{project}/tutorial/personal-site"
        )
}
fn validate_project_references(value: &Value, project: &str) -> Result<(), ApiError> {
    match value {
        Value::Object(object) => {
            for (key, v) in object {
                if matches!(
                    key.as_str(),
                    "project_id" | "producer_project_id" | "consumer_project_id"
                ) && v.as_str().is_some_and(|p| !p.is_empty() && p != project)
                {
                    return Err(forbidden(
                        "cross-workspace project references are not permitted",
                    ));
                }
                validate_project_references(v, project)?;
            }
        }
        Value::Array(array) => {
            for v in array {
                validate_project_references(v, project)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub async fn stream_permitted(s: &App, headers: &HeaderMap, project: &str) -> bool {
    let Some(principal) = s.auth.authenticate(headers, false) else {
        return false;
    };
    if !principal.actor_id.starts_with("account:") {
        return !principal.worker;
    }
    let Ok(actor) = current_actor(s, headers).await else {
        return false;
    };
    let Ok(Some(workspace)) = s.store.project_workspace(project).await else {
        return false;
    };
    s.store
        .workspace_role(&actor.account_id, &workspace)
        .await
        .ok()
        .flatten()
        .is_some()
}
pub async fn account(State(s): State<App>, headers: HeaderMap) -> ApiResult<Value> {
    let actor = current_actor(&s, &headers).await?;
    Ok(view(s.store.account_profile(&actor.account_id).await?))
}
#[derive(Deserialize)]
pub struct Name {
    pub name: String,
}
pub async fn update_account(
    State(s): State<App>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> ApiResult<Value> {
    let actor = current_actor(&s, &headers).await?;
    Ok(view(
        s.store
            .update_account(&actor.account_id, &text(&body.name, 80, "name")?)
            .await?,
    ))
}
#[derive(Deserialize)]
pub struct Password {
    current_password: String,
    new_password: String,
}
pub async fn password(
    State(s): State<App>,
    headers: HeaderMap,
    Json(body): Json<Password>,
) -> Result<Response, ApiError> {
    let mut actor = current_actor(&s, &headers).await?;
    let profile = s.store.account_profile(&actor.account_id).await?;
    let credentials = s
        .store
        .account_credentials(profile["email"].as_str().unwrap())
        .await?;
    s.auth
        .verify_account_password(body.current_password, credentials.map(|v| v.1))
        .await
        .map_err(login_error)?;
    if !(12..=4096).contains(&body.new_password.len()) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_LENGTH",
            "密码至少需要 12 个字符",
        ));
    }
    let hash = s
        .auth
        .hash_account_password(body.new_password)
        .await
        .map_err(login_error)?;
    actor.session_epoch = s
        .store
        .change_account_password(&actor.account_id, actor.session_epoch, &hash)
        .await?;
    let (token, csrf) = s.auth.issue_account_session(actor).map_err(login_error)?;
    Ok(session_response(token, csrf, profile))
}
pub async fn list(State(s): State<App>, headers: HeaderMap) -> ApiResult<Value> {
    let actor = current_actor(&s, &headers).await?;
    Ok(view(s.store.account_workspaces(&actor.account_id).await?))
}
pub async fn create(
    State(s): State<App>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> ApiResult<Value> {
    let actor = current_actor(&s, &headers).await?;
    let principal = Principal {
        actor_id: format!("account:{}", actor.account_id),
        worker: false,
        worker_id: None,
        project_id: None,
    };
    Ok(view(
        s.store
            .create_workspace(
                &actor.account_id,
                &text(&body.name, 80, "name")?,
                &identity(&headers, &principal)?.idempotency_key,
            )
            .await?,
    ))
}
async fn require_role(
    s: &App,
    headers: &HeaderMap,
    workspace: &str,
    owner: bool,
) -> Result<auth::SessionActor, ApiError> {
    let actor = current_actor(s, headers).await?;
    let role = s.store.workspace_role(&actor.account_id, workspace).await?;
    if role.is_none() || (owner && role.as_deref() != Some("OWNER")) {
        return Err(forbidden("workspace owner permission required"));
    }
    Ok(actor)
}
pub async fn members(
    State(s): State<App>,
    Path(w): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    require_role(&s, &headers, &w, false).await?;
    Ok(view(s.store.workspace_members(&w).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    role: String,
    email: Option<String>,
}
pub async fn invite(
    State(s): State<App>,
    Path(w): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Invite>,
) -> ApiResult<Value> {
    let actor = require_role(&s, &headers, &w, true).await?;
    if !matches!(body.role.as_str(), "EDITOR" | "VIEWER") {
        return Err(forbidden("invitation role must be EDITOR or VIEWER"));
    }
    let target = body
        .email
        .filter(|v| !v.trim().is_empty())
        .map(|v| email(&v))
        .transpose()?;
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let mut value = s
        .store
        .create_workspace_invitation(
            &actor.account_id,
            &w,
            &body.role,
            target.as_deref(),
            &forgeflow_planner::sha256(token.as_bytes()),
        )
        .await?;
    value["invite_token"] = json!(token);
    value["invite_path"] = json!(format!("/invite#{}", token));
    Ok(view(value))
}
pub async fn invitations(
    State(s): State<App>,
    Path(w): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    require_role(&s, &headers, &w, true).await?;
    Ok(view(s.store.workspace_invitations(&w).await?))
}
#[derive(Deserialize)]
pub struct Accept {
    token: String,
}
pub async fn accept(
    State(s): State<App>,
    headers: HeaderMap,
    Json(body): Json<Accept>,
) -> ApiResult<Value> {
    let actor = current_actor(&s, &headers).await?;
    if body.token.len() != 64 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "invitation unavailable",
        ));
    }
    Ok(view(
        s.store
            .accept_workspace_invitation(
                &actor.account_id,
                &forgeflow_planner::sha256(body.token.as_bytes()),
            )
            .await?,
    ))
}
pub async fn revoke(
    State(s): State<App>,
    Path((w, i)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let actor = require_role(&s, &headers, &w, true).await?;
    s.store
        .revoke_workspace_invitation(&actor.account_id, &w, &i)
        .await?;
    Ok(view(json!({"revoked":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberChange {
    // A missing field is invalid; only an explicit JSON null means removal.
    role: Value,
    #[serde(default)]
    expected_revision: Option<i64>,
}
pub async fn change_member(
    State(s): State<App>,
    Path((w, m)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<MemberChange>,
) -> ApiResult<Value> {
    let actor = current_actor(&s, &headers).await?;
    let role = match body.role {
        Value::Null => None,
        Value::String(value) if matches!(value.as_str(), "OWNER" | "EDITOR" | "VIEWER") => {
            Some(value)
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "role must be OWNER, EDITOR, VIEWER or explicit null",
            ));
        }
    };
    let revision = s
        .store
        .change_workspace_member(
            &actor.account_id,
            &w,
            &m,
            role.as_deref(),
            body.expected_revision,
        )
        .await?;
    Ok(view(json!({"saved":true,"revision":revision})))
}
