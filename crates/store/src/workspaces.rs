//! Account/workspace membership is independent of execution roles and grants.
use super::*;
use serde_json::json;

/// Revalidate account planning authority inside the actual catalog transaction.
/// The shared workspace lock is held through commit and conflicts with member
/// removal/downgrade, which takes FOR UPDATE on the same row.
pub(crate) async fn authorize_account_catalog(
    tx: &mut Transaction<'_, Postgres>,
    actor: &str,
    commands: &[CatalogCommand],
) -> Result<()> {
    let Some(scope) = actor.strip_prefix("account:") else {
        return Ok(());
    };
    let (account, workspace) = scope.split_once("@workspace:").ok_or_else(|| {
        err(
            "FORBIDDEN",
            "account catalog writes require a workspace identity",
        )
    })?;
    sqlx::query("SELECT workspace_id FROM workspaces WHERE workspace_id=$1 FOR SHARE")
        .bind(workspace)
        .execute(&mut **tx)
        .await?;
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
    )
    .bind(workspace)
    .bind(account)
    .fetch_optional(&mut **tx)
    .await?;
    if !matches!(role.as_deref(), Some("OWNER" | "EDITOR")) {
        return Err(err("FORBIDDEN", "工作区权限已变化，请刷新工作区后重试"));
    }
    let mut checked = std::collections::BTreeSet::new();
    for command in commands {
        let (project, creating) = match command {
            CatalogCommand::CreateProject(value) => (value.project_id.as_str(), true),
            CatalogCommand::UpdateProject { project: value, .. } => {
                (value.project_id.as_str(), false)
            }
            CatalogCommand::CreateRequirement(value)
            | CatalogCommand::UpdateRequirement {
                requirement: value, ..
            } => (value.project_id.as_str(), false),
            CatalogCommand::CreateTeam(value) | CatalogCommand::UpdateTeam { team: value, .. } => {
                (value.project_id.as_str(), false)
            }
            CatalogCommand::PutFlow { flow, .. }
            | CatalogCommand::PutFlowFromParent { flow, .. } => (flow.project_id.as_str(), false),
            CatalogCommand::ImportRequirements { project_id, .. }
            | CatalogCommand::CommitFlow { project_id, .. }
            | CatalogCommand::PutDocument { project_id, .. } => (project_id.as_str(), false),
            _ => {
                return Err(err(
                    "FORBIDDEN",
                    "this command requires the deployment administrator",
                ));
            }
        };
        if !checked.insert((project, creating)) {
            continue;
        }
        let binding: Option<String> =
            sqlx::query_scalar("SELECT workspace_id FROM project_workspaces WHERE project_id=$1")
                .bind(project)
                .fetch_optional(&mut **tx)
                .await?;
        if binding.as_deref().is_some_and(|bound| bound != workspace)
            || (!creating && binding.is_none())
        {
            return Err(err("FORBIDDEN", "project is outside the account workspace"));
        }
    }
    sqlx::query("SELECT set_config('forgeflow.workspace_id',$1,true)")
        .bind(workspace)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Store {
    pub async fn register_account(&self, email: &str, name: &str, hash: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let account = id();
        let workspace = id();
        sqlx::query("INSERT INTO accounts(account_id,email,display_name,password_hash) VALUES ($1,$2,$3,$4)")
            .bind(&account).bind(email).bind(name).bind(hash).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspaces(workspace_id,name,created_by,request_key) VALUES ($1,$2,$3,'registration')")
            .bind(&workspace).bind(format!("{}的工作区",name)).bind(&account).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspace_members(workspace_id,account_id,role,joined_at) VALUES ($1,$2,'OWNER',now())")
            .bind(&workspace)
            .bind(&account)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO principals(principal_id,kind,account_id,workspace_id,display_name) VALUES ($1,'HUMAN',$2,$3,$4) ON CONFLICT (principal_id) DO UPDATE SET workspace_id=COALESCE(principals.workspace_id,EXCLUDED.workspace_id),display_name=EXCLUDED.display_name")
            .bind(format!("human:{account}"))
            .bind(&account)
            .bind(&workspace)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(json!({"account_id":account,"workspace_id":workspace,"session_epoch":1}))
    }
    pub async fn account_credentials(&self, email: &str) -> Result<Option<(String, String, i64)>> {
        Ok(sqlx::query_as(
            "SELECT account_id,password_hash,session_epoch FROM accounts WHERE email=$1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?)
    }
    pub async fn account_epoch(&self, account: &str) -> Result<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT session_epoch FROM accounts WHERE account_id=$1")
                .bind(account)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    pub async fn account_profile(&self, account: &str) -> Result<Value> {
        sqlx::query_scalar("SELECT jsonb_build_object('account_id',account_id,'email',email,'display_name',display_name,'created_at',created_at) FROM accounts WHERE account_id=$1")
            .bind(account).fetch_optional(&self.pool).await?.ok_or_else(||err("NOT_FOUND","account not found"))
    }
    pub async fn update_account(&self, account: &str, name: &str) -> Result<Value> {
        sqlx::query("UPDATE accounts SET display_name=$2 WHERE account_id=$1")
            .bind(account)
            .bind(name)
            .execute(&self.pool)
            .await?;
        self.account_profile(account).await
    }
    pub async fn change_account_password(
        &self,
        account: &str,
        epoch: i64,
        hash: &str,
    ) -> Result<i64> {
        sqlx::query_scalar("UPDATE accounts SET password_hash=$3,session_epoch=session_epoch+1 WHERE account_id=$1 AND session_epoch=$2 RETURNING session_epoch")
            .bind(account).bind(epoch).bind(hash).fetch_optional(&self.pool).await?
            .ok_or_else(||err("REVISION_CONFLICT","account changed; sign in again"))
    }
    pub async fn account_workspaces(&self, account: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('workspace_id',w.workspace_id,'name',w.name,'role',m.role,'created_at',w.created_at) FROM workspaces w JOIN workspace_members m USING(workspace_id) WHERE m.account_id=$1 AND m.revoked_at IS NULL ORDER BY w.created_at,w.workspace_id")
            .bind(account).fetch_all(&self.pool).await?)
    }
    pub async fn workspace_role(&self, account: &str, workspace: &str) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&self.pool)
        .await?)
    }
    pub async fn project_workspace(&self, project: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT workspace_id FROM project_workspaces WHERE project_id=$1")
                .bind(project)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    pub async fn workspace_projects(&self, workspace: &str) -> Result<Vec<Project>> {
        let values: Vec<Value> = sqlx::query_scalar("SELECT p.data FROM projects p JOIN project_workspaces w USING(project_id) WHERE w.workspace_id=$1 ORDER BY p.project_id")
            .bind(workspace).fetch_all(&self.pool).await?;
        values.into_iter().map(decode).collect()
    }
    pub async fn workspace_resource_overview(&self, workspace: &str) -> Result<Value> {
        // One statement: all vectors and lists share one snapshot, with no foreign identifiers.
        let data:Value=sqlx::query_scalar(r#"WITH p AS (SELECT project_id FROM project_workspaces WHERE workspace_id=$1),
          scopes AS (SELECT * FROM resource_scopes WHERE project_id IN (SELECT project_id FROM p) OR (project_id IS NULL AND worker_id IS NULL))
          SELECT jsonb_build_object(
            'policies',(SELECT COALESCE(jsonb_agg(data ORDER BY scope_id),'[]') FROM scopes),
            'usage',(SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY scope_id,dimension),'[]') FROM resource_limits l WHERE scope_id IN (SELECT scope_id FROM scopes)),
            'allocations',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY allocation_id),'[]') FROM resource_allocations a WHERE project_id IN (SELECT project_id FROM p) AND state<>'RELEASED'),
            'native_allocations',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY resource_allocation_id),'[]') FROM native_child_allocations a WHERE project_id IN (SELECT project_id FROM p) AND state<>'RELEASED'),
            'workers',(SELECT COALESCE(jsonb_agg(jsonb_build_object('worker_id',worker_id,'heartbeat_at',heartbeat_at,'reported_active_attempts',jsonb_array_length(active_attempt_ids)) ORDER BY worker_id),'[]') FROM workers WHERE project_id IN (SELECT project_id FROM p)),
            'allocation_scope','workspace_unreleased')"#).bind(workspace).fetch_one(&self.pool).await?;
        Ok(data)
    }
    pub async fn create_workspace(&self, account: &str, name: &str, key: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        // Serialize retries by account, including a first request before its insert commits.
        sqlx::query("SELECT account_id FROM accounts WHERE account_id=$1 FOR UPDATE")
            .bind(account)
            .execute(&mut *tx)
            .await?;
        let created_id = id();
        let workspace: String = sqlx::query_scalar("INSERT INTO workspaces(workspace_id,name,created_by,request_key) VALUES ($1,$2,$3,$4) ON CONFLICT(created_by,request_key) DO UPDATE SET request_key=EXCLUDED.request_key RETURNING workspace_id")
            .bind(&created_id).bind(name).bind(account).bind(key).fetch_one(&mut *tx).await?;
        let saved_name: String =
            sqlx::query_scalar("SELECT name FROM workspaces WHERE workspace_id=$1")
                .bind(&workspace)
                .fetch_one(&mut *tx)
                .await?;
        if saved_name != name {
            return Err(err(
                "IDEMPOTENCY_CONFLICT",
                "request key already used with another workspace name",
            ));
        }
        if workspace == created_id {
            sqlx::query(
                "INSERT INTO workspace_members(workspace_id,account_id,role,joined_at) VALUES ($1,$2,'OWNER',now()) ON CONFLICT DO NOTHING",
            )
            .bind(&workspace)
            .bind(account)
            .execute(&mut *tx)
            .await?;
        }
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        )
        .bind(&workspace)
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        let role = role.ok_or_else(|| {
            err(
                "FORBIDDEN",
                "creation replay cannot restore removed workspace membership",
            )
        })?;
        tx.commit().await?;
        Ok(json!({"workspace_id":workspace,"name":name,"role":role}))
    }
    pub async fn workspace_members(&self, workspace: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('account_id',a.account_id,'display_name',a.display_name,'role',m.role,'joined_at',m.joined_at,'revision',m.revision,'authorization_epoch',m.authorization_epoch,'revoked_at',m.revoked_at) FROM workspace_members m JOIN accounts a USING(account_id) WHERE m.workspace_id=$1 ORDER BY m.joined_at,a.account_id")
            .bind(workspace).fetch_all(&self.pool).await?)
    }
    pub async fn create_workspace_invitation(
        &self,
        account: &str,
        workspace: &str,
        role: &str,
        email: Option<&str>,
        token_hash: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        lock_workspace_owner(&mut tx, account, workspace).await?;
        let result = sqlx::query_scalar("INSERT INTO workspace_invitations(invitation_id,workspace_id,token_hash,role,invited_email,created_by,expires_at) VALUES ($1,$2,$3,$4,$5,$6,now()+interval '7 days') RETURNING jsonb_build_object('invitation_id',invitation_id,'role',role,'invited_email',invited_email,'expires_at',expires_at)")
            .bind(id()).bind(workspace).bind(token_hash).bind(role).bind(email).bind(account).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn workspace_invitations(&self, workspace: &str) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object('invitation_id',invitation_id,'role',role,'invited_email',invited_email,'expires_at',expires_at,'accepted_by',accepted_by,'revoked_at',revoked_at) FROM workspace_invitations WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 100")
            .bind(workspace).fetch_all(&self.pool).await?)
    }
    pub async fn accept_workspace_invitation(&self, account: &str, hash: &str) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let workspace: String = sqlx::query_scalar(
            "SELECT workspace_id FROM workspace_invitations WHERE token_hash=$1",
        )
        .bind(hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| err("NOT_FOUND", "invitation unavailable"))?;
        // Same lock order as owner edits/revocations. A used invitation cannot
        // resurrect a member after removal or overwrite a later role change.
        sqlx::query("SELECT workspace_id FROM workspaces WHERE workspace_id=$1 FOR UPDATE")
            .bind(&workspace)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT invitation_id,workspace_id,role,invited_email,accepted_by,expires_at>now() AND revoked_at IS NULL AS valid FROM workspace_invitations WHERE token_hash=$1 FOR UPDATE")
            .bind(hash).fetch_optional(&mut *tx).await?.ok_or_else(||err("NOT_FOUND","invitation unavailable"))?;
        let workspace: String = row.try_get("workspace_id")?;
        let accepted: Option<String> = row.try_get("accepted_by")?;
        if !row.try_get::<bool, _>("valid")? || accepted.as_deref().is_some_and(|a| a != account) {
            return Err(err(
                "INVITATION_UNAVAILABLE",
                "invitation expired, revoked or already used",
            ));
        }
        if accepted.is_some() {
            let member:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL)")
                .bind(&workspace).bind(account).fetch_one(&mut *tx).await?;
            if !member {
                return Err(err(
                    "INVITATION_UNAVAILABLE",
                    "used invitation cannot restore removed membership",
                ));
            }
            tx.commit().await?;
            return Ok(json!({"workspace_id":workspace}));
        }
        let email: Option<String> = row.try_get("invited_email")?;
        if let Some(email) = email {
            let actual: String =
                sqlx::query_scalar("SELECT email FROM accounts WHERE account_id=$1")
                    .bind(account)
                    .fetch_one(&mut *tx)
                    .await?;
            if actual != email {
                return Err(err("FORBIDDEN", "invitation is for another account"));
            }
        }
        let role: String = row.try_get("role")?;
        sqlx::query("INSERT INTO workspace_members(workspace_id,account_id,role,joined_at,revision,authorization_epoch,revoked_at) VALUES ($1,$2,$3,now(),1,1,NULL) ON CONFLICT(workspace_id,account_id) DO UPDATE SET role=EXCLUDED.role,revision=workspace_members.revision+1,authorization_epoch=workspace_members.authorization_epoch+1,revoked_at=NULL")
            .bind(&workspace)
            .bind(account)
            .bind(role)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE workspace_invitations SET accepted_by=$2 WHERE invitation_id=$1")
            .bind(row.try_get::<String, _>("invitation_id")?)
            .bind(account)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(json!({"workspace_id":workspace}))
    }
    pub async fn revoke_workspace_invitation(
        &self,
        account: &str,
        workspace: &str,
        invitation: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        lock_workspace_owner(&mut tx, account, workspace).await?;
        sqlx::query("UPDATE workspace_invitations SET revoked_at=COALESCE(revoked_at,now()) WHERE workspace_id=$1 AND invitation_id=$2").bind(workspace).bind(invitation).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn change_workspace_member(
        &self,
        account: &str,
        workspace: &str,
        member: &str,
        role: Option<&str>,
        expected_revision: Option<i64>,
    ) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT workspace_id FROM workspaces WHERE workspace_id=$1 FOR UPDATE")
            .bind(workspace)
            .execute(&mut *tx)
            .await?;
        let actor_role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        )
        .bind(workspace)
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        if actor_role.as_deref() != Some("OWNER")
            && !(account == member && role.is_none() && actor_role.is_some())
        {
            return Err(err("FORBIDDEN", "workspace owner required"));
        }
        let owners: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workspace_members WHERE workspace_id=$1 AND role='OWNER' AND revoked_at IS NULL",
        )
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await?;
        let existing: Option<(String, i64)> = sqlx::query_as(
            "SELECT role,revision FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        )
        .bind(workspace)
        .bind(member)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.as_ref().map(|v| v.0.as_str()) == Some("OWNER")
            && role != Some("OWNER")
            && owners <= 1
        {
            return Err(err(
                "LAST_OWNER",
                "transfer ownership before leaving or removing the last owner",
            ));
        }
        if existing.is_none() && role.is_some() {
            return Err(err("NOT_FOUND", "workspace member not found"));
        }
        if let Some((_, current)) = existing.as_ref() {
            crate::ecp_membership::require_expected_revision(expected_revision, *current)?;
        }
        let membership_revision: i64 = if let Some(role) = role {
            let query = if expected_revision.is_some() {
                "UPDATE workspace_members SET role=$3,revision=revision+1,authorization_epoch=authorization_epoch+1,revoked_at=NULL WHERE workspace_id=$1 AND account_id=$2 AND revision=$4 AND revoked_at IS NULL RETURNING revision"
            } else {
                "UPDATE workspace_members SET role=$3,revision=revision+1,authorization_epoch=authorization_epoch+1,revoked_at=NULL WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL RETURNING revision"
            };
            let mut request = sqlx::query_scalar(query)
                .bind(workspace)
                .bind(member)
                .bind(role);
            if let Some(expected) = expected_revision {
                request = request.bind(expected);
            }
            request
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("REVISION_CONFLICT", "workspace membership revision changed"))?
        } else {
            let query = if expected_revision.is_some() {
                "UPDATE workspace_members SET revision=revision+1,authorization_epoch=authorization_epoch+1,revoked_at=clock_timestamp() WHERE workspace_id=$1 AND account_id=$2 AND revision=$3 AND revoked_at IS NULL RETURNING revision"
            } else {
                "UPDATE workspace_members SET revision=revision+1,authorization_epoch=authorization_epoch+1,revoked_at=clock_timestamp() WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL RETURNING revision"
            };
            let mut request = sqlx::query_scalar(query).bind(workspace).bind(member);
            if let Some(expected) = expected_revision {
                request = request.bind(expected);
            }
            request
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| err("REVISION_CONFLICT", "workspace membership revision changed"))?
        };
        if role.is_none() || role == Some("VIEWER") {
            sqlx::query("UPDATE agent_integrations SET disabled_at=COALESCE(disabled_at,now()) WHERE workspace_id=$1 AND account_id=$2").bind(workspace).bind(member).execute(&mut *tx).await?;
        }
        let principal_id = format!("human:{member}");
        let principal_revision: i64 = sqlx::query_scalar("UPDATE principals SET authorization_epoch=authorization_epoch+1,revision=revision+1 WHERE principal_id=$1 RETURNING revision")
            .bind(&principal_id).fetch_optional(&mut *tx).await?.unwrap_or(1);
        let kind = if role.is_none() {
            "MEMBER_REMOVED"
        } else {
            "MEMBER_CHANGED"
        };
        let payload = json!({"workspace_id":workspace,"account_id":member,"role":role,"membership_revision":membership_revision,"principal_revision":principal_revision});
        let event_id = id();
        sqlx::query("INSERT INTO workspace_security_events(event_id,workspace_id,principal_id,kind,object_id,object_revision,payload) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&event_id).bind(workspace).bind(&principal_id).bind(kind).bind(member).bind(membership_revision).bind(&payload).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO workspace_security_outbox(outbox_id,event_id,workspace_id,kind,payload) VALUES($1,$2,$3,$4,$5)")
            .bind(id()).bind(&event_id).bind(workspace).bind(kind).bind(&payload).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(membership_revision)
    }
}
pub(crate) async fn lock_workspace_owner(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    workspace: &str,
) -> Result<()> {
    sqlx::query("SELECT workspace_id FROM workspaces WHERE workspace_id=$1 FOR UPDATE")
        .bind(workspace)
        .execute(&mut **tx)
        .await?;
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM workspace_members WHERE workspace_id=$1 AND account_id=$2 AND revoked_at IS NULL",
    )
    .bind(workspace)
    .bind(account)
    .fetch_optional(&mut **tx)
    .await?;
    if role.as_deref() != Some("OWNER") {
        return Err(err("FORBIDDEN", "workspace owner required"));
    }
    Ok(())
}
