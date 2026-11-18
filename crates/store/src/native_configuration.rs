//! Native configuration drafts are canonical documents, separate from execution.
use super::*;
use std::collections::BTreeSet;

fn digest(value: &Value) -> Result<String> {
    Ok(forgeflow_planner::sha256(&serde_json::to_vec(value)?))
}
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(err(
            "VALIDATION_ERROR",
            "invalid native configuration identifier",
        ));
    }
    Ok(())
}
pub(crate) fn validate_native_spec(spec: &Value) -> Result<()> {
    let object = spec
        .as_object()
        .ok_or_else(|| err("VALIDATION_ERROR", "native spec must be an object"))?;
    let required = [
        "base_executor_profile_id",
        "presets",
        "plugins",
        "role_bindings",
    ];
    if !required.iter().all(|key| object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && key != "max_active_attempts_per_worker")
    {
        return Err(err(
            "VALIDATION_ERROR",
            "native spec fields must match the configuration contract",
        ));
    }
    if let Some(capacity) = object.get("max_active_attempts_per_worker") {
        if !capacity
            .as_u64()
            .is_some_and(|value| (1..=64).contains(&value))
        {
            return Err(err(
                "VALIDATION_ERROR",
                "max_active_attempts_per_worker must be an integer from 1 to 64",
            ));
        }
    }
    let profile = spec["base_executor_profile_id"].as_str().unwrap_or("");
    validate_identifier(profile)?;
    if serde_json::to_vec(spec)?.len() > 4 * 1024 * 1024 {
        return Err(err(
            "VALIDATION_ERROR",
            "native spec exceeds its complete byte bound",
        ));
    }
    for (key, identity, maximum) in [
        ("presets", "id", 1024),
        ("plugins", "entry_id", 256),
        ("role_bindings", "position_id", 10000),
    ] {
        let rows = spec[key]
            .as_array()
            .ok_or_else(|| err("VALIDATION_ERROR", format!("{key} must be an array")))?;
        if rows.is_empty() || rows.len() > maximum {
            return Err(err("VALIDATION_ERROR", format!("{key} count invalid")));
        }
        let mut ids = BTreeSet::new();
        for row in rows {
            let id = row[identity].as_str().unwrap_or("");
            validate_identifier(id)?;
            if !ids.insert(id) {
                return Err(err(
                    "VALIDATION_ERROR",
                    "duplicate native configuration identity",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_native_spec;
    use serde_json::{Value, json};

    fn legacy_spec() -> Value {
        json!({"base_executor_profile_id":"base","presets":[{"id":"preset"}],
            "plugins":[{"entry_id":"team"}],"role_bindings":[{"position_id":"position"}]})
    }

    #[test]
    fn native_spec_preserves_legacy_and_accepts_bounded_worker_capacity() {
        assert!(validate_native_spec(&legacy_spec()).is_ok());
        for capacity in [1, 21, 64] {
            let mut spec = legacy_spec();
            spec["max_active_attempts_per_worker"] = capacity.into();
            assert!(validate_native_spec(&spec).is_ok(), "capacity {capacity}");
        }
    }

    #[test]
    fn native_spec_rejects_invalid_worker_capacity_and_unknown_fields() {
        for capacity in [
            json!(0),
            json!(65),
            json!(-1),
            json!(true),
            json!(false),
            json!(21.0),
            json!(1.5),
            json!("21"),
            Value::Null,
            json!([]),
            json!({}),
        ] {
            let mut spec = legacy_spec();
            spec["max_active_attempts_per_worker"] = capacity.clone();
            assert!(validate_native_spec(&spec).is_err(), "capacity {capacity}");
        }
        let mut unknown = legacy_spec();
        unknown["max_active_attempts_per_worker"] = 21.into();
        unknown["max_active_attempt_per_worker"] = 21.into();
        assert!(validate_native_spec(&unknown).is_err());
        let mut missing = legacy_spec();
        missing.as_object_mut().unwrap().remove("presets");
        missing["max_active_attempts_per_worker"] = 21.into();
        assert!(validate_native_spec(&missing).is_err());
    }
}

async fn draft(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    id: &str,
    revision: u64,
) -> Result<Value> {
    let row = sqlx::query("SELECT revision,data FROM documents WHERE project_id=$1 AND collection='native_configuration_drafts' AND document_id=$2 FOR UPDATE")
        .bind(project).bind(id).fetch_optional(&mut **tx).await?
        .ok_or_else(|| err("NOT_FOUND", "native draft not found"))?;
    if row.get::<i64, _>("revision") != i64v(revision)? {
        return Err(err(
            "REVISION_CONFLICT",
            "native draft changed; reload before review",
        ));
    }
    Ok(row.get("data"))
}
async fn save(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    id: &str,
    value: Value,
) -> Result<Value> {
    let revision = value["revision"]
        .as_u64()
        .ok_or_else(|| err("VALIDATION_ERROR", "draft revision missing"))?;
    sqlx::query("INSERT INTO documents(project_id,collection,document_id,revision,data) VALUES($1,'native_configuration_drafts',$2,$3,$4) ON CONFLICT(project_id,collection,document_id) DO UPDATE SET revision=EXCLUDED.revision,data=EXCLUDED.data")
        .bind(project).bind(id).bind(i64v(revision)?).bind(&value).execute(&mut **tx).await?;
    event(tx, project, id, revision, "native.configuration_changed", serde_json::json!({"draft_id":id,"status":value["status"],"spec_sha256":value["spec_sha256"],"execution_rights_granted":false})).await?;
    Ok(value)
}

pub(crate) async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    command: NativeConfigurationCommand,
    actor: &str,
) -> Result<Value> {
    if actor != "native-configuration-service" {
        return Err(err(
            "AUTHORITY_SCOPE_VIOLATION",
            "configuration changes require the authenticated Native panel service",
        ));
    }
    project_lock(tx, project).await?;
    match command {
        NativeConfigurationCommand::Save {
            draft_id,
            expected_revision,
            base_config_sha256,
            spec,
            requested_by,
        } => {
            validate_identifier(&draft_id)?;
            validate_native_spec(&spec)?;
            if !valid_sha(&base_config_sha256) || requested_by.is_empty() {
                return Err(err(
                    "VALIDATION_ERROR",
                    "configuration source identity missing",
                ));
            }
            let revision = if let Some(expected) = expected_revision {
                let old = draft(tx, project, &draft_id, expected).await?;
                if old["status"] == "PUBLISHED" {
                    return Err(err(
                        "IMMUTABLE_BASELINE",
                        "published native versions are immutable; create a new draft",
                    ));
                }
                expected + 1
            } else {
                let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE project_id=$1 AND collection='native_configuration_drafts' AND document_id=$2)").bind(project).bind(&draft_id).fetch_one(&mut **tx).await?;
                if exists {
                    return Err(err("REVISION_CONFLICT", "draft already exists"));
                }
                1
            };
            let hash = digest(&spec)?;
            save(tx, project, &draft_id, serde_json::json!({"schema_version":"forgeflow.native-configuration-draft.v1","project_id":project,"draft_id":draft_id,"revision":revision,"status":"DRAFT","base_config_sha256":base_config_sha256,"spec_sha256":hash,"spec":spec,"requested_by":requested_by,"execution_rights_granted":false})).await
        }
        NativeConfigurationCommand::Preview {
            draft_id,
            expected_revision,
            base_config_sha256,
            spec_sha256,
            review,
        } => {
            let mut value = draft(tx, project, &draft_id, expected_revision).await?;
            if value["status"] == "PUBLISHED"
                || value["base_config_sha256"] != base_config_sha256
                || value["spec_sha256"] != spec_sha256
            {
                return Err(err(
                    "CONTEXT_STALE",
                    "preview source differs from saved draft",
                ));
            }
            if review["native_doctor_exit_code"] != 0
                || review["profile_id"].as_str().is_none()
                || review["resource_profile_id"].as_str().is_none()
                || !valid_sha(review["resource_profile_sha256"].as_str().unwrap_or(""))
                || review["spec_sha256"] != spec_sha256
                || review["active_profiles_modified"] != false
                || review["model_calls"] != 0
            {
                return Err(err(
                    "EVIDENCE_INCOMPLETE",
                    "actual immutable native composition preview required",
                ));
            }
            validate_identifier(review["resource_profile_id"].as_str().unwrap_or(""))?;
            value["revision"] = (expected_revision + 1).into();
            value["status"] = "PREVIEWED".into();
            value["review_sha256"] = digest(&review)?.into();
            value["review"] = review;
            save(tx, project, &draft_id, value).await
        }
        NativeConfigurationCommand::Publish {
            draft_id,
            expected_revision,
            review_sha256,
            profile,
            resource_profile,
            approved_by,
        } => {
            let mut value = draft(tx, project, &draft_id, expected_revision).await?;
            if value["status"] != "PREVIEWED"
                || value["review_sha256"] != review_sha256
                || profile["id"] != value["review"]["profile_id"]
                || resource_profile["id"].as_str().is_none()
                || resource_profile["id"] != value["review"]["resource_profile_id"]
                || resource_profile.get("revision").is_some()
                || Value::String(digest(&resource_profile)?)
                    != value["review"]["resource_profile_sha256"]
                || approved_by.is_empty()
            {
                return Err(err(
                    "CONTEXT_STALE",
                    "publish requires this exact saved native preview",
                ));
            }
            let profile_id = profile["id"]
                .as_str()
                .ok_or_else(|| err("VALIDATION_ERROR", "profile id missing"))?
                .to_owned();
            let resource_id = resource_profile["id"]
                .as_str()
                .ok_or_else(|| err("VALIDATION_ERROR", "resource profile id missing"))?
                .to_owned();
            validate_identifier(&resource_id)?;
            let resource_sha256 = digest(&resource_profile)?;
            // The executor and its exact sandbox are one immutable publication.
            // Either both ordinary profile registrations commit, or neither does.
            Box::pin(crate::catalog::apply_catalog(
                tx,
                CatalogCommand::PutDocument {
                    project_id: project.into(),
                    collection: "resource_profiles".into(),
                    id: resource_id.clone(),
                    expected_revision: None,
                    value: resource_profile,
                },
                actor,
            ))
            .await?;
            // Existing executor registration validation remains authoritative.
            Box::pin(crate::catalog::apply_catalog(
                tx,
                CatalogCommand::PutDocument {
                    project_id: project.into(),
                    collection: "executor_profiles".into(),
                    id: profile_id.clone(),
                    expected_revision: None,
                    value: profile,
                },
                actor,
            ))
            .await?;
            value["revision"] = (expected_revision + 1).into();
            value["status"] = "PUBLISHED".into();
            value["published_executor_profile_id"] = profile_id.into();
            value["published_resource_profile_id"] = resource_id.into();
            value["published_resource_profile_sha256"] = resource_sha256.into();
            value["approved_by"] = approved_by.into();
            value["execution_rights_granted"] = false.into();
            save(tx, project, &draft_id, value).await
        }
        NativeConfigurationCommand::Activate {
            draft_id,
            expected_revision,
            receipt,
            resource_policies,
            activated_by,
        } => {
            let mut value = draft(tx, project, &draft_id, expected_revision).await?;
            if value["status"] != "PUBLISHED"
                || receipt["project_id"] != project
                || receipt["executor_profile_id"] != value["published_executor_profile_id"]
                || value["published_resource_profile_id"].as_str().is_none()
                || !valid_sha(
                    value["published_resource_profile_sha256"]
                        .as_str()
                        .unwrap_or(""),
                )
                || receipt["resource_profile_id"] != value["published_resource_profile_id"]
                || receipt["resource_profile_sha256"] != value["published_resource_profile_sha256"]
                || receipt["draft_id"] != draft_id
                || receipt["spec_sha256"] != value["spec_sha256"]
                || receipt["active_attempts_modified"] != false
                || receipt["execution_rights_granted"] != false
                || !valid_sha(receipt["config_sha256"].as_str().unwrap_or(""))
                || activated_by.is_empty()
            {
                return Err(err(
                    "CONTEXT_STALE",
                    "activation requires the exact immutable publication and configuration receipt",
                ));
            }
            let resource: Value = sqlx::query_scalar(
                "SELECT data - 'revision' FROM documents WHERE project_id=$1 AND collection='resource_profiles' AND document_id=$2",
            )
            .bind(project)
            .bind(value["published_resource_profile_id"].as_str().unwrap_or(""))
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| err("NOT_FOUND", "published resource sandbox missing"))?;
            if Value::String(digest(&resource)?) != value["published_resource_profile_sha256"] {
                return Err(err(
                    "CONTEXT_STALE",
                    "published resource sandbox identity changed",
                ));
            }
            let ids = receipt["worker_ids"]
                .as_array()
                .ok_or_else(|| err("VALIDATION_ERROR", "activation Worker identities missing"))?;
            let mut workers = BTreeSet::new();
            for id in ids {
                let id = id.as_str().unwrap_or("");
                validate_identifier(id)?;
                if !workers.insert(id) {
                    return Err(err("VALIDATION_ERROR", "duplicate activation Worker"));
                }
            }
            if workers.is_empty() || workers.len() != resource_policies.len() {
                return Err(err(
                    "VALIDATION_ERROR",
                    "each future Worker requires one policy",
                ));
            }
            let mut scopes = BTreeSet::new();
            let mut policy_workers = BTreeSet::new();
            let mut updates = Vec::new();
            for policy in &resource_policies {
                let worker = policy.worker_id.as_deref().unwrap_or("");
                if !workers.contains(worker)
                    || policy.project_id.is_some()
                    || policy.team_id.is_some()
                {
                    return Err(err(
                        "AUTHORITY_SCOPE_VIOLATION",
                        "activation may stage only its own Worker resource scopes",
                    ));
                }
                validate_identifier(&policy.scope_id)?;
                if policy.revision != 1
                    || policy.parent_scope_id.as_deref() == Some(&policy.scope_id)
                    || !scopes.insert(&policy.scope_id)
                    || !policy_workers.insert(worker)
                {
                    return Err(err("VALIDATION_ERROR", "invalid future Worker policy"));
                }
                for (_, limit) in policy.limits.dimensions() {
                    i64v(limit)?;
                }
                if let Some(parent) = &policy.parent_scope_id {
                    let parent_project: Option<String> = sqlx::query_scalar(
                        "SELECT project_id FROM resource_scopes WHERE scope_id=$1",
                    )
                    .bind(parent)
                    .fetch_optional(&mut **tx)
                    .await?
                    .ok_or_else(|| err("NOT_FOUND", "resource parent missing"))?;
                    if parent_project.is_some() {
                        return Err(err(
                            "AUTHORITY_SCOPE_VIOLATION",
                            "Worker resource ancestor must be global",
                        ));
                    }
                }
                updates.push(serde_json::json!({"policy":policy,"expected_revision":null}));
            }
            // A future Worker has no registration or heartbeat yet. Native START
            // first launches/registers that process, then applies these policies
            // through the ordinary resource-policy authority and FK checks.
            value["revision"] = (expected_revision + 1).into();
            value["pending_resource_policy_updates"] = updates.into();
            value["activation"] = receipt;
            value["activated_by"] = activated_by.into();
            save(tx, project, &draft_id, value).await
        }
    }
}
