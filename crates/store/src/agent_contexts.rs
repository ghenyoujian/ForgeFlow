//! Persistent independent input/history descriptors; never execution authority.
use super::*;

pub(crate) fn validate_descriptor(
    project: &str,
    id: &str,
    value: &Value,
    old: Option<&Value>,
) -> Result<()> {
    let allowed = [
        "schema_version",
        "project_id",
        "context_id",
        "position_id",
        "model_route_id",
        "input_manifest_ref",
        "prompt_ref",
        "history_refs",
        "revision",
    ];
    if value["schema_version"] != "forgeflow.agent-context.v1"
        || value["project_id"].as_str() != Some(project)
        || value["context_id"].as_str() != Some(id)
        || value
            .as_object()
            .is_none_or(|v| v.keys().any(|k| !allowed.contains(&k.as_str())))
        || [
            id,
            value["position_id"].as_str().unwrap_or(""),
            value["model_route_id"].as_str().unwrap_or(""),
        ]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256)
        || value["history_refs"]
            .as_array()
            .is_none_or(|refs| refs.len() > 256)
    {
        return Err(err(
            "AGENT_CONTEXT_INVALID",
            "bounded project-scoped context descriptor required; no runtime/grant fields",
        ));
    }
    let references = [
        value["input_manifest_ref"].clone(),
        value["prompt_ref"].clone(),
    ];
    for reference in references
        .iter()
        .chain(value["history_refs"].as_array().unwrap())
    {
        if reference.as_object().is_none_or(|r| r.len() != 2)
            || reference["artifact_id"].as_str().is_none_or(str::is_empty)
            || reference["sha256"]
                .as_str()
                .is_none_or(|h| !valid_digest(h))
        {
            return Err(err(
                "AGENT_CONTEXT_INVALID",
                "exact immutable artifact references required",
            ));
        }
    }
    if let Some(old) = old {
        for field in [
            "project_id",
            "context_id",
            "position_id",
            "model_route_id",
            "input_manifest_ref",
            "prompt_ref",
        ] {
            if old[field] != value[field] {
                return Err(err(
                    "AGENT_CONTEXT_IDENTITY_CHANGED",
                    "create another context for a new identity/base; preserve original history",
                ));
            }
        }
        let prior = old["history_refs"]
            .as_array()
            .ok_or_else(|| err("AGENT_CONTEXT_INVALID", "prior context history unavailable"))?;
        if !value["history_refs"].as_array().unwrap().starts_with(prior) {
            return Err(err(
                "AGENT_CONTEXT_HISTORY_CHANGED",
                "history references append only; existing context cannot be reset or overwritten",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn validate(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    id: &str,
    value: &Value,
) -> Result<()> {
    let old: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='agent_contexts' AND document_id=$2 FOR UPDATE")
        .bind(project).bind(id).fetch_optional(&mut **tx).await?;
    validate_descriptor(project, id, value, old.as_ref())?;
    let base = [&value["input_manifest_ref"], &value["prompt_ref"]];
    for reference in base
        .into_iter()
        .chain(value["history_refs"].as_array().unwrap().iter())
    {
        let artifact: Option<Value> = sqlx::query_scalar("SELECT data FROM documents WHERE project_id=$1 AND collection='artifacts' AND document_id=$2")
            .bind(project).bind(reference["artifact_id"].as_str().unwrap()).fetch_optional(&mut **tx).await?;
        if artifact
            .as_ref()
            .is_none_or(|a| a["sha256"] != reference["sha256"])
        {
            return Err(err(
                "AGENT_CONTEXT_ARTIFACT_MISMATCH",
                "context artifact must belong to this exact project and digest",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn histories_are_independent_append_only_and_not_execution_grants() {
        let reference = json!({"artifact_id":"input","sha256":"a".repeat(64)});
        let value = json!({"schema_version":"forgeflow.agent-context.v1","project_id":"project","context_id":"ctx-1",
            "position_id":"role-1","model_route_id":"provider/model","input_manifest_ref":reference,"prompt_ref":reference,"history_refs":[]});
        assert!(validate_descriptor("project", "ctx-1", &value, None).is_ok());
        assert!(validate_descriptor("other", "ctx-1", &value, None).is_err());
        let mut next = value.clone();
        next["history_refs"] = json!([reference]);
        assert!(validate_descriptor("project", "ctx-1", &next, Some(&value)).is_ok());
        assert!(validate_descriptor("project", "ctx-1", &value, Some(&next)).is_err());
        let mut forged = value.clone();
        forged["state"] = json!("RUNNING");
        assert!(validate_descriptor("project", "ctx-1", &forged, None).is_err());
        let mut alias = value.clone();
        alias["context_id"] = json!("ctx-2");
        assert!(validate_descriptor("project", "ctx-2", &alias, Some(&value)).is_err());
    }
}
