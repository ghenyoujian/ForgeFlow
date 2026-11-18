//! Optional project compatibility is data, never a built-in project-name exception.
use super::*;

pub(crate) struct VerificationContract {
    pub recipe_schema: String,
    pub card_type: String,
    pub acceptance_scope: String,
}

fn compatibility(project: &str) -> Result<Value, ApiError> {
    let Some(path) = std::env::var_os("FORGEFLOW_PROJECT_COMPAT_FILE") else {
        return Ok(Value::Null);
    };
    let raw = native_panel::private_bytes(&PathBuf::from(path), 1_048_576)?;
    let expected = std::env::var("FORGEFLOW_PROJECT_COMPAT_SHA256").unwrap_or_default();
    decode_compatibility(project, &raw, &expected)
}

fn decode_compatibility(project: &str, raw: &[u8], expected: &str) -> Result<Value, ApiError> {
    if !forgeflow_domain::valid_digest(expected) || forgeflow_planner::sha256(raw) != expected {
        return Err(invalid());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| invalid())?;
    if value["schema_version"] != "forgeflow.project-compat.v1" || !value["projects"].is_object() {
        return Err(invalid());
    }
    Ok(value["projects"][project].clone())
}

fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "PROJECT_COMPAT_INVALID",
        "explicit project compatibility file is unavailable, changed or invalid",
    )
}

pub(crate) fn delivery_schema(project: &str, schema: &str) -> Result<bool, ApiError> {
    if schema == "forgeflow.native-delivery.v1" {
        return Ok(true);
    }
    Ok(compatibility(project)?["delivery_schemas"]
        .as_array()
        .is_some_and(|schemas| schemas.iter().any(|s| s.as_str() == Some(schema))))
}

pub(crate) fn verification_contract(
    project: &str,
    contract: &str,
) -> Result<Option<VerificationContract>, ApiError> {
    if contract == "forgeflow.workspace-handoff.v1" {
        return Ok(Some(VerificationContract {
            recipe_schema: "forgeflow.verification-recipe.v1".into(),
            card_type: "DATA_ONLY".into(),
            acceptance_scope: "DATA_ONLY_WORKSPACE_HANDOFF".into(),
        }));
    }
    let configuration = compatibility(project)?;
    let Some(row) = configuration["verification_contracts"].get(contract) else {
        return Ok(None);
    };
    let field = |name: &str| {
        row[name]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok(Some(VerificationContract {
        recipe_schema: field("recipe_schema")?,
        card_type: field("card_type")?,
        acceptance_scope: field("acceptance_scope")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_compatibility_is_digest_and_project_scoped() {
        let bytes = br#"{"schema_version":"forgeflow.project-compat.v1","projects":{"customer":{"delivery_schemas":["legacy.v1"]}}}"#;
        let hash = forgeflow_planner::sha256(bytes);
        assert_eq!(
            decode_compatibility("customer", bytes, &hash).unwrap()["delivery_schemas"][0],
            "legacy.v1"
        );
        assert!(
            decode_compatibility("other", bytes, &hash)
                .unwrap()
                .is_null()
        );
        assert!(decode_compatibility("customer", bytes, &"0".repeat(64)).is_err());
        assert!(
            decode_compatibility("customer", b"{}", &forgeflow_planner::sha256(b"{}")).is_err()
        );
    }
    #[test]
    fn generic_contract_is_project_independent() {
        for project in ["fresh-project", "another-project"] {
            let contract = verification_contract(project, "forgeflow.workspace-handoff.v1")
                .unwrap()
                .unwrap();
            assert_eq!(contract.recipe_schema, "forgeflow.verification-recipe.v1");
            assert!(delivery_schema(project, "forgeflow.native-delivery.v1").unwrap());
        }
    }
}
