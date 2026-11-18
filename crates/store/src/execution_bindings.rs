//! Internal storage indirection only. API, Worker and retained-source hashes
//! continue to consume the complete, original admitted binding object.
use super::*;
use sqlx::PgConnection;

const PROFILE_HASH_DOMAIN: &str = "forgeflow.frozen-executor-profile.v1";

fn invalid(message: &str) -> StoreError {
    err("FROZEN_EXECUTOR_PROFILE_INVALID", message)
}

// Sort recursively even if another crate enables serde_json/preserve_order.
// The bytes are compact JSON [domain, sorted_profile], never jsonb::text.
fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: std::collections::BTreeMap<_, _> = object
                .iter()
                .map(|(key, value)| (key.clone(), canonical_value(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        scalar => scalar.clone(),
    }
}

pub(crate) fn profile_digest(profile: &Value) -> Result<String> {
    if !profile.is_object() {
        return Err(invalid("frozen executor profile must be an object"));
    }
    Ok(forgeflow_planner::sha256(&serde_json::to_vec(
        &serde_json::json!([PROFILE_HASH_DOMAIN, canonical_value(profile)]),
    )?))
}

/// Called only after normal admission has validated the complete bindings.
/// Object publication and Attempt insertion use the very same transaction.
pub(crate) async fn freeze_profile_tx(
    tx: &mut Transaction<'_, Postgres>,
    project: &str,
    expected_profile_id: &str,
    bindings: &mut Value,
) -> Result<String> {
    let profile = bindings
        .get("executor_profile")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("admission requires the full frozen executor profile"))?;
    if profile["id"].as_str() != Some(expected_profile_id) {
        return Err(invalid(
            "executor profile differs from the admitted envelope",
        ));
    }
    let digest = profile_digest(profile)?;
    sqlx::query("INSERT INTO frozen_executor_profiles(project_id,sha256,data) VALUES($1,$2,$3) ON CONFLICT(project_id,sha256) DO NOTHING")
        .bind(project).bind(&digest).bind(profile).execute(&mut **tx).await?;
    let stored: Value = sqlx::query_scalar(
        "SELECT data FROM frozen_executor_profiles WHERE project_id=$1 AND sha256=$2",
    )
    .bind(project)
    .bind(&digest)
    .fetch_one(&mut **tx)
    .await?;
    if &stored != profile || profile_digest(&stored)? != digest {
        return Err(invalid(
            "existing frozen executor object differs from its content pin",
        ));
    }
    bindings
        .as_object_mut()
        .ok_or_else(|| invalid("execution bindings must be an object"))?
        .remove("executor_profile");
    Ok(digest)
}

/// Read through the caller's existing connection/transaction. A missing or
/// corrupt reference never falls back to a current profile document.
pub(crate) async fn load(
    connection: &mut PgConnection,
    project: &str,
    attempt: &str,
) -> Result<Value> {
    let row = sqlx::query(
        "SELECT a.execution_bindings,a.executor_profile_sha256,\
         a.envelope->>'executor_profile_id' AS executor_profile_id,p.data AS profile_data \
         FROM attempts a LEFT JOIN frozen_executor_profiles p \
         ON p.project_id=a.project_id AND p.sha256=a.executor_profile_sha256 \
         WHERE a.project_id=$1 AND a.attempt_id=$2",
    )
    .bind(project)
    .bind(attempt)
    .fetch_optional(connection)
    .await?
    .ok_or_else(|| err("NOT_FOUND", "attempt bindings not found"))?;
    let mut bindings: Value = row.try_get("execution_bindings")?;
    let digest: Option<String> = row.try_get("executor_profile_sha256")?;
    let Some(digest) = digest else {
        // Historical inline JSON, including historical hash inputs, is exact.
        return Ok(bindings);
    };
    if !bindings.is_object() || bindings.get("executor_profile").is_some() {
        return Err(invalid(
            "referenced binding cannot also contain an inline executor profile",
        ));
    }
    let profile: Option<Value> = row.try_get("profile_data")?;
    let profile = profile.ok_or_else(|| invalid("same-project frozen executor object missing"))?;
    let expected_id: Option<String> = row.try_get("executor_profile_id")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || profile_digest(&profile)? != digest
        || expected_id.is_none()
        || profile["id"].as_str() != expected_id.as_deref()
    {
        return Err(invalid(
            "frozen executor content pin or admitted identity mismatch",
        ));
    }
    bindings["executor_profile"] = profile;
    Ok(bindings)
}
