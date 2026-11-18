//! A single selected executor. Legacy DSH configuration keeps its exact JSON shape.
use anyhow::{Context, Result, bail};
use forgeflow_executors::{ClaudeLeafProfile, HeadlessProfile};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Debug, Clone)]
pub enum WorkerExecutorProfile {
    Dsh(HeadlessProfile),
    ClaudeLeaf(ClaudeLeafProfile),
}

impl From<HeadlessProfile> for WorkerExecutorProfile {
    fn from(profile: HeadlessProfile) -> Self {
        Self::Dsh(profile)
    }
}
impl From<ClaudeLeafProfile> for WorkerExecutorProfile {
    fn from(profile: ClaudeLeafProfile) -> Self {
        Self::ClaudeLeaf(profile)
    }
}
impl Serialize for WorkerExecutorProfile {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Dsh(profile) => profile.serialize(serializer),
            Self::ClaudeLeaf(profile) => {
                let mut value = serde_json::to_value(profile).map_err(serde::ser::Error::custom)?;
                value
                    .as_object_mut()
                    .expect("profile is an object")
                    .insert("kind".into(), json!("CLAUDE_CODE_LEAF"));
                value.serialize(serializer)
            }
        }
    }
}
impl<'de> Deserialize<'de> for WorkerExecutorProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let mut value = Value::deserialize(deserializer)?;
        let kind = value.get("kind").cloned();
        match kind {
            None => serde_json::from_value(value)
                .map(Self::Dsh)
                .map_err(serde::de::Error::custom),
            Some(Value::String(kind)) if kind == "CLAUDE_CODE_LEAF" => {
                value
                    .as_object_mut()
                    .expect("kind implies object")
                    .remove("kind");
                serde_json::from_value(value)
                    .map(Self::ClaudeLeaf)
                    .map_err(serde::de::Error::custom)
            }
            _ => Err(serde::de::Error::custom(
                "unknown executor profile kind; legacy DSH omits kind",
            )),
        }
    }
}
impl WorkerExecutorProfile {
    pub fn id(&self) -> &str {
        match self {
            Self::Dsh(p) => &p.id,
            Self::ClaudeLeaf(p) => &p.id,
        }
    }
    pub fn home(&self) -> &Path {
        match self {
            Self::Dsh(p) => &p.home,
            Self::ClaudeLeaf(p) => &p.home,
        }
    }
    pub fn model_route_id(&self) -> &str {
        match self {
            Self::Dsh(p) => &p.model_route_id,
            Self::ClaudeLeaf(p) => &p.model_route_id,
        }
    }
    pub fn dsh(&self) -> Option<&HeadlessProfile> {
        match self {
            Self::Dsh(p) => Some(p),
            _ => None,
        }
    }
    pub fn claude(&self) -> Option<&ClaudeLeafProfile> {
        match self {
            Self::ClaudeLeaf(p) => Some(p),
            _ => None,
        }
    }
    pub fn verify_identity(&self) -> Result<()> {
        match self {
            Self::Dsh(p) => p.verify_identity()?,
            Self::ClaudeLeaf(p) => p.verify_identity()?,
        };
        Ok(())
    }
    pub(crate) fn verify_configuration(
        &self,
        managed: bool,
        route: &str,
        sandbox: bool,
    ) -> Result<()> {
        if self.claude().is_some() && self.model_route_id() != route {
            bail!("Worker model route differs from selected executor profile");
        }
        if self.claude().is_some() && (managed || !sandbox) {
            bail!(
                "Claude leaf requires its own strong sandbox and cannot use managed DSH configuration"
            );
        }
        Ok(())
    }
    pub(crate) fn verify_route(&self, bindings: &Value) -> Result<Option<u32>> {
        if let Some(profile) = self.claude() {
            let route = bindings
                .get("model_route")
                .context("frozen model route missing")?;
            if route.get("model").and_then(Value::as_str) != Some(profile.model_id.as_str())
                || route.get("anthropic_base_url").and_then(Value::as_str)
                    != Some(profile.provider_base_url.as_str())
            {
                bail!("Claude model or endpoint differs from frozen model route");
            }
            let output_cap = route
                .get("max_output_tokens")
                .and_then(Value::as_u64)
                .filter(|value| (1..=131_072).contains(value))
                .context(
                    "Claude frozen model route requires integer max_output_tokens in 1..131072",
                )?;
            return Ok(Some(u32::try_from(output_cap)?));
        }
        Ok(None)
    }
}

/// Recovery reads the admitted profile, never the configuration of a replacement Worker.
pub(crate) fn journal_executor_identity(
    envelope: &forgeflow_domain::ExecutionEnvelope,
    journal: &forgeflow_runtime::Journal,
) -> Result<(&'static str, bool)> {
    if envelope.command.is_some() {
        return Ok(("CONTROLLED_LIGHTWEIGHT", false));
    }
    let bytes = match std::fs::read(journal.path("execution-bindings.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(("UNKNOWN_NATIVE", false));
        }
        Err(error) => return Err(error.into()),
    };
    let bindings: Value = serde_json::from_slice(&bytes)?;
    let profile = bindings
        .get("executor_profile")
        .context("journal frozen executor profile missing")?;
    if profile.get("id").and_then(Value::as_str) != Some(envelope.executor_profile_id.as_str()) {
        bail!("journal executor differs from envelope");
    }
    Ok(match profile.get("kind").and_then(Value::as_str) {
        Some("CLAUDE_CODE_LEAF") => ("CLAUDE_CODE_LEAF", false),
        Some("DSH_MANAGED") => ("DSH_MANAGED", true),
        None | Some("DSH_HEADLESS") => ("DSH_HEADLESS", true),
        _ => ("UNKNOWN_NATIVE", false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claude() -> ClaudeLeafProfile {
        ClaudeLeafProfile {
            id: "claude-leaf".into(),
            program: "/bin/true".into(),
            home: "/tmp/home".into(),
            artifact_pins: vec![],
            model_route_id: "route".into(),
            model_id: "glm-5.3".into(),
            provider_base_url: "http://127.0.0.1:17891".into(),
            credential_env: forgeflow_executors::ClaudeCredentialEnv::ApiKey,
            max_budget_usd: "1.00".into(),
            tools_allowlist: vec![],
            permission_mode: "dontAsk".into(),
            help_verified_flags: vec![],
            max_turns: None,
        }
    }
    #[test]
    fn legacy_dsh_serialization_is_byte_compatible_and_unknown_kind_fails() {
        let legacy = HeadlessProfile {
            id: "legacy".into(),
            program: "/usr/bin/node".into(),
            prefix_args: vec!["cli.js".into()],
            home: "/tmp/home".into(),
            profile_name: "headless".into(),
            artifact_pins: vec![],
            resume_verified: false,
            model_route_id: "route".into(),
            gateway_coverage_verified: false,
        };
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let selected: WorkerExecutorProfile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&selected).unwrap());
        let mut invalid = serde_json::to_value(legacy).unwrap();
        invalid["kind"] = json!("UNKNOWN");
        assert!(serde_json::from_value::<WorkerExecutorProfile>(invalid).is_err());
    }
    #[test]
    fn claude_profile_is_flat_and_rejects_dsh_mode_and_route_drift() {
        let selected = WorkerExecutorProfile::ClaudeLeaf(claude());
        let flat = serde_json::to_value(&selected).unwrap();
        assert_eq!(flat["kind"], "CLAUDE_CODE_LEAF");
        assert_eq!(flat["model_id"], "glm-5.3");
        assert!(flat.get("profile").is_none());
        let decoded: WorkerExecutorProfile = serde_json::from_value(flat.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), flat);
        assert!(selected.verify_configuration(true, "route", true).is_err());
        assert!(
            selected
                .verify_configuration(false, "route", false)
                .is_err()
        );
        assert!(selected.verify_configuration(false, "other", true).is_err());
        let mut bindings = json!({"model_route":{"model":"glm-5.3","anthropic_base_url":"http://127.0.0.1:17891","max_output_tokens":8192}});
        assert!(selected.verify_route(&bindings).is_ok());
        bindings["model_route"]["model"] = json!("unapproved-model");
        assert!(selected.verify_route(&bindings).is_err());
        bindings["model_route"]["model"] = json!("glm-5.3");
        bindings["model_route"]["anthropic_base_url"] = json!("https://other.example");
        assert!(selected.verify_route(&bindings).is_err());
    }
    #[test]
    fn output_cap_comes_only_from_valid_frozen_route_and_dsh_is_unchanged() {
        let selected = WorkerExecutorProfile::ClaudeLeaf(claude());
        let mut bindings = json!({"model_route":{"model":"glm-5.3","anthropic_base_url":"http://127.0.0.1:17891","max_output_tokens":8192}});
        assert_eq!(selected.verify_route(&bindings).unwrap(), Some(8192));
        for value in [json!(1), json!(131_072)] {
            bindings["model_route"]["max_output_tokens"] = value.clone();
            assert_eq!(
                selected.verify_route(&bindings).unwrap(),
                Some(value.as_u64().unwrap() as u32)
            );
        }
        for value in [
            Value::Null,
            json!(0),
            json!(-1),
            json!("8192"),
            json!(8192.0),
            json!(131_073),
            json!(u64::MAX),
        ] {
            bindings["model_route"]["max_output_tokens"] = value;
            assert!(selected.verify_route(&bindings).is_err());
        }
        bindings["model_route"]
            .as_object_mut()
            .unwrap()
            .remove("max_output_tokens");
        assert!(selected.verify_route(&bindings).is_err());
        let dsh =
            crate::tests::liveness_config("http://127.0.0.1:1", Path::new("/tmp/fixture")).profile;
        assert_eq!(dsh.verify_route(&json!({})).unwrap(), None);
    }
    #[test]
    fn recovery_uses_frozen_driver_and_preserves_unknown() {
        let temp = tempfile::tempdir().unwrap();
        let journal = forgeflow_runtime::Journal::new(temp.path(), "attempt-live").unwrap();
        let envelope = crate::tests::liveness_envelope();
        assert_eq!(
            journal_executor_identity(&envelope, &journal).unwrap(),
            ("UNKNOWN_NATIVE", false)
        );
        forgeflow_runtime::durable_json(&journal.path("execution-bindings.json"), &json!({"executor_profile":{"id":envelope.executor_profile_id,"kind":"CLAUDE_CODE_LEAF"}})).unwrap();
        assert_eq!(
            journal_executor_identity(&envelope, &journal).unwrap(),
            ("CLAUDE_CODE_LEAF", false)
        );
        forgeflow_runtime::durable_json(
            &journal.path("execution-bindings.json"),
            &json!({"executor_profile":{"id":"different","kind":"DSH_MANAGED"}}),
        )
        .unwrap();
        assert!(journal_executor_identity(&envelope, &journal).is_err());
    }
}
