//! ECP Claude CLI leaf adapter boundary.
//!
//! Claude v1 is deliberately a fresh-session code leaf. Resume, Team,
//! Workflow, and child supervision remain explicit unsupported capabilities
//! until a current real-model receipt proves them for the frozen profile.

use crate::{
    ClaudeLeafProfile, ExecutorError, HeadlessLaunchSpec, ParsedEvent, prepare_claude_leaf,
};
use forgeflow_domain::ExecutionEnvelope;

#[derive(Debug, Clone)]
pub struct ClaudeLeafAdapter {
    profile: ClaudeLeafProfile,
}

impl ClaudeLeafAdapter {
    pub fn new(profile: ClaudeLeafProfile) -> Result<Self, ExecutorError> {
        profile.verify_identity()?;
        Ok(Self { profile })
    }

    pub fn profile(&self) -> &ClaudeLeafProfile {
        &self.profile
    }

    pub fn prepare(
        &self,
        envelope: &ExecutionEnvelope,
        prompt: Vec<u8>,
    ) -> Result<HeadlessLaunchSpec, ExecutorError> {
        prepare_claude_leaf(envelope, prompt, &self.profile)
    }

    pub fn observe(&self, _raw: &[u8]) -> Result<ParsedEvent, ExecutorError> {
        Err(ExecutorError::Unsupported(
            "Claude stream observation is owned by Worker stream supervision".into(),
        ))
    }

    pub fn resume(&self) -> Result<(), ExecutorError> {
        Err(ExecutorError::Unsupported(
            "Claude v1 leaf session resume is not qualified".into(),
        ))
    }

    pub fn cancel(&self) -> Result<(), ExecutorError> {
        Err(ExecutorError::Unsupported(
            "Claude native session cancel is not qualified".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_profile_cannot_create_a_leaf_adapter() {
        let profile = serde_json::from_value::<ClaudeLeafProfile>(serde_json::json!({
            "id":"claude-leaf",
            "program":"/does/not/exist",
            "home":"/does/not/exist",
            "artifact_pins":[],
            "model_route_id":"route",
            "model_id":"model",
            "provider_base_url":"http://127.0.0.1:1",
            "credential_env":"API_KEY",
            "max_budget_usd":"1.0",
            "tools_allowlist":[],
            "permission_mode":"dontAsk",
            "help_verified_flags":[]
        }))
        .unwrap();
        assert!(ClaudeLeafAdapter::new(profile).is_err());
    }
}
