//! ECP DSH managed-leaf adapter boundary.
//!
//! Process ownership remains in Worker. This module intentionally exposes the
//! prepare step and explicit unsupported results for lifecycle operations that
//! have not received current native qualification.

use crate::{ExecutorError, HeadlessLaunchSpec, HeadlessProfile, ParsedEvent, prepare_headless};
use forgeflow_domain::ExecutionEnvelope;

#[derive(Debug, Clone)]
pub struct DshLeafAdapter {
    profile: HeadlessProfile,
}

impl DshLeafAdapter {
    pub fn new(profile: HeadlessProfile) -> Result<Self, ExecutorError> {
        profile.verify_identity()?;
        Ok(Self { profile })
    }

    pub fn profile(&self) -> &HeadlessProfile {
        &self.profile
    }

    pub fn prepare(
        &self,
        envelope: &ExecutionEnvelope,
        prompt: Vec<u8>,
    ) -> Result<HeadlessLaunchSpec, ExecutorError> {
        prepare_headless(envelope, prompt, &self.profile)
    }

    pub fn observe(&self, _raw: &[u8]) -> Result<ParsedEvent, ExecutorError> {
        Err(ExecutorError::Unsupported(
            "DSH leaf observation is owned by Worker stream supervision".into(),
        ))
    }

    pub fn cancel(&self) -> Result<(), ExecutorError> {
        Err(ExecutorError::Unsupported(
            "DSH native session cancel is not qualified for this profile".into(),
        ))
    }

    pub fn collect_artifacts(&self) -> Result<(), ExecutorError> {
        Err(ExecutorError::Unsupported(
            "DSH artifact collection is owned by Worker journal reconciliation".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_without_worker_supervision_is_explicitly_unsupported() {
        let profile = HeadlessProfile {
            id: "dsh-leaf".into(),
            program: "/does/not/exist".into(),
            prefix_args: vec![],
            home: "/does/not/exist".into(),
            profile_name: "managed".into(),
            artifact_pins: vec![],
            resume_verified: false,
            model_route_id: "route".into(),
            gateway_coverage_verified: false,
        };
        assert!(DshLeafAdapter::new(profile).is_err());
    }
}
