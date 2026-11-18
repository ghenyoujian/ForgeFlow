//! Fail-closed ECP physical-resource binding state.
//!
//! Logical resource budgets are useful for admission, but they do not prove
//! that an operating-system limit was installed.  This module keeps the two
//! facts separate and makes the physical part explicit: a launch may only be
//! claimed as physically fenced after an immutable binding digest is recorded;
//! a stop may only be claimed after a matching stop receipt is recorded.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub const PHYSICAL_BINDING_SCHEMA: &str = "forgeflow.ecp.physical-binding.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PhysicalBindingState {
    Unbound,
    Bound,
    StopRequested,
    Stopped,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalQualification {
    Unverified,
    BoundPendingReadback,
    StopVerified,
}

impl PhysicalQualification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::BoundPendingReadback => "BOUND_PENDING_READBACK",
            Self::StopVerified => "STOP_VERIFIED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalResourceBinding {
    pub schema_version: String,
    pub attempt_id: String,
    pub generation: i64,
    pub resource_profile_id: String,
    /// Unix epoch milliseconds after which a live binding must be fenced.
    pub lease_expires_at_ms: i64,
    /// Digest of the logical budget/profile used by admission.  This does not
    /// imply that the OS enforced it.
    pub logical_budget_sha256: String,
    /// Digest of the immutable cgroup/OS binding identity, when one exists.
    pub physical_identity_sha256: Option<String>,
    pub state: PhysicalBindingState,
    /// Digest of an immutable stop/readback receipt.  A process exit alone is
    /// never sufficient to enter STOPPED.
    pub stop_receipt_sha256: Option<String>,
}

impl PhysicalResourceBinding {
    pub fn unbound(
        attempt_id: impl Into<String>,
        generation: i64,
        resource_profile_id: impl Into<String>,
        lease_expires_at_ms: i64,
        logical_budget_sha256: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            schema_version: PHYSICAL_BINDING_SCHEMA.into(),
            attempt_id: attempt_id.into(),
            generation,
            resource_profile_id: resource_profile_id.into(),
            lease_expires_at_ms,
            logical_budget_sha256: logical_budget_sha256.into(),
            physical_identity_sha256: None,
            state: PhysicalBindingState::Unbound,
            stop_receipt_sha256: None,
        };
        value.validate_common()?;
        Ok(value)
    }

    pub fn bind(mut self, physical_identity_sha256: impl Into<String>) -> Result<Self> {
        if self.state != PhysicalBindingState::Unbound {
            bail!("physical binding may only be installed once from UNBOUND")
        }
        let digest = physical_identity_sha256.into();
        validate_digest(&digest, "physical identity")?;
        self.physical_identity_sha256 = Some(digest);
        self.state = PhysicalBindingState::Bound;
        Ok(self)
    }

    pub fn request_stop(mut self) -> Result<Self> {
        if self.state != PhysicalBindingState::Bound {
            bail!("physical stop requires an active bound identity")
        }
        self.state = PhysicalBindingState::StopRequested;
        Ok(self)
    }

    /// Convert an expired live lease into a stop request. The caller still
    /// needs an OS stop/readback receipt before the binding can be STOPPED.
    pub fn enforce_lease(mut self, now_ms: i64) -> Result<Self> {
        if now_ms < self.lease_expires_at_ms {
            return Ok(self);
        }
        match self.state {
            PhysicalBindingState::Bound | PhysicalBindingState::StopRequested => {
                self.state = PhysicalBindingState::StopRequested;
                Ok(self)
            }
            PhysicalBindingState::Stopped | PhysicalBindingState::Revoked => Ok(self),
            PhysicalBindingState::Unbound => {
                bail!("an unbound physical resource cannot outlive its lease")
            }
        }
    }

    pub fn validate_lease(&self, now_ms: i64) -> Result<()> {
        if now_ms >= self.lease_expires_at_ms {
            bail!("physical resource lease expired")
        }
        Ok(())
    }

    pub fn record_stop(mut self, stop_receipt_sha256: impl Into<String>) -> Result<Self> {
        if self.state != PhysicalBindingState::StopRequested {
            bail!("stop receipt requires a stop request")
        }
        let digest = stop_receipt_sha256.into();
        validate_digest(&digest, "stop receipt")?;
        self.stop_receipt_sha256 = Some(digest);
        self.state = PhysicalBindingState::Stopped;
        Ok(self)
    }

    pub fn revoke(mut self) -> Result<Self> {
        if self.state == PhysicalBindingState::Stopped {
            bail!("a stopped binding is immutable")
        }
        self.state = PhysicalBindingState::Revoked;
        Ok(self)
    }

    /// Check the exact identity that a launcher is about to use.  This does
    /// not access cgroups; the caller must obtain the OS readback separately.
    pub fn validate_launch(
        &self,
        expected_generation: i64,
        expected_logical_budget_sha256: &str,
    ) -> Result<()> {
        self.validate_common()?;
        if self.state != PhysicalBindingState::Bound
            || self.generation != expected_generation
            || self.logical_budget_sha256 != expected_logical_budget_sha256
            || self.physical_identity_sha256.is_none()
        {
            bail!("physical launch binding is missing, stale, or mismatched")
        }
        Ok(())
    }

    /// Check the exact stop receipt that a recovery worker observed.  A
    /// matching generation and physical identity are both required.
    pub fn validate_stop(
        &self,
        expected_generation: i64,
        expected_physical_identity_sha256: &str,
        expected_stop_receipt_sha256: &str,
    ) -> Result<()> {
        self.validate_common()?;
        if self.state != PhysicalBindingState::Stopped
            || self.generation != expected_generation
            || self.physical_identity_sha256.as_deref() != Some(expected_physical_identity_sha256)
            || self.stop_receipt_sha256.as_deref() != Some(expected_stop_receipt_sha256)
        {
            bail!("physical stop proof is missing, stale, or mismatched")
        }
        Ok(())
    }

    /// Human-facing qualification state deliberately stops short of claiming
    /// an OS limit until the stop/readback receipt is present.
    pub const fn qualification(&self) -> PhysicalQualification {
        match self.state {
            PhysicalBindingState::Bound | PhysicalBindingState::StopRequested => {
                PhysicalQualification::BoundPendingReadback
            }
            PhysicalBindingState::Stopped => PhysicalQualification::StopVerified,
            PhysicalBindingState::Unbound | PhysicalBindingState::Revoked => {
                PhysicalQualification::Unverified
            }
        }
    }

    fn validate_common(&self) -> Result<()> {
        if self.schema_version != PHYSICAL_BINDING_SCHEMA {
            bail!("unsupported physical binding schema")
        }
        if self.attempt_id.trim().is_empty()
            || self.resource_profile_id.trim().is_empty()
            || self.generation < 1
            || self.lease_expires_at_ms <= 0
        {
            bail!("physical binding identity is incomplete")
        }
        validate_digest(&self.logical_budget_sha256, "logical budget")?;
        if let Some(value) = &self.physical_identity_sha256 {
            validate_digest(value, "physical identity")?;
        }
        if let Some(value) = &self.stop_receipt_sha256 {
            validate_digest(value, "stop receipt")?;
        }
        if matches!(
            self.state,
            PhysicalBindingState::Bound
                | PhysicalBindingState::StopRequested
                | PhysicalBindingState::Stopped
        ) && self.physical_identity_sha256.is_none()
        {
            bail!("bound physical state requires an identity digest")
        }
        if self.state == PhysicalBindingState::Stopped && self.stop_receipt_sha256.is_none() {
            bail!("stopped physical state requires a stop receipt")
        }
        Ok(())
    }
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} must be a lowercase SHA-256 digest")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGICAL: &str = "a";
    const PHYSICAL: &str = "b";
    const STOP: &str = "c";

    fn digest(ch: &str) -> String {
        ch.repeat(64)
    }

    fn unbound() -> PhysicalResourceBinding {
        PhysicalResourceBinding::unbound("attempt-1", 3, "resource-1", 1000, digest(LOGICAL))
            .unwrap()
    }

    #[test]
    fn missing_physical_binding_is_unverified_and_cannot_launch() {
        let value = unbound();
        assert_eq!(value.qualification().as_str(), "UNVERIFIED");
        assert!(value.validate_launch(3, &digest(LOGICAL)).is_err());
    }

    #[test]
    fn expired_lease_is_fenced_before_stop_receipt() {
        let value = unbound().bind(digest(PHYSICAL)).unwrap();
        assert!(value.validate_lease(999).is_ok());
        assert!(value.clone().validate_lease(1000).is_err());
        let fenced = value.enforce_lease(1000).unwrap();
        assert_eq!(fenced.state, PhysicalBindingState::StopRequested);
        assert!(fenced.validate_launch(3, &digest(LOGICAL)).is_err());
    }

    #[test]
    fn logical_budget_and_physical_identity_are_separate() {
        let value = unbound().bind(digest(PHYSICAL)).unwrap();
        assert_eq!(value.qualification().as_str(), "BOUND_PENDING_READBACK");
        value.validate_launch(3, &digest(LOGICAL)).unwrap();
        assert!(value.validate_launch(3, &digest("d")).is_err());
    }

    #[test]
    fn stale_generation_cannot_launch_or_stop() {
        let value = unbound().bind(digest(PHYSICAL)).unwrap();
        assert!(value.validate_launch(2, &digest(LOGICAL)).is_err());
        let stopped = value
            .request_stop()
            .unwrap()
            .record_stop(digest(STOP))
            .unwrap();
        assert!(
            stopped
                .validate_stop(2, &digest(PHYSICAL), &digest(STOP))
                .is_err()
        );
    }

    #[test]
    fn stop_requires_request_and_matching_receipt() {
        let value = unbound().bind(digest(PHYSICAL)).unwrap();
        assert!(value.clone().record_stop(digest(STOP)).is_err());
        let stopped = value
            .request_stop()
            .unwrap()
            .record_stop(digest(STOP))
            .unwrap();
        assert_eq!(stopped.qualification().as_str(), "STOP_VERIFIED");
        stopped
            .validate_stop(3, &digest(PHYSICAL), &digest(STOP))
            .unwrap();
        assert!(
            stopped
                .validate_stop(3, &digest(PHYSICAL), &digest("d"))
                .is_err()
        );
    }

    #[test]
    fn stopped_binding_is_immutable_and_unknown_fields_are_rejected() {
        let stopped = unbound()
            .bind(digest(PHYSICAL))
            .unwrap()
            .request_stop()
            .unwrap()
            .record_stop(digest(STOP))
            .unwrap();
        assert!(stopped.clone().revoke().is_err());
        let mut raw = serde_json::to_value(stopped).unwrap();
        raw["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PhysicalResourceBinding>(raw).is_err());
    }
}
