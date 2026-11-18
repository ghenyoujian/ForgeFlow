//! Fail-closed resume decision. A rerun is never presented as native resume.
use serde::{Deserialize, Serialize};

const RESUME_SCHEMA: &str = "forgeflow.ecp.resume.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResumeKind {
    NativeResume,
    NewAttempt,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRequest {
    pub schema_version: String,
    pub attempt_id: String,
    pub generation: i64,
    pub epoch: i64,
    /// The generation and epoch read from the authoritative attempt/session
    /// row immediately before issuing the resume command.  A caller cannot
    /// resume an older identity by merely presenting a positive generation.
    pub current_generation: i64,
    pub current_epoch: i64,
    pub native_session_id: Option<String>,
    #[serde(rename = "resume_kind")]
    pub requested_kind: ResumeKind,
    pub evidence_status: String,
    pub receipt_ref: Option<String>,
    pub receipt_attempt_id: Option<String>,
    pub receipt_generation: Option<i64>,
    pub receipt_epoch: Option<i64>,
    pub receipt_session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeDecision {
    pub schema_version: String,
    pub attempt_id: String,
    pub generation: i64,
    pub epoch: i64,
    #[serde(rename = "resume_kind")]
    pub kind: ResumeKind,
    pub reason_code: String,
    pub evidence_status: String,
    pub receipt_ref: Option<String>,
}

pub fn decide(request: ResumeRequest, native_resume_verified: bool) -> ResumeDecision {
    let identity_valid = request.schema_version == RESUME_SCHEMA
        && !request.attempt_id.trim().is_empty()
        && request.generation >= 1
        && request.epoch >= 1
        && request.current_generation >= 1
        && request.current_epoch >= 1;
    let fence_matches =
        request.current_generation == request.generation && request.current_epoch == request.epoch;
    let evidence_verified = request.evidence_status == "VERIFIED"
        && request
            .receipt_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    let receipt_matches = request.receipt_attempt_id.as_deref()
        == Some(request.attempt_id.as_str())
        && request.receipt_generation == Some(request.generation)
        && request.receipt_epoch == Some(request.epoch)
        && request.receipt_session_id.as_deref() == request.native_session_id.as_deref();
    let kind = if identity_valid
        && fence_matches
        && request.requested_kind == ResumeKind::NativeResume
        && native_resume_verified
        && evidence_verified
        && receipt_matches
        && request
            .native_session_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        ResumeKind::NativeResume
    } else if identity_valid && request.requested_kind == ResumeKind::NewAttempt {
        ResumeKind::NewAttempt
    } else {
        ResumeKind::Unsupported
    };
    let reason_code = if !identity_valid {
        "INVALID_RESUME_IDENTITY"
    } else {
        match kind {
            ResumeKind::NativeResume => "CURRENT_RECEIPT",
            ResumeKind::NewAttempt => "FRESH_ATTEMPT",
            ResumeKind::Unsupported
                if request.requested_kind == ResumeKind::NativeResume && !evidence_verified =>
            {
                "RESUME_EVIDENCE_NOT_VERIFIED"
            }
            ResumeKind::Unsupported
                if request.requested_kind == ResumeKind::NativeResume
                    && (!fence_matches || !receipt_matches) =>
            {
                "RESUME_FENCE_MISMATCH"
            }
            ResumeKind::Unsupported => "NO_NATIVE_RESUME_RECEIPT",
        }
    }
    .into();
    ResumeDecision {
        schema_version: RESUME_SCHEMA.into(),
        attempt_id: request.attempt_id,
        generation: request.generation,
        epoch: request.epoch,
        kind,
        reason_code,
        evidence_status: request.evidence_status,
        receipt_ref: request.receipt_ref,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(kind: ResumeKind) -> ResumeRequest {
        ResumeRequest {
            schema_version: RESUME_SCHEMA.into(),
            attempt_id: "a".into(),
            generation: 1,
            epoch: 1,
            current_generation: 1,
            current_epoch: 1,
            native_session_id: Some("s".into()),
            requested_kind: kind,
            evidence_status: "NOT_RUN".into(),
            receipt_ref: None,
            receipt_attempt_id: None,
            receipt_generation: None,
            receipt_epoch: None,
            receipt_session_id: None,
        }
    }
    #[test]
    fn unsupported_resume_never_becomes_a_rerun_success() {
        let result = decide(request(ResumeKind::NativeResume), false);
        assert_eq!(result.kind, ResumeKind::Unsupported);
        assert_eq!(result.reason_code, "RESUME_EVIDENCE_NOT_VERIFIED");
    }
    #[test]
    fn fresh_attempt_is_explicitly_distinct() {
        let mut value = request(ResumeKind::NewAttempt);
        value.native_session_id = None;
        let result = decide(value, false);
        assert_eq!(result.kind, ResumeKind::NewAttempt);
        assert_eq!(result.reason_code, "FRESH_ATTEMPT");
    }
    #[test]
    fn native_resume_requires_verified_receipt_and_contract_identity() {
        let mut value = request(ResumeKind::NativeResume);
        value.evidence_status = "VERIFIED".into();
        value.receipt_ref = Some("receipt-1".into());
        value.receipt_attempt_id = Some("a".into());
        value.receipt_generation = Some(1);
        value.receipt_epoch = Some(1);
        value.receipt_session_id = Some("s".into());
        assert_eq!(decide(value.clone(), true).kind, ResumeKind::NativeResume);
        value.receipt_ref = None;
        assert_eq!(
            decide(value, true).reason_code,
            "RESUME_EVIDENCE_NOT_VERIFIED"
        );
    }

    #[test]
    fn stale_authoritative_generation_cannot_resume_a_native_session() {
        let mut value = request(ResumeKind::NativeResume);
        value.evidence_status = "VERIFIED".into();
        value.receipt_ref = Some("receipt-1".into());
        value.receipt_attempt_id = Some("a".into());
        value.receipt_generation = Some(1);
        value.receipt_epoch = Some(1);
        value.receipt_session_id = Some("s".into());
        value.current_generation = 2;
        assert_eq!(decide(value, true).kind, ResumeKind::Unsupported);
        assert_eq!(
            decide(request(ResumeKind::NativeResume), false).reason_code,
            "RESUME_EVIDENCE_NOT_VERIFIED"
        );
    }

    #[test]
    fn receipt_identity_must_bind_attempt_generation_epoch_and_session() {
        let mut value = request(ResumeKind::NativeResume);
        value.evidence_status = "VERIFIED".into();
        value.receipt_ref = Some("receipt-1".into());
        value.receipt_attempt_id = Some("other-attempt".into());
        value.receipt_generation = Some(1);
        value.receipt_epoch = Some(1);
        value.receipt_session_id = Some("s".into());
        assert_eq!(decide(value, true).reason_code, "RESUME_FENCE_MISMATCH");
    }

    #[test]
    fn resume_wire_contract_round_trips_fence_and_receipt_identity() {
        let mut value = request(ResumeKind::NativeResume);
        value.evidence_status = "VERIFIED".into();
        value.receipt_ref = Some("receipt-1".into());
        value.receipt_attempt_id = Some("a".into());
        value.receipt_generation = Some(1);
        value.receipt_epoch = Some(1);
        value.receipt_session_id = Some("s".into());
        let encoded = serde_json::to_value(&value).expect("resume request serializes");
        assert_eq!(encoded["resume_kind"], "NATIVE_RESUME");
        assert_eq!(encoded["current_generation"], 1);
        assert_eq!(encoded["receipt_attempt_id"], "a");
        let decoded: ResumeRequest =
            serde_json::from_value(encoded).expect("resume request parses");
        assert_eq!(decoded, value);
    }
    #[test]
    fn invalid_identity_cannot_become_a_fresh_attempt() {
        let mut value = request(ResumeKind::NewAttempt);
        value.schema_version = "old".into();
        value.attempt_id.clear();
        value.generation = 0;
        value.epoch = 0;
        let result = decide(value, false);
        assert_eq!(result.kind, ResumeKind::Unsupported);
        assert_eq!(result.reason_code, "INVALID_RESUME_IDENTITY");
    }
}
