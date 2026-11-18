//! Embedded Bot wake-up contract. Message delivery is durable in the Core;
//! this module only decides whether a bot wake is admissible.
use crate::ExecutorError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotWakeRequest {
    pub bot_principal_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub payload_sha256: String,
    pub generation: i64,
    pub capability_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotWakeDecision {
    pub accepted: bool,
    pub reason_code: String,
    pub message_id: String,
    pub payload_sha256: String,
}

pub fn validate_wake(
    request: &BotWakeRequest,
    payload: &[u8],
    bot_epoch: i64,
) -> Result<BotWakeDecision, ExecutorError> {
    if request.generation < 1 || request.capability_epoch != bot_epoch {
        return Err(ExecutorError::Identity(
            "bot generation or capability epoch is stale".into(),
        ));
    }
    if request.bot_principal_id.is_empty()
        || request.conversation_id.is_empty()
        || request.message_id.is_empty()
    {
        return Err(ExecutorError::InvalidEnvelope(
            "bot wake identity is incomplete".into(),
        ));
    }
    let digest = format!("{:x}", Sha256::digest(payload));
    if digest != request.payload_sha256 {
        return Err(ExecutorError::InvalidEnvelope(
            "bot wake payload digest mismatch".into(),
        ));
    }
    Ok(BotWakeDecision {
        accepted: false,
        reason_code: "PLATFORM_DISPATCH_REQUIRED".into(),
        message_id: request.message_id.clone(),
        payload_sha256: digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bot_wake_requires_digest_and_epoch() {
        let payload = b"hello";
        let request = BotWakeRequest {
            bot_principal_id: "bot:1".into(),
            conversation_id: "c".into(),
            message_id: "m".into(),
            payload_sha256: format!("{:x}", Sha256::digest(payload)),
            generation: 1,
            capability_epoch: 2,
        };
        assert!(validate_wake(&request, payload, 1).is_err());
        assert!(validate_wake(&request, payload, 2).unwrap().accepted == false);
    }
}
