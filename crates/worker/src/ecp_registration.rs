//! Worker/Connector registration contract. Registration is scoped to a
//! workspace/project and never grants a Worker model or write capability.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub protocol: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub token_sha256: String,
    pub status: String,
}

pub fn receipt(
    principal_id: &str,
    workspace_id: &str,
    project_id: &str,
    token: &[u8],
) -> Result<RegistrationReceipt, &'static str> {
    if principal_id.is_empty()
        || workspace_id.is_empty()
        || project_id.is_empty()
        || token.len() < 16
    {
        return Err("REGISTRATION_IDENTITY_INVALID");
    }
    Ok(RegistrationReceipt {
        protocol: "forgeflow.agent-network.v1".into(),
        principal_id: principal_id.into(),
        workspace_id: workspace_id.into(),
        project_id: project_id.into(),
        token_sha256: format!("{:x}", Sha256::digest(token)),
        status: "REGISTERED_NOT_QUALIFIED".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_receipt_is_scoped_and_hashed() {
        let r = receipt("connector:1", "w", "p", b"0123456789abcdef").unwrap();
        assert_eq!(r.protocol, "forgeflow.agent-network.v1");
        assert_eq!(r.token_sha256.len(), 64);
        assert!(receipt("connector:1", "w", "p", b"short").is_err());
    }
}
