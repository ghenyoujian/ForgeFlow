//! API-facing connector contract helpers. Durable connector routes remain in
//! agent_network.rs; this module documents the ECP identity boundary.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationReceipt {
    pub protocol: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub token_sha256: String,
    pub status: String,
}

pub fn registration_receipt(
    principal_id: &str,
    workspace_id: &str,
    project_id: &str,
    token: &[u8],
) -> Result<RegistrationReceipt, String> {
    if principal_id.is_empty()
        || workspace_id.is_empty()
        || project_id.is_empty()
        || token.len() < 16
    {
        return Err("REGISTRATION_IDENTITY_INVALID".into());
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
    fn connector_receipt_binds_scope_without_claiming_qualification() {
        let receipt = registration_receipt(
            "connector:i-1",
            "workspace-1",
            "project-1",
            b"0123456789abcdef",
        )
        .expect("valid connector token should produce a receipt");
        assert_eq!(receipt.protocol, "forgeflow.agent-network.v1");
        assert_eq!(receipt.workspace_id, "workspace-1");
        assert_eq!(receipt.project_id, "project-1");
        assert_eq!(receipt.status, "REGISTERED_NOT_QUALIFIED");
        assert_eq!(receipt.token_sha256.len(), 64);
    }

    #[test]
    fn connector_receipt_rejects_short_credentials() {
        assert_eq!(
            registration_receipt("connector:i-1", "w", "p", b"short").unwrap_err(),
            "REGISTRATION_IDENTITY_INVALID"
        );
    }
}
