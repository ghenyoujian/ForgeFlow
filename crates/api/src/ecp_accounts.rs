//! ECP account/session boundary helpers.
//! HTTP login, logout and password rotation remain in `workspaces.rs`.
use super::*;

pub const SESSION_CONTRACT: &str = "forgeflow.ecp.account-session.v1";

pub fn session_revoked() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "SESSION_REVOKED",
        "账号凭据已撤销，请重新登录",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn contract_is_versioned() {
        assert!(super::SESSION_CONTRACT.ends_with("account-session.v1"));
    }
}
