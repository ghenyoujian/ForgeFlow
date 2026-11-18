//! ECP account-session fence backed by the PostgreSQL account epoch.
use super::*;

pub const SESSION_CONTRACT: &str = "forgeflow.ecp.account-session.v1";

impl Store {
    pub async fn require_account_session_epoch(
        &self,
        account: &str,
        expected_epoch: i64,
    ) -> Result<()> {
        if expected_epoch <= 0 {
            return Err(err("SESSION_REVOKED", "account session epoch is invalid"));
        }
        match self.account_epoch(account).await? {
            Some(actual) if actual == expected_epoch => Ok(()),
            Some(_) | None => Err(err(
                "SESSION_REVOKED",
                "account credential was revoked; sign in again",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_contract_is_versioned() {
        assert!(super::SESSION_CONTRACT.ends_with("account-session.v1"));
    }
}
