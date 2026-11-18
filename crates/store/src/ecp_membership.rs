//! Shared Phase 1 membership invariants.
//!
//! Workspace membership remains authoritative in `workspace_members`; this
//! module only centralizes the revision/active-row rules used by command
//! handlers so a revoked row cannot be mistaken for a live grant.

use crate::{Result, err};

pub fn require_expected_revision(expected: Option<i64>, current: i64) -> Result<()> {
    if current < 1 {
        return Err(err(
            "CORRUPT_AUTHORITY",
            "membership revision must be positive",
        ));
    }
    if let Some(expected) = expected {
        if expected < 1 || expected != current {
            return Err(err(
                "REVISION_CONFLICT",
                "workspace membership revision changed",
            ));
        }
    }
    Ok(())
}

pub fn active(role: Option<&str>, revoked_at_present: bool) -> bool {
    role.is_some() && !revoked_at_present
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_revision_is_fail_closed() {
        assert!(require_expected_revision(Some(3), 3).is_ok());
        assert!(require_expected_revision(Some(2), 3).is_err());
        assert!(require_expected_revision(Some(0), 3).is_err());
        assert!(require_expected_revision(None, 1).is_ok());
    }

    #[test]
    fn revoked_rows_are_never_active() {
        assert!(active(Some("EDITOR"), false));
        assert!(!active(Some("EDITOR"), true));
        assert!(!active(None, false));
    }
}
