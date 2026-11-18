//! Store-side admission contract shared by scheduler and API consumers. The
//! final transaction still rechecks the authoritative profile row.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAdmissionInput {
    pub workspace_id: String,
    pub profile_id: String,
    pub profile_revision: i64,
    pub expected_revision: i64,
    pub binary_digest: String,
    pub adapter_digest: String,
    pub configuration_digest: String,
    pub support_status: String,
    pub evidence_status: String,
}

pub fn validate(input: &ProfileAdmissionInput) -> Result<(), &'static str> {
    if input.expected_revision != input.profile_revision {
        return Err("REVISION_CONFLICT");
    }
    if input.profile_revision < 1 {
        return Err("INVALID_PROFILE_REVISION");
    }
    for digest in [
        &input.binary_digest,
        &input.adapter_digest,
        &input.configuration_digest,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("PROFILE_DIGEST_INVALID");
        }
    }
    if input.support_status != "SUPPORTED" || input.evidence_status != "VERIFIED" {
        return Err("PROFILE_EVIDENCE_NOT_VERIFIED");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_rejects_unknown_evidence_and_revision_drift() {
        let mut input = ProfileAdmissionInput {
            workspace_id: "w".into(),
            profile_id: "p".into(),
            profile_revision: 2,
            expected_revision: 2,
            binary_digest: "a".repeat(64),
            adapter_digest: "b".repeat(64),
            configuration_digest: "c".repeat(64),
            support_status: "SUPPORTED".into(),
            evidence_status: "VERIFIED".into(),
        };
        assert!(validate(&input).is_ok());
        input.expected_revision = 1;
        assert_eq!(validate(&input), Err("REVISION_CONFLICT"));
        input.expected_revision = 2;
        input.evidence_status = "NOT_RUN".into();
        assert_eq!(validate(&input), Err("PROFILE_EVIDENCE_NOT_VERIFIED"));
    }
}
