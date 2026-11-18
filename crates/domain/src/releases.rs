use crate::{ArtifactRef, Project};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RELEASE_SCHEMA: &str = "forgeflow.release.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseState {
    Draft,
    Candidate,
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMilestoneBinding {
    pub milestone_id: String,
    pub milestone_revision: u64,
    pub baseline_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFileIdentity {
    pub artifact_id: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub release_id: String,
    pub project_id: String,
    pub phase_id: String,
    pub title: String,
    pub scope: String,
    pub main_sha: String,
    pub main_tree_oid: String,
    pub milestone_acceptances: Vec<Value>,
    pub files: Vec<ReleaseFileIdentity>,
    pub installation: String,
    pub not_proven: Vec<String>,
    pub risk_dispositions: Vec<String>,
    pub production_gate_claim: String,
    pub export_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema_version: String,
    pub release_id: String,
    pub project_id: String,
    pub phase_id: String,
    pub state: ReleaseState,
    pub revision: u64,
    pub title: String,
    pub milestone_refs: Vec<ReleaseMilestoneBinding>,
    pub installation: String,
    pub not_proven: Vec<String>,
    pub risk_dispositions: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub candidate_by: Option<String>,
    pub candidate_at: Option<DateTime<Utc>>,
    pub accepted_by: Option<String>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub acceptance_note: Option<String>,
    pub manifest: Option<ReleaseManifest>,
    pub manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPhase {
    pub schema_version: String,
    pub phase_id: String,
    pub project_id: String,
    pub ordinal: u64,
    pub previous_release_id: Option<String>,
    pub title: String,
    pub goal: String,
    pub baseline_main_sha: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseExportReceipt {
    pub schema_version: String,
    pub export_id: String,
    pub project_id: String,
    pub release_id: String,
    pub manifest_sha256: String,
    pub artifact: ArtifactRef,
    pub bytes: u64,
    pub bundle: ArtifactRef,
    pub bundle_bytes: u64,
    pub source_archive_sha256: String,
    pub exported_by: String,
    pub exported_at: DateTime<Utc>,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ReleaseCommand {
    CreateDraft {
        project_id: String,
        expected_project_revision: u64,
        title: String,
        milestone_refs: Vec<ReleaseMilestoneBinding>,
        installation: String,
        not_proven: Vec<String>,
        risk_dispositions: Vec<String>,
    },
    CreateCandidate {
        project_id: String,
        release_id: String,
        expected_revision: u64,
        expected_main_sha: String,
    },
    Accept {
        project_id: String,
        release_id: String,
        expected_revision: u64,
        expected_manifest_sha256: String,
        note: String,
    },
    RecordExport {
        project_id: String,
        release_id: String,
        expected_revision: u64,
        artifact_id: String,
        bundle_artifact_id: String,
    },
    Archive {
        project_id: String,
        release_id: String,
        expected_revision: u64,
        expected_project_revision: u64,
        reason: String,
    },
    Reopen {
        project_id: String,
        release_id: String,
        expected_revision: u64,
        expected_project_revision: u64,
        title: String,
        goal: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseOutcome {
    pub release: Release,
    pub project: Project,
    pub phase: ProjectPhase,
    pub export: Option<ReleaseExportReceipt>,
    /// Acceptance covers only the explicit manifest scope, never product Gates.
    pub accepted: bool,
}
