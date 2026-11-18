-- ECP Phase 8 release/restore qualification facts. No row grants release authority.
CREATE TABLE ecp_release_candidates (
  candidate_id TEXT PRIMARY KEY,
  source_sha TEXT NOT NULL,
  source_manifest_sha256 TEXT NOT NULL CHECK(source_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  binary_manifest_sha256 TEXT NOT NULL CHECK(binary_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  schema_manifest_sha256 TEXT NOT NULL CHECK(schema_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  profile_manifest_sha256 TEXT NOT NULL CHECK(profile_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  evidence_manifest_sha256 TEXT NOT NULL CHECK(evidence_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  status TEXT NOT NULL CHECK(status IN ('CANDIDATE','VERIFIED','REJECTED','APPROVED')),
  gate_snapshot JSONB NOT NULL CHECK(jsonb_typeof(gate_snapshot)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  verified_at TIMESTAMPTZ,
  approved_at TIMESTAMPTZ
);
CREATE TABLE ecp_restore_rehearsals (
  rehearsal_id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL REFERENCES ecp_release_candidates(candidate_id),
  backup_manifest_sha256 TEXT NOT NULL CHECK(backup_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  database_schema_sha256 TEXT NOT NULL CHECK(database_schema_sha256 ~ '^[a-f0-9]{64}$'),
  artifact_manifest_sha256 TEXT NOT NULL CHECK(artifact_manifest_sha256 ~ '^[a-f0-9]{64}$'),
  rpo_seconds BIGINT NOT NULL CHECK(rpo_seconds>=0),
  rto_seconds BIGINT NOT NULL CHECK(rto_seconds>=0),
  old_lease_count BIGINT NOT NULL CHECK(old_lease_count=0),
  status TEXT NOT NULL CHECK(status IN ('NOT_RUN','BLOCKED','INCONCLUSIVE','PASS','FAIL')),
  data JSONB NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(data)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE ecp_upgrade_rehearsals (
  rehearsal_id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL REFERENCES ecp_release_candidates(candidate_id),
  from_version TEXT NOT NULL,
  to_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('NOT_RUN','BLOCKED','INCONCLUSIVE','PASS','FAIL')),
  rollback_verified BOOLEAN NOT NULL DEFAULT false,
  data JSONB NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(data)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
