-- ECP Phase 6 resource/cost governance contract. Additive only: existing
-- resource_limits, leases, gateway budgets and model settlements remain the
-- execution authority until a runtime adapter binds these tables.
CREATE TABLE ecp_resource_profiles (
  profile_id TEXT PRIMARY KEY,
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  profile_version TEXT NOT NULL,
  logical_limits JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(logical_limits)='object'),
  physical_limits JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(physical_limits)='object'),
  enforcement_status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (enforcement_status IN ('ENFORCED','OBSERVED','UNKNOWN','BLOCKED')),
  source_sha256 TEXT NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(workspace_id,profile_version,source_sha256)
);
CREATE INDEX ecp_resource_profiles_scope ON ecp_resource_profiles(workspace_id,enforcement_status,profile_id);

CREATE TABLE ecp_budget_reservations (
  reservation_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  project_id TEXT REFERENCES projects(project_id),
  principal_id TEXT REFERENCES principals(principal_id),
  attempt_id TEXT REFERENCES attempts(attempt_id),
  profile_id TEXT REFERENCES ecp_resource_profiles(profile_id),
  dimension TEXT NOT NULL CHECK (dimension IN ('active_slot','coding_slot','cpu_units','memory_bytes','gpu_units','provider_inflight','model_tokens','model_cost')),
  amount NUMERIC NOT NULL CHECK (amount>0),
  reserved_amount NUMERIC NOT NULL CHECK (reserved_amount>=0 AND reserved_amount<=amount),
  state TEXT NOT NULL DEFAULT 'RESERVED' CHECK (state IN ('RESERVED','HELD','SETTLED','RELEASED','QUARANTINED','UNKNOWN')),
  idempotency_key TEXT NOT NULL,
  authorization_epoch BIGINT NOT NULL CHECK (authorization_epoch>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  released_at TIMESTAMPTZ,
  UNIQUE(workspace_id,idempotency_key,dimension)
);
CREATE INDEX ecp_budget_reservations_active ON ecp_budget_reservations(workspace_id,dimension,state,reservation_id);

CREATE TABLE ecp_cost_ledger (
  ledger_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  project_id TEXT REFERENCES projects(project_id),
  attempt_id TEXT REFERENCES attempts(attempt_id),
  reservation_id TEXT REFERENCES ecp_budget_reservations(reservation_id),
  provider_request_id TEXT,
  currency TEXT NOT NULL DEFAULT 'UNKNOWN',
  estimated_cost NUMERIC,
  settled_cost NUMERIC,
  usage JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(usage)='object'),
  settlement_status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (settlement_status IN ('ADMITTED','SETTLED','PARTIAL','UNKNOWN','QUARANTINED','REJECTED')),
  source_sha256 TEXT CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  settled_at TIMESTAMPTZ,
  UNIQUE(workspace_id,provider_request_id)
);
CREATE INDEX ecp_cost_ledger_scope ON ecp_cost_ledger(workspace_id,settlement_status,created_at,ledger_id);

CREATE TABLE ecp_lease_revocations (
  revocation_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  lease_id TEXT REFERENCES leases(lease_id),
  principal_id TEXT REFERENCES principals(principal_id),
  generation BIGINT NOT NULL CHECK (generation>0),
  reason_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (status IN ('REQUESTED','OBSERVED','STOPPED','UNKNOWN','FAILED')),
  source_sha256 TEXT NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  observed_at TIMESTAMPTZ
);
CREATE INDEX ecp_lease_revocations_scope ON ecp_lease_revocations(workspace_id,status,created_at,revocation_id);
