-- ECP Phase 2 registry. Discovery is separate from authority: a registered
-- agent/profile never grants execution by itself.
CREATE TABLE agent_registrations (
  registration_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  owner_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  display_name TEXT NOT NULL,
  executor_kinds JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(executor_kinds)='array'),
  project_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(project_set)='array'),
  status TEXT NOT NULL DEFAULT 'REGISTERED' CHECK (status IN ('REGISTERED','QUALIFYING','AVAILABLE','BUSY','DRAINING','OFFLINE','QUARANTINED','REVOKED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision>0),
  request_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(workspace_id,principal_id,request_key)
);
CREATE INDEX agent_registrations_workspace_status ON agent_registrations(workspace_id,status,registration_id);

CREATE TABLE executor_profile_registry (
  profile_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  registration_id TEXT NOT NULL REFERENCES agent_registrations(registration_id),
  provider TEXT NOT NULL,
  profile_version TEXT NOT NULL,
  binary_digest TEXT NOT NULL CHECK(binary_digest ~ '^[0-9a-f]{64}$'),
  adapter_digest TEXT NOT NULL CHECK(adapter_digest ~ '^[0-9a-f]{64}$'),
  configuration_digest TEXT NOT NULL CHECK(configuration_digest ~ '^[0-9a-f]{64}$'),
  capabilities JSONB NOT NULL CHECK(jsonb_typeof(capabilities)='object'),
  support_status TEXT NOT NULL CHECK(support_status IN ('SUPPORTED','PARTIAL','UNSUPPORTED','UNKNOWN')),
  evidence_status TEXT NOT NULL CHECK(evidence_status IN ('VERIFIED','FAILED','INCONCLUSIVE','NOT_RUN','BLOCKED')),
  status TEXT NOT NULL DEFAULT 'FROZEN' CHECK(status IN ('DRAFT','FROZEN','REVOKED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(workspace_id,registration_id,profile_version,binary_digest,adapter_digest,configuration_digest)
);
CREATE INDEX executor_profile_registry_workspace ON executor_profile_registry(workspace_id,provider,support_status,evidence_status);

CREATE TABLE worker_profile_bindings (
  binding_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  worker_id TEXT NOT NULL REFERENCES workers(worker_id),
  profile_id TEXT NOT NULL REFERENCES executor_profile_registry(profile_id),
  status TEXT NOT NULL DEFAULT 'BOUND' CHECK(status IN ('BOUND','DRAINING','REVOKED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(workspace_id,worker_id,profile_id)
);
CREATE INDEX worker_profile_bindings_lookup ON worker_profile_bindings(workspace_id,worker_id,status);
