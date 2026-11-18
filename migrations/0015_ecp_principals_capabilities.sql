-- ECP Phase 1 identity foundation. Existing account/workspace/network identities
-- remain compatible; this migration adds one immutable principal authority and
-- transactional capability/revocation facts.
ALTER TABLE workspace_members
  ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS authorization_epoch BIGINT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('HUMAN','MANAGED_AGENT','NATIVE_AGENT','WORKER','BOT','CONNECTOR')),
  account_id TEXT REFERENCES accounts(account_id),
  integration_id TEXT REFERENCES agent_integrations(integration_id),
  network_agent_id TEXT REFERENCES network_agents(agent_id),
  worker_id TEXT REFERENCES workers(worker_id),
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED','QUARANTINED')),
  authorization_epoch BIGINT NOT NULL DEFAULT 1 CHECK (authorization_epoch > 0),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  CHECK (num_nonnulls(account_id,integration_id,network_agent_id,worker_id)>=1)
);
CREATE UNIQUE INDEX principals_human_account ON principals(account_id) WHERE kind='HUMAN';
CREATE UNIQUE INDEX principals_integration ON principals(integration_id) WHERE integration_id IS NOT NULL AND kind='CONNECTOR';
CREATE UNIQUE INDEX principals_network_agent ON principals(network_agent_id) WHERE network_agent_id IS NOT NULL;
CREATE UNIQUE INDEX principals_worker ON principals(worker_id) WHERE worker_id IS NOT NULL;
CREATE INDEX principals_workspace_status ON principals(workspace_id,status,kind,principal_id);

INSERT INTO principals(principal_id,kind,account_id,workspace_id,display_name)
SELECT 'human:'||a.account_id,'HUMAN',a.account_id,
       (SELECT wm.workspace_id FROM workspace_members wm WHERE wm.account_id=a.account_id ORDER BY wm.joined_at,wm.workspace_id LIMIT 1),
       a.display_name
FROM accounts a
ON CONFLICT (principal_id) DO NOTHING;
INSERT INTO principals(principal_id,kind,integration_id,account_id,workspace_id,display_name,status)
SELECT 'connector:'||i.integration_id,'CONNECTOR',i.integration_id,i.account_id,i.workspace_id,i.name,
       CASE WHEN i.disabled_at IS NULL THEN 'ACTIVE' ELSE 'REVOKED' END
FROM agent_integrations i
ON CONFLICT (principal_id) DO NOTHING;
INSERT INTO principals(principal_id,kind,network_agent_id,integration_id,account_id,workspace_id,display_name)
SELECT 'agent:'||n.agent_id,'NATIVE_AGENT',n.agent_id,n.integration_id,n.account_id,n.workspace_id,n.name
FROM network_agents n
ON CONFLICT (principal_id) DO NOTHING;

CREATE TABLE capability_grants (
  grant_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  issuer_principal_id TEXT REFERENCES principals(principal_id),
  parent_grant_id TEXT REFERENCES capability_grants(grant_id),
  action_set JSONB NOT NULL CHECK (jsonb_typeof(action_set)='array'),
  project_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(project_set)='array'),
  write_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(write_set)='array'),
  executor_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(executor_set)='array'),
  budget JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(budget)='object'),
  authorization_epoch BIGINT NOT NULL CHECK (authorization_epoch > 0),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  request_key TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(workspace_id,principal_id,request_key)
);
CREATE INDEX capability_grants_active ON capability_grants(workspace_id,principal_id,revoked_at,expires_at);

CREATE TABLE workspace_security_events (
  event_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  principal_id TEXT REFERENCES principals(principal_id),
  kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  object_revision BIGINT NOT NULL CHECK (object_revision > 0),
  payload JSONB NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX workspace_security_events_cursor ON workspace_security_events(workspace_id,occurred_at,event_id);
CREATE TABLE workspace_security_outbox (
  outbox_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES workspace_security_events(event_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  kind TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  delivered_at TIMESTAMPTZ,
  UNIQUE(event_id,kind)
);
CREATE INDEX workspace_security_outbox_pending ON workspace_security_outbox(created_at) WHERE delivered_at IS NULL;
