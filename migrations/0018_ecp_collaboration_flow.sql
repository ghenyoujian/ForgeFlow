-- ECP Phase 4 collaboration contracts.  These are durable workflow facts only;
-- an assignment/proposal/decision never grants authority by itself.
CREATE TABLE ecp_assignments (
  assignment_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  project_id TEXT REFERENCES projects(project_id),
  task_id TEXT,
  issuer_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  assignee_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  parent_grant_id TEXT REFERENCES capability_grants(grant_id),
  action_set JSONB NOT NULL CHECK (jsonb_typeof(action_set)='array'),
  project_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(project_set)='array'),
  write_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(write_set)='array'),
  executor_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(executor_set)='array'),
  budget JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(budget)='object'),
  status TEXT NOT NULL DEFAULT 'OFFERED' CHECK (status IN ('OFFERED','ACCEPTED','DECLINED','REVOKED','EXPIRED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 16 AND 128),
  expected_revision BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ,
  UNIQUE(workspace_id,issuer_principal_id,request_key)
);
CREATE INDEX ecp_assignments_assignee ON ecp_assignments(workspace_id,assignee_principal_id,status,created_at);
CREATE INDEX ecp_assignments_task ON ecp_assignments(project_id,task_id,status,revision);

CREATE TABLE ecp_proposals (
  proposal_id TEXT PRIMARY KEY,
  assignment_id TEXT NOT NULL REFERENCES ecp_assignments(assignment_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  project_id TEXT REFERENCES projects(project_id),
  author_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  base_revision BIGINT NOT NULL CHECK (base_revision > 0),
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object'),
  payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
  write_set JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(write_set)='array'),
  budget JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(budget)='object'),
  status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','SUBMITTED','APPROVED','REJECTED','CHANGES_REQUESTED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(assignment_id,revision)
);
CREATE INDEX ecp_proposals_workspace_status ON ecp_proposals(workspace_id,status,created_at,proposal_id);

CREATE TABLE ecp_reviews (
  review_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL REFERENCES ecp_proposals(proposal_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  reviewer_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  decision TEXT NOT NULL CHECK (decision IN ('APPROVE','REJECT','REQUEST_CHANGES')),
  expected_revision BIGINT NOT NULL CHECK (expected_revision > 0),
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(proposal_id,reviewer_principal_id,expected_revision)
);
CREATE INDEX ecp_reviews_proposal ON ecp_reviews(proposal_id,created_at,review_id);

CREATE TABLE ecp_decisions (
  decision_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL REFERENCES ecp_proposals(proposal_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  issuer_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  outcome TEXT NOT NULL CHECK (outcome IN ('APPROVE','REJECT','REQUEST_CHANGES')),
  expected_revision BIGINT NOT NULL CHECK (expected_revision > 0),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  reason TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(proposal_id,revision)
);
CREATE INDEX ecp_decisions_workspace ON ecp_decisions(workspace_id,created_at,decision_id);

CREATE TABLE ecp_escalations (
  escalation_id TEXT PRIMARY KEY,
  assignment_id TEXT REFERENCES ecp_assignments(assignment_id),
  proposal_id TEXT REFERENCES ecp_proposals(proposal_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  raised_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  reason_code TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details)='object'),
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED','REJECTED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  resolved_at TIMESTAMPTZ,
  CHECK (assignment_id IS NOT NULL OR proposal_id IS NOT NULL)
);
CREATE INDEX ecp_escalations_workspace ON ecp_escalations(workspace_id,status,created_at,escalation_id);

CREATE TABLE ecp_collaboration_outbox (
  outbox_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  object_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  delivered_at TIMESTAMPTZ,
  UNIQUE(object_id,kind)
);
CREATE INDEX ecp_collaboration_outbox_pending ON ecp_collaboration_outbox(created_at,outbox_id) WHERE delivered_at IS NULL;
