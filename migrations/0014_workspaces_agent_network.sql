-- Personal accounts and collaboration are separate from execution authority.
CREATE TABLE accounts (
  account_id text PRIMARY KEY,
  email text NOT NULL UNIQUE CHECK (email = lower(email)),
  display_name text NOT NULL,
  password_hash text NOT NULL,
  session_epoch bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE workspaces (
  workspace_id text PRIMARY KEY,
  name text NOT NULL,
  created_by text REFERENCES accounts(account_id),
  request_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(created_by,request_key)
);
INSERT INTO workspaces(workspace_id,name) VALUES ('legacy','原有管理员工作区');
CREATE TABLE workspace_members (
  workspace_id text NOT NULL REFERENCES workspaces(workspace_id),
  account_id text NOT NULL REFERENCES accounts(account_id),
  role text NOT NULL CHECK (role IN ('OWNER','EDITOR','VIEWER')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(workspace_id,account_id)
);
CREATE INDEX workspace_members_account ON workspace_members(account_id,workspace_id);
CREATE TABLE workspace_invitations (
  invitation_id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(workspace_id),
  token_hash text NOT NULL UNIQUE,
  role text NOT NULL CHECK (role IN ('EDITOR','VIEWER')),
  invited_email text,
  created_by text NOT NULL REFERENCES accounts(account_id),
  expires_at timestamptz NOT NULL,
  accepted_by text REFERENCES accounts(account_id),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX workspace_invitations_workspace ON workspace_invitations(workspace_id,created_at);
CREATE TABLE project_workspaces (
  project_id text PRIMARY KEY REFERENCES projects(project_id),
  workspace_id text NOT NULL REFERENCES workspaces(workspace_id)
);
CREATE INDEX project_workspaces_workspace ON project_workspaces(workspace_id,project_id);
INSERT INTO project_workspaces SELECT project_id,'legacy' FROM projects;
CREATE FUNCTION bind_project_workspace() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO project_workspaces(project_id,workspace_id)
  VALUES (NEW.project_id,COALESCE(NULLIF(current_setting('forgeflow.workspace_id',true),''),'legacy'));
  RETURN NEW;
END $$;
CREATE TRIGGER bind_project_workspace AFTER INSERT ON projects
  FOR EACH ROW EXECUTE FUNCTION bind_project_workspace();
CREATE TABLE agent_integrations (
  integration_id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts(account_id),
  workspace_id text NOT NULL REFERENCES workspaces(workspace_id),
  project_id text NOT NULL REFERENCES project_workspaces(project_id),
  name text NOT NULL,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_integrations_account ON agent_integrations(account_id,project_id);
CREATE TABLE network_agents (
  agent_id text PRIMARY KEY,
  integration_id text NOT NULL REFERENCES agent_integrations(integration_id),
  account_id text NOT NULL REFERENCES accounts(account_id),
  workspace_id text NOT NULL REFERENCES workspaces(workspace_id),
  project_id text NOT NULL REFERENCES projects(project_id),
  native_agent_id text NOT NULL,
  name text NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(integration_id,native_agent_id)
);
CREATE INDEX network_agents_project ON network_agents(project_id,account_id,agent_id);
CREATE TABLE agent_messages (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  message_id text NOT NULL UNIQUE,
  workspace_id text NOT NULL REFERENCES workspaces(workspace_id),
  project_id text NOT NULL REFERENCES projects(project_id),
  sender_account_id text NOT NULL REFERENCES accounts(account_id),
  sender_agent_id text REFERENCES network_agents(agent_id),
  recipient_agent_id text NOT NULL REFERENCES network_agents(agent_id),
  client_message_id text NOT NULL,
  request_hash text NOT NULL,
  thread_id text NOT NULL,
  reply_to text REFERENCES agent_messages(message_id),
  parts jsonb NOT NULL CHECK (jsonb_typeof(parts)='array'),
  trace_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  received_at timestamptz,
  UNIQUE(sender_account_id,project_id,client_message_id)
);
CREATE INDEX agent_messages_project_cursor ON agent_messages(project_id,sequence);
CREATE INDEX agent_messages_inbox_cursor ON agent_messages(recipient_agent_id,sequence);
