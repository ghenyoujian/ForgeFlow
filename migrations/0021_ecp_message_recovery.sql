-- ECP Phase 3 recovery commands. Additive and append-only: command receipts
-- make cursor/check/claim/revoke retries idempotent without copying payloads.
CREATE TABLE ecp_checkpoint_commands (
  command_id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES ecp_conversations(conversation_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 16 AND 128),
  acknowledged_sequence BIGINT NOT NULL CHECK (acknowledged_sequence >= 0),
  result JSONB NOT NULL CHECK (jsonb_typeof(result)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (conversation_id,principal_id,request_key)
);

CREATE TABLE ecp_delivery_commands (
  command_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES ecp_deliveries(delivery_id),
  command_kind TEXT NOT NULL CHECK (command_kind IN ('CLAIM','FAIL')),
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 16 AND 128),
  generation BIGINT NOT NULL CHECK (generation > 0),
  result JSONB NOT NULL CHECK (jsonb_typeof(result)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (delivery_id,command_kind,request_key)
);
CREATE INDEX ecp_delivery_commands_delivery ON ecp_delivery_commands(delivery_id,created_at);

CREATE TABLE ecp_conversation_commands (
  command_id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES ecp_conversations(conversation_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  command_kind TEXT NOT NULL CHECK (command_kind IN ('REVOKE')),
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 16 AND 128),
  result JSONB NOT NULL CHECK (jsonb_typeof(result)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (conversation_id,principal_id,command_kind,request_key)
);
