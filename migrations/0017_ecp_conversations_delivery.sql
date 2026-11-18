-- ECP Phase 3 durable conversation and delivery schema.
-- This is additive to the 0014 network message surface and has no runtime
-- claim until producer/consumer/oracle tests bind the tables.
CREATE TABLE ecp_conversations (
  conversation_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  project_id TEXT REFERENCES projects(project_id),
  created_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','ARCHIVED','REVOKED')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  next_sequence BIGINT NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  archived_at TIMESTAMPTZ
);
CREATE INDEX ecp_conversations_workspace ON ecp_conversations(workspace_id,created_at,conversation_id);
CREATE INDEX ecp_conversations_project ON ecp_conversations(project_id,created_at,conversation_id);

CREATE TABLE ecp_conversation_participants (
  conversation_id TEXT NOT NULL REFERENCES ecp_conversations(conversation_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  role TEXT NOT NULL DEFAULT 'MEMBER' CHECK (role IN ('OWNER','MEMBER','OBSERVER')),
  joined_revision BIGINT NOT NULL DEFAULT 1 CHECK (joined_revision > 0),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  last_ack_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_ack_sequence >= 0),
  PRIMARY KEY (conversation_id,principal_id)
);
CREATE INDEX ecp_conversation_participants_active ON ecp_conversation_participants(conversation_id,revoked_at,principal_id);

CREATE TABLE ecp_threads (
  thread_id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES ecp_conversations(conversation_id),
  root_message_id TEXT,
  task_id TEXT,
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ecp_threads_conversation ON ecp_threads(conversation_id,created_at,thread_id);

CREATE TABLE ecp_messages (
  message_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  project_id TEXT REFERENCES projects(project_id),
  conversation_id TEXT NOT NULL REFERENCES ecp_conversations(conversation_id),
  thread_id TEXT NOT NULL REFERENCES ecp_threads(thread_id),
  sender_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  message_kind TEXT NOT NULL CHECK (length(message_kind) BETWEEN 1 AND 128),
  schema_version BIGINT NOT NULL CHECK (schema_version > 0),
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  correlation_id TEXT,
  causation_id TEXT,
  client_request_id TEXT NOT NULL CHECK (length(client_request_id) BETWEEN 16 AND 128),
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text) <= 262144),
  payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
  provenance JSONB NOT NULL CHECK (jsonb_typeof(provenance)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ,
  UNIQUE (conversation_id,sequence),
  UNIQUE (conversation_id,sender_principal_id,client_request_id)
);
CREATE INDEX ecp_messages_conversation_cursor ON ecp_messages(conversation_id,sequence);
CREATE INDEX ecp_messages_thread_cursor ON ecp_messages(thread_id,sequence);
CREATE INDEX ecp_messages_workspace_created ON ecp_messages(workspace_id,created_at,message_id);

CREATE TABLE ecp_deliveries (
  delivery_id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES ecp_messages(message_id),
  recipient_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','IN_FLIGHT','RETRY_WAIT','ACKED','EXPIRED','REVOKED','DEAD_LETTER','UNCONFIRMED')),
  attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ,
  first_sent_at TIMESTAMPTZ,
  acked_at TIMESTAMPTZ,
  last_error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (message_id,recipient_principal_id)
);
CREATE INDEX ecp_deliveries_queue ON ecp_deliveries(state,next_attempt_at,delivery_id);
CREATE INDEX ecp_deliveries_recipient ON ecp_deliveries(recipient_principal_id,state,created_at);

CREATE TABLE ecp_delivery_attempts (
  delivery_attempt_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES ecp_deliveries(delivery_id),
  attempt_number BIGINT NOT NULL CHECK (attempt_number > 0),
  generation BIGINT NOT NULL CHECK (generation > 0),
  state TEXT NOT NULL CHECK (state IN ('CLAIMED','SENT','RECEIVED','FAILED','UNCONFIRMED')),
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at TIMESTAMPTZ,
  error_code TEXT,
  UNIQUE (delivery_id,attempt_number)
);

CREATE TABLE ecp_delivery_receipts (
  receipt_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES ecp_deliveries(delivery_id),
  receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('RECEIVED','READ','PROCESSING','PROCESSED','REJECTED')),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  receipt_revision BIGINT NOT NULL DEFAULT 1 CHECK (receipt_revision > 0),
  data JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (delivery_id,receipt_kind,receipt_revision)
);

CREATE TABLE ecp_inbox_checkpoints (
  conversation_id TEXT NOT NULL REFERENCES ecp_conversations(conversation_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  acknowledged_sequence BIGINT NOT NULL DEFAULT 0 CHECK (acknowledged_sequence >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (conversation_id,principal_id)
);

CREATE TABLE ecp_message_outbox (
  outbox_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES ecp_deliveries(delivery_id),
  message_id TEXT NOT NULL REFERENCES ecp_messages(message_id),
  kind TEXT NOT NULL,
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  delivered_at TIMESTAMPTZ,
  claimed_by TEXT,
  UNIQUE (delivery_id,kind)
);
CREATE INDEX ecp_message_outbox_pending ON ecp_message_outbox(created_at,outbox_id) WHERE delivered_at IS NULL;

CREATE TABLE ecp_dead_letters (
  dead_letter_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES ecp_deliveries(delivery_id),
  reason_code TEXT NOT NULL,
  failure_count BIGINT NOT NULL CHECK (failure_count > 0),
  data JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  reissued_delivery_id TEXT
);
CREATE INDEX ecp_dead_letters_delivery ON ecp_dead_letters(delivery_id,created_at);
