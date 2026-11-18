-- Persist delivery receipt idempotency and bind retries to their exact payload.
CREATE TABLE ecp_delivery_receipt_commands (
  command_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES ecp_deliveries(delivery_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 16 AND 128),
  receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('RECEIVED','READ','PROCESSING','PROCESSED','REJECTED')),
  data_sha256 TEXT NOT NULL CHECK (data_sha256 ~ '^[a-f0-9]{64}$'),
  result JSONB NOT NULL CHECK (jsonb_typeof(result)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (delivery_id,principal_id,request_key)
);
CREATE INDEX ecp_delivery_receipt_commands_delivery
  ON ecp_delivery_receipt_commands(delivery_id,created_at);
