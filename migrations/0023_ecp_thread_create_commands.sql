-- Persist ECP thread creation idempotency in the conversation command ledger.
ALTER TABLE ecp_conversation_commands
  DROP CONSTRAINT IF EXISTS ecp_conversation_commands_command_kind_check;

ALTER TABLE ecp_conversation_commands
  ADD CONSTRAINT ecp_conversation_commands_command_kind_check
  CHECK (command_kind IN ('CREATE','CREATE_THREAD','REVOKE'));
