-- Persist conversation creation idempotency in the same command ledger used
-- by revoke/recovery.  Conversation IDs are immutable object identities; a
-- client retry must reuse its request key rather than silently replaying an
-- arbitrary create under the current ON CONFLICT path.
ALTER TABLE ecp_conversation_commands
  DROP CONSTRAINT IF EXISTS ecp_conversation_commands_command_kind_check;

ALTER TABLE ecp_conversation_commands
  ADD CONSTRAINT ecp_conversation_commands_command_kind_check
  CHECK (command_kind IN ('CREATE','REVOKE'));
