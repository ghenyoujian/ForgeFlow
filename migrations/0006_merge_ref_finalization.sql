ALTER TABLE merge_intents DROP CONSTRAINT merge_intents_state_check;
ALTER TABLE merge_intents ADD CONSTRAINT merge_intents_state_check CHECK(state IN('PREPARED','COMMIT_DECIDED','REF_UPDATED','FINALIZED','COMMITTED','ABORTED','RECOVERY_REQUIRED'));
DROP INDEX one_unresolved_merge_per_ref;
CREATE UNIQUE INDEX one_unresolved_merge_per_ref ON merge_intents(project_id,target_ref) WHERE state IN('PREPARED','COMMIT_DECIDED','REF_UPDATED','RECOVERY_REQUIRED');
