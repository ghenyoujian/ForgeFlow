-- Logical archive only: immutable event identity, payload, time and sequence stay
-- in their original rows and remain available to historical queries/backups.
ALTER TABLE events ADD COLUMN archived_at TIMESTAMPTZ;
CREATE INDEX events_hot_replay ON events(project_id,project_seq)
    WHERE archived_at IS NULL;
