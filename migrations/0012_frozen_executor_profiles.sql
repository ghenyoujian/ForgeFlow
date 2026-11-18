-- New attempts share exact admitted executor bytes. Historical inline bindings
-- are deliberately not rewritten, resealed or assigned synthetic references.
CREATE TABLE frozen_executor_profiles (
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    data JSONB NOT NULL CHECK (jsonb_typeof(data) = 'object'),
    PRIMARY KEY (project_id, sha256)
);

CREATE FUNCTION reject_frozen_executor_profile_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'frozen executor profiles are append only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER frozen_executor_profiles_immutable
BEFORE UPDATE OR DELETE ON frozen_executor_profiles
FOR EACH ROW EXECUTE FUNCTION reject_frozen_executor_profile_mutation();

CREATE TRIGGER frozen_executor_profiles_no_truncate
BEFORE TRUNCATE ON frozen_executor_profiles
FOR EACH STATEMENT EXECUTE FUNCTION reject_frozen_executor_profile_mutation();

ALTER TABLE attempts ADD COLUMN executor_profile_sha256 TEXT;
ALTER TABLE attempts ADD CONSTRAINT attempts_executor_profile_object_fk
    FOREIGN KEY (project_id, executor_profile_sha256)
    REFERENCES frozen_executor_profiles(project_id, sha256)
    ON UPDATE RESTRICT ON DELETE RESTRICT;
ALTER TABLE attempts ADD CONSTRAINT attempts_executor_profile_single_representation
    CHECK (executor_profile_sha256 IS NULL OR NOT (execution_bindings ? 'executor_profile'));

CREATE FUNCTION reject_attempt_executor_profile_rebinding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.executor_profile_sha256 IS DISTINCT FROM NEW.executor_profile_sha256 THEN
        RAISE EXCEPTION 'attempt executor profile reference is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER attempts_executor_profile_reference_immutable
BEFORE UPDATE OF executor_profile_sha256 ON attempts
FOR EACH ROW EXECUTE FUNCTION reject_attempt_executor_profile_rebinding();
