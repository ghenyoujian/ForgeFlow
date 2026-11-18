ALTER TABLE workers ADD COLUMN project_id TEXT REFERENCES projects(project_id);
ALTER TABLE workers ADD COLUMN executor_profile_ids JSONB NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(executor_profile_ids)='array');
