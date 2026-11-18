ALTER TABLE resource_scopes ADD COLUMN worker_id TEXT REFERENCES workers(worker_id);
CREATE UNIQUE INDEX unique_resource_team_scope ON resource_scopes(project_id,team_id) WHERE team_id IS NOT NULL;
CREATE UNIQUE INDEX unique_resource_worker_scope ON resource_scopes(worker_id) WHERE worker_id IS NOT NULL;
CREATE TABLE schedule_baselines(project_id TEXT NOT NULL REFERENCES projects,baseline_version BIGINT NOT NULL CHECK(baseline_version>0),schedule_id TEXT NOT NULL,data JSONB NOT NULL,PRIMARY KEY(project_id,baseline_version,schedule_id));
