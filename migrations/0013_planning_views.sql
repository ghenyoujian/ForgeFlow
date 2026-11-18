-- Filtered task lists and exact coverage read models. No execution state changes.
CREATE INDEX tasks_project_owner_key ON tasks(project_id,owner_id,task_id);
CREATE INDEX tasks_project_team_key ON tasks(project_id,team_id,task_id);
CREATE INDEX tasks_project_state_key ON tasks(project_id,state,task_id);
CREATE INDEX native_lifecycles_project_sessions ON native_child_lifecycles(project_id,attempt_id,native_session_id);
