ALTER TABLE attempts ADD CONSTRAINT terminal_state_has_timestamp CHECK ((state IN('SUCCEEDED','FAILED','CANCELLED')) = (terminal_at IS NOT NULL));
ALTER TABLE attempts ADD CONSTRAINT attempt_data_identity CHECK (data->>'project_id'=project_id AND data->>'attempt_id'=attempt_id AND data->>'task_id'=task_id AND data->>'state'=state AND (data->>'generation')::bigint=generation);
ALTER TABLE attempts ADD CONSTRAINT unique_attempt_lease_binding UNIQUE(attempt_id,generation,worker_id);
ALTER TABLE leases ADD CONSTRAINT lease_attempt_identity FOREIGN KEY(attempt_id,generation,worker_id) REFERENCES attempts(attempt_id,generation,worker_id);
ALTER TABLE resource_allocations ADD CONSTRAINT released_allocation_has_timestamp CHECK ((state='RELEASED') = (released_at IS NOT NULL));
ALTER TABLE resource_scopes ADD CONSTRAINT resource_scope_class CHECK ((team_id IS NULL OR project_id IS NOT NULL) AND (worker_id IS NULL OR (project_id IS NULL AND team_id IS NULL)) AND (parent_scope_id IS NULL OR parent_scope_id<>scope_id));
