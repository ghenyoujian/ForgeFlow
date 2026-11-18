-- Native DSH lifecycles are subordinate to one already admitted canonical Attempt.
-- Roots borrow the Attempt reservation; only children increase resource_limits.allocated.
ALTER TABLE attempts ADD CONSTRAINT native_parent_task_binding UNIQUE(project_id,attempt_id,task_id);
CREATE TABLE native_child_lifecycles (
    allocation_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation>0),
    worker_id TEXT NOT NULL,
    native_session_id TEXT NOT NULL CHECK (length(native_session_id) BETWEEN 1 AND 256),
    parent_session_id TEXT,
    parent_allocation_id TEXT,
    root_session_id TEXT NOT NULL,
    delegation_depth BIGINT NOT NULL CHECK (delegation_depth>=0),
    lifecycle_number BIGINT NOT NULL CHECK (lifecycle_number>0),
    source TEXT NOT NULL CHECK (source IN ('startup','resume','clear','compact')),
    borrowed_parent_reservation BOOLEAN NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    max_output_tokens BIGINT NOT NULL CHECK (max_output_tokens>0),
    admission JSONB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('HELD','QUARANTINED','RELEASED')),
    revoked BOOLEAN NOT NULL DEFAULT false,
    disposed_at TIMESTAMPTZ,
    process_stopped_at TIMESTAMPTZ,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    released_at TIMESTAMPTZ,
    release_reason TEXT,
    UNIQUE (allocation_id,attempt_id,generation,worker_id),
    UNIQUE (allocation_id,project_id,attempt_id),
    UNIQUE (allocation_id,native_session_id),
    UNIQUE (attempt_id,native_session_id,lifecycle_number),
    FOREIGN KEY (project_id,attempt_id) REFERENCES attempts(project_id,attempt_id),
    FOREIGN KEY (attempt_id,generation,worker_id) REFERENCES attempts(attempt_id,generation,worker_id),
    FOREIGN KEY (project_id,task_id) REFERENCES tasks(project_id,task_id),
    FOREIGN KEY (project_id,attempt_id,task_id) REFERENCES attempts(project_id,attempt_id,task_id),
    FOREIGN KEY (parent_allocation_id,attempt_id,generation,worker_id)
        REFERENCES native_child_lifecycles(allocation_id,attempt_id,generation,worker_id),
    CHECK ((state='RELEASED')=(released_at IS NOT NULL)),
    CHECK (borrowed_parent_reservation=(parent_session_id IS NULL)),
    CHECK ((parent_session_id IS NULL)=(parent_allocation_id IS NULL)),
    CHECK (NOT borrowed_parent_reservation OR delegation_depth=0),
    CHECK (borrowed_parent_reservation OR delegation_depth>0)
);
CREATE UNIQUE INDEX one_live_native_lifecycle ON native_child_lifecycles(attempt_id,native_session_id)
    WHERE disposed_at IS NULL AND released_at IS NULL;
CREATE UNIQUE INDEX one_live_native_root ON native_child_lifecycles(attempt_id)
    WHERE borrowed_parent_reservation AND disposed_at IS NULL AND released_at IS NULL;
CREATE TABLE native_child_allocations (
    resource_allocation_id TEXT PRIMARY KEY,
    allocation_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    amount BIGINT NOT NULL CHECK (amount>0),
    state TEXT NOT NULL CHECK (state IN ('HELD','QUARANTINED','RELEASED')),
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    released_at TIMESTAMPTZ,
    release_reason TEXT,
    UNIQUE (allocation_id,scope_id,dimension),
    FOREIGN KEY (allocation_id,project_id,attempt_id)
        REFERENCES native_child_lifecycles(allocation_id,project_id,attempt_id),
    FOREIGN KEY (project_id,attempt_id) REFERENCES attempts(project_id,attempt_id),
    FOREIGN KEY (scope_id,dimension) REFERENCES resource_limits(scope_id,dimension),
    CHECK ((state='RELEASED')=(released_at IS NOT NULL))
);
CREATE TABLE native_model_requests (
    request_id TEXT PRIMARY KEY,
    request_grant_id TEXT NOT NULL UNIQUE,
    project_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    worker_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    native_session_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    max_output_tokens BIGINT NOT NULL CHECK (max_output_tokens>0),
    purpose TEXT NOT NULL CHECK (purpose IN ('conversation','compaction','session-title')),
    request JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ADMITTED','SETTLED','QUARANTINED')),
    usage JSONB,
    usage_complete BOOLEAN NOT NULL DEFAULT false,
    cost_status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (cost_status='UNKNOWN'),
    settlement JSONB,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    settled_at TIMESTAMPTZ,
    FOREIGN KEY (project_id,attempt_id) REFERENCES attempts(project_id,attempt_id),
    FOREIGN KEY (allocation_id,attempt_id,generation,worker_id)
        REFERENCES native_child_lifecycles(allocation_id,attempt_id,generation,worker_id),
    FOREIGN KEY (allocation_id,native_session_id)
        REFERENCES native_child_lifecycles(allocation_id,native_session_id),
    CHECK ((status='SETTLED')=usage_complete),
    CHECK (NOT usage_complete OR usage IS NOT NULL)
);
CREATE INDEX native_model_pending ON native_model_requests(attempt_id,status);
CREATE TABLE native_bridge_rpc (
    rpc_id UUID PRIMARY KEY,
    project_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    worker_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request JSONB NOT NULL,
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (project_id,attempt_id) REFERENCES attempts(project_id,attempt_id),
    FOREIGN KEY (attempt_id,generation,worker_id) REFERENCES attempts(attempt_id,generation,worker_id)
);
