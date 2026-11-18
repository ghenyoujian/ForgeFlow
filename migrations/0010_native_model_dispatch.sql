-- A native grant is the sole budget admission. Consuming it grants at most one
-- subsequent upstream connection; an uncertain connection never resets this mark.
ALTER TABLE native_model_requests
    ADD COLUMN dispatched_at TIMESTAMPTZ,
    ADD COLUMN dispatch_body_sha256 TEXT,
    ADD COLUMN dispatch_transport_settlement JSONB,
    ADD CONSTRAINT native_dispatch_complete_binding CHECK (
        (dispatched_at IS NULL) = (dispatch_body_sha256 IS NULL)
    ),
    ADD CONSTRAINT native_dispatch_body_digest CHECK (
        dispatch_body_sha256 IS NULL OR dispatch_body_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT native_dispatch_transport_binding CHECK (
        dispatch_transport_settlement IS NULL OR (
            dispatched_at IS NOT NULL AND jsonb_typeof(dispatch_transport_settlement)='object'
        )
    );
