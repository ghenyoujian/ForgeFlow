ALTER TABLE attempts ADD COLUMN execution_bindings JSONB NOT NULL DEFAULT '{}';
