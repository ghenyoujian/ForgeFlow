export interface PageProps {
  projectId?: string;
  flowId?: string;
  taskId?: string;
  attemptId?: string;
}
export interface QueryMetadata {
  read_model_version?: number | null;
  projection_hash?: string;
  observed_at?: string;
  source?: string;
  next_cursor?: string | null;
  total_count?: number;
  revision?: number;
  event_cursor?: string;
  request_id?: string;
}
export interface ApiEnvelope<T> extends QueryMetadata {
  data: T;
}
export interface ProjectRef {
  id?: string;
  project_id?: string;
  name: string;
  authority_mode?: string;
  revision?: number;
}
