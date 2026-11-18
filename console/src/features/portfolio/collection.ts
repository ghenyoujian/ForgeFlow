import { useSharedApi } from "../../app/api";
/** Complete, version-checked traversal shares reads and event invalidation. */
export function useCollection<T>(path: string | null) { return useSharedApi<T[]>(path, true); }
