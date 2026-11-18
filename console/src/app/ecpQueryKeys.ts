import { getAuthScope, getWorkspace } from "./api";

/** Cache keys always include the authenticated workspace scope. */
export function ecpQueryKey(path: string, cursor: string | null = null) {
  return ["forgeflow", getAuthScope(), getWorkspace(), path, cursor] as const;
}
