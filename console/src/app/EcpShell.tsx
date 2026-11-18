import type { ReactNode } from "react";

/**
 * The shell marker is intentionally presentation-only. Authorization stays in
 * the API context headers and PostgreSQL-backed workspace membership.
 */
export function EcpShell({ children }: { children: ReactNode }) {
  return <div data-ecp-shell="true" data-ecp-contract="v1">{children}</div>;
}
