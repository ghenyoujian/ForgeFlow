/** Stable route identities used by the ECP shell and browser checks. */
export const ECP_ROUTES = {
  portfolio: "/portfolio",
  projects: "/projects",
  flow: "/flows",
  teams: "/teams",
  timeline: "/schedule",
  execution: "/runs",
  evidence: "/evidence",
  settings: "/settings",
} as const;

export type EcpRouteKey = keyof typeof ECP_ROUTES;
