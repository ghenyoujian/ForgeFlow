// ECP DSH Workflow bridge is observe-only until a current workflow receipt is
// bound to the profile. Events never create cancellation/resume authority.
export const forgeflowEcpDshWorkflowBridge = {
  schema_version: 'forgeflow.ecp.native-workflow-bridge.v1',
  provider: 'DSH',
  support_status: 'UNKNOWN',
  evidence_status: 'NOT_RUN',
  grants_authority: false,
};
