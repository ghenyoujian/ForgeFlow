-- ECP Phase 3 dispatcher claims.  Claim ownership is separate from the
-- recipient receipt: a dispatcher may reserve a delivery, but it can never
-- turn that reservation into an ACK without the recipient receipt command.
ALTER TABLE ecp_deliveries
  ADD COLUMN claimed_by TEXT,
  ADD COLUMN claimed_at TIMESTAMPTZ;

CREATE INDEX ecp_deliveries_claim_timeout
  ON ecp_deliveries(state,next_attempt_at,claimed_at,delivery_id)
  WHERE state IN ('IN_FLIGHT','RETRY_WAIT','PENDING','UNCONFIRMED');
