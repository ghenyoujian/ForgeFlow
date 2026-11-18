//! Short-transaction ECP delivery claims.
//!
//! A claim reserves a delivery for an external consumer.  It never performs
//! network I/O and never writes a receipt/ACK.  The paired message outbox row
//! is marked as durably handed off (`delivered_at`) in the same short
//! transaction; that timestamp is not a recipient receipt. Consumers must call
//! the public claim and receipt APIs using the returned generation.

use super::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const DEFAULT_CLAIM_VISIBILITY_SECONDS: i64 = 60;
pub const DEFAULT_CLAIM_MAX_ATTEMPTS: i64 = 3;
pub const DEFAULT_MAX_IN_FLIGHT: i64 = 128;
pub const MAX_IN_FLIGHT_BOUND: i64 = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcpDeliveryClaim {
    pub delivery_id: String,
    pub message_id: String,
    pub outbox_id: String,
    pub recipient_principal_id: String,
    pub generation: i64,
    pub attempt_number: i64,
    pub payload: Value,
    pub claimed_by: String,
    pub claimed_at: DateTime<Utc>,
    pub next_attempt_at: DateTime<Utc>,
}

fn ensure_dispatcher_id(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(err("VALIDATION_ERROR", "invalid dispatcher_id"));
    }
    Ok(())
}

fn ensure_claim_bounds(limit: i64, visibility_seconds: i64, max_attempts: i64) -> Result<()> {
    if !(1..=1000).contains(&limit) {
        return Err(err(
            "VALIDATION_ERROR",
            "claim limit must be between 1 and 1000",
        ));
    }
    if !(1..=3600).contains(&visibility_seconds) {
        return Err(err(
            "VALIDATION_ERROR",
            "claim visibility must be between 1 and 3600 seconds",
        ));
    }
    if !(1..=100).contains(&max_attempts) {
        return Err(err(
            "VALIDATION_ERROR",
            "max_attempts must be between 1 and 100",
        ));
    }
    Ok(())
}

fn ensure_max_in_flight(value: i64) -> Result<()> {
    if !(1..=MAX_IN_FLIGHT_BOUND).contains(&value) {
        return Err(err(
            "VALIDATION_ERROR",
            "max_in_flight must be between 1 and 100000",
        ));
    }
    Ok(())
}

impl Store {
    /// Claim due ECP deliveries using one short PostgreSQL transaction.
    ///
    /// The transaction only mutates durable claim/attempt state and emits a
    /// NOTIFY wakeup after each claim.  The returned claims must be delivered
    /// by an external consumer after this function returns; no network call is
    /// made while row locks are held.
    pub async fn claim_ecp_delivery_batch(
        &self,
        dispatcher_id: &str,
        limit: i64,
        visibility_seconds: i64,
        max_attempts: i64,
        max_in_flight: i64,
    ) -> Result<Vec<EcpDeliveryClaim>> {
        ensure_dispatcher_id(dispatcher_id)?;
        ensure_claim_bounds(limit, visibility_seconds, max_attempts)?;
        ensure_max_in_flight(max_in_flight)?;
        let mut tx = self.dispatch_pool.begin().await?;

        // A consumer that disappeared after claiming leaves IN_FLIGHT behind.
        // Move only expired leases back to retryable state, preserving the
        // prior attempt as UNCONFIRMED for independent recovery.
        sqlx::query(
            "UPDATE ecp_delivery_attempts a
                SET state='UNCONFIRMED', completed_at=clock_timestamp(), error_code='CLAIM_TIMEOUT'
              FROM ecp_deliveries d
             WHERE a.delivery_id=d.delivery_id
               AND a.attempt_number=d.attempt_count
               AND d.state='IN_FLIGHT'
               AND d.next_attempt_at <= clock_timestamp()",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE ecp_deliveries
                SET state='RETRY_WAIT', last_error_code='CLAIM_TIMEOUT', claimed_by=NULL, claimed_at=NULL
              WHERE state='IN_FLIGHT' AND next_attempt_at <= clock_timestamp()",
        )
        .execute(&mut *tx)
        .await?;

        // Expiry is terminal and must not be re-claimed.
        sqlx::query(
            "UPDATE ecp_deliveries
                SET state='EXPIRED', last_error_code='DELIVERY_EXPIRED', claimed_by=NULL, claimed_at=NULL
              WHERE state IN ('PENDING','RETRY_WAIT','UNCONFIRMED')
                AND expires_at IS NOT NULL AND expires_at <= clock_timestamp()",
        )
        .execute(&mut *tx)
        .await?;

        // Bound retries.  Insert a durable dead-letter row while the delivery
        // row is still locked, then leave it terminal and unclaimable.
        let exhausted = sqlx::query(
            "UPDATE ecp_deliveries
                SET state='DEAD_LETTER', last_error_code='MAX_ATTEMPTS_EXCEEDED', claimed_by=NULL, claimed_at=NULL
              WHERE state IN ('PENDING','RETRY_WAIT','UNCONFIRMED')
                AND attempt_count >= $1
                AND next_attempt_at <= clock_timestamp()
                AND (expires_at IS NULL OR expires_at > clock_timestamp())
             RETURNING delivery_id,attempt_count",
        )
        .bind(max_attempts)
        .fetch_all(&mut *tx)
        .await?;
        for row in exhausted {
            let delivery_id: String = row.try_get("delivery_id")?;
            let attempts: i64 = row.try_get("attempt_count")?;
            sqlx::query(
                "INSERT INTO ecp_dead_letters(dead_letter_id,delivery_id,reason_code,failure_count,data)
                 VALUES($1,$2,'MAX_ATTEMPTS_EXCEEDED',$3,$4)",
            )
            .bind(id())
            .bind(delivery_id)
            .bind(attempts.max(1))
            .bind(json!({"dispatcher_id": dispatcher_id, "max_attempts": max_attempts}))
            .execute(&mut *tx)
            .await?;
        }

        // Keep the admission decision and the bounded claim in this same
        // transaction. The dispatcher is single-owner by contract today;
        // deployments with multiple claimers must use distinct ids and an
        // external coordination lock until the pull contract is available.
        let in_flight: i64 =
            sqlx::query_scalar("SELECT count(*) FROM ecp_deliveries WHERE state='IN_FLIGHT'")
                .fetch_one(&mut *tx)
                .await?;
        let claim_limit = (max_in_flight - in_flight).min(limit);
        if claim_limit <= 0 {
            tx.commit().await?;
            return Ok(Vec::new());
        }

        let rows = sqlx::query(
            "SELECT d.delivery_id,d.message_id,o.outbox_id,d.recipient_principal_id,
                    d.attempt_count + 1 AS generation,
                    clock_timestamp() + make_interval(secs => $2) AS next_attempt_at,
                    o.payload
               FROM ecp_deliveries d
               JOIN ecp_messages m ON m.message_id=d.message_id
               JOIN ecp_message_outbox o ON o.delivery_id=d.delivery_id AND o.kind='MESSAGE_CREATED'
              WHERE d.state IN ('PENDING','RETRY_WAIT','UNCONFIRMED')
                AND d.next_attempt_at <= clock_timestamp()
                AND (d.expires_at IS NULL OR d.expires_at > clock_timestamp())
                AND d.attempt_count < $3
              ORDER BY d.next_attempt_at,d.created_at,d.delivery_id
              FOR UPDATE OF d SKIP LOCKED
              LIMIT $1",
        )
        .bind(claim_limit)
        .bind(visibility_seconds)
        .bind(max_attempts)
        .fetch_all(&mut *tx)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let delivery_id: String = row.try_get("delivery_id")?;
            let message_id: String = row.try_get("message_id")?;
            let outbox_id: String = row.try_get("outbox_id")?;
            let recipient_principal_id: String = row.try_get("recipient_principal_id")?;
            let generation: i64 = row.try_get("generation")?;
            let next_attempt_at: DateTime<Utc> = row.try_get("next_attempt_at")?;
            let claimed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE ecp_deliveries
                    SET state='IN_FLIGHT', attempt_count=$2,
                        first_sent_at=COALESCE(first_sent_at,$3),
                        next_attempt_at=$4, claimed_by=$5, claimed_at=$3,
                        last_error_code=NULL
                  WHERE delivery_id=$1",
            )
            .bind(&delivery_id)
            .bind(generation)
            .bind(claimed_at)
            .bind(next_attempt_at)
            .bind(dispatcher_id)
            .execute(&mut *tx)
            .await?;
            // `delivered_at` here means the durable outbox handoff completed;
            // it is deliberately independent from ecp_deliveries.ACKED,
            // which can only be written by the recipient receipt command.
            sqlx::query(
                "UPDATE ecp_message_outbox
                    SET delivered_at=COALESCE(delivered_at,$2), claimed_by=$3
                  WHERE outbox_id=$1",
            )
            .bind(&outbox_id)
            .bind(claimed_at)
            .bind(dispatcher_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO ecp_delivery_attempts(delivery_attempt_id,delivery_id,attempt_number,generation,state)
                 VALUES($1,$2,$3,$4,'CLAIMED')",
            )
            .bind(id())
            .bind(&delivery_id)
            .bind(generation)
            .bind(generation)
            .execute(&mut *tx)
            .await?;
            sqlx::query("SELECT pg_notify('ecp_delivery_claimed',$1)")
                .bind(&delivery_id)
                .execute(&mut *tx)
                .await?;
            claims.push(EcpDeliveryClaim {
                delivery_id,
                message_id,
                outbox_id,
                recipient_principal_id,
                generation,
                attempt_number: generation,
                payload: row.try_get("payload")?,
                claimed_by: dispatcher_id.to_owned(),
                claimed_at,
                next_attempt_at,
            });
        }
        tx.commit().await?;
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_bounds_are_fail_closed() {
        assert!(ensure_claim_bounds(1, 1, 1).is_ok());
        assert!(ensure_claim_bounds(1000, 3600, 100).is_ok());
        assert!(ensure_claim_bounds(0, 1, 1).is_err());
        assert!(ensure_claim_bounds(1001, 1, 1).is_err());
        assert!(ensure_claim_bounds(1, 0, 1).is_err());
        assert!(ensure_claim_bounds(1, 3601, 1).is_err());
        assert!(ensure_claim_bounds(1, 1, 0).is_err());
        assert!(ensure_claim_bounds(1, 1, 101).is_err());
    }

    #[test]
    fn dispatcher_identity_rejects_control_and_empty_values() {
        assert!(ensure_dispatcher_id("dispatcher-a").is_ok());
        assert!(ensure_dispatcher_id("").is_err());
        assert!(ensure_dispatcher_id("bad\nvalue").is_err());
        assert!(ensure_dispatcher_id(&"x".repeat(129)).is_err());
    }

    #[test]
    fn max_in_flight_is_strictly_bounded() {
        assert!(ensure_max_in_flight(1).is_ok());
        assert!(ensure_max_in_flight(DEFAULT_MAX_IN_FLIGHT).is_ok());
        assert!(ensure_max_in_flight(MAX_IN_FLIGHT_BOUND).is_ok());
        assert!(ensure_max_in_flight(0).is_err());
        assert!(ensure_max_in_flight(MAX_IN_FLIGHT_BOUND + 1).is_err());
    }
}
