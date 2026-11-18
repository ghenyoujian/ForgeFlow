//! ECP dispatcher boundary.
//!
//! This module owns only the durable claim side of delivery. The returned
//! claims are handed to an external consumer which performs network I/O and
//! submits the recipient receipt through the public API. No function here
//! acknowledges a delivery or performs network I/O while PostgreSQL locks are
//! held.

use forgeflow_store::{
    Store, StoreError,
    ecp_delivery_claim::{DEFAULT_MAX_IN_FLIGHT, EcpDeliveryClaim, MAX_IN_FLIGHT_BOUND},
};
use std::time::Duration;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct EcpDispatcherConfig {
    pub dispatcher_id: String,
    pub batch_size: i64,
    pub visibility_seconds: i64,
    pub max_attempts: i64,
    pub max_in_flight: i64,
}

impl Default for EcpDispatcherConfig {
    fn default() -> Self {
        Self {
            dispatcher_id: "forgeflow-server-ecp-dispatcher".into(),
            batch_size: 128,
            visibility_seconds: 60,
            max_attempts: 3,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }
}

impl EcpDispatcherConfig {
    pub(crate) fn from_env() -> Result<Self, String> {
        let mut config = Self::default();
        if let Ok(raw) = std::env::var("FORGEFLOW_ECP_DISPATCHER_MAX_IN_FLIGHT") {
            config.max_in_flight = parse_max_in_flight(&raw)?;
        }
        Ok(config)
    }
}

fn parse_max_in_flight(raw: &str) -> Result<i64, String> {
    let value = raw.parse::<i64>().map_err(|_| {
        "FORGEFLOW_ECP_DISPATCHER_MAX_IN_FLIGHT must be a positive integer".to_owned()
    })?;
    if !(1..=MAX_IN_FLIGHT_BOUND).contains(&value) {
        return Err(format!(
            "FORGEFLOW_ECP_DISPATCHER_MAX_IN_FLIGHT must be between 1 and {MAX_IN_FLIGHT_BOUND}"
        ));
    }
    Ok(value)
}

#[derive(Clone)]
pub(crate) struct EcpDispatcher {
    store: Store,
    config: EcpDispatcherConfig,
}

impl EcpDispatcher {
    pub(crate) fn new(store: Store, config: EcpDispatcherConfig) -> Self {
        Self { store, config }
    }

    /// Claim one bounded batch. The caller must perform network delivery
    /// after this future returns and must never treat a claim as an ACK.
    pub(crate) async fn claim_once(&self) -> Result<Vec<EcpDeliveryClaim>, StoreError> {
        self.store
            .claim_ecp_delivery_batch(
                &self.config.dispatcher_id,
                self.config.batch_size,
                self.config.visibility_seconds,
                self.config.max_attempts,
                self.config.max_in_flight,
            )
            .await
    }

    /// Optional bounded claim loop. It is deliberately not enabled by default:
    /// the current product has no in-process recipient transport. Enabling it
    /// only reserves claims and emits NOTIFY; an external consumer must still
    /// perform network delivery and submit the recipient receipt.
    pub(crate) async fn run_claim_loop(&self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.claim_once().await {
                        Ok(claims) if !claims.is_empty() => {
                            tracing::info!(
                                dispatcher=%self.config.dispatcher_id,
                                count=claims.len(),
                                max_in_flight=self.config.max_in_flight,
                                "ECP deliveries claimed for external consumer"
                            );
                        }
                        Ok(_) => tracing::debug!(
                            dispatcher=%self.config.dispatcher_id,
                            max_in_flight=self.config.max_in_flight,
                            "ECP dispatcher claim scan yielded no claims; queue may be empty or backpressure cap reached"
                        ),
                        Err(error) => tracing::error!(%error, "ECP dispatcher claim scan failed"),
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
            }
        }
    }

    pub(crate) fn config(&self) -> &EcpDispatcherConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dispatcher_is_bounded_and_does_not_define_ack() {
        let config = EcpDispatcherConfig::default();
        assert_eq!(config.batch_size, 128);
        assert_eq!(config.visibility_seconds, 60);
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.max_in_flight, 128);
        assert!(!config.dispatcher_id.is_empty());
    }

    #[test]
    fn dispatcher_max_in_flight_env_is_fail_closed() {
        assert_eq!(parse_max_in_flight("128").unwrap(), 128);
        assert!(parse_max_in_flight("0").is_err());
        assert!(parse_max_in_flight("100001").is_err());
        assert!(parse_max_in_flight("bogus").is_err());
    }
}
