//! One active Core per PostgreSQL database, independently of data_root/schema.
//! This is session ownership and bounded liveness detection, not a transaction
//! epoch fence. It does not persist or authorize a data-root relocation.
//! A sequential restart with the wrong root is not blocked, and an older Core
//! that does not acquire this lock must be stopped before upgrading.
use super::*;
use sqlx::{Connection, PgConnection};
use std::time::Duration;

// Separate from admission's transaction lock and all idempotency namespaces.
// PostgreSQL advisory locks include the current database in their lock tag.
const CORE_AUTHORITY_KEY: i64 = 0x4646_434f_5245_0001;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const CHECK_INTERVAL: Duration = Duration::from_secs(1);
pub const CORE_AUTHORITY_APPLICATION_NAME: &str = "forgeflow-core-authority-v1";

/// An opaque, non-cloneable dedicated connection. It is never returned to a
/// pool or automatically reconnected. Keep it until all Core activity stops.
pub struct CoreAuthorityGuard {
    connection: Option<PgConnection>,
    backend_pid: i32,
    failed: bool,
}

impl std::fmt::Debug for CoreAuthorityGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreAuthorityGuard")
            .field("backend_pid", &self.backend_pid)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Call before migration, startup reconciliation, HTTP or dispatch. Pool
    /// connection options preserve the actual configured PostgreSQL identity;
    /// no database URL or password is copied into diagnostics.
    pub async fn acquire_core_authority(&self) -> Result<CoreAuthorityGuard> {
        let options = self
            .pool
            .connect_options()
            .as_ref()
            .clone()
            .application_name(CORE_AUTHORITY_APPLICATION_NAME);
        let mut connection =
            tokio::time::timeout(CONNECT_TIMEOUT, PgConnection::connect_with(&options))
                .await
                .map_err(|_| {
                    err(
                        "CORE_AUTHORITY_UNAVAILABLE",
                        "Core ownership connection timed out",
                    )
                })??;
        let acquired: bool = tokio::time::timeout(
            CHECK_TIMEOUT,
            sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(CORE_AUTHORITY_KEY)
                .fetch_one(&mut connection),
        )
        .await
        .map_err(|_| {
            err(
                "CORE_AUTHORITY_UNAVAILABLE",
                "Core ownership acquisition timed out",
            )
        })??;
        if !acquired {
            let _ = tokio::time::timeout(CHECK_TIMEOUT, connection.close()).await;
            return Err(err(
                "CORE_AUTHORITY_HELD",
                "another Core or offline relocation already owns this PostgreSQL database; changing data_root does not create another authority",
            ));
        }
        let backend_pid: i32 = tokio::time::timeout(
            CHECK_TIMEOUT,
            sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut connection),
        )
        .await
        .map_err(|_| {
            err(
                "CORE_AUTHORITY_UNAVAILABLE",
                "Core ownership identity timed out",
            )
        })??;
        Ok(CoreAuthorityGuard {
            connection: Some(connection),
            backend_pid,
            failed: false,
        })
    }
}

impl CoreAuthorityGuard {
    /// Diagnostic identity only; it is neither a token nor access to the holder
    /// connection. Useful for an operator's explicit fail-stop verification.
    pub fn backend_pid(&self) -> i32 {
        self.backend_pid
    }

    async fn check_held(&mut self) -> Result<()> {
        if self.failed {
            return Err(err(
                "CORE_AUTHORITY_LOST",
                "Core ownership was already lost; reconnection is forbidden",
            ));
        }
        let Some(connection) = self.connection.as_mut() else {
            self.failed = true;
            return Err(err(
                "CORE_AUTHORITY_LOST",
                "Core ownership connection is closed",
            ));
        };
        let result = tokio::time::timeout(CHECK_TIMEOUT,
            sqlx::query_scalar::<_, bool>(
                "SELECT pg_backend_pid()=$1 AND EXISTS(SELECT 1 FROM pg_locks \
                 WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted \
                 AND mode='ExclusiveLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) \
                 AND classid::bigint=($2::bigint >> 32) \
                 AND objid::bigint=($2::bigint & 4294967295) AND objsubid=1)",
            ).bind(self.backend_pid).bind(CORE_AUTHORITY_KEY).fetch_one(connection),
        ).await;
        match result {
            Ok(Ok(true)) => Ok(()),
            _ => {
                self.failed = true;
                Err(err(
                    "CORE_AUTHORITY_LOST",
                    "Core ownership connection, backend identity or session lock was lost; fail-stop is required",
                ))
            }
        }
    }

    /// Permanently report the first failure; never reconnect or reacquire. A
    /// live session is checked every second with a two-second query deadline,
    /// giving an approximately three-second detection bound under a responsive
    /// runtime. This does not claim instantaneous or per-transaction fencing.
    pub async fn wait_for_loss(&mut self) -> StoreError {
        if self.failed {
            return err(
                "CORE_AUTHORITY_LOST",
                "Core ownership was already lost; reconnection is forbidden",
            );
        }
        let mut interval = tokio::time::interval(CHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) = self.check_held().await {
                return error;
            }
        }
    }

    /// Normal shutdown only, after Core tasks/requests and Store pools settle.
    /// Early errors/cancellation still drop the exclusive socket; no pooled
    /// session can retain an accidentally leaked advisory lock.
    pub async fn close(mut self) -> Result<()> {
        if let Some(connection) = self.connection.take() {
            tokio::time::timeout(CHECK_TIMEOUT, connection.close())
                .await
                .map_err(|_| {
                    err(
                        "CORE_AUTHORITY_CLOSE_TIMEOUT",
                        "Core ownership connection close timed out",
                    )
                })??;
        }
        Ok(())
    }
}
