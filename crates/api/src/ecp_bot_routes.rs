//! HTTP-facing Bot wake contract. The Core must persist and authorize the
//! message before a provider process is considered; no implicit model call is
//! made by this module.
use forgeflow_executors::ecp_bot_session::{BotWakeRequest, validate_wake};

pub fn validate_bot_wake(
    request: &BotWakeRequest,
    payload: &[u8],
    bot_epoch: i64,
) -> Result<(), String> {
    validate_wake(request, payload, bot_epoch)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
