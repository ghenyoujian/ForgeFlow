//! One scoped Worker stream; full project events remain inaccessible to Workers.
use super::*;
use std::collections::VecDeque;

#[derive(Debug, Deserialize)]
pub struct DispatchCursor {
    pub project_id: String,
    #[serde(default)]
    pub after: u64,
}

fn escape_scope(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut escaped, "%{byte:02X}").expect("String formatting");
        }
    }
    escaped
}

fn cursor_after(
    headers: &HeaderMap,
    project: &str,
    worker: &str,
    after: u64,
) -> Result<u64, ApiError> {
    let Some(last) = headers.get("last-event-id") else {
        return Ok(after);
    };
    let last = last.to_str().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_CURSOR",
            "invalid Last-Event-ID",
        )
    })?;
    let prefix = format!("{}:{}:", escape_scope(project), escape_scope(worker));
    let sequence = last.strip_prefix(&prefix).ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "SNAPSHOT_REQUIRED",
            "dispatch cursor belongs to a different project or Worker",
        )
    })?;
    sequence.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_CURSOR",
            "dispatch sequence must be an unsigned integer",
        )
    })
}

fn dispatch_error(error: forgeflow_store::StoreError) -> ApiError {
    match error {
        forgeflow_store::StoreError::Domain(domain) if domain.code == "WORKER_SCOPE_DENIED" => {
            ApiError(StatusCode::FORBIDDEN, domain)
        }
        forgeflow_store::StoreError::Domain(domain) if domain.code == "SNAPSHOT_REQUIRED" => {
            ApiError(StatusCode::CONFLICT, domain)
        }
        error => error.into(),
    }
}

pub async fn events(
    State(s): State<App>,
    Path(worker): Path<String>,
    Extension(actor): Extension<Principal>,
    headers: HeaderMap,
    Query(query): Query<DispatchCursor>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    if !actor.worker {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "WORKER_AUTH_REQUIRED",
            "dispatch notifications require the scoped Worker service",
        ));
    }
    s.auth
        .worker_scope(&actor, Some(&worker), Some(&query.project_id))
        .map_err(|error| ApiError::new(StatusCode::FORBIDDEN, "WORKER_SCOPE_DENIED", error))?;
    let after = cursor_after(&headers, &query.project_id, &worker, query.after)?;
    // The first read validates registered scope and cursor before HTTP headers.
    let queued = s
        .store
        .worker_dispatch_events(&worker, &query.project_id, after, 512)
        .await
        .map_err(dispatch_error)?;
    let catch_up = queued
        .last()
        .is_some_and(|fact| fact.project_seq.saturating_sub(after) >= 512);
    let stream = futures::stream::unfold(
        (
            s,
            query.project_id,
            worker,
            after,
            VecDeque::from(queued),
            catch_up,
            false,
        ),
        |(s, project, worker, mut after, mut queued, mut catch_up, closed)| async move {
            if closed {
                return None;
            }
            loop {
                if s.auth.is_shutting_down() {
                    return None;
                }
                if let Some(fact) = queued.pop_front() {
                    after = fact.project_seq;
                    let event = Event::default()
                        .id(format!(
                            "{}:{}:{}",
                            escape_scope(&project),
                            escape_scope(&worker),
                            after
                        ))
                        .event("worker-dispatch")
                        .json_data(&fact)
                        .expect("typed dispatch fact serializes");
                    return Some((
                        Ok(event),
                        (s, project, worker, after, queued, catch_up, false),
                    ));
                }
                // Drain bounded replay pages promptly after reconnect. The live
                // stream returns to one read each 100ms once it reaches the tip.
                if !catch_up {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                match s
                    .store
                    .worker_dispatch_events(&worker, &project, after, 512)
                    .await
                {
                    Ok(facts) => {
                        catch_up = facts
                            .last()
                            .is_some_and(|fact| fact.project_seq.saturating_sub(after) >= 512);
                        queued = VecDeque::from(facts);
                    }
                    Err(error) => {
                        let error = dispatch_error(error);
                        tracing::warn!(code=%error.1.code,"Worker dispatch stream read failed");
                        let event = Event::default()
                            .event("worker-dispatch-error")
                            .json_data(json!({"code":error.1.code}))
                            .expect("error code serializes");
                        return Some((Ok(event), (s, project, worker, after, queued, false, true)));
                    }
                }
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_resume_cursor_is_bound_to_both_scope_components() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "project:worker:73".parse().unwrap());
        assert_eq!(cursor_after(&headers, "project", "worker", 0).unwrap(), 73);
        assert_eq!(
            cursor_after(&headers, "other", "worker", 0)
                .unwrap_err()
                .1
                .code,
            "SNAPSHOT_REQUIRED"
        );
        assert_eq!(
            cursor_after(&headers, "project", "other", 0)
                .unwrap_err()
                .1
                .code,
            "SNAPSHOT_REQUIRED"
        );
        assert_ne!(
            format!("{}:{}", escape_scope("a:b"), escape_scope("c")),
            format!("{}:{}", escape_scope("a"), escape_scope("b:c"))
        );
    }
}
