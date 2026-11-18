use crate::{Journal, LaunchIntent, LaunchReceipt, ProcessIdentity, StopEvidence, boot_id};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{mpsc, watch},
    time::{Instant, timeout},
};

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub stdin: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogNotice {
    pub stream: String,
    pub offset: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone)]
pub struct SupervisionLimits {
    pub timeout: Duration,
    pub term_grace: Duration,
    pub kill_grace: Duration,
    pub max_log_bytes: u64,
}
impl Default for SupervisionLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3600),
            term_grace: Duration::from_secs(3),
            kill_grace: Duration::from_secs(3),
            max_log_bytes: 256 * 1024 * 1024,
        }
    }
}
#[derive(Debug)]
struct ProcInfo {
    pid: u32,
    pgid: i32,
    start_ticks: u64,
    state: char,
}
fn proc_info(pid: u32) -> Result<ProcInfo> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = value.rsplit_once(") ").context("invalid proc stat")?.1;
    let fields: Vec<_> = tail.split_whitespace().collect();
    Ok(ProcInfo {
        pid,
        state: fields[0].chars().next().unwrap_or('?'),
        pgid: fields[2].parse()?,
        start_ticks: fields[19].parse()?,
    })
}
fn processes() -> Vec<ProcInfo> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .filter_map(|p| proc_info(p).ok())
        .collect()
}
fn alive_group(pgid: i32) -> bool {
    processes()
        .iter()
        .any(|p| p.pgid == pgid && p.state != 'Z' && p.state != 'X')
}
fn has_attempt_marker(pid: u32, attempt: &str) -> bool {
    let marker = format!("FORGEFLOW_ATTEMPT_ID={attempt}");
    fs::read(format!("/proc/{pid}/environ"))
        .map(|bytes| bytes.split(|b| *b == 0).any(|v| v == marker.as_bytes()))
        .unwrap_or(false)
}
fn escaped(attempt: &str, pgid: i32) -> bool {
    processes()
        .iter()
        .any(|p| p.pgid != pgid && p.state != 'Z' && has_attempt_marker(p.pid, attempt))
}
pub fn identity_matches(identity: &ProcessIdentity) -> Result<bool> {
    if boot_id()? != identity.boot_id {
        return Ok(false);
    }
    Ok(proc_info(identity.pid)
        .map(|p| {
            p.pgid == identity.pgid
                && p.start_ticks == identity.start_ticks
                && has_attempt_marker(identity.pid, &identity.attempt_id)
        })
        .unwrap_or(false))
}
fn signal_group(pgid: i32, signal: i32) -> Result<()> {
    if pgid <= 1 {
        bail!("refusing unsafe process group");
    }
    let result = unsafe { libc::kill(-pgid, signal) };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
async fn wait_group(pgid: i32, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    while alive_group(pgid) {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}
fn reap_group(pgid: i32) {
    loop {
        let result = unsafe { libc::waitpid(-pgid, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            break;
        }
    }
}
fn physical_members(fence: &crate::PreparedCgroupFence) -> Result<Vec<(u32, u64)>> {
    fence.validate_live()?;
    Ok(
        fs::read_to_string(fence.identity.leaf_path.join("cgroup.procs"))?
            .lines()
            .filter_map(|line| line.parse::<u32>().ok())
            .filter_map(|pid| proc_info(pid).ok())
            .map(|process| (process.pid, process.start_ticks))
            .collect(),
    )
}
fn reap_physical_members(members: &[(u32, u64)]) {
    for (pid, start_ticks) in members {
        // Never reap another attempt's process after PID reuse. Only our
        // fingerprinted adopted descendant or already-waited root is eligible.
        if proc_info(*pid).is_ok_and(|process| process.start_ticks == *start_ticks) {
            unsafe {
                libc::waitpid(*pid as i32, std::ptr::null_mut(), libc::WNOHANG);
            }
        }
    }
}
/// Startup reconciliation never launches. Without native adoption, terminate authenticated old groups.
pub async fn reconcile(journal: &Journal, grace: Duration) -> Result<StopEvidence> {
    let receipt = journal
        .receipt()
        .context("launch without receipt remains quarantined")?;
    if receipt.execution_id.is_empty()
        || receipt.intent.execution_id.is_empty()
        || receipt.execution_id != receipt.intent.execution_id
    {
        bail!("legacy or inconsistent execution identity; quarantine");
    }
    let identity = &receipt.process;
    // Restore validates the original boot, mount, inode, ownership and limits
    // before any signalling. An uncertain physical tree remains quarantined.
    let physical = crate::PreparedCgroupFence::restore(journal)?;
    let physical_members = physical
        .as_ref()
        .map(physical_members)
        .transpose()?
        .unwrap_or_default();
    let boot_changed = boot_id()? != identity.boot_id;
    if !boot_changed && alive_group(identity.pgid) {
        let attributable = identity_matches(identity)?
            || processes().iter().any(|p| {
                p.pgid == identity.pgid && has_attempt_marker(p.pid, &identity.attempt_id)
            });
        if !attributable {
            bail!("process group identity uncertain; quarantine without signalling");
        }
        signal_group(identity.pgid, libc::SIGTERM)?;
        if !wait_group(identity.pgid, grace).await {
            signal_group(identity.pgid, libc::SIGKILL)?;
        }
        let _ = wait_group(identity.pgid, grace).await;
    }
    if let Some(fence) = &physical {
        if fence.populated()? {
            fence.kill()?;
        }
        let deadline = Instant::now() + grace;
        while fence.populated()? && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    reap_group(identity.pgid);
    reap_physical_members(&physical_members);
    let physical_empty = match &physical {
        Some(fence) => fence.record_stop(journal)?,
        None => true,
    };
    let confirmed = physical_empty
        && (boot_changed
            || (!alive_group(identity.pgid) && !escaped(&identity.attempt_id, identity.pgid)));
    let stop = StopEvidence {
        exit_code: None,
        signal: None,
        reason: "worker_restart_without_native_adoption".into(),
        process_exit_confirmed: confirmed,
        stdout_bytes: fs::metadata(journal.path("stdout.ndjson"))
            .map(|m| m.len())
            .unwrap_or(0),
        stderr_bytes: fs::metadata(journal.path("stderr.log"))
            .map(|m| m.len())
            .unwrap_or(0),
        notification_overflow: 0,
        log_error: None,
    };
    journal.record_stop(&stop)?;
    Ok(stop)
}
async fn drain<R: AsyncRead + Unpin>(
    mut source: R,
    path: PathBuf,
    stream: &'static str,
    notices: mpsc::Sender<LogNotice>,
    overflow: Arc<AtomicU64>,
    limit: u64,
) -> Result<u64> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .await?;
    let mut buffer = vec![0u8; 16 * 1024];
    let mut offset = 0;
    loop {
        let count = source.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        if offset + count as u64 > limit {
            bail!("{stream} log byte budget exceeded at {offset}");
        }
        output.write_all(&buffer[..count]).await?;
        // The file is authoritative. Notifications only reference durable offsets; bounded queues
        // cannot force unbounded memory and overflow is explicitly reported for cursor replay.
        output.sync_data().await?;
        if notices
            .try_send(LogNotice {
                stream: stream.into(),
                offset,
                bytes: count as u64,
            })
            .is_err()
        {
            overflow.fetch_add(1, Ordering::Relaxed);
        }
        offset += count as u64;
    }
    output.sync_all().await?;
    Ok(offset)
}
/// Owns the child until wait/reap and group quiescence. Caller cancellation uses watch, never abort.
pub async fn supervise(
    spec: ProcessSpec,
    intent: LaunchIntent,
    journal: Journal,
    limits: SupervisionLimits,
    cancellation: watch::Receiver<bool>,
    notices: mpsc::Sender<LogNotice>,
    launched: watch::Sender<Option<LaunchReceipt>>,
) -> Result<StopEvidence> {
    supervise_inner(
        spec,
        intent,
        journal,
        limits,
        cancellation,
        notices,
        launched,
        None,
    )
    .await
}
/// The exact admitted physical reservation is applied before exec, never after
/// author work starts. The legacy entrypoint above is explicitly unenforced.
pub async fn supervise_physical(
    spec: ProcessSpec,
    intent: LaunchIntent,
    journal: Journal,
    limits: SupervisionLimits,
    cancellation: watch::Receiver<bool>,
    notices: mpsc::Sender<LogNotice>,
    launched: watch::Sender<Option<LaunchReceipt>>,
    physical: crate::PhysicalFenceRequest,
) -> Result<StopEvidence> {
    supervise_inner(
        spec,
        intent,
        journal,
        limits,
        cancellation,
        notices,
        launched,
        Some(physical),
    )
    .await
}
async fn supervise_inner(
    spec: ProcessSpec,
    intent: LaunchIntent,
    journal: Journal,
    limits: SupervisionLimits,
    mut cancellation: watch::Receiver<bool>,
    notices: mpsc::Sender<LogNotice>,
    launched: watch::Sender<Option<LaunchReceipt>>,
    physical: Option<crate::PhysicalFenceRequest>,
) -> Result<StopEvidence> {
    uuid::Uuid::parse_str(&intent.execution_id)
        .context("launch execution identity must be independently allocated")?;
    if intent.execution_id == intent.operation_id {
        bail!("execution identity cannot alias operation");
    }
    if intent.boot_id != boot_id()? {
        bail!("launch boot identity mismatch");
    }
    if *cancellation.borrow() || limits.timeout.is_zero() {
        let stop = StopEvidence {
            exit_code: None,
            signal: None,
            reason: "cancelled_before_launch".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        journal.record_stop(&stop)?;
        return Ok(stop);
    }
    // Fsync may be slow on the workspace filesystem. Keep it off the async
    // reactor so other channels can renew leases and process handoffs, while
    // still awaiting the complete durable launch fence before any spawn.
    let authority_journal = journal.clone();
    let (spec, intent, physical) = tokio::task::spawn_blocking(move || {
        let physical = physical
            .map(|request| {
                crate::PreparedCgroupFence::prepare(request, &intent, &authority_journal)
            })
            .transpose()?;
        if let Some(fence) = &physical {
            authority_journal.record_bound_intent_physical(&intent, &spec, &fence.identity)?;
        } else {
            authority_journal.record_bound_intent(&intent, &spec)?;
        }
        // Return the exact inputs that were bound, rather than cloning a second
        // prompt/environment/argv while other channels wait to launch.
        Ok::<_, anyhow::Error>((spec, intent, physical))
    })
    .await
    .context("launch authority persistence task failed")??;
    // Adopt orphaned grandchildren so completed groups can be explicitly reaped on Linux.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        bail!("cannot establish child subreaper");
    }
    if *cancellation.borrow() {
        if let Some(fence) = &physical {
            fence.record_stop(&journal)?;
        }
        let stop = StopEvidence {
            exit_code: None,
            signal: None,
            reason: "cancelled_before_launch".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        };
        journal.record_stop(&stop)?;
        return Ok(stop);
    }
    let mut command = Command::new(&spec.program);
    command
        .env_clear()
        .args(&spec.args)
        .envs(&spec.env)
        .env("FORGEFLOW_ATTEMPT_ID", &intent.attempt_id)
        .env("FORGEFLOW_OPERATION_ID", &intent.operation_id)
        .env("FORGEFLOW_EXECUTION_ID", &intent.execution_id)
        .current_dir(&spec.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    if let Some(fence) = &physical {
        fence.validate_live()?;
        let fd = fence.attachment_fd();
        unsafe {
            command.pre_exec(move || crate::attach_before_exec(fd));
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let physical_empty = match &physical {
                Some(fence) => fence.record_stop(&journal)?,
                None => true,
            };
            let stop = StopEvidence {
                exit_code: None,
                signal: None,
                reason: format!("spawn_failed: {error}"),
                process_exit_confirmed: physical_empty,
                stdout_bytes: 0,
                stderr_bytes: 0,
                notification_overflow: 0,
                log_error: None,
            };
            journal.record_stop(&stop)?;
            return Ok(stop);
        }
    };
    let pid = child.id().context("spawned child lacks pid")?;
    let info = match proc_info(pid) {
        Ok(info) => info,
        Err(error) => {
            if let Some(fence) = &physical {
                let _ = fence.kill();
            }
            let _ = signal_group(pid as i32, libc::SIGKILL);
            let _ = child.wait().await;
            bail!("launched process fingerprint unavailable; quarantine: {error}");
        }
    };
    if let Some(fence) = &physical {
        if let Err(error) = fence.verify_membership(pid, &journal) {
            let _ = fence.kill();
            let _ = child.wait().await;
            bail!("physical launch membership not proved; quarantine: {error}");
        }
    }
    let receipt = LaunchReceipt {
        execution_id: intent.execution_id.clone(),
        intent: intent.clone(),
        process: ProcessIdentity {
            pid,
            pgid: info.pgid,
            start_ticks: info.start_ticks,
            boot_id: intent.boot_id.clone(),
            attempt_id: intent.attempt_id.clone(),
        },
        launched_at: chrono::Utc::now().to_rfc3339(),
        command_program: spec.program.clone(),
        command_args: spec.args.clone(),
        environment_key_names: spec.env.keys().cloned().collect(),
    };
    let receipt_journal = journal.clone();
    let persisted_receipt = tokio::task::spawn_blocking(move || {
        receipt_journal.record_receipt(&receipt)?;
        Ok::<_, anyhow::Error>(receipt)
    })
    .await
    .context("launch receipt persistence task failed")
    .and_then(|result| result);
    // Await the same complete receipt and its fsync before publication. Keeping
    // this disk work off the reactor lets SSE, lease renewal and other channel
    // claims run while a newly spawned author waits for durable acknowledgement.
    let receipt = match persisted_receipt {
        Ok(receipt) => receipt,
        Err(error) => {
            if let Some(fence) = &physical {
                let _ = fence.kill();
            }
            let _ = signal_group(info.pgid, libc::SIGKILL);
            let _ = child.wait().await;
            bail!("launch receipt persistence failed; quarantine: {error}");
        }
    };
    let _ = launched.send(Some(receipt));
    let stdout = child.stdout.take().context("missing stdout")?;
    let stderr = child.stderr.take().context("missing stderr")?;
    let mut stdin = child.stdin.take().context("missing stdin")?;
    let overflow = Arc::new(AtomicU64::new(0));
    let mut stdout_task = tokio::spawn(drain(
        stdout,
        journal.path("stdout.ndjson"),
        "stdout",
        notices.clone(),
        overflow.clone(),
        limits.max_log_bytes,
    ));
    let mut stderr_task = tokio::spawn(drain(
        stderr,
        journal.path("stderr.log"),
        "stderr",
        notices,
        overflow.clone(),
        limits.max_log_bytes,
    ));
    let mut input_task = tokio::spawn(async move {
        stdin.write_all(&spec.stdin).await?;
        stdin.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });
    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut input_done = false;
    let mut log_error = None;
    let mut reason = "executor_exited".to_owned();
    let status = loop {
        if *cancellation.borrow() {
            reason = "cancelled_or_lease_revoked".into();
            break None;
        }
        tokio::select! {
            status = child.wait() => break Some(status?),
            _ = &mut deadline => { reason = "deadline_exceeded".into(); break None; },
            change = cancellation.changed() => { if change.is_err() || *cancellation.borrow() { reason = "cancelled_or_controller_lost".into(); break None; } },
            result = &mut stdout_task, if stdout_result.is_none() => {
                let value = result.map_err(anyhow::Error::from).and_then(|v| v);
                if let Err(error) = &value { log_error = Some(error.to_string()); reason = "log_persistence_failed".into(); stdout_result = Some(value); break None; }
                stdout_result = Some(value);
            },
            result = &mut stderr_task, if stderr_result.is_none() => {
                let value = result.map_err(anyhow::Error::from).and_then(|v| v);
                if let Err(error) = &value { log_error = Some(error.to_string()); reason = "log_persistence_failed".into(); stderr_result = Some(value); break None; }
                stderr_result = Some(value);
            },
            result = &mut input_task, if !input_done => { input_done = true; if let Err(error) = result.map_err(anyhow::Error::from).and_then(|v|v) { reason = format!("stdin_failed: {error}"); break None; } },
        }
    };
    // Even normal parent exit may leave tool grandchildren alive and holding output pipes.
    let mut stop_error = None;
    let physical_members = match &physical {
        Some(fence) => match physical_members(fence) {
            Ok(members) => members,
            Err(error) => {
                stop_error = Some(error.to_string());
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    if status.is_none() || alive_group(info.pgid) {
        if let Err(error) = signal_group(info.pgid, libc::SIGTERM) {
            stop_error = Some(error.to_string());
        }
        if !wait_group(info.pgid, limits.term_grace).await {
            if let Err(error) = signal_group(info.pgid, libc::SIGKILL) {
                stop_error = Some(error.to_string());
            }
        }
    }
    // cgroup.kill also covers descendants that changed process group, cleared
    // markers or outlived a normally exiting root. Only this authenticated leaf
    // is touched; kernel-empty observation is required for positive settlement.
    if let Some(fence) = &physical {
        if let Err(error) = fence.kill() {
            stop_error = Some(error.to_string());
        }
    }
    let status = match status {
        Some(status) => Some(status),
        None => timeout(limits.kill_grace, child.wait())
            .await
            .ok()
            .and_then(|r| r.ok()),
    };
    let quiescent = wait_group(info.pgid, limits.kill_grace).await;
    let physical_empty = if let Some(fence) = &physical {
        let deadline = Instant::now() + limits.kill_grace;
        while fence.populated().unwrap_or(true) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        match fence.record_stop(&journal) {
            Ok(empty) => empty,
            Err(error) => {
                stop_error = Some(error.to_string());
                false
            }
        }
    } else {
        true
    };
    reap_group(info.pgid);
    reap_physical_members(&physical_members);
    if !input_done {
        input_task.abort();
        let _ = input_task.await;
    }
    if stdout_result.is_none() {
        stdout_result = Some(match timeout(limits.kill_grace, &mut stdout_task).await {
            Ok(value) => value.map_err(anyhow::Error::from).and_then(|v| v),
            Err(_) => {
                stdout_task.abort();
                Err(anyhow::anyhow!("stdout pipe not closed"))
            }
        });
    }
    if stderr_result.is_none() {
        stderr_result = Some(match timeout(limits.kill_grace, &mut stderr_task).await {
            Ok(value) => value.map_err(anyhow::Error::from).and_then(|v| v),
            Err(_) => {
                stderr_task.abort();
                Err(anyhow::anyhow!("stderr pipe not closed"))
            }
        });
    }
    for result in [&stdout_result, &stderr_result] {
        if let Some(Err(error)) = result {
            log_error = Some(error.to_string());
        }
    }
    if let Some(error) = stop_error {
        log_error = Some(format!("termination failed: {error}"));
    }
    use std::os::unix::process::ExitStatusExt;
    let stop = StopEvidence {
        exit_code: status.as_ref().and_then(|s| s.code()),
        signal: status.as_ref().and_then(|s| s.signal()),
        reason,
        process_exit_confirmed: status.is_some()
            && quiescent
            && physical_empty
            && !escaped(&intent.attempt_id, info.pgid),
        stdout_bytes: fs::metadata(journal.path("stdout.ndjson"))
            .map(|m| m.len())
            .unwrap_or(0),
        stderr_bytes: fs::metadata(journal.path("stderr.log"))
            .map(|m| m.len())
            .unwrap_or(0),
        notification_overflow: overflow.load(Ordering::Relaxed),
        log_error,
    };
    journal.record_stop(&stop)?;
    Ok(stop)
}
