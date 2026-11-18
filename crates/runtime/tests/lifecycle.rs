use forgeflow_runtime::*;
use std::{collections::BTreeMap, time::Duration};
use tokio::sync::{mpsc, watch};
fn intent(root: &std::path::Path, attempt: &str) -> LaunchIntent {
    LaunchIntent {
        execution_id: uuid::Uuid::new_v4().to_string(),
        operation_id: format!("op-{attempt}"),
        attempt_id: attempt.into(),
        generation: 1,
        worker_id: "worker".into(),
        boot_id: boot_id().unwrap(),
        workspace: root.into(),
        prompt_sha256: "a".repeat(64),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}
fn spec(root: &std::path::Path, script: &str) -> ProcessSpec {
    ProcessSpec {
        program: "/usr/bin/python3".into(),
        args: vec!["-c".into(), script.into()],
        env: BTreeMap::new(),
        cwd: root.into(),
        stdin: vec![],
    }
}
fn limits() -> SupervisionLimits {
    SupervisionLimits {
        timeout: Duration::from_secs(10),
        term_grace: Duration::from_millis(100),
        kill_grace: Duration::from_secs(2),
        max_log_bytes: 1024 * 1024,
    }
}
#[tokio::test]
async fn cancelled_parent_and_term_ignoring_grandchild_are_killed_and_reaped() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "tree").unwrap();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (notice_tx, _notice_rx) = mpsc::channel(1);
    let (launched_tx, mut launched_rx) = watch::channel(None);
    let script = "import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=os.fork()\nif p==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN)\n print('grandchild='+str(os.getpid()),flush=True)\nelse:\n print('parent='+str(os.getpid()),flush=True)\nwhile True: time.sleep(.01)";
    let task = tokio::spawn(supervise(
        spec(temp.path(), script),
        intent(temp.path(), "tree"),
        journal.clone(),
        limits(),
        cancel_rx,
        notice_tx,
        launched_tx,
    ));
    launched_rx.changed().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel_tx.send(true).unwrap();
    let stop = task.await.unwrap().unwrap();
    assert!(stop.process_exit_confirmed, "{stop:?}");
    assert_eq!(stop.signal, Some(libc::SIGKILL));
    let logs = std::fs::read_to_string(journal.path("stdout.ndjson")).unwrap();
    for line in logs.lines() {
        if let Some(pid) = line.split('=').nth(1) {
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "unreaped process {pid}"
            );
        }
    }
    assert_eq!(
        journal.disposition().unwrap(),
        RecoveryDisposition::Completed
    );
}
#[tokio::test]
async fn exit_zero_is_only_execution_evidence_and_orphans_are_cleaned() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "zero").unwrap();
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(1);
    let (launch, _) = watch::channel(None);
    let script = "import os,time\np=os.fork()\nif p==0:\n print('child='+str(os.getpid()),flush=True)\n time.sleep(30)\nelse:\n print('parent-exits-zero',flush=True)\n time.sleep(.1)";
    let stop = supervise(
        spec(temp.path(), script),
        intent(temp.path(), "zero"),
        journal.clone(),
        limits(),
        cancel_rx,
        tx,
        launch,
    )
    .await
    .unwrap();
    assert_eq!(stop.exit_code, Some(0));
    assert!(stop.process_exit_confirmed);
    assert_eq!(stop.reason, "executor_exited");
    assert!(stop.stdout_bytes > 0);
}
#[tokio::test]
async fn timeout_terminates_real_child() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "timeout").unwrap();
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(1);
    let (launch, _) = watch::channel(None);
    let mut limits = limits();
    limits.timeout = Duration::from_millis(100);
    let stop = supervise(
        spec(temp.path(), "import time;time.sleep(30)"),
        intent(temp.path(), "timeout"),
        journal,
        limits,
        cancel_rx,
        tx,
        launch,
    )
    .await
    .unwrap();
    assert_eq!(stop.reason, "deadline_exceeded");
    assert!(stop.process_exit_confirmed);
}
#[test]
fn crash_after_intent_without_receipt_never_authorizes_relaunch() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "ambiguous").unwrap();
    journal
        .record_intent(&intent(temp.path(), "ambiguous"))
        .unwrap();
    assert!(matches!(
        journal.disposition().unwrap(),
        RecoveryDisposition::RecoveryRequired(_)
    ));
    assert!(
        journal
            .record_intent(&intent(temp.path(), "ambiguous"))
            .is_err()
    );
    assert!(!journal.path("launch-receipt.json").exists());
}
#[tokio::test]
async fn persisted_log_backpressure_is_bounded_and_not_silent() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "logs").unwrap();
    let (_cancel, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(1);
    let (launch, _) = watch::channel(None);
    let stop=supervise(spec(temp.path(),"import sys,time;sys.stdout.write('x'*200000);sys.stdout.flush();sys.stderr.write('e'*90000);sys.stderr.flush();time.sleep(.1)"),intent(temp.path(),"logs"),journal.clone(),limits(),cancel_rx,tx,launch).await.unwrap();
    assert!(stop.process_exit_confirmed);
    assert_eq!(stop.stdout_bytes, 200000);
    assert_eq!(stop.stderr_bytes, 90000);
    assert!(stop.notification_overflow > 0);
    assert!(stop.log_error.is_none());
}

// Executed in a distinct OS process only by the crash-injection test below.
#[tokio::test]
async fn crash_helper() {
    let Ok(root) = std::env::var("FORGEFLOW_RUNTIME_CRASH_HELPER") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let journal = Journal::new(&root, "crashed").unwrap();
    let (_cancel, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(1);
    let (launch, _) = watch::channel(None);
    let script = "import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=os.fork()\nprint('pid='+str(os.getpid()),flush=True)\nwhile True: time.sleep(.1)";
    let mut crash_limits = limits();
    crash_limits.timeout = Duration::from_secs(60);
    supervise(
        spec(&root, script),
        intent(&root, "crashed"),
        journal,
        crash_limits,
        cancel_rx,
        tx,
        launch,
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn actual_supervisor_crash_in_launch_receipt_window_quarantines_then_reconciles() {
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "crashed").unwrap();
    // Adopt the helper's orphaned descendants to prove explicit reaping, including grandchildren.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let helper = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_helper", "--nocapture"])
        .env("FORGEFLOW_RUNTIME_CRASH_HELPER", temp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut cleanup = CrashCleanup {
        helper: Some(helper),
        journal: journal.clone(),
        identity: None,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let logs = loop {
        if let Ok(receipt) = journal.receipt() {
            cleanup.identity = Some(receipt.process);
        }
        if let Ok(logs) = std::fs::read_to_string(journal.path("stdout.ndjson")) {
            if logs.lines().filter(|line| line.starts_with("pid=")).count() >= 2
                && cleanup.identity.is_some()
            {
                break logs;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "helper never published both durable process markers"
        );
        assert!(
            cleanup
                .helper
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "helper exited before launch handshake"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let receipt = journal.receipt().unwrap();
    let mut helper = cleanup.helper.take().unwrap();
    helper.kill().unwrap();
    helper.wait().unwrap();
    // Inject crash boundary: launch really occurred, but authoritative receipt is absent.
    std::fs::remove_file(journal.path("launch-receipt.json")).unwrap();
    assert!(matches!(
        journal.disposition().unwrap(),
        RecoveryDisposition::RecoveryRequired(_)
    ));
    assert!(
        reconcile(&journal, Duration::from_millis(100))
            .await
            .is_err()
    );
    assert!(
        journal
            .record_intent(&intent(temp.path(), "crashed"))
            .is_err()
    );
    assert!(std::path::Path::new(&format!("/proc/{}", receipt.process.pid)).exists());
    // Restored authenticated identity represents manual recovery evidence; no second launch occurs.
    journal.record_receipt(&receipt).unwrap();
    let stop = reconcile(&journal, Duration::from_millis(100))
        .await
        .unwrap();
    assert!(stop.process_exit_confirmed);
    for line in logs.lines() {
        if let Some(pid) = line.split('=').nth(1) {
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "crash left child {pid}"
            );
        }
    }
}

// A failed assertion must not abandon the deliberately crashed supervisor or its tools.
struct CrashCleanup {
    helper: Option<std::process::Child>,
    journal: Journal,
    identity: Option<ProcessIdentity>,
}
impl Drop for CrashCleanup {
    fn drop(&mut self) {
        if let Some(mut helper) = self.helper.take() {
            let _ = helper.kill();
            let _ = helper.wait();
        }
        let identity = self
            .identity
            .clone()
            .or_else(|| self.journal.receipt().ok().map(|r| r.process));
        let mut cleanup_groups = std::collections::BTreeSet::new();
        // Cover the genuine spawn-before-receipt window using both exact test markers
        // and this test's unique cwd; never signal an unrelated process group.
        if identity.is_none() {
            let expected = self.journal.directory.parent();
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                        continue;
                    };
                    let Ok(environment) = std::fs::read(entry.path().join("environ")) else {
                        continue;
                    };
                    let marker = environment
                        .split(|b| *b == 0)
                        .any(|v| v == b"FORGEFLOW_ATTEMPT_ID=crashed")
                        && environment
                            .split(|b| *b == 0)
                            .any(|v| v == b"FORGEFLOW_OPERATION_ID=op-crashed");
                    if marker
                        && std::fs::read_link(entry.path().join("cwd")).ok().as_deref() == expected
                    {
                        let pgid = unsafe { libc::getpgid(pid) };
                        if pgid > 1 {
                            cleanup_groups.insert(pgid);
                            unsafe {
                                libc::kill(-pgid, libc::SIGKILL);
                            }
                        }
                    }
                }
            }
        }
        if let Some(identity) = identity {
            if identity_matches(&identity).unwrap_or(false) {
                unsafe {
                    libc::kill(-identity.pgid, libc::SIGKILL);
                }
            }
            cleanup_groups.insert(identity.pgid);
        }
        for pgid in cleanup_groups {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let pid = unsafe { libc::waitpid(-pgid, std::ptr::null_mut(), libc::WNOHANG) };
                if pid < 0 {
                    break;
                }
                if pid == 0 {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

#[tokio::test]
async fn revoked_before_spawn_cannot_start_even_a_fast_side_effect() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "pre-revoked").unwrap();
    let (_cancel, cancel_rx) = watch::channel(true);
    let (tx, _rx) = mpsc::channel(1);
    let (launch, _) = watch::channel(None);
    let stop = supervise(
        spec(
            temp.path(),
            "open('forbidden-side-effect','w').write('started')",
        ),
        intent(temp.path(), "pre-revoked"),
        journal.clone(),
        limits(),
        cancel_rx,
        tx,
        launch,
    )
    .await
    .unwrap();
    assert!(stop.process_exit_confirmed);
    assert_eq!(stop.reason, "cancelled_before_launch");
    assert!(!temp.path().join("forbidden-side-effect").exists());
    assert!(!journal.path("launch-receipt.json").exists());
}

#[test]
fn execution_uuid_survives_restart_and_never_aliases_dispatch_operation() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "identity").unwrap();
    let execution = journal.execution_id().unwrap();
    let mut launch = intent(temp.path(), "identity");
    launch.execution_id = execution.clone();
    launch.operation_id = uuid::Uuid::new_v4().to_string();
    assert_ne!(execution, launch.operation_id);
    journal.record_intent(&launch).unwrap();
    let reopened = Journal::new(temp.path(), "identity").unwrap();
    assert_eq!(reopened.execution_id().unwrap(), execution);
    let durable: LaunchIntent =
        serde_json::from_slice(&std::fs::read(reopened.path("launch-intent.json")).unwrap())
            .unwrap();
    assert_eq!(durable.execution_id, execution);
}
