use forgeflow_runtime::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};
use tokio::sync::{mpsc, watch};

fn intent(root: &Path, attempt: &str) -> LaunchIntent {
    LaunchIntent {
        execution_id: uuid::Uuid::new_v4().to_string(),
        operation_id: format!("dispatch-{attempt}"),
        attempt_id: attempt.into(),
        generation: 17,
        worker_id: "durability-worker".into(),
        boot_id: boot_id().unwrap(),
        workspace: root.into(),
        prompt_sha256: "a".repeat(64),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn spec(root: &Path) -> ProcessSpec {
    ProcessSpec {
        program: "/usr/bin/python3".into(),
        args: vec![
            "-c".into(),
            "import os,time,pathlib; p=pathlib.Path('actual-authors'); f=p.open('a'); f.write(os.environ['FORGEFLOW_EXECUTION_ID']+'\\n'); f.close(); print('actual-author',flush=True); time.sleep(.05)".into(),
        ],
        env: BTreeMap::from([
            ("PROVIDER_API_KEY".into(), "private-fixture-secret".into()),
            ("FORGEFLOW_ATTEMPT_ID".into(), "must-be-overridden".into()),
        ]),
        cwd: root.into(),
        stdin: b"private-fixture-stdin".to_vec(),
    }
}

fn limits() -> SupervisionLimits {
    SupervisionLimits {
        timeout: Duration::from_secs(10),
        term_grace: Duration::from_millis(100),
        kill_grace: Duration::from_secs(2),
        max_log_bytes: 8192,
    }
}

async fn run(
    journal: Journal,
    launch: LaunchIntent,
    spec: ProcessSpec,
) -> anyhow::Result<StopEvidence> {
    let (_cancel, cancellation) = watch::channel(false);
    let (notices, _rx) = mpsc::channel(8);
    let (launched, _rx) = watch::channel(None);
    supervise(
        spec,
        launch,
        journal,
        limits(),
        cancellation,
        notices,
        launched,
    )
    .await
}

#[test]
fn complete_bound_authority_retains_controls_and_hashes_without_secret_values() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "binding").unwrap();
    let launch = intent(temp.path(), "binding");
    let spec = spec(temp.path());
    journal.record_bound_intent(&launch, &spec).unwrap();
    let bytes = fs::read(journal.path("launch.lock")).unwrap();
    let authority = journal.launch_authority().unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&authority.intent).unwrap(),
        serde_json::to_value(&launch).unwrap()
    );
    let mut environment = spec.env.clone();
    environment.insert("FORGEFLOW_ATTEMPT_ID".into(), launch.attempt_id.clone());
    environment.insert("FORGEFLOW_OPERATION_ID".into(), launch.operation_id.clone());
    environment.insert("FORGEFLOW_EXECUTION_ID".into(), launch.execution_id.clone());
    assert_eq!(
        authority.environment_sha256,
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&environment).unwrap())
        )
    );
    assert_eq!(
        authority.command_sha256,
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(&spec.program, &spec.args)).unwrap())
        )
    );
    assert_eq!(
        authority.stdin_sha256,
        format!("{:x}", Sha256::digest(&spec.stdin))
    );
    assert_eq!(
        authority.working_directory_sha256,
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&spec.cwd).unwrap())
        )
    );
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("private-fixture-secret"));
    assert!(!text.contains("private-fixture-stdin"));
    assert!(!journal.path("execution-id.json").exists());
    assert_eq!(journal.execution_id().unwrap(), launch.execution_id);
    assert!(matches!(
        journal.disposition().unwrap(),
        RecoveryDisposition::RecoveryRequired(_)
    ));
    assert!(journal.record_bound_intent(&launch, &spec).is_err());
    assert_eq!(fs::read(journal.path("launch.lock")).unwrap(), bytes);
    assert!(!journal.path("launch-receipt.json").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(journal.path("launch.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&journal.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_supervisors_produce_one_actual_author_and_keep_one_authority() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "competing").unwrap();
    let first = intent(temp.path(), "competing");
    let second = intent(temp.path(), "competing");
    assert_ne!(first.execution_id, second.execution_id);
    let (one, two) = tokio::join!(
        run(journal.clone(), first, spec(temp.path())),
        run(journal.clone(), second, spec(temp.path())),
    );
    assert_eq!(
        usize::from(one.is_ok()) + usize::from(two.is_ok()),
        1,
        "{one:?} {two:?}"
    );
    let stop = one.or(two).unwrap();
    assert!(stop.process_exit_confirmed, "{stop:?}");
    let authority = journal.launch_authority().unwrap().unwrap();
    let receipt = journal.receipt().unwrap();
    assert_eq!(receipt.execution_id, authority.intent.execution_id);
    assert_eq!(
        fs::read_to_string(temp.path().join("actual-authors")).unwrap(),
        format!("{}\n", receipt.execution_id)
    );
    assert_eq!(
        journal.disposition().unwrap(),
        RecoveryDisposition::Completed
    );
}

// Only the crash test launches this helper in a separate real process.
#[test]
fn durability_crash_helper() {
    let Ok(root) = std::env::var("FORGEFLOW_RUNTIME_DURABILITY_ROOT") else {
        return;
    };
    let case = std::env::var("FORGEFLOW_RUNTIME_DURABILITY_CASE").unwrap();
    let root = std::path::PathBuf::from(root);
    let journal = Journal::new(&root, &format!("crash-{case}")).unwrap();
    // Deliberate aborts must not leave obsolete, potentially large core files.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
    if case == "complete" {
        journal
            .record_bound_intent(&intent(&root, "crash-complete"), &spec(&root))
            .unwrap();
    } else {
        use std::io::Write;
        fs::create_dir_all(&journal.directory).unwrap();
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(journal.path("launch.lock"))
            .unwrap();
        file.write_all(b"{\"schema_version\":\"forgeflow.launch-authority.v2\",\"intent\":")
            .unwrap();
        file.sync_all().unwrap();
        fs::File::open(&journal.directory)
            .unwrap()
            .sync_all()
            .unwrap();
    }
    std::process::abort();
}

#[tokio::test]
async fn real_crashes_with_complete_or_partial_authority_never_authorize_another_spawn() {
    for case in ["complete", "partial"] {
        let temp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durability_crash_helper", "--nocapture"])
            .env("FORGEFLOW_RUNTIME_DURABILITY_ROOT", temp.path())
            .env("FORGEFLOW_RUNTIME_DURABILITY_CASE", case)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGABRT));
        let attempt = format!("crash-{case}");
        let journal = Journal::new(temp.path(), &attempt).unwrap();
        let bytes = fs::read(journal.path("launch.lock")).unwrap();
        if case == "complete" {
            let execution = journal
                .launch_authority()
                .unwrap()
                .unwrap()
                .intent
                .execution_id;
            fs::remove_file(journal.path("launch-intent.json")).unwrap();
            assert_eq!(journal.execution_id().unwrap(), execution);
        } else {
            assert!(journal.execution_id().is_err());
        }
        assert!(matches!(
            journal.disposition().unwrap(),
            RecoveryDisposition::RecoveryRequired(_)
        ));
        assert!(
            reconcile(&journal, Duration::from_millis(20))
                .await
                .is_err()
        );
        assert!(
            run(
                journal.clone(),
                intent(temp.path(), &attempt),
                spec(temp.path())
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read(journal.path("launch.lock")).unwrap(), bytes);
        assert!(!temp.path().join("actual-authors").exists());
        assert!(!journal.path("launch-receipt.json").exists());
    }
}

#[tokio::test]
async fn actual_receipt_recovers_missing_or_torn_cache_and_refuses_conflicting_authority() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::new(temp.path(), "cache").unwrap();
    let stop = run(
        journal.clone(),
        intent(temp.path(), "cache"),
        spec(temp.path()),
    )
    .await
    .unwrap();
    assert!(stop.process_exit_confirmed);
    let original_receipt = fs::read(journal.path("launch-receipt.json")).unwrap();
    let original_authority = fs::read(journal.path("launch.lock")).unwrap();
    let expected = serde_json::to_value(&journal.receipt().unwrap().intent).unwrap();
    fs::remove_file(journal.path("launch-intent.json")).unwrap();
    journal.receipt().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(journal.path("launch-intent.json")).unwrap()
        )
        .unwrap(),
        expected
    );
    fs::write(journal.path("launch-intent.json"), b"{\"execution_id\":").unwrap();
    journal.receipt().unwrap();
    assert_eq!(
        fs::read(journal.path("launch-receipt.json")).unwrap(),
        original_receipt
    );
    assert_eq!(
        fs::read(journal.path("launch.lock")).unwrap(),
        original_authority
    );
    let mut changed = expected;
    changed["generation"] = serde_json::json!(18);
    fs::write(
        journal.path("launch-intent.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(journal.receipt().is_err());
    assert!(matches!(
        journal.disposition().unwrap(),
        RecoveryDisposition::RecoveryRequired(_)
    ));
    let mut changed: serde_json::Value = serde_json::from_slice(&original_authority).unwrap();
    changed["environment_sha256"] = serde_json::json!("b".repeat(64));
    fs::write(
        journal.path("launch.lock"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(journal.launch_authority().is_err());
    assert!(matches!(
        journal.disposition().unwrap(),
        RecoveryDisposition::RecoveryRequired(_)
    ));
    assert!(
        run(
            journal.clone(),
            intent(temp.path(), "cache"),
            spec(temp.path())
        )
        .await
        .is_err()
    );
    assert_eq!(
        fs::read_to_string(temp.path().join("actual-authors"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        fs::read(journal.path("launch-receipt.json")).unwrap(),
        original_receipt
    );
}

#[tokio::test]
async fn legacy_empty_lock_partial_intent_and_receipt_only_remain_fenced() {
    for case in ["lock", "partial-intent", "receipt-only"] {
        let temp = tempfile::tempdir().unwrap();
        let journal = Journal::new(temp.path(), case).unwrap();
        fs::create_dir_all(&journal.directory).unwrap();
        if case == "lock" {
            fs::write(journal.path("launch.lock"), []).unwrap();
        } else if case == "partial-intent" {
            fs::write(journal.path("launch-intent.json"), b"{\"execution_id\":").unwrap();
        } else {
            let launch = intent(temp.path(), case);
            let receipt = LaunchReceipt {
                execution_id: launch.execution_id.clone(),
                process: ProcessIdentity {
                    pid: 1234,
                    pgid: 1234,
                    start_ticks: 99,
                    boot_id: launch.boot_id.clone(),
                    attempt_id: case.into(),
                },
                intent: launch,
                launched_at: chrono::Utc::now().to_rfc3339(),
                command_program: "/usr/bin/python3".into(),
                command_args: vec![],
                environment_key_names: vec![],
            };
            journal.record_receipt(&receipt).unwrap();
            let original = fs::read(journal.path("launch-receipt.json")).unwrap();
            let mut changed = receipt;
            changed.process.pid += 1;
            assert!(journal.record_receipt(&changed).is_err());
            assert_eq!(
                fs::read(journal.path("launch-receipt.json")).unwrap(),
                original
            );
        }
        assert!(matches!(
            journal.disposition().unwrap(),
            RecoveryDisposition::RecoveryRequired(_)
        ));
        assert!(
            run(
                journal.clone(),
                intent(temp.path(), case),
                spec(temp.path())
            )
            .await
            .is_err()
        );
        assert!(!temp.path().join("actual-authors").exists());
    }
}
