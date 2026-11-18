use forgeflow_runtime::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
fn digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}
fn profile() -> SandboxProfile {
    let bwrap = PathBuf::from("/usr/bin/bwrap");
    let guard = PathBuf::from(env!("CARGO_BIN_EXE_forgeflow-sandbox-guard"));
    SandboxProfile {
        bwrap_sha256: digest(&bwrap),
        bwrap_program: bwrap,
        guard_sha256: digest(&guard),
        guard_program: guard,
        readonly_paths: vec!["/usr".into(), "/bin".into(), "/lib".into(), "/lib64".into()],
        network_allowed: false,
    }
}
fn intent(root: &Path, id: &str) -> LaunchIntent {
    LaunchIntent {
        execution_id: uuid::Uuid::new_v4().to_string(),
        operation_id: format!("op-{id}"),
        attempt_id: id.into(),
        generation: 1,
        worker_id: "sandbox-test".into(),
        boot_id: boot_id().unwrap(),
        workspace: root.into(),
        prompt_sha256: "a".repeat(64),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}
#[tokio::test]
async fn exact_mount_and_landlock_guard_blocks_undeclared_code_and_host_reads() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("private");
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join("denied.txt"), b"unchanged").unwrap();
    let host_secret = temp.path().join("host-secret");
    std::fs::write(&host_secret, b"not-mounted").unwrap();
    let script = "import pathlib,sys,json,os\na=pathlib.Path('allowed.txt');a.write_text('approved')\nchecks={}\nfor k,op in [('undeclared_write',lambda:pathlib.Path('denied.txt').write_text('bad')),('adjacent_temp',lambda:pathlib.Path('undeclared.tmp').write_text('bad')),('chmod',lambda:os.chmod('denied.txt',0o777)),('host_read',lambda:pathlib.Path(sys.argv[1]).read_text()),('host_proc',lambda:pathlib.Path('/proc/'+sys.argv[2]+'/environ').read_bytes())]:\n try:op();checks[k]=False\n except OSError:checks[k]=True\nprint(json.dumps(checks),flush=True)\nassert all(checks.values())";
    let original = ProcessSpec {
        program: "/usr/bin/python3".into(),
        args: vec![
            "-c".into(),
            script.into(),
            host_secret.to_string_lossy().into_owned(),
            std::process::id().to_string(),
        ],
        env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        cwd: workspace.clone(),
        stdin: vec![],
    };
    let spec = sandbox_command(
        original,
        &profile(),
        &SandboxInstance {
            workspace: workspace.clone(),
            write_set: vec!["allowed.txt".into()],
            allow_git_metadata: true,
            writable_mounts: vec![],
        },
    )
    .unwrap();
    let journal = Journal::new(&temp.path().join("journals"), "guarded").unwrap();
    let (_cancel, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(8);
    let (launch, _) = watch::channel(None);
    let stop = supervise(
        spec,
        intent(&workspace, "guarded"),
        journal.clone(),
        SupervisionLimits::default(),
        cancel_rx,
        tx,
        launch,
    )
    .await
    .unwrap();
    let stderr = std::fs::read_to_string(journal.path("stderr.log")).unwrap();
    assert_eq!(stop.exit_code, Some(0), "{stop:?} {stderr}");
    assert!(stop.process_exit_confirmed);
    assert_eq!(
        std::fs::read(workspace.join("allowed.txt")).unwrap(),
        b"approved"
    );
    assert_eq!(
        std::fs::read(workspace.join("denied.txt")).unwrap(),
        b"unchanged"
    );
    assert_eq!(std::fs::read(host_secret).unwrap(), b"not-mounted");
}

#[tokio::test]
async fn declared_directory_allows_atomic_replace_but_denies_outside_mutations() {
    // Real Python syscalls in bwrap/Landlock; this does not qualify Claude Edit.
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("private");
    std::fs::create_dir_all(workspace.join("owned")).unwrap();
    std::fs::write(workspace.join("owned/calculator.py"), b"old").unwrap();
    std::fs::write(workspace.join("denied.txt"), b"keep").unwrap();
    let script = r#"import pathlib,os,json
owned=pathlib.Path('owned')
target=owned/'calculator.py'
original_inode=target.stat().st_ino
stage=owned/'calculator.py.tmp.fixture'
stage.write_text('updated')
staged_inode=stage.stat().st_ino
os.replace(stage,target)
assert target.read_text()=='updated' and not stage.exists()
assert target.stat().st_ino==staged_inode and staged_inode!=original_inode
checks={}
def denied(label,operation):
    try: operation(); checks[label]=False
    except OSError: checks[label]=True
denied('outside_write',lambda:pathlib.Path('denied.txt').write_text('bad'))
denied('outside_create',lambda:pathlib.Path('outside.tmp').write_text('bad'))
rename_source=owned/'rename-source.tmp'
rename_source.write_text('owned')
denied('rename_out',lambda:os.replace(rename_source,'denied.txt'))
denied('rename_in',lambda:os.replace('denied.txt',owned/'stolen.txt'))
escape=owned/'escape'
os.symlink('../denied.txt',escape)
denied('symlink_write',lambda:escape.write_text('bad'))
os.symlink('..',owned/'parent-link')
denied('existing_symlink_directory_write',lambda:(owned/'parent-link'/'outside.tmp').write_text('bad'))
escape.unlink(); (owned/'parent-link').unlink(); rename_source.unlink()
assert pathlib.Path('denied.txt').read_text()=='keep'
assert all(checks.values()),checks
print(json.dumps(checks),flush=True)
"#;
    let spec = sandbox_command(
        ProcessSpec {
            program: "/usr/bin/python3".into(),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            cwd: workspace.clone(),
            stdin: vec![],
        },
        &profile(),
        &SandboxInstance {
            workspace: workspace.clone(),
            write_set: vec!["owned/".into()],
            allow_git_metadata: false,
            writable_mounts: vec![],
        },
    )
    .unwrap();
    let journal = Journal::new(&temp.path().join("journals"), "directory-atomic").unwrap();
    let (_cancel, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(8);
    let (launch, _) = watch::channel(None);
    let stop = supervise(
        spec,
        intent(&workspace, "directory-atomic"),
        journal.clone(),
        SupervisionLimits::default(),
        cancel_rx,
        tx,
        launch,
    )
    .await
    .unwrap();
    let stderr = std::fs::read_to_string(journal.path("stderr.log")).unwrap();
    assert_eq!(stop.exit_code, Some(0), "{stop:?} {stderr}");
    assert!(stop.process_exit_confirmed);
    assert_eq!(
        std::fs::read(workspace.join("owned/calculator.py")).unwrap(),
        b"updated"
    );
    assert_eq!(
        std::fs::read(workspace.join("denied.txt")).unwrap(),
        b"keep"
    );
    assert!(!workspace.join("outside.tmp").exists());
    assert_eq!(
        std::fs::read_dir(workspace.join("owned")).unwrap().count(),
        1
    );
}

#[test]
fn directory_scope_requires_single_suffix_real_directory_and_safe_concrete_path() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("private");
    std::fs::create_dir_all(workspace.join("owned/nested")).unwrap();
    std::fs::write(workspace.join("regular.txt"), b"keep").unwrap();
    symlink("owned", workspace.join("directory-link")).unwrap();
    let profile = profile();
    let prepare = |path: &str| {
        sandbox_command(
            ProcessSpec {
                program: "/usr/bin/true".into(),
                args: vec![],
                env: BTreeMap::new(),
                cwd: workspace.clone(),
                stdin: vec![],
            },
            &profile,
            &SandboxInstance {
                workspace: workspace.clone(),
                write_set: vec![path.into()],
                allow_git_metadata: false,
                writable_mounts: vec![],
            },
        )
    };
    assert!(prepare("owned/").is_ok());
    assert!(prepare("owned/nested/").is_ok());
    assert!(prepare("regular.txt").is_ok());
    for path in [
        "",
        "/",
        "/owned/",
        "owned//",
        "owned///",
        "owned//nested/",
        "owned/./nested/",
        "owned/../",
        "./owned/",
        "../owned/",
        ".git",
        ".git/",
        ".git/config/",
        "owned/*/",
        "owned/?/",
        "owned\\nested/",
        "C:/owned/",
        "owned\0/",
        "regular.txt/",
        "owned",
        "directory-link/",
        "directory-link/nested/",
        "missing/",
        "missing/nested/",
    ] {
        assert!(
            prepare(path).is_err(),
            "unsafe or mismatched scope accepted: {path:?}"
        );
    }
    assert!(!workspace.join("missing").exists());
    assert_eq!(
        std::fs::read(workspace.join("regular.txt")).unwrap(),
        b"keep"
    );
}
#[tokio::test]
async fn landlock_itself_denies_nonallowed_writes_on_writable_host_fixture() {
    let temp = tempfile::tempdir().unwrap();
    let allowed = temp.path().join("allowed");
    let denied = temp.path().join("denied");
    std::fs::write(&allowed, b"old").unwrap();
    std::fs::write(&denied, b"keep").unwrap();
    let script = "import pathlib,sys\npathlib.Path(sys.argv[1]).write_text('ok')\ntry:pathlib.Path(sys.argv[2]).write_text('bad');raise AssertionError('landlock failed')\nexcept PermissionError:pass";
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_forgeflow-sandbox-guard"))
        .args([
            "--allow-file",
            allowed.to_str().unwrap(),
            "--",
            "/usr/bin/python3",
            "-c",
            script,
            allowed.to_str().unwrap(),
            denied.to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(allowed).unwrap(), b"ok");
    assert_eq!(std::fs::read(denied).unwrap(), b"keep");
}
#[tokio::test]
async fn killing_sandbox_monitor_ends_setsid_grandchildren_in_private_pid_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("private");
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    let script = "import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=os.fork()\nif p==0:os.setsid();print('namespace-grandchild',flush=True)\nelse:print('namespace-parent',flush=True)\nwhile True:time.sleep(.01)";
    let spec = sandbox_command(
        ProcessSpec {
            program: "/usr/bin/python3".into(),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::new(),
            cwd: workspace.clone(),
            stdin: vec![],
        },
        &profile(),
        &SandboxInstance {
            workspace: workspace.clone(),
            write_set: vec![],
            allow_git_metadata: false,
            writable_mounts: vec![],
        },
    )
    .unwrap();
    let journal = Journal::new(temp.path(), "ns-cancel").unwrap();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(8);
    let (launch, _) = watch::channel(None);
    let mut limits = SupervisionLimits::default();
    limits.term_grace = Duration::from_millis(100);
    limits.kill_grace = Duration::from_secs(3);
    let task = tokio::spawn(supervise(
        spec,
        intent(&workspace, "ns-cancel"),
        journal.clone(),
        limits,
        cancel_rx,
        tx,
        launch,
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(log) = std::fs::read_to_string(journal.path("stdout.ndjson")) {
            if log.contains("namespace-grandchild") {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox never reached child marker"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel_tx.send(true).unwrap();
    let stop = task.await.unwrap().unwrap();
    assert!(stop.process_exit_confirmed, "{stop:?}");
}
