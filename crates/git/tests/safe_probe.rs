#![cfg(unix)]

use forgeflow_git::safe_probe::{ProbeQuery, read};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn command(root: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap()
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = command(root, args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn fixture() -> (tempfile::TempDir, PathBuf, String) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("source");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "--initial-branch=main"]);
    git(&root, &["config", "user.name", "Isolated probe test"]);
    git(&root, &["config", "user.email", "probe@example.test"]);
    fs::write(root.join("tracked"), "hi\n").unwrap();
    fs::write(root.join(".gitignore"), "ignored\n").unwrap();
    git(&root, &["add", "--all"]);
    git(
        &root,
        &["-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture"],
    );
    let head = git(&root, &["rev-parse", "HEAD"]);
    (temp, root, head)
}
fn hook(path: &Path, marker: &Path, filter: bool) {
    let tail = if filter { "cat\n" } else { "printf '\\0'\n" };
    fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf PROBE_HOOK > '{}'\n{tail}",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn unset_fixture_config(root: &Path, key: &str) {
    // `git -C root config --no-includes` can still parse the repository's
    // include during startup. Mutate only the explicit fixture file, from a
    // directory where no repository is discovered, exactly as the reader does.
    let output = Command::new("/usr/bin/git")
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["config", "--file"])
        .arg(root.join(".git/config"))
        .args(["--no-includes", "--unset", key])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn old_fsmonitor_executes_but_typed_probe_reads_the_same_repo_without_execution_or_index_write() {
    let (temp, root, head) = fixture();
    let marker = temp.path().join("marker");
    let executable = temp.path().join("fsmonitor");
    hook(&executable, &marker, false);
    git(
        &root,
        &["config", "core.fsmonitor", executable.to_str().unwrap()],
    );
    assert!(command(&root, &["status", "--porcelain"]).status.success());
    assert_eq!(fs::read_to_string(&marker).unwrap(), "PROBE_HOOK");
    fs::remove_file(&marker).unwrap();
    let index = fs::read(root.join(".git/index")).unwrap();
    assert_eq!(read(&root, ProbeQuery::Bare).unwrap(), "false");
    assert_eq!(read(&root, ProbeQuery::Head).unwrap(), head);
    assert_eq!(read(&root, ProbeQuery::Main).unwrap(), head);
    assert_eq!(read(&root, ProbeQuery::Branch).unwrap(), "main");
    assert_eq!(read(&root, ProbeQuery::Dirty).unwrap(), "");
    assert!(!marker.exists());
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
}

#[test]
fn old_clean_filter_executes_for_same_size_change_but_dirty_probe_fails_closed() {
    let (temp, root, _) = fixture();
    fs::write(root.join(".gitattributes"), "tracked filter=attack\n").unwrap();
    git(&root, &["add", ".gitattributes"]);
    git(&root, &["commit", "-m", "attributes"]);
    let marker = temp.path().join("marker");
    let executable = temp.path().join("clean-filter");
    hook(&executable, &marker, true);
    git(
        &root,
        &[
            "config",
            "filter.attack.clean",
            executable.to_str().unwrap(),
        ],
    );
    fs::write(root.join("tracked"), "ho\n").unwrap();
    assert!(
        command(
            &root,
            &["-c", "core.fsmonitor=false", "status", "--porcelain"]
        )
        .status
        .success()
    );
    assert!(
        marker.exists(),
        "same-size fixture must actually execute legacy clean filter"
    );
    fs::remove_file(&marker).unwrap();
    assert!(read(&root, ProbeQuery::Dirty).is_err());
    assert!(read(&root, ProbeQuery::Head).is_ok());
    assert!(!marker.exists());
    git(&root, &["config", "--unset", "filter.attack.clean"]);
    git(
        &root,
        &[
            "config",
            "filter.attack.process",
            executable.to_str().unwrap(),
        ],
    );
    assert!(read(&root, ProbeQuery::Dirty).is_err());
    assert!(!marker.exists());
}

#[test]
fn custom_attributes_cannot_be_ignored_to_report_a_false_clean_worktree() {
    let (temp, root, _) = fixture();
    let content = "$Id: external-normalization $\n";
    fs::write(root.join("tracked"), content).unwrap();
    git(&root, &["add", "tracked"]);
    git(&root, &["commit", "-m", "unnormalized fixture bytes"]);
    let attributes = temp.path().join("custom-attributes");
    fs::write(&attributes, "tracked ident\n").unwrap();
    git(
        &root,
        &[
            "config",
            "core.attributesFile",
            attributes.to_str().unwrap(),
        ],
    );
    fs::write(root.join("tracked"), content).unwrap();
    // Independent oracle: the configured ident rule changes these exact bytes.
    // Merely forcing attributesFile=/dev/null would incorrectly report clean.
    assert!(!git(&root, &["status", "--porcelain"]).is_empty());
    assert!(
        git(
            &root,
            &[
                "-c",
                "core.attributesFile=/dev/null",
                "status",
                "--porcelain"
            ]
        )
        .is_empty()
    );
    let index = fs::read(root.join(".git/index")).unwrap();
    assert!(read(&root, ProbeQuery::Dirty).is_err());
    assert!(read(&root, ProbeQuery::Head).is_ok());
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
}

#[test]
fn dirty_untracked_ignored_rename_and_detached_facts_remain_truthful() {
    let (_temp, root, head) = fixture();
    fs::write(root.join("ignored"), "ignored by tracked policy").unwrap();
    assert!(read(&root, ProbeQuery::Dirty).unwrap().is_empty());
    fs::write(root.join("untracked"), "new").unwrap();
    assert!(
        read(&root, ProbeQuery::Dirty)
            .unwrap()
            .contains("untracked")
    );
    fs::remove_file(root.join("untracked")).unwrap();
    git(&root, &["mv", "tracked", "renamed"]);
    let dirty = read(&root, ProbeQuery::Dirty).unwrap();
    assert!(dirty.contains("tracked") && dirty.contains("renamed"));
    git(&root, &["reset", "--hard", "HEAD"]);
    git(&root, &["checkout", "--detach", &head]);
    assert_eq!(read(&root, ProbeQuery::Head).unwrap(), head);
    assert!(read(&root, ProbeQuery::Branch).is_err());
    assert!(read(&root, ProbeQuery::Dirty).unwrap().is_empty());
}

#[test]
fn bare_linked_and_unborn_repositories_are_bound_to_the_requested_root() {
    let (temp, root, head) = fixture();
    let bare = temp.path().join("canonical.git");
    git(
        temp.path(),
        &[
            "clone",
            "--bare",
            root.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
    );
    assert_eq!(read(&bare, ProbeQuery::Bare).unwrap(), "true");
    assert_eq!(read(&bare, ProbeQuery::Head).unwrap(), head);
    assert!(read(&bare, ProbeQuery::Dirty).unwrap().is_empty());
    let linked = temp.path().join("linked");
    git(
        &root,
        &[
            "worktree",
            "add",
            "-b",
            "linked-branch",
            linked.to_str().unwrap(),
        ],
    );
    assert_eq!(read(&linked, ProbeQuery::Bare).unwrap(), "false");
    assert_eq!(read(&linked, ProbeQuery::Head).unwrap(), head);
    assert_eq!(read(&linked, ProbeQuery::Branch).unwrap(), "linked-branch");
    assert!(read(&linked, ProbeQuery::Dirty).unwrap().is_empty());
    fs::write(linked.join("tracked"), "linked dirt").unwrap();
    assert!(!read(&linked, ProbeQuery::Dirty).unwrap().is_empty());
    assert!(read(&root, ProbeQuery::Dirty).unwrap().is_empty());
    let wrong = temp.path().join("wrong");
    fs::create_dir(&wrong).unwrap();
    fs::copy(linked.join(".git"), wrong.join(".git")).unwrap();
    assert!(read(&wrong, ProbeQuery::Bare).is_err());
    let unborn = temp.path().join("unborn");
    fs::create_dir(&unborn).unwrap();
    git(&unborn, &["init", "-b", "main"]);
    assert_eq!(read(&unborn, ProbeQuery::Branch).unwrap(), "main");
    assert!(read(&unborn, ProbeQuery::Head).is_err());
    assert!(read(&unborn, ProbeQuery::Main).is_err());
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    assert!(
        read(&child, ProbeQuery::Bare).is_err(),
        "no parent discovery"
    );
}

#[test]
fn includes_external_objects_and_metadata_symlinks_are_rejected_without_following_them() {
    let (temp, root, _) = fixture();
    let outside = temp.path().join("outside-config");
    fs::write(&outside, "this is deliberately not valid Git config\n").unwrap();
    git(
        &root,
        &["config", "include.path", outside.to_str().unwrap()],
    );
    let error = read(&root, ProbeQuery::Bare).unwrap_err().to_string();
    assert!(error.contains("includes are unsupported"));
    unset_fixture_config(&root, "include.path");
    git(
        &root,
        &[
            "config",
            "includeIf.gitdir:*.path",
            outside.to_str().unwrap(),
        ],
    );
    assert!(read(&root, ProbeQuery::Head).is_err());
    unset_fixture_config(&root, "includeIf.gitdir:*.path");
    git(&root, &["config", "extensions.partialClone", "origin"]);
    assert!(read(&root, ProbeQuery::Bare).is_err());
    git(&root, &["config", "--unset", "extensions.partialClone"]);
    let alternates = root.join(".git/objects/info/alternates");
    fs::write(&alternates, "/outside/objects\n").unwrap();
    assert!(read(&root, ProbeQuery::Head).is_err());
    fs::remove_file(&alternates).unwrap();
    let config = root.join(".git/config");
    let saved = temp.path().join("saved-config");
    fs::rename(&config, &saved).unwrap();
    symlink(&saved, &config).unwrap();
    assert!(read(&root, ProbeQuery::Bare).is_err());
    fs::remove_file(&config).unwrap();
    fs::rename(saved, config).unwrap();
    fs::write(root.join(".git/commondir"), "../foreign\n").unwrap();
    assert!(read(&root, ProbeQuery::Dirty).is_err());
}

#[test]
fn transitive_symbolic_refs_cannot_escape_metadata_or_form_cycles() {
    let (temp, root, head) = fixture();
    let outside = temp.path().join("synthetic-valid-oid");
    fs::write(&outside, format!("{head}\n")).unwrap();
    let refs = root.join(".git/refs/heads");
    fs::write(refs.join("main"), "ref:\trefs/heads/indirect\n").unwrap();
    symlink(&outside, refs.join("indirect")).unwrap();
    assert_eq!(
        git(&root, &["rev-parse", "--verify", "HEAD^{commit}"]),
        head
    );
    assert!(read(&root, ProbeQuery::Head).is_err());
    fs::remove_file(refs.join("indirect")).unwrap();
    fs::write(refs.join("indirect"), "ref: refs/heads/main\n").unwrap();
    let error = read(&root, ProbeQuery::Head).unwrap_err().to_string();
    assert!(error.contains("cyclic symbolic reference"));
    fs::write(refs.join("main"), "ref: refs/heads/link0\n").unwrap();
    for index in 0..9 {
        fs::write(
            refs.join(format!("link{index}")),
            format!("ref: refs/heads/link{}\n", index + 1),
        )
        .unwrap();
    }
    fs::write(refs.join("link9"), format!("{head}\n")).unwrap();
    assert!(
        read(&root, ProbeQuery::Head)
            .unwrap_err()
            .to_string()
            .contains("depth exceeds limit")
    );
}

// Subprocess recursion injects hostile env without changing the shared test
// process environment (or racing unrelated parallel Rust tests).
#[test]
fn inherited_git_environment_and_path_cannot_redirect_the_probe() {
    if let Some(root) = std::env::var_os("FF_PROBE_CHILD_ROOT") {
        let root = PathBuf::from(root);
        assert_eq!(
            read(&root, ProbeQuery::Head).unwrap(),
            std::env::var("FF_PROBE_CHILD_HEAD").unwrap()
        );
        assert!(read(&root, ProbeQuery::Dirty).unwrap().is_empty());
        return;
    }
    let (temp, root, head) = fixture();
    let marker = temp.path().join("marker");
    let executable = temp.path().join("git");
    hook(&executable, &marker, false);
    let config = temp.path().join("host-config");
    fs::write(
        &config,
        format!(
            "[core]\n fsmonitor = {}\n[include]\n path = /does-not-exist\n",
            executable.display()
        ),
    )
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inherited_git_environment_and_path_cannot_redirect_the_probe",
            "--nocapture",
        ])
        .env("FF_PROBE_CHILD_ROOT", &root)
        .env("FF_PROBE_CHILD_HEAD", &head)
        .env("PATH", temp.path())
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path())
        .env("GIT_DIR", temp.path().join("wrong.git"))
        .env("GIT_COMMON_DIR", temp.path().join("wrong.git"))
        .env("GIT_WORK_TREE", temp.path())
        .env("GIT_INDEX_FILE", &config)
        .env("GIT_OBJECT_DIRECTORY", temp.path())
        .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", temp.path())
        .env("GIT_CONFIG_SYSTEM", &config)
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", &executable)
        .env("GIT_NAMESPACE", "wrong")
        .env("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=wrong'")
        .env("GIT_EXTERNAL_DIFF", &executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists());
}
