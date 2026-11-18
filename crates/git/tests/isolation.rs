use forgeflow_git::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn fixture() -> (tempfile::TempDir, PathBuf, String) {
    let temp = tempfile::tempdir().unwrap();
    let seed = temp.path().join("seed");
    fs::create_dir(&seed).unwrap();
    git(&seed, &["init", "--initial-branch=main"]);
    fs::write(seed.join("allowed.txt"), "base\n").unwrap();
    fs::write(seed.join("outside.txt"), "outside\n").unwrap();
    git(&seed, &["add", "--all"]);
    git(
        &seed,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@local",
            "commit",
            "-m",
            "base",
        ],
    );
    let base = resolve(&seed, "HEAD").unwrap();
    let repo = init_managed_repository(Some(&seed), &temp.path().join("canonical.git")).unwrap();
    (temp, repo, base)
}
fn scope() -> PathScope {
    PathScope {
        owner_paths: vec!["allowed.txt".into()],
        write_set: vec!["allowed.txt".into()],
    }
}

#[test]
fn private_metadata_refs_are_independent_and_audited_transfer_does_not_advance_main() {
    let (temp, repo, base) = fixture();
    let private =
        prepare_isolated_repository(&repo, &base, "private", &temp.path().join("private")).unwrap();
    assert_eq!(private.isolation_profile, "PRIVATE_GIT_METADATA");
    assert!(private.object_bytes > 0);
    assert!(private.object_files > 0);
    assert!(private.absolute_path.join(".git").is_dir());
    assert!(
        !private
            .absolute_path
            .join(".git/objects/info/alternates")
            .exists()
    );
    verify_private_repository(&private.absolute_path).unwrap();
    fs::write(private.absolute_path.join("allowed.txt"), "candidate\n").unwrap();
    let candidate =
        freeze_candidate(&private.absolute_path, &base, &scope(), "private candidate").unwrap();
    git(
        &private.absolute_path,
        &["update-ref", "refs/heads/main", &candidate.candidate_sha],
    );
    assert_eq!(resolve(&repo, "refs/heads/main").unwrap(), base);
    assert!(resolve(&repo, &candidate.candidate_sha).is_err());
    import_candidate(
        &repo,
        &private.absolute_path,
        &candidate,
        "private",
        &scope(),
    )
    .unwrap();
    import_candidate(
        &repo,
        &private.absolute_path,
        &candidate,
        "private",
        &scope(),
    )
    .unwrap();
    assert_eq!(
        resolve(&repo, "refs/forgeflow/candidates/private").unwrap(),
        candidate.candidate_sha
    );
    assert_eq!(
        source_hash(&repo, &candidate.candidate_sha).unwrap(),
        candidate.source_hash
    );
    assert_eq!(resolve(&repo, "refs/heads/main").unwrap(), base);
    fs::write(private.absolute_path.join("outside.txt"), "illegal dirt\n").unwrap();
    assert!(matches!(
        import_candidate(
            &repo,
            &private.absolute_path,
            &candidate,
            "private",
            &scope()
        ),
        Err(GitError::WriteScopeViolation(_))
    ));
}

#[test]
fn shared_metadata_and_executable_private_configuration_are_rejected_without_execution() {
    let (temp, repo, base) = fixture();
    let private =
        prepare_isolated_repository(&repo, &base, "config", &temp.path().join("private")).unwrap();
    let marker = temp.path().join("executed-hook");
    git(
        &private.absolute_path,
        &[
            "config",
            "core.fsmonitor",
            &format!("touch {}", marker.display()),
        ],
    );
    assert!(verify_private_repository(&private.absolute_path).is_err());
    assert!(audit_worktree(&private.absolute_path, &base, &scope()).is_err());
    assert!(!marker.exists());
    git(
        &private.absolute_path,
        &["config", "--unset", "core.fsmonitor"],
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        git(
            &private.absolute_path,
            &["config", "core.filemode", "false"],
        );
        fs::set_permissions(
            private.absolute_path.join("outside.txt"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(matches!(
            audit_private_worktree(&private.absolute_path, &base, &scope()),
            Err(GitError::WriteScopeViolation(_))
        ));
        fs::set_permissions(
            private.absolute_path.join("outside.txt"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    fs::write(
        private.absolute_path.join(".git/objects/info/alternates"),
        repo.join("objects").to_string_lossy().as_bytes(),
    )
    .unwrap();
    assert!(verify_private_repository(&private.absolute_path).is_err());
    fs::remove_file(private.absolute_path.join(".git/objects/info/alternates")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(repo.join("refs"), private.absolute_path.join(".git/escape"))
            .unwrap();
        assert!(verify_private_repository(&private.absolute_path).is_err());
        fs::remove_file(private.absolute_path.join(".git/escape")).unwrap();
    }
    fs::hard_link(
        private.absolute_path.join(".git/config"),
        temp.path().join("shared-config"),
    )
    .unwrap();
    assert!(verify_private_repository(&private.absolute_path).is_err());
    let pointer =
        prepare_isolated_repository(&repo, &base, "pointer", &temp.path().join("pointer")).unwrap();
    fs::rename(
        pointer.absolute_path.join(".git"),
        temp.path().join("saved-private.git"),
    )
    .unwrap();
    fs::write(
        pointer.absolute_path.join(".git"),
        format!("gitdir: {}\n", repo.display()),
    )
    .unwrap();
    assert!(audit_private_worktree(&pointer.absolute_path, &base, &scope()).is_err());
    assert!(
        freeze_private_candidate(
            &pointer.absolute_path,
            &base,
            &scope(),
            "illegal pointer fallback"
        )
        .is_err()
    );
    assert_eq!(resolve(&repo, "refs/heads/main").unwrap(), base);
}

#[test]
fn bwrap_executor_cannot_write_canonical_and_private_ref_changes_remain_private() {
    let (temp, repo, base) = fixture();
    let private =
        prepare_isolated_repository(&repo, &base, "sandbox", &temp.path().join("private")).unwrap();
    let script = r#"import os,subprocess,sys
canonical=sys.argv[1]
try:
    with open(canonical+'/refs/heads/main','w') as output: output.write('escape')
except OSError:
    print('canonical write refused')
else:
    raise AssertionError('canonical repository was exposed writable')
result=subprocess.run(['git','-C','/workspace','update-ref','refs/heads/private-executor','HEAD'],capture_output=True,text=True)
assert result.returncode==0,result.stderr
assert os.path.isdir('/workspace/.git')
assert not os.path.exists('/workspace/.git/objects/info/alternates')
print('private ref updated; no canonical metadata mounted')
"#;
    let mut command = Command::new("/usr/bin/bwrap");
    command.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for directory in ["/bin", "/lib", "/lib64"] {
        if Path::new(directory).exists() {
            command.args(["--ro-bind", directory, directory]);
        }
    }
    command
        .args([
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind",
        ])
        .arg(&private.absolute_path)
        .arg("/workspace")
        .args([
            "--chdir",
            "/workspace",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            script,
        ])
        .arg(&repo);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "bwrap actual isolation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("canonical write refused"));
    assert_eq!(resolve(&repo, "refs/heads/main").unwrap(), base);
    assert!(resolve(&repo, "refs/heads/private-executor").is_err());
    assert_eq!(
        resolve(&private.absolute_path, "refs/heads/private-executor").unwrap(),
        base
    );
}
