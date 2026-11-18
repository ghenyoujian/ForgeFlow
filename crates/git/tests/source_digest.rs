#![cfg(unix)]
use forgeflow_git::{SOURCE_CONTENT_ALGORITHM, source_content_manifest, source_hash};
use std::{
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
    },
    path::Path,
    process::Command,
};

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn seed(repo: &Path, format: &str) -> String {
    fs::create_dir(repo).unwrap();
    git(
        repo,
        &[
            "init",
            "--initial-branch=main",
            &format!("--object-format={format}"),
        ],
    );
    git(repo, &["config", "user.name", "Source digest test"]);
    git(repo, &["config", "user.email", "source@local"]);
    fs::write(repo.join("script"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(repo.join("script"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        repo.join(std::ffi::OsString::from_vec(b"\xff name\n\t".to_vec())),
        b"a\0b\n",
    )
    .unwrap();
    symlink("../../outside", repo.join("link")).unwrap();
    git(repo, &["add", "--all"]);
    git(repo, &["commit", "-m", "tracked bytes"]);
    git(repo, &["rev-parse", "HEAD"])
}

#[test]
fn raw_paths_modes_and_symlink_bytes_have_independent_known_digest_across_git_formats() {
    let temp = tempfile::tempdir().unwrap();
    let mut manifests = Vec::new();
    for format in ["sha1", "sha256"] {
        let repo = temp.path().join(format);
        let commit = seed(&repo, format);
        let manifest = source_content_manifest(&repo, &commit).unwrap();
        assert_eq!(manifest.algorithm, SOURCE_CONTENT_ALGORITHM);
        assert_eq!(manifest.commit_sha, commit);
        assert_eq!(manifest.tree_oid, source_hash(&repo, &commit).unwrap());
        assert_eq!(manifest.tracked_entries, 3);
        assert_eq!(manifest.total_blob_bytes, 34);
        // Independently generated from fixture bytes and the documented binary
        // format, without consulting Git IDs or this helper's manifest output.
        assert_eq!(
            manifest.source_sha256,
            "6b5bc4a062658d6702b540f2a373b83aa0261572b60aefb8741615c27bf05c7a"
        );
        assert_eq!(manifest.entries[2].path_hex, "ff206e616d650a09");
        assert_eq!(manifest.entries[0].mode, "120000");
        assert_eq!(manifest.entries[1].mode, "100755");
        manifests.push(manifest);
    }
    assert_ne!(manifests[0].tree_oid, manifests[1].tree_oid);
    assert_eq!(manifests[0].source_sha256, manifests[1].source_sha256);
}

#[test]
fn frozen_commit_ignores_dirty_files_external_symlink_targets_and_replacement_refs() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("nested")).unwrap();
    let repo = temp.path().join("nested/repo");
    let old = seed(&repo, "sha1");
    let expected = source_content_manifest(&repo, &old).unwrap();
    fs::write(repo.join("script"), "changed\n").unwrap();
    git(&repo, &["add", "script"]);
    git(&repo, &["commit", "-m", "different bytes"]);
    let new = git(&repo, &["rev-parse", "HEAD"]);
    assert_ne!(
        source_content_manifest(&repo, &new).unwrap().source_sha256,
        expected.source_sha256
    );
    git(&repo, &["replace", &old, &new]);
    fs::write(repo.join("script"), "dirty bytes").unwrap();
    fs::write(repo.join("untracked"), "ignored").unwrap();
    // A tracked link's target is hashed as bytes, without following the link.
    fs::write(temp.path().join("outside"), "target changed").unwrap();
    assert_eq!(source_content_manifest(&repo, &old).unwrap(), expected);
}

#[test]
fn submodule_tree_cannot_claim_known_source_content() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let commit = seed(&repo, "sha1");
    git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{commit},module"),
        ],
    );
    git(
        &repo,
        &["commit", "-m", "gitlink has unknown checkout bytes"],
    );
    let error = source_content_manifest(&repo, "HEAD").unwrap_err();
    assert!(error.to_string().contains("submodules"), "{error}");
}
