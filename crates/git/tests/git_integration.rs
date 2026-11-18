use async_trait::async_trait;
use forgeflow_domain::{MergeIntent, MergeIntentState};
use forgeflow_evidence::*;
use forgeflow_git::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

fn git(p: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .arg("-C")
        .arg(p)
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim().into()
}
struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    base: String,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().to_owned();
        let seed = root.join("seed");
        fs::create_dir(&seed).unwrap();
        git(&seed, &["init", "--initial-branch=main"]);
        git(&seed, &["config", "user.email", "test@local"]);
        git(&seed, &["config", "user.name", "Test"]);
        fs::write(seed.join("a.txt"), "a\n").unwrap();
        fs::write(seed.join("b.txt"), "b\n").unwrap();
        fs::write(seed.join(".gitignore"), "hidden/\n").unwrap();
        git(&seed, &["add", "--all"]);
        git(&seed, &["commit", "-m", "base"]);
        let base = resolve(&seed, "HEAD").unwrap();
        let repo = init_managed_repository(Some(&seed), &root.join("canonical.git")).unwrap();
        Self {
            _temp: t,
            repo,
            base,
            root,
        }
    }
    fn wt(&self, id: &str) -> PathBuf {
        prepare_worktree(&self.repo, &self.base, id, &self.root.join(id))
            .unwrap()
            .absolute_path
    }
    fn scope(path: &str) -> PathScope {
        PathScope {
            owner_paths: vec![path.into()],
            write_set: vec![path.into()],
        }
    }
    fn candidate(&self, id: &str, path: &str, text: &str) -> Candidate {
        let w = self.wt(id);
        fs::write(w.join(path), text).unwrap();
        freeze_candidate(&w, &self.base, &Self::scope(path), id).unwrap()
    }
}
#[test]
fn audit_sees_committed_staged_unstaged_ignored_and_rename_old_side() {
    let f = Fixture::new();
    let w = f.wt("scope");
    fs::write(w.join("a.txt"), "legal\n").unwrap();
    fs::write(w.join("b.txt"), "illegal\n").unwrap();
    git(&w, &["add", "b.txt"]);
    git(
        &w,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@local",
            "commit",
            "-m",
            "illegal committed",
        ],
    );
    fs::write(w.join("b.txt"), "illegal again\n").unwrap();
    fs::create_dir(w.join("hidden")).unwrap();
    fs::write(w.join("hidden/ignored.txt"), "illegal ignored").unwrap();
    let error = freeze_candidate(&w, &f.base, &Fixture::scope("a.txt"), "legal only").unwrap_err();
    assert!(matches!(error, GitError::WriteScopeViolation(_)));
    assert_eq!(git(&w, &["log", "-1", "--format=%s"]), "illegal committed");
    let git_dir = git(&w, &["rev-parse", "--absolute-git-dir"]);
    let rejected: serde_json::Value = serde_json::from_slice(
        &fs::read(Path::new(&git_dir).join("forgeflow-rejected-diff.json")).unwrap(),
    )
    .unwrap();
    let layers: Vec<_> = rejected["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["layer"].as_str().unwrap())
        .collect();
    assert!(
        layers.contains(&"committed")
            && layers.contains(&"unstaged")
            && layers.contains(&"untracked")
    );
    let r = f.wt("rename");
    git(&r, &["mv", "b.txt", "a-new.txt"]);
    assert!(matches!(
        audit_worktree(&r, &f.base, &Fixture::scope("a-new.txt")),
        Err(GitError::WriteScopeViolation(_))
    ));
    let deletion = f.wt("delete");
    fs::remove_file(deletion.join("b.txt")).unwrap();
    assert!(matches!(
        audit_worktree(&deletion, &f.base, &Fixture::scope("a.txt")),
        Err(GitError::WriteScopeViolation(_))
    ));
    let staged = f.wt("staged");
    fs::write(staged.join("b.txt"), "staged illegal\n").unwrap();
    git(&staged, &["add", "b.txt"]);
    assert!(matches!(
        freeze_candidate(&staged, &f.base, &Fixture::scope("a.txt"), "must reject"),
        Err(GitError::WriteScopeViolation(_))
    ));
    assert_eq!(resolve(&staged, "HEAD").unwrap(), f.base);
}
#[test]
fn symlinks_submodules_and_stale_ref_are_rejected() {
    let f = Fixture::new();
    let w = f.wt("symlink");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../../secret", w.join("link")).unwrap();
        assert!(matches!(
            audit_worktree(&w, &f.base, &Fixture::scope("link")),
            Err(GitError::WriteScopeViolation(_))
        ));
    }
    git(
        &w,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},module", f.base),
        ],
    );
    assert!(matches!(
        audit_worktree(&w, &f.base, &Fixture::scope("module")),
        Err(GitError::WriteScopeViolation(_))
    ));
    let a = f.candidate("first", "a.txt", "first\n");
    let b = f.candidate("second", "b.txt", "second\n");
    compare_and_swap_ref(&f.repo, "refs/heads/main", &f.base, &a.candidate_sha).unwrap();
    assert!(matches!(
        compare_and_swap_ref(&f.repo, "refs/heads/main", &f.base, &b.candidate_sha),
        Err(GitError::StaleRef { .. })
    ));
    assert_eq!(
        resolve(&f.repo, "refs/heads/main").unwrap(),
        a.candidate_sha
    );
}
#[derive(Default)]
struct MemoryStore {
    intent: Mutex<Option<MergeIntent>>,
    fail_confirm: Mutex<bool>,
    fail_finalize: Mutex<bool>,
    confirmations: Mutex<usize>,
}
#[async_trait]
impl IntegrationStore for MemoryStore {
    async fn prepare_merge(&self, i: MergeIntent) -> Result<MergeIntent, String> {
        *self.intent.lock().unwrap() = Some(i.clone());
        Ok(i)
    }
    async fn decide_merge(&self, _: &str, _: &str, _: u64) -> Result<MergeIntent, String> {
        let mut lock = self.intent.lock().unwrap();
        let i = lock.as_mut().unwrap();
        i.state = MergeIntentState::CommitDecided;
        if let Some(receipt) = i.receipt.as_mut() {
            receipt["commit_decided"] = serde_json::Value::Bool(true);
        }
        i.revision += 1;
        Ok(i.clone())
    }
    async fn confirm_merge(
        &self,
        _: &str,
        _: &str,
        sha: &str,
        r: serde_json::Value,
    ) -> Result<MergeIntent, String> {
        if *self.fail_confirm.lock().unwrap() {
            return Err("injected DB outage after Git ref advanced".into());
        }
        let mut lock = self.intent.lock().unwrap();
        let i = lock.as_mut().unwrap();
        if matches!(
            i.state,
            MergeIntentState::Committed | MergeIntentState::Finalized
        ) {
            return Ok(i.clone());
        }
        i.state = MergeIntentState::RefUpdated;
        i.integrated_sha = Some(sha.into());
        i.receipt = Some(r);
        if let Some(receipt) = i.receipt.as_mut() {
            receipt["commit_decided"] = serde_json::Value::Bool(true);
            receipt["ref_updated"] = serde_json::Value::Bool(true);
        }
        if *self.fail_finalize.lock().unwrap() {
            return Err("injected FINALIZED persistence outage after durable REF_UPDATED".into());
        }
        *self.confirmations.lock().unwrap() += 1;
        i.state = MergeIntentState::Finalized;
        Ok(i.clone())
    }
    async fn get_merge_intent(&self, _: &str, _: &str) -> Result<MergeIntent, String> {
        self.intent.lock().unwrap().clone().ok_or("missing".into())
    }
    async fn pending_merges(&self, _: &str, _: &str) -> Result<Vec<MergeIntent>, String> {
        Ok(self
            .intent
            .lock()
            .unwrap()
            .iter()
            .filter(|i| {
                matches!(
                    i.state,
                    MergeIntentState::Prepared
                        | MergeIntentState::CommitDecided
                        | MergeIntentState::RefUpdated
                        | MergeIntentState::RecoveryRequired
                )
            })
            .cloned()
            .collect())
    }
    async fn abort_merge(&self, _: &str, _: &str, _: &str) -> Result<MergeIntent, String> {
        let mut lock = self.intent.lock().unwrap();
        let i = lock.as_mut().unwrap();
        if i.state != MergeIntentState::Prepared {
            return Err("COMMIT_IN_PROGRESS".into());
        }
        i.state = MergeIntentState::Aborted;
        Ok(i.clone())
    }
    async fn mark_merge_recovery_required(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<MergeIntent, String> {
        let mut lock = self.intent.lock().unwrap();
        let i = lock.as_mut().unwrap();
        i.state = MergeIntentState::RecoveryRequired;
        Ok(i.clone())
    }
}
fn binding(c: &Candidate, id: &str) -> EvidenceBinding {
    EvidenceBinding {
        task_revision: 1,
        attempt_id: id.into(),
        generation: 1,
        base_sha: c.base_sha.clone(),
        candidate_sha: c.candidate_sha.clone(),
        integrated_sha: None,
        contract_version: "v1".into(),
        verification_plan_id: "plan-v1".into(),
        verification_plan_hash: "plan-hash".into(),
        input_hash: "fixture".into(),
        source_hash: c.source_hash.clone(),
    }
}
fn verify(path: &Path, b: &EvidenceBinding) -> Result<VerificationReceipt, GitError> {
    // Consumer independently reads both files and checks the merged commit is the object under verification.
    assert_eq!(source_hash(path, "HEAD")?, b.source_hash);
    assert!(fs::read_to_string(path.join("a.txt"))?.ends_with('\n'));
    assert!(fs::read_to_string(path.join("b.txt"))?.ends_with('\n'));
    let log = format!(
        "independent consumer verified tree {}: a.txt and b.txt newline cases\n",
        b.source_hash
    );
    let verification_root = integration_verification_root(path)?;
    fs::write(verification_root.join("consumer.log"), &log)?;
    Ok(VerificationReceipt {
        binding: b.clone(),
        environment_profile: "real-git-temp".into(),
        command: vec!["independent-consumer-file-reader".into()],
        exit_code: 0,
        total: 2,
        failed: 0,
        skipped: 0,
        positive_cases: 1,
        negative_cases: 1,
        oracle_id: "filesystem-consumer".into(),
        verifier_id: "independent".into(),
        author_id: "author".into(),
        independent: true,
        log_path: "consumer.log".into(),
        log_hash: sha256(log.as_bytes()),
    })
}
#[tokio::test]
async fn moving_main_is_revalidated_and_ref_advance_db_failure_recovers_once() {
    let f = Fixture::new();
    let a = f.candidate("a", "a.txt", "first\n");
    let b = f.candidate("b", "b.txt", "second\n");
    let service = IntegrationService::default();
    let store = MemoryStore::default();
    let ba = binding(&a, "a");
    let sa = Fixture::scope("a.txt");
    let pa = f.root.join("integrate-a");
    let ia = service
        .integrate(
            &store,
            IntegrationRequest {
                repo: &f.repo,
                project_id: "p",
                attempt_id: "a",
                generation: 1,
                target_ref: "refs/heads/main",
                candidate: &a,
                scope: &sa,
                integration_path: &pa,
                binding: &ba,
            },
            verify,
        )
        .await
        .unwrap();
    let bb = binding(&b, "b");
    let sb = Fixture::scope("b.txt");
    let pb = f.root.join("integrate-b");
    *store.fail_confirm.lock().unwrap() = true;
    let result = service
        .integrate(
            &store,
            IntegrationRequest {
                repo: &f.repo,
                project_id: "p",
                attempt_id: "b",
                generation: 1,
                target_ref: "refs/heads/main",
                candidate: &b,
                scope: &sb,
                integration_path: &pb,
                binding: &bb,
            },
            |path, binding| {
                assert_eq!(fs::read_to_string(path.join("a.txt")).unwrap(), "first\n");
                assert_eq!(fs::read_to_string(path.join("b.txt")).unwrap(), "second\n");
                assert_ne!(binding.source_hash, b.source_hash);
                verify(path, binding)
            },
        )
        .await;
    let (unknown_intent, unknown_sha) = match result {
        Err(GitError::CommitInProgress {
            intent_id, new_sha, ..
        }) => (intent_id, new_sha),
        other => panic!("expected explicit unresolved commit identity: {other:?}"),
    };
    let pending = store.intent.lock().unwrap().clone().unwrap();
    assert_eq!(unknown_intent, pending.intent_id);
    assert_eq!(Some(unknown_sha), pending.integrated_sha);
    assert_eq!(pending.expected_sha, ia.integrated_sha.unwrap());
    let advanced = resolve(&f.repo, "refs/heads/main").unwrap();
    assert_eq!(advanced, pending.integrated_sha.clone().unwrap());
    *store.fail_confirm.lock().unwrap() = false;
    service
        .recover(&store, &f.repo, "p", &pending.intent_id)
        .await
        .unwrap();
    service
        .recover(&store, &f.repo, "p", &pending.intent_id)
        .await
        .unwrap();
    assert_eq!(*store.confirmations.lock().unwrap(), 2);
    assert_eq!(resolve(&f.repo, "refs/heads/main").unwrap(), advanced);
}
#[tokio::test]
async fn real_merge_conflict_preserves_worktree_and_does_not_prepare_intent() {
    let f = Fixture::new();
    let a = f.candidate("left", "a.txt", "left\n");
    let b = f.candidate("right", "a.txt", "right\n");
    compare_and_swap_ref(&f.repo, "refs/heads/main", &f.base, &a.candidate_sha).unwrap();
    let service = IntegrationService::default();
    let store = MemoryStore::default();
    let binding = binding(&b, "right");
    let scope = Fixture::scope("a.txt");
    let p = f.root.join("conflict");
    let error = service
        .integrate(
            &store,
            IntegrationRequest {
                repo: &f.repo,
                project_id: "p",
                attempt_id: "right",
                generation: 1,
                target_ref: "refs/heads/main",
                candidate: &b,
                scope: &scope,
                integration_path: &p,
                binding: &binding,
            },
            verify,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, GitError::Conflict(_)));
    assert!(
        fs::read_to_string(p.join("a.txt"))
            .unwrap()
            .contains("<<<<<<<")
    );
    assert!(store.intent.lock().unwrap().is_none());
    assert_eq!(resolve(&f.repo, "main").unwrap(), a.candidate_sha);
}

#[tokio::test]
async fn different_repositories_and_service_instances_share_one_serial_lane() {
    let f = Fixture::new();
    let other = Fixture::new();
    let a = f.candidate("lane-a", "a.txt", "lane-a\n");
    let b = other.candidate("lane-b", "b.txt", "lane-b\n");
    let first = IntegrationService::default();
    let second = IntegrationService::default();
    let store = MemoryStore::default();
    let entered = tokio::sync::Notify::new();
    let release = tokio::sync::Notify::new();
    let entered_ref = &entered;
    let release_ref = &release;
    let ba = binding(&a, "lane-a");
    let bb = binding(&b, "lane-b");
    let sa = Fixture::scope("a.txt");
    let sb = Fixture::scope("b.txt");
    let pa = f.root.join("lane-integrate-a");
    let pb = other.root.join("lane-integrate-b");
    let one = first.integrate_async(
        &store,
        IntegrationRequest {
            repo: &f.repo,
            project_id: "p",
            attempt_id: "lane-a",
            generation: 1,
            target_ref: "refs/heads/main",
            candidate: &a,
            scope: &sa,
            integration_path: &pa,
            binding: &ba,
        },
        |path, binding| async move {
            entered_ref.notify_one();
            release_ref.notified().await;
            verify(&path, &binding)
        },
    );
    let two = async {
        entered.notified().await;
        let waiting = second.integrate(
            &store,
            IntegrationRequest {
                repo: &other.repo,
                project_id: "other-project",
                attempt_id: "lane-b",
                generation: 1,
                target_ref: "refs/heads/main",
                candidate: &b,
                scope: &sb,
                integration_path: &pb,
                binding: &bb,
            },
            verify,
        );
        tokio::pin!(waiting);
        tokio::select! {
            _result=&mut waiting=>panic!("second repository bypassed the global lane while first revalidation was active"),
            _=tokio::time::sleep(std::time::Duration::from_millis(30))=>{
                assert!(!pb.exists(),"queued integration must not mutate another repository before lane acquisition");
                release.notify_one();waiting.await
            }
        }
    };
    let (a_result, b_result) = tokio::join!(one, two);
    assert!(a_result.is_ok());
    assert!(b_result.is_ok());
    assert!(pb.exists());
}

#[tokio::test]
async fn recovery_records_divergence_and_never_rewrites_an_unexpected_ref() {
    let f = Fixture::new();
    let candidate = f.candidate("recover-a", "a.txt", "decided\n");
    let external = f.candidate("external-writer", "b.txt", "external\n");
    let service = IntegrationService::default();
    let store = MemoryStore::default();
    *store.fail_confirm.lock().unwrap() = true;
    let b = binding(&candidate, "recover-a");
    let scope = Fixture::scope("a.txt");
    let path = f.root.join("recover-integrate");
    let result = service
        .integrate(
            &store,
            IntegrationRequest {
                repo: &f.repo,
                project_id: "p",
                attempt_id: "recover-a",
                generation: 1,
                target_ref: "refs/heads/main",
                candidate: &candidate,
                scope: &scope,
                integration_path: &path,
                binding: &b,
            },
            verify,
        )
        .await;
    assert!(matches!(result, Err(GitError::CommitInProgress { .. })));
    let intent = store.intent.lock().unwrap().clone().unwrap();
    let advanced = resolve(&f.repo, "main").unwrap();
    compare_and_swap_ref(
        &f.repo,
        "refs/heads/main",
        &advanced,
        &external.candidate_sha,
    )
    .unwrap();
    *store.fail_confirm.lock().unwrap() = false;
    for _ in 0..2 {
        assert!(matches!(
            service
                .recover(&store, &f.repo, "p", &intent.intent_id)
                .await,
            Err(GitError::Diverged(_))
        ));
    }
    assert_eq!(
        store.intent.lock().unwrap().as_ref().unwrap().state,
        MergeIntentState::RecoveryRequired
    );
    assert_eq!(resolve(&f.repo, "main").unwrap(), external.candidate_sha);
    assert_eq!(*store.confirmations.lock().unwrap(), 0);
}

#[tokio::test]
async fn another_process_repository_lock_blocks_reference_mutation() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let f = Fixture::new();
    let c = f.candidate("locked", "a.txt", "locked\n");
    let mut child=Command::new("python3").args(["-c","import fcntl,sys,time;f=open(sys.argv[1],'a+');fcntl.flock(f,fcntl.LOCK_EX);print('locked',flush=True);time.sleep(30)"])
        .arg(f.repo.join("forgeflow-integration.lock")).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "locked");
    let service = IntegrationService::default();
    let store = MemoryStore::default();
    let b = binding(&c, "locked");
    let scope = Fixture::scope("a.txt");
    let path = f.root.join("lock-blocked");
    let result = service
        .integrate(
            &store,
            IntegrationRequest {
                repo: &f.repo,
                project_id: "p",
                attempt_id: "locked",
                generation: 1,
                target_ref: "refs/heads/main",
                candidate: &c,
                scope: &scope,
                integration_path: &path,
                binding: &b,
            },
            verify,
        )
        .await;
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(matches!(result,Err(GitError::Store(message)) if message.contains("lane busy")));
    assert_eq!(resolve(&f.repo, "main").unwrap(), f.base);
    assert!(!path.exists());
    assert!(store.intent.lock().unwrap().is_none());
}

#[tokio::test]
async fn persisted_ref_updated_recovers_finalization_and_ref_rewrites_are_never_reapplied() {
    for rewritten in [false, true] {
        let f = Fixture::new();
        let c = f.candidate("stages", "a.txt", "durable-stages\n");
        let service = IntegrationService::default();
        let store = MemoryStore::default();
        *store.fail_finalize.lock().unwrap() = true;
        let b = binding(&c, "stages");
        let scope = Fixture::scope("a.txt");
        let path = f.root.join("staged-integration");
        let result = service
            .integrate(
                &store,
                IntegrationRequest {
                    repo: &f.repo,
                    project_id: "p",
                    attempt_id: "stages",
                    generation: 1,
                    target_ref: "refs/heads/main",
                    candidate: &c,
                    scope: &scope,
                    integration_path: &path,
                    binding: &b,
                },
                verify,
            )
            .await;
        assert!(matches!(result, Err(GitError::CommitInProgress { .. })));
        let intent = store.intent.lock().unwrap().clone().unwrap();
        assert_eq!(intent.state, MergeIntentState::RefUpdated);
        let advanced = resolve(&f.repo, "main").unwrap();
        *store.fail_finalize.lock().unwrap() = false;
        if rewritten {
            compare_and_swap_ref(&f.repo, "refs/heads/main", &advanced, &f.base).unwrap();
            for _ in 0..2 {
                assert!(matches!(
                    service
                        .recover(&store, &f.repo, "p", &intent.intent_id)
                        .await,
                    Err(GitError::Diverged(_))
                ));
            }
            assert_eq!(resolve(&f.repo, "main").unwrap(), f.base);
            assert_eq!(*store.confirmations.lock().unwrap(), 0);
        } else {
            let recovered = service
                .recover(&store, &f.repo, "p", &intent.intent_id)
                .await
                .unwrap();
            assert_eq!(recovered.state, MergeIntentState::Finalized);
            service
                .recover(&store, &f.repo, "p", &intent.intent_id)
                .await
                .unwrap();
            assert_eq!(resolve(&f.repo, "main").unwrap(), advanced);
            assert_eq!(*store.confirmations.lock().unwrap(), 1);
        }
    }
}
