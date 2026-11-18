use forgeflow_evidence::*;
fn receipt() -> VerificationReceipt {
    VerificationReceipt {
        binding: EvidenceBinding {
            task_revision: 1,
            attempt_id: "attempt".into(),
            generation: 2,
            base_sha: "base".into(),
            candidate_sha: "candidate".into(),
            integrated_sha: None,
            contract_version: "v1".into(),
            verification_plan_id: "plan-v1".into(),
            verification_plan_hash: "plan-hash".into(),
            input_hash: "input".into(),
            source_hash: "tree".into(),
        },
        environment_profile: "linux-test".into(),
        command: vec!["consumer-test".into()],
        exit_code: 0,
        total: 2,
        failed: 0,
        skipped: 0,
        positive_cases: 1,
        negative_cases: 1,
        oracle_id: "independent-fixture".into(),
        verifier_id: "verifier".into(),
        author_id: "author".into(),
        independent: true,
        log_path: "artifacts/test.log".into(),
        log_hash: "log".into(),
    }
}
#[test]
fn rejects_empty_all_skipped_and_inconsistent_denominators() {
    let mut r = receipt();
    assert!(r.validate(&r.binding, true).is_ok());
    r.total = 0;
    assert!(matches!(
        r.validate(&r.binding, true),
        Err(EvidenceError::Invalid(_))
    ));
    r.total = 2;
    r.skipped = 2;
    assert!(matches!(
        r.validate(&r.binding, true),
        Err(EvidenceError::Invalid(_))
    ));
    r.skipped = 0;
    r.negative_cases = 0;
    assert!(matches!(
        r.validate(&r.binding, true),
        Err(EvidenceError::Invalid(_))
    ));
}
#[test]
fn rejects_wrong_binding_author_oracle_and_failure() {
    let mut r = receipt();
    let mut b = r.binding.clone();
    b.candidate_sha = "wrong".into();
    assert_eq!(r.validate(&b, true), Err(EvidenceError::BindingMismatch));
    r.verifier_id = r.author_id.clone();
    assert!(r.validate(&r.binding, true).is_err());
    r.verifier_id = "verifier".into();
    r.exit_code = 1;
    assert_eq!(r.validate(&r.binding, true), Err(EvidenceError::Failed));
}

#[test]
fn raw_log_bytes_are_required_and_path_escape_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let mut r = receipt();
    std::fs::create_dir(temp.path().join("artifacts")).unwrap();
    let bytes = b"independent raw test log: two actual cases\n";
    std::fs::write(temp.path().join(&r.log_path), bytes).unwrap();
    r.log_hash = sha256(bytes);
    assert!(r.validate_log(temp.path()).is_ok());
    std::fs::write(temp.path().join(&r.log_path), b"tampered").unwrap();
    assert!(r.validate_log(temp.path()).is_err());
    r.log_path = "../outside.log".into();
    assert!(r.validate_log(temp.path()).is_err());
    #[cfg(unix)]
    {
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), bytes).unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("escaped.log")).unwrap();
        r.log_path = "escaped.log".into();
        r.log_hash = sha256(bytes);
        assert!(r.validate_log(temp.path()).is_err());
    }
}
