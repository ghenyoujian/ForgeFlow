use forgeflow_evidence::*;
use std::{collections::BTreeMap, fs};

#[tokio::test]
async fn physical_verifier_seals_unused_commands_but_rejects_partial_launch_proofs() {
    let (t, plan, binding) = fixture("valid");
    let root = t.path().join("physical-artifacts");
    fs::create_dir(&root).unwrap();
    // Deliberately unavailable own delegation: no process may fall back to
    // legacy supervision, but an awaited prelaunch failure can close all rights.
    let request = forgeflow_runtime::PhysicalFenceRequest {
        project_id: "project-physical".into(),
        delegation: forgeflow_runtime::CgroupDelegation {
            unit_name: "forgeflow-control.service".into(),
            root_path: t.path().join("missing/forgeflow-control.service"),
        },
        limits: forgeflow_runtime::PhysicalCgroupLimits {
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
            memory_max_bytes: 128 * 1024 * 1024,
            memory_swap_max_bytes: 0,
            pids_max: 64,
            memory_oom_group: true,
        },
        resource_binding_sha256: "a".repeat(64),
    };
    let context = PhysicalVerificationContext::new(
        &binding.attempt_id,
        binding.generation,
        "physical-verification-op",
        &root,
        "verifier-root-physical",
        &plan,
        request,
    )
    .unwrap();
    assert_eq!(context.commands.len(), 3);
    assert_eq!(
        context
            .commands
            .iter()
            .map(|c| &c.execution_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    let (_tx, rx) = tokio::sync::watch::channel(false);
    assert!(
        execute_verification_with_guard_and_physical(
            &plan,
            &t.path().join("candidate"),
            &binding,
            &root,
            rx,
            Ok,
            Some(&context),
        )
        .await
        .is_err()
    );
    let evidence = verification_physical_stop_evidence(&root).unwrap();
    assert_eq!(evidence.len(), 3);
    assert!(
        evidence
            .iter()
            .all(|item| item["status"] == "NEVER_LAUNCHED"
                && item["unused_closed"] == true
                && item["runner_closed"] == true)
    );
    assert!(verification_stop_evidence(&root).unwrap().is_empty());
    assert!(!root.join("reports").exists());
    let seal_path = root.join("verification-physical-closed.json");
    let seal = fs::read(&seal_path).unwrap();
    fs::remove_file(&seal_path).unwrap();
    assert!(verification_physical_stop_evidence(&root).is_err());
    // Trusted exclusive startup also has the registered grant if a crash
    // preceded publication of the local command manifest. It closes rights,
    // never launches those commands to obtain a receipt.
    fs::remove_file(root.join("verification-physical-context.json")).unwrap();
    assert!(
        reconcile_registered_verification_runs(&root, Some(&context))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(fs::read(&seal_path).unwrap(), seal);
    assert_eq!(verification_physical_stop_evidence(&root).unwrap().len(), 3);
    let command = &context.commands[0];
    let journal = forgeflow_runtime::Journal::new(
        &root.join("verification-runs"),
        &command.process_attempt_id,
    )
    .unwrap();
    fs::create_dir_all(&journal.directory).unwrap();
    let intent = forgeflow_runtime::LaunchIntent {
        execution_id: command.execution_id.clone(),
        operation_id: context.operation_id.clone(),
        attempt_id: command.process_attempt_id.clone(),
        generation: context.generation,
        worker_id: plan.verifier_id.clone(),
        boot_id: forgeflow_runtime::boot_id().unwrap(),
        workspace: t.path().join("candidate"),
        prompt_sha256: "b".repeat(64),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    // A standalone PASS-shaped process stop cannot replace the missing bound
    // launch lock/fence; the previously unused seal cannot conceal new effects.
    forgeflow_runtime::durable_json(&journal.path("launch-intent.json"), &intent).unwrap();
    forgeflow_runtime::durable_json(
        &journal.path("stop.json"),
        &forgeflow_runtime::StopEvidence {
            exit_code: Some(0),
            signal: None,
            reason: "executor_exited".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        },
    )
    .unwrap();
    assert!(verification_stop_evidence(&root).is_err());
    fs::remove_file(journal.path("launch-intent.json")).unwrap();
    fs::remove_file(journal.path("stop.json")).unwrap();
    fs::write(journal.path("launch.lock"), b"partial authority").unwrap();
    assert!(verification_physical_stop_evidence(&root).is_err());
    assert!(verification_stop_evidence(&root).is_err());
    assert!(
        reconcile_registered_verification_runs(&root, Some(&context))
            .await
            .is_err()
    );
    fs::remove_file(journal.path("launch.lock")).unwrap();
    // prepare() creates a deterministic leaf before publishing cgroup-fence;
    // even without journal markers that leaf forbids a negative closure.
    let identity = (
        &context.physical_request.project_id,
        &command.process_attempt_id,
        context.generation,
        &command.execution_id,
    );
    let leaf = context.physical_request.delegation.root_path.join(format!(
        "attempt-{}",
        sha256(&serde_json::to_vec(&identity).unwrap())
    ));
    fs::create_dir_all(&leaf).unwrap();
    assert!(verification_physical_stop_evidence(&root).is_err());
    assert!(
        reconcile_registered_verification_runs(&root, Some(&context))
            .await
            .is_err()
    );
    fs::remove_dir(&leaf).unwrap();
    // Synthetic durable records exercise the two real runtime pre-exec stop
    // branches after an owned unit has gone away. This is a validator fixture,
    // never a claim that this unit test ran a physically contained process.
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(&context.physical_request.delegation.root_path).unwrap();
    let mut fence = forgeflow_runtime::CgroupFenceIdentity {
        schema_version: "forgeflow.cgroup-fence.v1".into(),
        project_id: context.physical_request.project_id.clone(),
        attempt_id: command.process_attempt_id.clone(),
        generation: context.generation,
        execution_id: command.execution_id.clone(),
        boot_id: intent.boot_id.clone(),
        owner_uid: metadata.uid(),
        delegation: context.physical_request.delegation.clone(),
        mount_id: 1,
        mount_path: t.path().to_path_buf(),
        mount_device: metadata.dev(),
        root_inode: metadata.ino(),
        leaf_path: leaf,
        leaf_inode: 4242,
        limits: context.physical_request.limits.clone(),
        resource_binding_sha256: context.physical_request.resource_binding_sha256.clone(),
        identity_sha256: String::new(),
    };
    fence.identity_sha256 = fence.digest().unwrap();
    journal.record_cgroup_fence(&fence).unwrap();
    let spec = forgeflow_runtime::ProcessSpec {
        program: plan.commands[0].program.clone(),
        args: plan.commands[0].args.clone(),
        env: plan.commands[0].env.clone(),
        cwd: intent.workspace.clone(),
        stdin: Vec::new(),
    };
    journal
        .record_bound_intent_physical(&intent, &spec, &fence)
        .unwrap();
    forgeflow_runtime::durable_json(
        &journal.path("verification-command.json"),
        &serde_json::json!({"context":context,"command":command}),
    )
    .unwrap();
    forgeflow_runtime::durable_json(
        &journal.path("cgroup-stop.json"),
        &serde_json::json!({
            "schema_version":"forgeflow.cgroup-stop.v1","identity_sha256":fence.identity_sha256,
            "boot_id":fence.boot_id,"leaf_inode":fence.leaf_inode,"populated":false,
            "process_exit_confirmed":true,"snapshot":{"cgroup.procs":"","pids.current":"1","cgroup.events":"populated 0\nfrozen 0"}
        }),
    )
    .unwrap();
    forgeflow_runtime::durable_json(&seal_path, &serde_json::json!({"context":context,
        "runner_closed":true,"unused_execution_ids":context.commands[1..].iter().map(|c| &c.execution_id).collect::<Vec<_>>()
    })).unwrap();
    for reason in [
        "cancelled_before_launch",
        "spawn_failed: executable unavailable",
    ] {
        journal
            .record_stop(&forgeflow_runtime::StopEvidence {
                exit_code: None,
                signal: None,
                reason: reason.into(),
                process_exit_confirmed: true,
                stdout_bytes: 0,
                stderr_bytes: 0,
                notification_overflow: 0,
                log_error: None,
            })
            .unwrap();
        let proof = verification_physical_stop_evidence(&root).unwrap();
        assert_eq!(proof[0]["status"], "STOPPED");
        assert_eq!(proof[0]["pre_exec_stopped"], true);
        assert!(proof[0]["launch_receipt"].is_null());
        assert!(proof[0]["physical_membership"].is_null());
        assert_eq!(verification_stop_evidence(&root).unwrap().len(), 1);
    }
    journal
        .record_stop(&forgeflow_runtime::StopEvidence {
            exit_code: None,
            signal: None,
            reason: "timeout".into(),
            process_exit_confirmed: true,
            stdout_bytes: 0,
            stderr_bytes: 0,
            notification_overflow: 0,
            log_error: None,
        })
        .unwrap();
    assert!(verification_physical_stop_evidence(&root).is_err());
    assert!(verification_stop_evidence(&root).is_err());
}

fn fixture(mode: &str) -> (tempfile::TempDir, VerificationPlan, EvidenceBinding) {
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join("candidate")).unwrap();
    fs::write(t.path().join("candidate/application.py"),"def add(a,b):\n    if not isinstance(a,int) or not isinstance(b,int):\n        raise TypeError('integer operands required')\n    return a+b\n").unwrap();
    let verifier = t.path().join("trusted-verifier.py");
    let source = r#"import os,sys,json,importlib.util
spec=importlib.util.spec_from_file_location('application',os.path.join(os.getcwd(),'application.py'))
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
binding=json.loads(os.environ['FORGEFLOW_EVIDENCE_BINDING'])
role=os.environ['FORGEFLOW_VERIFICATION_ROLE']
assert role==sys.argv[1], 'runner role differs from registered command role'
positive=app.add(2,3)==5
try:
    app.add('invalid',3)
    negative=False
except TypeError:
    negative=True
cases=[{'name':'sum_accept','kind':'positive','outcome':'passed' if positive else 'failed'},{'name':'bad_operand_reject','kind':'negative','outcome':'passed' if negative else 'failed'}]
mode=os.environ.get('REPORT_MODE','valid')
if mode=='binding': binding['candidate_sha']='different-candidate'
if mode=='empty': cases=[]
if mode=='skipped':
    for case in cases: case['outcome']='skipped'
if mode=='failed': cases[0]['outcome']='failed'
with open(os.environ['FORGEFLOW_REPORT_PATH'],'w') as output:
    json.dump({'binding':binding,'oracle_id':'integer-add-independent','cases':cases},output)
print('actually executed add(2,3) and invalid-operand rejection for role '+role)
if mode=='symlink':
    os.symlink(os.environ['ESCAPE_TARGET'],os.path.join(os.path.dirname(os.environ['FORGEFLOW_REPORT_PATH']),'future'))
if mode=='failed': sys.exit(1)
if mode=='guard':
    try:
        with open(os.path.join(os.getcwd(),'application.py'),'a') as target:
            target.write('# unauthorized verifier mutation')
    except OSError:
        print('readonly-candidate write refused',flush=True)
    else:
        raise AssertionError('verifier could modify frozen candidate')
    try:
        os.link(os.path.join(os.getcwd(),'application.py'),os.environ['FORGEFLOW_REPORT_PATH']+'.source-alias')
        with open(os.environ['FORGEFLOW_REPORT_PATH']+'.source-alias','a') as target:
            target.write('# illegal hardlink mutation')
    except OSError:
        print('readonly-candidate hardlink mutation refused',flush=True)
    else:
        raise AssertionError('verifier could mutate candidate through writable scratch alias')
if mode=='wait':
    import subprocess,time
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    print('started-verifier-child',child.pid,flush=True)
    time.sleep(60)
"#;
    fs::write(&verifier, source).unwrap();
    let python = fs::canonicalize("/usr/bin/python3")
        .expect("fixture requires approved system Python runtime under /usr");
    let executable_hash = sha256(&fs::read(&python).unwrap());
    let commands = [
        VerificationRole::Author,
        VerificationRole::Consumer,
        VerificationRole::Independent,
    ]
    .iter()
    .enumerate()
    .map(|(index, role)| CommandSpec {
        role: *role,
        program: python.clone(),
        args: vec![
            verifier.to_string_lossy().into(),
            ["author", "consumer", "independent"][index].into(),
        ],
        env: BTreeMap::from([
            ("REPORT_MODE".into(), mode.into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        executable_hash: executable_hash.clone(),
        bound_inputs: vec![BoundInput {
            path: verifier.clone(),
            sha256: sha256(source.as_bytes()),
        }],
        report_path: format!("reports/{index}.json"),
        expected_cases: vec![
            ExpectedCase {
                name: "sum_accept".into(),
                kind: CaseKind::Positive,
            },
            ExpectedCase {
                name: "bad_operand_reject".into(),
                kind: CaseKind::Negative,
            },
        ],
        timeout_seconds: 5,
    })
    .collect();
    let plan = VerificationPlan {
        plan_id: "add-contract-v1".into(),
        task_revision: 2,
        contract_version: "v1".into(),
        input_hash: "frozen-input".into(),
        environment_profile: "linux-python3".into(),
        oracle_id: "integer-add-independent".into(),
        verifier_id: "registered-consumer".into(),
        author_id: "application-author".into(),
        commands,
    };
    let binding = EvidenceBinding {
        task_revision: 2,
        attempt_id: "attempt-actual".into(),
        generation: 1,
        base_sha: "base".into(),
        candidate_sha: "candidate".into(),
        integrated_sha: Some("integrated".into()),
        contract_version: "v1".into(),
        verification_plan_id: plan.plan_id.clone(),
        verification_plan_hash: plan.digest(),
        input_hash: "frozen-input".into(),
        source_hash: "actual-source-tree".into(),
    };
    (t, plan, binding)
}

#[tokio::test]
async fn prior_role_report_symlink_cannot_create_host_directories_outside_artifact_root() {
    let (t, mut plan, mut binding) = fixture("valid");
    let root = t.path().join("artifacts");
    let outside = t.path().join("other-project");
    fs::create_dir(&outside).unwrap();
    plan.commands[0].report_path = "author.json".into();
    plan.commands[0]
        .env
        .insert("REPORT_MODE".into(), "symlink".into());
    plan.commands[0]
        .env
        .insert("ESCAPE_TARGET".into(), outside.to_string_lossy().into());
    plan.commands[1].report_path = "future/forbidden/report.json".into();
    binding.verification_plan_hash = plan.digest();
    assert!(
        execute_verification(&plan, &t.path().join("candidate"), &binding, &root)
            .await
            .is_err()
    );
    assert!(!outside.join("forbidden").exists());
    assert_eq!(verification_stop_evidence(&root).unwrap().len(), 1);
}

#[tokio::test]
async fn guarded_actual_verifier_cannot_mutate_candidate_and_wrapped_launch_is_logged() {
    let (t, mut plan, mut binding) = fixture("guard");
    plan.environment_profile = "linux-bwrap-landlock-verifier-fixture".into();
    binding.verification_plan_hash = plan.digest();
    let cwd = fs::canonicalize(t.path().join("candidate")).unwrap();
    let root = t.path().join("guard-artifacts");
    fs::create_dir_all(&root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let original = fs::read(cwd.join("application.py")).unwrap();
    let verifier = plan.commands[0].bound_inputs[0].path.clone();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let receipt = execute_verification_with_guard(&plan, &cwd, &binding, &root, rx, |spec| {
        let guard_binary = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("forgeflow-sandbox-guard");
        let mut readonly_paths = vec![std::path::PathBuf::from("/usr"), verifier.clone()];
        for directory in ["/bin", "/lib", "/lib64"] {
            if std::path::Path::new(directory).exists() {
                readonly_paths.push(directory.into());
            }
        }
        let profile = forgeflow_runtime::SandboxProfile {
            bwrap_program: "/usr/bin/bwrap".into(),
            bwrap_sha256: sha256(&fs::read("/usr/bin/bwrap").unwrap()),
            guard_sha256: sha256(&fs::read(&guard_binary).expect(
                "build normal forgeflow-sandbox-guard binary before strong verifier tests",
            )),
            guard_program: guard_binary,
            readonly_paths,
            network_allowed: false,
        };
        let instance = forgeflow_runtime::SandboxInstance {
            workspace: cwd.clone(),
            write_set: vec![],
            allow_git_metadata: false,
            writable_mounts: vec![forgeflow_runtime::SandboxMount {
                source: root.clone(),
                target: root.clone(),
            }],
        };
        forgeflow_runtime::sandbox_command(spec, &profile, &instance)
            .map_err(|e| EvidenceError::Invalid(e.to_string()))
    })
    .await
    .unwrap();
    assert_eq!(receipt.total, 6);
    assert_eq!(fs::read(cwd.join("application.py")).unwrap(), original);
    let log = fs::read_to_string(root.join(&receipt.log_path)).unwrap();
    assert!(log.contains("actual launch /usr/bin/bwrap"));
    assert!(log.contains("readonly-candidate write refused"));
    assert!(log.contains("readonly-candidate hardlink mutation refused"));
    assert!(log.contains("forgeflow-sandbox-guard"));
    assert_eq!(verification_stop_evidence(&root).unwrap().len(), 3);
}

#[tokio::test]
async fn lease_revocation_terminates_actual_verifier_group_before_settlement() {
    let (t, plan, binding) = fixture("wait");
    let root = t.path().join("artifacts");
    let revoke_root = root.clone();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let revoke = tokio::spawn(async move {
        for _ in 0..150 {
            let launched = fs::read_dir(revoke_root.join("verification-runs"))
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .any(|entry| {
                    fs::read_to_string(entry.path().join("stdout.ndjson"))
                        .map(|s| s.contains("started-verifier-child"))
                        .unwrap_or(false)
                });
            if launched {
                tx.send(true).unwrap();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        panic!("actual verifier child never launched");
    });
    assert!(
        execute_verification_with_cancel(&plan, &t.path().join("candidate"), &binding, &root, rx)
            .await
            .is_err()
    );
    revoke.await.unwrap();
    let stops = verification_stop_evidence(&root).unwrap();
    assert_eq!(stops.len(), 1);
    assert!(stops[0].process_exit_confirmed);
    assert!(stops[0].reason.contains("cancelled"));
    assert!(!root.join("verification-receipt.json").exists());
}
#[tokio::test]
async fn actual_commands_run_fixed_positive_and_negative_business_cases() {
    let (t, plan, binding) = fixture("valid");
    let frozen_plan = serde_json::to_value(&plan).unwrap();
    let root = t.path().join("artifacts");
    let receipt = execute_verification(&plan, &t.path().join("candidate"), &binding, &root)
        .await
        .unwrap();
    assert_eq!(
        (
            receipt.total,
            receipt.failed,
            receipt.skipped,
            receipt.positive_cases,
            receipt.negative_cases
        ),
        (6, 0, 0, 3, 3)
    );
    receipt.validate_log(&root).unwrap();
    let log = fs::read_to_string(root.join(&receipt.log_path)).unwrap();
    for role in ["author", "consumer", "independent"] {
        assert!(log.contains(&format!(
            "actually executed add(2,3) and invalid-operand rejection for role {role}"
        )));
    }
    assert_eq!(serde_json::to_value(&plan).unwrap(), frozen_plan);
    assert!(
        plan.commands
            .iter()
            .all(|command| !command.env.contains_key("FORGEFLOW_VERIFICATION_ROLE"))
    );
    assert_eq!(receipt.binding, binding);
    assert_eq!(
        receipt.command,
        plan.commands
            .iter()
            .flat_map(
                |command| std::iter::once(command.program.to_string_lossy().into_owned())
                    .chain(command.args.clone())
            )
            .collect::<Vec<_>>()
    );
    assert_eq!(verification_stop_evidence(&root).unwrap().len(), 3);
    assert!(root.join("verification-receipt.json").exists());
}

#[tokio::test]
async fn verifier_role_conflict_is_rejected_before_any_command_launch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for (index, conflicting_role) in [
        (0, "consumer"),
        (1, "author"),
        (2, "author"),
        (2, "INDEPENDENT"),
        (2, ""),
    ] {
        let (t, mut plan, mut binding) = fixture("valid");
        plan.commands[index].env.insert(
            "FORGEFLOW_VERIFICATION_ROLE".into(),
            conflicting_role.into(),
        );
        binding.verification_plan_hash = plan.digest();
        let root = t.path().join("artifacts");
        let guard_calls = AtomicUsize::new(0);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let error = execute_verification_with_guard(
            &plan,
            &t.path().join("candidate"),
            &binding,
            &root,
            rx,
            |spec| {
                guard_calls.fetch_add(1, Ordering::SeqCst);
                Ok(spec)
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reserved FORGEFLOW_VERIFICATION_ROLE differs")
        );
        assert_eq!(guard_calls.load(Ordering::SeqCst), 0);
        assert!(verification_stop_evidence(&root).unwrap().is_empty());
        assert!(!root.join("verification-runs").exists());
        assert!(!root.join("reports").exists());
        assert!(!root.join("verification-receipt.json").exists());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }
}
#[tokio::test]
async fn reports_cannot_change_binding_denominator_or_claim_all_skipped() {
    for mode in ["binding", "empty", "skipped"] {
        let (t, plan, binding) = fixture(mode);
        let root = t.path().join("artifacts");
        assert!(
            execute_verification(&plan, &t.path().join("candidate"), &binding, &root)
                .await
                .is_err()
        );
        assert!(root.join("verification-runs").exists());
    }
}
#[tokio::test]
async fn failed_tests_preserve_receipt_and_registered_plan_tampering_is_rejected() {
    let (t, plan, binding) = fixture("failed");
    let root = t.path().join("artifacts");
    assert_eq!(
        execute_verification(&plan, &t.path().join("candidate"), &binding, &root)
            .await
            .unwrap_err(),
        EvidenceError::Failed
    );
    let receipt: VerificationReceipt =
        serde_json::from_slice(&fs::read(root.join("verification-receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt.failed, 3);
    let (t, mut plan, binding) = fixture("valid");
    plan.commands[0].expected_cases.clear();
    assert_eq!(
        execute_verification(
            &plan,
            &t.path().join("candidate"),
            &binding,
            &t.path().join("artifacts")
        )
        .await
        .unwrap_err(),
        EvidenceError::BindingMismatch
    );
    let (t, plan, binding) = fixture("valid");
    let external = &plan.commands[2].bound_inputs[0].path;
    fs::write(external, "print('PASS')").unwrap();
    assert!(
        execute_verification(
            &plan,
            &t.path().join("candidate"),
            &binding,
            &t.path().join("artifacts")
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn read_only_artifact_receipt_has_no_fabricated_git_identity() {
    let (t, mut plan, _) = fixture("valid");
    let artifact = t.path().join("plan.json");
    fs::write(
        &artifact,
        b"{\"tasks\":[{\"id\":\"native-task\",\"dependencies\":[]}]}",
    )
    .unwrap();
    let script = r#"import os,json,sys
role=os.environ['FORGEFLOW_VERIFICATION_ROLE']
assert role==sys.argv[1], 'artifact runner role differs from registered command role'

def parse(data):
    if not isinstance(data,dict) or not isinstance(data.get('tasks'),list) or len(data['tasks'])==0:
        raise ValueError('nonempty task list required')
    if any(not isinstance(task.get('id'),str) or not isinstance(task.get('dependencies'),list) for task in data['tasks']):
        raise ValueError('invalid task identity or dependencies')
    return data

with open(os.environ['FORGEFLOW_ARTIFACT_PATH']) as source: actual=json.load(source)
positive=parse(actual)['tasks'][0]['id']=='native-task'
try:
    parse({'tasks':[]})
    negative=False
except ValueError:
    negative=True
cases=[{'name':'artifact_schema_accept','kind':'positive','outcome':'passed' if positive else 'failed'},{'name':'empty_plan_reject','kind':'negative','outcome':'passed' if negative else 'failed'}]
with open(os.environ['FORGEFLOW_REPORT_PATH'],'w') as output:
    json.dump({'binding':json.loads(os.environ['FORGEFLOW_EVIDENCE_BINDING']),'oracle_id':'integer-add-independent','cases':cases},output)
print('structured artifact parser accepted native task and rejected empty plan for role '+role)
"#;
    let verifier = plan.commands[0].bound_inputs[0].path.clone();
    fs::write(&verifier, script).unwrap();
    for (index, command) in plan.commands.iter_mut().enumerate() {
        command.env.insert(
            "FORGEFLOW_VERIFICATION_ROLE".into(),
            ["author", "consumer", "independent"][index].into(),
        );
        command.bound_inputs[0].sha256 = sha256(script.as_bytes());
        command.expected_cases = vec![
            ExpectedCase {
                name: "artifact_schema_accept".into(),
                kind: CaseKind::Positive,
            },
            ExpectedCase {
                name: "empty_plan_reject".into(),
                kind: CaseKind::Negative,
            },
        ];
    }
    let binding = ArtifactBinding {
        task_revision: plan.task_revision,
        attempt_id: "read-only-attempt".into(),
        generation: 3,
        verification_plan_id: plan.plan_id.clone(),
        verification_plan_hash: plan.digest(),
        contract_version: plan.contract_version.clone(),
        input_hash: plan.input_hash.clone(),
        context_hash: "context-bytes".into(),
        prompt_hash: "prompt-bytes".into(),
        artifact_hash: sha256(&fs::read(&artifact).unwrap()),
    };
    let root = t.path().join("read-only-logs");
    let frozen_plan = serde_json::to_value(&plan).unwrap();
    let receipt = execute_artifact_verification(
        &plan,
        &t.path().join("candidate"),
        &binding,
        &artifact,
        &root,
    )
    .await
    .unwrap();
    assert_eq!(receipt.total, 6);
    receipt.validate_artifact(&artifact).unwrap();
    assert_eq!(serde_json::to_value(&plan).unwrap(), frozen_plan);
    assert_eq!(receipt.binding, binding);
    let log = fs::read_to_string(root.join(&receipt.log_path)).unwrap();
    for role in ["author", "consumer", "independent"] {
        assert!(log.contains(&format!("structured artifact parser accepted native task and rejected empty plan for role {role}")));
    }
    assert_eq!(verification_stop_evidence(&root).unwrap().len(), 3);
    let value = serde_json::to_value(&receipt).unwrap();
    assert!(value["binding"].get("candidate_sha").is_none());
    assert!(value["binding"].get("base_sha").is_none());
    assert!(value["binding"].get("integrated_sha").is_none());
    fs::write(&artifact, b"{\"tasks\":[]}").unwrap();
    assert_eq!(
        receipt.validate_artifact(&artifact),
        Err(EvidenceError::BindingMismatch)
    );
}
