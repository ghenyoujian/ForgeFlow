# Registered verification

The server freezes a `VerificationPlan` for the task revision. Its `digest()` binds the complete plan, including the exact executable bytes, bound script/input bytes, explicit environment, argv, deadline, expected business case names, their positive/negative kinds, environment profile, contract, input digest and verifier/oracle identities. `EvidenceBinding` must refer to that authoritative plan ID/hash. The caller supplies the actual Git source tree identity; integration checks the new HEAD again after verification. Author-provided stdout or uploaded receipts are not a substitute for executing the plan.

`execute_verification(plan, cwd, binding, artifact_root)` executes registered author, consumer and independent commands through the runtime supervisor, with no ambient service secrets. `execute_verification_with_cancel` also accepts a `watch::Receiver<bool>`; lease rejection or operator cancellation must set it to true. Process journals and raw output remain available even when report parsing or verification fails. The process task continues supervising and reaping if the awaiting request disappears.

Strong runtime profiles use `execute_verification_with_guard` or `execute_artifact_verification_with_guard`, adding a trusted controller mapper from `ProcessSpec` to a guarded `ProcessSpec`. The API supplies `runtime::sandbox_command` with a frozen approved profile, a read-only candidate workspace, no writable Git metadata, and writable report/cache scratch only. Pinned verifier scripts and required runtime files are mounted explicitly. The raw log records the actual wrapper executable/argv alongside the registered command; the receipt keeps the plan's fixed command identity. Compatibility entrypoints without a guard do not qualify an OS isolation profile. Actual author and verifier guard launch evidence is required separately.

Each command receives `FORGEFLOW_REPORT_PATH`, `FORGEFLOW_EVIDENCE_BINDING` and `FORGEFLOW_SOURCE_HASH` in its explicit environment. It writes JSON of this shape to the supplied report path:

```python
import json, os
report = {
    "binding": json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"]),
    "oracle_id": "registered-oracle",
    "cases": [
        {"name": "registered_accept_case", "kind": "positive", "outcome": accept_outcome},
        {"name": "registered_reject_case", "kind": "negative", "outcome": reject_outcome},
    ],
}
with open(os.environ["FORGEFLOW_REPORT_PATH"], "w") as output:
    json.dump(report, output)
```

`accept_outcome` and `reject_outcome` must come from actual business assertions; outcomes are `passed`, `failed` or `skipped`. Missing, duplicate or extra cases, wrong kinds, mismatched bindings/oracles, empty reports, all-skipped required commands and nonzero exits fail. The independent oracle must execute both positive and negative cases. Failed structured receipts and original logs remain on disk; changing the denominator or deleting counterexamples is not accepted.

Independent verifier executables and their bound inputs must live outside the candidate write tree and match registered SHA256 values before and after execution. This proves the identity of the registered verifier, not that any arbitrary verifier is trustworthy; plan registration must remain a control-plane authority operation and independent golden expectations must be reviewed. The fixed plan cannot be accepted from an executor as part of its result.

The runner writes `verification-raw.log`, `verification-receipt.json`, individual structured reports and durable process journals beneath the explicit artifact root. A Git integration callback uses `forgeflow_git::integration_verification_root` for this writable scratch root. The private integration repository remains read-only in the verifier namespace. After verification settles, the controller snapshots the raw log and immutable receipt beneath `canonical/forgeflow-evidence/{intent_id}` and syncs them before a durable commit decision. Canonical snapshots are never verifier mounts. The initial author verification can use the attempt's registered artifact prefix.

`verification_stop_evidence(root)` requires confirmed durable stop records for every launched verifier, including failed runs. Resource release or cancellation confirmation must include these proofs in addition to the original author process. `reconcile_verification_runs(root)` settles authenticated old groups after an authority-server restart without relaunching commands; absent or uncertain process identity keeps the attempt quarantined. Register operation artifact roots durably before launching so startup can enumerate them.

For read-only PLANNING/REVIEW tasks use `ArtifactBinding`, `ArtifactVerificationReceipt` and `execute_artifact_verification(plan, cwd, binding, artifact_path, artifact_root)` (or its cancellation variant). This exports `FORGEFLOW_ARTIFACT_PATH` and checks the actual structured artifact bytes before and after independent verification. Its receipt binds task, prompt, context, plan and artifact hashes and contains no base/candidate/integrated Git SHA. Store completion uses `STRUCTURED_ARTIFACT` evidence and never fabricates an empty commit.
