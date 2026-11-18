# Independent verification

A10 owns this directory and `../benchmarks`. Results are evidence fragments, not automatic full Gate qualifications. `planning/gates.json` remains A00's authority. No simulated execution qualifies G07 or G20. Oracle fixtures never qualify G15.

Run the existing focused integration check for the changed subsystem. Reuse
qualified evidence when its source and workload remain unchanged; do not restart
blanket discovery or static source audits for routine delivery work.

`algorithm_check.py` compares the actual Rust probe with an independent reference
for DAGs, exact paths and hierarchical resource accounting. `guarded_api_chain.py`
executes the candidate, integration and read-only artifact branches through the
production API and sandbox mapper. Both require a qualified build and a fresh
evidence directory. The independent oracle in `oracle.py` remains shared by these
real integration checks; it intentionally imports no production module.

The retired `audit.py`, `isolation_branch_audit.py` and `test_oracle.py` duplicated
planning-only inspection, an API-equivalent canary and synthetic oracle checks.
Their historical results remain in `evidence/`. Canonical planner, scheduler,
store and evidence tests remain in the Rust crates; real workflow, browser,
recovery and load checks remain available here and in `../benchmarks`.

Rendered UI checks require a real running console and installed Playwright Chromium:

```bash
python3 verification/browser_check.py --url http://127.0.0.1:5173 --output verification/evidence/browser
```

Desktop, mobile and reduced-motion screenshots plus keyboard focus and overflow reports are retained. Browser smoke PASS cannot stand in for full business workflow, database authority or visual review.

All load evidence must record duration, unique effective attempts, actual controlled process identities, hardware, source identity, failure denominators, workload seed, command, and latency sample counts. 128 active channels must hold for a continuous 3,600-second verified interval with Worker execution and mixed fault scenarios. SSE client receive time and browser render time are separate metrics. 1/4/10 real DSH qualifications remain separate artifacts; G20 requires at least 100 live real DSH sessions, real model calls, quota, costs and stability facts.

The planning matrices retain the 67 original source tasks and 28 original
engineering requirement IDs alongside documented supplemental cards and later
user requirements. Planned cards with unbound future inputs remain unready;
retiring duplicate scripts does not qualify a task or change a Gate.

Current evidence is deliberately separated by scope:

- `evidence/baseline-current`: nine actual environment identity checks, including
  immutable source/binaries, archive, live PostgreSQL, native content pins and
  the pinned Rust executor doctor; G00 only for its recorded checkpoint.
- `evidence/algorithms-v2-root-bound`: 53 actual production Rust probe cases,
  2,575 independent assertions; database and operating-system authority need
  their own evidence.
- `evidence/native-g2-independent`: one actual native DSH business chain,
  24 independent authority/provenance checks and 15 fresh business assertions
  on the integrated Git blob. Real 4/10/100-session scopes are separate.
- `evidence/execution-binding-source5d5dda99`: twelve actual PostgreSQL/API
  admission authority checks, with an unchanged-template guard control.
- `../benchmarks/evidence/qa-control-one-source5d5dda99` and the corresponding
  four-channel directory: actual author processes held for about twenty seconds.
- `../benchmarks/evidence/qa-control-128-source5d5dda99`: failed fleet startup;
  128 admitted attempts reached only 21 actual author launches. The timed window
  never began. Quarantine is retained pending lawful recovery.
- `../benchmarks/evidence/qa-real-faults-source5d5dda99`: actual bounded TCP link
  failure, registered verification/Git completion and duplicate callback replay.
  The original missing-header harness failure remains beside the requalified
  callback evidence.

Later evidence records a historical **128-channel controlled continuity PASS**
over 3,601.0055 seconds, with 128 actual author PIDs throughout the recorded
observations, at source identity `d2e52b7e6313def8d520e0e6971b7ce2f681fb9d423b98492add5aba22d168ed`.
See `../benchmarks/evidence/strict-pool-20261009T232021Z-ab75e7dfdb/final-summary.json`.
That run injected no faults or handoffs; it does not qualify the full fault
matrix. The earlier failed fleet startup and heartbeat-expiration run remain
historical failures, and the separate 1,500-second regression is not an hour run.

Real native 1/4/10-session execution and actual managed native collaboration
also have scoped evidence. The collaboration parent closure at source identity
`531a659b0d59ca39735ea901cc979f73a3556b75908992d179f4e3891d2710a5`
records four distinct native agents, five lifecycles, cold resume, settled model
usage and independent read-only verification; see
`../evidence/native-rpc-diagnostic-fix-r1/actual-cap7-r1/closure-corrected-r1/report.json`.
These historical versions are separate from the current installed source;
`../evidence/engineering-status.json` and `../docs/DELIVERY_STATUS.zh-CN.md`
record the current delivery and retained failure scopes.

Full fault and recovery coverage, 100+ real DSH production qualification, the
full original 12-cohort Python/Rust scientific comparison and protection-removal
ablations remain unqualified. Completed baseline comparison cells do not qualify
the full study. This documentation refresh changes no Gate or goal status.
