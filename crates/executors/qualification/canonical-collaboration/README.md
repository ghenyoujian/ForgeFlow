# Canonical collaboration qualification

This directory owns protocol-v2 evidence. `legacy-v1-source/manifest.json` preserves
57 original v1 files and hashes before the bridge change. Its receipts retain their
historical local-only scope.

`prepare.py` selects exactly the authorized `agent-default-model` and `llm-pi-ai`
rows and credentials into private files, pins the current native runtime and mode,
and runs the actual supported CLI `--dump-config`. `doctor.receipt.json` records
configuration resolution only. It contains identities and hashes; raw configuration
and credential values remain private. Nine unavailable historical `forgeflow-ops`
files are explicitly excluded; the new composition refuses that unused plugin.
External transitive dependency content remains only partially inventoried.

`canonical_probe.py` requires an approved immutable build receipt and private database
credentials. It creates a separate database, server on port 8793, short private state
root, registered Worker and frozen strong sandbox. All lifecycle grants, resource
charges and model request budgets are canonical PostgreSQL facts. The finite native
probe exercises a one-shot child, Workflow child, Team child and real Team cold resume.
The cancellation probe waits for a settled child model call and cancels during its
actual finite tool wait, so positive Worker stop can be measured without declaring
an aborted request’s unknown usage settled. Failures and private originals are retained.

No result here qualifies full financial/model/OS egress, fork/remote providers,
100+ sessions, or a production gate. Independent review belongs to the assigned
reviewer after the actual run; harness checks are producer observations.
