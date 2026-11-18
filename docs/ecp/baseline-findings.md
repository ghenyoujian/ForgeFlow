# Phase 0 baseline findings

Run `python3 verification/ecp/baseline_regressions.py --output /outside/source/run.json`
from the control checkout. The report retains `source_sha` for compatibility;
it is a claim from an unauthenticated Git subprocess, not an authenticated
source identity. A matching source probe and claimed HEAD remain
`INCONCLUSIVE` without independent source authentication. The report records
probe output, not independent verification of its contents.

The database child is given an environment with database settings removed.
Its `BLOCKED` and zero-attempt values are self-reports, not independent proof
that no connection was attempted. A single source failure report bound to the
claimed HEAD, root and digest is retained as `FAIL` conservatively; without
that binding it is `INCONCLUSIVE`, while the reason still preserves the
reported failure. Multiple source-identity reports are always ambiguous and
`INCONCLUSIVE`; any reported failure remains explicit regardless of order.
These are probe claims and do not establish events independently. The database
failure status likewise identifies a probe report. These claims do not replace a
disposable PostgreSQL test. Browser and native executor observations remain
`NOT_RUN`. Results never sign an ECP Gate. The subprocess supervision and
timeout behavior require separate assessment. Evidence output must be outside
the source tree and is never overwritten; use a fresh output file for each run.
