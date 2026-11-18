# ECP-G0 independent review

`control/verification/ecp/gates/g0.py` only evaluates supplied evidence files.
It never changes the Gate registry and always keeps `product_gate_effect=NONE`.
A missing, failed, blocked, unexecuted, or inconclusive input prevents a product
Gate decision. The first admissible review must use a frozen source manifest,
an isolated PostgreSQL result, the real test denominator, and an independent
oracle on the same source identity.

## Output preservation and compatibility

Choose a fresh `--output` name in an existing directory. The reviewer no longer
creates parent directories or overwrites an existing output; a repeated run
must use a new name. It conservatively rejects an output path that normalizes
to an evidence path or is an ancestor or descendant of one. This check can
reject distinct names, and it cannot establish filesystem identity in the
presence of symlink changes, unusual naming rules or concurrent interference.

The output is opened with exclusive creation and a no-follow final component.
If creation, writing, synchronization or close cannot be confirmed, no success
report is emitted to stdout. A diagnostic on stderr retains the full evidence
report and output state: a supplied FAIL claim remains FAIL/exit 10, while
other evidence states produce BLOCKED/exit 20. A failed write may leave a new
empty or partial file; inspect it and choose a new output name rather than
blindly deleting or reusing it. Claims in that evidence remain unverified.

Report and diagnostic JSON escape non-ASCII characters so lone surrogates do
not require encoding them directly to a strict UTF-8 stream. The default JSON
parser remains permissive about duplicate keys and non-finite values; this is
not a strict-JSON guarantee. Exclusive creation and file synchronization do
not authenticate the source, directory, principal or writer, ensure a durable
directory entry, or prevent same-UID races and later replacement. They do not
turn this offline review into a product Gate.

For sources whose POSIX permissions are not reliably observable, the
[source normalization research contract](source-normalization-contract.md)
describes a proposed derived-candidate path. It is not admitted and does not
change v3 behavior or grant G0.

## P0-02 identity and execution boundary

The disposable-cluster marker, local socket path, process executable name and
output of an adjacent client are not an independent PostgreSQL identity proof.
In a controlled counterexample, a non-listening local socket, an unrelated
process named `postgres` and a fabricated `psql` reproduced the expected text
without any database connection. The previous direct probe reported PASS and
the P0-02 wrapper recorded a passing identity check, although the overall suite
remained INCONCLUSIVE. The current guard does not launch that unauthenticated
client; even matching local metadata remains INCONCLUSIVE. The P0-02 wrapper
does not promote a child self-report to an identity PASS, and reports actual
database connection count as unknown once an unconstrained child has started.
This deliberately blocks identity qualification even for a genuine database
until independent server, client, peer and execution authority are established.

The directly executable `ops/ecp/verify` launcher uses an absolute Python
interpreter with isolated startup; the database guard uses an absolute Bash in
privileged startup mode and isolated absolute Python invocations. These limits
address tested PATH and startup-hook substitutions, not all hostile runtime
environments. In particular, an explicit `python3 ops/ecp/verify` invocation
chooses and initializes the interpreter before the launcher can act, and even
direct execution cannot remove a hostile dynamic-loader environment before the
interpreter starts. A trusted caller must select and sanitize the interpreter,
loader and environment. Neither local hashes, same-UID metadata, nor this
launcher authenticate a principal, lease, database or product Gate.

## Undeclared suites and v3 guard (historical; see update below)

For a generic suite using the v2 source-manifest mode, an unavailable or
undeclared suite registry now returns the existing BLOCKED diagnostic before
starting the Git source probe. A non-P0-01 v3 suite reaches its existing
BLOCKED version guard before Git, subject to the earlier P0-02 and P0-03
specialized handling. In those branches `source_sha` is null because no Git
observation was made. Existing registered generic v2 suites retain their
prior status and self-reported Git source claim; their registry lookup now
occurs before that probe. P0-01 and the existing P0-02/P0-03 handling are
unchanged.

This ordering does not authenticate the registry, source, principal or lease,
and it does not establish a stopped process tree or grant a Gate. Other paths,
including registered v2 suites and P0-05 v2, can still invoke Git. The generic
`ops/ecp/verify.py` output writer retains its existing overwrite behavior; the
exclusive-output protection described above applies to the separate
`verification/ecp/gates/g0.py` reviewer.

## Registered generic v2 suites: update

Registered generic v2 suites without a bound executable workload or oracle
now retain their NOT_RUN result without invoking Git; their `source_sha` is
null because no Git source observation was made. Unavailable or undeclared
registry results and unsupported v3 requests retain their earlier guards.
P0-01 and P0-05 v2 can still invoke Git; P0-05 requires a source SHA for its
separate source review. The generic `verify.py` report writer can still
overwrite an existing output; this update does not address that behavior.

The dispatch checks use mocks and do not authenticate the registry, source,
principal, process tree or runtime. They do not execute a product workload or
grant a product Gate.

## P0-05 registry admission before Git

For P0-05 v2, an unavailable or unreadable registry, missing entry, or an
entrypoint other than the reviewed workflow returns the existing BLOCKED
result before the Git source probe and without writing the requested output.
The source SHA is null because Git was not run. A correctly bound entry still
performs the Git probe, records the registry digest and enters the same P0-05
runner; registry lookup now precedes Git.

Mock dispatch tests cover these branches but do not authenticate the registry,
source, runtime, principal or process tree. The registry is parsed and later
reread for a digest, so a concurrent change may produce a mismatched binding
and digest. P0-01 and a valid P0-05 can still invoke Git; the generic report
writer can still overwrite an existing output. No product Gate is granted.


## Generic verifier report output preservation: update

The previous notes about the generic verifier overwriting output describe the
old behavior. For calls routed through `verify.py::write_report`, a supplied
output now requires an existing parent path with no symlink components and a
fresh final filename. The writer rejects `..` and a final `.` before path
normalization, opens the output with exclusive nofollow creation, writes one
complete JSON report and fsyncs/closes it before printing the same report and
adding its path to `evidence_refs`. When their entries remain present, a `report` input or existing hardlink, file
or symlink is not replaced by this writer. Missing parent directories are not
created. Commands can still have their own specialized
output paths; this section makes no claim about those writers.

If output creation, writing, fsync or close is not confirmed, a diagnostic
appears on stderr and stdout receives no success report. It contains the
original report when JSON serialization permits it; a FAIL remains FAIL/10,
and other reports become BLOCKED/20. If the original report cannot be
serialized even as a diagnostic, `evidence_report` is null and
`evidence_report_state=UNSERIALIZABLE`; the original object remains in memory
and any string original status is retained. No new output reference is added
on failure. A newly created empty, partial or complete file may remain, and
unknown create errors remain uncertain. No failed output is unlinked. With no
output requested, previous direct stdout serialization behavior remains.

The writer's nofollow traversal and exclusive creation do not authenticate
the directory, principal or runtime, prevent same-UID rename or later writes,
or guarantee the durability of a directory entry. They do not prove source or
database identity or grant a product Gate.

Run `python3 -I -S -B ops/ecp/tests/test_report_output.py` for its synthetic
checks. Unless `ECP_REPORT_TEST_ROOT` supplies an existing private root, each
method creates and retains its own temporary directory; it is never removed by
the tests. `ECP_VERIFY_PATH` may select a specific reviewed verifier copy; when
unset the test imports the sibling `ops/ecp/verify.py`. These tests include
mocked and synthetic filesystem cases and do not execute Git, PostgreSQL or
a product workload. Passing them does not grant G0 qualification.
