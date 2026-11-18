# P0-01 source normalization: research contract

Status: **DRAFT / NOT ADMITTED**. This is a proposed contract for evaluating a
derived candidate when source POSIX permissions cannot be observed reliably.
It authorizes no execution, grants no principal or lease, and changes neither
the existing v3 preservation contract nor any product Gate. Until an
authorized policy and the independent checks below exist, the existing
`UNAVAILABLE` path remains blocked.

## Observations and transformation

Let `S` be the source observation, `P` a separately fixed transformation
policy, and `T` an independent observation of a candidate. `S` binds the source
manifest digest and Git commit, the included directory and file path sets,
exclusion boundaries, file kinds, raw content digests, Git blob IDs, link
targets and the observed source/index/mount identities. Filesystem properties
that cannot be observed reliably, including source mode, ACL, owner or group,
remain `UNKNOWN`; Git's executable classification is not a source POSIX mode.
An endpoint observation does not establish an atomic or continuously
unchanged source.

The current v3 manifest does not itself bind every tracked file's SHA-256 or
complete POSIX mode. Where this contract needs per-file facts, a separately
bound and independently checked supplemental observation must supply them;
they cannot be inferred from the v3 manifest alone.

`P` is a versioned, canonical, bounded document pinned independently before
materialization. It binds `S`'s manifest digest and commit, the exact path set,
directory modes, regular-file modes by Git kind, owner/group, access and
default ACL requirements, xattr rules, link rules, limits and execution
environment. No implicit default, caller-supplied identity string, mutable
receipt or hash alone establishes approval. Policy provenance, approver
authority and the execution lease must be independently authenticated for a
qualifying run. A local experimental policy can only describe a non-Gate
observation.

The expected mapping `E = normalize(S, P)` is defined only when source and
policy identities match and every included entry has exactly one supported
rule. The included directory paths in `E` equal those in `S`; regular-file and
link paths, kinds and bytes match `S`; target mode, owner/group, ACL and other
declared attributes follow `P`, not an invented source value. Target links
must not escape the allowed projection or reach excluded paths. Duplicate,
ambiguous, unsupported, missing or extra paths invalidate the mapping.
Excluded inputs remain explicitly out of scope and must not be silently
available to a later qualified workload.

`T` is gathered from the actual candidate by an independent implementation.
It checks the entire expected path set, content bytes and types, Git object
identity, link target and safety, regular-file and directory modes, owner and
group, link count, access/default ACL, explicitly covered xattrs and physical
root/mount identity. `stat` mode alone does not prove ACL absence: named ACL
entries and inherited defaults can persist after `chmod`. If a required
property cannot be read, it is `UNKNOWN`, never a match. The result must
distinguish byte/type agreement, policy conformance and source-permission
preservation; the last is `UNKNOWN` when source permissions are unavailable.

Under complete observations, collision-resistant digests, faithful kernel and
filesystem behavior, a valid `S` and independently approved `P`, an exact
`projection_P(T) = E` supports only the stated normalized-candidate claim;
`T` also carries identity, mount and count observations beyond `E`. It does **not**
prove source permission equivalence, an authenticated execution, absence of
transient mutation or product validity. Each missing assumption prevents a
qualified claim.

## Required implementation and evidence

1. Define a new schema and entry point; preserve existing v3 meaning and do
   not replace source `null` modes with normalized values. Bind the canonical
   policy digest, source manifest and commit in a versioned receipt. Admit the
   exact files, symbols, owner and rollback before implementation.
2. Materialize only into a separately owned, bounded candidate location;
   prevent overwrite and unsafe publication. Keep source, policy, candidate
   and receipt identities through observation. Retain uncertain publication or
   process-stop states instead of deleting or reporting success.
3. Implement the oracle separately from the materializer. Derive the expected
   mapping independently from `S` and `P`, inspect physical candidate objects
   and preserve the original logs, hashes, complete per-case denominators,
   subject and lease bindings. Equal endpoint hashes do not prove a continuous
   immutable window.
4. Before admitting the path, preregister and execute at least these 20
   distinct cases. A case passes only when its own expected result and
   independently observed evidence agree. Before execution, expand this table
   into individually identified cases with one explicit expected status each;
   `REJECT` may be a structured
   rejection or, where facts cannot be established, `INCONCLUSIVE`.

   | # | Case | Required observation |
   |---|---|---|
   | 1 | Verified-mode v3 compatibility | Existing behavior unchanged |
   | 2 | Real 9p source to ext4 candidate | Source mode unknown; policy matches candidate |
   | 3 | Two runs with identical `S`, `P` | Equal target inventory digests |
   | 4 | Changed policy | Policy digest changes |
   | 5 | Mismatched manifest or commit binding | REJECT |
   | 6 | Missing independent policy pin or authority | No qualification |
   | 7 | Git `100755` file | Required owner execution and policy mode |
   | 8 | Git `100644` file | No execution bits |
   | 9 | Special mode or unknown policy rule | REJECT |
   | 10 | Empty directories and exclusions | Exact admitted paths and boundaries |
   | 11 | Unicode paths | Stable canonical order and digest |
   | 12 | Escaping or cyclic links | REJECT |
   | 13 | Externally linked candidate file | REJECT |
   | 14 | Extra named access ACL | Detect policy violation |
   | 15 | Inherited default ACL after chmod | Detect policy violation |
   | 16 | Wrong or unavailable owner/group | REJECT or INCONCLUSIVE |
   | 17 | Unreadable mode, ACL or required xattr | INCONCLUSIVE |
   | 18 | Source, index or mount changes | REJECT or INCONCLUSIVE |
   | 19 | Uncertain publication or process stop | Retain evidence and uncertainty |
   | 20 | Deliberately altered candidate | Independent oracle detects discrepancy |
5. A real full-tree observation is required in addition to small fixtures.
   Formal P0-01 acceptance also requires the authorized subject, lease,
   independent execution and oracle, source identity and all card criteria.
   A successful prototype, zero denominator, `BLOCKED`, `NOT_RUN` or
   `INCONCLUSIVE` cannot satisfy G0.

No implementation currently in this repository exercises this contract as an
authorized P0-01 path. The existing v3 materializer and oracle still require
verified source modes and remain unchanged until the new contract is admitted.

The following standalone **research-only** modules exercise parts of the
proposed mapping without changing the public P0-01 entry point:

- `ops/ecp/normalized_source.py` observes included source bytes against a
  pinned v3 manifest and produces a supplemental document with source mode
  `UNKNOWN`; it can bind the caller's already-open source directory FD.
- `ops/ecp/normalized_policy.py` constructs and validates explicitly pinned
  M/S/P drafts. A valid hash and structure do not authenticate a policy or
  authorize a workload.
- `ops/ecp/normalized_materialize.py` materializes an explicit draft only in
  an owned, private target parent, reports uncertain publication rather than
  deleting it, and does not authenticate an execution principal or lease.
- `verification/ecp/normalized_candidate_oracle.py` independently reads the
  source, Git facts and physical candidate; its inventory digest and byte
  denominator have their own stated scope. Optionally, it reads a separately
  byte-pinned draft receipt twice and independently reconstructs the v1
  materializer inventory from its physical candidate observations, checking
  the receipt's M/S/P bindings, path, counts and inventory digest. The receipt
  digest is an integrity pin, not authentication. The v1 receipt does not bind
  an inode, mount or nonce: a same-path, same-content historical replay cannot
  be ruled out, and sync and limitation text remain unverified self-reports.
  Neither its result nor the materializer's result is a product Gate.

These components use non-atomic endpoint observations. The experimental
supplement scan performs fewer intermediate samples than the earlier draft;
it must not be described as equivalent to a continuous immutable snapshot.
Visible xattr checks depend on the observing process, and successful `fsync`
calls do not prove power-loss recovery. A full-tree qualification run on the
final candidate, the complete
preregistered fault matrix, independent subject/lease and real Store evidence
remain necessary before P0-01 and G0 can be admitted or accepted.
