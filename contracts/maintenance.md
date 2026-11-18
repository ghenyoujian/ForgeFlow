# Owner maintenance API

All endpoints use `/api/v1` and require an unscoped Owner identity. Workers are
rejected. These are maintenance read models and jobs, not new Attempt states or
authority to execute models. No endpoint starts DSH, registers Workers, enables
autostart, settles unknown usage, overwrites a database or resumes dispatch.

## Recovery observations

`GET /recovery-items?project_id=<optional>&cursor=<optional>&limit=100` returns
the standard paginated envelope, with a maximum of 500 records per page and
`snapshot_across_pages=false`. Cursor ordering is the canonical Attempt ID.

The projection includes `RECOVERY_REQUIRED`, unconfirmed `STOPPING`, stale Worker
heartbeats on nonterminal attempts, unresolved integration, and unresolved model
or resource custody even on terminal attempts. Fields include project/task/attempt,
canonical state/revision/generation, actual Worker heartbeat and lease timestamps,
unsettled native/gateway model request counts, allocation row counts, unfinished
merge intent identities and explicit reasons. Counts describe persisted rows,
not concurrent agents, active processes or distinct physical slots. A heartbeat
older than 120 seconds is an observation threshold and does not change authority.
Current host process status remains `UNKNOWN` until a trusted observation exists.

The UI links to the exact attempt and its existing author-custody protocol. The
existing IntegrationRecovery component retains its original Owner/CAS/frozen
commit-decision checks; viewing the page never sends a recovery command.

## Stop-dispatch backup

`GET /backup-readiness` reads a REPEATABLE READ PostgreSQL snapshot of projects,
all nonterminal attempts, unsettled native and gateway requests, held resource
allocations/lifecycles and unfinished merge decisions. Every such unsettled fact
blocks backup, including custody retained after author cancellation. Missing
managed repositories also block. The response contains `projects`,
`unsettled_attempts`, `custody`, `blockers`, `ready`, `scope_sha256`, `backup_root`
and `dispatch_will_remain_paused=true`. Reading it never clears blockers.

`POST /backups` requires `Idempotency-Key` and:

```json
{
  "reason": "Reviewed local backup",
  "pause_new_dispatch": true,
  "expected_scope_sha256": "<exact reviewed readiness hash>"
}
```

The reason must be nonblank and no more than 2,000 UTF-8 bytes. Any changed scope
returns `BACKUP_SCOPE_STALE`; unsettled custody returns `BACKUP_BLOCKED`. The
credential is an authenticated Owner bearer token, passed only through the private
child environment, never persisted in job records or command arguments.

The response is HTTP 202 with a durable `forgeflow.backup-job.v1` record. The
Owner/request idempotency identity hashes to a stable 64-character job ID. Exact
replay returns the original job; changing the body under that key returns a
conflict. One OS-lock-protected maintenance lane permits one actual backup across
API processes. HTTP disconnects do not cancel the accepted background task.

`GET /backups` supports cursor/limit pagination. `GET /backups/{backup}` reports
actual `ACCEPTED`, `RUNNING`, `SUCCEEDED`, `FAILED` or `RECOVERY_REQUIRED` job status
with the real phase, timestamps, error, archive size/digest and verification
receipt. `dispatch_pause_policy=PAUSE_AND_LEAVE_PAUSED` records the requested
policy, not an observation of current project flags. A sealed job additionally
reports `snapshot_dispatch_paused=true`, bound to its captured manifest rather
than a claim that no later Owner action changed the live projects. These statuses
belong only to backup jobs. An unfinished job from a
different Core process instance is projected `RECOVERY_REQUIRED`; it is never
automatically rerun or offered as a successful archive. Initial partial directories
without a durable record are likewise visible as recovery-required. Diagnostics
and partial files remain private and retained.

The API embeds the exact `ops/backup.py` and `ops/restore.py` bytes at build time.
The helper verifies that `FORGEFLOW_API_URL` identifies its exact data root before
pausing anything. It checks custody again, pauses projects using existing CAS
commands, refuses every nonterminal attempt, exports PostgreSQL, and compares
event watermarks, resource policies, repository refs and complete file inventories
before issuing the existing `forgeflow.backup.v1` manifest. Concurrent changes
reject the snapshot. No cancel, model call or automatic resume is issued.

Repositories already inside the copied data root reuse their verified `data/`
snapshot path. They are never copied a second time or hard-linked to mutable
production files. External managed repositories receive separate snapshots.

The job compresses its snapshot, streams every archive member through the same
restore inventory validator, verifies SHA256, and syncs the actual archive. Only
after that complete check may it remove **this job's** temporary snapshot. It
keeps one final compressed archive, receipts and small diagnostics; production,
previous backups and failure evidence are never garbage-collected here.

Output defaults to a private sibling `<data-root-name>-backups` directory.
`FORGEFLOW_BACKUP_ROOT` may configure an absolute private path outside the data
root. Directories require same-UID ownership and mode 0700, files require private
permissions and regular non-symlink types. The local callback URL should be
configured explicitly for alternate ports. Runtime dependencies are Python 3,
PostgreSQL client tools, Git, tar and gzip. A failed/missing tool is an actual
failed phase, never a successful placeholder. Each subprocess has a two-hour
limit and is stopped on graceful Core shutdown; interrupted custody stays
unresolved. Linux direct children also receive parent-death termination.

## Verified download and restoration review

`GET /backups/{backup}/archive` serves only a `SUCCEEDED` sealed job. It opens the
private regular archive, hashes that file descriptor and checks the registered
length/digest before streaming the same descriptor. It returns a fixed safe
filename, Content-Length, ETag, `private, no-store` and `nosniff`. Missing, partial
or modified bytes are rejected. Download itself grants no business completion.

The UI uses authenticated fetch. Browsers with a file-save API stream large
downloads to disk and check the sealed response digest and received byte length.
Other browsers independently hash bounded downloads up to 128 MiB; larger files
require a browser supporting streaming file save. It does not buffer an arbitrary
multi-GB backup in browser memory or expose Owner tokens in URLs.

`GET /backups/{backup}/restore-preview` rechecks the sealed archive digest and
returns its exact original full streamed verification plus isolation conditions.
It does not extract, copy state, execute SQL or restore production. The response
explicitly reports `restore_executed=false` and `production_overwritten=false`.

The shared CLI supports:

```sh
python3 ops/restore.py --archive /private/backup.tar.gz --verify-only
python3 ops/restore.py --backup /isolated/extracted-backup --verify-only
python3 ops/restore.py --backup /isolated/extracted-backup \
  --destination /new/nonexistent/restore-root --database-env /private/empty-db.json
```

Archive verification never extracts members. It rejects unsafe/duplicate paths,
symbolic-link ancestry, hard links and special members, invalid or missing
inventory, mismatched hashes, oversized metadata and expansion beyond the
declared limits. Default limits are 500,000 members, 64 MiB manifest, 1 MiB
extended-header payload, 32 GiB unpacked bytes and a bounded expansion ratio.
An explicit CLI unpacked-byte override is bounded to 1 TiB. Existing leaf
symlinks are preserved and explicitly require review; they are never followed
while validating archive contents.

Actual restore retains the original requirements: a fresh isolated directory, an
explicitly empty reachable PostgreSQL database, single-transaction pg_restore,
cleared Owner sessions, reviewed relocation and new distinct credentials. Archive
input is accepted only for read-only verification; restoration uses the verified
isolated extracted directory. Production overwrite and automatic dispatch are
not implemented or implied by preview.

## Evidence boundary

Source, syntax checks and local filesystem fixtures do not qualify a real backup,
successful isolated restore, production recovery or executor concurrency. The
coordinator must exercise the new routes against an isolated real PostgreSQL
deployment and inspect rendered UI before marking F23/F24 verified. DSH remains
disabled during those checks.
