# Linux/WSL process supervision

The runtime persists a launch intent before `spawn`, records a fingerprinted
receipt, drains stdout/stderr concurrently to durable private files and retains
ownership of the `Child` until explicit wait/reap and group quiescence. It sends
TERM, then KILL after a finite grace. Natural parent exit also checks descendants;
Linux subreaper mode permits explicit reaping of orphaned grandchildren. A bounded
notification channel carries file offsets; full original bytes remain the source
of truth and notification overflow is reported.

Only current-boot matching PID/start fingerprint or attributable attempt markers
permit recovery signalling. Missing receipts and escaped descendants remain
quarantined. A durable launch lock or intent precludes a second launch. Kernel
reboot proves processes from the previous boot stopped; it does not accept old
business results or restore write permission.

`StopEvidence.process_exit_confirmed` proves local quiescence within this trusted
process profile. `exit_code: 0` is execution evidence, never task or product success.

Meaningful tests in `tests/lifecycle.rs` exercise actual child/grandchild cleanup,
TERM-ignoring processes, explicit reap, normal exit with an orphan, timeout,
bounded log backpressure and a real supervisor SIGKILL with a deliberately missing
launch receipt. The crash test retains quarantine, refuses relaunch, restores the
authenticated identity solely for test cleanup and confirms all descendants end.

Run through the coordinated workspace build:

```bash
CARGO_TARGET_DIR=/home/chenyoujian/.cache/forgeflow-control-target \
CARGO_BUILD_JOBS=2 cargo test -p forgeflow-runtime --test lifecycle
```

This crate requires Linux `/proc` and POSIX process groups; no Windows-native
qualification is claimed. A process group is not an OS resource sandbox. The
caller must never abort a supervisor to represent cancellation; signal its watch
channel and await the durable stop evidence.
