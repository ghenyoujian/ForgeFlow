#!/usr/bin/env python3
"""Independent, conservative review of Phase 0 evidence references."""
from __future__ import annotations
import argparse
import json
import os
import sys
import unicodedata
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class OutputUnavailable(Exception):
    def __init__(self, reason: str, output_state: str):
        super().__init__(reason)
        self.output_state = output_state


def write_report_exclusive(output: Path, evidence: list[Path], text: str) -> None:
    """Best-effort no-clobber, not directory or principal authentication."""
    try:
        # Conservative normalization can reject distinct paths. It does not
        # establish race-free or exhaustive filesystem identity.
        def key(path: Path) -> str:
            return unicodedata.normalize("NFC", str(path.resolve(strict=False))).casefold()
        destination = Path(key(output)).parts
        def related(path: Path) -> bool:
            source = Path(key(path)).parts
            return (destination == source or destination[:len(source)] == source
                    or source[:len(destination)] == destination)
        if any(related(path) for path in evidence):
            raise OutputUnavailable("OUTPUT_MAY_ALIAS_EVIDENCE", "NOT_CREATED_BY_THIS_CALL")
        data = text.encode("utf-8")
    except OutputUnavailable:
        raise
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise OutputUnavailable("OUTPUT_PATH_OR_ENCODING_UNKNOWN", "NOT_CREATED_BY_THIS_CALL") from exc
    required = ("O_NOFOLLOW", "O_CLOEXEC")
    if not all(hasattr(os, flag) for flag in required):
        raise OutputUnavailable("OUTPUT_FLAGS_UNAVAILABLE", "NOT_CREATED_BY_THIS_CALL")
    try:
        # Do not create parent directories: one could be missing evidence.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(output, flags, 0o600)
    except FileExistsError as exc:
        raise OutputUnavailable("OUTPUT_ALREADY_EXISTS", "NOT_CREATED_BY_THIS_CALL") from exc
    except OSError as exc:
        raise OutputUnavailable("OUTPUT_CREATE_UNKNOWN", "CREATE_OUTCOME_UNKNOWN") from exc
    error = None
    try:
        try:
            pos = 0
            while pos < len(data):
                count = os.write(fd, data[pos:])
                if count <= 0 or count > len(data) - pos:
                    raise OSError("invalid output write count")
                pos += count
            os.fsync(fd)
        except OSError as exc:
            error = exc
    finally:
        try:
            os.close(fd)  # one attempt only; close outcome may be indeterminate
        except OSError as exc:
            if error is None:
                error = exc
    if error is not None:
        # A new empty/partial/full file may remain; never unlink by pathname.
        raise OutputUnavailable("OUTPUT_WRITE_OR_CLOSE_UNKNOWN", "UNKNOWN_PARTIAL") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reports = []
    missing = []
    invalid = []
    read_error = False
    valid_statuses = {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "INCONCLUSIVE"}
    for path in args.evidence:
        if not path.exists():
            missing.append(str(path))
            continue
        try:
            value = load(path)
        except (OSError, ValueError) as exc:
            read_error = True
            reports.append((str(path), None))
            invalid.append({"path": str(path), "reason": type(exc).__name__})
            continue
        status = value.get("status") if isinstance(value, dict) else None
        reports.append((str(path), status))
        if type(status) is not str or status not in valid_statuses:
            invalid.append({"path": str(path), "reason": "invalid supplied status or evidence object"})
    statuses = [value for _, value in reports]
    if any(type(value) is str and value == "FAIL" for value in statuses):
        status, reason = "FAIL", "supplied evidence reports FAIL; the claim is not independently authenticated"
    elif read_error:
        status, reason = "FAIL", "local evidence read or JSON parse failed; no supplied failure claim is authenticated"
    elif missing:
        status, reason = "BLOCKED", "required evidence file is missing"
    elif not reports:
        status, reason = "NOT_RUN", "no independent evidence was supplied"
    elif invalid:
        status, reason = "INCONCLUSIVE", "supplied evidence is malformed or has an invalid status"
    elif any(value in {"BLOCKED", "NOT_RUN", "INCONCLUSIVE"} for value in statuses):
        status, reason = "INCONCLUSIVE", "evidence contains unresolved or unexecuted checks"
    else:
        status, reason = "INCONCLUSIVE", "offline evidence cannot issue a product Gate"
    report = {"schema_version": "forgeflow.ecp-g0-review.v1", "product_gate_effect": "NONE", "status": status, "reason": reason, "evidence": [path for path, _ in reports], "missing": missing, "invalid": invalid, "observed_statuses": statuses}
    try:
        write_report_exclusive(args.output, args.evidence, json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n")
    except OutputUnavailable as exc:
        failure_status = "FAIL" if status == "FAIL" else "BLOCKED"
        diagnostic = {"status": failure_status, "product_gate_effect": "NONE", "reason": str(exc),
                      "output_status": exc.output_state, "evidence_report": report}
        print(json.dumps(diagnostic, ensure_ascii=True), file=sys.stderr)
        return 10 if failure_status == "FAIL" else 20
    print(json.dumps(report, ensure_ascii=True))
    return {"FAIL": 10, "BLOCKED": 20, "NOT_RUN": 20, "INCONCLUSIVE": 20}[status]


if __name__ == "__main__":
    raise SystemExit(main())
