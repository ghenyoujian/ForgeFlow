#!/usr/bin/env python3
"""Read-only timing of actual console event rows, alongside one existing run.

The source timestamp is the persisted API event delivered by the console's own
forgeflow-event channel. Receiving that event is not a display sample. A sample
requires the matching project sequence and kind in a visible React table row,
followed by two animation frames (a paint opportunity, not photon telemetry).
"""
import argparse
import asyncio
import hashlib
import json
import math
import signal
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright


def utc():
    return datetime.now(timezone.utc).isoformat()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def percentile(values, p):
    if not values:
        return None
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)]


INSTRUMENT = r"""(config) => {
  // Source occurred_at is UTC wall time. Never project a browser monotonic
  // timestamp onto a timeOrigin captured before a host clock adjustment.
  const now = () => Date.now();
  const monotonic = () => performance.now();
  const state = window.__eventDisplay = {
    config, source: new Map(), samples: [], errors: [], scopes: [],
    seen: new Set(), pending: new Set(), matches: 0, selectedAttempt: null,
    sourceEvents: 0, oldExcluded: 0, outOfScope: 0, scanCount: 0,
    clock: {timeOrigin: performance.timeOrigin, wallUnixMs: now(), performanceMs: monotonic()},
  };
  const error = (kind, fields = {}) => state.errors.push({kind, atUnixMs: now(), ...fields});
  window.addEventListener('error', e => error('window_error', {message: String(e.message)}));
  window.addEventListener('unhandledrejection', e => error('unhandled_rejection', {message: String(e.reason)}));
  function eligible(event) {
    return event.object_id === state.selectedAttempt || event.attempt_id === state.selectedAttempt;
  }
  window.addEventListener('forgeflow-event', e => {
    const raw = e.detail?.event;
    if (!raw || raw.project_id !== config.project || !Number.isSafeInteger(raw.project_seq)) {
      error('source_identity_mismatch'); return;
    }
    state.sourceEvents++;
    if (raw.project_seq <= config.cursor) {state.oldExcluded++; return;}
    const event = {event_id: raw.event_id, project_id: raw.project_id,
      project_seq: raw.project_seq, kind: raw.kind, occurred_at: raw.occurred_at,
      object_id: raw.object_id, attempt_id: raw.payload?.attempt_id,
      sourceUnixMs: Date.parse(raw.occurred_at), consoleReceivedUnixMs: now(),
      consoleReceivedPerformanceMs: monotonic()};
    if (!Number.isFinite(event.sourceUnixMs)) {error('invalid_source_timestamp', {sequence: raw.project_seq}); return;}
    const prior = state.source.get(raw.project_seq);
    if (prior && (prior.event_id !== event.event_id || prior.kind !== event.kind || prior.occurred_at !== event.occurred_at)) {
      error('duplicate_sequence_identity_mismatch', {sequence: raw.project_seq}); return;
    }
    if (!prior) state.source.set(raw.project_seq, event);
    schedule();
  });
  let queued = false;
  const visible = (row, region) => {
    const r = row.getBoundingClientRect(), p = region.getBoundingClientRect();
    return document.visibilityState === 'visible' && r.width > 0 && r.height > 0 &&
      r.bottom > Math.max(0, p.top) && r.top < Math.min(innerHeight, p.bottom) &&
      r.right > Math.max(0, p.left) && r.left < Math.min(innerWidth, p.right) &&
      getComputedStyle(row).visibility !== 'hidden';
  };
  function scan() {
    state.scanCount++;
    const region = document.querySelector('.attempt-events-scroll');
    if (!region || !state.selectedAttempt) return;
    const rows = [...region.querySelectorAll('tbody tr')];
    const unseen = rows.filter(row => {
      const sequence = Number(row.cells?.[0]?.textContent?.trim());
      const event = state.source.get(sequence);
      return event && eligible(event) && !state.seen.has(sequence) && !state.pending.has(sequence);
    });
    if (!unseen.length) return;
    // A real user can scroll this overflow region. Observation follows the most
    // recent row; rows clipped outside its viewport are never called visible.
    region.scrollIntoView({block: 'center', behavior: 'instant'});
    region.scrollTop = region.scrollHeight;
    for (const row of unseen) {
      const sequence = Number(row.cells[0].textContent.trim());
      const event = state.source.get(sequence);
      const scope = state.scopes.at(-1);
      if (event.sourceUnixMs < scope.selectedUnixMs) {state.seen.add(sequence); state.oldExcluded++; continue;}
      if (row.cells[2]?.textContent.trim() !== event.kind) {error('dom_kind_mismatch', {sequence}); state.seen.add(sequence); continue;}
      if (!visible(row, region)) continue;
      const domVisibleUnixMs = now(), domVisiblePerformanceMs = monotonic(), selectedAttempt = state.selectedAttempt;
      state.pending.add(sequence);
      requestAnimationFrame(() => {
        const firstRafUnixMs = now(), firstRafPerformanceMs = monotonic();
        requestAnimationFrame(() => {
          state.pending.delete(sequence);
          if (selectedAttempt !== state.selectedAttempt || !row.isConnected || !visible(row, region)) {
            error('row_not_visible_at_paint_opportunity', {sequence}); schedule(); return;
          }
          const secondRafUnixMs = now(), secondRafPerformanceMs = monotonic();
          state.seen.add(sequence); state.matches++;
          const sample = {...event, selectedAttempt, scopeIndex: state.scopes.length - 1,
            domVisibleUnixMs, domVisiblePerformanceMs, firstRafUnixMs, firstRafPerformanceMs,
            secondRafUnixMs, secondRafPerformanceMs,
            domVisibleLagMs: domVisibleUnixMs - event.sourceUnixMs,
            paintOpportunityLagMs: secondRafUnixMs - event.sourceUnixMs,
            receiveToPaintMonotonicMs: secondRafPerformanceMs - event.consoleReceivedPerformanceMs,
            receiveToPaintWallMs: secondRafUnixMs - event.consoleReceivedUnixMs,
            wallVsMonotonicDriftMs: (secondRafUnixMs - event.consoleReceivedUnixMs) -
              (secondRafPerformanceMs - event.consoleReceivedPerformanceMs),
            rowText: [row.cells[0].textContent.trim(), row.cells[1].textContent.trim(), row.cells[2].textContent.trim()],
            viewport: {width: innerWidth, height: innerHeight}, visibility: document.visibilityState,
            source: 'persisted_api_event_console_channel', display: 'actual_react_event_row_two_animation_frames'};
          if (sample.domVisibleLagMs < -1) error('source_clock_ahead', {sequence, lagMs: sample.domVisibleLagMs});
          if (Math.abs(sample.wallVsMonotonicDriftMs) > 100) error('wall_and_monotonic_clocks_diverged_during_sample',
            {sequence, driftMs: sample.wallVsMonotonicDriftMs});
          state.samples.push(sample);
        });
      });
    }
  }
  function schedule() {
    if (!queued) {queued = true; requestAnimationFrame(() => {queued = false; scan();});}
  }
  state.select = attempt => {
    const selectedUnixMs = now();
    state.selectedAttempt = attempt;
    state.scopes.push({attempt_id: attempt, selectedUnixMs, selectedAt: new Date(selectedUnixMs).toISOString(), cursorCutoff: config.cursor});
    schedule();
  };
  state.drain = () => {
    const samples = state.samples.splice(0), errors = state.errors.splice(0);
    const scope = state.scopes.at(-1);
    const applicable = [...state.source.values()].filter(e => eligible(e) && e.sourceUnixMs >= (scope?.selectedUnixMs ?? Infinity));
    const undisplayed = applicable.filter(e => !state.seen.has(e.project_seq));
    return {samples, errors, counters: {sourceEvents: state.sourceEvents, uniqueSourceEvents: state.source.size,
      selectedAttemptSourceEvents: applicable.length, matchedVisibleRows: state.matches,
      oldExcluded: state.oldExcluded, scanCount: state.scanCount,
      selectedAttemptNotDisplayedCount: undisplayed.length,
      selectedAttemptNotDisplayedSequences: undisplayed.slice(-100).map(e => e.project_seq),
      otherAttemptSourceEventsExcluded: state.source.size - applicable.length}, scopes: state.scopes,
      selectedAttempt: state.selectedAttempt, clock: {...state.clock, currentWallUnixMs: now(),
        currentPerformanceMs: monotonic(), timeOriginProjectionUnixMs: performance.timeOrigin + monotonic()},
      visibility: document.visibilityState};
  };
  new MutationObserver(schedule).observe(document, {subtree: true, childList: true, characterData: true});
}"""


async def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if (output / "started.json").exists():
        raise RuntimeError("refuse to overwrite an earlier observation")
    (output / "probe-source.py").write_bytes(Path(__file__).read_bytes())
    private = json.loads(Path(args.private_env).read_text())
    token = private["FORGEFLOW_OWNER_TOKEN"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = args.base_url.rstrip("/")
    project = args.project
    def get_snapshot():
        request = urllib.request.Request(base + "/api/v1/projects/" + urllib.parse.quote(project, safe="") + "/snapshot",
            headers={"Authorization": "Bearer " + token})
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read())["data"]
    snapshot = await asyncio.to_thread(get_snapshot)
    cursor = snapshot["revision"]
    run_evidence = Path(args.run_evidence)
    receipt = run_evidence / "build.receipt.json"
    isolation_file = run_evidence / "isolation.json"
    isolation = json.loads(isolation_file.read_text()) if isolation_file.exists() else {}
    console_files = Path(__file__).resolve().parents[1] / "console" / "dist"
    console_identity = [{"path": str(file.relative_to(console_files)),
        "sha256": hashlib.sha256(file.read_bytes()).hexdigest(), "bytes": file.stat().st_size}
        for file in sorted(console_files.rglob("*")) if file.is_file()]
    # Write source identity, never the private env, token, request headers or payloads.
    start = {"schema_version": "forgeflow.browser_event_display.v1", "began_at": utc(),
        "base_url": base, "project_id": project, "run_evidence": str(Path(args.run_evidence)),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "run_build_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt.exists() else None,
        "run_authority_identity": {k: isolation.get(k) for k in ["server_pid", "source_revision", "api_binary_sha256", "worker_binary_sha256"]},
        "console_dist_files": console_identity,
        "old_backlog_cutoff": {"project_seq": cursor, "snapshot_as_of": snapshot["as_of"],
            "policy": "seed both actual console event cursors; exclude sequence <= cutoff and source predating each attempt selection"},
        "method": "actual persisted API UTC wall timestamp -> matching visible React row Date.now -> two animation frames Date.now; browser monotonic stamps recorded separately",
        "limits": ["one desktop browser and selected actual attempts; not all project events", "two animation frames establish a paint opportunity, not OS photon timing", "same-host API/browser wall clocks; no independent clock calibration", "wall/monotonic divergence is recorded without attributing which clock changed", "no G4 or production qualification decision"],
        "readonly": True, "viewport": {"width": 1440, "height": 1000}}
    write(output / "started.json", start)
    samples, errors, selections, blocked, http_errors = [], [], [], [], []
    browser_errors = []
    served_console_assets = []
    latest = {}
    stop_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, stop_requested.set)
    loop.add_signal_handler(signal.SIGTERM, stop_requested.set)
    def summary(terminal=False):
        values = [s["paintOpportunityLagMs"] for s in samples]
        unstable = sum(abs(s["wallVsMonotonicDriftMs"]) > 100 for s in samples)
        return {**start, "ended_at": utc() if terminal else None,
            "status": "OBSERVED" if samples and not (errors or browser_errors or blocked or unstable) else "INCONCLUSIVE", "terminal": terminal,
            "samples": len(samples), "paint_opportunity_lag_ms": {"p50": percentile(values, .5), "p95": percentile(values, .95), "max": max(values) if values else None},
            "dom_visible_lag_ms": {"p95": percentile([s["domVisibleLagMs"] for s in samples], .95)},
            "over_2000ms": sum(v > 2000 for v in values), "instrument_errors": errors,
            "clock_unstable_samples": unstable,
            "browser_errors": browser_errors, "non_get_requests_blocked": blocked,
            "http_errors": http_errors, "latest_browser_state": latest, "attempt_selection_count": len(selections),
            "served_console_assets": served_console_assets,
            "not_displayed": "project events outside selected attempts and clipped rows are not display samples; sample denominator is explicit, not whole-project coverage"}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(executable_path=args.browser,
            headless=True, args=["--no-proxy-server", "--disable-dev-shm-usage"])
        context = await browser.new_context(viewport={"width": 1440, "height": 1000})
        async def readonly(route):
            req = route.request
            if req.method not in {"GET", "HEAD"}:
                blocked.append({"at": utc(), "method": req.method, "path": urllib.parse.urlsplit(req.url).path})
                await route.abort()
            elif not req.url.startswith(base + "/"):
                blocked.append({"at": utc(), "method": req.method, "external_origin": urllib.parse.urlsplit(req.url).netloc})
                await route.abort()
            else:
                await route.continue_()
        await context.route("**/*", readonly)
        await context.add_init_script("sessionStorage.setItem('forgeflow.owner-token', " + json.dumps(token) + ");" +
            "localStorage.setItem('forgeflow.project', " + json.dumps(project) + ");" +
            "if (!sessionStorage.getItem(" + json.dumps("forgeflow.cursor." + project) + ")) sessionStorage.setItem(" + json.dumps("forgeflow.cursor." + project) + ", " + json.dumps(project + ":" + str(cursor)) + ");" +
            "if (!sessionStorage.getItem(" + json.dumps("forgeflow.events." + project) + ")) sessionStorage.setItem(" + json.dumps("forgeflow.events." + project) + ", " + json.dumps(json.dumps({"events": [], "cursor": cursor})) + ");")
        # Inline actual probe before any application code executes.
        await context.add_init_script("(" + INSTRUMENT + ")(" + json.dumps({"project": project, "cursor": cursor}) + ");")
        page = await context.new_page()
        page.on("pageerror", lambda exc: browser_errors.append({"at": utc(), "message": str(exc)}))
        async def record_response(response):
            response_path = urllib.parse.urlsplit(response.url).path
            if response.status >= 400:
                http_errors.append({"at": utc(), "status": response.status, "path": response_path})
            if response.status == 200 and (response_path.startswith("/assets/") or response_path.startswith("/runs/")):
                try:
                    body = await response.body()
                    served_console_assets.append({"path": response_path, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
                except Exception as exc:
                    errors.append({"kind": "served_asset_identity_unavailable", "path": response_path, "type": type(exc).__name__})
        page.on("response", record_response)
        selected = None
        navigation_count = 0
        async def select(attempt):
            nonlocal selected, navigation_count
            selected = attempt["attempt_id"]
            navigation_count += 1
            await page.goto(base + "/runs/" + selected + "?project=" + urllib.parse.quote(project, safe=""), wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_selector(".attempt-events-scroll", timeout=30000)
            await page.evaluate("attempt => window.__eventDisplay.select(attempt)", selected)
            selections.append({"at": utc(), "attempt_id": selected, "state_when_selected": attempt["state"], "navigation": navigation_count})
            with (output / "attempt-selections.jsonl").open("a") as stream:
                stream.write(json.dumps(selections[-1]) + "\n")
        active = [a for a in snapshot["attempts"] if a["state"] == "RUNNING"]
        if not active:
            active = snapshot["attempts"][-1:]
        if not active:
            raise RuntimeError("authority has no actual attempt to render")
        await select(sorted(active, key=lambda a: a.get("created_at", ""), reverse=True)[0])
        write(output / "render-precheck.json", {"at": utc(), "actual_url": page.url,
            "event_region_rendered": await page.locator(".attempt-events-scroll").count() == 1,
            "attempt_id": selected, "rendered_row_count": await page.locator(".attempt-events-scroll tbody tr").count(),
            "browser_errors": browser_errors, "http_errors": http_errors, "non_get_requests_blocked": blocked})
        await page.locator(".attempt-events-scroll").scroll_into_view_if_needed()
        await page.screenshot(path=str(output / "render-precheck.png"))
        while True:
            try:
                await asyncio.wait_for(stop_requested.wait(), timeout=args.flush_seconds)
            except asyncio.TimeoutError:
                pass
            latest = await page.evaluate("() => window.__eventDisplay.drain()")
            batch = latest.pop("samples")
            batch_errors = latest.pop("errors")
            samples.extend(batch); errors.extend(batch_errors)
            with (output / "samples.jsonl").open("a") as stream:
                for sample in batch:
                    stream.write(json.dumps(sample, ensure_ascii=False, separators=(",", ":")) + "\n")
            with (output / "observations.jsonl").open("a") as stream:
                stream.write(json.dumps({"at": utc(), **latest, "new_samples": len(batch), "errors": batch_errors}, ensure_ascii=False) + "\n")
            write(output / "progress.json", summary())
            if stop_requested.is_set():
                start["observer_stop_reason"] = "explicit signal received; own browser only, harness actors untouched"
                break
            report = Path(args.run_evidence) / "report.json"
            if report.exists():
                harness = json.loads(report.read_text())
                if harness.get("ended_at"):
                    start["harness_terminal"] = {k: harness.get(k) for k in ["ended_at", "gate_status", "smoke_status", "duration_seconds", "observations"]}
                    break
            try:
                snapshot = await asyncio.to_thread(get_snapshot)
            except Exception as exc:
                errors.append({"kind": "readonly_snapshot_unavailable", "at": utc(), "type": type(exc).__name__})
                # A transport failure is not permission to restart any actor.
                # Keep the same observer until the harness records termination.
                continue
            current = next((a for a in snapshot["attempts"] if a["attempt_id"] == selected), None)
            if current and current["state"] in {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "RECOVERY_REQUIRED"}:
                active = [a for a in snapshot["attempts"] if a["state"] == "RUNNING"]
                if active:
                    await select(sorted(active, key=lambda a: a.get("created_at", ""), reverse=True)[0])
        write(output / "report.json", summary(terminal=True))
        await browser.close()
    print(json.dumps({"output": str(output), "samples": len(samples), "status": "OBSERVED" if samples else "INCONCLUSIVE"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--private-env", required=True)
    parser.add_argument("--run-evidence", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--flush-seconds", type=float, default=15)
    parser.add_argument("--browser", default="/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome")
    arguments = parser.parse_args()
    asyncio.run(run(arguments))
