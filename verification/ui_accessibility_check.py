#!/usr/bin/env python3
"""Only the unproved keyboard/zoom/dense-log/empty/error UX, real main GETs.

No business mutation, Worker, model or new API server. An own login session is
revoked at the end. CSS zoom is explicitly distinguished from browser zoom.
"""
import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence/enterprise-ux/accessibility-final-r1"
BASE = "http://127.0.0.1:8787"
RUNTIME = Path("/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json")
CHROME = "/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome"


def main():
    global BASE, OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--unfinished-only", action="store_true")
    parser.add_argument("--long-log-only", action="store_true")
    parser.add_argument("--resume-project-cursor", type=int)
    parser.add_argument("--frontend-receipt", type=Path)
    parser.add_argument("--base-url", default=BASE)
    parser.add_argument("--output", type=Path, default=OUT)
    args = parser.parse_args()
    if args.long_log_only and not args.unfinished_only:
        parser.error("--long-log-only requires --unfinished-only")
    if args.resume_project_cursor is not None and (not args.long_log_only or args.resume_project_cursor < 0):
        parser.error("--resume-project-cursor requires --long-log-only and a nonnegative actual cursor")
    BASE, OUT = args.base_url.rstrip("/"), args.output
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.run:
        if args.unfinished_only:
            print(json.dumps({"status": "POINT_CONTINUATION_READY_NOT_EXECUTED", "cases": ["long_log"] if args.long_log_only else ["CSS_zoom_200", "long_log"]}))
            return 0
        plan = {"status": "SOURCE_READY_NOT_EXECUTED", "only_missing_cases": ["keyboard", "actual_css_zoom_200_percent",
            "existing_dense_table", "existing_long_log_keyboard_reading", "real_filter_empty", "real_GET404_error"],
            "all_business_methods": ["GET"], "own_auth_exceptions": ["POST /session", "POST /logout"],
            "models": 0, "workers": 0, "new_server": False, "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        (OUT / "report.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n")
        print('{"status":"SOURCE_READY_NOT_EXECUTED","missing_case_count":6}')
        return 0
    report_path = OUT / "browser-report.json"
    if report_path.exists():
        raise RuntimeError("Keep the original bounded observation; no automatic repeat.")
    from playwright.sync_api import sync_playwright
    runtime = json.loads(RUNTIME.read_text())
    secrets = [v for k, v in runtime.items() if isinstance(v, str) and any(s in k for s in ("TOKEN", "PASSWORD", "SECRET"))]
    token = ""
    report = {"status": "RUNNING", "scope": "Only previously unproved UX obligations", "base_url": BASE,
        "cases": {}, "requests": [], "javascript_errors": [], "console_errors": [], "business_writes": 0,
        "model_requests_added": 0, "workers_started": 0, "servers_started": 0, "credential_values_disclosed": False}

    def sanitized(text):
        for secret in secrets:
            if secret:
                text = text.replace(secret, "<redacted>")
        return text[:700]

    def save():
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    browser = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path=CHROME, args=["--no-proxy-server"])
            context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            if args.resume_project_cursor is not None:
                original_path = ROOT / "evidence/enterprise-ux/accessibility-final-r1/browser-report.json"
                long_fixture = json.loads(original_path.read_text())["existing_fixture_discovery"]["long_log"]
                diagnostic_path = original_path.parent / "point-continuation-r1/log-entry-diagnostic.json"
                diagnostic = json.loads(diagnostic_path.read_text())
                html = diagnostic["main_html_excerpt"]
                if f"游标 {args.resume_project_cursor}" not in html or "事件帧超过缓冲上限" not in html:
                    raise RuntimeError("Resume cursor must bind the actual previous failed stream observation.")
                report["actual_previous_stream_failure"] = {"path": str(diagnostic_path),
                    "sha256": hashlib.sha256(diagnostic_path.read_bytes()).hexdigest(),
                    "cursor": args.resume_project_cursor,
                    "old_error_does_not_independently_prove_single_frame_size": True}
                context.add_init_script("""
                    const fixture = """ + json.dumps({"key": "forgeflow.events." + long_fixture["project_id"], "cursor": args.resume_project_cursor}) + ";\n" + """
                    sessionStorage.setItem(fixture.key, JSON.stringify({events:[],cursor:fixture.cursor}));
                    window.__forgeflowLogResync = [];
                    window.addEventListener('forgeflow-resync', event => window.__forgeflowLogResync.push(event.detail));
                """)
            page = context.new_page()
            page.set_default_timeout(30000)
            page.on("pageerror", lambda error: report["javascript_errors"].append(sanitized(str(error))))
            page.on("console", lambda message: report["console_errors"].append(sanitized(message.text)) if message.type == "error" else None)
            page.on("response", lambda response: report["requests"].append({"method": response.request.method,
                "path": response.url.replace(BASE, ""), "status": response.status}) if "/api/v1/" in response.url else None)

            def case(name, callback):
                try:
                    result = callback()
                    report["cases"][name] = result
                except Exception as error:
                    report["cases"][name] = {"status": "FAIL", "type": type(error).__name__, "message": sanitized(str(error))}
                save()

            def get(route, allowed=(200,)):
                response = context.request.get(BASE + "/api/v1" + route, headers={"Authorization": "Bearer " + token})
                report["requests"].append({"method": "GET", "path": "/api/v1" + route, "status": response.status})
                if response.status not in allowed:
                    raise RuntimeError("Readonly metadata HTTP " + str(response.status) + " at " + route)
                return response.json().get("data") if response.status == 200 else None

            response = page.goto(BASE + "/portfolio", wait_until="domcontentloaded")
            report["served_console_index_sha256"] = hashlib.sha256(response.body()).hexdigest()
            if args.frontend_receipt:
                receipt = json.loads(args.frontend_receipt.read_text())
                compiled_index = Path(receipt["output_dir"]) / "index.html"
                report["frontend_identity"] = {"receipt": str(args.frontend_receipt),
                    "receipt_sha256": hashlib.sha256(args.frontend_receipt.read_bytes()).hexdigest(),
                    "compiled_index_sha256": hashlib.sha256(compiled_index.read_bytes()).hexdigest()}
                if report["served_console_index_sha256"] != report["frontend_identity"]["compiled_index_sha256"]:
                    raise RuntimeError("Actual served console index differs from the supplied new frontend receipt.")
            password = page.get_by_label("负责人密码", exact=True)
            password.fill(runtime["FORGEFLOW_OWNER_PASSWORD"])
            with page.expect_response(lambda response: response.request.method == "POST" and response.url == BASE + "/api/v1/session") as pending:
                password.press("Enter")
            if pending.value.status != 200:
                raise RuntimeError("The own keyboard login did not succeed.")
            page.get_by_role("heading", name="项目组合", exact=True).wait_for()
            page.wait_for_function("Boolean(sessionStorage.getItem('forgeflow.owner-token'))")
            token = page.evaluate("sessionStorage.getItem('forgeflow.owner-token') || ''")
            secrets.append(token)
            report["own_keyboard_login_http_status"] = pending.value.status
            projects = [] if args.unfinished_only else get("/projects?limit=100")
            ranked = sorted(projects, key=lambda p: (not bool(re.search(r"native|DSH|128|日志|journey", p.get("name", ""), re.I)), p["project_id"]))
            dense, longest, inspected = None, None, []
            if args.unfinished_only:
                original_path = ROOT / "evidence/enterprise-ux/accessibility-final-r1/browser-report.json"
                original = json.loads(original_path.read_text())
                fixture = original["existing_fixture_discovery"]
                dense, longest = fixture["dense"], fixture["long_log"]
                report["point_continuation"] = {"original_report": str(original_path),
                    "original_report_sha256": hashlib.sha256(original_path.read_bytes()).hexdigest(),
                    "original_failure_preserved": True,
                    "inherited_passed_cases": {k:v for k,v in original["cases"].items() if v["status"] == "PASS"},
                    "repeated_passed_cases": [], "scope": ["CSS zoom=2", "unfinished real long-log reading"]}
            for project in ranked[:8]:
                project_id = project["project_id"]
                tasks = get("/projects/" + project_id + "/tasks?limit=100")
                attempts = get("/projects/" + project_id + "/attempts?limit=25")
                inspected.append({"project_id": project_id, "task_count_observed": len(tasks), "attempt_count_observed": len(attempts)})
                if tasks and (dense is None or len(tasks) > dense["count"]):
                    dense = {"project_id": project_id, "count": len(tasks)}
                for attempt in attempts[:3]:
                    log = get("/attempts/" + attempt["attempt_id"] + "/logs?offset=0&limit_bytes=65536", (200, 404))
                    if log:
                        text = log.get("text", "")
                        if len(text) > (longest["characters"] if longest else 0):
                            longest = {"project_id": project_id, "attempt_id": attempt["attempt_id"],
                                "characters": len(text), "log_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                "real_dsh": attempt.get("result", {}).get("evidence", {}).get("real_dsh", "NOT_DECLARED")}
                if dense and dense["count"] >= 25 and longest and longest["characters"] >= 16384:
                    break
            report["existing_fixture_discovery"] = {"projects_inspected": inspected, "dense": dense, "long_log": longest}

            def keyboard():
                page.goto(BASE + "/portfolio", wait_until="domcontentloaded")
                page.get_by_role("heading", name="项目组合", exact=True).wait_for()
                page.keyboard.press("Tab")
                skip_focused = page.evaluate("document.activeElement.classList.contains('skip-link')")
                if not skip_focused:
                    page.locator(".skip-link").focus()
                page.keyboard.press("Enter")
                main_focused = page.evaluate("document.activeElement.id === 'main-content'")
                if not dense:
                    return {"status": "INCONCLUSIVE", "reason": "No existing task rows", "skip_link_main_focused": main_focused}
                page.goto(BASE + "/projects/" + dense["project_id"] + "/tasks", wait_until="domcontentloaded")
                rows = page.locator("tr.interactive-row")
                rows.first.wait_for()
                rows.first.focus()
                if rows.count() > 1:
                    page.keyboard.press("ArrowDown")
                focused_index = rows.evaluate_all("nodes => nodes.indexOf(document.activeElement)")
                ring = page.evaluate("({visible:document.activeElement.matches(':focus-visible'),outline:getComputedStyle(document.activeElement).outlineWidth})")
                page.keyboard.press("Enter")
                drawer = page.get_by_role("dialog").last
                drawer.wait_for()
                close = drawer.get_by_role("button", name="关闭检查器", exact=True)
                close.focus()
                page.keyboard.press("Shift+Tab")
                wrapped_last = drawer.evaluate("el => el.contains(document.activeElement) && document.activeElement !== el.querySelector('button')")
                page.keyboard.press("Tab")
                wrapped_first = close.evaluate("el => document.activeElement === el")
                page.screenshot(path=str(OUT / "keyboard-drawer.png"), full_page=False)
                page.keyboard.press("Escape")
                drawer.wait_for(state="hidden")
                restored = rows.evaluate_all("nodes => nodes.indexOf(document.activeElement)") == focused_index
                passed = main_focused and focused_index == min(1, rows.count() - 1) and wrapped_last and wrapped_first and restored and ring["visible"]
                return {"status": "PASS" if passed else "FAIL", "skip_first_tab": skip_focused,
                    "skip_link_main_focused": main_focused, "row_arrow_index": focused_index, "focus_ring": ring,
                    "drawer_tab_wrap_last": wrapped_last, "drawer_tab_wrap_first": wrapped_first, "escape_restored_row_focus": restored}
            if not args.unfinished_only:
                case("keyboard", keyboard)

            def dense_and_zoom():
                if not dense:
                    return {"status": "INCONCLUSIVE", "reason": "No existing dense task data"}
                page.goto(BASE + "/projects/" + dense["project_id"] + "/tasks", wait_until="domcontentloaded")
                page.locator("tbody tr").first.wait_for()
                count = page.locator("tbody tr").count()
                page.evaluate("document.documentElement.style.zoom='2'")
                metrics = page.evaluate("({method:'actual CSS root zoom=2; not native browser zoom',zoom:getComputedStyle(document.documentElement).zoom,innerWidth,clientWidth:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth+2,headerRight:document.querySelector('.topbar').getBoundingClientRect().right,mainRight:document.querySelector('main').getBoundingClientRect().right})")
                page.screenshot(path=str(OUT / "css-zoom-200-dense-table.png"), full_page=False)
                page.evaluate("document.documentElement.style.zoom=''")
                return {"status": "PASS" if not metrics["overflow"] and metrics["headerRight"] <= 1442 and metrics["mainRight"] <= 1442 else "FAIL",
                    "rendered_rows": count, "dense_data_status": "PASS" if count >= 25 else "INCONCLUSIVE_BELOW_25_ROWS", "metrics": metrics}
            if not args.long_log_only:
                case("dense_table_and_css_zoom_200", dense_and_zoom)

            def empty():
                if not dense:
                    return {"status": "INCONCLUSIVE", "reason": "No existing task page for a real filter"}
                page.goto(BASE + "/projects/" + dense["project_id"] + "/tasks", wait_until="domcontentloaded")
                filter_input = page.get_by_label("过滤已加载任务", exact=True)
                filter_input.fill("ui-accessibility-no-match-20261010-r1")
                empty = page.get_by_role("heading", name="本页筛选没有匹配任务", exact=True)
                empty.wait_for()
                page.screenshot(path=str(OUT / "real-filter-empty.png"), full_page=False)
                filter_input.fill("")
                return {"status": "PASS", "origin": "actual existing rows filtered locally; no authoritative data created", "empty_feedback_visible": True}
            if not args.unfinished_only:
                case("real_filter_empty", empty)

            def error_feedback():
                project_id = dense["project_id"] if dense else projects[0]["project_id"]
                route = "/runs/ui-accessibility-missing-r1?project=" + project_id
                page.goto(BASE + route, wait_until="domcontentloaded")
                alert = page.get_by_role("alert").first
                alert.wait_for()
                text = alert.inner_text()
                retry = alert.get_by_role("button", name="重新请求", exact=True)
                retry_visible = retry.is_visible()
                page.screenshot(path=str(OUT / "real-get404-feedback.png"), full_page=False)
                return {"status": "PASS" if retry_visible and re.search(r"NOT_FOUND|ATTEMPT_NOT_FOUND", text) else "FAIL",
                    "route": route, "feedback": sanitized(text), "retry_control_visible": retry_visible,
                    "actual_http404_count": sum(r["status"] == 404 for r in report["requests"])}
            if not args.unfinished_only:
                case("real_GET404_error", error_feedback)

            def long_log():
                if not longest or longest["characters"] < 8192:
                    return {"status": "INCONCLUSIVE", "reason": "No sufficiently long original log in the bounded existing-project discovery", "longest": longest}
                page.goto(BASE + "/runs/" + longest["attempt_id"] + "?project=" + longest["project_id"], wait_until="domcontentloaded")
                panel = page.locator("section.panel").filter(has=page.get_by_role("heading", name="运行过程", exact=True))
                panel.wait_for()
                recovery = None
                if args.resume_project_cursor is not None:
                    snapshot_response = context.request.get(BASE + "/api/v1/projects/" + longest["project_id"] + "/snapshot",
                        headers={"Authorization": "Bearer " + token})
                    report["requests"].append({"method": "GET", "path": "/api/v1/projects/" + longest["project_id"] + "/snapshot", "status": snapshot_response.status})
                    snapshot = snapshot_response.json()
                    version = snapshot.get("read_model_version")
                    if snapshot_response.status != 200 or snapshot.get("source") != "postgres" or snapshot.get("data", {}).get("project", {}).get("project_id") != longest["project_id"] or not isinstance(version, int) or snapshot["data"].get("revision") != version:
                        raise RuntimeError("Actual recovery snapshot identity was not proved.")
                    page.wait_for_function("({key,head}) => JSON.parse(sessionStorage.getItem(key)||'null')?.cursor===head",
                        arg={"key": "forgeflow.events." + longest["project_id"], "head": version})
                    client = page.evaluate("key => {const raw=sessionStorage.getItem(key)||'';return {cached:JSON.parse(raw),cacheBytes:new TextEncoder().encode(raw).length,resyncs:window.__forgeflowLogResync}}", "forgeflow.events." + longest["project_id"])
                    notice = panel.get_by_text("历史事件未完整显示，已同步权威快照", exact=True)
                    synchronized = any(event.get("projectId") == longest["project_id"] for event in client["resyncs"])
                    if synchronized:
                        notice.wait_for()
                    recovery = {"actual_resume_cursor": args.resume_project_cursor, "authoritative_head": version,
                        "source": snapshot["source"], "cached_cursor": client["cached"]["cursor"],
                        "cached_event_count": len(client["cached"]["events"]), "resyncs": client["resyncs"],
                        "snapshot_resync_observed": synchronized, "notice_visible": notice.is_visible(),
                        "actual_serialized_cache_bytes": client["cacheBytes"], "cache_byte_limit": 256 * 1024,
                        "display_cache_budget_notice_visible": panel.locator("p[role=status]").filter(has_text="显示缓存预算为 256 KiB").is_visible(),
                        "interpretation": "Actual authority snapshot resync; old history intentionally omitted" if synchronized else "Actual consecutive frames reached authority head; no snapshot recovery or single-frame qualification claimed",
                        "empty_history_after_snapshot": len(client["cached"]["events"]) == 0 if synchronized else None}
                    report["actual_snapshot_recovery"] = recovery
                    if recovery["cached_cursor"] != version or synchronized and not recovery["empty_history_after_snapshot"]:
                        raise RuntimeError("Client did not resume from the actual authority head or retained unproved history after resync.")
                    if client["cacheBytes"] > recovery["cache_byte_limit"] or len(client["cached"]["events"]) > 1000:
                        raise RuntimeError("Actual browser display cache exceeds its byte or count budget.")
                    if client["cached"].get("cacheNotice") and not recovery["display_cache_budget_notice_visible"]:
                        raise RuntimeError("Actual display eviction was not disclosed to the user.")
                # Finish the initial native event/identity read before changing
                # tabs. A fresh locator reads actual current rendered state.
                panel.locator("p[role=status]").filter(has_text="事件已连接").wait_for()
                panel.get_by_role("button", name="日志", exact=True).click()
                log = page.locator(".log-view")
                log.wait_for()
                page.wait_for_function("document.querySelector('.log-view')?.textContent.length > 1000")
                metrics = log.evaluate("el => ({characters:el.textContent.length,height:el.clientHeight,scrollHeight:el.scrollHeight,tabIndex:el.tabIndex})")
                log.focus()
                focused = log.evaluate("el => document.activeElement === el")
                before = log.evaluate("el => el.scrollTop")
                page.keyboard.press("PageDown")
                page.wait_for_timeout(300)
                actual = page.evaluate("(()=>{const el=document.querySelector('.log-view');return el?{exists:true,scrollTop:el.scrollTop,text:el.textContent}:{exists:false}})()")
                if not actual["exists"]:
                    return {"status": "FAIL", "reason": "Actual log container disappeared after the key action; no longer treated as a locator timeout", "source": longest}
                after, text = actual["scrollTop"], actual["text"]
                raw_log_sha256 = hashlib.sha256(text.encode()).hexdigest()
                matches_original = len(text) == longest["characters"] and raw_log_sha256 == longest["log_sha256"]
                notice_preserved = not recovery or not recovery["snapshot_resync_observed"] or panel.get_by_text("历史事件未完整显示，已同步权威快照", exact=True).is_visible()
                cache_notice_preserved = not recovery or not recovery["display_cache_budget_notice_visible"] or panel.locator("p[role=status]").filter(has_text="显示缓存预算为 256 KiB").is_visible()
                safe = not any(secret and secret in text for secret in secrets)
                if safe:
                    log.scroll_into_view_if_needed()
                    page.screenshot(path=str(OUT / "original-long-log-keyboard.png"), full_page=False)
                return {"status": "PASS" if focused and after > before and matches_original and notice_preserved and cache_notice_preserved else "FAIL", "source": longest,
                    "metrics": metrics, "focusable": focused, "page_down_before": before, "page_down_after": after,
                    "rendered_log_sha256": raw_log_sha256, "original_text_identity_matches": matches_original,
                    "historical_gap_notice_preserved_in_log_tab": notice_preserved,
                    "display_cache_budget_notice_preserved_in_log_tab": cache_notice_preserved,
                    "screenshot_omitted_for_known_secret": not safe}
            case("original_long_log_keyboard", long_log)
            report["all_business_requests_GET"] = all(r["method"] == "GET" or r["path"] in ("/api/v1/session", "/api/v1/logout") for r in report["requests"])
            try:
                response = context.request.post(BASE + "/api/v1/logout", data={}, headers={"Authorization": "Bearer " + token})
                report["own_session_logout_http_status"] = response.status
                report["requests"].append({"method": "POST", "path": "/api/v1/logout", "status": response.status})
            except Exception as error:
                report["own_session_logout"] = {"status": "UNCONFIRMED", "type": type(error).__name__}
            report["status"] = "FAIL" if any(c["status"] == "FAIL" for c in report["cases"].values()) or report["javascript_errors"] else (
                "INCONCLUSIVE" if any(c["status"].startswith("INCONCLUSIVE") for c in report["cases"].values()) else "PASS")
            browser.close()
            browser = None
    except Exception as error:
        report.update(status="FAIL", fatal={"type": type(error).__name__, "message": sanitized(str(error))})
    finally:
        if token and report.get("own_session_logout_http_status") != 200:
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                request = urllib.request.Request(BASE + "/api/v1/logout", method="POST", data=b"{}",
                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
                with opener.open(request, timeout=15) as response:
                    report["own_session_logout_http_status"] = response.status
                report["requests"].append({"method": "POST", "path": "/api/v1/logout", "status": response.status})
            except Exception as error:
                report["own_session_logout"] = {"status": "UNCONFIRMED", "type": type(error).__name__}
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        save()
    print(json.dumps({"status": report["status"], "cases": {k:v["status"] for k,v in report["cases"].items()},
        "javascript_errors": len(report["javascript_errors"]), "logout": report.get("own_session_logout_http_status"), "report": str(report_path)}, ensure_ascii=False))
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
