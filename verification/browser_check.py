#!/usr/bin/env python3
"""Rendered browser checks; screenshots are evidence, not automatic design approval."""
import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path


async def run(args):
    from playwright.async_api import async_playwright
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"scope": "rendered UI smoke, responsiveness and keyboard", "at": datetime.now(timezone.utc).isoformat(),
              "url": args.url, "checks": [], "limitations": ["Workflow authority needs separate API/database evidence",
                "Screenshots require human aesthetic review; automated smoke does not prove Apple visual quality"]}
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, executable_path=args.executable)
        for name, width, height, reduced in [("desktop", 1440, 1000, False), ("mobile", 390, 844, False),
                                             ("desktop-reduced-motion", 1440, 1000, True)]:
            context = await browser.new_context(viewport={"width": width, "height": height},
                                               reduced_motion="reduce" if reduced else "no-preference")
            if args.private_env:
                private = json.loads(Path(args.private_env).read_text())
                token = private["FORGEFLOW_OWNER_TOKEN"]
                await context.add_init_script("sessionStorage.setItem('forgeflow.owner-token'," + json.dumps(token) + ");")
            page = await context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            for index, route in enumerate(args.routes):
                try:
                    # Persistent SSE intentionally keeps the network active.
                    response = await page.goto(args.url.rstrip("/") + route, wait_until="domcontentloaded", timeout=15000)
                    await page.locator("main,[role=main]").first.wait_for(state="visible", timeout=15000)
                    await page.wait_for_timeout(750)
                except Exception as exc:
                    report["checks"].append({"profile": name, "route": route, "status": "INCONCLUSIVE",
                                             "reason": "Browser navigation unavailable", "error": str(exc), "failures": []})
                    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
                    continue
                await page.screenshot(path=str(output / f"{name}-{index}.png"), full_page=True)
                details = await page.evaluate(r"""() => ({
                  title: document.title, bodyText: document.body.innerText.slice(0, 500),
                  documentWidth: document.documentElement.scrollWidth, viewportWidth: innerWidth,
                  hasMain: !!document.querySelector('main,[role=main]'),
                  focusable: document.querySelectorAll('button,a[href],input,select,textarea,[tabindex="0"]').length,
                  reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
                  chromaticStyles: [...document.querySelectorAll('*')].flatMap(e => {
                    const s=getComputedStyle(e); return ['color','backgroundColor','borderColor','fill','stroke'].flatMap(k => {
                      const rgb=s[k].match(/^rgba?\((\d+),\s*(\d+),\s*(\d+)/);
                      if(!rgb) return []; const channels=rgb.slice(1).map(Number);
                      return Math.max(...channels)-Math.min(...channels)>12 ? [{tag:e.tagName,class:e.className,property:k,value:s[k]}] : [];
                    });
                  }).slice(0,30),
                  motionViolations: [...document.querySelectorAll('*')].filter(e => {
                    const s=getComputedStyle(e); return matchMedia('(prefers-reduced-motion: reduce)').matches &&
                      ((s.animationName !== 'none' && s.animationDuration.split(',').some(v=>parseFloat(v)>0.01)) ||
                       s.transitionDuration.split(',').some(v=>parseFloat(v)>0.1));
                  }).slice(0,20).map(e=>({tag:e.tagName,class:e.className}))
                })""")
                focus = []
                for _ in range(12):
                    await page.keyboard.press("Tab")
                    focus.append(await page.evaluate("""() => ({tag:document.activeElement.tagName,
                      text:(document.activeElement.getAttribute('aria-label')||document.activeElement.innerText||'').slice(0,70),
                      outline:getComputedStyle(document.activeElement).outlineStyle,
                      shadow:getComputedStyle(document.activeElement).boxShadow})"""))
                interactions = []
                command_button = page.get_by_role("button", name="打开命令面板")
                if await command_button.count():
                    await command_button.click()
                    await page.wait_for_timeout(250)
                    opened = await page.get_by_text("前往工作区", exact=True).count() > 0
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(250)
                    closed = await page.get_by_text("前往工作区", exact=True).count() == 0
                    interactions.append({"name": "command_panel_open_escape_close", "passed": opened and closed})
                menu_button = page.get_by_role("button", name="打开主导航")
                if width < 600 and await menu_button.count():
                    await menu_button.click()
                    await page.wait_for_timeout(300)
                    nav_box = await page.get_by_role("navigation", name="主导航", exact=True).bounding_box()
                    opened = bool(nav_box and nav_box["x"] >= 0)
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(300)
                    interactions.append({"name": "mobile_navigation_open_escape_close", "passed": opened})
                failures = []
                if response and response.status >= 400:
                    failures.append("http_error")
                if errors:
                    failures.append("javascript_error")
                if details["documentWidth"] > width + 1:
                    failures.append("horizontal_page_overflow")
                if not details["hasMain"]:
                    failures.append("missing_main_landmark")
                if details["focusable"] == 0:
                    failures.append("no_keyboard_controls")
                if reduced and details["motionViolations"]:
                    failures.append("reduced_motion_not_respected")
                if details["chromaticStyles"]:
                    failures.append("non_achromatic_palette")
                if any(not i["passed"] for i in interactions):
                    failures.append("navigation_interaction_failed")
                report["checks"].append({"profile": name, "route": route, "details": details,
                                         "keyboard_focus": focus, "page_errors": list(errors), "failures": failures,
                                         "interactions": interactions,
                                         "screenshot": f"{name}-{index}.png"})
                (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
            await context.close()
        await browser.close()
    report["status"] = "FAIL" if any(c["failures"] for c in report["checks"]) else "INCONCLUSIVE" if any(c.get("status") == "INCONCLUSIVE" for c in report["checks"]) else "PASS"
    report["gate_status"] = "INCONCLUSIVE"
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": report["status"], "gate_status": report["gate_status"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--routes", nargs="+", default=["/"])
    parser.add_argument("--output", required=True)
    parser.add_argument("--executable", default=None)
    parser.add_argument("--private-env", default=None)
    asyncio.run(run(parser.parse_args()))
