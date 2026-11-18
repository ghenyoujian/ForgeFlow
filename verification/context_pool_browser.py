#!/usr/bin/env python3
"""Actual isolated console checks for context population, active limit and responsive navigation."""
import argparse
import asyncio
import json
from pathlib import Path


async def run(a):
    from playwright.async_api import async_playwright
    state=json.loads(a.environment.read_text()); secret=json.loads(a.private_env.read_text())
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    results=[]
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path=a.executable)
        try:
            for name,width,height,reduced in (("desktop",1440,1000,False),("mobile",390,844,False),("reduced-motion",1440,1000,True)):
                context=await browser.new_context(viewport={"width":width,"height":height},reduced_motion="reduce" if reduced else "no-preference")
                await context.add_init_script("sessionStorage.setItem('forgeflow.owner-token',"+json.dumps(secret["FORGEFLOW_OWNER_TOKEN"])+");")
                page=await context.new_page(); page.set_default_timeout(15000)
                errors=[];failed_api=[];mutations=[]
                page.on("pageerror",lambda e:errors.append(str(e)))
                page.on("response",lambda r:failed_api.append({"status":r.status,"url":r.url}) if "/api/v1/" in r.url and r.status>=400 else None)
                page.on("request",lambda r:mutations.append(r.url) if r.method not in ("GET","HEAD","OPTIONS") else None)
                response=await page.goto(state["api_url"]+f"/projects/{state['project_id']}/teams",wait_until="domcontentloaded")
                await page.get_by_text("已持久化 128 个独立上下文。",exact=False).wait_for()
                await page.get_by_text("活跃上限 32",exact=True).wait_for()
                await page.get_by_text("128 / 128",exact=True).wait_for()
                await page.get_by_text("R1 · COMMITTED",exact=True).wait_for()
                await page.get_by_text("当前 RUNNING 尝试 0",exact=False).wait_for()
                assert response.status==200
                assert await page.get_by_text("2,884",exact=False).count()==0
                assert await page.get_by_role("link",name="在 DSH 操作面板中开发").count()==0
                assert await page.get_by_role("alert").count()==0
                await page.screenshot(path=str(a.output/(name+"-overview.png")),full_page=True)
                await page.locator('section[aria-label="独立 Agent 上下文"]').scroll_into_view_if_needed()
                await page.screenshot(path=str(a.output/(name+"-context.png")),full_page=True)
                details=await page.evaluate("""() => ({width:innerWidth,documentWidth:document.documentElement.scrollWidth,
                    mainWidth:document.querySelector('main').getBoundingClientRect().width,
                    nonGray:[...document.querySelectorAll('*')].flatMap(e=>['color','backgroundColor'].flatMap(k=>{
                      const v=getComputedStyle(e)[k],m=v.match(/^rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);if(!m)return[];
                      const n=m.slice(1).map(Number);return Math.max(...n)-Math.min(...n)>12?[{tag:e.tagName,value:v}]:[];})).slice(0,10)})""")
                assert details["documentWidth"]<=width+1,details
                assert not details["nonGray"],details
                await page.get_by_role("tab",name="全量任务卡",exact=True).click()
                search=page.get_by_placeholder("搜索卡号、功能、Owner 或父任务")
                await search.fill("activate-context-0128")
                await page.get_by_role("button",name="打开 activate-context-0128 详情",exact=True).click()
                dialog=page.get_by_role("dialog")
                await dialog.wait_for()
                assert "activate-context-0128" in await dialog.inner_text()
                await page.get_by_role("button",name="关闭检查器",exact=True).click()
                assert await page.get_by_role("dialog").count()==0
                await search.fill("")
                await page.get_by_role("tab",name="岗位名册",exact=True).click()
                await page.get_by_text("128 个实际登记岗位",exact=True).wait_for()
                assert await page.locator("article.delivery-role").count()==128
                if width<600:
                    await page.get_by_role("button",name="打开主导航").click()
                    navigation=page.get_by_role("dialog",name="工作空间导航")
                    await navigation.wait_for()
                    await page.keyboard.press("Escape")
                    await navigation.wait_for(state="hidden")
                await page.get_by_role("tab",name="交付链路",exact=True).click()
                await page.keyboard.press("Tab")
                focused=await page.evaluate("document.activeElement.tagName")
                assert focused!="BODY"
                assert not errors,errors
                assert not failed_api,failed_api
                assert not mutations,mutations
                results.append({"profile":name,"status":"PASS","checks":["128persisted contexts", "cap32", "128cards", "committedFlow", "no legacy count/launch", "no alerts", "grayscale", "no page overflow", "card search/details", "128role identities", "keyboard", "mobile dialog" if width<600 else "desktop"],"details":details,"javascript_errors":errors,"failed_api":failed_api,"mutations":mutations})
                (a.output/"report.json").write_text(json.dumps({"status":"RUNNING","checks":results},ensure_ascii=False,indent=2)+"\n")
                await context.close()
        finally: await browser.close()
    report={"status":"PASS_SCOPED_BROWSER_CONTEXT_POOL","checks":results,"models_started":0,"g20":"NOT_RUN","scope":"Real console against dedicated PostgreSQL/Core; no response mocking"}
    (a.output/"report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"status":report["status"],"profiles":len(results),"models_started":0}))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("environment","private-env","output"):p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--executable",required=True)
    asyncio.run(run(p.parse_args()))
