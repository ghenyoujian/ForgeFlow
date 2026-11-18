// Fixed Chromium profile; each cold sample owns a fresh browser context/cache.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require('/home/chenyoujian/miniconda/lib/python3.13/site-packages/playwright/driver/package');
const output = path.resolve(process.argv[2]);
const run = JSON.parse(fs.readFileSync(path.join(output, 'private.json'), 'utf8'));
const sampleCount = Number(process.argv[3] ?? 12);
const browser = await chromium.launch({ executablePath: '/home/chenyoujian/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome', headless: true, args: ['--no-proxy-server'] });
const profile = { chromium: browser.version(), viewport: '1440x1000', timezone: 'Asia/Shanghai', reduced_motion: true, cpu: os.cpus()[0].model, logical_cpus: os.cpus().length, memory_gib: Math.round(os.totalmem() / 1073741824), deployment: 'isolated debug Rust server; static assets copied to Linux filesystem' };
const pages = [
  ['overview', '/projects/p00', '[aria-label="项目规划总览"] .planning-summary-card strong', '总览'],
  ['planning', '/projects/p00/flows', '.virtual-task-row', '规划'],
  ['team', '/projects/p00/teams', '[aria-label="团队任务范围"]', 'Agent 团队'],
  ['schedule', '/projects/p00/schedule', '[aria-label="情景容量范围"]', '排程'],
];
const results = {};
const summarize = samples => ({ samples: samples.length, p50_ms: Math.round([...samples].sort((a,b) => a-b)[Math.floor(samples.length / 2)]), p95_ms: Math.round([...samples].sort((a,b) => a-b)[Math.ceil(samples.length * .95) - 1]), raw_ms: samples.map(Math.round) });
async function makeContext() {
  const context = await browser.newContext({ viewport: { width:1440, height:1000 }, timezoneId: 'Asia/Shanghai', reducedMotion: 'reduce' });
  await context.addInitScript(token => { sessionStorage.setItem('forgeflow.owner-token', token); localStorage.setItem('forgeflow.planning-workbench', '1'); }, run.token);
  return context;
}
try {
  for (const [name, route, selector] of pages) {
    const cold = [];
    for (let i = 0; i < sampleCount; i++) {
      const context = await makeContext(); const page = await context.newPage();
      const started = performance.now(); await page.goto(run.base + route, { waitUntil: 'domcontentloaded' }); await page.locator(selector).first().waitFor({ timeout: 45000 });
      cold.push(performance.now() - started); await context.close();
    }
    results[name] = { cold: summarize(cold) };
    console.log(JSON.stringify({ page: name, cold: results[name].cold }));
  }
  const context = await makeContext(); const page = await context.newPage();
  await page.goto(run.base + '/projects/p00', { waitUntil: 'domcontentloaded' });
  for (const [, , selector, label] of pages) { await page.getByRole('navigation', { name:'项目核心导航' }).getByRole('link', { name:label, exact:true }).click(); await page.locator(selector).first().waitFor(); }
  const samples = Object.fromEntries(pages.map(([name]) => [name, []]));
  for (let i = 0; i < sampleCount; i++) for (const [name, , selector, label] of pages) {
    const started = performance.now(); await page.getByRole('navigation', { name:'项目核心导航' }).getByRole('link', { name:label, exact:true }).click(); await page.locator(selector).first().waitFor(); samples[name].push(performance.now() - started);
  }
  for (const [name] of pages) results[name].cached = summarize(samples[name]);
  // Browser render feedback after a view switch, excluding automation transport time.
  await page.getByRole('navigation', { name:'项目核心导航' }).getByRole('link', { name:'规划', exact:true }).click(); await page.locator('.virtual-task-row').first().waitFor();
  const interaction = [];
  for (let i = 0; i < 20; i++) interaction.push(await page.evaluate(async i => {
    const button = [...document.querySelectorAll('.planning-view-toolbar button')].find(button => button.textContent === (i % 2 ? '任务表' : '看板'));
    const start = performance.now(); button.click(); await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); return performance.now() - start;
  }, i));
  results.interaction = summarize(interaction); await context.close();
} finally {
  const targets = Object.fromEntries(pages.map(([name]) => [name, { cold_p95_under_2500: results[name]?.cold?.p95_ms <= 2500, cached_p95_under_1200: results[name]?.cached?.p95_ms <= 1200 }]));
  const report = { status: Object.values(targets).every(t => Object.values(t).every(Boolean)) && results.interaction?.p95_ms <= 150 ? 'PASS' : 'TARGETS_NOT_ALL_MET', profile, sample_count: sampleCount, synthetic_only:true, real_model_calls:0, results, targets };
  fs.writeFileSync(path.join(output, 'browser-performance.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ status:report.status, targets, interaction:results.interaction })); await browser.close();
}
