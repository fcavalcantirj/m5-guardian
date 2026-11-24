#!/usr/bin/env node
// Mobile Lighthouse gate on the production build. Starts `next start`, runs
// the pinned Lighthouse CLI three times against it (a fresh headless Chromium
// each run), then requires the median of each gated value to meet the
// thresholds below. Exit 0 = pass, 1 = a threshold failed, 2 = setup error.
//
//   node scripts/lighthouse.mjs            (after `next build`)
//
// Every page in PAGES is gated on its own: three runs each, and each page's medians must meet the
// thresholds (W09 added /what-it-detects). Reports are <page>-run-<n>.report.{json,html}.
// Environment:
//   LIGHTHOUSE_OUT   output folder (default: website/lighthouse/, git-ignored)
//   LIGHTHOUSE_PORT  server port (default 3211)
//   CHROME_PATH      browser (default: Playwright's pinned Chromium)
//   LIGHTHOUSE_URL   audit this deployment (its origin, every page in PAGES) instead of a local `next start` (W05/W06: the
//                    gate is measured on the Vercel preview of the exact revision, the shipped
//                    artifact; same thresholds and the same simulated mobile method)
//   LIGHTHOUSE_BYPASS  Vercel "Protection Bypass for Automation" secret for a protected preview;
//                    sent only as the x-vercel-protection-bypass header, never written to the record
//   LIGHTHOUSE_PREVIEW=1  (with LIGHTHOUSE_URL) the URL is a Vercel preview: drop is-crawlable from the
//                    SEO score when its only blocking directive is the preview's x-robots-tag header
//                    (scripts/lighthouse-preview.mjs); recorded per run. Never set on production.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { previewSeo } from "./lighthouse-preview.mjs";

const site = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(process.env.LIGHTHOUSE_OUT ?? join(site, "lighthouse"));
const port = Number(process.env.LIGHTHOUSE_PORT ?? 3211);
const remote = process.env.LIGHTHOUSE_URL ? new URL(process.env.LIGHTHOUSE_URL).href : null;
const origin = remote ?? `http://127.0.0.1:${port}/`;
// The gated pages, each audited and judged on its own.
const PAGES = ["/", "/what-it-detects"];
const pageName = (path) => (path === "/" ? "home" : path.replace(/^\//, "").replace(/\//g, "-"));
const bypass = process.env.LIGHTHOUSE_BYPASS ?? "";
const preview = process.env.LIGHTHOUSE_PREVIEW === "1";
const RUNS = 3;

// Ledger W05: median performance >= 90, accessibility 100, SEO >= 95,
// LCP <= 2.5 s, CLS <= 0.1, TBT <= 200 ms.
const THRESHOLDS = {
  categories: { performance: 0.9, accessibility: 1, seo: 0.95 },
  audits: {
    "largest-contentful-paint": 2500,
    "cumulative-layout-shift": 0.1,
    "total-blocking-time": 200,
  },
};

// Lighthouse's default mobile profile, stated explicitly so the record shows
// it: emulated moto g power (412x823 at 1.75), simulated slow 4G and 4x CPU.
const CONFIG = {
  extends: "lighthouse:default",
  settings: {
    formFactor: "mobile",
    throttlingMethod: "simulate",
    screenEmulation: { mobile: true, width: 412, height: 823, deviceScaleFactor: 1.75, disabled: false },
    onlyCategories: ["performance", "accessibility", "best-practices", "seo"],
  },
};
if (bypass) CONFIG.settings.extraHeaders = { "x-vercel-protection-bypass": bypass, "x-vercel-set-bypass-cookie": "true" };

function die(message) {
  console.error(`lighthouse-check: ${message}`);
  process.exit(2);
}

/**
 * One warm-up request (not a measurement). A network error is retried: after a page's runs, a
 * kept-alive socket from the previous warm-up may already be closed by the server (ECONNRESET).
 */
async function warmUp(target, init) {
  for (let attempt = 1; ; attempt++) {
    try {
      await (await fetch(target, init)).arrayBuffer();
      return;
    } catch (error) {
      if (attempt === 3) die(`warm-up request to ${target} failed: ${error.cause?.code ?? error.message}`);
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

function portFree(p) {
  return new Promise((ok) => {
    const probe = createServer();
    probe.once("error", () => ok(false));
    probe.listen(p, "127.0.0.1", () => probe.close(() => ok(true)));
  });
}

async function waitFor(target, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try {
      if ((await fetch(target)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  die(`server did not answer at ${target}`);
}

async function chromePath() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const { chromium } = await import("@playwright/test");
  const path = chromium.executablePath();
  if (!existsSync(path)) die(`Chromium missing at ${path}: run pnpm exec playwright install chromium`);
  return path;
}

const pinned = JSON.parse(readFileSync(join(site, "package.json"), "utf8")).devDependencies.lighthouse;
const cli = join(site, "node_modules/.bin/lighthouse");
if (!existsSync(cli)) die("lighthouse is not installed: run pnpm install --frozen-lockfile");
const installed = spawnSync(cli, ["--version"], { encoding: "utf8" }).stdout.trim();
if (installed !== pinned) die(`lighthouse ${pinned} pinned, ${installed} installed`);
if (preview && !remote) die("LIGHTHOUSE_PREVIEW=1 needs LIGHTHOUSE_URL (a deployed preview)");
if (preview && new URL(remote).host === "m5-guardian.vercel.app") die("LIGHTHOUSE_PREVIEW=1 is refused on the production URL");
if (!remote && !existsSync(join(site, ".next/BUILD_ID"))) die("no production build: run next build first");
if (!remote && !(await portFree(port))) die(`port ${port} is busy; stop the process using it or set LIGHTHOUSE_PORT`);

mkdirSync(out, { recursive: true });
// The bypass secret reaches Lighthouse through its config, so the config, every report and any run
// error log carry it. Scrub them on every exit, including die() and a stop signal, so a failed run
// never leaves the secret in the folder CI uploads.
function scrubBypass() {
  if (!bypass || !existsSync(out)) return;
  for (const f of readdirSync(out)) {
    const path = join(out, f);
    if (!statSync(path).isFile()) continue;
    const text = readFileSync(path, "utf8");
    if (text.includes(bypass)) writeFileSync(path, text.split(bypass).join("<redacted>"));
  }
}
process.on("exit", scrubBypass);
process.on("SIGTERM", () => process.exit(143));

const configPath = join(out, "lighthouse.config.json");
writeFileSync(configPath, JSON.stringify(CONFIG, null, 2) + "\n");
const chrome = await chromePath();
const chromeFlags = "--headless=new --no-sandbox --disable-dev-shm-usage";

const serverLog = [];
const server = remote ? null : spawn(join(site, "node_modules/.bin/next"), ["start", "--hostname", "127.0.0.1", "--port", String(port)], {
  cwd: site,
  stdio: ["ignore", "pipe", "pipe"],
});
server?.stdout.on("data", (d) => serverLog.push(String(d)));
server?.stderr.on("data", (d) => serverLog.push(String(d)));
const stop = () => server && server.exitCode === null && server.kill("SIGTERM");
process.on("exit", stop);
process.on("SIGINT", () => process.exit(130));

const results = [];
try {
  const warm = bypass ? { headers: { "x-vercel-protection-bypass": bypass } } : {};
  if (!remote) await waitFor(new URL("/robots.txt", origin).href, 60_000);
  for (const path of PAGES) {
    const url = new URL(path, origin).href;
    const name = pageName(path);
    const runs = [];
    await warmUp(url, warm); // one warm-up request so the first audit does not pay server start-up or a cold CDN
    for (let i = 1; i <= RUNS; i++) {
      const base = join(out, `${name}-run-${i}`);
      const result = spawnSync(
        cli,
        [url, `--config-path=${configPath}`, "--output=json", "--output=html", `--output-path=${base}`, `--chrome-flags=${chromeFlags}`, "--quiet"],
        { cwd: site, env: { ...process.env, CHROME_PATH: chrome }, encoding: "utf8", timeout: 240_000 },
      );
      if (result.status !== 0) {
        writeFileSync(join(out, `${name}-run-${i}.error.log`), `${result.stdout}\n${result.stderr}`);
        die(`${path} run ${i} failed (exit ${result.status}); see ${name}-run-${i}.error.log`);
      }
      const lhr = JSON.parse(readFileSync(`${base}.report.json`, "utf8"));
      if (lhr.runtimeError) die(`${path} run ${i}: ${lhr.runtimeError.code} ${lhr.runtimeError.message}`);
      const run = {
        run: i,
        categories: Object.fromEntries(Object.entries(lhr.categories).map(([k, v]) => [k, v.score])),
        audits: Object.fromEntries(Object.keys(THRESHOLDS.audits).map((k) => [k, lhr.audits[k].numericValue])),
        runWarnings: lhr.runWarnings,
      };
      if (preview) {
        let adjustment;
        try {
          adjustment = previewSeo(lhr);
        } catch (error) {
          die(`${path} run ${i}: ${error.message}`);
        }
        if (adjustment) {
          run.categories.seo = adjustment.adjusted;
          run.previewSeoAdjustment = adjustment;
        }
      }
      runs.push({ ...run, lhr });
      console.log(`${path} run ${i}: ${JSON.stringify({ categories: run.categories, audits: run.audits })}`);
    }
    results.push({ path, url, runs });
  }
} finally {
  stop();
  writeFileSync(join(out, "server.log"), serverLog.join(""));
}

/** One page's medians and the thresholds they miss. */
function judge({ path, url, runs }) {
  const first = runs[0].lhr;
  const medians = {
    categories: Object.fromEntries(
      Object.keys(first.categories).map((k) => [k, median(runs.map((r) => r.categories[k]))]),
    ),
    audits: Object.fromEntries(Object.keys(THRESHOLDS.audits).map((k) => [k, median(runs.map((r) => r.audits[k]))])),
  };
  const failures = [
    ...Object.entries(THRESHOLDS.categories)
      .filter(([k, min]) => !(medians.categories[k] >= min))
      .map(([k, min]) => `${path}: ${k} median ${medians.categories[k]} < ${min}`),
    ...Object.entries(THRESHOLDS.audits)
      .filter(([k, max]) => !(medians.audits[k] <= max))
      .map(([k, max]) => `${path}: ${k} median ${medians.audits[k]} > ${max}`),
  ];
  return { path, url, runs: runs.map(({ lhr, ...rest }) => rest), medians, pass: failures.length === 0, failures };
}

const pages = results.map(judge);
const failures = pages.flatMap((page) => page.failures);
const first = results[0].runs[0].lhr;
const summary = {
  origin,
  lighthouseVersion: first.lighthouseVersion,
  userAgent: first.environment?.hostUserAgent,
  benchmarkIndex: results.flatMap((page) => page.runs.map((r) => r.lhr.environment?.benchmarkIndex)),
  chromeFlags,
  preview,
  configSettings: { ...first.configSettings, extraHeaders: bypass ? { "x-vercel-protection-bypass": "<redacted>" } : first.configSettings.extraHeaders },
  thresholds: THRESHOLDS,
  pages,
  pass: failures.length === 0,
  failures,
};
writeFileSync(join(out, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
scrubBypass();
for (const page of pages) console.log(`${page.path} median: ${JSON.stringify(page.medians)}`);
console.log(failures.length ? `lighthouse-check: FAIL\n  ${failures.join("\n  ")}` : "lighthouse-check: PASS");
process.exit(failures.length ? 1 : 0);
