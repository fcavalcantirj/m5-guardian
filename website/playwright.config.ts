import { defineConfig } from "@playwright/test";
import { bypassStatePath } from "./e2e/remote";

// Browser checks run against the production server (`next start` on a fresh
// `next build`), never the dev server. Results and failure screenshots go to
// BROWSER_CHECK_OUT (default: the git-ignored test-results/ and
// playwright-report/ folders, which CI keeps as artifacts on failure).
//
// W06: with WEBSITE_URL set, the same suite runs against that deployment (a
// Vercel preview or production) and no local server starts. For a protected
// preview, WEBSITE_BYPASS carries the project's Protection Bypass for
// Automation secret: e2e/remote-setup.ts trades it once for Vercel's bypass
// cookie on that host, so the secret itself never rides on page requests or
// reaches another host, and the cookie file lives in the OS temp folder.
const port = Number(process.env.WEBSITE_PORT ?? 3210);
const out = process.env.BROWSER_CHECK_OUT;
const remote = process.env.WEBSITE_URL ? new URL(process.env.WEBSITE_URL).origin : null;
const bypass = Boolean(remote && process.env.WEBSITE_BYPASS);

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // Software WebGL (SwiftShader) on a busy or GPU-less machine needs minutes for a 3D activation.
  timeout: 300_000,
  expect: { timeout: 15_000 },
  outputDir: out ? `${out}/test-results` : "test-results",
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: out ? `${out}/playwright-report` : "playwright-report" }],
    ["json", { outputFile: out ? `${out}/results.json` : "test-results/results.json" }],
  ],
  globalSetup: bypass ? "./e2e/remote-setup.ts" : undefined,
  use: {
    baseURL: remote ?? `http://127.0.0.1:${port}`,
    storageState: bypass ? bypassStatePath : undefined,
    browserName: "chromium",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    reducedMotion: "no-preference",
    launchOptions: {
      // Software WebGL so the 3D viewer renders on machines without a GPU (CI).
      args: ["--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist"],
    },
  },
  webServer: remote ? undefined : {
    command: `node_modules/.bin/next start --hostname 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/robots.txt`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
