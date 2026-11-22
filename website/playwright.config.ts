import { defineConfig } from "@playwright/test";

// Browser checks run against the production server (`next start` on a fresh
// `next build`), never the dev server. Results and failure screenshots go to
// BROWSER_CHECK_OUT (default: the git-ignored test-results/ and
// playwright-report/ folders, which CI keeps as artifacts on failure).
const port = Number(process.env.WEBSITE_PORT ?? 3210);
const out = process.env.BROWSER_CHECK_OUT;

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
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    browserName: "chromium",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    reducedMotion: "no-preference",
    launchOptions: {
      // Software WebGL so the 3D viewer renders on machines without a GPU (CI).
      args: ["--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist"],
    },
  },
  webServer: {
    command: `node_modules/.bin/next start --hostname 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/robots.txt`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
