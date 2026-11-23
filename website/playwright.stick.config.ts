import { defineConfig } from "@playwright/test";

// W07 OWNER-RUN real-stick smoke (not in CI, never run by an agent session): stick-smoke/stick.spec.ts drives the
// install page in the owner's installed Google Chrome (headed: Web Serial and its port picker need a real window)
// against a StickS3 on the cable. The environment and the steps are in the header of stick-smoke/stick.spec.ts.
const port = Number(process.env.WEBSITE_PORT ?? 3211);
const remote = process.env.STICK_SMOKE_URL ? new URL(process.env.STICK_SMOKE_URL).origin : null;
const out = process.env.STICK_SMOKE_OUT;

export default defineConfig({
  testDir: "./stick-smoke",
  workers: 1,
  retries: 0,
  timeout: 30 * 60_000,
  expect: { timeout: 15_000 },
  outputDir: out ? `${out}/test-results` : "test-results/stick-smoke",
  reporter: [["list"]],
  use: {
    baseURL: remote ?? `http://127.0.0.1:${port}`,
    browserName: "chromium",
    channel: "chrome",
    headless: false,
    acceptDownloads: true,
    trace: "retain-on-failure",
  },
  webServer: remote
    ? undefined
    : {
        command: `node_modules/.bin/next start --hostname 127.0.0.1 --port ${port}`,
        url: `http://127.0.0.1:${port}/robots.txt`,
        reuseExistingServer: false,
        timeout: 60_000,
      },
});
