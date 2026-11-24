import type { Page } from "@playwright/test";
import { test, expect, remoteOrigin, vercelModeOrigin } from "./fixtures";

// W08 Vercel Web Analytics: mounted once in the root layout, only when the
// build runs on Vercel (VERCEL=1, the pages are prerendered). Locally the suite
// has two builds: the main one (no analytics at all) and a VERCEL=1 one, where the
// script must load on every page under the enforced Content-Security-Policy
// (the fixture fails on any violation). The script itself exists only on
// Vercel, so there it is a stand-in served at its real same-origin path.

const insights = "/_vercel/insights/";
const pages = ["/", "/install", "/what-it-detects"];

function watchInsights(page: Page) {
  const seen: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith(insights)) seen.push(path);
  });
  return seen;
}

test("a non-Vercel build loads no analytics script on any page", async ({ page }) => {
  test.skip(Boolean(remoteOrigin), "local build only: a deployment runs on Vercel");
  const seen = watchInsights(page);
  for (const path of pages) {
    await page.goto(path, { waitUntil: "networkidle" });
    await expect(page.locator(`script[src*="${insights}"]`)).toHaveCount(0);
  }
  expect(seen).toEqual([]);
});

test("on Vercel, every page loads the analytics script from its own origin, allowed by the CSP", async ({ page }) => {
  test.skip(!vercelModeOrigin, "local VERCEL=1 server; a deployment is checked by the next test");
  await page.route(`${vercelModeOrigin}${insights}script.js`, (route) =>
    route.fulfill({ contentType: "application/javascript", body: "window.__insightsRan = (window.__insightsRan || 0) + 1;" }),
  );
  const seen = watchInsights(page);
  for (const path of pages) {
    const response = await page.goto(`${vercelModeOrigin}${path}`);
    expect(response!.headers()["content-security-policy"]).toBeTruthy();
    await expect.poll(() => page.evaluate(() => (window as unknown as { __insightsRan?: number }).__insightsRan), { message: `${path}: script ran` }).toBe(1);
  }
  expect(seen).toEqual(pages.map(() => `${insights}script.js`));
});

test("a click on a link that leaves the site sends one outbound_click with its target and page, an internal link none", async ({ page }) => {
  test.skip(Boolean(remoteOrigin), "local build: the analytics queue is a stand-in");
  await page.addInitScript(() => {
    const w = window as unknown as { __va: unknown[]; va: (...a: unknown[]) => void };
    w.__va = [];
    w.va = (...a: unknown[]) => w.__va.push(a);
  });
  // The link opens a new tab; answer it locally so nothing leaves the test machine.
  await page.context().route("https://github.com/**", (route) => route.fulfill({ contentType: "text/html", body: "<title>stand-in</title>" }));
  await page.goto("/what-it-detects");
  const events = () => page.evaluate(() => (window as unknown as { __va: [string, { name: string; data: unknown }][] }).__va);

  // An on-site link that keeps the page (and its event queue): Back to top.
  await page.locator("footer").getByRole("link", { name: /Back to top/ }).click();
  expect(await events()).toEqual([]);

  const popup = page.waitForEvent("popup");
  await page.locator("footer").getByRole("link", { name: /^GitHub/ }).click();
  await (await popup).close();
  await expect.poll(events).toEqual([["event", { name: "outbound_click", data: { target: "repo", from: "/what-it-detects" } }]]);
});

test("a deployment serves the analytics script on every page", async ({ page }) => {
  test.skip(!remoteOrigin, "deployment check: set WEBSITE_URL");
  for (const path of pages) {
    const loaded = page.waitForResponse((response) => new URL(response.url()).pathname === `${insights}script.js`);
    await page.goto(path);
    const response = await loaded;
    expect(response.status(), `${path}: ${insights}script.js`).toBe(200);
  }
});
