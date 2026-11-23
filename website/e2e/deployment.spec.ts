import { test, expect, remoteOrigin } from "./fixtures";

// W06 deployment checks. They run only against a deployment (WEBSITE_URL):
// the GitHub links must reach the public repository (and the README section
// a fragment names), and production must be indexable with its canonical URL.
// Locally they are skipped: a pull request may add a link to a file that only
// exists on GitHub once it merges.

const productionOrigin = "https://m5-guardian.vercel.app";

test("every GitHub link on the page resolves, including README section anchors", async ({ page, request }) => {
  test.skip(!remoteOrigin, "deployment check: set WEBSITE_URL");
  await page.goto("/");
  const hrefs = await page
    .locator('a[href^="https://github.com/"]')
    .evaluateAll((links) => links.map((link) => (link as HTMLAnchorElement).href));
  const unique = [...new Set(hrefs)].sort();
  expect(unique.length, "the page links to the repository").toBeGreaterThan(3);
  const pages = new Map<string, string>();
  for (const href of unique) {
    const url = new URL(href);
    const fragment = decodeURIComponent(url.hash.slice(1));
    url.hash = "";
    if (!pages.has(url.href)) {
      const response = await request.get(url.href);
      expect(response.status(), url.href).toBe(200);
      pages.set(url.href, await response.text());
    }
    if (fragment) expect(pages.get(url.href), `${href}: section exists`).toContain(`user-content-${fragment}`);
  }
});

test("production is indexable at its canonical URL", async ({ page }) => {
  test.skip(remoteOrigin !== productionOrigin, `production check: set WEBSITE_URL=${productionOrigin}`);
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  expect(response!.headers()["x-robots-tag"] ?? "", "no noindex header").not.toMatch(/noindex/i);
  for (const content of await page.locator('meta[name="robots"]').evaluateAll((els) => els.map((el) => el.getAttribute("content"))))
    expect(content ?? "").not.toMatch(/noindex/i);
  expect(new URL((await page.locator('link[rel="canonical"]').getAttribute("href"))!).href).toBe(`${productionOrigin}/`);
  await expect(page).toHaveTitle("M5 Guardian: your Wi-Fi, under watch");
});
