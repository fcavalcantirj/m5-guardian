import { readFileSync } from "node:fs";
import { test, expect, remoteOrigin } from "./fixtures";
import { lastCommitDate, pageSources } from "../lib/last-modified";

// Response status, metadata, canonical link, social images, favicon, robots,
// sitemap, the custom 404, the configured headers and (W08) the JSON-LD and the
// Content-Security-Policy, all from `next start` (or WEBSITE_URL).

const siteUrl = "https://m5-guardian.vercel.app";
const configuredHeaders = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=63072000",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

const homeDescription =
  "M5StickS3 guard for your own Wi-Fi: receive-only monitoring, five rated faces for advertised settings, red or amber alerts. Open source; browser install.";
const releaseVersion = /^version=(\S+)$/m.exec(readFileSync(new URL("../../release/version.txt", import.meta.url), "utf8"))![1];

/**
 * The page's Content-Security-Policy (W08): enforced, a static header (the
 * pages stay prerendered), scripts from this origin plus Next's inline
 * bootstrap, nothing evaluated, no plugins, never framed. Returns the policy.
 */
function checkCsp(headers: Record<string, string>) {
  const policy = headers["content-security-policy"];
  expect(policy, "Content-Security-Policy header").toBeTruthy();
  expect(headers["content-security-policy-report-only"]).toBeUndefined();
  expect(policy).toMatch(/(?:^|; )script-src 'self' 'unsafe-inline'(?: https:\/\/vercel\.live)?(?:;|$)/);
  for (const directive of ["default-src 'self'", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'"])
    expect(policy).toContain(directive);
  expect(policy).not.toMatch(/unsafe-eval|nonce-/);
  return policy;
}

/** Width and height from a PNG's IHDR chunk. */
function pngSize(bytes: Buffer) {
  expect(bytes.subarray(1, 4).toString("latin1")).toBe("PNG");
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

/** The local path of an absolute site URL, so it can be fetched from this server. */
const local = (url: string) => {
  const parsed = new URL(url, siteUrl);
  expect(parsed.origin).toBe(siteUrl);
  return parsed.pathname + parsed.search;
};

test("home page: 200, configured headers, title, description and canonical link", async ({ page }) => {
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  const headers = response!.headers();
  for (const [name, value] of Object.entries(configuredHeaders)) expect(headers[name]).toBe(value);
  expect(headers["x-powered-by"]).toBeUndefined();

  await expect(page).toHaveTitle("M5 Guardian: Wi-Fi guard firmware for M5StickS3");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  // W08: no simulation sentence in the snippet; the page itself still says it is a simulation.
  await expect(page.locator('meta[name="description"]')).toHaveAttribute("content", homeDescription);
  await expect(page.getByText("This website is a simulation.", { exact: false }).first()).toBeVisible();
  // Next writes the root URL without its trailing slash; both spell the same URL.
  const canonical = page.locator('link[rel="canonical"]');
  await expect(canonical).toHaveCount(1);
  expect(new URL((await canonical.getAttribute("href"))!).href).toBe(`${siteUrl}/`);
  const ogUrl = await page.locator('meta[property="og:url"]').getAttribute("content");
  expect(new URL(ogUrl!).href).toBe(`${siteUrl}/`);
  await expect(page.locator('meta[name="viewport"]')).toHaveAttribute("content", /width=device-width/);
});

for (const { path, image } of [
  { path: "/", image: /^\/(opengraph|twitter)-image(\?|$)/ },
  { path: "/install", image: /^\/install\/(opengraph|twitter)-image(\?|$)/ },
  { path: "/what-it-detects", image: /^\/what-it-detects\/(opengraph|twitter)-image(\?|$)/ },
]) {
  test(`social cards of ${path}: its own 1200x630 PNG images, title and description`, async ({ page, request }) => {
    await page.goto(path);
    const title = await page.title();
    const description = await page.locator('meta[name="description"]').getAttribute("content");
    expect(description).toBeTruthy();
    for (const prefix of ["og", "twitter"]) {
      const attr = prefix === "og" ? "property" : "name";
      await expect(page.locator(`meta[${attr}="${prefix}:image"]`), `one ${prefix}:image`).toHaveCount(1);
      const url = await page.locator(`meta[${attr}="${prefix}:image"]`).getAttribute("content");
      expect(local(url!), `${prefix}:image belongs to ${path}`).toMatch(image);
      await expect(page.locator(`meta[${attr}="${prefix}:image:width"]`)).toHaveAttribute("content", "1200");
      await expect(page.locator(`meta[${attr}="${prefix}:image:height"]`)).toHaveAttribute("content", "630");
      await expect(page.locator(`meta[${attr}="${prefix}:image:alt"]`)).toHaveAttribute("content", /M5 Guardian/);
      const response = await request.get(local(url!));
      expect(response.status(), `${prefix} image status`).toBe(200);
      expect(response.headers()["content-type"]).toBe("image/png");
      expect(pngSize(await response.body())).toEqual({ width: 1200, height: 630 });
      // Each page's card speaks for that page.
      await expect(page.locator(`meta[${attr}="${prefix}:title"]`)).toHaveAttribute("content", title);
      await expect(page.locator(`meta[${attr}="${prefix}:description"]`)).toHaveAttribute("content", description!);
    }
    await expect(page.locator('meta[name="twitter:card"]')).toHaveAttribute("content", "summary_large_image");
    const ogUrl = await page.locator('meta[property="og:url"]').getAttribute("content");
    expect(new URL(ogUrl!).pathname).toBe(path);
  });
}

test("icons: favicon.ico (16/32/48), the SVG icon and the 180 px Apple touch icon are linked and served", async ({ page, request }) => {
  await page.goto("/");
  const icons = await page.locator('link[rel="icon"]').evaluateAll((links) =>
    links.map((link) => ({ href: link.getAttribute("href")!, sizes: link.getAttribute("sizes"), type: link.getAttribute("type") })),
  );
  const ico = icons.find((icon) => /^\/favicon\.ico/.test(icon.href));
  const svg = icons.find((icon) => /^\/icon\.svg/.test(icon.href));
  expect(ico, JSON.stringify(icons)).toBeTruthy();
  expect(svg, JSON.stringify(icons)).toBeTruthy();
  expect(svg!.type).toBe("image/svg+xml");

  // /favicon.ico itself (what browsers and crawlers ask for without a link) is a real icon file.
  for (const href of ["/favicon.ico", ico!.href]) {
    const response = await request.get(href);
    expect(response.status(), href).toBe(200);
    expect(response.headers()["content-type"]).toMatch(/image\/(x-icon|vnd\.microsoft\.icon)/);
    const bytes = await response.body();
    expect([bytes.readUInt16LE(0), bytes.readUInt16LE(2)]).toEqual([0, 1]);
    expect(Array.from({ length: bytes.readUInt16LE(4) }, (_, i) => bytes[6 + 16 * i])).toEqual([16, 32, 48]);
  }
  const svgResponse = await request.get(svg!.href);
  expect(svgResponse.status()).toBe(200);
  expect(svgResponse.headers()["content-type"]).toContain("image/svg+xml");
  expect((await svgResponse.text()).trim()).toMatch(/^<svg[\s>]/);

  const apple = page.locator('link[rel="apple-touch-icon"]');
  await expect(apple).toHaveCount(1);
  await expect(apple).toHaveAttribute("sizes", "180x180");
  const appleResponse = await request.get((await apple.getAttribute("href"))!);
  expect(appleResponse.status()).toBe(200);
  expect(appleResponse.headers()["content-type"]).toBe("image/png");
  expect(pngSize(await appleResponse.body())).toEqual({ width: 180, height: 180 });
});

test("structured data: one JSON-LD block with WebSite and SoftwareApplication, version from release/version.txt", async ({ page }) => {
  for (const path of ["/", "/install", "/what-it-detects"]) {
    await page.goto(path);
    const blocks = await page.locator('script[type="application/ld+json"]').allTextContents();
    expect(blocks, path).toHaveLength(1);
    const data = JSON.parse(blocks[0]);
    expect(data["@context"]).toBe("https://schema.org");
    const [website, app] = data["@graph"];
    expect(website).toMatchObject({ "@type": "WebSite", name: "M5 Guardian", url: `${siteUrl}/` });
    expect(app).toMatchObject({
      "@type": "SoftwareApplication",
      name: "M5 Guardian",
      applicationCategory: "SecurityApplication",
      operatingSystem: "ESP32-S3 firmware (M5Stack StickS3)",
      license: "https://github.com/fcavalcantirj/m5-guardian/blob/main/LICENSE",
      sameAs: ["https://github.com/fcavalcantirj/m5-guardian"],
      isAccessibleForFree: true,
      offers: { "@type": "Offer", price: "0" },
      softwareVersion: releaseVersion,
      downloadUrl: `${siteUrl}/install`,
    });
    expect(JSON.stringify(data)).not.toMatch(/aggregateRating|"review"/);
  }
});

test("Content-Security-Policy: the same enforced policy on every page, and the pages stay prerendered", async ({ request }) => {
  const policies = new Set<string>();
  for (const path of ["/", "/install", "/what-it-detects", "/", "/no-such-page"]) {
    const response = await request.get(path);
    expect(response.status()).toBe(path === "/no-such-page" ? 404 : 200);
    policies.add(checkCsp(response.headers()));
    if (path !== "/no-such-page")
      expect(response.headers()["cache-control"] ?? "", `${path} is not rendered per request`).not.toMatch(/private|no-store/);
  }
  expect(policies.size, "one static policy").toBe(1);
});

test("robots.txt allows crawling and names the sitemap", async ({ request }) => {
  const response = await request.get("/robots.txt");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("text/plain");
  const text = await response.text();
  expect(text).toMatch(/User-Agent: \*/i);
  expect(text).toMatch(/Allow: \//);
  expect(text).not.toMatch(/Disallow: \/\s*$/m);
  expect(text).toContain(`Sitemap: ${siteUrl}/sitemap.xml`);
});

test("sitemap.xml lists the home, install and what-it-detects pages, each with its last source commit date", async ({ request }) => {
  const response = await request.get("/sitemap.xml");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("xml");
  const text = await response.text();
  expect(text.match(/<url>/g)).toHaveLength(3);
  const site = new URL("..", import.meta.url).pathname;
  for (const [path, loc] of [
    ["/", `${siteUrl}/`],
    ["/install", `${siteUrl}/install`],
    ["/what-it-detects", `${siteUrl}/what-it-detects`],
  ] as const) {
    const entry = text.split("<url>").find((block) => block.includes(`<loc>${loc}</loc>`));
    expect(entry, loc).toBeTruthy();
    const lastmod = /<lastmod>([^<]+)<\/lastmod>/.exec(entry!)?.[1];
    if (remoteOrigin) {
      // A Git deployment knows the dates; a CLI upload has no .git and leaves them out (lib/last-modified.ts).
      if (lastmod) expect(new Date(lastmod).getTime()).toBeLessThanOrEqual(Date.now());
      else test.info().annotations.push({ type: "note", description: `${loc}: no lastmod (no Git history in this build)` });
    } else {
      // The local build reads this checkout's history: the dates must be exactly Git's, and a page whose last
      // change is outside a shallow clone has no lastmod rather than a wrong one (lib/last-modified.ts).
      const expected = lastCommitDate(pageSources[path], site);
      expect(lastmod, `${loc} lastmod`).toBe(expected?.toISOString());
    }
  }
});

test("unknown paths get the custom 404 page with status 404, noindex and headers", async ({ page, browserLog }) => {
  const response = await page.goto("/no-such-page");
  // Chrome logs the document's own 404 status; that one line is expected here. Over HTTP/2 (a deployment)
  // there is no reason phrase, so Chrome prints "404 ()"; locally (HTTP/1.1) it is "404 (Not Found)".
  const expected = /^console\.error: Failed to load resource: the server responded with a status of 404 \((?:Not Found)?\)$/;
  expect(browserLog.filter((line) => expected.test(line))).toHaveLength(1);
  browserLog.splice(browserLog.findIndex((line) => expected.test(line)), 1);
  expect(response?.status()).toBe(404);
  const headers = response!.headers();
  for (const [name, value] of Object.entries(configuredHeaders)) expect(headers[name]).toBe(value);
  checkCsp(headers);
  await expect(page).toHaveTitle("Page not found | M5 Guardian");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Nothing heard at this address.");
  const robots = page.locator('meta[name="robots"]');
  expect(await robots.count()).toBeGreaterThan(0);
  for (const content of await robots.evaluateAll((els) => els.map((el) => el.getAttribute("content"))))
    expect(content).toMatch(/noindex/);
  await expect(page.locator('link[rel="canonical"]')).toHaveCount(0);
  await expect(page.locator('meta[property="og:url"]')).toHaveCount(0);
  await page.getByRole("link", { name: /Back to the home page/ }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Your Wi-Fi");
});

test("public assets the page relies on are served", async ({ request }) => {
  for (const path of [
    "/images/LICENSE",
    "/models/NOTICE.txt",
    "/images/very-good.png",
    "/images/very-good-alert.png",
  ]) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(200);
  }
});

test("a full page load and scroll logs no errors or hydration failures", async ({ page }) => {
  const failed: string[] = [];
  page.on("response", (response) => {
    if (response.status() >= 400) failed.push(`${response.status()} ${response.url()}`);
  });
  page.on("requestfailed", (request) => failed.push(`failed ${request.url()}`));
  await page.goto("/", { waitUntil: "networkidle" });
  await page.evaluate(async () => {
    for (let y = 0; y < document.body.scrollHeight; y += 600) {
      window.scrollTo(0, y);
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  });
  await page.waitForLoadState("networkidle");
  expect(failed).toEqual([]);
  // browserLog (auto fixture) asserts no console errors and no hydration messages.
});
