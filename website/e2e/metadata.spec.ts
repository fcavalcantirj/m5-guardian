import { test, expect } from "./fixtures";

// Response status, metadata, canonical link, social images, favicon, robots,
// sitemap, the custom 404 and the configured headers, all from `next start`.

const siteUrl = "https://m5-guardian.vercel.app";
const configuredHeaders = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=63072000",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

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

  await expect(page).toHaveTitle("M5 Guardian: your Wi-Fi, under watch");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.locator('meta[name="description"]')).toHaveAttribute("content", /simulation/);
  // Next writes the root URL without its trailing slash; both spell the same URL.
  const canonical = page.locator('link[rel="canonical"]');
  await expect(canonical).toHaveCount(1);
  expect(new URL((await canonical.getAttribute("href"))!).href).toBe(`${siteUrl}/`);
  const ogUrl = await page.locator('meta[property="og:url"]').getAttribute("content");
  expect(new URL(ogUrl!).href).toBe(`${siteUrl}/`);
  await expect(page.locator('meta[name="viewport"]')).toHaveAttribute("content", /width=device-width/);
});

test("social images: Open Graph and Twitter cards are 1200x630 PNGs that load", async ({ page, request }) => {
  await page.goto("/");
  for (const prefix of ["og", "twitter"]) {
    const attr = prefix === "og" ? "property" : "name";
    const image = await page.locator(`meta[${attr}="${prefix}:image"]`).getAttribute("content");
    expect(image, `${prefix}:image`).toBeTruthy();
    await expect(page.locator(`meta[${attr}="${prefix}:image:width"]`)).toHaveAttribute("content", "1200");
    await expect(page.locator(`meta[${attr}="${prefix}:image:height"]`)).toHaveAttribute("content", "630");
    await expect(page.locator(`meta[${attr}="${prefix}:image:alt"]`)).toHaveAttribute("content", /M5 Guardian/);
    const response = await request.get(local(image!));
    expect(response.status(), `${prefix} image status`).toBe(200);
    expect(response.headers()["content-type"]).toBe("image/png");
    expect(pngSize(await response.body())).toEqual({ width: 1200, height: 630 });
  }
  await expect(page.locator('meta[name="twitter:card"]')).toHaveAttribute("content", "summary_large_image");
  await expect(page.locator('meta[property="og:title"]')).toHaveAttribute("content", "M5 Guardian: your Wi-Fi, under watch");
});

test("favicon is linked and served as SVG", async ({ page, request }) => {
  await page.goto("/");
  const href = await page.locator('link[rel="icon"]').first().getAttribute("href");
  expect(href).toMatch(/^\/icon\.svg/);
  const response = await request.get(href!);
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("image/svg+xml");
  expect((await response.text()).trim()).toMatch(/^<svg[\s>]/);
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

test("sitemap.xml lists the home page", async ({ request }) => {
  const response = await request.get("/sitemap.xml");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("xml");
  const text = await response.text();
  expect(text).toContain(`<loc>${siteUrl}/</loc>`);
  expect(text.match(/<url>/g)).toHaveLength(1);
});

test("unknown paths get the custom 404 page with status 404, noindex and headers", async ({ page, browserLog }) => {
  const response = await page.goto("/no-such-page");
  // Chrome logs the document's own 404 status; that one line is expected here.
  const expected = "console.error: Failed to load resource: the server responded with a status of 404 (Not Found)";
  expect(browserLog.filter((line) => line === expected)).toHaveLength(1);
  browserLog.splice(browserLog.indexOf(expected), 1);
  expect(response?.status()).toBe(404);
  const headers = response!.headers();
  for (const [name, value] of Object.entries(configuredHeaders)) expect(headers[name]).toBe(value);
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
