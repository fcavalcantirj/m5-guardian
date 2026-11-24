import AxeBuilder from "@axe-core/playwright";
import type { Page, Route } from "@playwright/test";
import { test, expect } from "./fixtures";

// W07 install page in Chromium (Playwright's bundled build) against the production server. The signed release is
// served by a mocked /api/firmware/latest (the route itself is unit-tested with a mocked GitHub), and Web Serial is
// a fake (no device is touched): what is checked is the page's behaviour up to the port, the honest messages, the
// analytics payloads, accessibility, layout, and that esptool-js loads only after a click. Flashing a real stick is
// the owner-run smoke in stick-smoke/ (not in CI).

const sha = (c: string) => c.repeat(64);
const release = {
  tag: "guardian-1.0.0-b1-cccccccccccc",
  version: "1.0.0",
  build: 1,
  date: "2026-11-23",
  notes: "First public image.",
  parts: [
    ["bootloader.bin", 0x0, 21_000, "a"],
    ["partition-table.bin", 0x8000, 3072, "b"],
    ["ota_data_initial.bin", 0x10000, 8192, "d"],
    ["guardian_sticks3-signed.bin", 0x20000, 1_958_849, "c"],
  ].map(([file, offset, size, c]) => ({ file, offset, size, sha256: sha(c as string), url: `/api/firmware/guardian-1.0.0-b1-cccccccccccc/${file}` })),
};

async function mockRelease(page: Page, answer: "ok" | "none" = "ok") {
  await page.route("**/api/firmware/latest", (route: Route) =>
    answer === "ok"
      ? route.fulfill({ json: release })
      : route.fulfill({ status: 404, json: { kind: "no-release", error: "No release has been published yet. The install page will offer it as soon as the first signed release is out." } }),
  );
}

/** A Web Serial stand-in: `cancel` closes the picker; `busy` hands a port whose open() fails like a port in use. */
async function fakeSerial(page: Page, mode: "cancel" | "busy") {
  await page.addInitScript((mode) => {
    const w = window as unknown as { __serial: unknown[]; __va: unknown[]; va: (...a: unknown[]) => void };
    w.__serial = [];
    w.__va = [];
    w.va = (...a: unknown[]) => w.__va.push(a);
    const port = {
      getInfo: () => ({ usbVendorId: 0x303a, usbProductId: 0x1001 }),
      open: async () => {
        w.__serial.push("open");
        throw new DOMException("Failed to execute 'open' on 'SerialPort': Failed to open serial port.", "NetworkError");
      },
      close: async () => void w.__serial.push("close"),
      setSignals: async () => {},
      addEventListener() {},
      removeEventListener() {},
      readable: null,
      writable: null,
    };
    const serial = {
      requestPort: async (options: unknown) => {
        w.__serial.push(options);
        if (mode === "cancel") throw new DOMException("No port selected by the user.", "NotFoundError");
        return port;
      },
      getPorts: async () => [],
      addEventListener() {},
      removeEventListener() {},
    };
    Object.defineProperty(Navigator.prototype, "serial", { configurable: true, get: () => serial });
  }, mode);
}

/** Records every script whose body carries esptool-js (text only its loader has). */
function watchEsptool(page: Page) {
  const seen: string[] = [];
  page.on("response", async (response) => {
    if (response.request().resourceType() !== "script") return;
    const body = await response.text().catch(() => "");
    if (body.includes("Detecting chip type")) seen.push(response.url());
  });
  return seen;
}

test("the hero and the footer link to /install", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator(".hero-actions").getByRole("link", { name: "Install on your StickS3" })).toHaveAttribute("href", "/install");
  await expect(page.locator(".site-footer").getByRole("link", { name: "Install on your StickS3" })).toHaveAttribute("href", "/install");
});

test("the install page shows the signed release, the steps and its own canonical URL", async ({ page }) => {
  await mockRelease(page);
  await page.goto("/install");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Put the Guardian on your own StickS3.");
  await expect(page.locator('link[rel="canonical"]')).toHaveAttribute("href", /\/install$/);
  await expect(page.getByTestId("flasher-release")).toContainText("1.0.0");
  await expect(page.getByTestId("flasher-release")).toContainText("build 1, published 2026-11-23");
  await expect(page.getByTestId("flasher-button")).toHaveText("Connect and update to 1.0.0");
  await expect(page.getByTestId("flasher-button")).toBeEnabled();
  await expect(page.locator(".install-lead")).toContainText("it does not connect to or protect your network");
  // Header links go back to the home page sections.
  await expect(page.locator(".desktop-nav a").first()).toHaveAttribute("href", "/#guardian");
});

test("esptool-js loads only after a click; a port in use gets a plain message and only step counts", async ({ page }) => {
  await mockRelease(page);
  await fakeSerial(page, "busy");
  const esptool = watchEsptool(page);
  await page.goto("/install");
  await expect(page.getByTestId("flasher-button")).toBeEnabled();
  await page.waitForLoadState("networkidle");
  expect(esptool, "no esptool-js script before the click").toEqual([]);
  await page.getByTestId("flasher-button").click();
  await expect(page.getByTestId("flasher-error")).toContainText("could not be opened");
  await expect.poll(() => esptool.length, { message: "esptool-js loaded after the click" }).toBeGreaterThan(0);
  const calls = await page.evaluate(() => (window as unknown as { __serial: unknown[] }).__serial);
  expect(calls[0]).toEqual({ filters: [{ usbVendorId: 0x303a }] });
  const events = await page.evaluate(() => (window as unknown as { __va: [string, { name: string; data: unknown }][] }).__va);
  expect(events.map(([, e]) => e.name)).toEqual(["guardian_install", "guardian_install"]);
  expect(events.map(([, e]) => e.data)).toEqual([
    { action: "update", result: "start", step: "update:start" },
    { action: "update", result: "error_connecting", step: "update:error_connecting" },
  ]);
});

test("closing the port picker is not an error: the download-mode hint appears", async ({ page }) => {
  await mockRelease(page);
  await fakeSerial(page, "cancel");
  await page.goto("/install");
  await page.getByTestId("flasher-button").click();
  await expect(page.getByTestId("flasher-picker-hint")).toContainText("hold the small button on the side");
  await expect(page.getByTestId("flasher-error")).toHaveCount(0);
});

test("First install offers the backup and needs two confirmations before erasing", async ({ page }) => {
  await mockRelease(page);
  await fakeSerial(page, "cancel");
  await page.goto("/install");
  await page.getByRole("radio", { name: /First install/ }).check();
  await expect(page.getByTestId("flasher-backup-button")).toHaveText("Download a backup of what is on the stick now");
  await expect(page.getByTestId("flasher-backup")).toContainText("Restore a backup");
  const main = page.getByTestId("flasher-button");
  await expect(main).toHaveText("Connect, erase and install 1.0.0");
  await expect(main).toBeDisabled();
  await page.getByRole("checkbox", { name: /the whole stick is erased/ }).check();
  await main.click();
  const confirm = page.getByTestId("flasher-confirm");
  await expect(confirm).toContainText("erase the whole stick");
  expect(await page.evaluate(() => (window as unknown as { __serial: unknown[] }).__serial), "nothing asked of the port yet").toEqual([]);
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await expect(main).toBeVisible();
  await main.click();
  await page.getByTestId("flasher-confirm-yes").click();
  await expect(page.getByTestId("flasher-picker-hint")).toBeVisible();
  const events = await page.evaluate(() => (window as unknown as { __va: [string, { data: unknown }][] }).__va.map(([, e]) => e.data));
  expect(events).toEqual([
    { action: "install", result: "start", step: "install:start" },
    { action: "install", result: "cancel", step: "install:cancel" },
  ]);
});

test("Restore accepts only a whole 8 MB backup, shows its SHA-256 and confirms twice", async ({ page }) => {
  await mockRelease(page);
  await fakeSerial(page, "cancel");
  await page.goto("/install");
  await page.getByRole("radio", { name: /Restore a backup/ }).check();
  const file = page.getByTestId("flasher-restore-file");
  await file.setInputFiles({ name: "short.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(1024, 0xe9) });
  await expect(page.getByTestId("flasher-restore-info")).toContainText("exactly 8,388,608 bytes");
  await page.getByRole("checkbox", { name: /replaced by this backup/ }).check();
  await expect(page.getByTestId("flasher-button")).toBeDisabled();
  const image = Buffer.alloc(8 * 1024 * 1024, 0xff);
  image[0] = 0xe9;
  const { createHash } = await import("node:crypto");
  await file.setInputFiles({ name: "sticks3-backup.bin", mimeType: "application/octet-stream", buffer: image });
  await expect(page.getByTestId("flasher-restore-info")).toContainText(createHash("sha256").update(image).digest("hex"));
  await page.getByRole("checkbox", { name: /replaced by this backup/ }).check();
  await page.getByTestId("flasher-button").click();
  await expect(page.getByTestId("flasher-confirm")).toContainText("replace everything on the stick with this backup");
});

test("no published release yet is said plainly and nothing can be installed", async ({ page, browserLog }) => {
  await mockRelease(page, "none");
  await fakeSerial(page, "cancel");
  await page.goto("/install");
  await expect(page.getByTestId("flasher-loading")).toContainText("No release has been published yet");
  await expect(page.getByTestId("flasher-button")).toBeDisabled();
  // Restore still works without a release.
  await page.getByRole("radio", { name: /Restore a backup/ }).check();
  await expect(page.getByTestId("flasher-restore-file")).toBeEnabled();
  // Chrome logs the 404 of the mocked latest answer; that one line is expected here.
  const expected = "console.error: Failed to load resource: the server responded with a status of 404 (Not Found)";
  await expect.poll(() => browserLog.filter((line) => line === expected).length).toBe(1);
  browserLog.splice(browserLog.indexOf(expected), 1);
});

test("a browser without Web Serial is told to use desktop Chrome or Edge", async ({ page }) => {
  await mockRelease(page);
  await page.addInitScript(() => {
    delete (Navigator.prototype as unknown as { serial?: unknown }).serial;
  });
  await page.goto("/install");
  await expect(page.getByTestId("flasher-unsupported")).toHaveAttribute("data-support", "no-serial");
  await expect(page.getByTestId("flasher-unsupported")).toContainText("Chrome");
  await expect(page.getByTestId("flasher-button")).toBeDisabled();
});

test.describe("on a phone", () => {
  test.use({
    viewport: { width: 390, height: 844 },
    userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
  });
  test("a phone is told that flashing needs a desktop computer", async ({ page }) => {
    await mockRelease(page);
    await page.goto("/install");
    await expect(page.getByTestId("flasher-unsupported")).toHaveAttribute("data-support", "mobile");
    await expect(page.getByTestId("flasher-button")).toBeDisabled();
  });
});

for (const viewport of [
  { width: 320, height: 568 },
  { width: 768, height: 1024 },
  { width: 1440, height: 900 },
]) {
  test(`axe and layout at ${viewport.width}px: default, First install and Restore states`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    await mockRelease(page);
    await fakeSerial(page, "cancel");
    await page.goto("/install");
    await expect(page.getByTestId("flasher-release")).toContainText("1.0.0");
    for (const state of ["update", "install", "restore"] as const) {
      if (state === "install") {
        await page.getByRole("radio", { name: /First install/ }).check();
        await page.getByRole("checkbox", { name: /the whole stick is erased/ }).check();
        await page.getByTestId("flasher-button").click();
      }
      if (state === "restore") await page.getByRole("radio", { name: /Restore a backup/ }).check();
      const results = await new AxeBuilder({ page }).analyze();
      await testInfo.attach(`axe-install-${state}-${viewport.width}.json`, { body: JSON.stringify(results, null, 2), contentType: "application/json" });
      const blocking = results.violations
        .filter((v) => v.impact === "serious" || v.impact === "critical")
        .map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target.join(" ")) }));
      expect(blocking, `${state} at ${viewport.width}: no serious or critical axe findings`).toEqual([]);
      const size = await page.evaluate(() => ({ doc: document.documentElement.scrollWidth, view: window.innerWidth }));
      expect(size.doc, `${state} at ${viewport.width}: no horizontal overflow`).toBeLessThanOrEqual(size.view);
    }
    await testInfo.attach(`install-${viewport.width}.png`, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  });
}
