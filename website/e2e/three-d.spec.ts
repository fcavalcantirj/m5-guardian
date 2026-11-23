import type { Page, Response } from "@playwright/test";
import { test, expect, enter3d, isViewerRequest, pauseMotion, viewerChunks, watchViewerScripts } from "./fixtures";

// The 3D viewer is on demand: loading the page and waiting without any
// interaction requests no viewer chunk and no model. After "See in 3D" the
// viewer chunk, the three StickS3 models and the face texture load with 200,
// and the screen artwork is photographed from the front, side and rear.
// Viewer chunks are recognised by name from the local build and, on any
// server (also a deployment, WEBSITE_URL), by the content of each script.

const IDLE_WAIT_MS = 8_000;
const chunks = viewerChunks();

const profiles = {
  desktop: { viewport: { width: 1440, height: 900 } },
  mobile: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 3 },
};

for (const [name, profile] of Object.entries(profiles)) {
  test.describe(name, () => {
    test.use(profile);

    test("no 3D chunk or model is requested on load or while waiting", async ({ page }) => {
      const requests: string[] = [];
      page.on("request", (request) => requests.push(request.url()));
      const scripts = watchViewerScripts(page);
      await page.goto("/", { waitUntil: "networkidle" });
      await page.waitForTimeout(IDLE_WAIT_MS);
      await page.waitForLoadState("networkidle");
      expect(requests.length).toBeGreaterThan(5);
      expect(requests.filter((url) => isViewerRequest(url, chunks))).toEqual([]);
      const loaded = await scripts();
      expect(loaded.unreadable).toEqual([]);
      expect(loaded.viewer, "no script carrying the viewer before activation").toEqual([]);
      await expect(page.locator("canvas")).toHaveCount(0);
    });

    test("activation loads the viewer chunk, the three models and the face texture", async ({ page }) => {
      await page.goto("/", { waitUntil: "networkidle" });
      const responses: Response[] = [];
      const failed: string[] = [];
      page.on("response", (response) => responses.push(response));
      const scripts = watchViewerScripts(page);
      page.on("requestfailed", (request) => failed.push(request.url()));
      await enter3d(page);
      await expect(page.locator(".stick-viewer")).toHaveAttribute("data-screen-face", "drawn");
      await page.waitForLoadState("networkidle");

      const path = (response: Response) => new URL(response.url()).pathname;
      const statuses = Object.fromEntries(responses.map((r) => [path(r), r.status()]));
      expect(failed).toEqual([]);
      expect(responses.filter((r) => r.status() >= 400).map((r) => `${r.status()} ${path(r)}`)).toEqual([]);
      for (const model of ["sticks3-front.stl", "sticks3-back.stl", "sticks3-buttons.stl"]) {
        const response = responses.find((r) => path(r) === `/models/${model}`);
        expect(response, `${model} requested`).toBeTruthy();
        expect(response!.status()).toBe(200);
        expect((await response!.body()).byteLength, `${model} has bytes`).toBeGreaterThan(10_000);
      }
      if (chunks.length) expect(responses.some((r) => chunks.some((chunk) => path(r).endsWith(`/${chunk}`)))).toBe(true);
      const loaded = await scripts();
      expect(loaded.unreadable).toEqual([]);
      expect(loaded.viewer.length, "a script carrying the viewer loaded on activation").toBeGreaterThan(0);
      expect(statuses["/images/very-good.png"], "face texture").toBe(200);
      expect(Object.keys(statuses).filter((p) => /\.(glb|gltf|obj|fbx)$/i.test(p))).toEqual([]);
      await expect(page.locator("canvas")).toHaveCount(1);
    });
  });
}

/**
 * Strongly coloured pixels (max minus min channel above 80) per thousand in the
 * central band of a PNG screenshot (35-65 % across, 10-90 % down), measured by
 * the browser. The lit face and screen text are colourful; the grey case and
 * the dark page behind it are not. Measured on a reviewed run: front 19,
 * side 8, rear 0.
 */
async function colouredPerMille(page: Page, png: Buffer) {
  return page.evaluate(async (base64) => {
    const blob = await (await fetch(`data:image/png;base64,${base64}`)).blob();
    const bitmap = await createImageBitmap(blob);
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const context = canvas.getContext("2d")!;
    context.drawImage(bitmap, 0, 0);
    const x = Math.round(bitmap.width * 0.35);
    const y = Math.round(bitmap.height * 0.1);
    const { data } = context.getImageData(x, y, Math.round(bitmap.width * 0.3), Math.round(bitmap.height * 0.8));
    let coloured = 0;
    for (let i = 0; i < data.length; i += 4)
      if (Math.max(data[i], data[i + 1], data[i + 2]) - Math.min(data[i], data[i + 1], data[i + 2]) > 80) coloured++;
    return Math.round((1000 * coloured) / (data.length / 4));
  }, png.toString("base64"));
}

test.describe("screen alignment", () => {
  test.use(profiles.desktop);

  test("front, side and rear views of the screen artwork", async ({ page }, testInfo) => {
    await page.goto("/");
    await pauseMotion(page);
    await enter3d(page);
    const viewer = page.locator(".stick-viewer");
    await expect(viewer).toHaveAttribute("data-screen-face", "drawn");
    await viewer.focus();

    const views: Record<string, Buffer> = {};
    const shoot = async (label: string, keys: string[]) => {
      for (const key of keys) await page.keyboard.press(key);
      await page.waitForTimeout(800);
      views[label] = await viewer.screenshot({ path: testInfo.outputPath(`screen-${label}.png`) });
      await testInfo.attach(`screen-${label}.png`, { body: views[label], contentType: "image/png" });
    };
    await shoot("front", ["Home"]);
    await shoot("side", ["Home", ...Array(10).fill("ArrowRight")]);
    await shoot("rear", ["Home", ...Array(21).fill("ArrowRight")]);

    const coloured = {
      front: await colouredPerMille(page, views.front),
      side: await colouredPerMille(page, views.side),
      rear: await colouredPerMille(page, views.rear),
    };
    await testInfo.attach("coloured-per-mille.json", { body: JSON.stringify(coloured), contentType: "application/json" });
    expect(views.front.equals(views.side)).toBe(false);
    expect(views.front.equals(views.rear)).toBe(false);
    // The screen faces the camera at the front, turns away at the side and is hidden at the rear.
    expect(coloured.front, "front shows the lit screen").toBeGreaterThanOrEqual(10);
    expect(coloured.side, "side shows less of it").toBeLessThan(coloured.front);
    expect(coloured.rear, "rear shows no screen").toBeLessThanOrEqual(2);
  });
});
