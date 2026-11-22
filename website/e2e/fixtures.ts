import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect, type Page } from "@playwright/test";

/**
 * Every page in the browser suite is watched for uncaught errors, console
 * errors and hydration failures; any one of them fails the test that saw it.
 */
export const test = base.extend<{ browserLog: string[] }>({
  browserLog: [
    async ({ page }, use, testInfo) => {
      const log: string[] = [];
      page.on("pageerror", (error) => log.push(`pageerror: ${error.message}`));
      page.on("console", (message) => {
        const text = message.text();
        if (message.type() === "error") log.push(`console.error: ${text}`);
        else if (/hydrat/i.test(text)) log.push(`console.${message.type()}: ${text}`);
      });
      await use(log);
      if (log.length)
        await testInfo.attach("browser-log", { body: log.join("\n"), contentType: "text/plain" });
      expect(log, "no uncaught errors, console errors or hydration failures").toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

const site = new URL("..", import.meta.url).pathname;

/** Built chunks that carry the 3D viewer (three.js, Fiber or the STL paths). */
export function viewerChunks(): string[] {
  const dir = join(site, ".next/static/chunks");
  const chunks = readdirSync(dir).filter((name) => {
    if (!name.endsWith(".js")) return false;
    const text = readFileSync(join(dir, name), "utf8");
    return (
      text.includes("WebGLRenderer") ||
      text.includes("sticks3-front.stl") ||
      text.includes("PMREMGenerator")
    );
  });
  if (chunks.length === 0) throw new Error("no viewer chunk found in the build");
  return chunks;
}

/** True for any request that belongs to the 3D viewer: its chunks or a model file. */
export function isViewerRequest(url: string, chunks: string[]) {
  const path = new URL(url).pathname;
  return /\.(stl|glb|gltf|obj|fbx)$/i.test(path) || chunks.some((chunk) => path.endsWith(`/${chunk}`));
}

export const scenarioLabels = {
  normal: "Listening",
  nearby: "Nearby activity",
  alert: "Network alert",
  stale: "No fresh data",
} as const;

export async function chooseScenario(page: Page, scenario: keyof typeof scenarioLabels) {
  const group = page.getByRole("group", { name: "Simulated radio condition" });
  const button = group.getByRole("button", { name: scenarioLabels[scenario] });
  await button.click();
  await expect(button).toHaveAttribute("aria-pressed", "true");
}

export async function pauseMotion(page: Page) {
  const pause = page.getByRole("button", { name: "Pause motion" });
  if (await pause.isVisible()) await pause.click();
  await expect(page.getByRole("button", { name: "Resume motion" })).toBeVisible();
}

/** Opens the 3D viewer and waits until its scene is ready. */
export async function enter3d(page: Page) {
  await page.getByRole("button", { name: "See in 3D" }).click();
  await expect(page.locator(".guardian-stage")).toHaveAttribute("data-view", "3d", { timeout: 150_000 });
}

/** Ensures the page body never scrolls sideways. */
export async function horizontalOverflow(page: Page) {
  return page.evaluate(() => {
    const doc = document.documentElement;
    return {
      viewport: doc.clientWidth,
      documentWidth: doc.scrollWidth,
      bodyWidth: document.body.scrollWidth,
    };
  });
}
