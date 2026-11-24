import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test as base, expect, type Page } from "@playwright/test";

/**
 * Every page in the browser suite is watched for uncaught errors, console
 * errors, hydration failures and Content-Security-Policy violations (W08,
 * enforced or report-only); any one of them fails the test that saw it.
 */
export const test = base.extend<{ browserLog: string[] }>({
  browserLog: [
    async ({ page }, use, testInfo) => {
      const log: string[] = [];
      await page.exposeBinding("__guardianCspViolation", (_source, line: string) => void log.push(line));
      await page.addInitScript(() =>
        document.addEventListener("securitypolicyviolation", (event) =>
          (window as unknown as { __guardianCspViolation: (line: string) => void }).__guardianCspViolation(
            `csp-violation: ${event.disposition} ${event.effectiveDirective} blocked ${event.blockedURI || "(inline)"} in ${event.sourceFile || "(document)"}`,
          ),
        ),
      );
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

/**
 * The deployment under test when WEBSITE_URL is set (W06: a Vercel preview or
 * production); null for the local production server that playwright.config.ts starts.
 */
export const remoteOrigin = process.env.WEBSITE_URL ? new URL(process.env.WEBSITE_URL).origin : null;

/**
 * W08: a second local server of the same build that runs as on Vercel
 * (VERCEL=1), so the root layout mounts Vercel Web Analytics; started by
 * playwright.config.ts on the next port. Null against a deployment.
 */
export const vercelModeOrigin = remoteOrigin ? null : `http://127.0.0.1:${Number(process.env.WEBSITE_PORT ?? 3210) + 1}`;

/** Text that only the 3D viewer's code carries (three.js, Fiber or the STL paths). */
export function isViewerSource(text: string) {
  return text.includes("WebGLRenderer") || text.includes("sticks3-front.stl") || text.includes("PMREMGenerator");
}

/**
 * Built chunks that carry the 3D viewer, read from the local build. Against a
 * deployment the local build is not the code being served, so this returns no
 * names there and watchViewerScripts() identifies the viewer by content instead.
 */
export function viewerChunks(): string[] {
  if (remoteOrigin) return [];
  const dir = join(site, ".next/static/chunks");
  const chunks = readdirSync(dir).filter(
    (name) => name.endsWith(".js") && isViewerSource(readFileSync(join(dir, name), "utf8")),
  );
  if (chunks.length === 0) throw new Error("no viewer chunk found in the build");
  return chunks;
}

/**
 * Reads the body of every script the page loads and records those that carry
 * the 3D viewer, so the check works on any server, including a deployment.
 * Call the returned function after the page settles; unreadable script bodies
 * are reported separately and must be empty.
 */
export function watchViewerScripts(page: Page) {
  const viewer: string[] = [];
  const unreadable: string[] = [];
  const pending: Promise<void>[] = [];
  page.on("response", (response) => {
    if (response.request().resourceType() !== "script") return;
    const path = new URL(response.url()).pathname;
    pending.push(
      response.text().then(
        (text) => void (isViewerSource(text) && viewer.push(path)),
        (error) => void unreadable.push(`${path}: ${error}`),
      ),
    );
  });
  return async () => {
    await Promise.all(pending);
    return { viewer, unreadable };
  };
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
