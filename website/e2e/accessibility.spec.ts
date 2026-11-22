import AxeBuilder from "@axe-core/playwright";
import type { Page, TestInfo } from "@playwright/test";
import { test, expect, chooseScenario, enter3d, pauseMotion, scenarioLabels } from "./fixtures";

// Automated accessibility (axe-core, every rule including best practices) in
// the normal, nearby, alert, stale, mobile-navigation and active-3D states, and
// scripted keyboard checks for focus, names, selection, status updates and
// fallback recovery. A screen reader is not driven here: the accessibility
// tree of each state is attached as the reviewer's input for that manual check.

const desktop = { width: 1440, height: 900 };
const mobile = { width: 390, height: 844 };

async function audit(page: Page, testInfo: TestInfo, state: string) {
  const results = await new AxeBuilder({ page }).analyze();
  await testInfo.attach(`axe-${state}.json`, {
    body: JSON.stringify(results, null, 2),
    contentType: "application/json",
  });
  await testInfo.attach(`aria-${state}.yml`, {
    body: await page.locator("body").ariaSnapshot(),
    contentType: "text/yaml",
  });
  const blocking = results.violations
    .filter((violation) => violation.impact === "serious" || violation.impact === "critical")
    .map((violation) => ({
      id: violation.id,
      impact: violation.impact,
      targets: violation.nodes.map((node) => node.target.join(" ")),
    }));
  expect(blocking, `${state}: no serious or critical axe findings`).toEqual([]);
  return results;
}

for (const scenario of ["normal", "nearby", "alert", "stale"] as const) {
  test(`axe: ${scenario} state`, async ({ page }, testInfo) => {
    await page.setViewportSize(desktop);
    await page.goto("/");
    await chooseScenario(page, scenario);
    await expect(page.locator(".guardian-state strong")).toHaveText(
      scenario === "normal" ? "Very good" : scenarioLabels[scenario],
    );
    await audit(page, testInfo, scenario);
  });
}

test("axe: mobile navigation open", async ({ page }, testInfo) => {
  await page.setViewportSize(mobile);
  await page.goto("/");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("navigation", { name: "Mobile navigation" })).toBeVisible();
  await audit(page, testInfo, "mobile-navigation");
});

test("axe: active 3D viewer", async ({ page }, testInfo) => {
  await page.setViewportSize(desktop);
  await page.goto("/");
  await pauseMotion(page);
  await enter3d(page);
  await expect(page.getByRole("group", { name: /StickS3 in 3D/ })).toBeVisible();
  await audit(page, testInfo, "active-3d");
});

/** The focused element shows a visible focus indicator (outline or ring). */
async function focusIndicator(page: Page) {
  return page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el || el === document.body) return null;
    const style = getComputedStyle(el);
    return {
      tag: el.tagName,
      text: (el.getAttribute("aria-label") ?? el.textContent ?? "").trim().slice(0, 60),
      focusVisible: el.matches(":focus-visible"),
      visible:
        (style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0) ||
        (style.boxShadow !== "none" && style.boxShadow !== ""),
    };
  });
}

test("keyboard: skip link, then every Tab stop has a name and a visible focus indicator", async ({ page }) => {
  await page.setViewportSize(desktop);
  await page.goto("/");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to content" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main$/);

  await page.goto("/");
  const stops: { tag: string; text: string }[] = [];
  for (let i = 0; i < 60; i++) {
    await page.keyboard.press("Tab");
    const focus = await focusIndicator(page);
    if (!focus) break;
    expect(focus.text, `Tab stop ${i + 1} (${focus.tag}) has a name`).not.toBe("");
    expect(focus.focusVisible, `Tab stop ${i + 1} ${focus.text} matches :focus-visible`).toBe(true);
    expect(focus.visible, `Tab stop ${i + 1} ${focus.text} shows a focus indicator`).toBe(true);
    stops.push({ tag: focus.tag, text: focus.text });
  }
  expect(stops.length).toBeGreaterThan(15);
  expect(stops.map((stop) => stop.text)).toContain("See in 3D");
});

test("keyboard: expression and scenario selection, with status updates", async ({ page }) => {
  await page.setViewportSize(desktop);
  await page.goto("/");
  const state = page.locator(".guardian-state strong");
  const status = page.locator(".scenario-description[role=status]");

  // Choosing an expression shows its normal state (the scenario returns to Listening).
  const moods = page.getByRole("group", { name: "Guardian advertised-settings expression" });
  const veryGood = moods.getByRole("button", { name: /^Very good\s*Looking sharp\.$/ });
  await expect(veryGood).toHaveAttribute("aria-pressed", "true");
  const bad = moods.getByRole("button", { name: /^Bad\s*We need to talk\.$/ });
  await bad.focus();
  await page.keyboard.press("Enter");
  await expect(bad).toHaveAttribute("aria-pressed", "true");
  await expect(veryGood).toHaveAttribute("aria-pressed", "false");
  await expect(state).toHaveText("Bad");
  await expect(status).toHaveText("Demo advertised-settings rating: bad. Listening for changes.");

  const scenarios = page.getByRole("group", { name: "Simulated radio condition" });
  const listening = scenarios.getByRole("button", { name: "Listening" });
  await expect(listening).toHaveAttribute("aria-pressed", "true");
  await listening.focus();
  await page.keyboard.press("ArrowRight");
  const nearby = scenarios.getByRole("button", { name: "Nearby activity" });
  await expect(nearby).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(nearby).toHaveAttribute("aria-pressed", "true");
  await expect(listening).toHaveAttribute("aria-pressed", "false");
  await expect(status).toContainText("probes from 12 addresses nearby");
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("Space");
  await expect(scenarios.getByRole("button", { name: "Network alert" })).toHaveAttribute("aria-pressed", "true");
  await expect(status).toContainText("24 disconnect frames");
  await expect(state).toHaveText("Network alert");
  await expect(page.locator(".guardian-portrait")).toHaveAttribute("src", /bad-alert\.png/);
});

test("keyboard: mobile navigation opens, is reachable and closes with Escape", async ({ page }) => {
  await page.setViewportSize(mobile);
  await page.goto("/");
  const menu = page.getByRole("button", { name: "Open navigation" });
  await menu.focus();
  await page.keyboard.press("Enter");
  const close = page.getByRole("button", { name: "Close navigation" });
  await expect(close).toHaveAttribute("aria-expanded", "true");
  const nav = page.getByRole("navigation", { name: "Mobile navigation" });
  await page.keyboard.press("Tab");
  await expect(nav.getByRole("link").first()).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(nav).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Open navigation" })).toBeFocused();
});

test("keyboard: 3D viewer opens, is named, rotates and returns focus on Escape", async ({ page }) => {
  await page.setViewportSize(desktop);
  await page.goto("/");
  await pauseMotion(page);
  const toggle = page.getByRole("button", { name: "See in 3D" });
  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".guardian-stage")).toHaveAttribute("data-view", "3d", { timeout: 150_000 });
  await expect(page.getByRole("button", { name: "Back to 2D" })).toBeVisible();
  const viewer = page.getByRole("group", { name: /StickS3 in 3D showing the simulated Guardian screen/ });
  await expect(viewer).toHaveAttribute("aria-roledescription", "3D model");
  await expect(page.locator(".stick-viewer-hint")).toBeVisible();
  await viewer.focus();
  for (const key of ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home"]) await page.keyboard.press(key);
  await page.keyboard.press("Escape");
  await expect(page.locator(".guardian-stage")).toHaveAttribute("data-view", "2d");
  await expect(page.getByRole("button", { name: "See in 3D" })).toBeFocused();
});

test("keyboard: without WebGL the fallback is announced, 2D stays usable and focus stays put", async ({ page }) => {
  await page.addInitScript(() => {
    type GetContext = (this: HTMLCanvasElement, type: string, ...rest: unknown[]) => unknown;
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: GetContext };
    const original = proto.getContext;
    proto.getContext = function (type, ...rest) {
      return /webgl/i.test(type) ? null : original.call(this, type, ...rest);
    };
  });
  await page.setViewportSize(desktop);
  await page.goto("/");
  const toggle = page.getByRole("button", { name: "See in 3D" });
  await toggle.focus();
  await page.keyboard.press("Enter");
  const status = page.locator(".view-status[role=status]");
  await expect(status).toHaveText(
    "3D view unavailable: this browser has WebGL turned off or unsupported. Showing the 2D view instead.",
  );
  await expect(page.locator(".guardian-stage")).toHaveAttribute("data-view", "2d");
  await expect(page.getByRole("button", { name: "See in 3D" })).toBeFocused();
  await expect(page.locator(".guardian-portrait")).toBeVisible();
  await expect(page.locator("canvas")).toHaveCount(0);
  // The rest of the demo keeps working after the failure.
  await chooseScenario(page, "stale");
  await expect(page.locator(".no-data-portrait")).toBeVisible();
  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(status).toContainText("3D view unavailable");
});
