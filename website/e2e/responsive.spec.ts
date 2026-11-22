import type { Locator, Page } from "@playwright/test";
import { test, expect, enter3d, horizontalOverflow, pauseMotion } from "./fixtures";

// Responsive checks at 320, 375, 390, 600, 768, 1024 and 1440 CSS pixels, and
// 200 percent zoom of a 1280x800 window. Zoom is emulated the way the browser
// lays it out: the page sees a 640x400 CSS-pixel viewport at device scale 2.
// At each size: no horizontal page overflow, and the disclaimer, license text,
// navigation and 3D controls are visible, inside the viewport and usable.

const sizes = [
  { name: "320", width: 320, height: 568 },
  { name: "375", width: 375, height: 667 },
  { name: "390", width: 390, height: 844 },
  { name: "600", width: 600, height: 960 },
  { name: "768", width: 768, height: 1024 },
  { name: "1024", width: 1024, height: 768 },
  { name: "1440", width: 1440, height: 900 },
  { name: "1280 at 200% zoom", width: 640, height: 400, deviceScaleFactor: 2 },
];

async function expectNoOverflow(page: Page, where: string) {
  const size = await horizontalOverflow(page);
  expect(size.documentWidth, `${where}: document wider than viewport`).toBeLessThanOrEqual(size.viewport);
  expect(size.bodyWidth, `${where}: body wider than viewport`).toBeLessThanOrEqual(size.viewport);
}

/** Visible, horizontally inside the viewport and not clipped by its own box. */
async function expectFits(page: Page, locator: Locator, what: string) {
  await locator.scrollIntoViewIfNeeded();
  await expect(locator, `${what} visible`).toBeVisible();
  const box = await locator.boundingBox();
  const width = page.viewportSize()!.width;
  expect(box, `${what} has a box`).not.toBeNull();
  expect(box!.x, `${what} starts inside the viewport`).toBeGreaterThanOrEqual(-0.5);
  expect(box!.x + box!.width, `${what} ends inside the viewport`).toBeLessThanOrEqual(width + 0.5);
  const clipped = await locator.evaluate((el) => el.scrollWidth > el.clientWidth + 1);
  expect(clipped, `${what} text is not cut off sideways`).toBe(false);
}

for (const size of sizes) {
  test.describe(`viewport ${size.name}`, () => {
    test.use({
      viewport: { width: size.width, height: size.height },
      deviceScaleFactor: size.deviceScaleFactor ?? 1,
    });

    test("no horizontal overflow; disclaimer, license and navigation fit and work", async ({ page }, testInfo) => {
      await page.goto("/");
      await expectNoOverflow(page, "top of page");
      await testInfo.attach(`top-${size.name}.png`, { body: await page.screenshot(), contentType: "image/png" });

      await expectFits(page, page.locator(".simulation-note"), "hero simulation disclaimer");
      await expectFits(page, page.locator(".console-disclaimer"), "demo disclaimer");
      const license = page.locator(".site-footer p span");
      await expect(license).toContainText("Code: MIT. Guardian artwork: all rights reserved.");
      await expect(license).toContainText("does not connect to or protect your network");
      await expectFits(page, license, "footer license and disclaimer text");
      const footer = page.locator(".site-footer");
      await expectFits(page, footer.getByRole("link", { name: "Code license", exact: true }), "code license link");
      await expectFits(page, footer.getByRole("link", { name: "Artwork license", exact: true }), "artwork license link");
      await expectNoOverflow(page, "footer");

      await page.evaluate(() => window.scrollTo(0, 0));
      const desktopNav = page.getByRole("navigation", { name: "Main navigation" });
      const labels = ["The Guardian", "How it works", "Hardware", "Open source"];
      if (await desktopNav.isVisible()) {
        for (const label of labels)
          await expectFits(page, desktopNav.getByRole("link", { name: label }), `nav link ${label}`);
        await desktopNav.getByRole("link", { name: "Hardware" }).click();
      } else {
        const menu = page.getByRole("button", { name: "Open navigation" });
        await expectFits(page, menu, "menu button");
        await menu.click();
        const mobileNav = page.getByRole("navigation", { name: "Mobile navigation" });
        for (const label of [...labels, "View on GitHub"])
          await expectFits(page, mobileNav.getByRole("link", { name: label }), `mobile nav link ${label}`);
        await expectNoOverflow(page, "mobile navigation open");
        await mobileNav.getByRole("link", { name: "Hardware" }).click();
        await expect(mobileNav).toHaveCount(0);
      }
      await expect(page).toHaveURL(/#hardware$/);
      await expect(page.locator("#hardware")).toBeInViewport();
    });

    test("3D controls fit and work without overflow", async ({ page }, testInfo) => {
      await page.goto("/");
      await pauseMotion(page);
      const toggle = page.getByRole("button", { name: "See in 3D" });
      await expectFits(page, toggle, "See in 3D");
      await enter3d(page);
      const back = page.getByRole("button", { name: "Back to 2D" });
      await expectFits(page, back, "Back to 2D");
      await expectFits(page, page.locator(".stick-viewer-hint"), "rotation instructions");
      const stage = await page.locator(".guardian-stage").boundingBox();
      const viewer = await page.locator(".stick-viewer").boundingBox();
      expect(viewer!.x).toBeGreaterThanOrEqual(stage!.x - 0.5);
      expect(viewer!.x + viewer!.width).toBeLessThanOrEqual(stage!.x + stage!.width + 0.5);
      await expectNoOverflow(page, "3D active");
      await testInfo.attach(`3d-${size.name}.png`, {
        body: await page.locator(".guardian-stage").screenshot(),
        contentType: "image/png",
      });
      await back.click();
      await expect(page.locator(".guardian-stage")).toHaveAttribute("data-view", "2d");
      await expect(page.getByRole("button", { name: "See in 3D" })).toBeVisible();
    });
  });
}
