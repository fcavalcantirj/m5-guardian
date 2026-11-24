import AxeBuilder from "@axe-core/playwright";
import type { Page, TestInfo } from "@playwright/test";
import { test, expect, horizontalOverflow } from "./fixtures";
import { detectsDescription, detectsLead, detectsSections, detectsTitle } from "../lib/what-it-detects";

// W09 content page /what-it-detects against the production server (or WEBSITE_URL): status,
// metadata, the question headings with their answers, the links to it from the home page and
// the footer, axe-core with every rule, and no horizontal overflow at 320, 768 and 1440 px.

const siteUrl = "https://m5-guardian.vercel.app";
const path = "/what-it-detects";

async function audit(page: Page, testInfo: TestInfo, state: string) {
  const results = await new AxeBuilder({ page }).analyze();
  await testInfo.attach(`axe-${state}.json`, { body: JSON.stringify(results, null, 2), contentType: "application/json" });
  await testInfo.attach(`aria-${state}.yml`, { body: await page.locator("body").ariaSnapshot(), contentType: "text/yaml" });
  const findings = results.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    targets: violation.nodes.map((node) => node.target.join(" ")),
  }));
  // A text page has no reason for any finding, so every impact level counts here.
  expect(findings, `${state}: no axe findings`).toEqual([]);
}

test("the page answers each question under its own heading, with its own metadata", async ({ page }) => {
  const response = await page.goto(path);
  expect(response?.status()).toBe(200);
  await expect(page).toHaveTitle(detectsTitle);
  await expect(page.locator('meta[name="description"]')).toHaveAttribute("content", detectsDescription);
  const canonical = page.locator('link[rel="canonical"]');
  await expect(canonical).toHaveCount(1);
  expect(await canonical.getAttribute("href")).toBe(`${siteUrl}${path}`);
  await expect(page.locator('meta[name="robots"][content*="noindex"]')).toHaveCount(0);

  const main = page.locator("main#main");
  await expect(main.getByRole("heading", { level: 1 })).toHaveCount(1);
  await expect(main.locator(".detects-lead")).toHaveText(detectsLead.text);
  const headings = main.getByRole("heading", { level: 2 });
  await expect(headings).toHaveText(detectsSections.map((section) => section.question));
  for (const section of detectsSections) {
    const block = main.locator(`section#${section.id}`);
    await expect(block.locator(".detects-answer")).toHaveText(section.answer.text);
    await expect(block.locator(".detects-points > li")).toHaveText(section.points.map((point) => point.text));
    // The table of contents leads to the section.
    await expect(main.getByRole("navigation", { name: "Questions on this page" }).getByRole("link", { name: section.question })).toHaveAttribute(
      "href",
      `#${section.id}`,
    );
  }

  // Only the site-wide JSON-LD (W08), no FAQ markup.
  const blocks = await page.locator('script[type="application/ld+json"]').allTextContents();
  expect(blocks).toHaveLength(1);
  expect(blocks[0]).not.toMatch(/FAQPage|Question/);
});

test("the home page links to it beside the alert story, and the footer links to it on every page", async ({ page }) => {
  await page.goto("/");
  const homeLink = page.locator("#how-it-works").getByRole("link", { name: "What makes it red or amber" });
  await homeLink.scrollIntoViewIfNeeded();
  await expect(homeLink).toBeVisible();
  await expect(homeLink).toHaveAttribute("href", path);
  for (const at of ["/", "/install", path]) {
    await page.goto(at);
    const footerLink = page.locator(".site-footer").getByRole("link", { name: "What it detects", exact: true });
    await footerLink.scrollIntoViewIfNeeded();
    await expect(footerLink, at).toBeVisible();
    await expect(footerLink).toHaveAttribute("href", path);
  }
  await page.goto("/");
  await page.locator("#how-it-works").getByRole("link", { name: "What makes it red or amber" }).click();
  await expect(page).toHaveURL(new RegExp(`${path}$`));
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("What the Guardian sees, and what it cannot.");
});

for (const viewport of [
  { name: "1440", width: 1440, height: 900 },
  { name: "390", width: 390, height: 844 },
]) {
  test(`axe: the page at ${viewport.name} px`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    await page.goto(path);
    await audit(page, testInfo, `what-it-detects-${viewport.name}`);
  });
}

for (const viewport of [
  { name: "320", width: 320, height: 568 },
  { name: "768", width: 768, height: 1024 },
  { name: "1440", width: 1440, height: 900 },
]) {
  test(`no horizontal overflow at ${viewport.name} px, top to bottom`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    await page.goto(path);
    for (const where of ["main h1", "section#red", "section#compared", ".site-footer"]) {
      await page.locator(where).first().scrollIntoViewIfNeeded();
      const size = await horizontalOverflow(page);
      expect(size.documentWidth, `${where}: document wider than viewport`).toBeLessThanOrEqual(size.viewport);
      expect(size.bodyWidth, `${where}: body wider than viewport`).toBeLessThanOrEqual(size.viewport);
    }
    // No element sticks out of the viewport sideways or is cut off inside its own box.
    const outside = await page.evaluate(() =>
      [...document.querySelectorAll("main *, .site-footer *")]
        .filter((el) => {
          const box = el.getBoundingClientRect();
          return box.width > 0 && (box.left < -0.5 || box.right > document.documentElement.clientWidth + 0.5 || el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflowX !== "visible");
        })
        .map((el) => `${el.tagName.toLowerCase()}.${el.className}`),
    );
    expect(outside).toEqual([]);
    await page.evaluate(() => window.scrollTo(0, 0));
    await testInfo.attach(`what-it-detects-${viewport.name}.png`, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  });
}
