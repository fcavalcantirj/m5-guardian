import { rmSync } from "node:fs";
import { request } from "@playwright/test";
import { bypassStatePath } from "./remote";

/**
 * Global setup for a protected Vercel deployment (WEBSITE_URL + WEBSITE_BYPASS):
 * one request carries the Protection Bypass for Automation secret with
 * x-vercel-set-bypass-cookie, Vercel answers with a bypass cookie for that host,
 * and every test starts from that cookie (playwright.config.ts storageState).
 * The secret is never printed or written; only the host-scoped cookie is kept,
 * and the returned teardown deletes it when the run ends.
 */
export default async function remoteSetup() {
  const origin = new URL(process.env.WEBSITE_URL!).origin;
  const context = await request.newContext({
    extraHTTPHeaders: {
      "x-vercel-protection-bypass": process.env.WEBSITE_BYPASS!,
      "x-vercel-set-bypass-cookie": "true",
    },
  });
  try {
    const response = await context.get(`${origin}/robots.txt`, { maxRedirects: 0 });
    const state = await context.storageState({ path: bypassStatePath });
    const host = new URL(origin).hostname;
    if (!state.cookies.some((cookie) => cookie.domain.replace(/^\./, "") === host))
      throw new Error(`no bypass cookie from ${origin} (status ${response.status()}); check WEBSITE_BYPASS`);
  } catch (error) {
    rmSync(bypassStatePath, { force: true });
    throw error;
  } finally {
    await context.dispose();
  }
  return () => rmSync(bypassStatePath, { force: true });
}
