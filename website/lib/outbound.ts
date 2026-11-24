import { repositoryUrl } from "./guardian.ts";

/** Vercel Web Analytics event for a click on a link that leaves the site (read by tools/site_stats.sh). */
export const OUTBOUND_EVENT = "outbound_click";

/** Two properties, the Vercel Pro limit per custom event: where the link goes and the page it was on. */
export type OutboundEvent = { target: string; from: string };

const MAX = 255; // Vercel's limit for a property value
const repo = new URL(repositoryUrl);

/**
 * The event for a click on `href` from the page at `pageUrl`, or null when the link stays on the site or is
 * not http(s). Links into this project's repository are named `repo` plus the rest of their path and anchor
 * (e.g. `repo#build-and-install`, `repo/releases`); any other link is its host and path. Query strings are
 * never recorded.
 */
export function outboundEvent(href: string, pageUrl: string): OutboundEvent | null {
  let url: URL;
  let page: URL;
  try {
    page = new URL(pageUrl);
    url = new URL(href, page);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (url.origin === page.origin) return null;
  const path = url.pathname.replace(/\/+$/, "");
  const inRepo = url.origin === repo.origin && (path === repo.pathname || path.startsWith(`${repo.pathname}/`));
  const target = inRepo ? `repo${path.slice(repo.pathname.length)}${url.hash}` : `${url.host}${path}${url.hash}`;
  return { target: target.slice(0, MAX), from: page.pathname.slice(0, MAX) };
}
