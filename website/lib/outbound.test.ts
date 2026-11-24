import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { OUTBOUND_EVENT, outboundEvent } from "./outbound.ts";

// Outbound link counts (round-2 SEO audit): which links leave the site, from which page. Two properties only.

const site = new URL("..", import.meta.url).pathname;
const page = "https://m5-guardian.vercel.app/what-it-detects";

test("links into the repository are named repo plus their path and anchor", () => {
  assert.equal(OUTBOUND_EVENT, "outbound_click");
  assert.deepEqual(outboundEvent("https://github.com/fcavalcantirj/m5-guardian", page), { target: "repo", from: "/what-it-detects" });
  assert.deepEqual(outboundEvent("https://github.com/fcavalcantirj/m5-guardian/", page), { target: "repo", from: "/what-it-detects" });
  assert.equal(outboundEvent("https://github.com/fcavalcantirj/m5-guardian#build-and-install", page)?.target, "repo#build-and-install");
  assert.equal(
    outboundEvent("https://github.com/fcavalcantirj/m5-guardian/blob/main/docs/attack-coverage.md", page)?.target,
    "repo/blob/main/docs/attack-coverage.md",
  );
  assert.equal(outboundEvent("https://github.com/fcavalcantirj/m5-guardian/releases", page)?.target, "repo/releases");
});

test("a look-alike repository name is not this repository", () => {
  assert.equal(outboundEvent("https://github.com/fcavalcantirj/m5-guardian-fork", page)?.target, "github.com/fcavalcantirj/m5-guardian-fork");
});

test("other sites are host and path, never the query string", () => {
  assert.deepEqual(outboundEvent("https://docs.m5stack.com/en/core/StickS3?utm_source=x&id=1#spec", page), {
    target: "docs.m5stack.com/en/core/StickS3#spec",
    from: "/what-it-detects",
  });
});

test("links that stay on the site, and non-web links, are not counted", () => {
  assert.equal(outboundEvent("/install", page), null);
  assert.equal(outboundEvent("https://m5-guardian.vercel.app/", page), null);
  assert.equal(outboundEvent("#main", page), null);
  assert.equal(outboundEvent("mailto:", page), null);
  assert.equal(outboundEvent("tel:+10000000000", page), null);
  assert.equal(outboundEvent("javascript:void(0)", page), null);
  assert.equal(outboundEvent("http://[bad", page), null);
});

test("every value fits Vercel's 255-character limit and the event has exactly two properties", () => {
  const event = outboundEvent(`https://example.com/${"a".repeat(400)}`, page)!;
  assert.deepEqual(Object.keys(event).sort(), ["from", "target"]);
  assert.equal(event.target.length, 255);
});

test("the click listener is mounted once, in the root layout, and sends only outboundEvent()", () => {
  const layout = readFileSync(join(site, "app/layout.tsx"), "utf8");
  assert.equal(layout.match(/<OutboundClicks \/>/g)?.length, 1);
  const component = readFileSync(join(site, "components/outbound-clicks.tsx"), "utf8");
  assert.deepEqual([...component.matchAll(/track\(([^)]+)\)/g)].map((m) => m[1]), ["OUTBOUND_EVENT, event"]);
});
