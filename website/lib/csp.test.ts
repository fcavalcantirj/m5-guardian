import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { contentSecurityPolicy, cspHeaderName, newNonce } from "./csp.ts";

// W08 Content-Security-Policy. The pages are rendered per request so that
// Next can put a fresh nonce on its inline bootstrap scripts (proxy.ts); every
// other source is listed exactly. website/DEPLOYMENT.md explains each source.

const site = new URL("..", import.meta.url).pathname;

/** Directive name to its source list. */
function directives(policy: string) {
  const map = new Map<string, string[]>();
  for (const part of policy.split(";").map((p) => p.trim()).filter(Boolean)) {
    const [name, ...sources] = part.split(/\s+/);
    assert.ok(!map.has(name), `${name} appears once`);
    map.set(name, sources);
  }
  return map;
}

test("production policy: same-origin only, a nonce for inline scripts, nothing else inline", () => {
  const policy = directives(contentSecurityPolicy({ nonce: "abc123==" }));
  assert.deepEqual(Object.fromEntries(policy), {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'nonce-abc123=='"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
  });
  const text = contentSecurityPolicy({ nonce: "abc123==" });
  assert.doesNotMatch(text, /unsafe-eval|strict-dynamic|\*|https?:|data:|blob:/);
});

test("development adds unsafe-eval (React's dev error overlay) and nothing else", () => {
  const prod = directives(contentSecurityPolicy({ nonce: "n" }));
  const dev = directives(contentSecurityPolicy({ nonce: "n", dev: true }));
  assert.deepEqual(dev.get("script-src"), [...prod.get("script-src")!, "'unsafe-eval'"]);
  dev.delete("script-src");
  prod.delete("script-src");
  assert.deepEqual(dev, prod);
});

test("preview deployments add exactly Vercel's documented toolbar sources", () => {
  const prod = directives(contentSecurityPolicy({ nonce: "n" }));
  const preview = directives(contentSecurityPolicy({ nonce: "n", preview: true }));
  const added = Object.fromEntries(
    [...preview].map(([name, sources]) => [name, sources.filter((s) => !(prod.get(name) ?? []).includes(s))]).filter(([, s]) => s.length),
  );
  assert.deepEqual(added, {
    "script-src": ["https://vercel.live"],
    "connect-src": ["https://vercel.live", "wss://ws-us3.pusher.com"],
    "img-src": ["https://vercel.live", "https://vercel.com", "data:", "blob:"],
    "frame-src": ["https://vercel.live"],
    "style-src": ["https://vercel.live"],
    "font-src": ["https://vercel.live", "https://assets.vercel.com"],
  });
  for (const [name, sources] of prod) for (const source of sources) assert.ok(preview.get(name)!.includes(source), `${name} keeps ${source}`);
});

test("the header is enforced unless report-only is asked for", () => {
  assert.equal(cspHeaderName(undefined), "Content-Security-Policy");
  assert.equal(cspHeaderName(""), "Content-Security-Policy");
  assert.equal(cspHeaderName("0"), "Content-Security-Policy");
  assert.equal(cspHeaderName("1"), "Content-Security-Policy-Report-Only");
});

test("nonces are fresh, base64 and at least 128 bits", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) {
    const nonce = newNonce();
    assert.match(nonce, /^[A-Za-z0-9+/]+={0,2}$/);
    assert.ok(Buffer.from(nonce, "base64").length >= 16);
    seen.add(nonce);
  }
  assert.equal(seen.size, 50);
});

test("proxy.ts sets the policy on the request (for Next's nonce) and the response, and skips static files", () => {
  const proxy = readFileSync(join(site, "proxy.ts"), "utf8");
  assert.match(proxy, /export function proxy\(/);
  assert.match(proxy, /requestHeaders\.set\("content-security-policy", policy\)/);
  assert.match(proxy, /response\.headers\.set\(header, policy\)/);
  assert.match(proxy, /process\.env\.GUARDIAN_CSP_REPORT_ONLY/);
  assert.match(proxy, /process\.env\.VERCEL_ENV === "preview"/);
  // The matcher's source, unescaped from the file and matched against real paths as Next does (whole pathname).
  const source = JSON.parse(`"${/source:\s*"([^"]+)"/.exec(proxy)![1]}"`);
  const matcher = new RegExp(`^${source}$`);
  for (const path of ["/", "/install", "/no-such-page"]) assert.ok(matcher.test(path), `${path} gets the policy`);
  for (const path of [
    "/api/firmware/latest",
    "/api/firmware/guardian-1.0.0-b1-cccccccccccc/bootloader.bin",
    "/_next/static/chunks/main.js",
    "/_next/image",
    "/_vercel/insights/script.js",
    "/favicon.ico",
    "/icon.svg",
    "/apple-icon.png",
    "/opengraph-image",
    "/twitter-image",
    "/install/opengraph-image",
    "/install/twitter-image",
    "/robots.txt",
    "/sitemap.xml",
    "/images/very-good.png",
    "/models/NOTICE.txt",
  ])
    assert.ok(!matcher.test(path), `${path} skips the proxy`);
});

test("the root layout waits for the request, so every page is rendered with its own nonce", () => {
  const layout = readFileSync(join(site, "app/layout.tsx"), "utf8");
  assert.match(layout, /await connection\(\)/);
  assert.match(layout, /export default async function RootLayout/);
});
