import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { contentSecurityPolicy, cspHeaderName } from "./csp.ts";

// W08 Content-Security-Policy: a static header from next.config.mjs, so the
// pages stay prerendered; every source is listed exactly. website/DEPLOYMENT.md
// explains each source and the measurement behind 'unsafe-inline' for scripts.

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

test("production policy: same-origin only, inline allowed for Next's bootstrap scripts and React's style attributes", () => {
  const policy = directives(contentSecurityPolicy());
  assert.deepEqual(Object.fromEntries(policy), {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
  });
  const text = contentSecurityPolicy();
  assert.doesNotMatch(text, /unsafe-eval|strict-dynamic|\*|https?:|data:|blob:/);
});

test("development adds unsafe-eval (React's dev error overlay) and nothing else", () => {
  const prod = directives(contentSecurityPolicy());
  const dev = directives(contentSecurityPolicy({ dev: true }));
  assert.deepEqual(dev.get("script-src"), [...prod.get("script-src")!, "'unsafe-eval'"]);
  dev.delete("script-src");
  prod.delete("script-src");
  assert.deepEqual(dev, prod);
});

test("preview deployments add exactly Vercel's documented toolbar sources", () => {
  const prod = directives(contentSecurityPolicy());
  const preview = directives(contentSecurityPolicy({ preview: true }));
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

test("next.config.mjs sends the policy on every path as a static header, and no proxy renders pages per request", () => {
  const config = readFileSync(join(site, "next.config.mjs"), "utf8");
  assert.match(config, /source: "\/\(\.\*\)"/);
  assert.match(config, /key: cspHeaderName\(process\.env\.GUARDIAN_CSP_REPORT_ONLY\)/);
  assert.match(config, /dev: phase === PHASE_DEVELOPMENT_SERVER/);
  assert.match(config, /preview: process\.env\.VERCEL_ENV === "preview"/);
  assert.ok(!existsSync(join(site, "proxy.ts")), "no proxy.ts");
  assert.ok(!existsSync(join(site, "middleware.ts")), "no middleware.ts");
});

test("the root layout is prerendered: no request-time APIs", () => {
  const layout = readFileSync(join(site, "app/layout.tsx"), "utf8");
  assert.doesNotMatch(layout, /connection\(\)|headers\(\)|cookies\(\)|export default async function/);
});
