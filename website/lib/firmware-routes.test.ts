import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sign } from "node:crypto";
import { fileResponse, latestResponse } from "./firmware-routes.ts";
import { fixtureRelease, githubFetch, publishedRoutes, sha, throwawayKey, type Routes } from "./firmware-test-fixtures.ts";

// W07: /api/firmware/latest and /api/firmware/[tag]/[file] with a mocked fetch (github.com release URLs) and a
// throwaway signing key. The route files only pass their parameters to these handlers (checked at the end).

const key = throwawayKey();
const fx = fixtureRelease();
const signature = new Uint8Array(sign("sha256", fx.bytes, key.privateKey));
const opts = (routes: Routes) => ({ fetch: githubFetch(routes), publicKeyPem: key.publicKeyPem });
const site = new URL("..", import.meta.url).pathname;

test("latest answers the verified release with same-origin part URLs and a short CDN cache", async () => {
  const res = await latestResponse(opts(publishedRoutes(fx, signature)));
  assert.equal(res.status, 200);
  assert.match(res.headers.get("cache-control") ?? "", /s-maxage=60/);
  const body = await res.json();
  assert.equal(body.tag, fx.tag);
  assert.equal(body.version, "1.0.0");
  assert.equal(body.build, 1);
  assert.equal(body.notes, "First public image.");
  assert.deepEqual(
    body.parts.map((p: { file: string; offset: number; url: string; sha256: string; size: number }) => [p.file, p.offset, p.url, p.sha256, p.size]),
    fx.manifest.parts.map((p) => [p.file, p.offset, `/api/firmware/${fx.tag}/${p.file}`, p.sha256, p.size]),
  );
});

test("latest says plainly when nothing is published yet, and is not cached", async () => {
  const res = await latestResponse(opts({}));
  assert.equal(res.status, 404);
  assert.equal(res.headers.get("cache-control"), "no-store");
  const body = await res.json();
  assert.equal(body.kind, "no-release");
  assert.match(body.error, /No release has been published yet/);
});

test("a bad signature, a bad manifest or GitHub down are 502/503 with a plain message", async () => {
  const other = new Uint8Array(sign("sha256", fx.bytes, throwawayKey().privateKey));
  const badSig = await latestResponse(opts(publishedRoutes(fx, other)));
  assert.equal(badSig.status, 502);
  assert.deepEqual(await badSig.json(), { kind: "bad-signature", error: "The signature of this release does not verify. Nothing was sent." });
  const routes = publishedRoutes(fx, signature);
  routes["latest/download/manifest.json"] = () => new Response("{}");
  const badManifest = await latestResponse(opts(routes));
  assert.equal(badManifest.status, 502);
  assert.equal((await badManifest.json()).kind, "bad-manifest");
  const down = await latestResponse({ fetch: async () => { throw new TypeError("fetch failed"); }, publicKeyPem: key.publicKeyPem });
  assert.equal(down.status, 503);
  assert.equal((await down.json()).kind, "unavailable");
});

test("a part is served as bytes with its sha256 and a year of cache", async () => {
  const file = "guardian_sticks3-signed.bin";
  const res = await fileResponse(fx.tag, file, opts(publishedRoutes(fx, signature)));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "application/octet-stream");
  assert.match(res.headers.get("cache-control") ?? "", /immutable/);
  const bytes = new Uint8Array(await res.arrayBuffer());
  assert.equal(sha(bytes), fx.manifest.parts[3].sha256);
  assert.equal(res.headers.get("x-content-sha256"), fx.manifest.parts[3].sha256);
  assert.equal(res.headers.get("content-length"), String(bytes.length));
});

test("a file outside the signed manifest, an unknown tag or changed bytes are never served", async () => {
  const notListed = await fileResponse(fx.tag, "manifest.json", opts(publishedRoutes(fx, signature)));
  assert.equal(notListed.status, 404);
  assert.equal((await notListed.json()).kind, "not-found");
  const badTag = await fileResponse("v1.0.0", "bootloader.bin", opts(publishedRoutes(fx, signature)));
  assert.equal(badTag.status, 404);
  const routes = publishedRoutes(fx, signature);
  routes[`download/${fx.tag}/bootloader.bin`] = () => new Response(new Uint8Array(1024).fill(1));
  const changed = await fileResponse(fx.tag, "bootloader.bin", opts(routes));
  assert.equal(changed.status, 502);
  assert.deepEqual(await changed.json(), { kind: "mismatch", error: "The file does not match the signed release. Nothing was sent." });
  assert.equal(changed.headers.get("cache-control"), "no-store");
});

test("the route files hand their parameters to these handlers and run on Node", () => {
  const latest = readFileSync(`${site}app/api/firmware/latest/route.ts`, "utf8");
  assert.match(latest, /latestResponse\(\)/);
  const file = readFileSync(`${site}app/api/firmware/[tag]/[file]/route.ts`, "utf8");
  assert.match(file, /fileResponse\(tag, file\)/);
  for (const text of [latest, file]) {
    assert.match(text, /export const runtime = "nodejs"/);
    assert.match(text, /export const dynamic = "force-dynamic"/);
  }
});
