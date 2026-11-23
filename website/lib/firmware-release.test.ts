import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { sign } from "node:crypto";
import {
  FirmwareError,
  RELEASES_URL,
  RELEASE_REPO,
  fetchAllowlisted,
  keyFingerprint,
  latestRelease,
  parseManifest,
  releaseByTag,
  releaseFile,
  verifySignature,
} from "./firmware-release.ts";
import { RELEASE_PUBLIC_KEY_PEM, RELEASE_PUBLIC_KEY_SHA256 } from "./release-key.ts";
import { fixtureRelease, githubFetch, publishedRoutes, sha, throwawayKey, type Routes } from "./firmware-test-fixtures.ts";

// W07: the signed release the install page flashes, read and checked on the server (the GitHub Release has no
// CORS). Every signature here is made with a THROWAWAY P-256 key generated for this run; the committed public key
// is only compared with release/release-public-key.json.

const key = throwawayKey();
const fx = fixtureRelease();
const signature = new Uint8Array(sign("sha256", fx.bytes, key.privateKey));
const opts = (routes: Routes, seen?: string[]) => ({ fetch: githubFetch(routes, seen), publicKeyPem: key.publicKeyPem });

test("the committed public key is the release key of release/release-public-key.json", (t) => {
  assert.equal(keyFingerprint(), RELEASE_PUBLIC_KEY_SHA256);
  assert.equal(RELEASE_PUBLIC_KEY_SHA256, "070fda9b871a87bb7d45295016b1cfce5bb579957623fb121ce6c7af302ca17b");
  const file = new URL("../../release/release-public-key.json", import.meta.url);
  if (!existsSync(file)) return t.skip("release/ is not part of the website upload");
  const record = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(record.spki_pem, RELEASE_PUBLIC_KEY_PEM);
  assert.equal(record.spki_der_sha256, RELEASE_PUBLIC_KEY_SHA256);
  assert.equal(record.algorithm, "ECDSA P-256 with SHA-256");
});

test("the website applies the manifest rules of tools/release_support.py", (t) => {
  const file = new URL("../../tools/release_support.py", import.meta.url);
  if (!existsSync(file)) return t.skip("tools/release_support.py is not part of the website upload");
  const text = readFileSync(file, "utf8");
  // The shapes both sides agree on; a change on either side breaks this test.
  assert.match(text, /TAG_RE = re\.compile\(r'\^guardian-\(\\d\+\\\.\\d\+\\\.\\d\+\)-b\(\[1-9\]\\d\{0,8\}\)-\(\[0-9a-f\]\{12\}\)\$'\)/);
  assert.match(text, /MANIFEST_MAX = 4096/);
  assert.match(text, /set\(m\) != \{'tag', 'version', 'build', 'date', 'notes', 'parts'\}/);
  assert.match(text, /\(0x0, 'bootloader\.bin'/);
  assert.match(text, /\(0x8000, 'partition-table\.bin'/);
  assert.match(text, /\(0x10000, 'ota_data_initial\.bin'/);
  assert.match(text, /\(0x20000, APP, APP\)/);
  assert.match(text, /APP = 'guardian_sticks3-signed\.bin'/);
});

test("a release manifest parses into its four parts", () => {
  const r = parseManifest(fx.bytes);
  assert.equal(r.tag, fx.tag);
  assert.equal(r.version, "1.0.0");
  assert.equal(r.build, 1);
  assert.equal(r.date, "2026-11-23");
  assert.equal(r.notes, "First public image.");
  assert.deepEqual(r.parts.map((p) => [p.file, p.offset]), [
    ["bootloader.bin", 0],
    ["partition-table.bin", 0x8000],
    ["ota_data_initial.bin", 0x10000],
    ["guardian_sticks3-signed.bin", 0x20000],
  ]);
});

test("a manifest outside the rules is refused as bad-manifest", () => {
  const bad = (change: (m: Record<string, unknown> & { parts: Record<string, unknown>[] }) => void, why: RegExp) => {
    const m = structuredClone(fx.manifest) as unknown as Record<string, unknown> & { parts: Record<string, unknown>[] };
    change(m);
    assert.throws(() => parseManifest(new TextEncoder().encode(JSON.stringify(m))), (e: unknown) => {
      assert.ok(e instanceof FirmwareError);
      assert.equal(e.kind, "bad-manifest");
      assert.match(e.message, why);
      return true;
    });
  };
  bad((m) => (m.extra = 1), /keys/);
  bad((m) => delete m.notes, /keys/);
  bad((m) => (m.tag = "guardian-1.0.0-b1-zzzzzzzzzzzz"), /tag/);
  bad((m) => (m.version = "1.0.1"), /tag, version and build/);
  bad((m) => (m.build = 2), /tag, version and build/);
  bad((m) => (m.build = "1"), /tag, version and build/);
  bad((m) => (m.date = "23/11/2026"), /date/);
  bad((m) => (m.notes = ""), /notes/);
  bad((m) => (m.notes = "x".repeat(1001)), /notes/);
  bad((m) => m.parts.pop(), /four parts/);
  bad((m) => (m.parts[2].offset = 0x9000), /ota_data_initial\.bin at 0x10000/);
  bad((m) => (m.parts[0].file = "boot.bin"), /bootloader\.bin at 0x0/);
  bad((m) => (m.parts[1].extra = true), /partition-table\.bin at 0x8000/);
  bad((m) => (m.parts[1].sha256 = "ABC"), /sha256 or size/);
  bad((m) => (m.parts[1].size = 0), /sha256 or size/);
  bad((m) => (m.parts[2].size = 0x2001), /slot/);
  bad((m) => (m.parts[3].sha256 = "0".repeat(64)), /does not name the app/);
  assert.throws(() => parseManifest(new TextEncoder().encode("{")), /not JSON/);
  assert.throws(() => parseManifest(new Uint8Array(4097).fill(0x20)), /4 KiB/);
});

test("the signature verifies over the manifest's exact bytes and nothing else", () => {
  assert.ok(verifySignature(fx.bytes, signature, key.publicKeyPem));
  const changed = new Uint8Array([...fx.bytes, 0x20]);
  assert.ok(!verifySignature(changed, signature, key.publicKeyPem), "one added byte fails");
  assert.ok(!verifySignature(fx.bytes, new Uint8Array(0), key.publicKeyPem));
  assert.ok(!verifySignature(fx.bytes, new Uint8Array([1, 2, 3]), key.publicKeyPem), "garbage is false, not a throw");
  assert.ok(!verifySignature(fx.bytes, signature), "the committed key did not sign the throwaway fixture");
  assert.ok(!verifySignature(fx.bytes, signature, throwawayKey().publicKeyPem), "another key fails");
});

test("the latest release is read like the stick: manifest through latest, signature by its tag", async () => {
  const seen: string[] = [];
  const r = await latestRelease(opts(publishedRoutes(fx, signature), seen));
  assert.equal(r.tag, fx.tag);
  const github = seen.filter((u) => u.startsWith("https://github.com/"));
  assert.deepEqual(github, [`${RELEASES_URL}/latest/download/manifest.json`, `${RELEASES_URL}/download/${fx.tag}/manifest.sig`]);
});

test("no published release yet is its own answer", async () => {
  await assert.rejects(latestRelease(opts({})), (e: unknown) => e instanceof FirmwareError && e.kind === "no-release");
});

test("a manifest whose signature fails is refused, whoever signed it", async () => {
  const other = new Uint8Array(sign("sha256", fx.bytes, throwawayKey().privateKey));
  await assert.rejects(latestRelease(opts(publishedRoutes(fx, other))), (e: unknown) => e instanceof FirmwareError && e.kind === "bad-signature");
  const routes = publishedRoutes(fx, signature);
  routes[`download/${fx.tag}/manifest.sig`] = () => new Response("Not Found", { status: 404 });
  await assert.rejects(latestRelease(opts(routes)), (e: unknown) => e instanceof FirmwareError && e.kind === "unavailable");
});

test("a manifest fetched by tag must name that tag", async () => {
  const fx2 = fixtureRelease(2);
  const sig2 = new Uint8Array(sign("sha256", fx2.bytes, key.privateKey));
  const routes = publishedRoutes(fx, signature);
  routes[`download/${fx.tag}/manifest.json`] = () => new Response(fx2.bytes);
  routes[`download/${fx.tag}/manifest.sig`] = () => new Response(sig2);
  await assert.rejects(releaseByTag(fx.tag, opts(routes)), (e: unknown) => e instanceof FirmwareError && e.kind === "bad-manifest" && /names/.test(e.message));
});

test("a part is served only when the signed manifest lists it and its bytes match", async () => {
  const bytes = await releaseFile(fx.tag, "guardian_sticks3-signed.bin", opts(publishedRoutes(fx, signature)));
  assert.equal(sha(bytes), fx.manifest.parts[3].sha256);
  await assert.rejects(releaseFile(fx.tag, "manifest.sig", opts(publishedRoutes(fx, signature))), (e: unknown) => e instanceof FirmwareError && e.kind === "not-found");
  await assert.rejects(releaseFile("../etc", "bootloader.bin", opts(publishedRoutes(fx, signature))), (e: unknown) => e instanceof FirmwareError && e.kind === "not-found");
  const routes = publishedRoutes(fx, signature);
  routes[`download/${fx.tag}/bootloader.bin`] = () => new Response(new Uint8Array(1024).fill(0xe8));
  await assert.rejects(releaseFile(fx.tag, "bootloader.bin", opts(routes)), (e: unknown) => e instanceof FirmwareError && e.kind === "mismatch");
  const big = publishedRoutes(fx, signature);
  big[`download/${fx.tag}/bootloader.bin`] = () => new Response(new Uint8Array(5 * 1024 * 1024));
  await assert.rejects(releaseFile(fx.tag, "bootloader.bin", opts(big)), (e: unknown) => e instanceof FirmwareError && e.kind === "refused" && /too large/.test(e.message));
});

test("redirects stay on HTTPS GitHub release hosts, at most five hops", async () => {
  const hop = (location: string) => async () => new Response(null, { status: 302, headers: { location } });
  await assert.rejects(fetchAllowlisted("https://example.com/x", hop("https://github.com/")), (e: unknown) => e instanceof FirmwareError && e.kind === "refused");
  await assert.rejects(fetchAllowlisted(`${RELEASES_URL}/x`, hop("https://evil.example/asset")), (e: unknown) => e instanceof FirmwareError && e.kind === "refused" && /evil\.example/.test(e.message));
  await assert.rejects(fetchAllowlisted(`${RELEASES_URL}/x`, hop("http://objects.githubusercontent.com/a")), (e: unknown) => e instanceof FirmwareError && e.kind === "refused" && /host not allowed: http:/.test(e.message));
  let n = 0;
  const loop = async () => new Response(null, { status: 302, headers: { location: `https://github.com/r/${n++}` } });
  await assert.rejects(fetchAllowlisted(`${RELEASES_URL}/x`, loop), (e: unknown) => e instanceof FirmwareError && /too many redirects/.test(e.message));
  assert.equal(n, 6, "the first request and five redirects");
  for (const host of ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]) {
    const res = await fetchAllowlisted(`https://${host}/ok`, async () => new Response("ok"));
    assert.equal(await res.text(), "ok");
  }
  await assert.rejects(fetchAllowlisted(`${RELEASES_URL}/x`, async () => { throw new TypeError("fetch failed"); }), (e: unknown) => e instanceof FirmwareError && e.kind === "unavailable");
});
