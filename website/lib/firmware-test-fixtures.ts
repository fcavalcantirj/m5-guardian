// W07 test fixtures, imported only by the unit tests: a throwaway ECDSA P-256 key generated per run (no key
// material is committed), a release in the exact bytes tools/release_support.py writes, and a fetch that answers
// like github.com's release download URLs.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { RELEASES_URL, RELEASE_REPO } from "./firmware-release.ts";

export const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

export function throwawayKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { privateKey, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

/** Four small parts and a manifest in exactly the bytes tools/release_support.py manifest_bytes writes. */
export function fixtureRelease(build = 1) {
  const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
  const app = fill(4096, 0x5a);
  app[0] = 0xe9;
  const files: Record<string, Uint8Array> = {
    "bootloader.bin": fill(1024, 0xe9),
    "partition-table.bin": fill(3072, 0xaa),
    "ota_data_initial.bin": fill(8192, 0xff),
    "guardian_sticks3-signed.bin": app,
  };
  const offsets = [0x0, 0x8000, 0x10000, 0x20000];
  const parts = Object.entries(files).map(([file, bytes], i) => ({ file, offset: offsets[i], sha256: sha(bytes), size: bytes.length }));
  const tag = `guardian-1.0.0-b${build}-${parts[3].sha256.slice(0, 12)}`;
  const manifest = { tag, version: "1.0.0", build, date: "2026-11-23", notes: "First public image.", parts };
  return { tag, files, manifest, bytes: new TextEncoder().encode(JSON.stringify(manifest)) };
}

export type Routes = Record<string, () => Response>;
/** A fetch that answers like github.com: each asset URL redirects once to release-assets.githubusercontent.com. */
export function githubFetch(routes: Routes, seen: string[] = []) {
  return async (input: string, init?: RequestInit) => {
    seen.push(input);
    assert.equal(init?.redirect, "manual", "redirects are followed by hand, hop by hop");
    const url = new URL(input);
    if (url.hostname === "github.com") {
      const path = url.pathname.replace(`/${RELEASE_REPO}/releases/`, "");
      if (!(path in routes)) return new Response("Not Found", { status: 404 });
      return new Response(null, { status: 302, headers: { location: `https://release-assets.githubusercontent.com/x/${encodeURIComponent(path)}` } });
    }
    if (url.hostname === "release-assets.githubusercontent.com") return routes[decodeURIComponent(url.pathname.slice(3))]();
    throw new Error(`unexpected host ${url.hostname}`);
  };
}

export function publishedRoutes(fx: ReturnType<typeof fixtureRelease>, signature: Uint8Array): Routes {
  const routes: Routes = {
    "latest/download/manifest.json": () => new Response(fx.bytes),
    [`download/${fx.tag}/manifest.json`]: () => new Response(fx.bytes),
    [`download/${fx.tag}/manifest.sig`]: () => new Response(signature),
  };
  for (const [file, bytes] of Object.entries(fx.files)) routes[`download/${fx.tag}/${file}`] = () => new Response(bytes);
  return routes;
}

