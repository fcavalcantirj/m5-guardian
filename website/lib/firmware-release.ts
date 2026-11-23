import { createHash, createPublicKey, verify } from "node:crypto";
import { RELEASE_PUBLIC_KEY_PEM } from "./release-key.ts";
import { RELEASE_PARTS } from "./flash-plan.ts";

/**
 * The signed M5 Guardian releases the install page flashes (W07), read on the server because GitHub release assets
 * send no CORS header. Ported from the owner's Doutor VPD website (lib/firmware.ts, MIT, see THIRD_PARTY_NOTICES.md)
 * for the Guardian's G26 release format (tools/release_support.py, tools/release_publish.sh):
 *
 * - `releases/latest/download/manifest.json`, then `manifest.sig` BY THE TAG inside that manifest (never through
 *   `latest`, whose redirects GitHub caches per URL after a publish); ECDSA P-256 over the manifest's exact bytes
 *   with the committed release key (lib/release-key.ts).
 * - The manifest's exact shape: the four parts at 0x0, 0x8000, 0x10000 and 0x20000, each within its slot, the tag
 *   naming the version, the build and the app's sha256.
 * - A part is served only when the signed manifest lists it and its bytes have the listed size and sha256.
 * - Every redirect hop stays on HTTPS and on GitHub's release hosts, at most five hops.
 */
export const RELEASE_REPO = "fcavalcantirj/m5-guardian";
export const RELEASES_URL = `https://github.com/${RELEASE_REPO}/releases`;
const ALLOWED_HOSTS = new Set(["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);
const MAX_REDIRECT_HOPS = 5;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const TIMEOUT_MS = 20_000;
const MANIFEST_MAX = 4096;
const SIGNATURE_MAX = 512;
const ASSET_MAX = 4 * 1024 * 1024; // the app slot is 3 MiB
const NOTES_MAX = 1000;

const TAG_RE = /^guardian-(\d+\.\d+\.\d+)-b([1-9]\d{0,8})-([0-9a-f]{12})$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const KEYS = ["build", "date", "notes", "parts", "tag", "version"];
const PART_KEYS = ["file", "offset", "sha256", "size"];

export type FirmwareErrorKind =
  | "no-release"
  | "not-found"
  | "unavailable"
  | "bad-signature"
  | "bad-manifest"
  | "mismatch"
  | "refused";

export class FirmwareError extends Error {
  readonly kind: FirmwareErrorKind;
  constructor(kind: FirmwareErrorKind, message: string) {
    super(message);
    this.kind = kind;
    this.name = "FirmwareError";
  }
}

export type FirmwarePart = { file: string; offset: number; sha256: string; size: number };
export type FirmwareRelease = {
  tag: string;
  version: string;
  build: number;
  date: string;
  notes: string;
  parts: FirmwarePart[];
};

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;
export type ReleaseOptions = { fetch?: Fetch; publicKeyPem?: string };

function fail(kind: FirmwareErrorKind, message: string): never {
  throw new FirmwareError(kind, message);
}

export const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/** SHA-256 of the key's DER SubjectPublicKeyInfo, as release/release-public-key.json records it. */
export function keyFingerprint(publicKeyPem = RELEASE_PUBLIC_KEY_PEM): string {
  return sha256Hex(createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }));
}

/** True only when `signature` (DER, as `openssl dgst -sha256 -sign` writes it) verifies over the exact bytes. */
export function verifySignature(manifest: Uint8Array, signature: Uint8Array, publicKeyPem = RELEASE_PUBLIC_KEY_PEM): boolean {
  if (signature.length === 0) return false;
  try {
    return verify("sha256", manifest, createPublicKey(publicKeyPem), signature);
  } catch {
    return false;
  }
}

const allowed = (url: URL) => url.protocol === "https:" && ALLOWED_HOSTS.has(url.hostname);

/** GET following redirects by hand while every hop stays on HTTPS and GitHub's release hosts. */
export async function fetchAllowlisted(url: string, fetchImpl: Fetch = fetch): Promise<Response> {
  let current = new URL(url);
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    if (!allowed(current)) fail("refused", `host not allowed: ${current.protocol}//${current.host}`);
    let res: Response;
    try {
      res = await fetchImpl(current.toString(), { redirect: "manual", cache: "no-store", signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (error) {
      fail("unavailable", `GitHub did not answer: ${String(error)}`);
    }
    if (!REDIRECTS.has(res.status)) return res;
    const location = res.headers.get("location");
    if (!location) fail("unavailable", `redirect without a location from ${current.host}`);
    current = new URL(location, current);
  }
  fail("refused", "too many redirects");
}

/** The body, refusing anything larger than `max` before and after reading it. */
async function body(res: Response, what: string, max: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > max) fail("refused", `${what}: too large (${declared} bytes)`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (bytes.length > max) fail("refused", `${what}: too large (${bytes.length} bytes)`);
  return bytes;
}

/** One release asset; a 404 is `missing`, anything else but 200 is 'unavailable'. */
async function asset(path: string, fetchImpl: Fetch, max: number, missing: FirmwareErrorKind = "unavailable") {
  const res = await fetchAllowlisted(`${RELEASES_URL}/${path}`, fetchImpl);
  if (res.status === 404) fail(missing, `${path}: 404`);
  if (res.status !== 200) fail("unavailable", `${path}: HTTP ${res.status}`);
  return body(res, path, max);
}

const sameKeys = (value: unknown, keys: string[]) =>
  typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).sort().join() === keys.join();

/** The manifest's exact shape (tools/release_support.py parse_manifest plus the slot sizes); anything else is refused. */
export function parseManifest(bytes: Uint8Array): FirmwareRelease {
  if (bytes.length > MANIFEST_MAX) fail("bad-manifest", "manifest larger than 4 KiB");
  let m: Record<string, unknown>;
  try {
    m = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail("bad-manifest", "manifest is not JSON");
  }
  if (!sameKeys(m, KEYS)) fail("bad-manifest", "manifest keys must be tag, version, build, date, notes, parts");
  const { tag, version, build, date, notes, parts } = m;
  const match = typeof tag === "string" ? TAG_RE.exec(tag) : null;
  if (!match) fail("bad-manifest", `manifest tag ${JSON.stringify(tag)} is not guardian-<x.y.z>-b<n>-<sha12>`);
  if (match[1] !== version || !Number.isSafeInteger(build) || match[2] !== String(build))
    fail("bad-manifest", "manifest tag, version and build disagree");
  if (typeof date !== "string" || !DATE_RE.test(date)) fail("bad-manifest", "manifest date must be YYYY-MM-DD");
  if (typeof notes !== "string" || !notes.trim() || notes.length > NOTES_MAX) fail("bad-manifest", `manifest notes must be 1 to ${NOTES_MAX} characters`);
  if (!Array.isArray(parts) || parts.length !== RELEASE_PARTS.length) fail("bad-manifest", "manifest must list the four parts");
  const out: FirmwarePart[] = [];
  for (const [i, want] of RELEASE_PARTS.entries()) {
    const p = parts[i] as Record<string, unknown>;
    if (!sameKeys(p, PART_KEYS) || p.file !== want.file || p.offset !== want.offset)
      fail("bad-manifest", `manifest part ${i + 1} is not ${want.file} at 0x${want.offset.toString(16)}`);
    if (typeof p.sha256 !== "string" || !SHA_RE.test(p.sha256) || !Number.isSafeInteger(p.size) || (p.size as number) <= 0)
      fail("bad-manifest", `manifest part ${want.file}: bad sha256 or size`);
    if ((p.size as number) > want.max) fail("bad-manifest", `manifest part ${want.file}: larger than its slot`);
    out.push({ file: want.file, offset: want.offset, sha256: p.sha256, size: p.size as number });
  }
  if (out[3].sha256.slice(0, 12) !== match[3]) fail("bad-manifest", "manifest tag does not name the app part");
  return { tag: match[0], version: match[1], build: build as number, date, notes, parts: out };
}

function verified(manifest: Uint8Array, signature: Uint8Array, tag: string, publicKeyPem?: string): FirmwareRelease {
  if (!verifySignature(manifest, signature, publicKeyPem)) fail("bad-signature", `${tag}: manifest.sig does not verify with the release key`);
  const release = parseManifest(manifest);
  if (release.tag !== tag) fail("bad-manifest", `the manifest names ${release.tag}, not ${tag}`);
  return release;
}

/** One verified release: its manifest and signature fetched by tag. */
export async function releaseByTag(tag: string, options: ReleaseOptions = {}): Promise<FirmwareRelease> {
  const fetchImpl = options.fetch ?? fetch;
  if (!TAG_RE.test(tag)) fail("not-found", "not a release tag");
  const manifest = await asset(`download/${tag}/manifest.json`, fetchImpl, MANIFEST_MAX, "not-found");
  return verified(manifest, await asset(`download/${tag}/manifest.sig`, fetchImpl, SIGNATURE_MAX), tag, options.publicKeyPem);
}

/** The latest release, read like the stick: the manifest through latest, its signature by the tag inside it. */
export async function latestRelease(options: ReleaseOptions = {}): Promise<FirmwareRelease> {
  const fetchImpl = options.fetch ?? fetch;
  const manifest = await asset("latest/download/manifest.json", fetchImpl, MANIFEST_MAX, "no-release");
  const tag = parseManifest(manifest).tag;
  return verified(manifest, await asset(`download/${tag}/manifest.sig`, fetchImpl, SIGNATURE_MAX), tag, options.publicKeyPem);
}

/** One part of a verified release, only when its bytes have the signed size and sha256. */
export async function releaseFile(tag: string, file: string, options: ReleaseOptions = {}): Promise<Uint8Array> {
  const release = await releaseByTag(tag, options);
  const part = release.parts.find((p) => p.file === file);
  if (!part) fail("not-found", `${file} is not a part of ${tag}`);
  const bytes = await asset(`download/${tag}/${part.file}`, options.fetch ?? fetch, ASSET_MAX);
  if (bytes.length !== part.size || sha256Hex(bytes) !== part.sha256)
    fail("mismatch", `${file}: the bytes differ from the signed manifest`);
  return bytes;
}
