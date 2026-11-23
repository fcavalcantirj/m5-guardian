import { FirmwareError, latestRelease, releaseFile, sha256Hex, type FirmwareErrorKind, type ReleaseOptions } from "./firmware-release.ts";

/**
 * The two firmware routes of the install page (W07), as plain handlers so the unit tests run them with a mocked
 * fetch (lib/firmware-routes.test.ts). app/api/firmware/latest/route.ts and app/api/firmware/[tag]/[file]/route.ts
 * only call them.
 */
const STATUS: Record<FirmwareErrorKind, number> = {
  "no-release": 404,
  "not-found": 404,
  unavailable: 503,
  "bad-signature": 502,
  "bad-manifest": 502,
  mismatch: 502,
  refused: 502,
};

const MESSAGE: Record<FirmwareErrorKind, string> = {
  "no-release": "No release has been published yet. The install page will offer it as soon as the first signed release is out.",
  "not-found": "That firmware file is not part of a signed release.",
  unavailable: "GitHub did not answer just now. Try again in a moment.",
  "bad-signature": "The signature of this release does not verify. Nothing was sent.",
  "bad-manifest": "The data of this release is not valid. Nothing was sent.",
  mismatch: "The file does not match the signed release. Nothing was sent.",
  refused: "A download address was refused. Nothing was sent.",
};

/** A firmware error as JSON the flasher shows; never cached. Details go to the server log only. */
export function firmwareErrorResponse(error: unknown): Response {
  const kind: FirmwareErrorKind = error instanceof FirmwareError ? error.kind : "unavailable";
  if (kind !== "no-release" && kind !== "not-found") console.error("firmware:", kind, String(error));
  return Response.json({ kind, error: MESSAGE[kind] }, { status: STATUS[kind], headers: { "Cache-Control": "no-store" } });
}

/** GET /api/firmware/latest: the verified latest release; the CDN keeps it 60 s. */
export async function latestResponse(options?: ReleaseOptions): Promise<Response> {
  try {
    const r = await latestRelease(options);
    const parts = r.parts.map((p) => ({ ...p, url: `/api/firmware/${r.tag}/${p.file}` }));
    return Response.json(
      { tag: r.tag, version: r.version, build: r.build, date: r.date, notes: r.notes, parts },
      { headers: { "Cache-Control": "public, s-maxage=60, stale-while-revalidate=300" } },
    );
  } catch (error) {
    return firmwareErrorResponse(error);
  }
}

/** GET /api/firmware/[tag]/[file]: one part of a verified release; a tag never changes, so a year of cache. */
export async function fileResponse(tag: string, file: string, options?: ReleaseOptions): Promise<Response> {
  try {
    const bytes = await releaseFile(tag, file, options);
    return new Response(bytes as BodyInit, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(bytes.length),
        "Cache-Control": "public, max-age=31536000, s-maxage=31536000, immutable",
        "X-Content-SHA256": sha256Hex(bytes),
      },
    });
  } catch (error) {
    return firmwareErrorResponse(error);
  }
}
