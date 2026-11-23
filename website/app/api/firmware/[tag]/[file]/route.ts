import { fileResponse } from "@/lib/firmware-routes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** One part of a signed release, same-origin for the browser flasher, only with the signed sha256. */
export async function GET(_request: Request, { params }: { params: Promise<{ tag: string; file: string }> }) {
  const { tag, file } = await params;
  return fileResponse(tag, file);
}
