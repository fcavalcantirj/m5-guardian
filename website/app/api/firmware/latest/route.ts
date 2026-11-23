import { latestResponse } from "@/lib/firmware-routes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The latest signed Guardian release, verified on the server (lib/firmware-release.ts). */
export async function GET() {
  return latestResponse();
}
