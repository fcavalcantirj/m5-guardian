import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Where e2e/remote-setup.ts keeps Vercel's bypass cookie for a protected
 * deployment (W06): a fresh file in the OS temp folder, outside the tree and
 * outside the test-results/ and playwright-report/ folders that CI uploads.
 * Chosen once in the runner process; workers inherit it through the environment.
 */
process.env.WEBSITE_BYPASS_STATE ??= join(tmpdir(), `m5-guardian-bypass-${randomUUID()}.json`);
export const bypassStatePath = process.env.WEBSITE_BYPASS_STATE;
