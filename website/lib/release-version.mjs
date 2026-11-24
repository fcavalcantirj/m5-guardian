// The public release number from release/version.txt (G26), read by next.config.mjs when the build starts
// and handed to the page as GUARDIAN_RELEASE_VERSION (the JSON-LD softwareVersion). A missing or malformed
// file fails the build: the page never shows a guessed version.
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** @param {string} text */
export function parseReleaseVersion(text) {
  const matches = [...text.matchAll(/^version=(.*)$/gm)];
  if (matches.length > 1) throw new Error("release/version.txt: more than one version= line");
  const value = matches[0]?.[1].trim();
  if (!value) throw new Error("release/version.txt: no version= line");
  if (!/^\d+\.\d+\.\d+$/.test(value)) throw new Error(`release/version.txt: ${value} is not a release version (x.y.z)`);
  return value;
}

/** @param {string} repoRoot the repository root (website/..) */
export function readReleaseVersion(repoRoot) {
  const path = join(repoRoot, "release/version.txt");
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    throw new Error(`release/version.txt cannot be read at ${path}: ${error instanceof Error ? error.message : error}`);
  }
  return parseReleaseVersion(text);
}
