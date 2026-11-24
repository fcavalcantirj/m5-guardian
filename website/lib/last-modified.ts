import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";

// Sitemap lastmod (W08): the committer date of the newest commit that touched a
// page's source files, read from Git when the sitemap is generated (build time).
// No answer is better than a wrong one, so the date is left out when:
// - there is no Git (a Vercel CLI deployment uploads no .git),
// - the files were never committed, or
// - the clone is shallow (Vercel clones 10 commits deep) and the newest commit
//   Git names is the clone's boundary, which only appears to add every file.

/** Source files (website-relative Git pathspecs) behind each sitemap page. */
export const pageSources = {
  "/": [
    "app/page.tsx",
    "app/layout.tsx",
    "app/globals.css",
    "components",
    ":(exclude)components/install",
    "lib/guardian.ts",
    "lib/viewer.ts",
    "public/images",
    "public/models",
  ],
  "/install": [
    "app/install",
    "app/layout.tsx",
    "app/globals.css",
    "components/install",
    "components/site-header.tsx",
    "components/site-footer.tsx",
    "lib/flash-plan.ts",
  ],
} as const satisfies Record<string, readonly string[]>;

const git = (cwd: string, args: string[]) =>
  execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

/** Commit ids at the boundary of a shallow clone (empty for a full clone). */
function shallowBoundary(cwd: string) {
  let path = git(cwd, ["rev-parse", "--git-path", "shallow"]);
  if (!isAbsolute(path)) path = join(cwd, path);
  return existsSync(path) ? new Set(readFileSync(path, "utf8").split("\n").filter(Boolean)) : new Set<string>();
}

export function lastCommitDate(paths: readonly string[], cwd: string): Date | undefined {
  try {
    const line = git(cwd, ["log", "-1", "--format=%H %cI", "--", ...paths]);
    if (!line) return undefined;
    const [id, date] = line.split(" ");
    if (shallowBoundary(cwd).has(id)) return undefined;
    const parsed = new Date(date);
    return Number.isNaN(parsed.getTime()) ? undefined : parsed;
  } catch {
    return undefined;
  }
}
