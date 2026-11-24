import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { lastCommitDate, pageSources } from "./last-modified.ts";

// W08 sitemap lastmod: the commit date of the last commit that touched a page's
// source files, read from Git at build time. Without a usable answer (no Git,
// files never committed, or a shallow clone whose boundary hides the real date)
// the date is left out rather than guessed. Each case runs real Git in a
// throwaway repository.

const site = new URL("..", import.meta.url).pathname;
const gitEnv: NodeJS.ProcessEnv = {
  NODE_ENV: "test",
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  HOME: tmpdir(),
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "test",
  GIT_AUTHOR_EMAIL: "test",
  GIT_COMMITTER_NAME: "test",
  GIT_COMMITTER_EMAIL: "test",
};

function git(repo: string, args: string[], date?: string) {
  const env = date ? { ...gitEnv, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : gitEnv;
  const result = spawnSync("git", ["-C", repo, ...args], { env, encoding: "utf8" });
  assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}

function commitFile(repo: string, path: string, text: string, date: string) {
  mkdirSync(dirname(join(repo, path)), { recursive: true });
  writeFileSync(join(repo, path), text);
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", path], date);
}

function withRepo(run: (repo: string) => void) {
  const repo = mkdtempSync(join(tmpdir(), "lastmod-"));
  try {
    git(repo, ["init", "-q", "-b", "main"]);
    run(repo);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
}

test("the date is the committer date of the newest commit touching any of the files", () =>
  withRepo((repo) => {
    commitFile(repo, "website/app/page.tsx", "a", "2026-11-01T10:00:00Z");
    commitFile(repo, "website/app/install/page.tsx", "b", "2026-11-05T10:00:00Z");
    commitFile(repo, "firmware/main.c", "c", "2026-11-09T10:00:00Z");
    commitFile(repo, "website/components/x.tsx", "d", "2026-11-03T10:00:00Z");
    const site = join(repo, "website");
    assert.equal(lastCommitDate(["app/page.tsx", "components"], site)?.toISOString(), "2026-11-03T10:00:00.000Z");
    assert.equal(lastCommitDate(["app/install"], site)?.toISOString(), "2026-11-05T10:00:00.000Z");
    assert.equal(lastCommitDate(["app/page.tsx"], site)?.toISOString(), "2026-11-01T10:00:00.000Z");
  }));

test("excluded paths do not count", () =>
  withRepo((repo) => {
    commitFile(repo, "website/components/a.tsx", "a", "2026-11-01T10:00:00Z");
    commitFile(repo, "website/components/install/flasher.tsx", "b", "2026-11-07T10:00:00Z");
    const site = join(repo, "website");
    assert.equal(lastCommitDate(["components", ":(exclude)components/install"], site)?.toISOString(), "2026-11-01T10:00:00.000Z");
  }));

test("no Git, or files never committed: no date", () => {
  const bare = mkdtempSync(join(tmpdir(), "lastmod-nogit-"));
  try {
    writeFileSync(join(bare, "page.tsx"), "x");
    assert.equal(lastCommitDate(["page.tsx"], bare), undefined);
  } finally {
    rmSync(bare, { recursive: true, force: true });
  }
  withRepo((repo) => {
    commitFile(repo, "website/app/page.tsx", "a", "2026-11-01T10:00:00Z");
    assert.equal(lastCommitDate(["app/never-committed.tsx"], join(repo, "website")), undefined);
  });
});

test("a shallow clone gives the date only when the last change is inside the clone's history", () =>
  withRepo((origin) => {
    commitFile(origin, "website/app/page.tsx", "old", "2026-10-01T10:00:00Z");
    for (let i = 0; i < 3; i++) commitFile(origin, `firmware/f${i}.c`, `${i}`, `2026-10-1${i}T10:00:00Z`);
    commitFile(origin, "website/app/install/page.tsx", "new", "2026-11-01T10:00:00Z");
    const clone = mkdtempSync(join(tmpdir(), "lastmod-shallow-"));
    try {
      const result = spawnSync("git", ["clone", "-q", "--depth", "2", `file://${origin}`, clone], { env: gitEnv, encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      const site = join(clone, "website");
      // Inside the 2-commit history: exact.
      assert.equal(lastCommitDate(["app/install"], site)?.toISOString(), "2026-11-01T10:00:00.000Z");
      // Older than the clone: Git would name the boundary commit, which did not change it. Left out.
      assert.equal(lastCommitDate(["app/page.tsx"], site), undefined);
    } finally {
      rmSync(clone, { recursive: true, force: true });
    }
  }));

test("each sitemap page names its own source files, all of which exist", () => {
  assert.deepEqual(Object.keys(pageSources), ["/", "/install"]);
  for (const [page, paths] of Object.entries(pageSources) as [string, readonly string[]][]) {
    assert.ok(paths.length > 0, page);
    for (const path of paths.filter((p) => !p.startsWith(":("))) {
      const result = spawnSync("test", ["-e", join(site, path)]);
      assert.equal(result.status, 0, `${page}: ${path} exists`);
    }
  }
  assert.ok(pageSources["/"].includes("app/page.tsx"));
  assert.ok(pageSources["/install"].includes("app/install"));
});

test("the sitemap takes lastModified from the page sources and keeps both URLs", () => {
  const sitemap = readFileSync(join(site, "app/sitemap.ts"), "utf8");
  assert.match(sitemap, /lastCommitDate\(pageSources\[/);
  assert.match(sitemap, /\$\{siteUrl\}\/install/);
});
