import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// W05 quality gates: these checks keep the gate files honest. They read the
// files as text; the gates themselves run in scripts/check.sh, the browser
// suite under e2e/ and scripts/lighthouse.mjs.

const site = new URL("..", import.meta.url).pathname;
const repo = new URL("../..", import.meta.url).pathname;
const read = (path: string) => readFileSync(path, "utf8");
const pkg = JSON.parse(read(join(site, "package.json")));
const workflowPath = join(repo, ".github/workflows/website-checks.yml");

function walk(dir: string, keep: (name: string) => boolean): string[] {
  return readdirSync(dir).flatMap((name) => {
    if (name === "node_modules" || name.startsWith(".")) return [];
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path, keep) : keep(name) ? [path] : [];
  });
}

/** The `paths:` lists of the workflow's push and pull_request triggers. */
function triggerPaths(text: string): Record<string, string[]> {
  const lists: Record<string, string[]> = {};
  let event = "";
  let inPaths = false;
  for (const line of text.split("\n")) {
    const eventMatch = /^ {2}(\w+):/.exec(line);
    if (eventMatch) {
      event = eventMatch[1];
      inPaths = false;
      continue;
    }
    if (/^ {4}paths:\s*$/.test(line)) {
      inPaths = true;
      lists[event] = [];
      continue;
    }
    const item = /^ {6}- "?([^"]+)"?\s*$/.exec(line);
    if (inPaths && item) lists[event].push(item[1]);
    else if (inPaths && /^ {4}\S/.test(line)) inPaths = false;
    if (/^\S/.test(line) && !line.startsWith("on:")) event = "";
  }
  return lists;
}

test("the test command discovers every unit test file, not a fixed list", () => {
  const script: string = pkg.scripts.test;
  assert.match(script, /--test\b/);
  assert.match(script, /'\*\*\/\*\.test\.ts'/, "the test script uses the **/*.test.ts glob");
  assert.doesNotMatch(script, /lib\/\w+\.test\.ts/, "no hard-coded test file list");
  const files = walk(site, (name) => name.endsWith(".test.ts"));
  assert.ok(files.length >= 6, `only ${files.length} test files found`);
});

test("the website check script runs typegen, typecheck, tests and the production build", () => {
  const path = join(site, "scripts/check.sh");
  assert.ok(existsSync(path), "website/scripts/check.sh exists");
  assert.ok((statSync(path).mode & 0o111) !== 0, "check.sh is executable");
  const text = read(path);
  assert.match(text, /^#!\/usr\/bin\/env bash/);
  assert.match(text, /set -euo pipefail/);
  for (const step of [/next typegen/, /tsc --noEmit/, /--test/, /next build/])
    assert.match(text, step);
  // Test discovery is checked against the files on disk, not trusted.
  assert.match(text, /junit/);
  assert.match(text, /find /);
  // The pinned toolchain is enforced, so a different Node or pnpm fails loudly.
  assert.match(text, /packageManager/);
  assert.match(text, /v24\./);
});

test("the root Makefile has a website-check target that runs the check script", () => {
  const text = read(join(repo, "Makefile"));
  assert.match(text, /^website-check:/m);
  assert.match(text, /--frozen-lockfile/);
  assert.match(text, /website\/scripts\/check\.sh|scripts\/check\.sh/);
  assert.match(text, /^\.PHONY:.*website-check/m);
});

test("the website-checks workflow pins Node 24.x and pnpm 12.3.4 with a frozen, lockfile-keyed install", () => {
  assert.ok(existsSync(workflowPath), ".github/workflows/website-checks.yml exists");
  const text = read(workflowPath);
  assert.match(text, /^name: website-checks$/m);
  assert.match(text, /node-version: "?24\.x"?/);
  assert.match(text, /pnpm\/action-setup@[0-9a-f]{40}/);
  assert.match(text, /package_json_file: website\/package\.json/);
  assert.equal(pkg.packageManager, "pnpm@12.3.4");
  assert.match(text, /cache: pnpm/);
  assert.match(text, /cache-dependency-path: website\/pnpm-lock\.yaml/);
  assert.match(text, /pnpm install --frozen-lockfile/);
  assert.match(text, /workflow_dispatch:/);
  // Every third-party action is pinned to a full commit.
  for (const use of text.matchAll(/uses: (\S+)/g))
    assert.match(use[1], /@[0-9a-f]{40}$/, `${use[1]} is pinned to a commit`);
});

test("the workflow runs every gate and keeps failed-check logs and screenshots", () => {
  const text = read(workflowPath);
  for (const step of [
    /make website-check/,
    /playwright install --with-deps chromium/,
    /playwright test/,
    /scripts\/lighthouse\.mjs/,
    /python3 tools\/public_check\.py/,
    /actions\/upload-artifact@/,
    /if: failure\(\)/,
    /test-results/,
  ])
    assert.match(text, step);
});

test("the workflow triggers on website files, itself, the Makefile, check scripts and documentation inputs", () => {
  const text = read(workflowPath);
  const lists = triggerPaths(text);
  assert.deepEqual(Object.keys(lists).sort(), ["pull_request", "push"]);
  assert.deepEqual(lists.push, lists.pull_request, "push and pull_request watch the same paths");
  const paths = lists.push;
  const record = JSON.parse(read(join(site, "claims.json")));
  const documentation = new Set<string>([
    ".github/workflows/website-checks.yml",
    "Makefile",
    "tools/public_check.py",
    "tools/public_check.allow",
    "THIRD_PARTY_NOTICES.md",
    "LICENSE",
    ...record.claims.flatMap((claim: { sources: { path: string }[] }) =>
      claim.sources.map((source) => source.path),
    ),
    ...[...record.documents.coverage, ...record.documents.limitations].map(
      (doc: string) => doc.split("#")[0],
    ),
  ]);
  assert.ok(paths.includes("website/**"), "website/** is watched");
  for (const path of documentation)
    assert.ok(paths.includes(path), `${path} is a trigger path`);
  for (const path of paths)
    if (!path.includes("*")) assert.ok(existsSync(join(repo, path)), `trigger path ${path} exists`);
});

test("browser checks and Lighthouse use pinned tool versions", () => {
  for (const name of ["@playwright/test", "@axe-core/playwright", "lighthouse"])
    assert.match(pkg.devDependencies[name] ?? "", /^\d+\.\d+\.\d+$/, `${name} pinned exactly`);
  const config = read(join(site, "playwright.config.ts"));
  assert.match(config, /testDir: "\.\/e2e"/);
  assert.match(config, /next start/, "browser checks run against the production server");
  assert.match(config, /screenshot: "only-on-failure"/);
  const specs = walk(join(site, "e2e"), (name) => name.endsWith(".spec.ts")).map((path) =>
    relative(site, path),
  );
  for (const spec of [
    "e2e/metadata.spec.ts",
    "e2e/accessibility.spec.ts",
    "e2e/responsive.spec.ts",
    "e2e/three-d.spec.ts",
  ])
    assert.ok(specs.includes(spec), `${spec} exists`);
});

test("the Lighthouse gate records three mobile runs against the ledger thresholds", () => {
  const text = read(join(site, "scripts/lighthouse.mjs"));
  assert.match(text, /RUNS = 3/);
  assert.match(text, /formFactor: "mobile"/);
  for (const threshold of [
    /performance: 0\.9\b/,
    /accessibility: 1\b/,
    /seo: 0\.95\b/,
    /"largest-contentful-paint": 2500\b/,
    /"cumulative-layout-shift": 0\.1\b/,
    /"total-blocking-time": 200\b/,
  ])
    assert.match(text, threshold);
  assert.match(text, /median/);
});

test("browser and Lighthouse output stays out of the tracked tree", () => {
  const ignore = read(join(site, ".gitignore"));
  for (const entry of ["test-results/", "playwright-report/", "lighthouse/", ".cache/"])
    assert.ok(ignore.split("\n").includes(entry), `${entry} ignored`);
});
