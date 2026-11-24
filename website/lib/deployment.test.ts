import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";

// W06 deployment configuration, read as text: website/vercel.json (install,
// build and ignored-build commands), the root .vercelignore (the CLI upload
// set) and the preview Lighthouse workflow. The project settings that live
// only in Vercel (Git repository, production branch, Root Directory, Node
// version) are recorded and verified by the supervisor; see website/DEPLOYMENT.md.

const site = new URL("..", import.meta.url).pathname;
const repo = new URL("../..", import.meta.url).pathname;
const read = (path: string) => readFileSync(path, "utf8");
const vercel = JSON.parse(read(join(site, "vercel.json")));
const previewWorkflow = join(repo, ".github/workflows/website-preview-lighthouse.yml");

test("vercel.json: Next.js, frozen pnpm 12 install through corepack, the quality script as build, the ignore script", () => {
  assert.equal(vercel.framework, "nextjs");
  // Vercel's own pnpm could not read the pnpm 12 lockfile (supervisor, W05); corepack runs the pinned one.
  assert.equal(vercel.installCommand, "corepack pnpm install --frozen-lockfile");
  assert.equal(JSON.parse(read(join(site, "package.json"))).packageManager, "pnpm@12.3.4");
  // check.sh verifies Node 24 and the pnpm version it is given, then typegen, tsc, tests and next build.
  assert.equal(vercel.buildCommand, "PNPM='corepack pnpm' bash scripts/check.sh");
  assert.equal(vercel.ignoreCommand, "bash scripts/vercel-ignore-build.sh");
  for (const script of ["scripts/check.sh", "scripts/vercel-ignore-build.sh"]) {
    assert.ok(existsSync(join(site, script)), `${script} exists`);
    assert.ok((statSync(join(site, script)).mode & 0o111) !== 0, `${script} is executable`);
  }
  // No output directory override: Next's framework output handling stays in charge.
  assert.equal(vercel.outputDirectory, undefined);
  assert.deepEqual(Object.keys(vercel).sort(), ["$schema", "buildCommand", "framework", "ignoreCommand", "installCommand"]);
});

// The Vercel CLI 66.2.0 default upload ignore list (read from the CLI build on
// 2026-11-22). .vercelignore rules are appended after it, gitignore semantics.
const CLI_DEFAULT_IGNORES = [
  ".hg", ".git", ".gitmodules", ".svn", ".cache", ".next", ".now", ".vercel", ".npmignore",
  ".dockerignore", ".gitignore", ".*.swp", ".DS_Store", ".wafpicke-*", ".lock-wscript",
  ".env.local", ".env.*.local", ".venv", ".yarn/cache", ".pnp*", "npm-debug.log",
  "config.gypi", "node_modules", "__pycache__", "venv",
];

/** The `paths:` entries of website-checks.yml (both triggers list the same paths; gates.test.ts checks that). */
function triggerPaths() {
  const text = read(join(repo, ".github/workflows/website-checks.yml"));
  const push = text.split(/^ {2}pull_request:/m)[0];
  return [...push.matchAll(/^ {6}- "?([^"\n]+?)"?\s*$/gm)].map((match) => match[1]);
}

/**
 * Repository files the page links to (`${repositoryUrl}/blob/main/...` and README
 * anchors), found with the pattern lib/claims.test.ts checks them with.
 */
function linkTargets() {
  const targets = new Set<string>();
  for (const dir of ["app", "components", "lib"])
    for (const path of walk(join(site, dir)).filter((p) => /\.tsx?$/.test(p) && !p.endsWith(".test.ts")))
      for (const match of read(path).matchAll(/\$\{repositoryUrl\}(\/blob\/main\/[^`"'\s}#]+|#[^`"'\s}]+)/g))
        targets.add(match[1].startsWith("#") ? "README.md" : match[1].replace("/blob/main/", ""));
  return [...targets].sort();
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    if (name === "node_modules" || name.startsWith(".")) return [];
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

/**
 * Files a CLI deployment from the repository root would upload, out of the
 * given candidates: an empty mirror of the paths, filtered by the CLI defaults
 * plus .vercelignore with Git's own directory walk (a re-included file under
 * an excluded directory stays excluded, as in gitignore).
 */
function uploaded(candidates: string[]) {
  const mirror = mkdtempSync(join(tmpdir(), "vercel-upload-"));
  const rules = join(mirror, "..", `${mirror.split("/").pop()}.rules`);
  try {
    for (const path of candidates) {
      mkdirSync(dirname(join(mirror, path)), { recursive: true });
      writeFileSync(join(mirror, path), "");
    }
    writeFileSync(rules, `${CLI_DEFAULT_IGNORES.join("\n")}\n${read(join(repo, ".vercelignore"))}`);
    const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
    assert.equal(spawnSync("git", ["init", "-q", mirror], { env }).status, 0, "git init");
    const result = spawnSync("git", ["-C", mirror, "ls-files", "--others", `--exclude-from=${rules}`, "-z"], { env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return new Set(result.stdout.split("\0").filter(Boolean));
  } finally {
    rmSync(mirror, { recursive: true, force: true });
    rmSync(rules, { force: true });
  }
}

test(".vercelignore uploads the website and every repository file its quality script reads, nothing else", () => {
  const websiteOutputs = /^website\/(test-results|playwright-report|lighthouse|out)\/|\.tsbuildinfo$/;
  const website = walk(site)
    .map((path) => relative(repo, path))
    .filter((path) => !websiteOutputs.test(path));
  const links = linkTargets();
  assert.ok(links.includes("firmware/README.md") && links.includes("README.md"), links.join(" "));
  const outside = [...triggerPaths().filter((path) => !path.includes("*")), ...links];
  const required = [
    ...website,
    "website/.gitignore",
    ".vercelignore",
    ".github/workflows/website-preview-lighthouse.yml",
    ...outside,
  ];
  for (const path of required) assert.ok(existsSync(join(repo, path)), `${path} exists`);
  assert.ok(website.includes("website/package.json") && website.includes("website/vercel.json"));

  const excluded = [
    "package.json",
    "ralph.sh",
    "website-tasks.json",
    "AGENTS.md",
    "docs/roadmap.md",
    "tools/ralph_runner.py",
    "firmware/boards/README.md",
    "firmware/boards/sticks3/main/main.cpp",
    "firmware/components/guardian_core/core.cpp",
    "firmware/components/guardian_core/include/guardian/other.hpp",
    "firmware/art/persona.blend",
    "lab/receiver/main.c",
    "archive/notes.md",
    ".github/workflows/other.yml",
    ".env",
    ".vercel/project.json",
    "website/.env",
    "website/.env.production",
    "website/.vercel/project.json",
    "website/.next/BUILD_ID",
    "website/.cache/website-check/unit-tests.junit.xml",
    "website/node_modules/next/package.json",
    "website/test-results/results.json",
    "website/playwright-report/index.html",
    "website/lighthouse/summary.json",
    "website/tsconfig.tsbuildinfo",
  ];
  const upload = uploaded([...required, ...excluded]);
  for (const path of required) assert.ok(upload.has(path), `${path} is uploaded`);
  for (const path of excluded) assert.ok(!upload.has(path), `${path} is not uploaded`);
  // The source resolves website/package.json exactly once.
  assert.deepEqual([...upload].filter((path) => path.endsWith("package.json")), ["website/package.json"]);
});

test("website-checks.yml reruns the unit tests when the deployment files or linked repository files change", () => {
  const paths = triggerPaths();
  for (const path of [".vercelignore", ".github/workflows/website-preview-lighthouse.yml", ...linkTargets()])
    assert.ok(
      paths.includes(path) || paths.some((glob) => glob.endsWith("/**") && path.startsWith(glob.slice(0, -2))),
      `${path} is a website-checks trigger path`,
    );
});

test("the preview Lighthouse gate runs on successful Vercel Preview deployments with the bypass secret", () => {
  const text = read(previewWorkflow);
  assert.match(text, /^on:\n {2}deployment_status:\n/m);
  assert.match(text, /github\.event\.deployment_status\.state == 'success'/);
  assert.match(text, /startsWith\(github\.event\.deployment\.environment, 'Preview'\)/);
  assert.match(text, /github\.event\.deployment_status\.creator\.login == 'vercel\[bot\]'/);
  assert.match(text, /^permissions:\n {2}contents: read$/m);
  // The deployed commit is the one measured, with the same script and thresholds as W05.
  assert.match(text, /ref: \$\{\{ github\.event\.deployment\.sha \}\}/);
  assert.match(text, /node scripts\/lighthouse\.mjs/);
  assert.match(text, /LIGHTHOUSE_URL: \$\{\{ env\.DEPLOYMENT_URL \}\}/);
  assert.match(text, /LIGHTHOUSE_PREVIEW: "1"/);
  assert.match(text, /pnpm install --frozen-lockfile/);
  assert.match(text, /node-version: "24\.x"/);
  // The secret goes only to this project's vercel.app hosts, and only into the Lighthouse step.
  assert.match(text, /\^m5-guardian-\[a-z0-9-\]\+\\\.vercel\\\.app\$/);
  const uses = [...text.matchAll(/secrets\.VERCEL_AUTOMATION_BYPASS_SECRET/g)];
  assert.equal(uses.length, 2, "one presence check and one Lighthouse step");
  assert.match(text, /HAS_BYPASS: \$\{\{ secrets\.VERCEL_AUTOMATION_BYPASS_SECRET != '' \}\}/);
  assert.match(text, /LIGHTHOUSE_BYPASS: \$\{\{ secrets\.VERCEL_AUTOMATION_BYPASS_SECRET \}\}/);
  assert.doesNotMatch(text.split("LIGHTHOUSE_BYPASS:")[0], /^ {6}LIGHTHOUSE_BYPASS/m);
  for (const use of text.matchAll(/uses: (\S+)/g))
    assert.match(use[1], /@[0-9a-f]{40}$/, `${use[1]} is pinned to a commit`);
});

// 2026-11-23, measured on a Git deployment: with only "/*" the Git build deleted .git, the ignored build
// step printed "the website is not a Git checkout" and built a firmware-only commit. .git must stay.
test(".vercelignore keeps .git so the ignored build step can compare commits on Git deployments", () => {
  const lines = read(join(repo, ".vercelignore")).split("\n").map((l) => l.trim());
  const dropAll = lines.indexOf("/*");
  const keepGit = lines.indexOf("!/.git");
  assert.ok(dropAll >= 0, "the upload set starts from /*");
  assert.ok(keepGit > dropAll, "!/.git must follow /*");
});

// W08: next.config.mjs reads release/version.txt when the build starts (the JSON-LD softwareVersion) and a
// missing file fails the build, so every upload must carry it, and website-checks must rerun when it changes.
test("the upload carries release/version.txt (read by next.config at build time), nothing else of release/", () => {
  const upload = uploaded(["release/version.txt", "release/release-public-key.json", "website/next.config.mjs"]);
  assert.ok(upload.has("release/version.txt"), "release/version.txt is uploaded: add !/release, /release/* and !/release/version.txt to .vercelignore");
  assert.ok(!upload.has("release/release-public-key.json"), "the rest of release/ stays out");
  assert.ok(triggerPaths().includes("release/version.txt"), "release/version.txt is a website-checks trigger path");
});
