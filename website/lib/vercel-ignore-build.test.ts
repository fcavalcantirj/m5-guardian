import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

// W06: the Ignored Build Step (scripts/vercel-ignore-build.sh). Vercel runs it
// in the Root Directory (website/) with VERCEL_GIT_COMMIT_SHA and
// VERCEL_GIT_PREVIOUS_SHA (the last successful deployment of the branch).
// Exit 0 skips the build (Vercel records the deployment as CANCELED);
// exit 1 builds. Only a change set with nothing under website/ may skip.
// Each case runs the real script copied into a throwaway Git repository.

const script = new URL("../scripts/vercel-ignore-build.sh", import.meta.url).pathname;

// Isolated Git: no user or system configuration (signing, hooks, templates).
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

function git(repo: string, ...args: string[]) {
  const result = spawnSync("git", ["-C", repo, ...args], { env: gitEnv, encoding: "utf8" });
  assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}

function write(repo: string, path: string, text: string) {
  mkdirSync(dirname(join(repo, path)), { recursive: true });
  writeFileSync(join(repo, path), text);
}

/** Commits everything and returns the commit id. */
function commit(repo: string, message: string) {
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "--allow-empty", "-m", message);
  return git(repo, "rev-parse", "HEAD");
}

/** A repository shaped like this one: website/ (with the script) and firmware/. */
function makeRepo() {
  const repo = mkdtempSync(join(tmpdir(), "vercel-ignore-"));
  git(repo, "init", "-q", "-b", "main");
  mkdirSync(join(repo, "website/scripts"), { recursive: true });
  copyFileSync(script, join(repo, "website/scripts/vercel-ignore-build.sh"));
  write(repo, "website/page.txt", "page\n");
  write(repo, "website/old-name.txt", "old\n");
  write(repo, "firmware/main.c", "int main(void) { return 0; }\n");
  write(repo, "firmware/notes.txt", "notes\n");
  const base = commit(repo, "base");
  return { repo, base, cleanup: () => rmSync(repo, { recursive: true, force: true }) };
}

/** Runs the copied script the way Vercel does: bash, from the Root Directory. */
function decide(repo: string, env: Record<string, string>, cwd = join(repo, "website")) {
  const result = spawnSync("bash", [join(repo, "website/scripts/vercel-ignore-build.sh")], {
    cwd,
    env: { ...gitEnv, ...env },
    encoding: "utf8",
  });
  return { code: result.status, out: `${result.stdout}${result.stderr}` };
}

const SKIP = 0;
const BUILD = 1;

function expectDecision(
  outcome: { code: number | null; out: string },
  code: number,
  reason: RegExp,
) {
  assert.equal(outcome.code, code, outcome.out);
  assert.match(outcome.out, code === SKIP ? /SKIP/ : /BUILD/);
  assert.match(outcome.out, reason);
}

test("a firmware-only change is skipped (exit 0)", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    write(repo, "firmware/main.c", "int main(void) { return 1; }\n");
    write(repo, "firmware/new.c", "\n");
    const head = commit(repo, "firmware only");
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: head, VERCEL_GIT_PREVIOUS_SHA: base }),
      SKIP,
      /no change under website\//,
    );
  } finally {
    cleanup();
  }
});

test("the decision is the same when run from the Git root", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    write(repo, "firmware/main.c", "changed\n");
    const head = commit(repo, "firmware only");
    const env = { VERCEL_GIT_COMMIT_SHA: head, VERCEL_GIT_PREVIOUS_SHA: base };
    assert.equal(decide(repo, env, repo).code, SKIP);
    write(repo, "website/page.txt", "changed\n");
    const site = commit(repo, "website");
    assert.equal(decide(repo, { ...env, VERCEL_GIT_COMMIT_SHA: site }, repo).code, BUILD);
  } finally {
    cleanup();
  }
});

for (const [name, change] of [
  ["an addition", (repo: string) => write(repo, "website/added.txt", "new\n")],
  ["a modification", (repo: string) => write(repo, "website/page.txt", "changed\n")],
  ["a deletion", (repo: string) => rmSync(join(repo, "website/page.txt"))],
  ["a rename inside website/", (repo: string) => renameSync(join(repo, "website/old-name.txt"), join(repo, "website/new-name.txt"))],
  ["a rename out of website/", (repo: string) => renameSync(join(repo, "website/old-name.txt"), join(repo, "firmware/old-name.txt"))],
  ["a rename into website/", (repo: string) => renameSync(join(repo, "firmware/notes.txt"), join(repo, "website/notes.txt"))],
  ["a change to the ignore script itself", (repo: string) => write(repo, "website/scripts/vercel-ignore-build.sh", "# edited\n")],
] as const) {
  test(`a website change builds (exit 1): ${name}`, () => {
    const { repo, base, cleanup } = makeRepo();
    try {
      change(repo);
      write(repo, "firmware/main.c", "also firmware\n");
      const head = commit(repo, name);
      // The edited copy of the script would decide for itself; run the original instead.
      copyFileSync(script, join(repo, "website/scripts/vercel-ignore-build.sh"));
      expectDecision(
        decide(repo, { VERCEL_GIT_COMMIT_SHA: head, VERCEL_GIT_PREVIOUS_SHA: base }),
        BUILD,
        /website\//,
      );
    } finally {
      cleanup();
    }
  });
}

test("a website change followed by a firmware-only commit still builds against the last deployment", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    write(repo, "website/page.txt", "website change\n");
    const websiteCommit = commit(repo, "website");
    write(repo, "firmware/main.c", "firmware after\n");
    const firmwareCommit = commit(repo, "firmware only");
    // Last deployment is the base (the website commit was never deployed): build.
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: firmwareCommit, VERCEL_GIT_PREVIOUS_SHA: base }),
      BUILD,
      /website\/page\.txt/,
    );
    // Once the website commit is the last deployment, the firmware-only commit skips.
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: firmwareCommit, VERCEL_GIT_PREVIOUS_SHA: websiteCommit }),
      SKIP,
      /no change under website\//,
    );
  } finally {
    cleanup();
  }
});

test("the first deployment of a branch builds (no previous commit)", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    expectDecision(decide(repo, { VERCEL_GIT_COMMIT_SHA: base }), BUILD, /first deployment/);
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: base, VERCEL_GIT_PREVIOUS_SHA: "" }),
      BUILD,
      /first deployment/,
    );
  } finally {
    cleanup();
  }
});

test("a missing current commit id builds", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    expectDecision(decide(repo, { VERCEL_GIT_PREVIOUS_SHA: base }), BUILD, /VERCEL_GIT_COMMIT_SHA/);
  } finally {
    cleanup();
  }
});

test("a commit absent from the clone builds (shallow clone or rewritten history)", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    const absent = "0123456789abcdef0123456789abcdef01234567";
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: base, VERCEL_GIT_PREVIOUS_SHA: absent }),
      BUILD,
      /not in this clone/,
    );
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: absent, VERCEL_GIT_PREVIOUS_SHA: base }),
      BUILD,
      /not in this clone/,
    );
  } finally {
    cleanup();
  }
});

test("in a depth-10 clone like Vercel's, an older last deployment builds and a recent one decides", () => {
  const { repo, base, cleanup } = makeRepo();
  const clone = mkdtempSync(join(tmpdir(), "vercel-ignore-clone-"));
  try {
    let recent = base;
    for (let i = 1; i <= 12; i++) {
      write(repo, "firmware/main.c", `revision ${i}\n`);
      const id = commit(repo, `firmware ${i}`);
      if (i === 10) recent = id;
    }
    const head = git(repo, "rev-parse", "HEAD");
    const result = spawnSync("git", ["clone", "-q", "--depth=10", `file://${repo}`, clone], { env: gitEnv, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    expectDecision(
      decide(clone, { VERCEL_GIT_COMMIT_SHA: head, VERCEL_GIT_PREVIOUS_SHA: base }),
      BUILD,
      /not in this clone/,
    );
    expectDecision(
      decide(clone, { VERCEL_GIT_COMMIT_SHA: head, VERCEL_GIT_PREVIOUS_SHA: recent }),
      SKIP,
      /no change under website\//,
    );
  } finally {
    rmSync(clone, { recursive: true, force: true });
    cleanup();
  }
});

test("a malformed commit id builds", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    for (const bad of ["HEAD", "main", "--output=x", "abc", `${base} ${base}`])
      expectDecision(
        decide(repo, { VERCEL_GIT_COMMIT_SHA: base, VERCEL_GIT_PREVIOUS_SHA: bad }),
        BUILD,
        /not a full commit id/,
      );
  } finally {
    cleanup();
  }
});

test("a comparison error builds (no Git checkout around the site)", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    rmSync(join(repo, ".git"), { recursive: true, force: true });
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: base, VERCEL_GIT_PREVIOUS_SHA: base }),
      BUILD,
      /not a Git checkout/,
    );
  } finally {
    cleanup();
  }
});

test("a comparison error builds (diff fails on a non-commit object)", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    const blob = git(repo, "rev-parse", "HEAD:website/page.txt");
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: base, VERCEL_GIT_PREVIOUS_SHA: blob }),
      BUILD,
      /not in this clone/,
    );
  } finally {
    cleanup();
  }
});

test("redeploying the last deployed commit builds (an explicit rebuild)", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    expectDecision(
      decide(repo, { VERCEL_GIT_COMMIT_SHA: base, VERCEL_GIT_PREVIOUS_SHA: base }),
      BUILD,
      /same commit/,
    );
  } finally {
    cleanup();
  }
});

test("an explicit forced build builds a firmware-only change", () => {
  const { repo, base, cleanup } = makeRepo();
  try {
    write(repo, "firmware/main.c", "changed\n");
    const head = commit(repo, "firmware only");
    const env = { VERCEL_GIT_COMMIT_SHA: head, VERCEL_GIT_PREVIOUS_SHA: base };
    for (const value of ["1", "true"])
      expectDecision(decide(repo, { ...env, WEBSITE_FORCE_BUILD: value }), BUILD, /forced/);
    // Any other value is not a request to force; the normal decision applies.
    assert.equal(decide(repo, { ...env, WEBSITE_FORCE_BUILD: "0" }).code, SKIP);
  } finally {
    cleanup();
  }
});
