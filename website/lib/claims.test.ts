import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// The claim-to-source record (claims.json) ties every factual device statement
// on the page to a quotation in a repository file. This check keeps both ends
// honest: the page wording must still be in the cited website file, and the
// quotation must still be in the cited repository file.

const site = new URL("..", import.meta.url).pathname;
const repo = new URL("../..", import.meta.url).pathname;

type Claim = {
  id: string;
  statement: string;
  status: "current" | "host-only" | "deferred";
  page: { file: string; text: string }[];
  sources: { path: string; quote: string }[];
};
type Record = {
  documents: { coverage: string[]; limitations: string[] };
  claims: Claim[];
};

const record: Record = JSON.parse(
  readFileSync(join(site, "claims.json"), "utf8"),
);
const squash = (text: string) => text.replace(/\s+/g, " ").trim();
const read = (path: string) => squash(readFileSync(path, "utf8"));

// GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens.
function anchors(markdownPath: string): Set<string> {
  const lines = readFileSync(join(repo, markdownPath), "utf8").split("\n");
  return new Set(
    lines
      .filter((line) => /^#{1,6} /.test(line))
      .map((line) =>
        line
          .replace(/^#+ /, "")
          .trim()
          .toLowerCase()
          .replace(/[^\p{L}\p{N} _-]/gu, "")
          .replace(/ /g, "-"),
      ),
  );
}

function assertRepositoryTarget(target: string, context: string) {
  const [path, fragment] = target.split("#");
  assert.match(path, /^[A-Za-z0-9_./-]+$/, `${context}: path ${path}`);
  assert.ok(!path.split("/").includes(".."), `${context}: ${path} leaves the tree`);
  assert.ok(existsSync(join(repo, path)), `${context}: ${path} is missing`);
  if (fragment)
    assert.ok(
      anchors(path).has(fragment),
      `${context}: ${path} has no heading #${fragment}`,
    );
}

test("the record links the published coverage and limitations documents", () => {
  assert.ok(record.documents.coverage.length > 0);
  assert.ok(record.documents.limitations.length > 0);
  for (const target of [
    ...record.documents.coverage,
    ...record.documents.limitations,
  ])
    assertRepositoryTarget(target, "documents");
});

test("every claim has a status, page wording and a verbatim source quotation", () => {
  const ids = new Set<string>();
  for (const claim of record.claims) {
    assert.ok(!ids.has(claim.id), `duplicate claim id ${claim.id}`);
    ids.add(claim.id);
    assert.ok(
      ["current", "host-only", "deferred"].includes(claim.status),
      `${claim.id}: status ${claim.status}`,
    );
    assert.ok(claim.page.length > 0, `${claim.id}: no page wording`);
    assert.ok(claim.sources.length > 0, `${claim.id}: no source`);
    for (const { file, text } of claim.page) {
      assert.match(file, /^(app|components|lib)\/[A-Za-z0-9_./-]+$/);
      assert.ok(
        read(join(site, file)).includes(squash(text)),
        `${claim.id}: "${text}" is not in website/${file}`,
      );
    }
    for (const { path, quote } of claim.sources) {
      assertRepositoryTarget(path, claim.id);
      assert.ok(
        read(join(repo, path)).includes(squash(quote)),
        `${claim.id}: quotation not found in ${path}: "${quote}"`,
      );
    }
  }
});

test("the record distinguishes current, host-only and deferred statements", () => {
  const statuses = new Set(record.claims.map((claim) => claim.status));
  for (const status of ["current", "host-only", "deferred"])
    assert.ok(statuses.has(status as Claim["status"]), `no ${status} claim`);
});

test("every repository link on the page points at a file and heading that exist", () => {
  const walk = (dir: string): string[] =>
    readdirSync(join(site, dir)).flatMap((name) => {
      const path = join(dir, name);
      return statSync(join(site, path)).isDirectory()
        ? walk(path)
        : /\.tsx?$/.test(name) && !name.endsWith(".test.ts")
          ? [path]
          : [];
    });
  const files = ["app", "components", "lib"].flatMap(walk);
  let links = 0;
  for (const file of files) {
    const text = readFileSync(join(site, file), "utf8");
    for (const match of text.matchAll(
      /\$\{repositoryUrl\}(\/blob\/main\/[^`"'\s}]+|#[^`"'\s}]+)/g,
    )) {
      const target = match[1].startsWith("#")
        ? `README.md${match[1]}`
        : match[1].replace("/blob/main/", "");
      assertRepositoryTarget(target, `website/${file}`);
      links++;
    }
  }
  assert.ok(links >= 6, `only ${links} repository links found`);
});
