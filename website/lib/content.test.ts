import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { moods, getPresentation } from "./guardian.ts";

const site = new URL("..", import.meta.url).pathname;

function sourceFiles(dir: string): string[] {
  return readdirSync(join(site, dir)).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(join(site, path)).isDirectory()) return sourceFiles(path);
    return /\.(tsx?|css)$/.test(name) && !name.endsWith(".test.ts")
      ? [path]
      : [];
  });
}

const pageText = ["app", "components", "lib"]
  .flatMap(sourceFiles)
  .map((path) => readFileSync(join(site, path), "utf8"))
  .join("\n")
  .replace(/\s+/g, " ");

test("the top mood makes no optional-cigar claim", () => {
  assert.doesNotMatch(pageText, /cigar is optional/i);
  for (const mood of moods) assert.doesNotMatch(mood.description, /cigar/i);
});

test("ratings are described as five rated outcomes plus Not rated and No fresh data", () => {
  assert.doesNotMatch(pageText, /every advertised security state/i);
  assert.match(pageText, /Five rated faces/);
  assert.match(pageText, /Not rated/);
  assert.match(pageText, /No fresh data/);
});

test("receive-only is qualified as monitoring and transmissions are disclosed", () => {
  assert.doesNotMatch(pageText, />\s*RX ONLY\s*</);
  assert.match(pageText, /Receive-only monitoring/);
  assert.match(pageText, /setup access point/);
  assert.match(pageText, /signed update check/);
  assert.match(pageText, /stops listening/);
});

test("limits name clients' application traffic and scope the computer and cloud claims", () => {
  assert.doesNotMatch(pageText, /traffic inspection,/);
  assert.match(pageText, /clients(’|&apos;|')? application traffic/);
  assert.doesNotMatch(pageText, /No companion computer required\./);
  assert.doesNotMatch(pageText, /NO CLOUD REQUIRED/);
  assert.match(pageText, /No companion computer for normal monitoring/i);
  assert.match(pageText, /No cloud for normal monitoring/i);
});

test("the website states that it is a simulation that does not touch a visitor's network", () => {
  assert.match(
    pageText,
    /This website is a simulation\. It does not connect to or protect your network\./,
  );
});

test("the stale demo keeps its rating withheld and names no all-clear", () => {
  const view = getPresentation(moods[0], "stale");
  assert.equal(view.label, "No fresh data");
  assert.match(view.description, /withheld/);
});
