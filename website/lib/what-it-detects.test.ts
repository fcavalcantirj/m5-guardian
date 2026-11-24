import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  detectsDescription,
  detectsLead,
  detectsPath,
  detectsSections,
  detectsTitle,
  type Statement,
} from "./what-it-detects.ts";

// W09 content page /what-it-detects. Its words live in lib/what-it-detects.ts as
// statements, each citing claims.json entries. Every sentence of every statement
// must be page wording (in that file) of a claim it cites; lib/claims.test.ts then
// ties that wording to a verbatim quotation in a repository file.

const site = new URL("..", import.meta.url).pathname;
const contentFile = "lib/what-it-detects.ts";
const read = (path: string) => readFileSync(join(site, path), "utf8");
const squash = (text: string) => text.replace(/\s+/g, " ").trim();

type Claim = { id: string; page: { file: string; text: string }[] };
const claims: Claim[] = JSON.parse(read("claims.json")).claims;
const byId = new Map(claims.map((claim) => [claim.id, claim]));

/** Sentences: split after . ? or ! followed by a space and an upper-case letter, a quote or a digit. */
const sentences = (text: string) =>
  squash(text)
    .split(/(?<=[.?!])\s+(?=[A-Z0-9“"(])/)
    .filter(Boolean);

/** Page wording of a claim inside the content file. */
const wording = (id: string) =>
  (byId.get(id)?.page ?? []).filter((p) => p.file === contentFile).map((p) => squash(p.text));

const statements = (): { where: string; statement: Statement }[] => [
  { where: "lead", statement: detectsLead },
  ...detectsSections.flatMap((section) => [
    { where: `${section.id}: answer`, statement: section.answer },
    ...section.points.map((statement, i) => ({ where: `${section.id}: point ${i + 1}`, statement })),
  ]),
];

test("title and meta description fit the search result and the description is recorded wording", () => {
  assert.equal(detectsPath, "/what-it-detects");
  assert.ok(detectsTitle.length <= 60, `title ${detectsTitle.length} characters`);
  assert.ok(detectsDescription.length <= 160, `description ${detectsDescription.length} characters`);
  assert.ok(detectsDescription.length >= 110, `description ${detectsDescription.length} characters is too thin`);
  for (const term of [/deauth/i, /evil twin/i, /WPA3/, /StickS3/])
    assert.match(`${detectsTitle} ${detectsDescription}`, term);
  for (const sentence of sentences(detectsDescription))
    assert.ok(
      claims.some((claim) => wording(claim.id).some((text) => text.includes(sentence))),
      `description sentence "${sentence}" is not page wording of any claim in ${contentFile}`,
    );
});

test("each section is a plain question with a direct answer and the ledger's topics", () => {
  const ids = detectsSections.map((section) => section.id);
  assert.deepEqual(new Set(ids).size, ids.length, "unique section ids");
  for (const id of ["firmware", "ratings", "red", "amber", "limits", "compared"]) assert.ok(ids.includes(id), `section ${id}`);
  for (const section of detectsSections) {
    assert.match(section.id, /^[a-z-]+$/);
    assert.match(section.question, /\?$/, `${section.id}: the heading is a question`);
    assert.ok(sentences(section.answer.text).length >= 1, `${section.id}: an answer`);
    assert.ok(section.points.length >= 2, `${section.id}: points after the answer`);
  }
});

test("every sentence on the page is the page wording of a claim it cites", () => {
  let count = 0;
  for (const { where, statement } of statements()) {
    assert.ok(statement.claims.length > 0, `${where}: cites no claim`);
    for (const id of statement.claims) assert.ok(byId.has(id), `${where}: claim ${id} is not in claims.json`);
    for (const sentence of sentences(statement.text)) {
      count++;
      assert.ok(
        statement.claims.some((id) => wording(id).some((text) => text.includes(sentence))),
        `${where}: "${sentence}" is not page wording (${contentFile}) of ${statement.claims.join(", ")}`,
      );
    }
  }
  assert.ok(count >= 30, `only ${count} sentences`);
});

test("statements that are host-tested only say so on the page", () => {
  const status = new Map(
    (JSON.parse(read("claims.json")).claims as { id: string; status: string }[]).map((c) => [c.id, c.status]),
  );
  for (const { where, statement } of statements())
    if (statement.claims.some((id) => status.get(id) === "host-only"))
      assert.match(statement.text, /host-tested|host tests/i, `${where}: cites a host-only claim without saying so`);
});

test("the page describes the category, never another project, and radio events by counts, scope and colour", () => {
  const text = [read(contentFile), read("app/what-it-detects/page.tsx")].join("\n");
  assert.doesNotMatch(
    text,
    /Bruce|Marauder|Nemo|Spacehuhn|DSTIKE|Periscope|Evil-?M5|GhostESP|Flipper|PORKCHOP|Poseidon|pwnagotchi|Cardputer/i,
  );
  // No frame-level detail: no frame type codes, reason codes, key-handshake internals or address patterns.
  assert.doesNotMatch(text, /0x[0-9A-F]{2}|reason (code|\d)|EAPOL|PMKID|ANonce|DE:AD|12:34:56/i);
  assert.match(text, /red/i);
  assert.match(text, /amber/i);
});

test("the page has its own metadata, Open Graph image and no FAQ markup", () => {
  const page = read("app/what-it-detects/page.tsx");
  assert.match(page, /alternates: \{ canonical: detectsPath \}/);
  assert.match(page, /title: detectsTitle/);
  assert.match(page, /description: detectsDescription/);
  assert.match(page, /url: detectsPath/);
  assert.doesNotMatch(page, /FAQPage|application\/ld\+json/);
  for (const image of ["opengraph-image.tsx", "twitter-image.tsx"]) {
    const path = `app/what-it-detects/${image}`;
    assert.ok(existsSync(join(site, path)), `${path} exists`);
    assert.match(read(path), /renderDetectsCard\(\)/);
    assert.match(read(path), /size = \{ width: 1200, height: 630 \}/);
  }
});

test("the home page links to it near the alert story, and the footer links to it on every page", () => {
  const story = read("components/project-story.tsx");
  const howItWorks = story.slice(story.indexOf("export function HowItWorks"), story.indexOf("export function Hardware"));
  assert.match(howItWorks, /href="\/what-it-detects"/);
  assert.match(read("components/site-footer.tsx"), /href="\/what-it-detects"/);
});
