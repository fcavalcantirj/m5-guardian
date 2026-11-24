import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { jsonLd, structuredData } from "./structured-data.ts";
import { parseReleaseVersion, readReleaseVersion } from "./release-version.mjs";
import { repositoryUrl, siteUrl } from "./guardian.ts";

// W08 structured data: one JSON-LD block in the root layout with a schema.org
// WebSite and a SoftwareApplication. Every value is a fact of the project; the
// version is the one in release/version.txt, read when next.config loads (build time).

const site = new URL("..", import.meta.url).pathname;
const repo = new URL("../..", import.meta.url).pathname;
const versionFile = readFileSync(join(repo, "release/version.txt"), "utf8");
const releaseVersion = /^version=(\S+)$/m.exec(versionFile)![1];

type Node = { "@type": string; [key: string]: unknown };

test("release/version.txt is parsed strictly; a missing or malformed version fails closed", () => {
  assert.equal(parseReleaseVersion("# comment\nversion=1.2.3\nbuild=4\n"), "1.2.3");
  assert.equal(parseReleaseVersion(versionFile), releaseVersion);
  assert.throws(() => parseReleaseVersion("build=1\n"), /no version=/);
  assert.throws(() => parseReleaseVersion("version=\n"), /no version=/);
  assert.throws(() => parseReleaseVersion("version=1.0\n"), /not a release version/);
  assert.throws(() => parseReleaseVersion("version=1.0.0\nversion=1.0.1\n"), /more than one version=/);
  assert.equal(readReleaseVersion(repo), releaseVersion);
  assert.throws(() => readReleaseVersion(join(repo, "no-such-dir")), /release\/version\.txt/);
});

test("next.config exposes the release version to the build", async () => {
  // next.config.mjs exports a function of the build phase (the CSP's dev allowance depends on it).
  const config = (await import(join(site, "next.config.mjs"))).default("phase-production-build");
  assert.equal(config.env.GUARDIAN_RELEASE_VERSION, releaseVersion);
});

test("the JSON-LD holds a WebSite and a SoftwareApplication with only real values", () => {
  const data = JSON.parse(jsonLd(structuredData("9.8.7")));
  assert.equal(data["@context"], "https://schema.org");
  const graph: Node[] = data["@graph"];
  assert.deepEqual(graph.map((node) => node["@type"]), ["WebSite", "SoftwareApplication"]);
  const [website, app] = graph;
  assert.deepEqual(website, { "@type": "WebSite", "@id": `${siteUrl}/#website`, name: "M5 Guardian", url: `${siteUrl}/` });
  assert.equal(app.name, "M5 Guardian");
  assert.equal(app.url, `${siteUrl}/`);
  assert.equal(app.applicationCategory, "SecurityApplication");
  assert.equal(app.operatingSystem, "ESP32-S3 firmware (M5Stack StickS3)");
  assert.equal(app.license, `${repositoryUrl}/blob/main/LICENSE`);
  assert.deepEqual(app.sameAs, [repositoryUrl]);
  assert.equal(app.isAccessibleForFree, true);
  assert.deepEqual(app.offers, { "@type": "Offer", price: "0", priceCurrency: "USD" });
  assert.equal(app.softwareVersion, "9.8.7");
  assert.equal(app.downloadUrl, `${siteUrl}/install`);
  // No ratings, reviews or other values the project cannot back.
  const text = JSON.stringify(data);
  for (const key of ["aggregateRating", "review", "ratingValue", "author", "datePublished", "screenshot"])
    assert.ok(!text.includes(`"${key}"`), `no ${key}`);
});

test("the serialised JSON-LD cannot close its script element", () => {
  const text = jsonLd({ name: "</script><script>alert(1)</script>" });
  assert.ok(!text.includes("<"), text);
  assert.equal(JSON.parse(text).name, "</script><script>alert(1)</script>");
});

test("the root layout renders the JSON-LD with the build-time release version", () => {
  const layout = readFileSync(join(site, "app/layout.tsx"), "utf8");
  assert.match(layout, /type="application\/ld\+json"/);
  assert.match(layout, /structuredData\(process\.env\.GUARDIAN_RELEASE_VERSION!?\)/);
});
