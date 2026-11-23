import { test } from "node:test";
import assert from "node:assert/strict";
import { categoryScore, previewSeo } from "../scripts/lighthouse-preview.mjs";

// W06: on a Vercel preview, Lighthouse's is-crawlable audit fails because
// Vercel sends x-robots-tag: noindex on every preview. previewSeo() removes
// that one audit from the SEO score only when every blocking directive is that
// response header, and only after reproducing Lighthouse's own SEO score.
// The weights are Lighthouse 13.6.0's SEO category as recorded in a report.

const passing = ["document-title", "meta-description", "http-status-code", "link-text", "crawlable-anchors", "robots-txt", "image-alt", "hreflang", "canonical"];

function report({ crawlable = 1, items = [] as unknown[], seo = undefined as number | undefined, extra = {} as Record<string, number> } = {}) {
  const audits: Record<string, { score: number | null; scoreDisplayMode: string; details?: unknown }> = {
    "is-crawlable": { score: crawlable, scoreDisplayMode: "binary", details: { type: "table", items } },
    "structured-data": { score: null, scoreDisplayMode: "manual" },
  };
  for (const id of passing) audits[id] = { score: extra[id] ?? 1, scoreDisplayMode: "binary" };
  const auditRefs = [
    { id: "is-crawlable", weight: 4.043478260869565 },
    ...passing.map((id) => ({ id, weight: 1 })),
    { id: "structured-data", weight: 0 },
  ];
  const lhr = { categories: { seo: { score: 0 as number | null, auditRefs } }, audits };
  lhr.categories.seo.score = seo ?? categoryScore(auditRefs, audits);
  return lhr;
}

test("categoryScore reproduces Lighthouse's weighted mean, rounded to two decimals", () => {
  // Measured on the W05 preview: SEO 0.69 with only is-crawlable failing.
  const lhr = report({ crawlable: 0, items: [{ source: "x-robots-tag: noindex" }] });
  assert.equal(lhr.categories.seo.score, 0.69);
  assert.equal(report().categories.seo.score, 1);
});

test("a header-only noindex is dropped from the SEO score", () => {
  const result = previewSeo(report({ crawlable: 0, items: [{ source: "x-robots-tag: noindex" }] }));
  assert.deepEqual(result, {
    reported: 0.69,
    adjusted: 1,
    excluded: "is-crawlable",
    directives: ["x-robots-tag: noindex"],
  });
});

test("other failing SEO audits still count after the adjustment", () => {
  const lhr = report({ crawlable: 0, items: [{ source: "X-Robots-Tag: noindex" }], extra: { "meta-description": 0 } });
  assert.equal(previewSeo(lhr)?.adjusted, 0.89);
});

test("a passing is-crawlable needs no adjustment", () => {
  assert.equal(previewSeo(report()), null);
});

test("a noindex in the page or robots.txt is never dropped", () => {
  const meta = { source: { type: "node", snippet: '<meta name="robots" content="noindex">' } };
  const robots = { source: { type: "source-location", url: "https://x.vercel.app/robots.txt", line: 2 } };
  for (const items of [[meta], [robots], [{ source: "x-robots-tag: noindex" }, meta], []])
    assert.equal(previewSeo(report({ crawlable: 0, items })), null, JSON.stringify(items));
});

test("a report whose SEO score cannot be reproduced is refused", () => {
  const lhr = report({ crawlable: 0, items: [{ source: "x-robots-tag: noindex" }], seo: 0.5 });
  assert.throws(() => previewSeo(lhr), /does not reproduce/);
});

test("a null audit score makes the category null, as in Lighthouse", () => {
  const lhr = report();
  lhr.audits["link-text"].score = null;
  assert.equal(categoryScore(lhr.categories.seo.auditRefs, lhr.audits), null);
});
