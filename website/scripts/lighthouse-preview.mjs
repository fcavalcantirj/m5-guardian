// Preview-only SEO adjustment for the Lighthouse gate (W06).
//
// Vercel sends `x-robots-tag: noindex` on every preview deployment, so
// Lighthouse's is-crawlable audit fails there by design (measured on the W05
// preview: SEO 0.69 with only that audit failing). With LIGHTHOUSE_PREVIEW=1,
// scripts/lighthouse.mjs replaces the SEO score with previewSeo().adjusted:
// the same category recomputed without is-crawlable, but only when
//   - is-crawlable failed and every blocking directive it lists is an
//     x-robots-tag response header (a meta robots tag or robots.txt rule in
//     the site itself is never dropped), and
//   - recomputing the category with is-crawlable included reproduces the score
//     Lighthouse reported, so the arithmetic below matches the report.
// Production runs never use this: SEO >= 0.95 is gated there in full.

/**
 * Lighthouse's category score (core/scoring.js, ReportScoring.arithmeticMean):
 * the weighted mean of the audits with weight > 0, rounded to two decimals;
 * null if any of those audits has a null score.
 * @param {{id: string, weight: number}[]} auditRefs
 * @param {Record<string, {score: number | null}>} audits
 * @returns {number | null}
 */
export function categoryScore(auditRefs, audits) {
  const items = auditRefs
    .filter((ref) => ref.weight > 0)
    .map((ref) => ({ score: audits[ref.id].score, weight: ref.weight }));
  if (items.some((item) => item.score === null)) return null;
  const weight = items.reduce((sum, item) => sum + item.weight, 0);
  const total = items.reduce((sum, item) => sum + /** @type {number} */ (item.score) * item.weight, 0);
  return Math.round(((total / weight) || 0) * 100) / 100;
}

/**
 * @param {any} lhr a Lighthouse result (JSON report)
 * @returns {{reported: number, adjusted: number | null, excluded: string, directives: string[]} | null}
 *   null when no adjustment applies; throws if the report's SEO score cannot be reproduced.
 */
export function previewSeo(lhr) {
  const audit = lhr.audits["is-crawlable"];
  if (!audit || audit.score !== 0) return null;
  const items = audit.details?.items ?? [];
  const headerOnly =
    items.length > 0 &&
    items.every((item) => typeof item.source === "string" && /^x-robots-tag:/i.test(item.source));
  if (!headerOnly) return null;

  const { auditRefs, score: reported } = lhr.categories.seo;
  const reproduced = categoryScore(auditRefs, lhr.audits);
  if (reproduced !== reported)
    throw new Error(`SEO score ${reported} does not reproduce (recomputed ${reproduced}); refusing to adjust it`);
  return {
    reported,
    adjusted: categoryScore(auditRefs.filter((ref) => ref.id !== "is-crawlable"), lhr.audits),
    excluded: "is-crawlable",
    directives: items.map((item) => item.source),
  };
}
