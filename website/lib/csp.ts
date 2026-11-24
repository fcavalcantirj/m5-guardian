// Content-Security-Policy of every page (W08), a static header set in
// next.config.mjs, so the pages stay prerendered and edge-cached. Next's inline
// bootstrap scripts change with every build and a nonce would force per-request
// rendering (measured 2026-11-24: first byte from Brazil ~0.67 s instead of
// ~0.35 s, cold 1.9 s), so script-src allows 'unsafe-inline'; every other
// source (Next chunks, the 3D viewer, esptool-js and spark-md5, the firmware
// API, Vercel Web Analytics at /_vercel/insights) is same-origin. Each source
// is explained in website/DEPLOYMENT.md.

type Options = {
  /** next dev: React's error overlay needs eval. */
  dev?: boolean;
  /** A Vercel preview deployment: Vercel's documented sources for its toolbar and comments. */
  preview?: boolean;
};

const toolbar: Record<string, string[]> = {
  "script-src": ["https://vercel.live"],
  "connect-src": ["https://vercel.live", "wss://ws-us3.pusher.com"],
  "img-src": ["https://vercel.live", "https://vercel.com", "data:", "blob:"],
  "frame-src": ["https://vercel.live"],
  "style-src": ["https://vercel.live"],
  "font-src": ["https://vercel.live", "https://assets.vercel.com"],
};

export function contentSecurityPolicy({ dev = false, preview = false }: Options = {}) {
  const policy: [string, string[]][] = [
    ["default-src", ["'self'"]],
    // Next's inline bootstrap scripts (no user input reaches the page, no third-party script is loaded).
    ["script-src", ["'self'", "'unsafe-inline'", ...(dev ? ["'unsafe-eval'"] : [])]],
    // React renders style attributes into the HTML; no style elements are inlined.
    ["style-src", ["'self'", "'unsafe-inline'"]],
    ["img-src", ["'self'"]],
    ["font-src", ["'self'"]],
    ["connect-src", ["'self'"]],
    ["object-src", ["'none'"]],
    ["base-uri", ["'self'"]],
    ["form-action", ["'self'"]],
    ["frame-ancestors", ["'none'"]],
  ];
  if (preview)
    for (const [name, sources] of Object.entries(toolbar)) {
      const directive = policy.find(([n]) => n === name);
      if (directive) directive[1].push(...sources);
      else policy.push([name, [...sources]]);
    }
  return policy.map(([name, sources]) => `${name} ${sources.join(" ")}`).join("; ");
}

/** GUARDIAN_CSP_REPORT_ONLY=1 sends the policy as Report-Only (a trial on a preview); anything else enforces it. */
export function cspHeaderName(reportOnly: string | undefined) {
  return reportOnly === "1" ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
}
