// Content-Security-Policy of every page (W08), applied by proxy.ts. Next's
// inline bootstrap scripts carry the per-request nonce; everything else the
// pages load (Next chunks, the 3D viewer, esptool-js and spark-md5, the
// firmware API, Vercel Web Analytics at /_vercel/insights) is same-origin.
// Each source is explained in website/DEPLOYMENT.md.

type Options = {
  nonce: string;
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

export function contentSecurityPolicy({ nonce, dev = false, preview = false }: Options) {
  const policy: [string, string[]][] = [
    ["default-src", ["'self'"]],
    ["script-src", ["'self'", `'nonce-${nonce}'`, ...(dev ? ["'unsafe-eval'"] : [])]],
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

/** 128 random bits, base64. */
export function newNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}
