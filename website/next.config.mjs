import { fileURLToPath } from "node:url";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants.js";
import { contentSecurityPolicy, cspHeaderName } from "./lib/csp.ts";
import { readReleaseVersion } from "./lib/release-version.mjs";

// The release number of release/version.txt, read once when the build starts
// (a missing or malformed file fails the build). The root layout's JSON-LD
// names it as softwareVersion.
const releaseVersion = readReleaseVersion(fileURLToPath(new URL("..", import.meta.url)));

/** @type {(phase: string) => import('next').NextConfig} */
const nextConfig = (phase) => ({
  poweredByHeader: false,
  env: { GUARDIAN_RELEASE_VERSION: releaseVersion },
  // AVIF first (smaller than WebP for the persona art), WebP as the fallback.
  images: { formats: ["image/avif", "image/webp"] },
  // A second local build for the VERCEL=1 browser checks (playwright.config.ts) goes to its own folder.
  distDir: process.env.GUARDIAN_DIST_DIR || ".next",
  // The Content-Security-Policy is a static header (lib/csp.ts explains why), fixed when the build starts:
  // a Vercel preview build adds the toolbar's sources; GUARDIAN_CSP_REPORT_ONLY=1 sends it as Report-Only.
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Strict-Transport-Security", value: "max-age=63072000" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
          {
            key: cspHeaderName(process.env.GUARDIAN_CSP_REPORT_ONLY),
            value: contentSecurityPolicy({
              dev: phase === PHASE_DEVELOPMENT_SERVER,
              preview: process.env.VERCEL_ENV === "preview",
            }),
          },
        ],
      },
    ];
  },
});

export default nextConfig;
