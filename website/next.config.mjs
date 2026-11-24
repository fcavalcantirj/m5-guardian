import { fileURLToPath } from "node:url";
import { readReleaseVersion } from "./lib/release-version.mjs";

// The release number of release/version.txt, read once when the build starts
// (a missing or malformed file fails the build). The root layout's JSON-LD
// names it as softwareVersion.
const releaseVersion = readReleaseVersion(fileURLToPath(new URL("..", import.meta.url)));

/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  env: { GUARDIAN_RELEASE_VERSION: releaseVersion },
  // AVIF first (smaller than WebP for the persona art), WebP as the fallback.
  images: { formats: ["image/avif", "image/webp"] },
  // The Content-Security-Policy is set per request by proxy.ts: it carries a nonce, which a static header cannot.
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
        ],
      },
    ];
  },
};

export default nextConfig;
