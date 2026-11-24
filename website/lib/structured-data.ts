import { codeLicenseUrl, repositoryUrl, siteUrl } from "./guardian.ts";

// schema.org data for the root layout's JSON-LD (W08). Only facts of the
// project: no ratings, reviews or counts. The version comes from
// release/version.txt at build time (next.config.mjs, GUARDIAN_RELEASE_VERSION).

export function structuredData(version: string) {
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebSite",
        "@id": `${siteUrl}/#website`,
        name: "M5 Guardian",
        url: `${siteUrl}/`,
      },
      {
        "@type": "SoftwareApplication",
        name: "M5 Guardian",
        url: `${siteUrl}/`,
        applicationCategory: "SecurityApplication",
        operatingSystem: "ESP32-S3 firmware (M5Stack StickS3)",
        license: codeLicenseUrl,
        sameAs: [repositoryUrl],
        isAccessibleForFree: true,
        offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
        softwareVersion: version,
        downloadUrl: `${siteUrl}/install`,
      },
    ],
  };
}

/** JSON for a <script type="application/ld+json"> body; "<" is escaped so the text can never close the element. */
export function jsonLd(data: unknown) {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}
