import type { MetadataRoute } from "next";
import { siteUrl } from "@/lib/guardian";
import { lastCommitDate, pageSources } from "@/lib/last-modified";

// Generated at build time. lastModified is the last commit date of each page's
// sources, left out when Git cannot tell (see lib/last-modified.ts).
export default function sitemap(): MetadataRoute.Sitemap {
  const site = process.cwd();
  return [
    { url: `${siteUrl}/`, lastModified: lastCommitDate(pageSources["/"], site), changeFrequency: "monthly", priority: 1 },
    {
      url: `${siteUrl}/install`,
      lastModified: lastCommitDate(pageSources["/install"], site),
      changeFrequency: "monthly",
      priority: 0.8,
    },
  ];
}
