import { SiteHeader } from "@/components/site-header";
import { GuardianExperience } from "@/components/guardian-experience";
import { HowItWorks, Hardware, OpenSource } from "@/components/project-story";
import { SiteFooter } from "@/components/site-footer";
import type { Metadata } from "next";
import { siteDescription, siteTitle } from "@/lib/guardian";

// The canonical and Open Graph URLs belong to the home page only, so the 404
// page does not claim them.
export const metadata: Metadata = {
  alternates: { canonical: "/" },
  openGraph: {
    title: siteTitle,
    description: siteDescription,
    url: "/",
    siteName: "M5 Guardian",
    locale: "en",
    type: "website",
  },
};

export default function Page() {
  return (
    <>
      <SiteHeader />
      <main id="main">
        <GuardianExperience />
        <HowItWorks />
        <Hardware />
        <OpenSource />
      </main>
      <SiteFooter />
    </>
  );
}
