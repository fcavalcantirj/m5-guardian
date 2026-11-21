import { SiteHeader } from "@/components/site-header";
import { GuardianExperience } from "@/components/guardian-experience";
import { HowItWorks, Hardware, OpenSource } from "@/components/project-story";
import { SiteFooter } from "@/components/site-footer";

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
