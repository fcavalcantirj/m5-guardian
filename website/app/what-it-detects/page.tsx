import type { Metadata } from "next";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { repositoryUrl } from "@/lib/guardian";
import {
  detectsDescription,
  detectsLead,
  detectsPath,
  detectsSections,
  detectsTitle,
  type Statement,
} from "@/lib/what-it-detects";

// W09: every sentence below comes from lib/what-it-detects.ts, where each one cites
// its claims.json entry. No structured data beyond the site-wide JSON-LD (Google
// shows FAQ rich results only for government and health sites).
export const metadata: Metadata = {
  title: detectsTitle,
  description: detectsDescription,
  alternates: { canonical: detectsPath },
  // The images come from opengraph-image.tsx and twitter-image.tsx beside this page.
  openGraph: { title: detectsTitle, description: detectsDescription, url: detectsPath, siteName: "M5 Guardian", locale: "en", type: "website" },
  twitter: { card: "summary_large_image", title: detectsTitle, description: detectsDescription },
};

/** A statement, with the words before its first colon in bold when it names a term. */
function Text({ statement }: { statement: Statement }) {
  const colon = statement.term ? statement.text.indexOf(": ") : -1;
  if (colon < 0) return <>{statement.text}</>;
  return (
    <>
      <strong>{statement.text.slice(0, colon)}:</strong> {statement.text.slice(colon + 2)}
    </>
  );
}

export default function WhatItDetectsPage() {
  return (
    <>
      <SiteHeader base="/" />
      <main id="main" className="detects-page container">
        <span className="eyebrow">WHAT IT DETECTS / STICKS3</span>
        <h1>What the Guardian sees, and what it cannot.</h1>
        <p className="detects-lead">
          <Text statement={detectsLead} />
        </p>

        <nav aria-label="Questions on this page" className="detects-toc">
          <ol>
            {detectsSections.map((section) => (
              <li key={section.id}>
                <a href={`#${section.id}`}>{section.question}</a>
              </li>
            ))}
          </ol>
        </nav>

        {detectsSections.map((section) => (
          <section key={section.id} id={section.id} aria-labelledby={`${section.id}-title`} className="detects-section" data-tone={section.tone}>
            <h2 id={`${section.id}-title`}>{section.question}</h2>
            <p className="detects-answer">
              <Text statement={section.answer} />
            </p>
            <ul className="detects-points">
              {section.points.map((point) => (
                <li key={point.text}>
                  <Text statement={point} />
                </li>
              ))}
            </ul>
            {section.id === "firmware" && (
              <p className="detects-links">
                <a href="/install">
                  Install on your StickS3 <ArrowRight aria-hidden="true" />
                </a>
                <a href={`${repositoryUrl}#build-and-install`} target="_blank" rel="noreferrer">
                  Build your own <ArrowUpRight aria-hidden="true" />
                </a>
              </p>
            )}
            {section.id === "compared" && (
              <p className="detects-links">
                <a href={`${repositoryUrl}/blob/main/docs/attack-coverage.md`} target="_blank" rel="noreferrer">
                  Detection coverage <ArrowUpRight aria-hidden="true" />
                </a>
                <a href={`${repositoryUrl}#what-it-cannot-see`} target="_blank" rel="noreferrer">
                  What it cannot see <ArrowUpRight aria-hidden="true" />
                </a>
                <a href="/#guardian">
                  Try the simulation <ArrowRight aria-hidden="true" />
                </a>
              </p>
            )}
          </section>
        ))}
      </main>
      <SiteFooter />
    </>
  );
}
