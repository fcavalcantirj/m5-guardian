import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";
import { siteDescription, siteTitle, siteUrl } from "@/lib/guardian";
import { jsonLd, structuredData } from "@/lib/structured-data";

const geist = Geist({ subsets: ["latin"], variable: "--font-geist" });
const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
});

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: siteTitle,
  description: siteDescription,
  openGraph: {
    title: siteTitle,
    description: siteDescription,
    siteName: "M5 Guardian",
    locale: "en",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: siteTitle,
    description: siteDescription,
  },
};

export const viewport: Viewport = {
  themeColor: "#080b0c",
  colorScheme: "dark",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${geist.variable} ${geistMono.variable}`}>
      <body>
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        {children}
        <script
          type="application/ld+json"
          // A data block (never executed), escaped by jsonLd(); the version is release/version.txt at build time.
          dangerouslySetInnerHTML={{ __html: jsonLd(structuredData(process.env.GUARDIAN_RELEASE_VERSION!)) }}
        />
        {/* Vercel Web Analytics (cookieless page views and the install step counts), in Vercel builds only (VERCEL=1 at build time; the pages are prerendered). */}
        {process.env.VERCEL === "1" && <Analytics />}
      </body>
    </html>
  );
}
