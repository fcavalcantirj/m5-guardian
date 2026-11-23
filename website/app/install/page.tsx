import type { Metadata } from "next";
import { Analytics } from "@vercel/analytics/next";
import { ArrowUpRight, Cable, MonitorSmartphone, Power, ShieldCheck } from "lucide-react";
import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { Flasher } from "@/components/install/flasher";
import { artworkLicenseUrl, repositoryUrl } from "@/lib/guardian";

const title = "Install M5 Guardian on your StickS3 | M5 Guardian";
const description =
  "Flash the signed M5 Guardian firmware onto your own M5Stack StickS3 from Chrome or Edge on a desktop: update and keep your settings, or back up and install fresh.";

export const metadata: Metadata = {
  title,
  description,
  alternates: { canonical: "/install" },
  openGraph: { title, description, url: "/install", siteName: "M5 Guardian", locale: "en", type: "website" },
};

const needs = [
  { icon: MonitorSmartphone, text: "Chrome or Edge on a desktop computer (Windows, macOS or Linux). Phones, tablets, Safari and Firefox cannot flash." },
  { icon: Cable, text: "Your M5Stack StickS3 and a USB-C data cable (a charge-only cable shows no device)." },
  { icon: Power, text: "Download mode, only if the stick does not appear: hold the small side button until the green light inside flashes." },
];

export default function InstallPage() {
  return (
    <>
      <SiteHeader base="/" />
      <main id="main" className="install-page container">
        <span className="eyebrow">INSTALL / STICKS3</span>
        <h1>Put the Guardian on your own StickS3.</h1>
        <p className="install-lead">
          This page writes the official, signed M5 Guardian firmware onto your StickS3 over USB, from your browser. Later updates are a re-flash
          from this same page. It talks only to the stick on your cable: it does not connect to or protect your network.
        </p>

        <section aria-labelledby="install-needs" className="install-section">
          <h2 id="install-needs">What you need</h2>
          <ul className="install-needs">
            {needs.map(({ icon: Icon, text }) => (
              <li key={text}>
                <Icon aria-hidden="true" />
                <span>{text}</span>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="install-steps" className="install-section">
          <h2 id="install-steps">Steps</h2>
          <ol className="install-steps">
            <li>Plug the StickS3 into this computer with the USB-C cable.</li>
            <li>
              Choose <strong>Update</strong> for a stick that already runs the Guardian, or <strong>First install</strong> for one that runs
              something else (download a backup first).
            </li>
            <li>Click the button and pick the stick in the browser&apos;s window. Keep it on the cable until the page says it is done.</li>
            <li>The stick restarts by itself. After a first install it greets you with three welcome pages; then pick your network.</li>
          </ol>
        </section>

        <section aria-labelledby="install-flash" className="install-section">
          <h2 id="install-flash">Flash</h2>
          <Flasher />
        </section>

        <section aria-labelledby="install-trust" className="install-section install-trust">
          <h2 id="install-trust">What this page does and does not do</h2>
          <ul>
            <li>
              <ShieldCheck aria-hidden="true" /> Writes only the four files of a signed release (bootloader, partition table, boot selector and
              the signed app) at their fixed offsets. An update never touches the parts of the flash that hold your settings, the radio
              calibration or your stored Wi-Fi.
            </li>
            <li>
              <ShieldCheck aria-hidden="true" /> Checks the release signature on the server and every file&apos;s SHA-256 again in your browser,
              then reads each write back (MD5).
            </li>
            <li>
              <ShieldCheck aria-hidden="true" /> Counts how far each install gets (anonymous, cookieless: the action and the step only). No chip
              name, address, file or error text leaves the page.
            </li>
          </ul>
          <p className="install-muted">
            Licence: flashing the official image from this website onto your own device for personal, non-commercial use is permitted; everything
            else about the Guardian artwork stays reserved (
            <a href={artworkLicenseUrl} target="_blank" rel="noreferrer">
              artwork licence <ArrowUpRight aria-hidden="true" className="install-inline-icon" />
            </a>
            ). The code is open source (
            <a href={repositoryUrl} target="_blank" rel="noreferrer">
              GitHub <ArrowUpRight aria-hidden="true" className="install-inline-icon" />
            </a>
            ).
          </p>
        </section>
      </main>
      <SiteFooter />
      {process.env.VERCEL === "1" && <Analytics />}
    </>
  );
}
