import { ArrowUpRight, ShieldCheck } from "lucide-react";
import {
  artworkLicenseUrl,
  codeLicenseUrl,
  repositoryUrl,
} from "@/lib/guardian";

export function SiteFooter() {
  return (
    <footer className="site-footer container">
      <a href="#" className="footer-brand" aria-label="M5 Guardian, back to top">
        <ShieldCheck aria-hidden="true" />
        <span>M5 / GUARDIAN.</span>
      </a>
      <p>
        Made to watch. Built to understand.
        <br />
        <span>
          Code: MIT. Guardian artwork: all rights reserved. This website is a
          simulation and does not connect to or protect your network.
        </span>
      </p>
      <div>
        <a href={codeLicenseUrl} target="_blank" rel="noreferrer">
          Code license <ArrowUpRight aria-hidden="true" />
        </a>
        <a href={artworkLicenseUrl} target="_blank" rel="noreferrer">
          Artwork license <ArrowUpRight aria-hidden="true" />
        </a>
        <a href={repositoryUrl} target="_blank" rel="noreferrer">
          GitHub <ArrowUpRight aria-hidden="true" />
        </a>
        <a href="#">Back to top ↑</a>
      </div>
    </footer>
  );
}
