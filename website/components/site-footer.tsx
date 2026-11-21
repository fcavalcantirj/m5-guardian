import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { repositoryUrl } from "@/lib/guardian";

export function SiteFooter() {
  return (
    <footer className="site-footer container">
      <a href="#" className="footer-brand">
        <ShieldCheck aria-hidden="true" />
        <span>M5 / GUARDIAN.</span>
      </a>
      <p>
        Made to watch. Built to understand.
        <br />
        <span>Code: MIT. Guardian artwork: all rights reserved.</span>
      </p>
      <div>
        <a
          href={`${repositoryUrl}/blob/main/LICENSE`}
          target="_blank"
          rel="noreferrer"
        >
          License <ArrowUpRight aria-hidden="true" />
        </a>
        <a href={repositoryUrl} target="_blank" rel="noreferrer">
          GitHub <ArrowUpRight aria-hidden="true" />
        </a>
        <a href="#">Back to top ↑</a>
      </div>
    </footer>
  );
}
