"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowUpRight, Menu, ShieldCheck, X } from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { repositoryUrl } from "@/lib/guardian";
import { cn } from "@/lib/utils";

const links = [
  ["The Guardian", "#guardian"],
  ["How it works", "#how-it-works"],
  ["Hardware", "#hardware"],
  ["Open source", "#open-source"],
] as const;

export function Brand() {
  return (
    <a href="/" className="brand" aria-label="M5 Guardian home">
      <span className="brand-mark">
        <ShieldCheck strokeWidth={1.7} aria-hidden="true" />
      </span>
      <span>
        M5<span className="brand-divider">/</span>GUARDIAN
        <span className="brand-period">.</span>
      </span>
    </a>
  );
}

/** `base` prefixes the in-page links, so another page (/install) points them at the home page. */
export function SiteHeader({ base = "" }: { base?: string } = {}) {
  const [open, setOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);

  // Escape closes the open menu from anywhere and returns focus to its button.
  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      setOpen(false);
      menuButton.current?.focus();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  return (
    <header className="site-header">
      <div className="container header-inner">
        <Brand />
        <nav className="desktop-nav" aria-label="Main navigation">
          {links.map(([label, href]) => (
            <a key={href} href={`${base}${href}`}>
              {label}
            </a>
          ))}
        </nav>
        <a
          href={repositoryUrl}
          target="_blank"
          rel="noreferrer"
          className={cn(
            buttonVariants({ variant: "outline", size: "lg" }),
            "header-source",
          )}
        >
          View on GitHub{" "}
          <ArrowUpRight data-icon="inline-end" aria-hidden="true" />
        </a>
        <Button
          ref={menuButton}
          variant="outline"
          size="icon-lg"
          className="mobile-menu-button"
          aria-label={open ? "Close navigation" : "Open navigation"}
          aria-expanded={open}
          aria-controls="mobile-nav"
          onClick={() => setOpen(!open)}
        >
          {open ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
        </Button>
      </div>
      {open && (
        <nav
          id="mobile-nav"
          className="mobile-nav"
          aria-label="Mobile navigation"
        >
          {links.map(([label, href]) => (
            <a key={href} href={`${base}${href}`} onClick={() => setOpen(false)}>
              {label}
              <ArrowUpRight aria-hidden="true" />
            </a>
          ))}
          <a href={repositoryUrl} target="_blank" rel="noreferrer">
            View on GitHub
            <ArrowUpRight aria-hidden="true" />
          </a>
        </nav>
      )}
    </header>
  );
}
