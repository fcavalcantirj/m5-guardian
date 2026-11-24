"use client";

import { useEffect } from "react";
import { track } from "@vercel/analytics";
import { OUTBOUND_EVENT, outboundEvent } from "@/lib/outbound";

/**
 * Counts clicks on links that leave the site (mostly the GitHub repository) as one Vercel Web Analytics event,
 * through one listener on the document, so no link needs its own handler. Left and middle clicks both count.
 * Without the analytics script (any non-Vercel build) track() does nothing.
 */
export function OutboundClicks() {
  useEffect(() => {
    const onClick = (click: MouseEvent) => {
      if (click.button !== 0 && click.button !== 1) return;
      const link = click.target instanceof Element ? click.target.closest("a[href]") : null;
      if (!(link instanceof HTMLAnchorElement)) return;
      const event = outboundEvent(link.href, window.location.href);
      if (event) track(OUTBOUND_EVENT, event);
    };
    document.addEventListener("click", onClick, true);
    document.addEventListener("auxclick", onClick, true);
    return () => {
      document.removeEventListener("click", onClick, true);
      document.removeEventListener("auxclick", onClick, true);
    };
  }, []);
  return null;
}
