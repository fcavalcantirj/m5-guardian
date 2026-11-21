"use client";

import Image from "next/image";
import { useRef, type PointerEvent } from "react";
import { Radio, ShieldCheck, WifiOff } from "lucide-react";
import type { Presentation } from "@/lib/guardian";

export function GuardianStage({
  view,
  motion,
}: {
  view: Presentation;
  motion: boolean;
}) {
  const portrait = useRef<HTMLDivElement>(null);

  function handlePointerMove(event: PointerEvent<HTMLDivElement>) {
    if (
      !motion ||
      event.pointerType !== "mouse" ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    )
      return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - bounds.left) / bounds.width - 0.5;
    const y = (event.clientY - bounds.top) / bounds.height - 0.5;
    if (portrait.current)
      portrait.current.style.transform = `rotateY(${x * 15}deg) rotateX(${-y * 12}deg) translate3d(${x * 8}px, ${y * 8}px, 0)`;
  }

  function resetTilt() {
    if (portrait.current) portrait.current.style.transform = "";
  }

  return (
    <div
      className="guardian-stage"
      data-tone={view.tone}
      onPointerMove={handlePointerMove}
      onPointerLeave={resetTilt}
    >
      <div className="stage-grid" aria-hidden="true" />
      <div className="stage-glow" aria-hidden="true" />
      <div className="radar radar-outer" aria-hidden="true">
        <span />
      </div>
      <div className="radar radar-inner" aria-hidden="true" />
      <div className="stage-coordinate coordinate-top">
        <span className="status-dot" /> GUARDIAN / DEMO
      </div>
      <div className="stage-coordinate coordinate-right">
        RX ONLY
        <br />
        <span>2.4 GHz</span>
      </div>
      <div className="stage-coordinate coordinate-left">
        <span>CH.06</span>
        <i />
        PASSIVE LISTENING
      </div>
      <div className="portrait-perspective">
        <div className="portrait-tilt" ref={portrait}>
          <div className="portrait-float">
            {view.image ? (
              <Image
                key={view.image}
                src={view.image}
                alt={`Approved M5 Guardian ${view.label.toLowerCase()} expression`}
                width={512}
                height={512}
                priority
                sizes="(max-width: 700px) 90vw, 550px"
                className="guardian-portrait"
              />
            ) : (
              <div className="no-data-portrait">
                <WifiOff strokeWidth={0.8} aria-hidden="true" />
                <span>NO FRESH DATA</span>
                <small>Silence isn’t an all-clear.</small>
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="signal-particles" aria-hidden="true">
        {Array.from({ length: 12 }, (_, i) => (
          <i key={i} style={{ "--i": i } as React.CSSProperties} />
        ))}
      </div>
      <div className="guardian-state" aria-live="polite" aria-atomic="true">
        <span className="state-icon">
          {view.image ? (
            <ShieldCheck aria-hidden="true" />
          ) : (
            <WifiOff aria-hidden="true" />
          )}
        </span>
        <div>
          <span className="micro-label">DEMO NETWORK STATE</span>
          <strong>{view.label}</strong>
        </div>
        <div className="signal-bars" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
          <i />
        </div>
      </div>
      <div className="stage-bottom">
        <span>
          <Radio size={12} aria-hidden="true" /> A FACE FOR THE INVISIBLE
        </span>
        <span>01 — 05</span>
      </div>
    </div>
  );
}
