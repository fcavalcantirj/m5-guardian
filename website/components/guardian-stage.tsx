"use client";

import Image from "next/image";
import dynamic from "next/dynamic";
import {
  Component,
  useCallback,
  useEffect,
  useReducer,
  useRef,
  type PointerEvent,
  type ReactNode,
} from "react";
import { Box, Radio, ShieldCheck, WifiOff, X } from "lucide-react";
import type { Presentation } from "@/lib/guardian";
import {
  classifyFailure,
  failureMessage,
  initialViewer,
  viewerReducer,
  type FailureReason,
} from "@/lib/viewer";

// three.js, Fiber and the STL models load only after "See in 3D", never on the server.
const StickViewer = dynamic(() => import("@/components/stick-viewer"), {
  ssr: false,
  loading: () => null,
});

/** Probes for WebGL without keeping a context alive. */
function webglAvailable() {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl2") ?? canvas.getContext("webgl");
    if (!gl) return false;
    gl.getExtension("WEBGL_lose_context")?.loseContext();
    return true;
  } catch {
    return false;
  }
}

/** Catches a failed viewer chunk, renderer or model so the rest of the page keeps working. */
class ViewerBoundary extends Component<
  { onError: (error: unknown) => void; children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch(error: unknown) {
    this.props.onError(error);
  }
  render() {
    return this.state.failed ? null : this.props.children;
  }
}

export function GuardianStage({
  view,
  motion,
}: {
  view: Presentation;
  motion: boolean;
}) {
  const portrait = useRef<HTMLDivElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const [viewer, dispatch] = useReducer(viewerReducer, initialViewer);
  const { attempt } = viewer;
  const flat = viewer.mode !== "3d";

  // Pausing motion or a reduced-motion request returns the portrait to rest.
  useEffect(() => {
    if (!motion && portrait.current) portrait.current.style.transform = "";
  }, [motion]);

  // Leaving 3D (Esc, a failure) must not strand keyboard focus on the removed canvas.
  const previousMode = useRef(viewer.mode);
  useEffect(() => {
    const was = previousMode.current;
    previousMode.current = viewer.mode;
    if (was !== "2d" && viewer.mode === "2d") {
      const active = document.activeElement;
      if (!active || active === document.body) toggle.current?.focus();
    }
  }, [viewer.mode]);

  function activate() {
    resetTilt();
    dispatch({ type: "activate" });
    if (!webglAvailable())
      dispatch({ type: "fail", attempt: attempt + 1, reason: "no-webgl" });
  }
  const back = useCallback(() => {
    dispatch({ type: "back" });
    toggle.current?.focus();
  }, []);
  const ready = useCallback(() => dispatch({ type: "ready", attempt }), [attempt]);
  const fail = useCallback(
    (reason: FailureReason) => dispatch({ type: "fail", attempt, reason }),
    [attempt],
  );

  function handlePointerMove(event: PointerEvent<HTMLDivElement>) {
    if (
      viewer.mode !== "2d" ||
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
      data-view={viewer.mode}
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
        RX-ONLY MONITOR
        <br />
        <span>2.4 GHz</span>
      </div>
      <div className="stage-coordinate coordinate-left">
        <span>CH.06</span>
        <i />
        PASSIVE LISTENING
      </div>
      <div className="portrait-perspective" hidden={!flat}>
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
                fetchPriority="high"
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
      <div className="view-controls">
        <button
          ref={toggle}
          type="button"
          className="view-toggle"
          onClick={viewer.mode === "2d" ? activate : back}
        >
          {viewer.mode === "2d" ? (
            <>
              <Box aria-hidden="true" /> See in 3D
            </>
          ) : (
            <>
              <X aria-hidden="true" /> Back to 2D
            </>
          )}
        </button>
        <p className="view-status" role="status">
          {viewer.mode === "loading"
            ? "Loading the 3D StickS3…"
            : viewer.failure
              ? failureMessage(viewer.failure)
              : ""}
        </p>
      </div>
      {viewer.mode !== "2d" && (
        <ViewerBoundary
          key={attempt}
          onError={(error) => fail(classifyFailure(error))}
        >
          <div className="stick-viewer-layer" data-ready={viewer.mode === "3d"}>
            <StickViewer
              view={view}
              motion={motion}
              onReady={ready}
              onFail={fail}
              onExit={back}
            />
          </div>
        </ViewerBoundary>
      )}
      <div className="signal-particles" aria-hidden="true">
        {Array.from({ length: 12 }, (_, i) => (
          <i key={i} style={{ "--i": i } as React.CSSProperties} />
        ))}
      </div>
      <div className="guardian-state">
        <span className="state-icon">
          {view.image ? (
            <ShieldCheck aria-hidden="true" />
          ) : (
            <WifiOff aria-hidden="true" />
          )}
        </span>
        <div>
          <span className="micro-label">DEMO STATE</span>
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
