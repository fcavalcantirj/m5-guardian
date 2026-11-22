/**
 * Pure parts of the 3D StickS3 viewer: what the simulated screen shows, how it
 * is painted, the viewer's mode, rotation and failure explanations. Nothing here
 * touches the DOM or WebGL, so node:test covers it (lib/viewer.test.ts).
 */
import type { Presentation } from "./guardian.ts";

// ----------------------------------------------------------------------------
// Screen contents
// ----------------------------------------------------------------------------

/** The StickS3 panel is 135 x 240 pixels; the texture is drawn at twice that. */
export const SCREEN_TEXTURE = { width: 270, height: 480 } as const;

export const toneColors: Record<string, string> = {
  green: "#b5f36a",
  cyan: "#75d6da",
  amber: "#e5b760",
  red: "#ee7e77",
  muted: "#929c9e",
};

export type ScreenSpec = {
  kind: "face" | "no-data";
  /** Identifies what is on the screen; equal keys paint identical screens. */
  key: string;
  image: string | null;
  heading: string;
  detail: string;
  tone: string;
};

/** The simulated screen for the current presentation. Stale data never shows a face. */
export function screenFor(view: Presentation): ScreenSpec {
  if (view.image === null) {
    return {
      kind: "no-data",
      key: "no-data",
      image: null,
      heading: "NO FRESH DATA",
      detail: "Silence isn’t an all-clear.",
      tone: "muted",
    };
  }
  const heading = view.label.toUpperCase();
  const detail =
    view.label === view.rating ? "SIMULATED RATING" : `RATING: ${view.rating.toUpperCase()}`;
  return {
    kind: "face",
    key: `face|${view.image}|${heading}|${view.tone}|${detail}`,
    image: view.image,
    heading,
    detail,
    tone: view.tone,
  };
}

/** The subset of CanvasRenderingContext2D the screen painter uses. */
export type ScreenImage = CanvasImageSource;
export type ScreenSurface = {
  /** A real CanvasRenderingContext2D satisfies this type; its size is on .canvas. */
  readonly canvas: { readonly width: number; readonly height: number };
  fillStyle: string | CanvasGradient | CanvasPattern;
  font: string;
  textAlign: CanvasTextAlign;
  textBaseline: CanvasTextBaseline;
  clearRect(x: number, y: number, w: number, h: number): void;
  fillRect(x: number, y: number, w: number, h: number): void;
  fillText(text: string, x: number, y: number, maxWidth?: number): void;
  drawImage(image: ScreenImage, dx: number, dy: number, dw: number, dh: number): void;
};

const SCREEN_FONT = "ui-monospace, SFMono-Regular, Menlo, monospace";

/**
 * Paints one screen. The surface is always cleared first, so nothing of the
 * previous screen survives; a face is drawn only when its image is given.
 */
export function drawScreen(
  surface: ScreenSurface,
  spec: ScreenSpec,
  image: ScreenImage | null,
) {
  const { width: w, height: h } = surface.canvas;
  surface.clearRect(0, 0, w, h);
  surface.fillStyle = "#020303";
  surface.fillRect(0, 0, w, h);
  const color = toneColors[spec.tone] ?? toneColors.muted;
  surface.textAlign = "center";
  surface.textBaseline = "middle";

  // Status strip at the top in the state colour.
  surface.fillStyle = color;
  surface.fillRect(0, 0, w, 6);
  surface.font = `600 15px ${SCREEN_FONT}`;
  surface.fillStyle = "#8f9b93";
  surface.fillText("GUARDIAN · DEMO", w / 2, 30, w - 20);

  if (spec.kind === "no-data") {
    surface.fillStyle = "#1a2220";
    surface.fillRect(w / 2 - 50, h / 2 - 110, 100, 100);
    surface.fillStyle = color;
    surface.font = `600 42px ${SCREEN_FONT}`;
    surface.fillText("?", w / 2, h / 2 - 60);
    surface.font = `700 22px ${SCREEN_FONT}`;
    surface.fillStyle = "#edf0ee";
    surface.fillText(spec.heading, w / 2, h / 2 + 30, w - 20);
    surface.font = `400 15px ${SCREEN_FONT}`;
    surface.fillStyle = color;
    surface.fillText(spec.detail, w / 2, h / 2 + 62, w - 20);
    return;
  }

  if (image) surface.drawImage(image, 0, 64, w, w);
  surface.font = `700 22px ${SCREEN_FONT}`;
  surface.fillStyle = color;
  surface.fillText(spec.heading, w / 2, h - 92, w - 16);
  surface.font = `400 14px ${SCREEN_FONT}`;
  surface.fillStyle = "#c3cbc6";
  surface.fillText(spec.detail, w / 2, h - 60, w - 16);
  surface.fillStyle = color;
  surface.fillRect(w / 2 - 30, h - 30, 60, 3);
}

export type ScreenPainter = {
  show(spec: ScreenSpec): void;
  state(): { key: string | null; kind: ScreenSpec["kind"] | null; faceDrawn: boolean };
  dispose(): void;
};

/**
 * Keeps a surface in step with the latest screen. Each change is painted at
 * once without the face (cleared first); the face follows when its image has
 * loaded, unless a newer screen has replaced it meanwhile.
 */
export function createScreenPainter({
  surface,
  load,
  onChange,
  onError,
}: {
  surface: ScreenSurface;
  load: (src: string) => Promise<ScreenImage>;
  onChange: () => void;
  onError: (src: string) => void;
}): ScreenPainter {
  const loaded = new Map<string, ScreenImage>();
  let token = 0;
  let disposed = false;
  let current: ScreenSpec | null = null;
  let faceDrawn = false;

  function paint(spec: ScreenSpec, image: ScreenImage | null) {
    drawScreen(surface, spec, image);
    faceDrawn = image !== null;
    onChange();
  }

  return {
    show(spec) {
      if (disposed) return;
      const mine = ++token;
      current = spec;
      const src = spec.image;
      const ready = src ? loaded.get(src) : undefined;
      paint(spec, ready ?? null);
      if (!src || ready) return;
      load(src).then(
        (image) => {
          loaded.set(src, image);
          if (!disposed && mine === token) paint(spec, image);
        },
        () => {
          if (!disposed && mine === token) onError(src);
        },
      );
    },
    state: () => ({ key: current?.key ?? null, kind: current?.kind ?? null, faceDrawn }),
    dispose() {
      disposed = true;
      loaded.clear();
    },
  };
}

// ----------------------------------------------------------------------------
// Viewer mode
// ----------------------------------------------------------------------------

export type FailureReason =
  | "no-webgl"
  | "renderer"
  | "chunk"
  | "model"
  | "face"
  | "context-lost";

export type ViewerState = {
  mode: "2d" | "loading" | "3d";
  failure: FailureReason | null;
  /** Increments on each activation; events from an earlier viewer are ignored. */
  attempt: number;
};

export type ViewerAction =
  | { type: "activate" }
  | { type: "ready"; attempt: number }
  | { type: "fail"; attempt: number; reason: FailureReason }
  | { type: "back" };

export const initialViewer: ViewerState = { mode: "2d", failure: null, attempt: 0 };

export function viewerReducer(state: ViewerState, action: ViewerAction): ViewerState {
  switch (action.type) {
    case "activate":
      return { mode: "loading", failure: null, attempt: state.attempt + 1 };
    case "ready":
      if (state.mode !== "loading" || action.attempt !== state.attempt) return state;
      return { ...state, mode: "3d" };
    case "fail":
      if (state.mode === "2d" || action.attempt !== state.attempt) return state;
      return { ...state, mode: "2d", failure: action.reason };
    case "back":
      return { ...state, mode: "2d", failure: null };
  }
}

const failureText: Record<FailureReason, string> = {
  "no-webgl": "3D view unavailable: this browser has WebGL turned off or unsupported.",
  renderer: "3D view unavailable: the 3D renderer could not start.",
  chunk: "3D view unavailable: the viewer code failed to download.",
  model: "3D view unavailable: the StickS3 model failed to load.",
  face: "3D view unavailable: the Guardian screen image failed to load.",
  "context-lost": "3D view stopped: the browser lost the WebGL context.",
};

export function failureMessage(reason: FailureReason) {
  return `${failureText[reason]} Showing the 2D view instead.`;
}

/** Sorts an error thrown while loading or running the viewer into a failure reason. */
export function classifyFailure(error: unknown): FailureReason {
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : String(error ?? "");
  if (
    name === "ChunkLoadError" ||
    /loading (css )?chunk|dynamically imported module|importing a module script failed/i.test(
      message,
    )
  )
    return "chunk";
  if (/\.stl\b/i.test(message)) return "model";
  return "renderer";
}

// ----------------------------------------------------------------------------
// Rotation
// ----------------------------------------------------------------------------

export const BASE_RX = -0.12;
export const BASE_RY = -0.42;
export const MAX_TILT = 0.5;

export type Spin = { rx: number; ry: number; vx: number; vy: number };

export const restSpin: Spin = { rx: BASE_RX, ry: BASE_RY, vx: 0, vy: 0 };

const clampTilt = (rx: number) => Math.max(-MAX_TILT, Math.min(MAX_TILT, rx));

/**
 * One animation step while not dragging. With motion off (paused or reduced
 * motion) the model holds still: no throw, no settling, no idle sway.
 */
export function stepSpin(
  spin: Spin,
  { motion, idle, time }: { motion: boolean; idle: boolean; time: number },
): Spin {
  if (!motion) {
    if (spin.vx === 0 && spin.vy === 0) return spin;
    return { ...spin, vx: 0, vy: 0 };
  }
  let { rx, ry, vx, vy } = spin;
  ry += vy;
  rx += vx;
  vy *= 0.94;
  vx *= 0.9;
  if (idle && Math.abs(vy) < 0.002) {
    const targetY = BASE_RY + Math.sin(time * 0.5) * 0.3;
    const targetX = BASE_RX + Math.sin(time * 0.37) * 0.07;
    const nearest = targetY + Math.round((ry - targetY) / (Math.PI * 2)) * Math.PI * 2;
    ry += (nearest - ry) * 0.035;
    rx += (targetX - rx) * 0.05;
  }
  return { rx: clampTilt(rx), ry, vx, vy };
}

/** Applies a pointer drag of dx, dy CSS pixels. */
export function dragSpin(spin: Spin, dx: number, dy: number): Spin {
  return {
    rx: clampTilt(spin.rx + dy * 0.006),
    ry: spin.ry + dx * 0.009,
    vx: dy * 0.006,
    vy: dx * 0.009,
  };
}

/** Ends a drag: the throw keeps its velocity only when motion is on. */
export function releaseSpin(spin: Spin, motion: boolean): Spin {
  return motion ? spin : { ...spin, vx: 0, vy: 0 };
}

export type KeyAction =
  | { type: "rotate"; drx: number; dry: number }
  | { type: "reset" }
  | { type: "exit" };

export function keyAction(key: string, shift: boolean): KeyAction | null {
  const step = shift ? 0.45 : 0.15;
  const tilt = 0.1;
  switch (key) {
    case "ArrowLeft":
      return { type: "rotate", drx: 0, dry: -step };
    case "ArrowRight":
      return { type: "rotate", drx: 0, dry: step };
    case "ArrowUp":
      return { type: "rotate", drx: -tilt, dry: 0 };
    case "ArrowDown":
      return { type: "rotate", drx: tilt, dry: 0 };
    case "Home":
    case "r":
    case "R":
    case "0":
      return { type: "reset" };
    case "Escape":
      return { type: "exit" };
    default:
      return null;
  }
}

export function applyKey(spin: Spin, action: Extract<KeyAction, { type: "rotate" }>): Spin {
  return { rx: clampTilt(spin.rx + action.drx), ry: spin.ry + action.dry, vx: 0, vy: 0 };
}

/** Continuous rendering only while the viewer is on screen and motion is on. */
export function frameloopFor({
  motion,
  visible,
}: {
  motion: boolean;
  visible: boolean;
}): "always" | "demand" | "never" {
  if (!visible) return "never";
  return motion ? "always" : "demand";
}
