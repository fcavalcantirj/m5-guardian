import { test } from "node:test";
import assert from "node:assert/strict";
import { moods, getPresentation, type Scenario } from "./guardian.ts";
import {
  BASE_RX,
  BASE_RY,
  classifyFailure,
  createScreenPainter,
  drawScreen,
  failureMessage,
  frameloopFor,
  initialViewer,
  keyAction,
  releaseSpin,
  screenFor,
  stepSpin,
  viewerReducer,
  type ScreenImage,
  type ScreenSurface,
  type ViewerState,
} from "./viewer.ts";

const scenarios: Scenario[] = ["normal", "nearby", "alert", "stale"];

/** Records every drawing call so a test can see what a screen holds. */
function recordingSurface() {
  const ops: string[] = [];
  const surface: ScreenSurface = {
    canvas: { width: 270, height: 480 },
    fillStyle: "",
    font: "",
    textAlign: "center",
    textBaseline: "middle",
    clearRect: (x, y, w, h) => void ops.push(`clear ${x},${y},${w},${h}`),
    fillRect: (x, y, w, h) => void ops.push(`fill ${x},${y},${w},${h}`),
    fillText: (text) => void ops.push(`text ${text}`),
    drawImage: (image) => void ops.push(`image ${(image as { src: string }).src}`),
  };
  return { surface, ops };
}

function deferredLoader() {
  const pending = new Map<
    string,
    { resolve: (img: ScreenImage) => void; reject: (e: Error) => void }[]
  >();
  const load = (src: string) =>
    new Promise<ScreenImage>((resolve, reject) => {
      const list = pending.get(src) ?? [];
      list.push({ resolve, reject });
      pending.set(src, list);
    });
  const resolve = async (src: string) => {
    for (const p of pending.get(src) ?? []) p.resolve({ src } as ScreenImage);
    pending.delete(src);
    await new Promise((r) => setTimeout(r, 0));
  };
  const reject = async (src: string) => {
    for (const p of pending.get(src) ?? []) p.reject(new Error("404"));
    pending.delete(src);
    await new Promise((r) => setTimeout(r, 0));
  };
  return { load, resolve, reject };
}

test("all twenty mood and scenario pairs map to the presentation's screen", () => {
  const keys = new Set<string>();
  let count = 0;
  for (const mood of moods) {
    for (const scenario of scenarios) {
      count++;
      const view = getPresentation(mood, scenario);
      const screen = screenFor(view);
      keys.add(screen.key);
      if (scenario === "stale") {
        assert.equal(screen.kind, "no-data", `${mood.id}/${scenario}`);
        assert.equal(screen.image, null);
        assert.equal(screen.heading, "NO FRESH DATA");
        // Same negation as the 2D portrait; never a positive all-clear.
        assert.equal(screen.detail, "Silence isn’t an all-clear.");
        assert.doesNotMatch(screen.detail, /\bsafe\b|secure/i);
        continue;
      }
      assert.equal(screen.kind, "face", `${mood.id}/${scenario}`);
      assert.equal(screen.image, view.image);
      assert.equal(screen.heading, view.label.toUpperCase());
      if (scenario === "normal") {
        assert.equal(screen.image, mood.image);
        assert.equal(screen.tone, mood.tone);
      }
      if (scenario === "nearby") {
        assert.equal(screen.image, mood.image);
        assert.equal(screen.tone, "amber");
        assert.match(screen.detail, new RegExp(mood.name, "i"));
      }
      if (scenario === "alert") {
        assert.equal(screen.image, `/images/${mood.id}-alert.png`);
        assert.equal(screen.tone, "red");
      }
    }
  }
  assert.equal(count, 20);
  // Fifteen distinct rated screens plus one shared no-data screen.
  assert.equal(keys.size, 16);
});

test("a stale screen is cleared and draws no face", () => {
  const { surface, ops } = recordingSurface();
  drawScreen(surface, screenFor(getPresentation(moods[0], "stale")), null);
  assert.equal(ops[0], "clear 0,0,270,480");
  assert.ok(!ops.some((op) => op.startsWith("image")));
  assert.ok(ops.includes("text NO FRESH DATA"));
});

test("switching to stale before the previous face loads leaves no face on the screen", async () => {
  const { surface, ops } = recordingSurface();
  const loader = deferredLoader();
  let changes = 0;
  const failures: string[] = [];
  const painter = createScreenPainter({
    surface,
    load: loader.load,
    onChange: () => changes++,
    onError: (src) => failures.push(src),
  });
  painter.show(screenFor(getPresentation(moods[1], "normal")));
  assert.equal(painter.state().faceDrawn, false);
  painter.show(screenFor(getPresentation(moods[1], "stale")));
  ops.length = 0;
  await loader.resolve(moods[1].image);
  assert.deepEqual(ops, [], "a late face must not be painted over the stale screen");
  assert.equal(painter.state().kind, "no-data");
  assert.equal(painter.state().faceDrawn, false);
  assert.deepEqual(failures, []);
  assert.ok(changes >= 2);
});

test("a face replaced by stale is cleared, and the face returns with fresh data", async () => {
  const { surface, ops } = recordingSurface();
  const loader = deferredLoader();
  const painter = createScreenPainter({
    surface,
    load: loader.load,
    onChange: () => {},
    onError: () => {},
  });
  painter.show(screenFor(getPresentation(moods[2], "alert")));
  await loader.resolve("/images/medium-alert.png");
  assert.equal(painter.state().faceDrawn, true);
  assert.ok(ops.includes("image /images/medium-alert.png"));
  ops.length = 0;
  painter.show(screenFor(getPresentation(moods[2], "stale")));
  assert.equal(ops[0], "clear 0,0,270,480");
  assert.ok(!ops.some((op) => op.startsWith("image")));
  assert.equal(painter.state().faceDrawn, false);
  ops.length = 0;
  // Loaded before: the face is painted at once, after a clear.
  painter.show(screenFor(getPresentation(moods[2], "alert")));
  assert.equal(ops[0], "clear 0,0,270,480");
  assert.ok(ops.includes("image /images/medium-alert.png"));
  assert.equal(painter.state().faceDrawn, true);
});

test("a failed face image is reported once and nothing is painted after dispose", async () => {
  const { surface, ops } = recordingSurface();
  const loader = deferredLoader();
  const failures: string[] = [];
  const painter = createScreenPainter({
    surface,
    load: loader.load,
    onChange: () => {},
    onError: (src) => failures.push(src),
  });
  painter.show(screenFor(getPresentation(moods[3], "normal")));
  await loader.reject(moods[3].image);
  assert.deepEqual(failures, [moods[3].image]);
  painter.show(screenFor(getPresentation(moods[4], "normal")));
  painter.dispose();
  ops.length = 0;
  await loader.resolve(moods[4].image);
  assert.deepEqual(ops, []);
});

test("toggling modes keeps the selection outside the viewer state and ignores late events", () => {
  let state: ViewerState = initialViewer;
  state = viewerReducer(state, { type: "activate" });
  assert.equal(state.mode, "loading");
  const first = state.attempt;
  state = viewerReducer(state, { type: "ready", attempt: first });
  assert.equal(state.mode, "3d");
  state = viewerReducer(state, { type: "back" });
  assert.deepEqual(state, { mode: "2d", failure: null, attempt: first });
  // A late ready or failure from the closed viewer changes nothing.
  assert.deepEqual(viewerReducer(state, { type: "ready", attempt: first }), state);
  assert.deepEqual(
    viewerReducer(state, { type: "fail", attempt: first, reason: "model" }),
    state,
  );
  state = viewerReducer(state, { type: "activate" });
  assert.equal(state.attempt, first + 1);
  assert.deepEqual(
    viewerReducer(state, { type: "ready", attempt: first }),
    state,
    "a ready from an earlier attempt is ignored",
  );
  state = viewerReducer(state, { type: "fail", attempt: first + 1, reason: "chunk" });
  assert.deepEqual(state, { mode: "2d", failure: "chunk", attempt: first + 1 });
  // Activating again clears the explanation.
  assert.equal(viewerReducer(state, { type: "activate" }).failure, null);
  // The reducer holds only the viewer mode: no mood, scenario or motion.
  assert.deepEqual(Object.keys(state).sort(), ["attempt", "failure", "mode"]);
});

test("every failure falls back with a visible explanation", () => {
  const reasons = ["no-webgl", "renderer", "chunk", "model", "face", "context-lost"] as const;
  for (const reason of reasons) {
    const message = failureMessage(reason);
    assert.match(message, /2D/);
    assert.ok(message.length > 20);
  }
  const chunk = new Error("Loading chunk 123 failed.");
  chunk.name = "ChunkLoadError";
  assert.equal(classifyFailure(chunk), "chunk");
  assert.equal(
    classifyFailure(new TypeError("Failed to fetch dynamically imported module: /x.js")),
    "chunk",
  );
  assert.equal(
    classifyFailure(new Error("Could not load /models/sticks3-front.stl: 404")),
    "model",
  );
  assert.equal(classifyFailure(new Error("Error creating WebGL context.")), "renderer");
  assert.equal(classifyFailure("anything"), "renderer");
});

test("motion off stops automatic rotation and inertial settling", () => {
  const spun = { rx: 0.1, ry: 0.4, vx: 0.05, vy: 0.2 };
  const still = stepSpin(spun, { motion: false, idle: true, time: 3 });
  assert.equal(still.rx, 0.1);
  assert.equal(still.ry, 0.4);
  assert.equal(still.vx, 0);
  assert.equal(still.vy, 0);
  const settling = stepSpin(spun, { motion: true, idle: false, time: 3 });
  assert.notEqual(settling.ry, 0.4);
  const rest = { rx: BASE_RX, ry: BASE_RY, vx: 0, vy: 0 };
  const auto = stepSpin(rest, { motion: true, idle: true, time: 3 });
  assert.notEqual(auto.ry, BASE_RY, "idle motion sways the model");
  assert.deepEqual(stepSpin(rest, { motion: false, idle: true, time: 3 }), rest);
  // Letting go with motion off drops the throw.
  assert.deepEqual(releaseSpin(spun, false), { ...spun, vx: 0, vy: 0 });
  assert.deepEqual(releaseSpin(spun, true), spun);
});

test("arrow keys rotate, Home resets and Escape returns to 2D", () => {
  assert.deepEqual(keyAction("ArrowLeft", false), { type: "rotate", drx: 0, dry: -0.15 });
  assert.deepEqual(keyAction("ArrowRight", true), { type: "rotate", drx: 0, dry: 0.45 });
  assert.deepEqual(keyAction("ArrowUp", false), { type: "rotate", drx: -0.1, dry: 0 });
  assert.deepEqual(keyAction("ArrowDown", false), { type: "rotate", drx: 0.1, dry: 0 });
  assert.deepEqual(keyAction("Home", false), { type: "reset" });
  assert.deepEqual(keyAction("r", false), { type: "reset" });
  assert.deepEqual(keyAction("Escape", false), { type: "exit" });
  assert.equal(keyAction("a", false), null);
});

test("rendering runs continuously only while visible with motion on", () => {
  assert.equal(frameloopFor({ motion: true, visible: true }), "always");
  assert.equal(frameloopFor({ motion: false, visible: true }), "demand");
  assert.equal(frameloopFor({ motion: true, visible: false }), "never");
  assert.equal(frameloopFor({ motion: false, visible: false }), "never");
});
