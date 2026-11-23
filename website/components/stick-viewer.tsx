/**
 * The on-demand 3D StickS3. A client module: GuardianStage loads it through
 * next/dynamic only after "See in 3D" (no server render), so neither three.js
 * nor the STL models are fetched before a visitor asks for them.
 *
 * Geometry: M5Stack's StickS3 CAD (MIT), see public/models/NOTICE.txt. The
 * model set-up, lighting and drag feel are adapted from the owner's Doutor VPD
 * viewer (THIRD_PARTY_NOTICES.md). Only the StickS3 and its simulated screen
 * are drawn here.
 */

import { Canvas, useFrame, useLoader, useThree, type RootState } from "@react-three/fiber";
import {
  Suspense,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
} from "react";
import * as THREE from "three";
import { STLLoader } from "three/examples/jsm/loaders/STLLoader.js";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { toCreasedNormals } from "three/examples/jsm/utils/BufferGeometryUtils.js";
import type { Presentation } from "@/lib/guardian";
import { LABEL_H, LABEL_W, drawLabel, resolveLabelFonts } from "./back-label";
import {
  SCREEN_TEXTURE,
  applyKey,
  createScreenPainter,
  dragSpin,
  frameloopFor,
  keyAction,
  releaseSpin,
  restSpin,
  screenFor,
  stepSpin,
  type FailureReason,
  type ScreenImage,
  type ScreenSurface,
  type Spin,
} from "@/lib/viewer";

// Model units: the CAD is in millimetres, scaled to 0.1 scene units per mm.
const MM = 0.1;
const FRONT_Z = 0.652;
/** The back face of the case; the label sits just behind it (Doutor VPD: BACK_Z - 0.004). */
const BACK_Z = -0.75;
const SCREEN_W = 1.36;
const SCREEN_H = 2.42;
const SCREEN_Y = 0.69;
const SCREEN_Z = FRONT_Z - 0.02;
const IDLE_MS = 2200;
export const MODEL_PARTS = [
  "/models/sticks3-front.stl",
  "/models/sticks3-back.stl",
  "/models/sticks3-buttons.stl",
];

type Props = {
  view: Presentation;
  motion: boolean;
  onReady: () => void;
  onFail: (reason: FailureReason) => void;
  onExit: () => void;
};

export default function StickViewer({ view, motion, onReady, onFail, onExit }: Props) {
  const root = useRef<HTMLDivElement>(null);
  const three = useRef<RootState | null>(null);
  const spin = useRef<Spin>({ ...restSpin });
  const drag = useRef<{ id: number; x: number; y: number } | null>(null);
  const lastInteraction = useRef(-Infinity);
  const motionRef = useRef(motion);
  const [visible, setVisible] = useState(true);
  const [grabbing, setGrabbing] = useState(false);
  const hintId = useId();

  const invalidate = useCallback(() => three.current?.invalidate(), []);

  // Motion turned off mid-throw: drop the throw at once and draw the still model.
  useEffect(() => {
    motionRef.current = motion;
    if (!motion) spin.current = releaseSpin(spin.current, false);
    invalidate();
  }, [motion, invalidate]);

  // Render nothing while the viewer is scrolled away or the tab is hidden.
  useEffect(() => {
    const el = root.current;
    if (!el) return;
    let onScreen = true;
    const sync = () => setVisible(onScreen && document.visibilityState === "visible");
    const observer = new IntersectionObserver(([entry]) => {
      onScreen = entry.isIntersecting;
      sync();
    });
    observer.observe(el);
    document.addEventListener("visibilitychange", sync);
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", sync);
    };
  }, []);

  useEffect(() => {
    if (visible) invalidate();
  }, [visible, invalidate]);

  // Context-loss listener lives as long as the renderer; removed on unmount.
  const contextLost = useRef<(() => void) | null>(null);
  const handleCreated = useCallback(
    (state: RootState) => {
      three.current = state;
      const canvas = state.gl.domElement;
      const lost = (event: Event) => {
        event.preventDefault();
        onFail("context-lost");
      };
      canvas.addEventListener("webglcontextlost", lost);
      contextLost.current = () => canvas.removeEventListener("webglcontextlost", lost);
    },
    [onFail],
  );
  useEffect(
    () => () => {
      contextLost.current?.();
      contextLost.current = null;
      three.current = null;
      // A failed or finished load is not kept: the next activation fetches again.
      useLoader.clear(STLLoader, MODEL_PARTS);
    },
    [],
  );

  // Ready once the models have drawn and the screen holds its first picture.
  const parts = useRef({ model: false, screen: false, sent: false });
  const markReady = useCallback(
    (part: "model" | "screen") => {
      const p = parts.current;
      p[part] = true;
      if (p.model && p.screen && !p.sent) {
        p.sent = true;
        onReady();
      }
    },
    [onReady],
  );

  function endDrag(event: PointerEvent<HTMLDivElement>) {
    if (!drag.current || drag.current.id !== event.pointerId) return;
    drag.current = null;
    spin.current = releaseSpin(spin.current, motionRef.current);
    lastInteraction.current = performance.now();
    setGrabbing(false);
    invalidate();
  }

  return (
    <div
      ref={root}
      className="stick-viewer"
      data-grabbing={grabbing}
      role="group"
      aria-roledescription="3D model"
      aria-label={`StickS3 in 3D showing the simulated Guardian screen: ${view.label}`}
      aria-describedby={hintId}
      tabIndex={0}
      onPointerDown={(event) => {
        if (event.pointerType === "mouse" && event.button !== 0) return;
        event.currentTarget.setPointerCapture(event.pointerId);
        drag.current = { id: event.pointerId, x: event.clientX, y: event.clientY };
        spin.current = { ...spin.current, vx: 0, vy: 0 };
        setGrabbing(true);
      }}
      onPointerMove={(event) => {
        const d = drag.current;
        if (!d || d.id !== event.pointerId) return;
        const dx = event.clientX - d.x;
        const dy = event.clientY - d.y;
        d.x = event.clientX;
        d.y = event.clientY;
        spin.current = dragSpin(spin.current, dx, dy);
        lastInteraction.current = performance.now();
        invalidate();
      }}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onLostPointerCapture={endDrag}
      onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
        if (event.target !== event.currentTarget) return;
        const action = keyAction(event.key, event.shiftKey);
        if (!action) return;
        event.preventDefault();
        if (action.type === "exit") return onExit();
        spin.current = action.type === "reset" ? { ...restSpin } : applyKey(spin.current, action);
        lastInteraction.current = performance.now();
        invalidate();
      }}
    >
      <Canvas
        className="stick-viewer-canvas"
        frameloop={frameloopFor({ motion, visible })}
        dpr={[1, 2]}
        camera={{ position: [0, 0, 12.3], fov: 30 }}
        gl={{ antialias: true, alpha: true, toneMapping: THREE.ACESFilmicToneMapping }}
        onCreated={handleCreated}
      >
        <Suspense fallback={null}>
          <Studio />
          <Turntable
            spin={spin}
            dragging={drag}
            lastInteraction={lastInteraction}
            motion={motion}
            root={root}
          >
            <Model />
            <BackLabel />
            <Screen view={view} onFail={onFail} onPainted={() => markReady("screen")} root={root} />
          </Turntable>
          <BlobShadow />
          <Ready onReady={() => markReady("model")} />
        </Suspense>
      </Canvas>
      <p id={hintId} className="stick-viewer-hint">
        Drag or use arrow keys to rotate. Home resets. Esc returns to 2D.
      </p>
    </div>
  );
}

/** Mounts after Suspense has resolved the models; reports after two drawn frames. */
function Ready({ onReady }: { onReady: () => void }) {
  const invalidate = useThree((s) => s.invalidate);
  useEffect(() => {
    invalidate();
    let id = requestAnimationFrame(() => {
      invalidate();
      id = requestAnimationFrame(() => onReady());
    });
    return () => cancelAnimationFrame(id);
  }, [onReady, invalidate]);
  return null;
}

function Turntable({
  spin,
  dragging,
  lastInteraction,
  motion,
  root,
  children,
}: {
  spin: React.RefObject<Spin>;
  dragging: React.RefObject<unknown>;
  lastInteraction: React.RefObject<number>;
  motion: boolean;
  root: React.RefObject<HTMLDivElement | null>;
  children: React.ReactNode;
}) {
  const group = useRef<THREE.Group>(null);
  const frames = useRef(0);
  useFrame(({ clock }) => {
    const g = group.current;
    if (!g) return;
    if (!dragging.current) {
      spin.current = stepSpin(spin.current, {
        motion,
        idle: performance.now() - lastInteraction.current > IDLE_MS,
        time: clock.elapsedTime,
      });
    }
    g.rotation.set(spin.current.rx, spin.current.ry, 0);
    frames.current += 1;
    if (root.current) root.current.dataset.frames = String(frames.current);
  });
  return <group ref={group}>{children}</group>;
}

function Studio() {
  const gl = useThree((s) => s.gl);
  const scene = useThree((s) => s.scene);
  useEffect(() => {
    const pmrem = new THREE.PMREMGenerator(gl);
    const room = new RoomEnvironment();
    const env = pmrem.fromScene(room, 0.04).texture;
    scene.environment = env;
    scene.environmentIntensity = 0.85;
    return () => {
      scene.environment = null;
      env.dispose();
      pmrem.dispose();
      room.traverse((object) => {
        const mesh = object as THREE.Mesh;
        mesh.geometry?.dispose();
        const material = mesh.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(material)) material.forEach((m) => m.dispose());
        else material?.dispose();
      });
    };
  }, [gl, scene]);
  return (
    <>
      <directionalLight position={[3, 5, 6]} intensity={1.1} />
      <directionalLight position={[-5, 1, -4]} intensity={0.35} />
    </>
  );
}

/** A scaled copy with creased normals; the loaded STL itself is left untouched. */
function prepare(geometry: THREE.BufferGeometry) {
  // toCreasedNormals edits a non-indexed geometry (as STLLoader returns) in place.
  const g = toCreasedNormals(geometry.clone(), Math.PI / 5);
  g.scale(MM, MM, MM);
  return g;
}

function Model() {
  const [front, back, buttons] = useLoader(STLLoader, MODEL_PARTS);
  const geo = useMemo(() => {
    const keys = prepare(buttons);
    // Only the key cap that pokes out of the front shell is blue.
    const pos = keys.getAttribute("position");
    const colors = new Float32Array(pos.count * 3);
    const blue = new THREE.Color("#1e88ff");
    const dark = new THREE.Color("#2a2d31");
    for (let i = 0; i < pos.count; i += 3) {
      const z = (pos.getZ(i) + pos.getZ(i + 1) + pos.getZ(i + 2)) / 3;
      const c = z > FRONT_Z + 0.01 ? blue : dark;
      for (let j = 0; j < 3; j++) c.toArray(colors, (i + j) * 3);
    }
    keys.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    return { front: prepare(front), back: prepare(back), keys };
  }, [front, back, buttons]);

  useEffect(
    () => () => {
      geo.front.dispose();
      geo.back.dispose();
      geo.keys.dispose();
    },
    [geo],
  );

  return (
    <>
      <mesh geometry={geo.front}>
        <meshPhysicalMaterial color="#5a5e64" roughness={0.62} clearcoat={0.18} clearcoatRoughness={0.55} />
      </mesh>
      <mesh geometry={geo.back}>
        <meshPhysicalMaterial color="#4c5056" roughness={0.68} clearcoat={0.1} clearcoatRoughness={0.6} />
      </mesh>
      <mesh geometry={geo.keys}>
        <meshPhysicalMaterial vertexColors roughness={0.38} clearcoat={0.5} clearcoatRoughness={0.3} />
      </mesh>
    </>
  );
}

/** The printed label that closes the open back of the case model (see back-label.ts). */
function BackLabel() {
  const [texture, setTexture] = useState<THREE.CanvasTexture | null>(null);
  const gl = useThree((s) => s.gl);
  const invalidate = useThree((s) => s.invalidate);

  useEffect(() => {
    let cancelled = false;
    let tex: THREE.CanvasTexture | null = null;
    document.fonts.ready.then(() => {
      if (cancelled) return;
      tex = new THREE.CanvasTexture(drawLabel(resolveLabelFonts()));
      tex.colorSpace = THREE.SRGBColorSpace;
      tex.anisotropy = gl.capabilities.getMaxAnisotropy();
      setTexture(tex);
      invalidate();
    });
    return () => {
      cancelled = true;
      tex?.dispose();
    };
  }, [gl, invalidate]);

  if (!texture) return null;
  return (
    <mesh position={[0, 0, BACK_Z - 0.004]} rotation-y={Math.PI}>
      <planeGeometry args={[LABEL_W, LABEL_H]} />
      <meshStandardMaterial map={texture} roughness={0.55} transparent alphaTest={0.5} />
    </mesh>
  );
}

function loadImage(src: string) {
  return new Promise<ScreenImage>((resolve, reject) => {
    const image = new Image();
    image.decoding = "async";
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error(`Could not load ${src}`));
    image.src = src;
  });
}

/** The simulated display: a canvas texture on a plane set into the front bezel. */
function Screen({
  view,
  onFail,
  onPainted,
  root,
}: {
  view: Presentation;
  onFail: (reason: FailureReason) => void;
  onPainted: () => void;
  root: React.RefObject<HTMLDivElement | null>;
}) {
  const invalidate = useThree((s) => s.invalidate);
  const [surface, setSurface] = useState<{
    texture: THREE.CanvasTexture;
    painter: ReturnType<typeof createScreenPainter>;
  } | null>(null);
  const callbacks = useRef({ onFail, onPainted });
  callbacks.current = { onFail, onPainted };

  useEffect(() => {
    const canvas = document.createElement("canvas");
    canvas.width = SCREEN_TEXTURE.width;
    canvas.height = SCREEN_TEXTURE.height;
    const context = canvas.getContext("2d");
    if (!context) {
      callbacks.current.onFail("renderer");
      return;
    }
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = 4;
    const painter = createScreenPainter({
      surface: context satisfies ScreenSurface,
      load: loadImage,
      onChange: () => {
        texture.needsUpdate = true;
        const state = painter.state();
        if (root.current) {
          root.current.dataset.screenKey = state.key ?? "";
          root.current.dataset.screenFace = state.faceDrawn ? "drawn" : "none";
        }
        if (state.faceDrawn || state.kind === "no-data") callbacks.current.onPainted();
        invalidate();
      },
      onError: () => callbacks.current.onFail("face"),
    });
    setSurface({ texture, painter });
    return () => {
      painter.dispose();
      texture.dispose();
      setSurface(null);
    };
  }, [invalidate, root]);

  // The presentation object is rebuilt on every render; the key names what is on screen.
  const spec = screenFor(view);
  const latest = useRef(spec);
  latest.current = spec;
  useEffect(() => {
    surface?.painter.show(latest.current);
  }, [surface, spec.key]);

  if (!surface) return null;
  return (
    <mesh position={[0, SCREEN_Y, SCREEN_Z]}>
      <planeGeometry args={[SCREEN_W, SCREEN_H]} />
      <meshBasicMaterial map={surface.texture} toneMapped={false} />
    </mesh>
  );
}

/** A soft shadow under the device from one small gradient texture. */
function BlobShadow() {
  const texture = useMemo(() => {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 128;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      const g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
      g.addColorStop(0, "rgba(0,0,0,0.55)");
      g.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, 128, 128);
    }
    return new THREE.CanvasTexture(canvas);
  }, []);
  useEffect(() => () => texture.dispose(), [texture]);
  return (
    <mesh position={[0, -3.1, 0]} rotation={[-Math.PI / 2, 0, 0]}>
      <planeGeometry args={[3.2, 1.6]} />
      <meshBasicMaterial map={texture} transparent depthWrite={false} toneMapped={false} />
    </mesh>
  );
}
