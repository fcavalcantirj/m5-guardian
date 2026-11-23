// The StickS3's back label for the 3D viewer. The model's back shell is open (the STL is the case as
// printed), so without a label the viewer shows the inside of the front shell. Adapted from the owner's
// Doutor VPD back sticker (MIT, see THIRD_PARTY_NOTICES.md): same size and placement, Guardian text only
// (the persona art is not drawn here).
export const LABEL_W = 1.9;
export const LABEL_H = 3.9;

export const LABEL_PX_W = 760;
export const LABEL_PX_H = Math.round((LABEL_PX_W * LABEL_H) / LABEL_W);

export type LabelFonts = { sans: string; mono: string };

export const LABEL_TEXT = {
  title: "M5 GUARDIAN",
  subtitle: "Receive-only Wi-Fi monitor",
  chips: ["RX ONLY", "2.4 GHz", "PASSIVE"],
  specs: ["M5Stack StickS3", "ESP32-S3 · 8 MB flash · 8 MB PSRAM", "135 × 240 colour display"],
  pins: ["G1", "G2", "G8", "G9", "GND", "5V", "BAT"],
  repo: "github.com/fcavalcantirj/m5-guardian",
  rights: "Firmware MIT · persona art © all rights reserved",
} as const;

const INK = "#141716";
const PAPER = "#f3f4ef";
const LIME = "#b5f36a";
const LIME_INK = "#142006";
const GREY = "#5b615d";

function fontOf(className: string) {
  const el = document.createElement("span");
  el.className = className;
  el.style.position = "absolute";
  el.style.visibility = "hidden";
  document.body.appendChild(el);
  const family = getComputedStyle(el).fontFamily;
  el.remove();
  return family;
}

/** The site's own families, read from the page so the canvas matches the 2D view. */
export function resolveLabelFonts(): LabelFonts {
  return { sans: fontOf("font-sans"), mono: fontOf("font-mono") };
}

function chip(ctx: CanvasRenderingContext2D, f: LabelFonts, x: number, y: number, label: string) {
  ctx.font = `700 22px ${f.mono}`;
  const w = ctx.measureText(label).width + 24;
  ctx.beginPath();
  ctx.roundRect(x, y, w, 36, 7);
  ctx.fillStyle = INK;
  ctx.fill();
  ctx.fillStyle = LIME;
  ctx.textBaseline = "middle";
  ctx.textAlign = "left";
  ctx.fillText(label, x + 12, y + 19);
  return w;
}

/** Paints the label onto a new canvas (LABEL_PX_W x LABEL_PX_H). */
export function drawLabel(f: LabelFonts, doc: Pick<Document, "createElement"> = document) {
  const c = doc.createElement("canvas");
  c.width = LABEL_PX_W;
  c.height = LABEL_PX_H;
  const ctx = c.getContext("2d");
  if (!ctx) return c;
  const pad = 44;

  ctx.beginPath();
  ctx.roundRect(0, 0, LABEL_PX_W, LABEL_PX_H, 64);
  ctx.fillStyle = PAPER;
  ctx.fill();
  ctx.save();
  ctx.clip();

  // Header pin strip, as on the real StickS3.
  ctx.fillStyle = INK;
  ctx.fillRect(0, 0, LABEL_PX_W, 96);
  ctx.font = `700 24px ${f.mono}`;
  ctx.fillStyle = "#ffffff";
  ctx.textBaseline = "middle";
  ctx.textAlign = "center";
  const step = (LABEL_PX_W - pad * 2) / LABEL_TEXT.pins.length;
  LABEL_TEXT.pins.forEach((p, i) => ctx.fillText(p, pad + step * (i + 0.5), 54));

  // Name block.
  let y = 170;
  ctx.fillStyle = LIME;
  ctx.fillRect(pad, y, 10, 150);
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = INK;
  ctx.font = `800 82px ${f.sans}`;
  ctx.fillText("M5", pad + 34, y + 70);
  ctx.fillText("GUARDIAN", pad + 34, y + 150);
  y += 210;
  ctx.font = `500 32px ${f.sans}`;
  ctx.fillStyle = GREY;
  ctx.fillText(LABEL_TEXT.subtitle, pad, y);

  // Chips.
  y += 44;
  let x = pad;
  for (const c2 of LABEL_TEXT.chips) x += chip(ctx, f, x, y, c2) + 12;

  // Specs.
  y += 110;
  ctx.fillStyle = INK;
  ctx.fillRect(pad, y - 40, LABEL_PX_W - pad * 2, 2);
  ctx.font = `600 28px ${f.mono}`;
  for (const line of LABEL_TEXT.specs) {
    ctx.fillStyle = INK;
    ctx.fillText(line, pad, y);
    y += 50;
  }

  // Lime band with the repository.
  const bandY = LABEL_PX_H - 250;
  ctx.fillStyle = LIME;
  ctx.fillRect(0, bandY, LABEL_PX_W, 92);
  ctx.fillStyle = LIME_INK;
  ctx.font = `700 26px ${f.mono}`;
  ctx.textBaseline = "middle";
  ctx.fillText(LABEL_TEXT.repo, pad, bandY + 47);

  // Rights line.
  ctx.fillStyle = GREY;
  ctx.font = `500 22px ${f.sans}`;
  ctx.fillText(LABEL_TEXT.rights, pad, LABEL_PX_H - 110);

  ctx.restore();
  return c;
}
