import { test } from "node:test";
import assert from "node:assert/strict";
import { LABEL_H, LABEL_PX_H, LABEL_PX_W, LABEL_TEXT, LABEL_W, drawLabel } from "../components/back-label.ts";

/** A canvas whose 2D context records the text it draws and refuses anything it does not model. */
function recordingDocument() {
  const texts: string[] = [];
  const canvas = {
    width: 0,
    height: 0,
    getContext: (kind: string) => {
      assert.equal(kind, "2d");
      return {
        fillStyle: "",
        font: "",
        textAlign: "left",
        textBaseline: "alphabetic",
        beginPath() {},
        roundRect() {},
        fill() {},
        save() {},
        clip() {},
        restore() {},
        fillRect() {},
        measureText: (t: string) => ({ width: t.length * 12 }),
        fillText: (t: string) => void texts.push(t),
      };
    },
  };
  const doc = { createElement: (tag: string) => (assert.equal(tag, "canvas"), canvas) };
  return { doc: doc as unknown as Pick<Document, "createElement">, canvas, texts };
}

test("the back label keeps the Doutor VPD sticker size and aspect", () => {
  assert.equal(LABEL_W, 1.9);
  assert.equal(LABEL_H, 3.9);
  assert.equal(LABEL_PX_H, Math.round((LABEL_PX_W * LABEL_H) / LABEL_W));
});

test("drawLabel paints a full-size canvas with the Guardian text and no Doutor VPD wording", () => {
  const { doc, canvas, texts } = recordingDocument();
  const out = drawLabel({ sans: "sans-serif", mono: "monospace" }, doc);
  assert.equal(out, canvas);
  assert.equal(canvas.width, LABEL_PX_W);
  assert.equal(canvas.height, LABEL_PX_H);
  for (const needed of ["M5", "GUARDIAN", LABEL_TEXT.subtitle, ...LABEL_TEXT.chips, ...LABEL_TEXT.specs, LABEL_TEXT.repo, LABEL_TEXT.rights]) {
    assert.ok(texts.includes(needed), `missing "${needed}"`);
  }
  for (const pin of LABEL_TEXT.pins) assert.ok(texts.includes(pin), `missing pin ${pin}`);
  assert.ok(!texts.some((t) => /vpd|doutor/i.test(t)), "no Doutor VPD text on the Guardian label");
});
