import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderIcons } from "../scripts/icons.mjs";

// W08 icons: app/favicon.ico (16, 32 and 48 px) and app/apple-icon.png (180 px)
// are generated from app/icon.svg by scripts/icons.mjs (resvg through next/og,
// the same renderer as the social cards; deterministic). The committed files
// must be exactly what the script makes from the committed SVG, so an edit to
// the SVG without regenerating fails here.

const site = new URL("..", import.meta.url).pathname;
const committedIco = readFileSync(join(site, "app/favicon.ico"));
const committedApple = readFileSync(join(site, "app/apple-icon.png"));

function pngSize(bytes: Buffer) {
  assert.equal(bytes.subarray(0, 8).toString("hex"), "89504e470d0a1a0a", "PNG signature");
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

/** The images of an ICO file: header, directory entries and each PNG payload. */
function readIco(bytes: Buffer) {
  assert.equal(bytes.readUInt16LE(0), 0, "reserved");
  assert.equal(bytes.readUInt16LE(2), 1, "type 1 = icon");
  const count = bytes.readUInt16LE(4);
  return Array.from({ length: count }, (_, i) => {
    const entry = 6 + 16 * i;
    const size = bytes.readUInt32LE(entry + 8);
    const offset = bytes.readUInt32LE(entry + 12);
    assert.ok(offset + size <= bytes.length, `image ${i} inside the file`);
    return {
      width: bytes[entry] || 256,
      height: bytes[entry + 1] || 256,
      planes: bytes.readUInt16LE(entry + 4),
      bitCount: bytes.readUInt16LE(entry + 6),
      png: bytes.subarray(offset, offset + size),
    };
  });
}

test("favicon.ico holds 16, 32 and 48 px PNG images whose pixels match the directory", () => {
  const images = readIco(committedIco);
  assert.deepEqual(images.map((i) => i.width), [16, 32, 48]);
  for (const image of images) {
    assert.equal(image.height, image.width);
    assert.equal(image.planes, 1);
    assert.equal(image.bitCount, 32);
    assert.deepEqual(pngSize(image.png), { width: image.width, height: image.width });
  }
});

test("apple-icon.png is 180 x 180", () => {
  assert.deepEqual(pngSize(committedApple), { width: 180, height: 180 });
});

test("the committed icons are exactly what scripts/icons.mjs makes from app/icon.svg", async () => {
  const fresh = await renderIcons(readFileSync(join(site, "app/icon.svg")));
  assert.ok(fresh.ico.equals(committedIco), "app/favicon.ico is stale: run node scripts/icons.mjs");
  assert.ok(fresh.appleIcon.equals(committedApple), "app/apple-icon.png is stale: run node scripts/icons.mjs");
});
