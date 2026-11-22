import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const site = new URL("..", import.meta.url).pathname;
const root = join(site, "..");
const models = join(site, "public/models");

test("only the three StickS3 parts are served, with the hashes their notice records", () => {
  const files = readdirSync(models).sort();
  assert.deepEqual(files, [
    "NOTICE.txt",
    "sticks3-back.stl",
    "sticks3-buttons.stl",
    "sticks3-front.stl",
  ]);
  const notice = readFileSync(join(models, "NOTICE.txt"), "utf8");
  for (const name of files.filter((f) => f.endsWith(".stl"))) {
    const bytes = readFileSync(join(models, name));
    const sha = createHash("sha256").update(bytes).digest("hex");
    assert.match(notice, new RegExp(`${name}\\s+[\\d,]+ B\\s+sha256 ${sha}`), name);
  }
  assert.match(notice, /Copyright \(c\) 2021 M5Stack/);
  assert.match(notice, /Products\/K150_StickS3\/Structures\/StickS3\.stl/);
  assert.match(notice, /8231e759560ce63d864c8987b8ca12f9c09c825b/);
});

test("the root notices carry the M5Stack MIT text and the viewer's adaptation basis", () => {
  const notices = readFileSync(join(root, "THIRD_PARTY_NOTICES.md"), "utf8");
  const start = notices.indexOf("## StickS3 3D model and viewer");
  assert.ok(start >= 0, "section present");
  const section = notices.slice(start);
  assert.match(section, /Copyright \(c\) 2021 M5Stack/);
  assert.match(section, /THE SOFTWARE IS PROVIDED "AS IS"/);
  assert.match(section, /Adapted viewer source/);
  assert.match(section, /Basis:/);
});

test("the 3D view holds only the StickS3 and its screen", () => {
  // Code only: the header comment names the adapted source.
  const viewer = readFileSync(join(site, "components/stick-viewer.tsx"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
  // No head model, Blender/GLB export or sibling-product detail.
  assert.doesNotMatch(viewer, /GLTFLoader|\.glb|\.gltf|useGLTF|OBJLoader|FBXLoader/i);
  assert.doesNotMatch(viewer, /sticker|doutor-vpd\/|VPD|ENV III|head mode/i);
  const loaded = viewer.match(/"\/models\/[^"]+"/g) ?? [];
  assert.deepEqual(loaded, [
    '"/models/sticks3-front.stl"',
    '"/models/sticks3-back.stl"',
    '"/models/sticks3-buttons.stl"',
  ]);
  assert.ok(!existsSync(join(site, "public/models/guardian-head.glb")));
});
