import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// W07 install page wiring, read as text: the heavy flasher code loads only after a click (the Lighthouse gate),
// analytics only on Vercel, the real-stick smoke never in CI, and the owner's licence grant in both art notices.

const site = new URL("..", import.meta.url).pathname;
const repo = new URL("../..", import.meta.url).pathname;
const read = (path: string) => readFileSync(path, "utf8");

test("esptool-js and spark-md5 are imported only dynamically, inside the click handler", () => {
  const flasher = read(join(site, "components/install/flasher.tsx"));
  assert.doesNotMatch(flasher, /^import[^;]*from "esptool-js"/m);
  assert.doesNotMatch(flasher, /^import[^;]*from "spark-md5"/m);
  assert.match(flasher, /await withTimeout\(import\("esptool-js"\)/);
  assert.match(flasher, /await import\("spark-md5"\)/);
  for (const path of ["app/install/page.tsx", "app/page.tsx", "app/layout.tsx"])
    assert.doesNotMatch(read(join(site, path)), /esptool-js|spark-md5/, `${path}: no flasher import in a page`);
});

test("the port request is filtered to Espressif's USB vendor and the analytics carry no device data", () => {
  const flasher = read(join(site, "components/install/flasher.tsx"));
  assert.match(flasher, /requestPort\(\{ filters: \[\{ usbVendorId: ESPRESSIF_USB_VENDOR \}\] \}\)/);
  const calls = [...flasher.matchAll(/track\(([^)]*)\)/g)].map((m) => m[1]);
  assert.deepEqual(calls, ["ANALYTICS_EVENT, stepEvent(what, result"]);
});

test("Vercel Web Analytics is mounted on the install page only, and only in a Vercel build", () => {
  const install = read(join(site, "app/install/page.tsx"));
  assert.match(install, /\{process\.env\.VERCEL === "1" && <Analytics \/>\}/);
  for (const path of ["app/layout.tsx", "app/page.tsx"]) assert.doesNotMatch(read(join(site, path)), /Analytics/);
});

test("the real-stick smoke is owner-run: its own config, headed Chrome, outside the CI test folder", () => {
  const smoke = read(join(site, "playwright.stick.config.ts"));
  assert.match(smoke, /testDir: "\.\/stick-smoke"/);
  assert.match(smoke, /channel: "chrome"/);
  assert.match(smoke, /headless: false/);
  assert.match(read(join(site, "playwright.config.ts")), /testDir: "\.\/e2e"/);
  assert.match(read(join(site, "stick-smoke/stick.spec.ts")), /test\.skip\(process\.env\.STICK_SMOKE !== "1"/);
});

test("both artwork notices carry the owner's grant to flash the official image, personal and non-commercial", (t) => {
  const paths = [join(site, "public/images/LICENSE"), join(repo, "firmware/art/LICENSE")];
  for (const path of paths) {
    if (!existsSync(path)) return t.skip(`${path} is not part of the upload`);
    const text = read(path).replace(/\s+/g, " ");
    assert.match(text, /Flash the official M5 Guardian image, which contains the artwork, from the project website \(https:\/\/m5-guardian\.vercel\.app\/install\) onto your own device, for your own personal, non-commercial use\./);
    assert.match(text, /All rights reserved\./);
  }
});
