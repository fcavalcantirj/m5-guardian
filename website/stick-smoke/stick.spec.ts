import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";

// W07 OWNER-RUN real-stick smoke (playwright.stick.config.ts; never in CI, never run by an agent session). It flashes
// the owner's own StickS3 through the install page exactly as a visitor would, and reads the stick's own answer
// (STATUS over the same USB port) after every step instead of asking the owner. Order:
//   A  backup of what is on the stick (the page's sha256 = the downloaded file's sha256, 8 MB)
//   B  restore a NON-Guardian 8 MB image (STICK_FOREIGN_IMAGE), so the next step starts from another firmware
//   C  First install from that image: the stick answers STATUS as a fresh Guardian (no Wi-Fi stored)
//   D  restore backup A (MD5 of the 8 MB read back on the chip = the file): STATUS S1
//   E  Update: STATUS S2 keeps S1's settings= and wifi_provisioned=, app_version is the release (-rel)
//   F  restore backup A again: the stick is left exactly as found (STATUS S3 app_version = S1's)
// Environment: STICK_SMOKE=1, STICK_SMOKE_OUT=<folder on the store>, STICK_FOREIGN_IMAGE=<8 MB non-Guardian image>,
// optional STICK_SMOKE_URL (a deployment; default: next start of this build). The first port picker needs the
// owner's click on the stick; later pickers reuse that granted port (one StickS3 on the computer). backup-A.bin holds
// the stick's stored Wi-Fi credential: keep STICK_SMOKE_OUT on the owner's store, never in the repository.
// Run: STICK_SMOKE=1 STICK_SMOKE_OUT=... STICK_FOREIGN_IMAGE=... pnpm run test:stick (after next build).

const out = process.env.STICK_SMOKE_OUT ?? "";
const foreign = process.env.STICK_FOREIGN_IMAGE ?? "";
const FLASH = 8 * 1024 * 1024;
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const STEP_TIMEOUT = 6 * 60_000;

test.skip(process.env.STICK_SMOKE !== "1", "owner-run smoke: set STICK_SMOKE=1 with a StickS3 on the cable");

/** After the first real picker, requestPort hands back the one port this origin was granted. */
async function reuseGrantedPort(page: Page) {
  await page.addInitScript(() => {
    const serial = navigator.serial;
    const ask = serial.requestPort.bind(serial);
    serial.requestPort = async (options?: SerialPortRequestOptions) => {
      const granted = await serial.getPorts();
      return granted.length === 1 ? granted[0] : ask(options);
    };
  });
}

/** The stick's STATUS line over USB (the read-only console verb), or null when no Guardian answers in `ms`. */
async function readStatus(page: Page, ms = 40_000): Promise<string | null> {
  return page.evaluate(async (ms) => {
    const [port] = await navigator.serial.getPorts();
    if (!port) throw new Error("no granted port");
    const end = Date.now() + ms;
    await new Promise((r) => setTimeout(r, 4000)); // the stick boots after the page's restart
    await port.open({ baudRate: 115200 });
    try {
      await port.setSignals({ dataTerminalReady: false, requestToSend: false });
      const writer = port.writable!.getWriter();
      const reader = port.readable!.getReader();
      const decoder = new TextDecoder();
      let text = "";
      try {
        while (Date.now() < end) {
          await writer.write(new TextEncoder().encode("STATUS\n"));
          const until = Date.now() + 2000;
          while (Date.now() < until) {
            const chunk = await Promise.race([reader.read(), new Promise<null>((r) => setTimeout(() => r(null), until - Date.now()))]);
            if (!chunk || chunk.done) break;
            text += decoder.decode(chunk.value, { stream: true });
            const line = text.split(/\r?\n/).find((l) => l.includes("app_version="));
            if (line) return line;
          }
        }
        return null;
      } finally {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
        writer.releaseLock();
      }
    } finally {
      await port.close();
    }
  }, ms);
}

const token = (line: string | null, key: string) => line?.match(new RegExp(`(?:^|\\s)${key}=(\\S+)`))?.[1] ?? null;

async function choose(page: Page, mode: "Update" | "First install" | "Restore a backup") {
  await page.getByRole("radio", { name: new RegExp(mode) }).check();
}

async function waitDone(page: Page, action: string) {
  await expect(page.getByTestId("flasher-error")).toHaveCount(0);
  await expect(page.getByTestId("flasher-done")).toHaveAttribute("data-action", action, { timeout: STEP_TIMEOUT });
}

async function restore(page: Page, file: string) {
  await choose(page, "Restore a backup");
  await page.getByTestId("flasher-restore-file").setInputFiles(file);
  await expect(page.getByTestId("flasher-restore-info")).toContainText(sha(readFileSync(file)));
  await page.getByRole("checkbox", { name: /replaced by this backup/ }).check();
  await page.getByTestId("flasher-button").click();
  await page.getByTestId("flasher-confirm-yes").click();
  await waitDone(page, "restore");
  await expect(page.getByTestId("flasher-done")).toContainText("read back the same");
}

test("backup, first install from another firmware, update keeps settings, restore byte-exact", async ({ page }) => {
  expect(out && existsSync(out), "STICK_SMOKE_OUT is an existing folder").toBeTruthy();
  expect(foreign && statSync(foreign).size === FLASH, "STICK_FOREIGN_IMAGE is an 8 MB image").toBeTruthy();
  expect(readFileSync(foreign).subarray(0, 4096 * 16).includes(Buffer.from("guardian-")), "the foreign image is not a Guardian").toBe(false);
  const record: Record<string, unknown> = { started: new Date().toISOString(), foreign_sha256: sha(readFileSync(foreign)) };
  const save = () => writeFileSync(join(out, "stick-smoke.json"), JSON.stringify(record, null, 2) + "\n");

  await reuseGrantedPort(page);
  await page.goto("/install");
  await expect(page.getByTestId("flasher-release")).toContainText(/build \d+/);
  record.release = await page.getByTestId("flasher-release").innerText();

  // A: backup (the owner picks the stick in this first picker).
  await choose(page, "First install");
  const download = page.waitForEvent("download", { timeout: STEP_TIMEOUT });
  await page.getByTestId("flasher-backup-button").click();
  const backupPath = join(out, "backup-A.bin");
  await (await download).saveAs(backupPath);
  await waitDone(page, "backup");
  const backup = readFileSync(backupPath);
  expect(backup.length).toBe(FLASH);
  await expect(page.getByTestId("flasher-backup-done")).toContainText(sha(backup));
  record.A = { sha256: sha(backup), status: await readStatus(page) };
  save();

  // B: another firmware on the stick.
  await restore(page, foreign);
  const b = await readStatus(page, 20_000);
  record.B = { status: b };
  expect(token(b, "app_version") ?? "", "no Guardian answers on the foreign image").not.toMatch(/^guardian-/);
  save();

  // C: First install over it.
  await choose(page, "First install");
  await page.getByRole("checkbox", { name: /the whole stick is erased/ }).check();
  await page.getByTestId("flasher-button").click();
  await page.getByTestId("flasher-confirm-yes").click();
  await waitDone(page, "install");
  const c = await readStatus(page);
  record.C = { status: c };
  save();
  expect(token(c, "app_version")).toMatch(/^guardian-.*-rel$/);
  expect(token(c, "wifi_provisioned")).toBe("no");

  // D: back to the owner's backup.
  await restore(page, backupPath);
  const s1 = await readStatus(page);
  record.D = { status: s1 };
  save();
  expect(token(s1, "app_version")).toMatch(/^guardian-/);

  // E: Update keeps the settings.
  await choose(page, "Update");
  await page.getByTestId("flasher-button").click();
  await waitDone(page, "update");
  const s2 = await readStatus(page);
  record.E = { status: s2 };
  save();
  expect(token(s2, "app_version")).toMatch(/-rel$/);
  expect(token(s2, "settings")).toBe(token(s1, "settings"));
  expect(token(s2, "wifi_provisioned")).toBe(token(s1, "wifi_provisioned"));

  // F: leave the stick as found.
  await restore(page, backupPath);
  const s3 = await readStatus(page);
  record.F = { status: s3, finished: new Date().toISOString() };
  save();
  expect(token(s3, "app_version")).toBe(token(s1, "app_version"));
  expect(token(s3, "settings")).toBe(token(s1, "settings"));
});
