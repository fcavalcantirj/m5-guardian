import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  ANALYTICS_EVENT,
  DOWNLOAD_MODE_STEPS,
  ESPRESSIF_USB_VENDOR,
  FLASH_SIZE,
  PROTECTED_RANGES,
  READ_BAUD,
  RELEASE_PARTS,
  WRITE_BAUD,
  backupFileName,
  browserSupport,
  checkBackupImage,
  checkPlan,
  eraseSpan,
  friendlyError,
  isChipOk,
  isMobileAgent,
  protectedHit,
  restartIntoFirmware,
  sha256Hex,
  stepEvent,
  weightedPercent,
  writeOptions,
  type PlannedWrite,
} from "./flash-plan.ts";

// W07: the rules the browser flasher applies before it writes a byte. The sizes below are the release of the
// spike (firmware/evidence/sticks3-W07-flash-spike-20261123.log) rounded: what matters is the offsets.
const release: PlannedWrite[] = [
  { file: "bootloader.bin", offset: 0x0, size: 21_000 },
  { file: "partition-table.bin", offset: 0x8000, size: 3072 },
  { file: "ota_data_initial.bin", offset: 0x10000, size: 8192 },
  { file: "guardian_sticks3-signed.bin", offset: 0x20000, size: 1_958_849 },
];

test("the release plan is the four parts at 0x0, 0x8000, 0x10000 and 0x20000", () => {
  assert.deepEqual(
    RELEASE_PARTS.map((p) => [p.file, p.offset]),
    [
      ["bootloader.bin", 0x0],
      ["partition-table.bin", 0x8000],
      ["ota_data_initial.bin", 0x10000],
      ["guardian_sticks3-signed.bin", 0x20000],
    ],
  );
  assert.equal(checkPlan("update", release), null);
  assert.equal(checkPlan("install", release), null);
});

test("the protected ranges are nvs 0x9000-0xEFFF, phy_init 0xF000 and nvs_cred 0x12000-0x15FFF", () => {
  assert.deepEqual(
    PROTECTED_RANGES.map((r) => [r.start, r.end]),
    [
      [0x9000, 0xf000],
      [0xf000, 0x10000],
      [0x12000, 0x16000],
    ],
  );
});

test("the protected ranges match the firmware partition table when the repository is present", (t) => {
  const csv = new URL("../../firmware/boards/sticks3/partitions.csv", import.meta.url);
  if (!existsSync(csv)) return t.skip("partitions.csv is not part of the website upload");
  const rows = Object.fromEntries(
    readFileSync(csv, "utf8")
      .split("\n")
      .filter((line) => line.trim() && !line.startsWith("#"))
      .map((line) => line.split(",").map((s) => s.trim()))
      .map(([name, , , offset, size]) => [name, [Number(offset), Number(offset) + Number(size)]]),
  );
  assert.deepEqual(rows.nvs, [0x9000, 0xf000]);
  assert.deepEqual(rows.phy_init, [0xf000, 0x10000]);
  assert.deepEqual(rows.nvs_cred, [0x12000, 0x16000]);
  assert.deepEqual(rows.otadata, [0x10000, 0x12000]);
  assert.equal(rows.ota_0[0], 0x20000);
  assert.equal(rows.ota_0[1] - rows.ota_0[0], RELEASE_PARTS[3].max);
});

test("a write is refused when its erased sectors touch a protected range", () => {
  assert.equal(protectedHit(0x8000, 0x1000), null, "the partition table ends where nvs starts");
  assert.match(protectedHit(0x8000, 0x1001) ?? "", /nvs \(settings/, "one byte more erases the first nvs sector");
  assert.match(protectedHit(0xe000, 16) ?? "", /nvs/);
  assert.match(protectedHit(0xf000, 1) ?? "", /phy_init/);
  assert.equal(protectedHit(0x10000, 0x2000), null, "otadata ends where nvs_cred starts");
  assert.match(protectedHit(0x10000, 0x2001) ?? "", /nvs_cred/);
  assert.match(protectedHit(0x15fff, 1) ?? "", /nvs_cred/);
  assert.equal(protectedHit(0x16000, 0x1000), null);
  // A write that starts inside a sector erases it from the sector start.
  assert.deepEqual(eraseSpan(0x11800, 0x100), { start: 0x11000, end: 0x12000 });
  assert.equal(protectedHit(0x11800, 0x100), null, "otadata's last sector is not protected");
  assert.match(protectedHit(0x11ff0, 0x20) ?? "", /nvs_cred/, "crossing into 0x12000 is refused");
});

test("an Update or a First install refuses any plan that is not exactly the release", () => {
  const swap = (i: number, change: Partial<PlannedWrite>) => release.map((w, j) => (j === i ? { ...w, ...change } : w));
  assert.match(checkPlan("update", release.slice(0, 3)) ?? "", /exactly 4 parts/);
  assert.match(checkPlan("update", [...release, { file: "x.bin", offset: 0x320000, size: 4 }]) ?? "", /exactly 4/);
  assert.match(checkPlan("update", swap(2, { offset: 0x9000 })) ?? "", /must be ota_data_initial\.bin at 0x10000/);
  assert.match(checkPlan("update", swap(3, { file: "evil.bin" })) ?? "", /must be guardian_sticks3-signed\.bin/);
  assert.match(checkPlan("update", swap(1, { size: 0x1001 })) ?? "", /larger than its slot/);
  assert.match(checkPlan("update", swap(2, { size: 0x2001 })) ?? "", /larger than its slot/);
  assert.match(checkPlan("update", swap(3, { size: 0x300001 })) ?? "", /larger than its slot/);
  assert.match(checkPlan("install", swap(0, { size: 0 })) ?? "", /invalid offset or size/);
  assert.match(checkPlan("install", swap(0, { size: -5 })) ?? "", /invalid/);
  assert.match(checkPlan("update", [...release].reverse()) ?? "", /Part 1 must be bootloader\.bin/);
  assert.match(checkPlan("restore", release) ?? "", /exactly one 8 MB backup/);
});

test("a Restore accepts exactly one 8 MB image at 0x0", () => {
  assert.equal(checkPlan("restore", [{ file: "backup.bin", offset: 0, size: FLASH_SIZE }]), null);
  assert.match(checkPlan("restore", [{ file: "b.bin", offset: 0, size: FLASH_SIZE - 1 }]) ?? "", /exactly one 8 MB/);
  assert.match(checkPlan("restore", [{ file: "b.bin", offset: 0x1000, size: FLASH_SIZE }]) ?? "", /past the end/);
  assert.match(checkPlan("restore", [{ file: "b.bin", offset: 0, size: FLASH_SIZE + 1 }]) ?? "", /past the end/);
});

test("write options: the release with dio/80m/8MB, the erase only for First install, Restore keeps every byte", () => {
  assert.deepEqual(writeOptions("update"), { flashMode: "dio", flashFreq: "80m", flashSize: "8MB", eraseAll: false, compress: true });
  assert.deepEqual(writeOptions("install"), { flashMode: "dio", flashFreq: "80m", flashSize: "8MB", eraseAll: true, compress: true });
  assert.deepEqual(writeOptions("restore"), { flashMode: "keep", flashFreq: "keep", flashSize: "keep", eraseAll: false, compress: true });
  assert.equal(WRITE_BAUD, 460800);
  assert.equal(READ_BAUD, 921600);
  assert.equal(ESPRESSIF_USB_VENDOR, 0x303a);
});

test("a backup to restore is exactly 8 MB and starts with a bootloader", () => {
  const good = new Uint8Array(FLASH_SIZE);
  good[0] = 0xe9;
  assert.equal(checkBackupImage(good), null);
  assert.match(checkBackupImage(good.subarray(1)) ?? "", /8,388,607 bytes/);
  assert.match(checkBackupImage(new Uint8Array(FLASH_SIZE)) ?? "", /bootloader/);
});

test("backup file names carry the MAC and the time, nothing else", () => {
  assert.equal(backupFileName("02:00:5E:10:00:01", new Date(2026, 10, 23, 9, 5, 7)), "sticks3-backup-02005e100001-20261123-090507.bin");
  assert.equal(backupFileName("", new Date(2026, 0, 1, 0, 0, 0)), "sticks3-backup-unknown-20260101-000000.bin");
});

test("sha256Hex is the SHA-256 of the bytes", async () => {
  const bytes = new TextEncoder().encode("guardian");
  assert.equal(await sha256Hex(bytes), createHash("sha256").update(bytes).digest("hex"));
});

test("progress is weighted by bytes, not by part count", () => {
  const sizes = [100, 900];
  assert.equal(weightedPercent(sizes, 0, 0, 100), 0);
  assert.equal(weightedPercent(sizes, 0, 100, 100), 10);
  assert.equal(weightedPercent(sizes, 1, 450, 900), 55);
  assert.equal(weightedPercent(sizes, 1, 900, 900), 100);
  assert.equal(weightedPercent(sizes, 1, 2000, 900), 100, "clamped");
  assert.equal(weightedPercent([], 0, 1, 1), 0);
});

test("only an ESP32-S3 is accepted", () => {
  assert.ok(isChipOk("ESP32-S3 (QFN56) (revision v0.2)"));
  assert.ok(!isChipOk("ESP32-C3 (QFN32) (revision v0.4)"));
  assert.ok(!isChipOk("ESP32-D0WD-V3 (revision v3.1)"));
});

type Call = [string, unknown];
function fakePort(failOn?: string) {
  const calls: Call[] = [];
  return {
    calls,
    async open(o: { baudRate: number }) {
      calls.push(["open", o]);
      if (failOn === "open") throw new Error("Failed to open serial port.");
    },
    async setSignals(s: { dataTerminalReady?: boolean; requestToSend?: boolean }) {
      calls.push(["signals", s]);
      if (failOn === "signals") throw new Error("NetworkError: The device has been lost.");
    },
    async close() {
      calls.push(["close", null]);
    },
  };
}

test("the restart is a fresh connection: RTS high 200 ms with DTR low, released with DTR still low, then closed", async () => {
  const port = fakePort();
  const sleeps: number[] = [];
  await restartIntoFirmware(port, async (ms) => {
    sleeps.push(ms);
    port.calls.push(["sleep", ms]);
  });
  assert.deepEqual(port.calls, [
    ["open", { baudRate: 115200 }],
    ["signals", { dataTerminalReady: false, requestToSend: true }],
    ["sleep", 200],
    ["signals", { dataTerminalReady: false, requestToSend: false }],
    ["sleep", 300],
    ["close", null],
  ]);
  assert.ok(port.calls.every(([kind, s]) => kind !== "signals" || (s as { dataTerminalReady: boolean }).dataTerminalReady === false), "DTR is never raised (IO0 stays high: run the app)");
});

test("the restart closes the port even when a signal fails", async () => {
  const port = fakePort("signals");
  await assert.rejects(restartIntoFirmware(port, async () => {}), /device has been lost/);
  assert.deepEqual(port.calls.at(-1), ["close", null]);
});

test("errors map to plain English steps; a closed picker is not an error", () => {
  const named = (name: string, message: string) => Object.assign(new Error(message), { name });
  assert.equal(friendlyError(named("NotFoundError", "No port selected by the user.")), null);
  assert.equal(friendlyError(new Error("No port selected by the user.")), null);
  assert.equal(friendlyError(new Error("Failed to execute 'open' on 'SerialPort': Failed to open serial port."))?.kind, "port-busy");
  assert.equal(friendlyError(named("InvalidStateError", "The port is already open."))?.kind, "port-busy");
  assert.equal(friendlyError(new Error("MD5 of file does not match data in flash!"))?.kind, "md5");
  for (const m of ["Failed to connect with the device", "Timeout", "Read timeout exceeded", "Invalid head of packet (0x50): Possible serial noise or corruption.", "Failed to start stub. Unexpected response"]) {
    const e = friendlyError(new Error(m));
    assert.equal(e?.kind, "no-download-mode", m);
    assert.ok(e?.text.includes(DOWNLOAD_MODE_STEPS));
    assert.match(e?.text ?? "", /data cable/);
  }
  assert.equal(friendlyError(named("NetworkError", "The device has been lost."))?.kind, "lost");
  assert.equal(friendlyError(named("WrongChipError", "This board is an ESP32-C3, not a StickS3 (ESP32-S3)."))?.kind, "wrong-chip");
  assert.match(friendlyError(named("ReleaseCheckError", "bootloader.bin does not match the signed release."))?.text ?? "", /Nothing was written/);
  const other = friendlyError("boom");
  assert.equal(other?.kind, "other");
  assert.match(other?.text ?? "", /boom/);
  assert.match(DOWNLOAD_MODE_STEPS, /small button on the side/);
  assert.match(DOWNLOAD_MODE_STEPS, /green light/);
});

test("browser support: https first, then desktop, then Web Serial", () => {
  assert.equal(browserSupport({ secure: false, serial: true, mobile: false }), "insecure");
  assert.equal(browserSupport({ secure: true, serial: true, mobile: true }), "mobile");
  assert.equal(browserSupport({ secure: true, serial: false, mobile: false }), "no-serial");
  assert.equal(browserSupport({ secure: true, serial: true, mobile: false }), "ok");
  assert.ok(isMobileAgent("Mozilla/5.0 (Linux; Android 14) Chrome/140 Mobile Safari/537.36"));
  assert.ok(isMobileAgent("Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)"));
  assert.ok(isMobileAgent("x", true));
  assert.ok(!isMobileAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/142 Safari/537.36"));
});

test("an analytics event carries only the action, the step result and both joined, never device data", () => {
  assert.equal(ANALYTICS_EVENT, "guardian_install");
  const event = stepEvent("update", "error_writing");
  assert.deepEqual(Object.keys(event).sort(), ["action", "result", "step"]);
  assert.deepEqual(event, { action: "update", result: "error_writing", step: "update:error_writing" });
});
