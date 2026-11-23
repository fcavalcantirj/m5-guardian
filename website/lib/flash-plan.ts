/**
 * The install page's flashing rules (W07), kept free of React, esptool-js and Node so they are unit tested
 * (lib/flash-plan.test.ts) and shared by the browser flasher (components/install/flasher.tsx).
 *
 * Ported from the flasher core of the owner's Doutor VPD website (lib/flasher-core.ts, MIT, see
 * THIRD_PARTY_NOTICES.md) and changed for the Guardian's partition table
 * (firmware/boards/sticks3/partitions.csv):
 *
 *   0x0      bootloader.bin                 written
 *   0x8000   partition-table.bin            written
 *   0x9000   nvs        0x6000              PROTECTED: settings, the picked network, TUNE values
 *   0xF000   phy_init   0x1000              PROTECTED: the radio's calibration
 *   0x10000  ota_data_initial.bin (otadata) written: boots ota_0
 *   0x12000  nvs_cred   0x4000              PROTECTED: the stored Wi-Fi credential
 *   0x20000  guardian_sticks3-signed.bin    written into ota_0 (0x300000)
 *
 * An Update writes only the four parts of a signed release and never erases a byte of a protected range
 * (the measured spike, firmware/evidence/sticks3-W07-flash-spike-20261123.log, step S2: every setting kept).
 * A First install erases the whole chip first. A Restore writes one whole 8 MB backup back from 0x0.
 */
export const ESPRESSIF_USB_VENDOR = 0x303a;
export const FLASH_SIZE = 0x800000; // 8 MB, the StickS3's ESP32-S3-PICO-1
export const SECTOR = 0x1000; // the flash erases whole 4 KiB sectors
/** The spike's measured speeds: writes at 460800 baud (24.9 s update), the 8 MB read at 921600 (60.8 s). */
export const WRITE_BAUD = 460800;
export const READ_BAUD = 921600;
export const ROM_BAUD = 115200;

export type Range = { name: string; start: number; end: number };

/** Ranges an Update or a release write must never touch (end exclusive). */
export const PROTECTED_RANGES: readonly Range[] = [
  { name: "nvs (settings and the picked network)", start: 0x9000, end: 0xf000 },
  { name: "phy_init (radio calibration)", start: 0xf000, end: 0x10000 },
  { name: "nvs_cred (the stored Wi-Fi credential)", start: 0x12000, end: 0x16000 },
];

/** The four parts of a release, in flash order, each with the largest size its slot holds. */
export const RELEASE_PARTS = [
  { file: "bootloader.bin", offset: 0x0, max: 0x8000 },
  { file: "partition-table.bin", offset: 0x8000, max: 0x1000 },
  { file: "ota_data_initial.bin", offset: 0x10000, max: 0x2000 },
  { file: "guardian_sticks3-signed.bin", offset: 0x20000, max: 0x300000 },
] as const;

export type Mode = "update" | "install" | "restore";
export type PlannedWrite = { file: string; offset: number; size: number };

const hex = (n: number) => `0x${n.toString(16)}`;

/** The bytes a write of `size` at `offset` erases: whole sectors, from the sector of the first byte. */
export function eraseSpan(offset: number, size: number): { start: number; end: number } {
  const start = Math.floor(offset / SECTOR) * SECTOR;
  const end = Math.ceil((offset + size) / SECTOR) * SECTOR;
  return { start, end };
}

/** Why a write of `size` bytes at `offset` would touch a protected range, or null. */
export function protectedHit(offset: number, size: number): string | null {
  const { start, end } = eraseSpan(offset, size);
  for (const range of PROTECTED_RANGES)
    if (start < range.end && end > range.start)
      return `A write at ${hex(offset)} of ${size} bytes would touch ${range.name} (${hex(range.start)}-${hex(range.end - 1)}).`;
  return null;
}

/**
 * Why this list of writes must not be flashed in this mode, or null. Update and First install accept exactly the
 * four release parts at their offsets, each within its slot and clear of every protected range; Restore accepts
 * exactly one 8 MB image at 0x0.
 */
export function checkPlan(mode: Mode, writes: readonly PlannedWrite[]): string | null {
  for (const w of writes) {
    if (!Number.isSafeInteger(w.offset) || !Number.isSafeInteger(w.size) || w.offset < 0 || w.size <= 0)
      return `${w.file}: invalid offset or size.`;
    if (w.offset + w.size > FLASH_SIZE) return `${w.file} would run past the end of the 8 MB flash.`;
  }
  if (mode === "restore") {
    if (writes.length !== 1 || writes[0].offset !== 0 || writes[0].size !== FLASH_SIZE)
      return "A restore writes exactly one 8 MB backup at 0x0.";
    return null;
  }
  if (writes.length !== RELEASE_PARTS.length) return `A release writes exactly ${RELEASE_PARTS.length} parts.`;
  for (const [i, part] of RELEASE_PARTS.entries()) {
    const w = writes[i];
    if (w.file !== part.file || w.offset !== part.offset)
      return `Part ${i + 1} must be ${part.file} at ${hex(part.offset)}, not ${w.file} at ${hex(w.offset)}.`;
    if (w.size > part.max) return `${w.file} (${w.size} bytes) is larger than its slot (${part.max} bytes).`;
    const hit = protectedHit(w.offset, w.size);
    if (hit) return hit;
  }
  for (let i = 1; i < writes.length; i++)
    if (eraseSpan(writes[i - 1].offset, writes[i - 1].size).end > writes[i].offset)
      return `${writes[i - 1].file} would overlap ${writes[i].file}.`;
  return null;
}

/** The esptool-js writeFlash options per mode. Restore keeps the header bytes so the image goes back byte-exact. */
export function writeOptions(mode: Mode) {
  if (mode === "restore")
    return { flashMode: "keep", flashFreq: "keep", flashSize: "keep", eraseAll: false, compress: true } as const;
  return { flashMode: "dio", flashFreq: "80m", flashSize: "8MB", eraseAll: mode === "install", compress: true } as const;
}

/** Why a file the person picked cannot be restored, or null: a whole-chip backup is exactly 8 MB and starts with a bootloader. */
export function checkBackupImage(bytes: Uint8Array): string | null {
  if (bytes.length !== FLASH_SIZE)
    return `This file is ${bytes.length.toLocaleString("en-US")} bytes; a whole StickS3 backup is exactly 8,388,608 bytes.`;
  if (bytes[0] !== 0xe9) return "This file does not start with an ESP32 bootloader, so it is not a backup of a StickS3.";
  return null;
}

/** The name the browser saves a backup under: the chip's MAC and the local time, no other data. */
export function backupFileName(mac: string, at: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${at.getFullYear()}${pad(at.getMonth() + 1)}${pad(at.getDate())}-${pad(at.getHours())}${pad(at.getMinutes())}${pad(at.getSeconds())}`;
  const id = mac.toLowerCase().replace(/[^0-9a-f]/g, "");
  return `sticks3-backup-${id || "unknown"}-${stamp}.bin`;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Progress over several parts weighted by their sizes, 0..100. */
export function weightedPercent(sizes: readonly number[], index: number, written: number, total: number): number {
  const all = sizes.reduce((n, s) => n + s, 0);
  if (all <= 0) return 0;
  const before = sizes.slice(0, index).reduce((n, s) => n + s, 0);
  const share = total > 0 ? Math.min(1, written / total) * (sizes[index] ?? 0) : 0;
  return Math.max(0, Math.min(100, Math.round(((before + share) / all) * 100)));
}

export const isChipOk = (description: string) => /ESP32-S3/i.test(description);

export type SignalPort = {
  open(options: { baudRate: number }): Promise<void>;
  setSignals(signals: { dataTerminalReady?: boolean; requestToSend?: boolean }): Promise<void>;
  close(): Promise<void>;
};

/**
 * Restart the stick into its firmware after a write or a read. Measured on the StickS3 (Doutor VPD spike
 * 2026-10-21, and the Guardian spike 2026-11-23 step S1): esptool-js 0.7.0's own hard reset, or a pulse inside its
 * session, left the chip in download mode; a FRESH connection with RTS high 200 ms and DTR low, released with DTR
 * still low (IO0 high: run the app), started it.
 */
export async function restartIntoFirmware(port: SignalPort, sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))) {
  await port.open({ baudRate: ROM_BAUD });
  try {
    await port.setSignals({ dataTerminalReady: false, requestToSend: true });
    await sleep(200);
    await port.setSignals({ dataTerminalReady: false, requestToSend: false });
    await sleep(300);
  } finally {
    await port.close();
  }
}

/**
 * A StickS3 on another firmware may not answer the browser until it is in download mode. The power chip's long
 * press does it (M5Stack StickS3 manual): the green light inside flashes.
 */
export const DOWNLOAD_MODE_STEPS =
  "With the cable plugged in, hold the small button on the side (not the big front one) until the green light inside the stick flashes: that is download mode. Then click the button on this page again.";

export type ErrorKind = "port-busy" | "md5" | "no-download-mode" | "wrong-chip" | "release" | "lost" | "other";

/** What the person should do, in plain English; null when they simply closed the port picker. */
export function friendlyError(error: unknown): { kind: ErrorKind; text: string } | null {
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : String(error);
  if (name === "NotFoundError" || /no port selected/i.test(message)) return null;
  if (name === "WrongChipError")
    return { kind: "wrong-chip", text: `${message} Nothing was written.` };
  if (name === "ReleaseCheckError")
    return { kind: "release", text: `${message} Nothing was written. Reload the page and try again.` };
  if (/failed to open serial port|open serial port|in use|busy|access denied|InvalidStateError/i.test(`${name} ${message}`))
    return {
      kind: "port-busy",
      text: "The stick's port could not be opened: close any other program that uses it (a serial monitor, Arduino IDE, another browser tab) and try again.",
    };
  if (/md5/i.test(message))
    return {
      kind: "md5",
      text: "The written data did not read back the same (MD5 mismatch). Try again with the same choice; a stick that does not start comes back with another write over USB.",
    };
  if (/timeout|timed out|no serial data|failed to connect|invalid head of packet|failed to start stub|wrong boot mode/i.test(message))
    return {
      kind: "no-download-mode",
      text: `The stick did not enter download mode. ${DOWNLOAD_MODE_STEPS} If it still fails, try another USB-C cable (a data cable, not a charge-only one).`,
    };
  if (name === "NetworkError" || /device has been lost|disconnected|the device was lost/i.test(message))
    return {
      kind: "lost",
      text: "The stick disconnected during the operation. Plug it back in and run the same step again; until a write finishes, the stick may not start.",
    };
  return { kind: "other", text: `Something went wrong: ${message}. Try again. ${DOWNLOAD_MODE_STEPS}` };
}

/** Where this browser stands: Web Serial needs a secure page and desktop Chrome or Edge. */
export type Support = "ok" | "insecure" | "mobile" | "no-serial";

export function browserSupport(env: { secure: boolean; serial: boolean; mobile: boolean }): Support {
  if (!env.secure) return "insecure";
  if (env.mobile) return "mobile";
  return env.serial ? "ok" : "no-serial";
}

export const isMobileAgent = (userAgent: string, uaDataMobile?: boolean) =>
  uaDataMobile === true || /Android|iPhone|iPad|iPod|Mobile/i.test(userAgent);

/**
 * The analytics event of every step (Vercel Web Analytics, cookieless): only which action and how far it got. No
 * chip name, MAC, file name, hash, size or error text leaves the page.
 */
export type Step = "connecting" | "downloading" | "reading" | "writing" | "restarting";
export type StepResult =
  | "start"
  | "connected"
  | "done"
  | "cancel"
  | "error_plan"
  | `error_${Step}`;
export const ANALYTICS_EVENT = "guardian_install";

export function stepEvent(mode: Mode | "backup", result: StepResult): { action: Mode | "backup"; result: StepResult } {
  return { action: mode, result };
}
