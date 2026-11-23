"use client";

import { useEffect, useRef, useState } from "react";
import { track } from "@vercel/analytics";
import { Button } from "@/components/ui/button";
import {
  ANALYTICS_EVENT,
  DOWNLOAD_MODE_STEPS,
  ESPRESSIF_USB_VENDOR,
  READ_BAUD,
  WRITE_BAUD,
  FLASH_SIZE,
  backupFileName,
  browserSupport,
  checkBackupImage,
  checkPlan,
  friendlyError,
  isChipOk,
  isMobileAgent,
  restartIntoFirmware,
  sha256Hex,
  stepEvent,
  weightedPercent,
  writeOptions,
  type Mode,
  type Step,
  type StepResult,
  type Support,
} from "@/lib/flash-plan";

/** What /api/firmware/latest answers (lib/firmware-routes.ts). */
export type LatestRelease = {
  tag: string;
  version: string;
  build: number;
  date: string;
  notes: string;
  parts: { file: string; offset: number; sha256: string; size: number; url: string }[];
};

type Phase = "idle" | Step | "done" | "error";
type Action = Mode | "backup";
type Backup = { name: string; sha256: string; size: number };
type RestoreFile = { name: string; bytes: Uint8Array; sha256: string; problem: string | null };

const LOAD_TIMEOUT_MS = 15_000;

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what}: timeout`)), ms);
    promise.then(
      (v) => (clearTimeout(timer), resolve(v)),
      (e) => (clearTimeout(timer), reject(e)),
    );
  });
}

const named = (name: string, message: string) => Object.assign(new Error(message), { name });
const short = (sha: string) => `${sha.slice(0, 16)}…`;

/**
 * Flashes the Guardian onto the visitor's own StickS3 over Web Serial with Espressif's esptool-js 0.7.0 (loaded only
 * after a click). Update writes the four parts of the signed release and keeps every setting; First install erases
 * the chip after a backup offer and a double confirm; Restore writes a whole 8 MB backup back. Every part is checked
 * against the signed sha256 before writing and read back (MD5) after; then the restart measured on the stick.
 */
export function Flasher() {
  const [latest, setLatest] = useState<LatestRelease | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [support, setSupport] = useState<Support | "checking">("checking");
  const [mode, setMode] = useState<Mode>("update");
  const [eraseOk, setEraseOk] = useState(false);
  const [restoreOk, setRestoreOk] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState({ label: "", pct: 0 });
  const [message, setMessage] = useState("");
  const [device, setDevice] = useState("");
  const [pickerHint, setPickerHint] = useState(false);
  const [backup, setBackup] = useState<Backup | null>(null);
  const [restoreFile, setRestoreFile] = useState<RestoreFile | null>(null);
  const [doneMode, setDoneMode] = useState<Action | null>(null);
  const [verified, setVerified] = useState("");
  const log = useRef<string[]>([]);
  const [logText, setLogText] = useState("");
  const statusRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const uaData = (navigator as Navigator & { userAgentData?: { mobile?: boolean } }).userAgentData;
    setSupport(
      browserSupport({
        secure: window.isSecureContext,
        serial: "serial" in navigator,
        mobile: isMobileAgent(navigator.userAgent, uaData?.mobile),
      }),
    );
    fetch("/api/firmware/latest", { signal: AbortSignal.timeout(LOAD_TIMEOUT_MS) })
      .then(async (r) => {
        const body = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(typeof body.error === "string" ? body.error : `HTTP ${r.status}`);
        return body as LatestRelease;
      })
      .then(setLatest)
      .catch((e: unknown) =>
        setLoadError(e instanceof Error && !/abort|timeout/i.test(e.name + e.message) ? e.message : "The published release could not be read just now. Reload the page in a moment."),
      );
  }, []);

  const note = (line: string) => {
    log.current.push(line);
    setLogText(log.current.slice(-200).join("\n"));
  };
  const count = (what: Action, result: StepResult) => track(ANALYTICS_EVENT, stepEvent(what, result));

  /** Ask for the port, load esptool-js, identify the chip. Everything after the click. */
  async function connect(baud: number) {
    const port = await navigator.serial.requestPort({ filters: [{ usbVendorId: ESPRESSIF_USB_VENDOR }] });
    const { ESPLoader, Transport } = await withTimeout(import("esptool-js"), LOAD_TIMEOUT_MS, "loading esptool-js");
    const transport = new Transport(port, false);
    const terminal = { clean() {}, writeLine: (s: string) => note(s), write: (s: string) => note(s) };
    const loader = new ESPLoader({ transport, baudrate: baud, terminal, debugLogging: false });
    return { port, transport, loader };
  }

  async function run(what: Action) {
    const session: { port: SerialPort | null; transport: { disconnect(): Promise<void> } | null } = { port: null, transport: null };
    let step: Step = "connecting";
    const enter = (next: Step) => {
      step = next;
      setPhase(next);
    };
    setPickerHint(false);
    setMessage("");
    setDevice("");
    setVerified("");
    setConfirming(false);
    log.current = [];
    setLogText("");
    count(what, "start");
    try {
      // Plans are checked before the port is even asked for.
      if (what === "update" || what === "install") {
        if (!latest) throw named("ReleaseCheckError", "No signed release is loaded.");
        const problem = checkPlan(what, latest.parts);
        if (problem) {
          count(what, "error_plan");
          return fail(`${problem} Nothing was written.`);
        }
      }
      if (what === "restore") {
        if (!restoreFile || restoreFile.problem) return fail(restoreFile?.problem ?? "Choose a backup file first.");
        const problem = checkPlan("restore", [{ file: restoreFile.name, offset: 0, size: restoreFile.bytes.length }]);
        if (problem) {
          count(what, "error_plan");
          return fail(problem);
        }
      }

      enter("connecting");
      setProgress({ label: "", pct: 0 });
      const { port, transport, loader } = await connect(what === "backup" ? READ_BAUD : WRITE_BAUD);
      session.port = port;
      session.transport = transport;
      const chip = await loader.main();
      if (!isChipOk(chip)) throw named("WrongChipError", `This board is ${chip}, not a StickS3 (ESP32-S3).`);
      const mac = String(await loader.chip.readMac(loader)).toUpperCase();
      setDevice(`${chip} · ${mac}`);
      count(what, "connected");

      if (what === "backup") {
        enter("reading");
        const bytes = await loader.readFlash(0, FLASH_SIZE, (_packet, done, total) =>
          setProgress({ label: "Reading the whole flash", pct: weightedPercent([total], 0, done, total) }),
        );
        if (bytes.length !== FLASH_SIZE) throw new Error(`the read returned ${bytes.length} bytes, not ${FLASH_SIZE}`);
        const sha = await sha256Hex(bytes);
        const name = backupFileName(mac, new Date());
        save(bytes, name);
        setBackup({ name, sha256: sha, size: bytes.length });
      } else {
        const files: { data: Uint8Array; address: number; label: string }[] = [];
        if (what === "restore" && restoreFile) {
          files.push({ data: restoreFile.bytes, address: 0, label: restoreFile.name });
        } else if (latest) {
          enter("downloading");
          for (const [i, part] of latest.parts.entries()) {
            setProgress({ label: `Downloading ${part.file}`, pct: Math.round((i / latest.parts.length) * 100) });
            const res = await fetch(part.url);
            if (!res.ok) {
              const body = await res.json().catch(() => ({}));
              throw named("ReleaseCheckError", typeof body.error === "string" ? body.error : `${part.file}: HTTP ${res.status}.`);
            }
            const data = new Uint8Array(await res.arrayBuffer());
            // The browser re-checks every part against the signed manifest before a byte is written.
            if (data.length !== part.size || (await sha256Hex(data)) !== part.sha256)
              throw named("ReleaseCheckError", `${part.file} does not match the signed release.`);
            files.push({ data, address: part.offset, label: part.file });
          }
          const problem = checkPlan(what, files.map((f) => ({ file: f.label, offset: f.address, size: f.data.length })));
          if (problem) throw named("ReleaseCheckError", problem);
        }

        enter("writing");
        const { default: SparkMD5 } = await import("spark-md5");
        const sizes = files.map((f) => f.data.length);
        if (what === "install") setProgress({ label: "Erasing the whole chip", pct: 0 });
        await loader.writeFlash({
          fileArray: files.map(({ data, address }) => ({ data, address })),
          ...writeOptions(what),
          reportProgress: (index: number, written: number, total: number) =>
            setProgress({ label: `Writing ${files[index].label}`, pct: weightedPercent(sizes, index, written, total) }),
          calculateMD5Hash: (image: Uint8Array) =>
            SparkMD5.ArrayBuffer.hash(image.buffer.slice(image.byteOffset, image.byteOffset + image.byteLength) as ArrayBuffer),
        });
        setVerified(
          what === "restore"
            ? `The stick's 8 MB read back the same as ${restoreFile?.name} (MD5), sha256 ${short(restoreFile?.sha256 ?? "")}.`
            : `All four parts read back the same as the signed release (MD5).`,
        );
      }

      enter("restarting");
      await transport.disconnect();
      session.transport = null;
      await restartIntoFirmware(port);
      session.port = null;
      setDoneMode(what);
      setPhase("done");
      count(what, "done");
    } catch (error) {
      if (session.transport) await session.transport.disconnect().catch(() => {});
      else await session.port?.close().catch(() => {});
      const mapped = friendlyError(error);
      if (mapped === null) {
        // The picker was closed: often because the stick was not in the list (another firmware, charge-only cable).
        count(what, "cancel");
        setPickerHint(true);
        setPhase("idle");
        return;
      }
      count(what, `error_${step}`);
      fail(mapped.text);
    } finally {
      statusRef.current?.focus();
    }
  }

  function fail(text: string) {
    setMessage(text);
    setPhase("error");
  }

  function save(bytes: Uint8Array, name: string) {
    const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  async function pickRestore(file: File | undefined) {
    setRestoreOk(false);
    setConfirming(false);
    if (!file) return setRestoreFile(null);
    const bytes = new Uint8Array(await file.arrayBuffer());
    setRestoreFile({ name: file.name, bytes, sha256: await sha256Hex(bytes), problem: checkBackupImage(bytes) });
  }

  const busy = phase === "connecting" || phase === "downloading" || phase === "reading" || phase === "writing" || phase === "restarting";
  const canUse = support === "ok" && !busy;
  const needsRelease = mode === "update" || mode === "install";
  const ready =
    canUse &&
    (!needsRelease || latest !== null) &&
    (mode !== "install" || eraseOk) &&
    (mode !== "restore" || (restoreFile !== null && restoreFile.problem === null && restoreOk));
  const twoStep = mode === "install" || mode === "restore";
  const mainLabel =
    mode === "update"
      ? `Connect and update${latest ? ` to ${latest.version}` : ""}`
      : mode === "install"
        ? `Connect, erase and install${latest ? ` ${latest.version}` : ""}`
        : "Connect and restore this backup";

  return (
    <div className="install-flasher" data-testid="flasher">
      {support !== "ok" && support !== "checking" && (
        <p className="install-note install-warn" role="status" data-testid="flasher-unsupported" data-support={support}>
          {support === "insecure" && "Flashing works only on an https page. Open this page at its https address."}
          {support === "mobile" &&
            "Flashing needs a desktop computer: Chrome or Edge on Windows, macOS or Linux, with the StickS3 on a USB-C data cable. Phones and tablets cannot do it."}
          {support === "no-serial" && (
            <>
              This browser cannot talk to a USB device. Use <strong>Chrome</strong> or <strong>Edge</strong> on a desktop computer (Windows, macOS
              or Linux). Safari and Firefox cannot.
            </>
          )}
        </p>
      )}

      <div className="install-release" data-testid="flasher-release">
        {latest ? (
          <>
            <p className="install-kicker">Signed release</p>
            <p className="install-version">{latest.version}</p>
            <p className="install-muted">
              build {latest.build}, published {latest.date}
            </p>
            <p>{latest.notes}</p>
            <details className="install-details">
              <summary>Files, offsets and SHA-256</summary>
              <ul>
                {latest.parts.map((p) => (
                  <li key={p.file}>
                    0x{p.offset.toString(16)} {p.file} {p.size.toLocaleString("en-US")} B {p.sha256}
                  </li>
                ))}
              </ul>
              <p>
                The manifest that lists these hashes is signed with the Guardian release key (ECDSA P-256); this site checks the signature,
                and your browser checks each file again before writing it.
              </p>
            </details>
          </>
        ) : (
          <p className="install-muted" data-testid="flasher-loading">
            {loadError ?? "Reading the published release…"}
          </p>
        )}
      </div>

      <fieldset className="install-modes" disabled={busy}>
        <legend>What do you want to do?</legend>
        <label>
          <input type="radio" name="mode" value="update" checked={mode === "update"} onChange={() => { setMode("update"); setConfirming(false); }} />
          <span>
            <strong>Update</strong>
            <span>For a stick that already runs the Guardian. Writes the new firmware and keeps your settings, your picked network and your stored Wi-Fi.</span>
          </span>
        </label>
        <label>
          <input type="radio" name="mode" value="install" checked={mode === "install"} onChange={() => { setMode("install"); setConfirming(false); }} />
          <span>
            <strong>First install (erases everything)</strong>
            <span>For a StickS3 that runs something else. Erases the whole chip, then installs the Guardian.</span>
          </span>
        </label>
        <label>
          <input type="radio" name="mode" value="restore" checked={mode === "restore"} onChange={() => { setMode("restore"); setConfirming(false); }} />
          <span>
            <strong>Restore a backup</strong>
            <span>Writes a whole 8 MB backup made on this page back onto the stick, byte for byte.</span>
          </span>
        </label>
      </fieldset>

      {mode === "install" && (
        <div className="install-box" data-testid="flasher-backup">
          <p>
            <strong>Before you erase:</strong> keep a copy of what is on the stick now. It takes about a minute and saves the whole 8 MB flash
            as a <code>.bin</code> file. You can put it back later with <strong>Restore a backup</strong> on this page.
          </p>
          <Button variant="outline" size="lg" disabled={!canUse} onClick={() => run("backup")} data-testid="flasher-backup-button">
            Download a backup of what is on the stick now
          </Button>
          {backup && (
            <p className="install-ok" data-testid="flasher-backup-done">
              Saved <code>{backup.name}</code> ({backup.size.toLocaleString("en-US")} bytes), SHA-256 <code className="install-hash">{backup.sha256}</code>.
              It holds everything on the stick, including any stored Wi-Fi password: keep it private.
            </p>
          )}
          <label className="install-check">
            <input type="checkbox" checked={eraseOk} onChange={(e) => { setEraseOk(e.target.checked); setConfirming(false); }} disabled={busy} />
            <span>I understand: the whole stick is erased, including whatever it runs now and anything stored on it.</span>
          </label>
        </div>
      )}

      {mode === "restore" && (
        <div className="install-box" data-testid="flasher-restore">
          <label className="install-file">
            <span>Backup file (.bin, exactly 8 MB)</span>
            <input type="file" accept=".bin,application/octet-stream" disabled={busy} onChange={(e) => pickRestore(e.target.files?.[0])} data-testid="flasher-restore-file" />
          </label>
          {restoreFile && (
            <p className={restoreFile.problem ? "install-error-text" : "install-muted"} data-testid="flasher-restore-info">
              {restoreFile.problem ?? (
                <>
                  <code>{restoreFile.name}</code>, {restoreFile.bytes.length.toLocaleString("en-US")} bytes, SHA-256{" "}
                  <code className="install-hash">{restoreFile.sha256}</code>
                </>
              )}
            </p>
          )}
          <label className="install-check">
            <input type="checkbox" checked={restoreOk} onChange={(e) => { setRestoreOk(e.target.checked); setConfirming(false); }} disabled={busy} />
            <span>I understand: everything on the stick is replaced by this backup.</span>
          </label>
        </div>
      )}

      {confirming && twoStep ? (
        <div className="install-confirm" role="alertdialog" aria-labelledby="install-confirm-text" data-testid="flasher-confirm">
          <p id="install-confirm-text">
            {mode === "install"
              ? "Last check: erase the whole stick and install the Guardian?"
              : "Last check: replace everything on the stick with this backup?"}
          </p>
          <div>
            <Button size="lg" variant="destructive" onClick={() => run(mode)} data-testid="flasher-confirm-yes">
              {mode === "install" ? "Yes, erase and install" : "Yes, restore"}
            </Button>
            <Button size="lg" variant="outline" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button size="lg" className="install-main" disabled={!ready} onClick={() => (twoStep ? setConfirming(true) : run(mode))} data-testid="flasher-button">
          {mainLabel}
        </Button>
      )}

      {pickerHint && phase === "idle" && (
        <p className="install-note install-warn" data-testid="flasher-picker-hint">
          <strong>The stick was not in the list?</strong> {DOWNLOAD_MODE_STEPS} Use a USB-C data cable.
        </p>
      )}

      <div ref={statusRef} tabIndex={-1} className="install-status" aria-live="polite">
        {phase !== "idle" && (
          <>
            {device && <p className="install-muted install-mono">{device}</p>}
            {busy && (
              <>
                <p>
                  {phase === "connecting" && "Pick the stick in the browser's window…"}
                  {phase === "restarting" && "Restarting the stick…"}
                  {(phase === "downloading" || phase === "reading" || phase === "writing") && `${progress.label}… ${progress.pct}%`}
                </p>
                <div className="install-bar" role="progressbar" aria-label="Progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress.pct}>
                  <div style={{ width: `${progress.pct}%` }} />
                </div>
                <p className="install-muted">Do not unplug the cable.</p>
              </>
            )}
            {phase === "done" && (
              <div className="install-done" data-testid="flasher-done" data-action={doneMode ?? ""}>
                {doneMode === "backup" && (
                  <p>
                    <strong>Backup saved.</strong> The stick was only read and has restarted into what it ran before.
                    {mode === "install" && " Next: tick the box above and install."}
                  </p>
                )}
                {doneMode === "update" && (
                  <p>
                    <strong>Done.</strong> The stick restarted with the Guardian {latest?.version}. Your settings, picked network and stored
                    Wi-Fi were kept. If the screen stays dark, press the small side button once.
                  </p>
                )}
                {doneMode === "install" && (
                  <>
                    <p>
                      <strong>Done.</strong> The Guardian {latest?.version} is installed. If the screen stays dark, press the small side button once.
                    </p>
                    <p>
                      On its first boot the stick shows three welcome pages; a short press of either key moves on. Then pick your network:
                      hold the side key to open the list, move to your network with the front (blue) key and choose it with the side key. The
                      Guardian listens to that network&apos;s channel; it needs no Wi-Fi password to guard.
                    </p>
                  </>
                )}
                {doneMode === "restore" && (
                  <p>
                    <strong>Done.</strong> The backup is back on the stick and it restarted into it.
                  </p>
                )}
                {verified && <p className="install-muted">{verified}</p>}
              </div>
            )}
            {phase === "error" && (
              <p className="install-error" role="alert" data-testid="flasher-error">
                {message}
              </p>
            )}
            {logText && (
              <details className="install-details">
                <summary>Technical details</summary>
                <pre>{logText}</pre>
              </details>
            )}
          </>
        )}
      </div>
    </div>
  );
}
