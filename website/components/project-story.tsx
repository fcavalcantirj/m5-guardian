import Image from "next/image";
import {
  ArrowRight,
  ArrowUpRight,
  BatteryMedium,
  Check,
  ChevronRight,
  CircuitBoard,
  Code2,
  Cpu,
  Eye,
  Fingerprint,
  GitFork,
  Radio,
  ShieldCheck,
  Terminal,
  Usb,
  Wifi,
} from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import {
  artworkLicenseUrl,
  codeLicenseUrl,
  repositoryUrl,
} from "@/lib/guardian";

const steps = [
  {
    number: "01",
    icon: Wifi,
    title: "Pick your network.",
    description:
      "Choose your own access point on the StickS3. Guardian listens on its 2.4 GHz channel, without joining it to monitor.",
  },
  {
    number: "02",
    icon: Eye,
    title: "Let the air tell its story.",
    description:
      "Advertised settings, fresh observations, and unusual frame counts become a picture you can understand at a glance.",
  },
  {
    number: "03",
    icon: ShieldCheck,
    title: "Know when to look closer.",
    description:
      "Red for an incident on your network. Amber for nearby activity. Clear context, not dramatic guesses about who is behind it.",
  },
];

export function HowItWorks() {
  return (
    <section
      id="how-it-works"
      className="how-section section-bordered"
      aria-labelledby="how-title"
    >
      <div className="container">
        <div className="section-heading">
          <div>
            <span className="eyebrow">
              <span className="section-index">02 /</span> QUIETLY PAYING
              ATTENTION
            </span>
            <h2 id="how-title">
              It listens.
              <br />
              You stay in the know.
            </h2>
          </div>
          <p>
            Built to observe. Never to interfere.
            <br />A little less uncertainty in the air around you.
          </p>
        </div>
        <div className="how-grid">
          <div className="steps">
            {steps.map(({ number, icon: Icon, title, description }) => (
              <article key={number} className="step">
                <span className="step-number">{number}</span>
                <div>
                  <h3>
                    <Icon aria-hidden="true" />
                    {title}
                  </h3>
                  <p>{description}</p>
                </div>
              </article>
            ))}
          </div>
          <div className="observation-panel">
            <div className="panel-heading">
              <span>
                <Terminal aria-hidden="true" /> THE OBSERVATION LAYER
              </span>
              <span>EXAMPLE: SYNTHETIC NAME AND COUNTS</span>
            </div>
            <div className="observation-network">
              <div className="network-symbol">
                <Wifi aria-hidden="true" />
              </div>
              <div>
                <span className="micro-label">SELECTED NETWORK</span>
                <strong>YOUR-NETWORK</strong>
                <span className="network-meta">
                  2.4 GHz <i /> Channel 06 <i /> Receive-only monitoring
                </span>
              </div>
              <span className="status-dot" />
            </div>
            <div className="observation-row">
              <span className="event-time">00:00:01</span>
              <span className="event-dot tone-green" />
              <div>
                <strong>Fresh evidence received</strong>
                <p>Advertised settings observed</p>
              </div>
              <Check aria-hidden="true" />
            </div>
            <div className="observation-row">
              <span className="event-time">00:00:04</span>
              <span className="event-dot tone-amber" />
              <div>
                <strong>Activity nearby</strong>
                <p>16 probes · 12 addresses · 10 s</p>
              </div>
              <span className="event-scope">NEARBY</span>
            </div>
            <div className="observation-row">
              <span className="event-time">00:00:10</span>
              <span className="event-dot tone-red" />
              <div>
                <strong>Disconnect burst observed</strong>
                <p>24 frames · 10 s · cause unknown</p>
              </div>
              <span className="event-scope">YOUR AP</span>
            </div>
            <div className="observation-footer">
              <Fingerprint aria-hidden="true" />
              <span>
                Counts and context.
                <br />
                <strong>Not assumptions about identity.</strong>
              </span>
            </div>
          </div>
        </div>
        <div className="limits-note">
          <span>KNOW THE LIMITS</span>
          <div className="limits-copy">
            <p>
              2.4 GHz only. One selected channel. No password-strength testing,
              no inspection of clients’ application traffic, and no promise of
              absolute safety.
            </p>
            <p>
              Receive-only monitoring: the stick transmits only for its phone
              setup access point and, as an ordinary Wi-Fi client, for its
              signed update check. It stops listening for the seconds each
              check takes, every 120 s by default.
            </p>
            <p>
              Disconnect bursts on your network and nearby activity are proven
              on the device; several other detector families are host-tested
              only.
            </p>
          </div>
          <ul className="limits-links" aria-label="Published limits and coverage">
            <li>
              <a
                href={`${repositoryUrl}#what-it-cannot-see`}
                target="_blank"
                rel="noreferrer"
              >
                What it cannot see <ArrowUpRight aria-hidden="true" />
              </a>
            </li>
            <li>
              <a
                href={`${repositoryUrl}/blob/main/docs/attack-coverage.md`}
                target="_blank"
                rel="noreferrer"
              >
                Detection coverage <ArrowUpRight aria-hidden="true" />
              </a>
            </li>
            <li>
              <a
                href={`${repositoryUrl}/blob/main/docs/G23-delivery.md`}
                target="_blank"
                rel="noreferrer"
              >
                Delivery record and limits <ArrowUpRight aria-hidden="true" />
              </a>
            </li>
          </ul>
        </div>
      </div>
    </section>
  );
}

export function Hardware() {
  return (
    <section
      id="hardware"
      className="hardware-section container"
      aria-labelledby="hardware-title"
    >
      <div className="hardware-visual">
        <div className="hardware-grid" aria-hidden="true" />
        <span className="hardware-corner top-left">M5 / STICKS3</span>
        <span className="hardware-corner bottom-right">
          POCKET-SIZED. ALWAYS CURIOUS.
        </span>
        <div
          className="device-wrap"
          role="img"
          aria-label="Stylized M5 StickS3 interface illustration showing the Guardian very good expression"
        >
          <div className="device-side-button" />
          <div className="device-body">
            <div className="device-brand">
              M5<span>STICKS3</span>
            </div>
            <div className="device-screen">
              <div className="device-status">
                <Wifi size={11} />
                <span>DEMO</span>
                <BatteryMedium size={14} />
              </div>
              <Image
                src="/images/very-good.png"
                alt=""
                width={180}
                height={180}
              />
              <span className="device-mood">VERY GOOD</span>
              <span className="device-network">YOUR-NETWORK</span>
            </div>
            <div className="device-button" />
            <span className="device-bottom-label">GUARDIAN</span>
          </div>
          <div className="device-shadow" />
        </div>
        <span className="device-callout callout-screen">
          135 × 240<span>COLOR DISPLAY</span>
        </span>
        <span className="device-callout callout-chip">
          ESP32-S3<span>ON-DEVICE CORE</span>
        </span>
        <span className="hardware-caption">
          INTERFACE ILLUSTRATION · NOT TO SCALE
        </span>
      </div>
      <div className="hardware-copy">
        <span className="eyebrow">
          <span className="section-index">03 /</span> SMALL FOOTPRINT. BIG
          CHARACTER.
        </span>
        <h2 id="hardware-title">
          A guardian.
          <br />
          Not another server.
        </h2>
        <p>
          A screen, a radio, two buttons, and a whole lot of personality. Your
          first Guardian lives on an M5 StickS3. No companion computer for
          normal monitoring: a computer does the first USB install and serves
          the signed updates.
        </p>
        <div className="hardware-specs">
          <div>
            <Cpu aria-hidden="true" />
            <span>
              ESP32-S3<strong>Native ESP-IDF</strong>
            </span>
          </div>
          <div>
            <CircuitBoard aria-hidden="true" />
            <span>
              8 MB + 8 MB<strong>Flash + PSRAM</strong>
            </span>
          </div>
          <div>
            <BatteryMedium aria-hidden="true" />
            <span>
              Built-in battery<strong>Made to go with you</strong>
            </span>
          </div>
          <div>
            <Usb aria-hidden="true" />
            <span>
              USB first install<strong>Signed updates after</strong>
            </span>
          </div>
        </div>
        <a
          href={`${repositoryUrl}#hardware`}
          target="_blank"
          rel="noreferrer"
          className={buttonVariants({ variant: "outline", size: "hero" })}
        >
          Explore the hardware{" "}
          <ArrowUpRight data-icon="inline-end" aria-hidden="true" />
        </a>
        <span className="hardware-future">
          <Radio aria-hidden="true" /> Wi-Fi first. A Bluetooth guard is
          deferred to a second release.
        </span>
      </div>
    </section>
  );
}

export function OpenSource() {
  return (
    <section
      id="open-source"
      className="open-source-section section-bordered"
      aria-labelledby="source-title"
    >
      <div className="container open-source-inner">
        <div className="source-icon">
          <Code2 aria-hidden="true" />
        </div>
        <span className="eyebrow">NO BLACK BOXES. JUST OPEN CODE.</span>
        <h2 id="source-title">
          Trust is built.
          <br />
          <span>So build your own.</span>
        </h2>
        <p>
          Read the source. Check the evidence. Make it yours.
          <br />A personal project for people who like to know what&apos;s in
          the air.
        </p>
        <div className="source-actions">
          <a
            href={repositoryUrl}
            target="_blank"
            rel="noreferrer"
            className={buttonVariants({ size: "hero" })}
          >
            <GitFork data-icon="inline-start" aria-hidden="true" /> Explore on
            GitHub <ArrowUpRight data-icon="inline-end" aria-hidden="true" />
          </a>
          <a
            href={`${repositoryUrl}/blob/main/firmware/README.md`}
            target="_blank"
            rel="noreferrer"
            className="text-link"
          >
            Read the docs <ArrowRight aria-hidden="true" />
          </a>
        </div>
        <div className="source-facts">
          <a href={codeLicenseUrl} target="_blank" rel="noreferrer">
            <Check aria-hidden="true" /> Code license: MIT
          </a>
          <a href={artworkLicenseUrl} target="_blank" rel="noreferrer">
            <Check aria-hidden="true" /> Artwork: all rights reserved
          </a>
          <span>
            <Check aria-hidden="true" /> Portable C++17 core
          </span>
          <span>
            <Check aria-hidden="true" /> Defensive by design
          </span>
        </div>
        <a
          href={repositoryUrl}
          target="_blank"
          rel="noreferrer"
          className="repository-path"
        >
          <Code2 aria-hidden="true" />
          <span>fcavalcantirj</span>
          <ChevronRight aria-hidden="true" />
          <strong>m5-guardian</strong>
          <span className="sr-only"> on GitHub</span>
          <ArrowUpRight aria-hidden="true" />
        </a>
      </div>
    </section>
  );
}
