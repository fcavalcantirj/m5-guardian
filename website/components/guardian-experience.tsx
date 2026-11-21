"use client";

import Image from "next/image";
import { useEffect, useState } from "react";
import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  Check,
  CircleAlert,
  Eye,
  Info,
  Pause,
  Play,
  Radio,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { GuardianStage } from "@/components/guardian-stage";
import {
  getPresentation,
  moods,
  repositoryUrl,
  type Scenario,
} from "@/lib/guardian";

const scenarios = [
  { value: "normal", label: "Listening", icon: Radio },
  { value: "nearby", label: "Nearby activity", icon: Eye },
  { value: "alert", label: "Network alert", icon: CircleAlert },
  { value: "stale", label: "No fresh data", icon: WifiOff },
] as const;

export function GuardianExperience() {
  const [selectedMood, setSelectedMood] = useState("very-good");
  const [scenario, setScenario] = useState<Scenario>("normal");
  const [paused, setPaused] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [ready, setReady] = useState(false);
  const mood = moods.find((item) => item.id === selectedMood) ?? moods[0];
  const view = getPresentation(mood, scenario);
  const motion = !paused && !reducedMotion;

  useEffect(() => {
    setReady(true);
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setReducedMotion(query.matches);
    sync();
    query.addEventListener("change", sync);
    return () => query.removeEventListener("change", sync);
  }, []);

  return (
    <div
      className="guardian-experience"
      data-motion={motion ? "on" : "off"}
      data-ready={ready}
    >
      <section className="hero container" aria-labelledby="hero-title">
        <div className="hero-copy">
          <div className="eyebrow hero-eyebrow">
            <span className="status-dot" /> SMALL DEVICE. SERIOUS AWARENESS.
          </div>
          <h1 id="hero-title">
            Your Wi-Fi.
            <br />
            <span>Under watch.</span>
          </h1>
          <p className="hero-description">
            Meet your pocket-sized radio guardian. It listens to the invisible,
            spots the unusual, and wears your Wi-Fi&apos;s state on its face.
          </p>
          <p className="simulation-note">
            <Info aria-hidden="true" />
            <span>
              This website is a simulation. It does not connect to or protect
              your network.
            </span>
          </p>
          <div className="hero-actions">
            <a href="#guardian" className={buttonVariants({ size: "hero" })}>
              Meet the Guardian{" "}
              <ArrowDown data-icon="inline-end" aria-hidden="true" />
            </a>
            <a
              href={`${repositoryUrl}#build-and-install`}
              target="_blank"
              rel="noreferrer"
              className={buttonVariants({ variant: "outline", size: "hero" })}
            >
              Build your own{" "}
              <ArrowUpRight data-icon="inline-end" aria-hidden="true" />
            </a>
          </div>
          <div className="hero-proof">
            <span>
              <ShieldCheck aria-hidden="true" /> Defensive by design
            </span>
            <i />
            <span>Open-source code</span>
          </div>
          <div className="hero-platform">
            <span className="platform-line" />
            <span>
              BUILT ON <strong>M5 StickS3</strong>
            </span>
            <span className="platform-separator">/</span>
            <span>
              STARTING WITH <strong>Wi-Fi</strong>
            </span>
          </div>
        </div>
        <GuardianStage view={view} motion={motion} />
      </section>

      <section
        className="signal-console container"
        aria-label="Interactive Guardian simulation"
      >
        <div className="console-top">
          <div className="console-title">
            <span className="status-dot" />
            <span>TRY THE SIGNAL</span>
            <span className="demo-tag">INTERACTIVE DEMO</span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="motion-toggle"
            onClick={() => setPaused(!paused)}
            disabled={reducedMotion}
            aria-label={
              reducedMotion
                ? "Motion off: reduced motion is requested by your system"
                : paused
                  ? "Resume motion"
                  : "Pause motion"
            }
          >
            {motion ? (
              <Pause data-icon="inline-start" aria-hidden="true" />
            ) : (
              <Play data-icon="inline-start" aria-hidden="true" />
            )}
            <span className="motion-label">
              {reducedMotion
                ? "Motion off (system)"
                : paused
                  ? "Resume motion"
                  : "Pause motion"}
            </span>
          </Button>
        </div>
        <div className="console-main">
          <div className="console-prompt">
            <Wifi aria-hidden="true" />
            <span>
              Change the air.
              <br />
              <strong>Watch the Guardian react.</strong>
            </span>
          </div>
          <ToggleGroup
            aria-label="Simulated radio condition"
            value={[scenario]}
            onValueChange={(values) => {
              if (values[0]) setScenario(values[0] as Scenario);
            }}
            variant="console"
            size="console"
            spacing={1}
            className="scenario-controls"
          >
            {scenarios.map(({ value, label, icon: Icon }) => (
              <ToggleGroupItem key={value} value={value}>
                <Icon aria-hidden="true" />
                {label}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <div className="console-frequency">
            <span>FREQUENCY</span>
            <strong>
              2.4 <small>GHz</small>
            </strong>
          </div>
        </div>
        <div className="console-bottom">
          <span className="scenario-description" role="status">
            {view.description}
          </span>
          <span className="console-disclaimer">
            Simulated data, not a live reading. This website is a simulation. It
            does not connect to or protect your network.
          </span>
        </div>
      </section>

      <div className="principles-strip container">
        <span>
          <Radio aria-hidden="true" /> Receive-only monitoring
        </span>
        <span>
          <ShieldCheck aria-hidden="true" /> Your network. Your control.
        </span>
        <span>
          <Eye aria-hidden="true" /> Awareness, not interference
        </span>
        <span className="strip-end">No cloud for normal monitoring</span>
      </div>

      <section
        id="guardian"
        className="moods-section container"
        aria-labelledby="moods-title"
      >
        <div className="section-heading">
          <div>
            <span className="eyebrow">
              <span className="section-index">01 /</span> MEET YOUR GUARDIAN
            </span>
            <h2 id="moods-title">
              One guardian.
              <br />
              Five ways to say it.
            </h2>
          </div>
          <p>
            No wall of numbers. No guessing games.
            <br />
            Five rated faces for the settings your network advertises. Settings
            outside those five rows read Not rated, and stale evidence shows No
            fresh data instead of a face.
            <br />
            <span className="text-bright">Pick a face. Get the message.</span>
          </p>
        </div>
        <ToggleGroup
          aria-label="Guardian advertised-settings expression"
          value={[selectedMood]}
          onValueChange={(values) => {
            if (values[0]) {
              setSelectedMood(values[0] as string);
              setScenario("normal");
            }
          }}
          variant="portrait"
          size="portrait"
          className="mood-grid"
          spacing={3}
        >
          {moods.map((item, i) => (
            <ToggleGroupItem
              key={item.id}
              value={item.id}
              aria-label={`${item.name}: ${item.caption}`}
            >
              <span className="mood-card-top">
                <span>0{i + 1}</span>
                <span className="mood-selection">
                  {selectedMood === item.id ? (
                    <Check aria-hidden="true" />
                  ) : (
                    <ArrowUpRight aria-hidden="true" />
                  )}
                </span>
              </span>
              <span className="mood-image-wrap">
                <Image
                  src={item.image}
                  alt=""
                  width={240}
                  height={240}
                  sizes="(max-width: 600px) 43vw, 240px"
                />
              </span>
              <span className="mood-text">
                <strong>
                  <i data-tone={item.tone} />
                  {item.name}
                </strong>
                <span>{item.caption}</span>
              </span>
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <div className="mood-explanation">
          <div>
            <span className="status-dot" />
            <strong>{mood.name}</strong>
            <ArrowRight aria-hidden="true" />
            <p>{mood.description}</p>
          </div>
          <a href="#how-it-works">
            More than a pretty face <ArrowDown aria-hidden="true" />
          </a>
        </div>
        <p className="honesty-note">
          <Info aria-hidden="true" /> Faces rate advertised settings, not
          password strength or absolute safety. Incidents are separate. No fresh
          evidence? No rated face.
        </p>
      </section>
    </div>
  );
}
