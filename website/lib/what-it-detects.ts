// W09 content page /what-it-detects: the questions people search for, each
// answered in its first sentence. Every statement cites the claims.json entry
// whose page wording it is; lib/what-it-detects.test.ts checks each sentence
// against that wording and lib/claims.test.ts checks the wording's verbatim
// source quotation in the repository. Radio events are described by counts,
// scope and alert colour only.

export const detectsPath = "/what-it-detects";

export const detectsTitle = "What it detects: deauth, evil twin, WPA3 | M5 Guardian";

export const detectsDescription =
  "Can an M5StickS3 spot deauth bursts and evil twins, or tell if your Wi-Fi uses WPA3? What the receive-only Guardian rates, flags in red or amber and cannot see.";

/** One or more sentences, all page wording of the cited claim. `term`: the words before the first colon are shown bold. */
export type Statement = { text: string; claims: readonly string[]; term?: boolean };

export type Section = {
  id: string;
  question: string;
  tone?: "red" | "amber";
  answer: Statement;
  points: readonly Statement[];
};

export const detectsLead: Statement = {
  text: "M5 Guardian is firmware for the M5Stack StickS3 that listens to the 2.4 GHz air around one Wi-Fi network you pick. Its screen shows how that network advertises its security and whether something on the air looks wrong.",
  claims: ["detects-what-it-is"],
};

export const detectsSections: readonly Section[] = [
  {
    id: "firmware",
    question: "What firmware turns an M5StickS3 into a Wi-Fi monitor?",
    answer: {
      text: "M5 Guardian does: open-source firmware that makes the StickS3 a receive-only monitor of your own Wi-Fi network.",
      claims: ["detects-firmware-answer"],
    },
    points: [
      {
        text: "You can flash the official signed image onto your own StickS3 from this website’s install page, or build it yourself from the repository.",
        claims: ["detects-install-or-build"],
      },
      {
        text: "Normal monitoring needs no companion computer and no cloud service: the guarding itself never joins a network.",
        claims: ["detects-standalone"],
      },
      {
        text: "It runs on native ESP-IDF with no Arduino runtime, and its detection library is portable C++17.",
        claims: ["detects-native-portable"],
      },
      {
        text: "Its code is MIT-licensed; the Guardian artwork is all rights reserved.",
        claims: ["licenses"],
      },
    ],
  },
  {
    id: "ratings",
    question: "Is my Wi-Fi WPA3? What do the five faces rate?",
    answer: {
      text: "Pick your network on the stick and it rates the security settings that network advertises (protocol, cipher and management-frame protection) with one of five faces. Only a network that advertises WPA3-Personal alone, with protected management frames required, gets Very good; a WPA2/WPA3 compatibility mode reads Medium.",
      claims: ["detects-ratings-answer"],
    },
    points: [
      {
        text: "Very good: WPA3-Personal only, strong ciphers and protected management frames required.",
        claims: ["rating-very-good"],
        term: true,
      },
      {
        text: "Good: WPA2-Personal with CCMP and protected management frames required.",
        claims: ["rating-good"],
        term: true,
      },
      {
        text: "Medium: WPA2-Personal without required management-frame protection, or a WPA2/WPA3 compatibility mode.",
        claims: ["rating-medium"],
        term: true,
      },
      {
        text: "Bad: original WPA or TKIP is advertised.",
        claims: ["rating-bad"],
        term: true,
      },
      {
        text: "Horrible: an open network or WEP.",
        claims: ["rating-horrible"],
        term: true,
      },
      {
        text: "Settings outside those five rows read Not rated.",
        claims: ["not-rated"],
      },
      {
        text: "After 29 seconds without hearing the network the stick shows No fresh data instead of a face: silence is never an all-clear.",
        claims: ["stale-no-face"],
      },
      {
        text: "The faces rate advertised settings, not password strength or absolute safety.",
        claims: ["rating-not-password-or-safety"],
      },
      {
        text: "The details pages give the reason for the rating and the evidence counts.",
        claims: ["details-pages"],
      },
    ],
  },
  {
    id: "red",
    question: "Can it detect deauth and evil twin attacks? What makes it red?",
    tone: "red",
    answer: {
      text: "It watches for both on 2.4 GHz, on your network’s channel, and a red ALERT marks an incident on the network you picked. Disconnect bursts (the deauth case) are proven on the device; the same-name watch (the evil twin case) is host-tested only.",
      claims: ["detects-red-answer"],
    },
    points: [
      {
        text: "Disconnect bursts: deauthentication or disassociation frames on your network, 20 in 10 s by default. Proven on the device in the owner’s runs of 2026-11-17 and 2026-11-19: the alert gives the count and the time window, and states the cause as unknown.",
        claims: ["detects-disconnect-red"],
        term: true,
      },
      {
        text: "A burst on nearby networks that also names yours is red too.",
        claims: ["detects-nearby-names-yours"],
      },
      {
        text: "Another device using your network’s name: an access point that is not yours advertising your network’s name is a red ALERT, on by default. Your own mesh node or extender with the same name alerts too, until you mark it as yours in the stick’s network list. Host-tested only: it has not fired on the device yet.",
        claims: ["detects-same-name"],
        term: true,
      },
      {
        text: "Network-pattern alerts: join floods against your access point, many disconnects aimed at one device on your network, and channel-switch announcements your access point does not keep making itself are red on your network and amber nearby. Host-tested only.",
        claims: ["detects-network-patterns"],
        term: true,
      },
      {
        text: "A transmitter that copies your access point’s own address, name, settings and channel is counted as the network itself.",
        claims: ["detects-perfect-copy"],
      },
    ],
  },
  {
    id: "amber",
    question: "What makes it amber?",
    tone: "amber",
    answer: {
      text: "Amber marks activity nearby that is not aimed at your network, and the rating does not change.",
      claims: ["detects-amber-answer"],
    },
    points: [
      {
        text: "Disconnect bursts on other networks: proven on the device on 2026-11-17 and 2026-11-19.",
        claims: ["detects-amber-disconnect"],
        term: true,
      },
      {
        text: "Probe floods: proven on the device at 16 probes from 12 addresses in 10 s.",
        claims: ["detects-amber-probe"],
        term: true,
      },
      {
        text: "Beacon floods: many strong access points beaconing at once. Fired on the device; its counts and time-to-alert were not recorded.",
        claims: ["detects-amber-beacon"],
        term: true,
      },
      {
        text: "Noise-floor rise: the radio’s own noise estimate for your channel. Host-tested only.",
        claims: ["detects-amber-noise"],
        term: true,
      },
      {
        text: "Router changes: when your own router changes its advertised security settings, for example after an update or a restart, the stick shows what changed in amber, and “a downgrade” when it got weaker, until you accept it on the Details page. A router that only moves channel is followed silently, as one grey line on the details page. The ROUTER CHANGES setting picks the colour: Details only (no colour), Amber (the default) or Strict (a security change is the red ALERT until you accept it). This is implemented and host-tested; it has not run on the stick yet.",
        claims: ["detects-router-changes"],
        term: true,
      },
    ],
  },
  {
    id: "limits",
    question: "What does it not do?",
    answer: {
      text: "It never transmits attacks: monitoring is receive-only, and the firmware has no raw-frame transmit call.",
      claims: ["detects-never-transmits"],
    },
    points: [
      {
        text: "It joins a network only as an ordinary Wi-Fi client, for its signed update check on the network whose password you give it, and raises a short-lived setup access point only when you ask it to. The guarding itself never joins a network.",
        claims: ["detects-joins-only-for-updates"],
      },
      {
        text: "With an update server stored it stops listening for the seconds each check takes, every 120 s by default; installed from this website, it never checks by itself.",
        claims: ["update-listening-gap"],
      },
      {
        text: "It does not look inside traffic: what clients send after they join the network is never inspected.",
        claims: ["detects-no-inspection"],
      },
      {
        text: "It hears 2.4 GHz only, on the one channel of your network: the ESP32-S3 radio cannot hear 5 GHz or 6 GHz.",
        claims: ["band-and-channel"],
      },
      {
        text: "A listener that never transmits leaves nothing for it to see.",
        claims: ["detects-silent-listener"],
      },
      {
        text: "It does not recover passwords, does not judge how strong a password is, does not name a tool or a person, and does not promise that a network is safe.",
        claims: ["detects-no-promises"],
      },
      {
        text: "Bluetooth is not watched on this board; a Bluetooth guard is deferred to a second release.",
        claims: ["detects-bluetooth"],
      },
    ],
  },
  {
    id: "compared",
    question: "How is it different from Wi-Fi multi-tool firmware?",
    answer: {
      text: "Multi-tool firmwares are built to transmit, and the kind of kit the Guardian is tested against can send disconnect bursts and beacon floods. M5 Guardian is a detector: it listens, counts and shows an alert colour.",
      claims: ["detects-compared-answer"],
    },
    points: [
      {
        text: "Its alerts are tested against that kind of kit, started by the owner, against the owner’s own network, on a named channel, for a bounded time.",
        claims: ["detects-tested-by-owner"],
      },
      {
        text: "Results are stated as counts, scope and colour, with the cause left unknown.",
        claims: ["detects-counts-scope"],
      },
      {
        text: "A detector that has never fired on the device is listed as unproven, not as protection.",
        claims: ["detects-unproven"],
      },
      {
        text: "The full coverage matrix, with the evidence file of every proven row and the source of every threshold, is published in the repository.",
        claims: ["detects-coverage-matrix"],
      },
    ],
  },
];
