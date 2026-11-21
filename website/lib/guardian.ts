export const repositoryUrl = "https://github.com/fcavalcantirj/m5-guardian";
export const siteUrl = "https://m5-guardian.vercel.app";
export const siteTitle = "M5 Guardian: your Wi-Fi, under watch";
export const siteDescription =
  "A pocket radio guard for your own Wi-Fi on the M5 StickS3: receive-only monitoring, five rated faces for advertised settings, and red or amber alerts. This website is a simulation.";
export const codeLicenseUrl = `${repositoryUrl}/blob/main/LICENSE`;
export const artworkLicenseUrl = `${repositoryUrl}/blob/main/website/public/images/LICENSE`;

export const moods = [
  {
    id: "very-good",
    name: "Very good",
    caption: "Looking sharp.",
    image: "/images/very-good.png",
    tone: "green",
    description:
      "The strongest advertised-settings rating: WPA3-Personal only, strong ciphers and protected management frames required. It earns the big grin.",
  },
  {
    id: "good",
    name: "Good",
    caption: "Steady and watchful.",
    image: "/images/good.png",
    tone: "cyan",
    description:
      "A good advertised-settings rating: WPA2-Personal with CCMP and protected management frames required. Guardian stays composed and keeps listening.",
  },
  {
    id: "medium",
    name: "Medium",
    caption: "An eyebrow is raised.",
    image: "/images/medium.png",
    tone: "amber",
    description:
      "WPA2-Personal without required management-frame protection, or a WPA2/WPA3 compatibility mode. The details pages explain the settings behind the raised eyebrow.",
  },
  {
    id: "bad",
    name: "Bad",
    caption: "We need to talk.",
    image: "/images/bad.png",
    tone: "amber",
    description:
      "Original WPA or TKIP is advertised. A worried face makes the warning hard to miss. Check the details and review your access point’s configuration.",
  },
  {
    id: "horrible",
    name: "Horrible",
    caption: "That’s a hard no.",
    image: "/images/horrible.png",
    tone: "red",
    description:
      "An open network or WEP: the lowest advertised-settings rating. The face is a prompt to review protection, not proof of an incident.",
  },
] as const;

export type Mood = (typeof moods)[number];
export type Scenario = "normal" | "nearby" | "alert" | "stale";
export type Presentation = {
  label: string;
  description: string;
  image: string | null;
  rating: string;
  tone: string;
  demo: true;
};

export function getPresentation(mood: Mood, scenario: Scenario): Presentation {
  const base = {
    rating: mood.name,
    image: mood.image,
    tone: mood.tone,
    demo: true as const,
  };
  if (scenario === "stale")
    return {
      ...base,
      label: "No fresh data",
      description:
        "Demo: the network was not heard for 29 seconds. Rating withheld until fresh evidence returns.",
      image: null,
      rating: "Unavailable",
      tone: "muted",
    };
  if (scenario === "alert")
    return {
      ...base,
      label: "Network alert",
      description:
        "Demo: 24 disconnect frames on the selected network in 10 seconds. Cause unknown.",
      image: `/images/${mood.id}-alert.png`,
      tone: "red",
    };
  if (scenario === "nearby")
    return {
      ...base,
      label: "Nearby activity",
      description:
        "Demo: 16 probes from 12 addresses nearby in 10 seconds. The selected network’s rating is unchanged.",
      tone: "amber",
    };
  return {
    ...base,
    label: mood.name,
    description: `Demo advertised-settings rating: ${mood.name.toLowerCase()}. Listening for changes.`,
  };
}
