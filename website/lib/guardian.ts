export const repositoryUrl = "https://github.com/fcavalcantirj/m5-guardian";

export const moods = [
  {
    id: "very-good",
    name: "Very good",
    caption: "Looking sharp.",
    image: "/images/very-good.png",
    tone: "green",
    description:
      "The strongest advertised-settings rating. Modern protection earns the big grin. The cigar is optional. The attitude isn’t.",
  },
  {
    id: "good",
    name: "Good",
    caption: "Steady and watchful.",
    image: "/images/good.png",
    tone: "cyan",
    description:
      "A good advertised-settings rating. Guardian stays composed, keeps listening, and watches for changes on your network.",
  },
  {
    id: "medium",
    name: "Medium",
    caption: "An eyebrow is raised.",
    image: "/images/medium.png",
    tone: "amber",
    description:
      "Mixed advertised protection. Something deserves a closer look. The details screen explains the settings behind the raised eyebrow.",
  },
  {
    id: "bad",
    name: "Bad",
    caption: "We need to talk.",
    image: "/images/bad.png",
    tone: "amber",
    description:
      "Weak advertised settings. A worried face makes the warning hard to miss. Check the details and review your access point’s configuration.",
  },
  {
    id: "horrible",
    name: "Horrible",
    caption: "That’s a hard no.",
    image: "/images/horrible.png",
    tone: "red",
    description:
      "The lowest advertised-settings rating. Guardian does not sugarcoat it. The face is a prompt to review protection, not proof of an incident.",
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
        "No observation for 29 seconds. Rating withheld until fresh evidence returns.",
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
