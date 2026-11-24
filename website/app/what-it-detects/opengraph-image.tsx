import { renderDetectsCard } from "@/lib/social-card";

export const alt = "M5 Guardian, what it detects: red for your network, amber for nearby. What it rates, flags and cannot see.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return renderDetectsCard();
}
