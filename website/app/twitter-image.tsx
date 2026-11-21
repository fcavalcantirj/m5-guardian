import { renderSocialCard } from "@/lib/social-card";

export const alt =
  "M5 Guardian: the Guardian persona's Very good face beside the words Your Wi-Fi, under watch.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return renderSocialCard();
}
