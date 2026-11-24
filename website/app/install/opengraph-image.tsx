import { renderInstallCard } from "@/lib/social-card";

export const alt = "M5 Guardian install page: Put the Guardian on your own StickS3. Signed firmware over USB, from Chrome or Edge on a desktop.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return renderInstallCard();
}
