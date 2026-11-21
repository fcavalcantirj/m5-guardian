import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geist = Geist({ subsets: ["latin"], variable: "--font-geist" });
const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
});

export const metadata: Metadata = {
  title: "M5 Guardian — Your Wi-Fi. Under watch.",
  description:
    "A pocket-sized radio guardian with a face for the invisible. Explore defensive, receive-only Wi-Fi monitoring on the M5 StickS3. Open-source code. On-device awareness.",
  openGraph: {
    title: "M5 Guardian — A face for the invisible.",
    description:
      "Your Wi-Fi. Under watch. Meet the pocket radio guardian built on M5 StickS3.",
    type: "website",
    images: [
      {
        url: "/images/very-good.png",
        width: 512,
        height: 512,
        alt: "The M5 Guardian persona",
      },
    ],
  },
  twitter: { card: "summary", title: "M5 Guardian — Your Wi-Fi. Under watch." },
};

export const viewport: Viewport = {
  themeColor: "#080b0c",
  colorScheme: "dark",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${geist.variable} ${geistMono.variable}`}>
      <body>
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
