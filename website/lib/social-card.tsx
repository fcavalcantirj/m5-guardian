import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";

// The 1200x630 card shared by the Open Graph and Twitter image routes. The
// portrait is the owner's reserved artwork (public/images/LICENSE), used here
// only for this website's own social card.
const socialCardSize = { width: 1200, height: 630 };

export async function renderSocialCard() {
  const portrait = await readFile(
    join(process.cwd(), "public/images/very-good.png"),
    "base64",
  );
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          background: "#080b0c",
          color: "#edf0ee",
          padding: "0 72px",
          gap: "48px",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
          <div
            style={{
              display: "flex",
              fontSize: 26,
              letterSpacing: 4,
              color: "#b5f36a",
            }}
          >
            M5 / GUARDIAN
          </div>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              fontSize: 84,
              lineHeight: 1.05,
              marginTop: 28,
              fontWeight: 600,
            }}
          >
            <span>Your Wi-Fi.</span>
            <span style={{ color: "#b5f36a" }}>Under watch.</span>
          </div>
          <div
            style={{
              display: "flex",
              fontSize: 28,
              lineHeight: 1.4,
              marginTop: 32,
              color: "#b8c0c2",
            }}
          >
            Receive-only Wi-Fi monitoring on the M5 StickS3.
          </div>
        </div>
        <img
          src={`data:image/png;base64,${portrait}`}
          width={460}
          height={460}
          alt=""
        />
      </div>
    ),
    { ...socialCardSize },
  );
}

// The /install card: the same layout and colours, text only (no artwork).
export function renderInstallCard() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          background: "#080b0c",
          color: "#edf0ee",
          padding: "0 72px",
        }}
      >
        <div
          style={{
            display: "flex",
            fontSize: 26,
            letterSpacing: 4,
            color: "#b5f36a",
          }}
        >
          M5 / GUARDIAN / INSTALL
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            fontSize: 84,
            lineHeight: 1.05,
            marginTop: 28,
            fontWeight: 600,
          }}
        >
          <span>Put the Guardian</span>
          <span style={{ color: "#b5f36a" }}>on your own StickS3.</span>
        </div>
        <div
          style={{
            display: "flex",
            fontSize: 28,
            lineHeight: 1.4,
            marginTop: 32,
            color: "#b8c0c2",
          }}
        >
          Signed firmware over USB, from Chrome or Edge on a desktop.
        </div>
      </div>
    ),
    { ...socialCardSize },
  );
}
