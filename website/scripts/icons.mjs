#!/usr/bin/env node
// Generates app/favicon.ico (16, 32 and 48 px) and app/apple-icon.png (180 px)
// from app/icon.svg (W08), so /favicon.ico is served and iOS has a touch icon.
// The SVG is drawn by resvg through next/og, the renderer of the social cards:
// the output is byte-for-byte reproducible, and lib/icons.test.ts checks that
// the committed files are exactly what this script makes.
//
// Usage, from website/:  node scripts/icons.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createElement } from "react";
import { ImageResponse } from "next/og.js"; // next has no ESM exports map: name the file

const app = fileURLToPath(new URL("../app/", import.meta.url));
export const faviconSizes = [16, 32, 48];
export const appleIconSize = 180;
const background = "#080b0c"; // the icon's own fill: iOS shows no transparency in a touch icon

async function render(svg, size, opaque) {
  const src = `data:image/svg+xml;base64,${svg.toString("base64")}`;
  const image = createElement("img", { src, width: size, height: size });
  const element = opaque
    ? createElement("div", { style: { display: "flex", width: "100%", height: "100%", background } }, image)
    : image;
  const response = new ImageResponse(element, { width: size, height: size });
  return Buffer.from(await response.arrayBuffer());
}

/** An ICO file (type 1) whose images are PNGs, the format every current browser reads. */
function ico(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = 6 + 16 * images.length;
  const entries = images.map(({ size, png }) => {
    const entry = Buffer.alloc(16);
    entry[0] = size >= 256 ? 0 : size;
    entry[1] = size >= 256 ? 0 : size;
    entry[2] = 0; // no palette
    entry[3] = 0;
    entry.writeUInt16LE(1, 4); // colour planes
    entry.writeUInt16LE(32, 6); // bits per pixel
    entry.writeUInt32LE(png.length, 8);
    entry.writeUInt32LE(offset, 12);
    offset += png.length;
    return entry;
  });
  return Buffer.concat([header, ...entries, ...images.map(({ png }) => png)]);
}

/** @param {Buffer} svg the bytes of app/icon.svg */
export async function renderIcons(svg) {
  const images = [];
  for (const size of faviconSizes) images.push({ size, png: await render(svg, size, false) });
  return { ico: ico(images), appleIcon: await render(svg, appleIconSize, true) };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { ico: favicon, appleIcon } = await renderIcons(readFileSync(`${app}icon.svg`));
  writeFileSync(`${app}favicon.ico`, favicon);
  writeFileSync(`${app}apple-icon.png`, appleIcon);
  console.log(`app/favicon.ico ${favicon.length} bytes (${faviconSizes.join(", ")} px), app/apple-icon.png ${appleIcon.length} bytes (${appleIconSize} px)`);
}
