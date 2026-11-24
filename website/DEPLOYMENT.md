# Website deployment (Vercel)

The landing page in `website/` deploys to the Vercel project **m5-guardian**
(team scope `flowcoders`), production URL <https://m5-guardian.vercel.app>.
This file records the configuration, the checks a deployment must pass and the
rollback procedure. It holds no credentials: the bypass secret lives only in
Vercel and in the GitHub Actions secret `VERCEL_AUTOMATION_BYPASS_SECRET`.

## Configuration

Project settings (set in Vercel, verified by the supervisor from the project
settings page or the API):

| Setting | Value |
| --- | --- |
| Git repository | `fcavalcantirj/m5-guardian` |
| Production branch | `main` |
| Framework preset | Next.js |
| Root Directory | `website` |
| Node.js version | 24.x |

Versioned in [`vercel.json`](vercel.json), which overrides the dashboard values:

| Key | Value | Why |
| --- | --- | --- |
| `installCommand` | `corepack pnpm install --frozen-lockfile` | pnpm 12.3.4 from `packageManager`, lockfile frozen; Vercel's bundled pnpm cannot read the pnpm 12 lockfile |
| `buildCommand` | `PNPM='corepack pnpm' bash scripts/check.sh` | the website quality script: checks Node 24 and pnpm 12.3.4 (printed in the build log), then typegen, typecheck, every unit test and `next build` |
| `ignoreCommand` | `bash scripts/vercel-ignore-build.sh` | skips firmware-only changes (below) |
| `framework` | `nextjs` | no output directory override: Next's framework output handling stays in charge |

`lib/deployment.test.ts` checks these values.

## Firmware-only changes are skipped

Vercel runs the ignored-build command in the Root Directory of its depth-10
clone, with `VERCEL_GIT_COMMIT_SHA` (the commit being deployed) and
`VERCEL_GIT_PREVIOUS_SHA` (the last successful deployment of that branch,
empty on the branch's first deployment). The script resolves the Git root and
diffs the two commits restricted to `website/`:

- exit 0, **skip**: both commits are present and valid, they differ, and
  nothing under `website/` changed. Vercel stops the build and records the
  deployment with state **CANCELED** (its "Ignored Build Step" outcome; it is
  not a failure, and the previous deployment keeps serving).
- exit 1, **build**: any addition, modification, deletion or rename under
  `website/` (into, out of or within it); a first deployment; an empty,
  malformed or missing commit id (for example older than the depth-10 clone);
  any comparison error; a redeploy of the same commit; or
  `WEBSITE_FORCE_BUILD=1` (or `true`).

Since W08 a change to `release/version.txt` also builds: the page's JSON-LD names that version.

The diff is from the last successful deployment, not from the previous commit:
a website commit followed by a firmware-only commit still builds if the website
commit was never deployed. `lib/vercel-ignore-build.test.ts` runs the real
script against throwaway repositories for each case, including a depth-10 clone.

To force a build of a firmware-only commit: set `WEBSITE_FORCE_BUILD=1` as a
project environment variable for that one deployment (and remove it after),
or for a CLI deployment pass `--build-env WEBSITE_FORCE_BUILD=1`.

## CLI deployments

Run the CLI from the repository root (the project Root Directory is `website`),
from a clean checkout of the exact revision, so no uncommitted file ships:

```sh
git worktree add --detach <dir> <accepted-commit>
cd <dir> && vercel link --project m5-guardian --scope flowcoders
vercel deploy            # preview; production goes through promotion below
```

`.vercel/` is git-ignored. The root `.vercelignore` limits the upload to
`website/` plus the few repository files the quality script's unit tests read
(the documentation the page cites, notices, licenses and gate files);
`lib/deployment.test.ts` simulates the upload with the CLI's default ignore list
and checks that `website/package.json` is the only `package.json` uploaded. A
CLI upload carries no `.git`, so the ignored-build script always builds there.

## Checks before production

On the preview deployment of the accepted revision (`<preview-url>` below is the
unique deployment URL; `<bypass>` is the Protection Bypass for Automation
secret, given through the environment and never printed):

```sh
cd website
WEBSITE_URL=<preview-url> WEBSITE_BYPASS=<bypass> pnpm exec playwright test
LIGHTHOUSE_URL=<preview-url> LIGHTHOUSE_BYPASS=<bypass> LIGHTHOUSE_PREVIEW=1 node scripts/lighthouse.mjs
```

- The browser suite covers metadata, assets, the 404 page, all four simulated
  states, the mobile navigation, delayed 3D loading (no viewer script or model
  before activation, recognised by script content on a deployment), rotation,
  screen mapping, WebGL fallback and every GitHub link on the page (with its
  README section).
- Lighthouse: three mobile runs, medians against the ledger thresholds. On a
  preview, `LIGHTHOUSE_PREVIEW=1` drops only the is-crawlable audit from SEO
  when its sole blocking directive is Vercel's `x-robots-tag: noindex` preview
  header. CI repeats this gate on every successful Preview deployment
  (`.github/workflows/website-preview-lighthouse.yml`, which needs the GitHub
  Actions secret `VERCEL_AUTOMATION_BYPASS_SECRET`).

After promotion, on production (no bypass, no preview mode; SEO must reach
0.95 with is-crawlable included):

```sh
WEBSITE_URL=https://m5-guardian.vercel.app pnpm exec playwright test
LIGHTHOUSE_URL=https://m5-guardian.vercel.app node scripts/lighthouse.mjs
```

Keep run outputs outside the tree (`BROWSER_CHECK_OUT`, `LIGHTHOUSE_OUT`).

## Install page (W07)

`/install` flashes the signed release onto a visitor's own StickS3 (Web Serial, esptool-js 0.7.0 loaded only
after a click). What a deployment needs:

- **The routes** `/api/firmware/latest` and `/api/firmware/[tag]/[file]` run on Node and read the GitHub
  Releases of `fcavalcantirj/m5-guardian` (no token: a public repository). Before the first signed release
  (G26, owner-run `tools/release_publish.sh --publish`) `/api/firmware/latest` answers 404
  `{"kind":"no-release"}` and the page says so; Update and First install stay disabled, Restore works.
  The release key is `lib/release-key.ts` (a copy of `release/release-public-key.json`, compared by
  `lib/firmware-release.test.ts`); a new release key needs a new website deployment.
- **Step counts** use Vercel Web Analytics (`@vercel/analytics`, cookieless), mounted once in the root layout
  since W08 (page views on every page) and only in a Vercel build (`process.env.VERCEL === "1"` at build
  time: the pages are prerendered). Enable Web Analytics in the project settings, or every page requests a missing
  `/_vercel/insights/script.js`. The event is `guardian_install` with three properties,
  `action` (update, install, restore, backup), `result` (start, connected, done, cancel, error_plan,
  error_<step>) and `step` = `<action>:<result>` (since 2026-11-24; the query API groups by one property at
  a time, so `step` gives every combination in one count); nothing about the device.
- **Reading the numbers**: `tools/site_stats.sh [days]` (repository root, read-only, Vercel CLI logged in,
  `.vercel/project.json` from `vercel link`) prints visitors, page views, pages, referrers, countries,
  devices and the install counts by `step` (e.g. `update:done`, `install:done`, `restore:done`,
  `install:error_writing`). The query API counts whole UTC days. Counts are browser-side: a visitor who
  blocks the analytics script is not counted.
- **Live check after the first release**: `curl -s <url>/api/firmware/latest` names the published tag, and a
  part URL from it answers 200 with `X-Content-SHA256` equal to the manifest. Flashing a real stick is the
  owner-run smoke: `STICK_SMOKE=1 STICK_SMOKE_OUT=<store folder> STICK_FOREIGN_IMAGE=<8 MB non-Guardian image>
  STICK_SMOKE_URL=<url> pnpm run test:stick` (headed Chrome; never in CI).

## Search, share cards and Content-Security-Policy (W08)

- **Share cards.** Each page has its own Open Graph and Twitter image (1200x630 PNG): `app/opengraph-image.tsx`
  and `app/twitter-image.tsx` for `/`, `app/install/opengraph-image.tsx` and `app/install/twitter-image.tsx`
  for `/install` (text only, the site's colours, no artwork). `/install` sets its own `twitter` title and
  description, so a shared install link no longer shows the home page's text.
- **Structured data.** The root layout renders one JSON-LD block: schema.org `WebSite` and
  `SoftwareApplication` (no ratings or reviews). `softwareVersion` is `version=` of `release/version.txt`, read
  by `next.config.mjs` when the build starts; a missing or malformed file fails the build. **The upload must
  therefore carry `release/version.txt`**: the root `.vercelignore` needs `!/release`, `/release/*`,
  `!/release/version.txt`, and `.github/workflows/website-checks.yml` should list `release/version.txt` in both
  trigger lists (outside the website folder: applied by the supervisor; until then a Vercel build stops at
  `release/version.txt cannot be read`).
- **Icons.** `app/favicon.ico` (16, 32, 48 px) and `app/apple-icon.png` (180 px) are generated from
  `app/icon.svg` by `node scripts/icons.mjs` (resvg through `next/og`, byte-reproducible). Edit the SVG, then
  rerun the script; `lib/icons.test.ts` fails on stale icons.
- **Sitemap `lastmod`** is the commit date of the newest commit touching each page's sources
  (`lib/last-modified.ts`), read at build time. A Git deployment has the history (Vercel clones 10 commits
  deep; a page last changed before that has no `lastmod` rather than a wrong one). A CLI deployment uploads no
  `.git`, so its sitemap has no `lastmod`.

### Content-Security-Policy

A static header set in `next.config.mjs` for every path (built by `lib/csp.ts`), so `/`, `/install` and the
404 page stay prerendered and edge-cached. The W08 worker first built a per-request nonce (`proxy.ts`, pages
rendered per request); measured on its preview on 2026-11-24 from Brazil, interleaved with production, the
first byte took ~0.67 s instead of ~0.35 s (one cold start 1.9 s; the function runs in iad1, the edge in
gru1), while the Lighthouse gate on the US GitHub runner could not see it. The site takes no user input and
loads no third-party script, so the nonce bought little; the supervisor replaced it with `'unsafe-inline'` for
scripts (Next's inline bootstrap changes with every build, so a fixed hash list cannot cover it).

Measured before enforcing (2026-11-24, local production build, Chromium 1.65.1 via Playwright, a strict
Report-Only policy without inline allowances; `/` loaded, scrolled and switched to 3D, `/install` with a mocked
release and a fake serial port clicked through to the port error): `/` 3 inline scripts and 21 `style`
attributes, `/install` 3 inline scripts; nothing else (esptool-js, spark-md5, the 3D viewer chunks and STL
models, fonts, images and the firmware API are all same-origin).

The enforced production policy and why each source is there:

| Directive | Sources | Why |
| --- | --- | --- |
| `default-src` | `'self'` | everything not named below: same origin only |
| `script-src` | `'self'` `'unsafe-inline'` | Next chunks, the 3D viewer, esptool-js and spark-md5 (dynamic imports of same-origin chunks) and the Vercel Web Analytics script `/_vercel/insights/script.js` are same-origin; `'unsafe-inline'` covers Next's inline bootstrap (see above). No other host, no `'unsafe-eval'` (added only under `next dev`, for React's error overlay) |
| `style-src` | `'self'` `'unsafe-inline'` | the CSS files, and the `style` attributes React renders into the HTML (21 on `/`); a nonce would not cover attributes |
| `img-src` | `'self'` | persona art, icons and Next's image route |
| `font-src` | `'self'` | the self-hosted Geist fonts |
| `connect-src` | `'self'` | `/api/firmware/*` (release manifest and parts), the STL models, and `/_vercel/insights/*` (analytics events) |
| `object-src` | `'none'` | no plugins |
| `base-uri` | `'self'` | no foreign `<base>` |
| `form-action` | `'self'` | the site has no forms |
| `frame-ancestors` | `'none'` | the site is never framed |

Not needed, so not listed: `data:` and `blob:` (the backup download is a `blob:` URL opened as a download
link, which `img-src`/`connect-src` do not govern), `worker-src`, `frame-src` and any other host.

On a **Vercel preview** (`VERCEL_ENV=preview`) the policy adds the sources Vercel documents for its toolbar
and comments (<https://vercel.com/docs/vercel-toolbar/managing-toolbar>): `script-src https://vercel.live`,
`connect-src https://vercel.live wss://ws-us3.pusher.com`, `img-src https://vercel.live https://vercel.com
data: blob:`, `frame-src https://vercel.live`, `style-src https://vercel.live`, `font-src https://vercel.live
https://assets.vercel.com`. Production carries none of them; if the toolbar is enabled for production
deployments it is blocked there (turn it off for production in the project settings).

**Report-Only trial:** set `GUARDIAN_CSP_REPORT_ONLY=1` as a build environment variable of a preview deployment and
the same policy is sent as `Content-Security-Policy-Report-Only`; the browser console then lists what it would
block. Remove the variable to enforce. The browser suite fails on any violation, enforced or report-only
(`e2e/fixtures.ts`), and checks the header and that the pages stay prerendered (`e2e/metadata.spec.ts`).

## Promotion and rollback

Promote the checked preview: `vercel promote <preview-url> --scope flowcoders`
(or "Promote to Production" on that deployment). Vercel documents that promoting
a preview "triggers a complete rebuild with production environment variables"
from the same source, so the production deployment is a new build of the
accepted commit: run the production checks against it, then confirm it is Ready
and that `m5-guardian.vercel.app` points at it
(`vercel inspect https://m5-guardian.vercel.app --scope flowcoders`). If the
ignored-build script runs for that rebuild, the same commit or a website change
builds; a skip would mean production already serves the same website files.

Rollback: `vercel rollback <previous-production-deployment> --scope flowcoders`
(or Instant Rollback in the dashboard); no rebuild. Per Vercel's documentation,
after a rollback "new pushes to your production branch won't replace the
rolled-back deployment" until a deployment is promoted again (`vercel promote`
re-enables auto-assignment), and the Hobby plan can roll back only to the
immediately previous production deployment. Rollback does not change Git: fix
forward with a new commit, check its preview, then promote.

## Live record

Filled by the supervisor after the live checks (W06):

| Item | Value |
| --- | --- |
| Accepted revision | _pending (set at acceptance)_ |
| Preview deployment (unique URL / id) | m5-guardian-jp3n2f3ak (Git push of branch w06-preview-check, 94f9ecf): Ready; the first Git preview (j974sntxc) failed on the claim check after G26 changed the README, which is the check working |
| Production deployment (id) | m5-guardian-juh1pewek (CLI, clean export of 07a480f, 2026-11-23) |
| Production alias verified | https://m5-guardian.vercel.app: page 200, robots/sitemap/icon/OG/models/images 200, unknown path 404, no x-robots-tag, canonical correct; Lighthouse SEO/accessibility/best practices 1.0, LCP 2.28-2.47 s (TBT varies with host load) |
| Firmware-only commit, deployment state | _pending_ (expected: CANCELED by the ignored build step) |
