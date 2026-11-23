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
| Accepted revision | _pending_ |
| Preview deployment (unique URL / id) | _pending_ |
| Production deployment (id) | _pending_ |
| Production alias verified | _pending_ |
| Firmware-only commit, deployment state | _pending_ (expected: CANCELED by the ignored build step) |
