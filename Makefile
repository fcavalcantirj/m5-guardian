# Website quality gates (the firmware builds with ESP-IDF, not make).
#   make website-check            frozen install, then typegen, typecheck, unit tests and production build
#   make website-browser-check    browser suite and three mobile Lighthouse runs on the production build
# Override PNPM to point at a specific pnpm 12.3.4 binary.

PNPM ?= pnpm

.PHONY: website-check website-browser-check

website-check:
	cd website && $(PNPM) install --frozen-lockfile
	PNPM="$(PNPM)" website/scripts/check.sh

website-browser-check:
	cd website && $(PNPM) exec playwright test
	cd website && node scripts/lighthouse.mjs
