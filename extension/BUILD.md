# Build instructions for reviewers

AMO requires the human-readable source with every submission, because the shipped bundles are
minified and a reviewer cannot read them. This file travels at the root of that source archive,
which `release-artifacts.yml` builds with `git archive HEAD:extension` and uploads alongside the
package — so what you are reading is the same text a Mozilla reviewer sees.

The archive is the complete, unmodified source of the **DFIR Companion — Evidence Capture &
Push** add-on, taken straight from the project's public repository:

    https://github.com/hasamba/DFIR-Companion   (directory: extension/)

Nothing in it is transpiled, concatenated, minified, or machine-generated.

## Build environment

| Requirement | Version |
|---|---|
| Node.js | 22.x (the project's CI builds on Node 22; 20.x also works) |
| npm | 10 or later (ships with Node 22) |
| Operating system | Any — Linux, macOS, or Windows. No platform-specific steps. |

Install Node from https://nodejs.org/ or via nvm: `nvm install 22 && nvm use 22`.

No network access is needed beyond `npm ci`, and the build itself is offline.

## Steps

Run these from the root of this archive — the directory holding `package.json`:

    npm ci
    npm run build:firefox

`npm run build:firefox` is the single build script that performs every technical step. It is
defined in `package.json` and implemented in `scripts/build-firefox.mjs`.

## Output, and how to compare it with the uploaded package

The build writes `dist-firefox/`. That directory's contents are exactly what was submitted.

To rebuild the uploaded archive, zip the CONTENTS of `dist-firefox/` — `manifest.json` must sit
at the archive root, not inside a folder:

    cd dist-firefox && zip -r ../reproduced.zip .

This was verified before submission: a clean `npm ci && npm run build:firefox` from this archive
produced a `dist-firefox/` identical to the uploaded package under `diff -r`.

## What the build does

`scripts/build-extension.mjs` runs Vite three times, deliberately, rather than once:

1. `src/content.ts` -> `content.js` (the content script)
2. `src/pageHook.ts` -> `pageHook.js` (injected into the MAIN world)
3. `src/serviceWorker.ts`, `src/popup.ts`, `src/options.ts` and their shared modules

They are separate invocations so no chunk is shared between an entry point that must be a
classic script and one that may be a module. The build asserts this and fails loudly if a
future change breaks it.

## The Firefox manifest is generated — this is intentional

There is no `manifest-firefox.json` in this archive, and its absence is by design.

`manifest.json` here is the Chrome manifest. `scripts/manifest-firefox.mjs` derives the Firefox
manifest from it at build time, changing exactly three keys:

* `browser_specific_settings` — the add-on ID, `strict_min_version: "140.0"`, and
  `data_collection_permissions`.
* `background` — Firefox has no MV3 service worker, so `service_worker` becomes
  `scripts: [...]` (an event page). Same bundle either way.
* `incognito` — set to `not_allowed`, so the add-on is invisible to private windows.

A second hand-maintained manifest would carry its own `version` field and drift out of sync with
the release process, which reads the version from `manifest.json` only. Generating means every
shared field has exactly one source. `tests/firefox.test.ts` asserts that the transform changes
those three keys and nothing else.

Deliberately absent: `gecko_android`. Per MDN, an extension is offered on Firefox for Android
only when that key is present — even as `{}`. This is a desktop analyst tool, so the key is
omitted rather than added to silence a linter warning.

## Running the test suite (optional)

    npm test        # 245 tests
    npm run typecheck

## What the add-on talks to

The add-on communicates with **one** address: the DFIR Companion server the analyst configures,
which defaults to `http://127.0.0.1:4773` — a localhost server the analyst runs themselves. See
`src/companionClient.ts`; those are the only outbound requests in the codebase, alongside two
`/health` and `/cases` reads from the same configured address in `src/popup.ts`.

To exercise the add-on you need that server running. It is free and open source (AGPL-3.0-only),
in the same repository under `companion/`:

    git clone https://github.com/hasamba/DFIR-Companion
    cd DFIR-Companion/companion && npm ci && npm run dev

It then listens on http://127.0.0.1:4773 with a dashboard at /dashboard.

Host permissions are **optional** and granted one origin at a time by the analyst at runtime; a
fresh install has access to no website at all. `PRIVACY.md` in this archive documents what is
collected and where it goes.
