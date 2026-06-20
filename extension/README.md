# DFIR Companion — Evidence Capture & Push (extension)

MV3 extension that captures the active tab (timer + events) and sends to the companion, and
one-click pushes structured artifacts straight from DFIR consoles (Splunk / Velociraptor / Elastic /
CrowdStrike) into the case timeline.

## Install — Chrome Web Store

Listed publication is set up via CI (see [Publishing](#publishing-chrome-web-store)); once the
listing is live, install it from the Chrome Web Store for one-click setup and automatic updates.
Until then (and for development), use the unpacked load below.

## Build & load (development / unpacked)
    cd extension && npm install && npm run build
Load `extension/dist` as an unpacked extension in Comet/Chrome.

## Test
    npm test

Verified end-to-end against the companion: live capture, offline queue/sync, dashboard live updates, and report generation.

## Keyboard shortcut

`Ctrl+Shift+S` (macOS `Cmd+Shift+S`) toggles capture on/off without opening the popup — turning it on takes one capture immediately and the toolbar badge flashes `REC`/`off`. Rebind it at `chrome://extensions/shortcuts` (or via the **rebind** link in the popup). If the default key conflicts with another extension at install time, Chrome leaves it unset until you assign one there.

## Automated artifact fetching (#102)

On a recognized DFIR console the content script activates a **site adapter** and injects a floating
**📤 Push … → DFIR-Companion** button (bottom-right by default). It only sends when *you* click it —
explicit analyst intent, nothing automatic. **Drag the button** anywhere if a site's own UI covers
it; the position is remembered across pages/tabs and always kept on-screen.

Supported tools (matched by host / path / port — self-hosted instances on any host work):

| Adapter | Recognizes | Capture |
|---|---|---|
| **Splunk** | `*splunk*` host, `/<locale>/app/…`, `:8000` | search-job `…/results` JSON (`output_mode=json`/`json_rows`) |
| **Velociraptor** | `*velociraptor*` host, `/app/index.html`, `:8889` | `/api/v1/GetTable` columns+rows |
| **Elastic / Kibana** | `*kibana*`/`*elastic*` host, `/app/discover…`, `:5601`/`:9200` | `_search` / Kibana `bsearch` `hits.hits[]._source` |
| **CrowdStrike Falcon** | `*crowdstrike*`/`*falcon*` host | API `resources[]` / `events[]` |

**How it grabs the data** (two paths, in order):
1. **API interception** — a tiny MAIN-world hook (`pageHook.js`, injected only on recognized tools)
   wraps `fetch`/`XMLHttpRequest` and keeps a copy of the clean JSON the console already fetched for
   the table you're looking at. The hook is transparent (original responses are untouched) and the
   data stays in the page until you click Push.
2. **DOM table scrape** — if nothing was intercepted (no clean JSON API), clicking Push parses the
   visible results `<table>` into rows.

On click the rows are POSTed to the companion's unified import route
(`POST /cases/:id/import`) for the **case currently selected in the popup** — the same case used for
screenshot capture. The server auto-detects the format and routes it into the timeline + IOCs. The
button shows the result (`✓ Pushed N rows to "<case>"` or the error). On an unrecognized site the
extension does nothing extra — plain screenshot capture is unaffected.

> Pick a case in the popup first (the artifact push uses it). The push reuses the localhost,
> unauthenticated import path — no token needed (unlike the server's external `/push` webhook).

## Capture interval note

The periodic capture timer is implemented with `chrome.alarms`, which clamps `periodInMinutes` to a minimum of roughly 1 minute for packed/published extensions — so sub-minute intervals (e.g. 5 s) will only fire at that cadence in unpacked/dev loads. Event-based triggers (tab switch, navigation, and manual capture) are not subject to this floor and fire immediately regardless of the alarm schedule.

## Publishing (Chrome Web Store)

Privacy policy: [`PRIVACY.md`](./PRIVACY.md) — the Extension sends data only to your local
companion (`127.0.0.1:4773`); no third-party calls. Use its raw GitHub URL as the listing's
required privacy-policy link.

Store icons live in [`icons/`](./icons) (16/32/48/128, derived from the Companion logo) and are
wired into `manifest.json` (`icons` + `action.default_icon`); the build copies them into `dist/`.
The toolbar icon is still drawn at runtime in `actionIcon.ts` — these statics are what Chrome and
the store listing use.

CI (`.github/workflows/release-artifacts.yml`, job **`chrome-webstore`**) uploads and **publishes**
the built zip on every `v*` tag. It no-ops until these repo secrets are set, so the developer
account can be created independently of merging:

- `CHROME_EXTENSION_ID` — the item ID from the Web Store dashboard (after the first manual upload)
- `CHROME_CLIENT_ID`, `CHROME_CLIENT_SECRET`, `CHROME_REFRESH_TOKEN` — Chrome Web Store API OAuth2
  credentials (Google Cloud project + a one-time refresh-token exchange)

**One-time human steps** (CI can't do these): create the $5 Chrome developer account, do the first
upload + fill the listing (name/description/icon/screenshots/privacy policy) + data-use disclosures,
and submit for review. With `<all_urls>` host access, expect a manual review (days) on first
submission. After that, tagged releases publish new versions automatically.
