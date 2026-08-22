# DFIR Companion — Evidence Capture & Push (extension)

MV3 extension that captures the active tab (timer + events) and sends to the companion, and
one-click pushes structured artifacts straight from DFIR consoles (Splunk / Velociraptor / Elastic /
CrowdStrike) into the case timeline.

It installs with **zero website access**. Open a console, click the extension, and approve that
exact origin before enabling ongoing capture or the in-page Push integration. **Capture this tab
once** uses temporary `activeTab` access and does not retain site permission.

## Install — Chrome Web Store

Listed publication is set up via CI (see [Publishing](#publishing-chrome-web-store)); once the
listing is live, install it from the Chrome Web Store for one-click setup and automatic updates.
Until then (and for development), use the unpacked load below. Firefox has no AMO listing yet, so
there it is always a temporary add-on — but you no longer have to build it: every release attaches
`dfir-capture-extension-firefox-<tag>.zip` (see [Releases](https://github.com/hasamba/DFIR-Companion/releases/latest)).

## Build & load (development / unpacked)

    cd extension && npm install

**Chrome / Comet**

    npm run build

`chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the
`extension/dist` **folder**.

**Firefox 140+**

    npm run build:firefox

`about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…** → select
`extension/dist-firefox/manifest.json` — the manifest **file**, not the folder Chrome asks for.

Not developing? Unzip `dfir-capture-extension-firefox-<tag>.zip` from the
[latest release](https://github.com/hasamba/DFIR-Companion/releases/latest) and point the same
**Load Temporary Add-on…** dialog at the `manifest.json` inside it — the archive holds exactly what
`npm run build:firefox` emits. It is unsigned either way, so it is still a temporary load, not a
permanent install; that needs the AMO listing below.

> Firefox removes a temporary add-on when the browser restarts, so repeat the load each session.
> That is how unsigned local add-ons work, not something this one does; a signed AMO build would
> install permanently. Captures are unaffected either way — evidence is POSTed to the companion,
> never held in the browser.

Both targets emit the same bundles from the same sources; only the manifest differs. There is no
`manifest-firefox.json` on disk — [`scripts/manifest-firefox.mjs`](./scripts/manifest-firefox.mjs)
derives it from `manifest.json` at build time, so every shared field has one source (#300). Firefox
128 is the floor because it is where `scripting.executeScript` gained `world: "MAIN"`, which the
API-interception hook below depends on; on anything older the hook installs into the isolated world
and silently captures nothing (#298).

## Test
    npm test

Verified end-to-end against the companion: live capture, offline queue/sync, dashboard live updates, and report generation.

## Keyboard shortcut

`Ctrl+Shift+S` (macOS `Cmd+Shift+S`) toggles ongoing capture on/off. Ongoing capture fails closed on
an origin that has not been approved: open the popup on that console once and choose **Allow this
site**. Rebind the shortcut at `chrome://extensions/shortcuts` (or via the **rebind** link in the
popup). If the default key conflicts with another extension at install time, Chrome leaves it unset
until you assign one there.

## Site access

1. Open the Velociraptor, Splunk, Kibana, or other web console you want to use.
2. Click the DFIR Companion extension icon.
3. Click **Allow this site** and approve the browser's exact-origin prompt.
4. Select a case. Use **Start** for ongoing capture, **Capture this tab once** for a temporary
   screenshot, or the console's floating Push button for structured rows.

The popup always says whether the current origin is connected. **Review permissions and audit log**
lists every granted origin with a Revoke button and the latest 100 local grant/denial/revocation
records. Revocation disables the integration immediately. Browser/private pages, `file:`/`data:`
pages, and private browsing are refused.

## Automated artifact fetching (#102)

On an approved, recognized DFIR console the content script activates a **site adapter** and injects a floating
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
extension does nothing extra. No content script is injected at all until the origin is approved.

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
and submit for review. Host access is optional and requested one origin at a time, so the install
does not carry an all-sites warning. After that, tagged releases publish new versions automatically.

### Managed enterprise origins (Chrome)

Administrators can use Chrome's `ExtensionSettings` policy to force-install/pin the extension and
set `runtime_blocked_hosts` to `*://*`, with only the organization's approved console origins in
`runtime_allowed_hosts`. This browser policy is a hard ceiling: it does not let the extension work
around an analyst denial, and no origin outside the managed allow-list can be granted. Use exact
origins such as `https://velociraptor.example` rather than a broad wildcard. The Extension options
page reflects the permissions the browser has actually granted.

## Publishing (Firefox / AMO)

Not submitted to AMO yet, but the build is packaged: `release-artifacts.yml`'s **`extension-zip`**
job now builds both targets and attaches `dfir-capture-extension-firefox-<tag>.zip` — zipped from
inside `dist-firefox/`, so `manifest.json` sits at the archive root — alongside the Chrome zip on
every `v*` tag (#366). The job's `sha256` output stays the *Chrome* zip's, because the Chocolatey
package downloads and verifies that specific asset.

What is still missing is the listing itself: AMO upload/publish needs API credentials and a first
manual submission, exactly as the Chrome listing did. Until then the release zip is an unsigned
temporary add-on, not a permanent install.

Two values in [`scripts/manifest-firefox.mjs`](./scripts/manifest-firefox.mjs) are already settled
and should not be changed casually:

- **`GECKO_ID`** (`dfir-companion@hasamba.github.io`) — the add-on's permanent identity, decided
  before the first submission on purpose (#301). AMO ties updates to it and `storage.local` is
  scoped to it, so changing it after publication ships what Firefox treats as a *different* add-on:
  existing installs stop receiving updates, and every analyst's saved settings (companion URL,
  active case, dragged button position) are orphaned. `tests/firefox.test.ts` fails if it is ever
  set back to a reserved documentation domain.
- **`MIN_FIREFOX_VERSION`** (`140.0`) — two floors in one number. 128 is where
  `scripting.executeScript` gained `world: "MAIN"`; below it, capture fails silently. 140 is where
  Firefox reads `data_collection_permissions` and shows the consent screen it drives; below it, the
  add-on would collect what it declares while the install prompt said nothing, which is not one of
  the three ways Mozilla permits shipping to older releases. Lowering it breaks one or the other.
- **`DATA_COLLECTION_PERMISSIONS`** (`browsingActivity`, `websiteContent`) — mandatory in every AMO
  submission since 2025-11-03; without it the upload is rejected outright. It is not `none` because
  Mozilla counts any hand-off outside the browser as collection, and a capture POSTs the tab URL,
  its title and a screenshot to the companion process. There is deliberately no `gecko_android`
  key: any value there — `{}` included — would publish this desktop tool to Firefox for Android.
