# Privacy Policy — DFIR Companion: Evidence Capture & Push

_Last updated: 2026-06-20_

This is the privacy policy for the **DFIR Companion — Evidence Capture & Push** browser
extension (the "Extension"), published for Chrome and other Chromium browsers. It is part of
the open-source [DFIR Companion](https://github.com/hasamba/DFIR-Companion) project and is
licensed AGPL-3.0-only.

## Summary

**The Extension sends data only to a DFIR Companion server running on your own machine
(`http://127.0.0.1:4773` by default, a `localhost` address). It makes no calls to the
extension authors, to any analytics service, or to any other third party. There is no
tracking, no telemetry, and no remote logging.**

You — the analyst — are always in control of what is sent and when.

## What the Extension does

The Extension supports a forensic investigation workflow in two ways:

1. **Screenshot evidence capture.** It captures screenshots of the **active browser tab** —
   on a periodic timer, on navigation/tab-switch events, or on demand (toolbar button or the
   `Ctrl+Shift+S` shortcut) — and submits them as evidence to your local DFIR Companion.

2. **Detection / artifact push from DFIR consoles.** When you are viewing a recognized
   security tool's web console (for example **Splunk**, **Velociraptor**, **Elastic/Kibana**,
   or **CrowdStrike Falcon**), the Extension can extract the **structured results you are
   looking at** (the JSON the console already fetched, or the visible results table) and push
   those rows to your local DFIR Companion when you click the **"📤 Push → DFIR-Companion"**
   button. This step only ever runs on your explicit click — nothing is sent automatically
   from these pages.

## What data is handled

- **Screenshots** of the active tab (image data).
- **Structured detection data** scraped from recognized DFIR consoles when you click Push
  (e.g. alert/event rows, hostnames, hashes, IP addresses contained in those results).
- **Extension settings and an offline send-queue**, stored locally via `chrome.storage`
  (e.g. the selected case, capture interval, the companion server URL, and any captures that
  could not be delivered yet because the companion was unreachable).

## Where the data goes

- All captured screenshots and pushed detections are transmitted **only** to the DFIR
  Companion server address you configure — by default `http://127.0.0.1:4773`, i.e. a server
  on your own computer. No data leaves your machine via the Extension.
- The Extension contains **no third-party SDKs, analytics, advertising, or crash/usage
  reporting.** It does not sell or share data with anyone, and the developers receive no
  data from it.
- Settings and the offline queue stay in your browser's local extension storage and are
  never uploaded anywhere except your own companion.

## Permissions and why they are needed

| Permission | Why |
|---|---|
| `activeTab` | Read/capture the tab you are currently viewing so it can be saved as evidence. |
| `tabs` | Identify the active tab and react to tab switches for event-driven capture. |
| `webNavigation` | Capture on page navigations (so the timeline reflects what you browsed). |
| `scripting` | Inject the small content script / page hook that powers the Push button and reads the console results you are viewing. |
| `storage` | Persist your settings and hold the offline send-queue locally. |
| `alarms` | Drive the optional periodic-capture timer. |
| `host_permissions: <all_urls>` | Evidence capture and the DFIR-console Push feature must work on any site or self-hosted console (security tools run on arbitrary hosts/ports), so the Extension needs access to all sites. It still only **sends** data to your local companion, and the Push feature only acts when you click it. |

## Data retention

The Extension itself does not retain forensic data beyond the local send-queue needed to
deliver captures to your companion. Once delivered, evidence is stored and managed by **your**
DFIR Companion server, under your control. Clearing the Extension's storage (or removing the
Extension) clears its settings and any undelivered queued captures.

## Children's privacy

The Extension is a professional incident-response tool and is not directed at children.

## Changes to this policy

Material changes will be reflected in this file in the project repository and dated above.

## Contact

Questions about this policy or the Extension can be raised as an issue in the project's
GitHub repository.
