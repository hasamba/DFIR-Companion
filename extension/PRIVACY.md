# Privacy Policy — DFIR Companion: Evidence Capture & Push

_Last updated: 2026-08-22_

This is the privacy policy for the **DFIR Companion — Evidence Capture & Push** browser
extension (the "Extension"), published for Firefox, Chrome, and other Chromium browsers. It is
part of the open-source [DFIR Companion](https://github.com/hasamba/DFIR-Companion) project and
is licensed AGPL-3.0-only.

## Summary

**The Extension sends data to exactly one destination at a time: the DFIR Companion server
address you configure. By default that is `http://127.0.0.1:4773` — a server on your own
machine — and for a single analyst working locally, nothing the Extension handles ever leaves
the machine. If you point the Extension at a team Companion instead, captures go to that host,
because that is what you asked it to do. In either case it makes no calls to the extension
authors, to any analytics service, or to any other third party. There is no tracking, no
telemetry, and no remote logging.**

You — the analyst — are always in control of what is sent and when. A fresh installation has
**no access to any website**. Persistent access is granted one console origin at a time.

## What the Extension does

The Extension supports a forensic investigation workflow in two ways:

1. **Screenshot evidence capture.** A one-off capture uses temporary `activeTab` access after
   you click the Extension. Ongoing timer/navigation/tab-switch capture runs only on an origin
   you previously approved. Screenshots are submitted as evidence to your DFIR Companion.

2. **Detection / artifact push from approved DFIR consoles.** When you are viewing a recognized
   security tool's web console (for example **Splunk**, **Velociraptor**, **Elastic/Kibana**,
   or **CrowdStrike Falcon**), the Extension can extract the **structured results you are
   looking at** (the JSON the console already fetched, or the visible results table) and push
   those rows to the Companion you configured when you click the **"📤 Push → DFIR-Companion"**
   button. This step only ever runs on your explicit click — nothing is sent automatically
   from these pages.

3. **Right-click "Send to DFIR-Companion".** On a page where you invoke the menu, you can send a text
   selection, a table, or a link and choose "Send to DFIR-Companion" to push that selected
   text, the nearest table's rows, or the link's URL to that same Companion. Like the Push
   button above, this only ever runs when you explicitly choose it from the menu.

## What data is handled

- **Screenshots** of the active tab (image data).
- **Structured detection data** scraped from recognized DFIR consoles when you click Push
  (e.g. alert/event rows, hostnames, hashes, IP addresses contained in those results).
- **Text you explicitly send via the right-click menu** — a page's selected text, a table's
  rows, or a link's URL — only when you choose "Send to DFIR-Companion" from the menu.
- **Extension settings and an offline send-queue**, stored locally via `chrome.storage`
  (e.g. the selected case, capture interval, the companion server URL, and any captures that
  could not be delivered yet because the companion was unreachable).
- **Approved origins and a local permission audit.** The browser retains the origins you approve.
  The Extension retains the latest 100 grant, denial, and revocation records (time, action, and
  origin) in local extension storage so permission changes are visible.

## Where the data goes

- All captured screenshots and pushed detections are transmitted **only** to the DFIR
  Companion server address you configure. The default is `http://127.0.0.1:4773`, a server on
  your own computer, and on that default nothing the Extension handles leaves your machine.
- **The address is yours to change, and changing it changes where the evidence goes.** Team
  mode exists for exactly that: a Companion another person or machine can reach. Point the
  Extension at one — which is also what the optional team service token is for — and captures
  travel to that host over your network. The Extension does not restrict the address, so read
  it as the destination it is.
- The Extension contains **no third-party SDKs, analytics, advertising, or crash/usage
  reporting.** It does not sell or share data with anyone, and the developers receive no
  data from it.
- Your settings and the permission audit stay in the browser's extension storage and are
  never uploaded anywhere at all. The offline queue is stored there too; what leaves it are the
  queued captures themselves, delivered to the Companion you configured once it is reachable
  again.

## What the Extension declares it collects

The Extension declares two categories of data collection, in the words Mozilla requires:

- **Browsing activity** — a capture carries the tab's URL and title.
- **Website content** — the screenshot itself, and the rows a console Push scrapes.

Mozilla counts any hand-off outside the browser as collection — including one to a server on
your own computer — which is why these are declared rather than `none`. The declaration would
be required for the default loopback address alone; a team Companion on another host only makes
it plainer. Both categories describe what the Extension sends **to the Companion you
configured**, and nothing else. Nothing reaches the authors or any third party, and the
Extension declares no telemetry of any kind.

**When Firefox shows you this, and when it does not.** Firefox 140 and later display a
data-collection notice as you install a signed add-on — from Mozilla Add-ons, or from a signed
file. The Extension requires 140 for that reason: shipping the declaration to an older Firefox
would mean collecting what is described here behind a prompt that said nothing.

A **temporary** add-on is different. Loading an unsigned build through
`about:debugging` → "Load Temporary Add-on…" — the route the project's own install
instructions describe, because there is no Mozilla Add-ons listing yet — displays **no prompt at
all**. Firefox grants every permission silently and shows no data-collection notice. Until the
listing exists, this policy is the disclosure, which is why the install instructions repeat the
two categories above rather than leaving Firefox to state them.

## Permissions and why they are needed

| Permission | Why |
|---|---|
| `activeTab` | Temporarily capture the current tab after an explicit toolbar, menu, or shortcut action. |
| `webNavigation` | React to navigation on an already-approved origin. |
| `scripting` | Inject the Push button and console-result hook only after host access is granted. |
| `contextMenus` | Add the right-click "Send to DFIR-Companion" menu items (send selection / table / link). |
| `storage` | Persist your settings and hold the offline send-queue locally. |
| `alarms` | Drive the optional periodic-capture timer. |
| Optional `http://*/*` / `https://*/*` hosts | Lets the browser offer an exact-origin permission at runtime. The wildcard is never granted at install: approving `https://velo.example:8889` grants that origin only. |

The Extension refuses browser-internal pages, local `file:`/`data:` pages, and private/incognito
tabs. Firefox is marked `not_allowed` for private browsing; Chromium is excluded by default and the
Extension still refuses private tabs if a user later enables it there.

## What an approved console page exposes

On an approved origin, the content script reads the page URL/title, tool-identifying DOM markers,
the visible results table when you click Push, and only the API response bodies matching the active
DFIR-console adapter. Matching response rows stay in that page's memory until you click Push; they
are not uploaded automatically. Revoking the origin disables the page integration immediately,
clears the hook's match patterns, removes the Push button, and makes the service worker reject any
late message from that page.

## Data retention

The Extension itself does not retain forensic data beyond the local send-queue needed to
deliver captures to the Companion. Once delivered, evidence is stored and managed by that
DFIR Companion server, under the control of whoever runs it — you, on the default local
address; your team and its retention rules, if you pointed the Extension at a team Companion. Clearing the Extension's storage (or removing the
Extension) clears its settings, permission audit, and any undelivered queued captures. Approved
origins can be revoked from the popup, the Extension options page, or the browser's extension
permission controls.

## Children's privacy

The Extension is a professional incident-response tool and is not directed at children.

## Changes to this policy

Material changes will be reflected in this file in the project repository and dated above.

## Contact

Questions about this policy or the Extension can be raised as an issue in the project's
GitHub repository.
