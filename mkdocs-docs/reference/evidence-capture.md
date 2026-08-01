# Evidence Capture (Browser Extension)

## How It Works

The extension captures a screenshot of the current browser tab and sends it to the Companion. The
server saves the image before doing anything else — evidence is always persisted first, before any
AI analysis.

A fresh installation has no access to websites. On the console you want to use, click the extension
icon and **Allow this site**. The browser prompt names that exact origin. Access remains limited to
that origin until you revoke it from the popup, the Extension options page, or the browser's own
extension controls.

## Capture Modes

| Method | How |
|--------|-----|
| **One-off screenshot** | Click the extension icon → select case → **Capture this tab once**. Uses temporary tab access; no site grant is retained. |
| **Ongoing screenshots** | Approve the console origin → select case → **Start**. Timer/navigation/tab-switch capture is limited to approved origins. |
| **Hotkey** | `Ctrl+Shift+S` toggles ongoing capture; an unapproved site fails closed and tells you to use the popup. |
| **Floating push button** | Injected only into an approved, recognised DFIR console; a click sends the current rows. |

Browser-internal pages, local files, data URLs, and private/incognito tabs cannot be captured.

## Recognised Consoles (One-Click Push)

After origin approval, the extension can inject a push button into:

- **Security Onion** (Alerts, Hunt, Dashboards)
- **SO-CRATES** (network/file events, Sigma detections)
- **Elasticsearch/Kibana** (standard and modern async-search)

Velociraptor, Splunk, Kibana/Elastic, CrowdStrike, VolWeb, and other supported/self-hosted consoles
are recognized by their URL or page signature. A custom origin still requires the same explicit
**Allow this site** action.

## What Page Data Is Used

On an approved console, the extension reads the page URL/title, tool-identifying page markers, the
visible table when you click Push, and API responses matching that console adapter. Matching rows
stay in page memory and are transmitted only after you click Push. Screenshots are sent only when a
capture action or enabled capture trigger fires. Nothing is sent to the extension authors or an
analytics service.

The options page shows approved origins and a local log of the latest 100 grants, denials, and
revocations. Revoking an origin removes the Push button, disables the page hook, and blocks late
messages from that page.

## Screenshot OCR Full-Text Search

Every screenshot is OCR'd locally in the background after capture using Tesseract — no AI, nothing leaves the machine. You can search the text content of all screenshots using the **🔍 Screenshot text** box in the dashboard filter bar.

Results link back to the original screenshot. This is useful when you remember seeing a hostname, hash, or error message but can not find where.

!!! tip "Backfill OCR for older cases"
    ```bash
    npm run ocr-index -- <caseId>
    ```
    Opt out entirely by setting `DFIR_OCR_SEARCH=off` in `.env`.
