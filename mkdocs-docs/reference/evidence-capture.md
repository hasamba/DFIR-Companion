# Evidence Capture (Browser Extension)

## How It Works

The extension captures a screenshot of the current browser tab and POSTs it to `POST /captures` on the Companion server. The server saves the image to `cases/<id>/screenshots/` before doing anything else — evidence is always persisted first, before any AI analysis.

## Capture Modes

| Method | How |
|--------|-----|
| **Hotkey** | `Ctrl+Shift+S` in any browser tab |
| **Extension popup** | Click the extension icon → select case → click Capture |
| **Floating push button** | Button injected into recognised DFIR consoles; single-click sends the current event/row |

## Recognised Consoles (One-Click Push)

The extension automatically injects a push button into:

- **Security Onion** (Alerts, Hunt, Dashboards)
- **SO-CRATES** (network/file events, Sigma detections)
- **Elasticsearch/Kibana** (standard and modern async-search)

For any other browser-based tool (Velociraptor, Splunk, a custom SIEM, etc.), use `Ctrl+Shift+S` to enable capture mode and click the floating Push chip.

## Screenshot OCR Full-Text Search

Every screenshot is OCR'd locally in the background after capture using Tesseract — no AI, nothing leaves the machine. You can search the text content of all screenshots using the **🔍 Screenshot text** box in the dashboard filter bar.

Results link back to the original screenshot. This is useful when you remember seeing a hostname, hash, or error message but can not find where.

!!! tip "Backfill OCR for older cases"
    ```bash
    npm run ocr-index -- <caseId>
    ```
    Opt out entirely by setting `DFIR_OCR_SEARCH=off` in `.env`.
