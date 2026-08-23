# Getting Started

## Installation

Choose the method that fits your setup:

=== "From source"

    Recommended for development or if you want to customise prompts.

    1. Install [Node.js](https://nodejs.org/) **22.19 or later** (required by the indexed case store).
    2. Clone or download the repository.
    3. Run:
       ```bash
       cd companion
       npm install
       cp .env.example .env
       npm run dev
       ```
    4. The server starts on **http://127.0.0.1:4773**. Open the dashboard at **http://127.0.0.1:4773/dashboard**.

=== "Windows — Chocolatey"

    ```powershell
    choco install dfir-companion
    ```

    Installs the portable Windows build and bundles the capture extension on disk for offline "Load unpacked". Data is stored in `%LOCALAPPDATA%\DFIR-Companion`.

=== "Windows — Portable exe"

    Download `dfir-companion-win.zip` from the [latest GitHub release](https://github.com/hasamba/DFIR-Companion/releases/latest), extract, and run `dfir-companion.exe`. No Node.js required.

=== "Linux — AppImage"

    Download `dfir-companion-linux.AppImage` from the [latest GitHub release](https://github.com/hasamba/DFIR-Companion/releases/latest), make it executable, and run it.

    ```bash
    chmod +x dfir-companion-linux.AppImage
    ./dfir-companion-linux.AppImage
    ```

    Set `DFIR_ENV_FILE` to point to your `.env` if you need the config file outside the AppImage mount.

=== "Docker"

    ```bash
    docker run -p 127.0.0.1:4773:4773 \
      -v /your/cases:/cases \
      -e DFIR_CASES_ROOT=/cases \
      -e DFIR_ALLOW_UNAUTHENTICATED_REMOTE=container-loopback-proxy \
      ghcr.io/hasamba/dfir-companion:latest
    ```

    Dashboard is then at **http://127.0.0.1:4773/dashboard**. Mount a local volume for persistent case storage.

---

!!! warning "Port already in use?"
    If the dashboard says "companion offline", the server is not running. If you see `EADDRINUSE`, another instance is already running — just use that one, or free the port:
    ```powershell
    # Windows
    Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
    ```
    ```bash
    # Linux / macOS
    kill $(lsof -ti tcp:4773)
    # Linux only, if lsof isn't installed
    fuser -k 4773/tcp
    ```

---

## First-Run Setup Wizard

When you open the dashboard for the first time with no AI provider configured, a **Setup Wizard** appears automatically. It walks you through everything in a guided, multi-step flow:

| Step | What you configure |
|------|--------------------|
| **AI analysis** | Provider (OpenAI, Anthropic/Claude, OpenRouter, Gemini, Ollama, LiteLLM), model name, API key. A "Save & test" button confirms the key works before you proceed. |
| **Presidio PII scan** | Optional analyzer URL, confidence floor and timeout for the extra PII detector in front of the AI. Save, then restart — these keys are read at startup. |
| **Velociraptor** | API config path for hunt-and-collect integration. |
| **DFIR-IRIS** | URL + key for bidirectional case sync. |
| **Timesketch** | URL + credentials to push the timeline to Timesketch. |
| **Notion** | API token for exporting cases to Notion pages. |
| **ClickUp** | API token for pushing the response playbook to ClickUp. |
| **Threat-intel enrichment** | API keys for VirusTotal, AbuseIPDB, Hunting.ch, CrowdStrike, Shodan, MISP, YETI, OpenCTI, RockyRaccoon, GeoIP. |
| **Customer exposure** | Keys for LeakCheck, HIBP, DeHashed. |
| **Push ingest** | Token for the webhook endpoint. |
| **NSRL** | Path to a known-good hash database. |
| **Notifications** | Slack/Teams/Mattermost/Discord webhook, or a Telegram bot (token + chat ID), for alert notifications. |

!!! tip
    Everything is optional. You can dismiss the wizard and add things later from **Settings**. You can reopen the wizard any time from **Settings → General → Open setup wizard**.

---

## Installing the Browser Extension

The capture extension lets you screenshot any browser tab with a keyboard shortcut.

=== "Chrome Web Store (easiest)"

    Install directly from the Chrome Web Store — no developer mode needed:

    **[DFIR Companion — Evidence Capture & Push](https://chromewebstore.google.com/detail/dfir-companion-%E2%80%94-evidence/jhlffkfnamlmfkijgpaopdnbmbajldmf)**

    Click **Add to Chrome**, confirm the permissions, and the extension icon appears in your toolbar.

=== "Load unpacked"

    For Chocolatey installs (extension is pre-built on disk) or if building from source:

    1. In Chrome (or any Chromium browser), go to `chrome://extensions/`.
    2. Enable **Developer mode** (top-right toggle).
    3. Click **Load unpacked** and select the `extension/dist/` folder (run `npm run build` inside `extension/` first if building from source; Chocolatey installs it pre-built on disk).
    4. The extension icon appears in the toolbar.

=== "Firefox"

    Needs **Firefox 140 or later**. There is no Mozilla Add-ons listing yet, so it loads as a temporary add-on:

    1. Download `dfir-capture-extension-firefox-*.zip` from the [latest GitHub release](https://github.com/hasamba/DFIR-Companion/releases/latest) and unzip it. (Building from source instead? Run `npm run build:firefox` inside `extension/` — it writes the same files to `extension/dist-firefox/`.)
    2. In Firefox, go to `about:debugging#/runtime/this-firefox`.
    3. Click **Load Temporary Add-on…** and select the `manifest.json` inside the unzipped folder — the manifest **file**, not the folder. (Chrome asks for a folder here; Firefox asks for the manifest inside it.)

    !!! info "What it collects, since a temporary load never asks"

        Firefox shows its data-collection notice only for a signed add-on installed normally; `about:debugging` grants everything silently. The extension declares **browsing activity** (a capture carries the tab's URL and title) and **website content** (the screenshot, and the rows a Push scrapes). The extension sends it to the companion address you configure and nowhere else; what that companion forwards afterwards — a vision model reads the screenshots, AI synthesis reads the rows, enrichment queries reputation services — is the companion's own configuration.
    4. The extension icon appears in the toolbar.

    !!! note "Temporary add-ons don't survive a restart"

        Firefox removes a temporary add-on when the browser restarts, so repeat step 3 each session. That is how unsigned add-ons work — the release zip is not signed by Mozilla, so it cannot be installed permanently until there is an AMO listing. Nothing you captured is lost either way: evidence is sent to the Companion server as you capture it and lives in the case, not in the browser.

**Keyboard shortcut:** `Ctrl+Shift+S` (Windows/Linux) toggles capture mode on/off. When capture is active, a floating push button appears on the page.

---

## Next Steps

- Follow the [Analyst Walkthrough](walkthrough.md) for a complete investigation from start to finish.
- Browse the [Feature Reference](reference/cases.md) for details on any specific feature.
