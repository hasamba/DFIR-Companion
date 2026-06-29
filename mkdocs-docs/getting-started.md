# Getting Started

## Installation

Choose the method that fits your setup:

=== "From source"

    Recommended for development or if you want to customise prompts.

    1. Install [Node.js](https://nodejs.org/) **20 or later** (Node 22.5+ if you want the NSRL SQLite backend).
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
    docker run -p 4773:4773 \
      -v /your/cases:/cases \
      -e DFIR_CASES_ROOT=/cases \
      ghcr.io/hasamba/dfir-companion:latest
    ```

    Dashboard is then at **http://127.0.0.1:4773/dashboard**. Mount a local volume for persistent case storage.

---

!!! warning "Port already in use?"
    If the dashboard says "companion offline", the server is not running. If you see `EADDRINUSE`, another instance is already running — just use that one, or free the port:
    ```powershell
    Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
    ```

---

## First-Run Setup Wizard

When you open the dashboard for the first time with no AI provider configured, a **Setup Wizard** appears automatically. It walks you through everything in a guided, multi-step flow:

| Step | What you configure |
|------|--------------------|
| **AI analysis** | Provider (OpenAI, Anthropic/Claude, OpenRouter, Gemini, Ollama, LiteLLM), model name, API key. A "Save & test" button confirms the key works before you proceed. |
| **Velociraptor** | API config path for hunt-and-collect integration. |
| **DFIR-IRIS** | URL + key for bidirectional case sync. |
| **Timesketch** | URL + credentials to push the timeline to Timesketch. |
| **Notion** | API token for exporting cases to Notion pages. |
| **ClickUp** | API token for pushing the response playbook to ClickUp. |
| **Threat-intel enrichment** | API keys for VirusTotal, AbuseIPDB, Hunting.ch, CrowdStrike, Shodan, MISP, YETI, OpenCTI, RockyRaccoon, GeoIP. |
| **Customer exposure** | Keys for LeakCheck, HIBP, DeHashed. |
| **Push ingest** | Token for the webhook endpoint. |
| **NSRL** | Path to a known-good hash database. |
| **Notifications** | Slack/Teams/Mattermost/Discord webhook for alert notifications. |

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

**Keyboard shortcut:** `Ctrl+Shift+S` (Windows/Linux) toggles capture mode on/off. When capture is active, a floating push button appears on the page.

---

## Next Steps

- Follow the [Analyst Walkthrough](walkthrough.md) for a complete investigation from start to finish.
- Browse the [Feature Reference](reference/cases.md) for details on any specific feature.
