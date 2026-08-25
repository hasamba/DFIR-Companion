// Setup-wizard step definitions (#181) — the data table only.
//
// Split out of js/dashboard-setup-wizard.js when moving the wizard's state home (#415) pushed that
// module to 833 lines, past the 800-line budget. The size gate says plainly that the ledger is a
// freeze on files that are already too big, not a budget to spend — so the answer is a new module,
// not a bigger one.
//
// Published as ACCESSORS, not as the array: the feature manifest requires published names to be
// callable (the gate that rejected a bare QA_AUDIT_MARK in extraction 76).
(function () {
  "use strict";

  const F = (key, label, opts) => Object.assign({ key, label }, opts || {});
  const WIZARD_STEPS = [
    // Presidio comes first because it is a boundary ON step 1: it decides what the AI provider is
    // allowed to see. Its three keys are also the only ones in this table /settings/reload cannot
    // apply — DFIR_PRESIDIO_ is deliberately off that allowlist, because the analyzer client is
    // built once at startup — so kind:"presidio" saves, tests the URL as typed, and says "restart"
    // instead of the save -> apply-live -> test every other step runs.
    {
      id: "presidio",
      icon: "🕵️",
      label: "Presidio PII scan",
      status: "presidio",
      kind: "presidio",
      blurb:
        "OPTIONAL — a second PII detector in front of the AI. It scans text the built-in patterns have ALREADY masked, and catches the names and IDs a regex cannot.",
      note: "Presidio reads your case text — masked, but still your timeline. Run the analyzer yourself, on this machine or your own network. These three values are read at STARTUP: save them here, then restart the server.",
      fields: [
        F("DFIR_PRESIDIO_URL", "Analyzer URL", {
          hint: "http://localhost:5002 — a Presidio Analyzer container you run yourself. Blank = the layer is off.",
        }),
        F("DFIR_PRESIDIO_MIN_SCORE", "Confidence floor", {
          hint: "0–1, default 0.6. Findings the analyzer scores below this are ignored.",
        }),
        F("DFIR_PRESIDIO_TIMEOUT_MS", "Request timeout (ms)", {
          hint: "Budget for ONE scan request, default 60000. Raise it for a slow or shared analyzer.",
        }),
      ],
    },
    {
      id: "velociraptor",
      icon: "🦖",
      label: "Velociraptor",
      status: "velociraptor",
      blurb:
        "Endpoint visibility, hunts, and live monitoring across your fleet.",
      reload: "DFIR_VELOCIRAPTOR_",
      test: { method: "POST", url: "/velociraptor/reconnect" },
      fields: [
        F("DFIR_VELOCIRAPTOR_API_CONFIG", "API config path", {
          hint: "Path to the velociraptor --api_config YAML (api_client.yaml).",
          browse: "Select Velociraptor API config file",
        }),
        F("DFIR_VELOCIRAPTOR_BINARY", "Velociraptor binary", {
          hint: "Path to the velociraptor executable (optional if on PATH).",
          browse: "Select Velociraptor binary",
          download: true,
        }),
        F("DFIR_VELOCIRAPTOR_GUI_URL", "GUI URL", {
          hint: "Base URL for client links (optional).",
        }),
      ],
    },
    {
      id: "iris",
      icon: "🔎",
      label: "DFIR-IRIS",
      status: "iris",
      blurb: "Push / import cases to a DFIR-IRIS case-management instance.",
      reload: "DFIR_IRIS_",
      test: { method: "POST", url: "/iris/reconnect" },
      fields: [
        F("DFIR_IRIS_URL", "IRIS URL", { hint: "https://iris.example.com" }),
        F("DFIR_IRIS_KEY", "API key", { secret: true }),
        F("DFIR_IRIS_CUSTOMER_ID", "Customer ID", {
          hint: "Numeric (optional).",
        }),
        F("DFIR_IRIS_CLASSIFICATION_ID", "Classification ID", {
          hint: "Numeric (optional).",
        }),
        F("DFIR_IRIS_INSECURE", "Skip TLS verify", {
          hint: "true = accept a self-signed IRIS cert without verifying (lab only).",
        }),
        // Global key, not DFIR_IRIS_: the step's reload prefix won't apply it, so the field
        // carries its own — wizSaveAndTestGeneric reloads it when the field was saved.
        F("DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "Allow insecure TLS to external hosts", {
          hint: "Skip TLS verify toward a NON-loopback host is refused (MITM risk) unless this is true. Applies to every integration; prefer a CA bundle.",
          reload: "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
        }),
      ],
    },
    {
      id: "timesketch",
      icon: "📆",
      label: "Timesketch",
      status: "timesketch",
      blurb: "Push the forensic timeline to a Timesketch instance.",
      reload: "DFIR_TIMESKETCH_",
      test: { method: "POST", url: "/timesketch/reconnect" },
      fields: [
        F("DFIR_TIMESKETCH_URL", "Timesketch URL", {
          hint: "https://timesketch.example.com",
        }),
        F("DFIR_TIMESKETCH_USER", "Username"),
        F("DFIR_TIMESKETCH_PASSWORD", "Password", { secret: true }),
        // Timesketch is nearly always self-hosted behind its own cert, so Test lands on
        // "self-signed certificate (DEPTH_ZERO_SELF_SIGNED_CERT)" — a dead end while this pair
        // lived only in Settings › All. Same reasoning as the IRIS step above.
        F("DFIR_TIMESKETCH_INSECURE", "Skip TLS verify", {
          hint: "true = accept a self-signed Timesketch cert without verifying (lab only).",
        }),
        // Global key, not DFIR_TIMESKETCH_: the step's reload prefix won't apply it, so the field
        // carries its own — wizSaveAndTestGeneric reloads it when the field was saved.
        F("DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "Allow insecure TLS to external hosts", {
          hint: "Skip TLS verify toward a NON-loopback host is refused (MITM risk) unless this is true. Applies to every integration; prefer a CA bundle.",
          reload: "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
        }),
      ],
    },
    {
      id: "enrichment",
      icon: "🧪",
      label: "Threat-intel enrichment",
      status: "enrichment",
      blurb:
        "Look up IOCs against threat-intel sources. OFF by default — external sources are opt-in per case (OPSEC).",
      kind: "providers",
      note: "Saving a key only enables a source — nothing is sent externally until you opt in per case.",
      providers: [
        {
          id: "virustotal",
          label: "VirusTotal",
          scope: "external",
          reload: "DFIR_VT_",
          fields: [F("DFIR_VT_KEY", "API key", { secret: true })],
        },
        {
          id: "abuseipdb",
          label: "AbuseIPDB",
          scope: "external",
          reload: "DFIR_ABUSEIPDB_",
          fields: [F("DFIR_ABUSEIPDB_KEY", "API key", { secret: true })],
        },
        {
          id: "huntingch",
          label: "Hunting.ch (abuse.ch)",
          scope: "external",
          reload: "DFIR_HUNTINGCH_",
          fields: [F("DFIR_HUNTINGCH_KEY", "Auth-Key", { secret: true })],
        },
        {
          id: "crowdstrike",
          label: "CrowdStrike Intel",
          scope: "external",
          reload: "DFIR_CROWDSTRIKE_",
          fields: [
            F("DFIR_CROWDSTRIKE_CLIENT_ID", "Client ID"),
            F("DFIR_CROWDSTRIKE_CLIENT_SECRET", "Client secret", {
              secret: true,
            }),
          ],
        },
        {
          id: "shodan",
          label: "Shodan",
          scope: "external",
          reload: "DFIR_SHODAN_",
          fields: [F("DFIR_SHODAN_KEY", "API key", { secret: true })],
        },
        {
          id: "misp",
          label: "MISP",
          scope: "local",
          reload: "DFIR_MISP_",
          fields: [
            F("DFIR_MISP_URL", "URL"),
            F("DFIR_MISP_KEY", "API key", { secret: true }),
          ],
        },
        {
          id: "yeti",
          label: "YETI",
          scope: "local",
          reload: "DFIR_YETI_",
          fields: [
            F("DFIR_YETI_URL", "URL"),
            F("DFIR_YETI_KEY", "API key", { secret: true }),
          ],
        },
        {
          id: "opencti",
          label: "OpenCTI",
          scope: "local",
          reload: "DFIR_OPENCTI_",
          fields: [
            F("DFIR_OPENCTI_URL", "URL"),
            F("DFIR_OPENCTI_KEY", "API key", { secret: true }),
          ],
        },
        {
          id: "rockyraccoon",
          label: "RockyRaccoon",
          scope: "external",
          reload: "DFIR_ROCKYRACCOON_",
          fields: [F("DFIR_ROCKYRACCOON_KEY", "API key", { secret: true })],
        },
        {
          id: "geoip",
          label: "GeoIP (ipinfo key, optional)",
          scope: "external",
          reload: "DFIR_GEOIP_",
          fields: [F("DFIR_GEOIP_KEY", "API key", { secret: true })],
        },
      ],
    },
    {
      id: "exposure",
      icon: "🔓",
      label: "Customer exposure",
      status: "exposure",
      blurb:
        "Check the VICTIM org's own domains/emails against breach DBs (separate from IOC enrichment).",
      kind: "providers",
      note: "Only the customer's own domains are ever sent — never adversary/IOC domains.",
      providers: [
        {
          id: "leakcheck",
          label: "LeakCheck",
          scope: "external",
          reload: "DFIR_LEAKCHECK_",
          fields: [F("DFIR_LEAKCHECK_KEY", "API key", { secret: true })],
        },
        {
          id: "hibp",
          label: "Have I Been Pwned",
          scope: "external",
          reload: "DFIR_HIBP_",
          fields: [F("DFIR_HIBP_KEY", "API key", { secret: true })],
        },
        {
          id: "dehashed",
          label: "DeHashed",
          scope: "external",
          reload: "DFIR_DEHASHED_",
          fields: [F("DFIR_DEHASHED_KEY", "API key", { secret: true })],
        },
      ],
    },
    {
      id: "notion",
      icon: "📝",
      label: "Notion export",
      status: "notion",
      blurb: "Export a case into a Notion page.",
      reload: "DFIR_NOTION_",
      test: { method: "GET", url: "/notion/status" },
      fields: [
        F("DFIR_NOTION_TOKEN", "Integration token", { secret: true }),
        F("DFIR_NOTION_DATABASE_ID", "Database ID", {
          hint: "For new pages from a template (optional).",
        }),
        F("DFIR_NOTION_PARENT_PAGE_ID", "Parent page ID", {
          hint: "Parent for new child pages (optional).",
        }),
      ],
    },
    {
      id: "clickup",
      icon: "✅",
      label: "ClickUp export",
      status: "clickup",
      blurb: "Push the Response Playbook to a ClickUp list as tasks.",
      reload: "DFIR_CLICKUP_",
      test: { method: "GET", url: "/clickup/status" },
      fields: [
        F("DFIR_CLICKUP_TOKEN", "API token", { secret: true }),
        F("DFIR_CLICKUP_LIST_ID", "Default list ID", {
          hint: "Optional — can be chosen at push time.",
        }),
      ],
    },
    {
      id: "push",
      icon: "📡",
      label: "Push ingest",
      status: "push",
      blurb:
        "OPTIONAL — only needed if an external tool (SIEM webhook, EDR/Velociraptor poller, a custom script) should stream alerts straight into a case as they happen. For manual work (screenshots + the Import button) you can skip this.",
      note: "There's nothing to look up — you INVENT a secret token here (treat it like a password), then configure your tool to send it as the X-DFIR-Key header when it POSTs to /cases/<id>/push. Push is OFF until a token is set. Not using an external pusher? Leave it blank and skip.",
      reload: "DFIR_PUSH_TOKEN",
      test: { method: "GET", url: "/setup/status", statusKey: "push" },
      fields: [
        F("DFIR_PUSH_TOKEN", "Push token (you choose this)", {
          secret: true,
          hint: "A random secret you make up — e.g. a 32-char string from a password manager. Senders must send the SAME value as their X-DFIR-Key header.",
        }),
      ],
    },
    {
      id: "nsrl",
      icon: "🗄️",
      label: "NSRL known-good",
      status: "nsrl",
      blurb:
        "Auto-mark known-software hashes as a false positive. Flat hash file and/or an RDS SQLite DB.",
      reload: "DFIR_NSRL_",
      test: { method: "GET", url: "/setup/status", statusKey: "nsrl" },
      fields: [
        F("DFIR_NSRL_DB", "RDS SQLite DB path", {
          hint: "RDS_*.db queried on demand (needs Node 22.5+).",
        }),
        F("DFIR_NSRL_FILE", "Hash file path(s)", {
          hint: "NSRLFile.txt / hashdeep / plain hash list; ;-separated; preloaded at startup.",
        }),
      ],
    },
    // Notifications are stored in a GLOBAL config file (not .env), so this step uses the dedicated
    // /notifications API (add channel → test), NOT /settings/env. It covers the webhook case
    // (Slack/Teams/Mattermost/Discord — one URL) and Telegram (a bot token + a chat id); email
    // needs a whole SMTP block and stays in Settings → Notifications. kind:"notifications" routes
    // to its own handler.
    {
      id: "notifications",
      icon: "🔔",
      label: "Notifications",
      status: "notifications",
      kind: "notifications",
      blurb:
        "Get a Slack / Teams / Mattermost / Discord / Telegram ping on new findings, playbook updates, and milestones.",
      note: "Adds a channel + sends a test message. Email (a full SMTP block) lives in Settings → Notifications.",
    },
  ];

  const WIZ_ORDER = ["ai", ...WIZARD_STEPS.map((s) => s.id)];
  const WIZARD_BY_ID = Object.fromEntries(WIZARD_STEPS.map((s) => [s.id, s]));

  function wizardOrder() {
    return WIZ_ORDER;
  }
  function wizardStepById(id) {
    return WIZARD_BY_ID[id];
  }

  window.wizardOrder = wizardOrder;
  window.wizardStepById = wizardStepById;
})();
