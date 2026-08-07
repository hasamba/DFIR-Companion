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
        }),
        F("DFIR_VELOCIRAPTOR_BINARY", "velociraptor binary", {
          hint: "Path to the velociraptor executable (optional if on PATH).",
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
    // /notifications API (add channel → test), NOT /settings/env. The wizard handles the common
    // webhook case (Slack/Teams/Mattermost/Discord — one URL); email/Telegram (multi-field) stay in
    // Settings → Notifications. kind:"notifications" routes to its own handler.
    {
      id: "notifications",
      icon: "🔔",
      label: "Notifications",
      status: "notifications",
      kind: "notifications",
      blurb:
        "Get a Slack / Teams / Mattermost / Discord ping on new findings, playbook updates, and milestones.",
      note: "Adds a webhook channel + sends a test message. Email & Telegram (more fields) live in Settings → Notifications.",
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
