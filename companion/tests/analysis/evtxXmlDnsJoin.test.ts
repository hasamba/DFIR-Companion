import { describe, it, expect } from "vitest";
import { parseEvtxXml, parseEvtxXmlProgress } from "../../src/analysis/evtxXmlImport.js";
import { buildSiemResult } from "../../src/analysis/siemImport.js";
import { buildWindowsEventResult } from "../../src/analysis/siemBuildProgress.js";
import { DNS_VARIANTS_MAX } from "../../src/analysis/dnsRecord.js";
import { canonicalConformanceIssues } from "../../src/analysis/canonicalEvent.js";

// #1636: the Windows Event XML import runs the same DNS variant bounding and DNS→connection join
// (#933 item 2, #996) that the SIEM JSON import runs, on the streaming builder.

const HOST = "WS-01.example.com";
const SYSMON = "Microsoft-Windows-Sysmon";

function event(eid: number, time: string, data: Record<string, string>): string {
  const fields = Object.entries(data)
    .map(([k, v]) => `<Data Name="${k}">${v}</Data>`)
    .join("");
  return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="${SYSMON}"/><EventID>${eid}</EventID><Level>4</Level><TimeCreated SystemTime="${time}"/><Channel>${SYSMON}/Operational</Channel><Computer>${HOST}</Computer></System><EventData>${fields}</EventData></Event>`;
}

const query = (name: string, results: string, time = "2026-03-01T10:00:00.000Z"): string =>
  event(22, time, {
    UtcTime: time.replace("T", " ").replace("Z", ""),
    Image: "C:\\Windows\\System32\\svchost.exe",
    ProcessId: "1234",
    QueryName: name,
    QueryStatus: "0",
    QueryResults: results,
  });

const connection = (ip: string, time = "2026-03-01T10:00:05.000Z"): string =>
  event(3, time, {
    UtcTime: time.replace("T", " ").replace("Z", ""),
    Image: "C:\\Windows\\System32\\svchost.exe",
    Protocol: "tcp",
    Initiated: "true",
    DestinationIp: ip,
    DestinationPort: "443",
  });

const xml = (...events: string[]): string => `<Events>${events.join("")}</Events>`;

describe("Windows Event XML — Sysmon 22 → Sysmon 3 connection join (#1636)", () => {
  const joined = xml(query("join.example", "::ffff:203.0.113.9;"), connection("203.0.113.9"));

  it("the live (progress) import annotates the DNS row with the connection lead", async () => {
    const r = await parseEvtxXmlProgress(joined);
    const e = r.events.find((ev) => ev.description.includes("[query: join.example]"))!;
    expect(e.description).toContain(
      "203.0.113.9: connection record ≤10 s after the answer arrived, inside the window",
    );
    expect(e.canonical?.dns).toMatchObject({
      joinState: "joined",
      leads: [{ address: "203.0.113.9", state: "connected inside the window" }],
    });
    expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
    // IOC provenance follows the rewritten key
    expect(r.iocs.find((i) => i.value === "join.example")?.sourceAggKeys).toContain(e.aggKey);
    // the connection row itself is still imported
    expect(r.events.some((ev) => /Network connection/i.test(ev.description))).toBe(true);
  });

  it("the sync parse gives the same answer as the live import", async () => {
    const live = await parseEvtxXmlProgress(joined);
    const sync = parseEvtxXml(joined);
    expect(sync.events.map((e) => e.description).sort()).toEqual(
      live.events.map((e) => e.description).sort(),
    );
  });

  it("a DNS row with no connection records says so", async () => {
    const r = await parseEvtxXmlProgress(xml(query("alone.example", "::ffff:203.0.113.9;")));
    expect(r.events[0].description).toContain("connection join: no connection records in this upload");
  });
});

describe("Windows Event XML — bounded DNS variants (#1636)", () => {
  it("returned-value churn on one query folds past the budget into one overflow row", async () => {
    const churn = Array.from({ length: DNS_VARIANTS_MAX + 10 }, (_, i) =>
      query("txt.attacker.example", `type: 16 nonce-${i};`),
    );
    const r = await parseEvtxXmlProgress(xml(...churn));
    const overflow = r.events.filter((e) => e.description.includes("[overflow:"));
    expect(overflow).toHaveLength(1);
    expect(overflow[0].count).toBe(10);
    expect(overflow[0].canonical?.dns).toMatchObject({ returned: [], folded: true });
    expect(r.iocs.find((i) => i.value === "txt.attacker.example")?.sourceAggKeys).toContain(
      overflow[0].aggKey,
    );
  });

  it("with aggregation off nothing is folded", async () => {
    const churn = Array.from({ length: DNS_VARIANTS_MAX + 2 }, (_, i) =>
      query("txt.attacker.example", `type: 16 nonce-${i};`),
    );
    const r = await parseEvtxXmlProgress(xml(...churn), { aggregate: false });
    expect(r.events.every((e) => !e.description.includes("[overflow:"))).toBe(true);
  });

  it("cancellation still stops the import while held DNS rows drain", async () => {
    const controller = new AbortController();
    const churn = Array.from({ length: 600 }, (_, i) =>
      query(`q${i}.example`, "::ffff:203.0.113.9;", "2026-03-01T10:00:00.000Z"),
    );
    // The abort lands on the next turn of the event loop — after mapping has finished, so only a
    // yield inside the DNS pass can see it.
    const abortSoon = () => void setImmediate(() => controller.abort());
    const work = parseEvtxXmlProgress(xml(...churn), {}, undefined, abortSoon, controller.signal);
    await expect(work).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("the Windows-event builder matches the SIEM JSON builder on DNS rows (#1636)", () => {
  const rec = (eid: number, ts: string, ed: Record<string, string>): Record<string, unknown> => ({
    "@timestamp": ts,
    log_name: `${SYSMON}/Operational`,
    computer_name: HOST,
    event_id: eid,
    event_data: { Image: "C:\\Windows\\System32\\svchost.exe", ...ed },
  });
  const records = [
    rec(22, "2026-03-01T10:00:00Z", {
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "::ffff:203.0.113.9;",
    }),
    rec(22, "2026-03-01T10:00:01Z", {
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "::ffff:203.0.113.9;",
    }),
    rec(22, "2026-03-01T11:00:00Z", {
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "::ffff:203.0.113.9;",
    }),
    rec(3, "2026-03-01T10:00:10Z", { Protocol: "tcp", DestinationIp: "203.0.113.9", DestinationPort: "443" }),
    ...Array.from({ length: DNS_VARIANTS_MAX + 3 }, (_, i) =>
      rec(22, "2026-03-01T10:05:00Z", {
        QueryName: "b.example",
        QueryStatus: "0",
        QueryResults: `type: 16 n-${i};`,
      }),
    ),
  ];

  it("same rows, same keys, same counts, same IOC provenance", () => {
    const view = (r: ReturnType<typeof buildSiemResult>) => ({
      events: r.events
        .map((e) => ({ k: e.aggKey, d: e.description, c: e.count, dns: e.canonical?.dns }))
        .sort((a, b) => (a.k ?? "").localeCompare(b.k ?? "")),
      iocs: r.iocs.map((i) => ({ v: i.value, s: i.sourceAggKeys })),
      kept: r.kept,
      dropped: r.dropped,
    });
    expect(view(buildWindowsEventResult(records, "x"))).toEqual(view(buildSiemResult(records, "x")));
  });

  it("at the event cap and with aggregation off, tied rows keep the source order the SIEM builder keeps", () => {
    const tied = [
      rec(22, "2026-03-01T10:00:00Z", {
        QueryName: "c.example",
        QueryStatus: "0",
        QueryResults: "::ffff:203.0.113.7;",
      }),
      rec(3, "2026-03-01T10:00:00Z", {
        Protocol: "tcp",
        DestinationIp: "198.51.100.7",
        DestinationPort: "443",
      }),
      rec(22, "2026-03-01T10:00:00Z", {
        QueryName: "d.example",
        QueryStatus: "0",
        QueryResults: "::ffff:203.0.113.8;",
      }),
    ];
    for (const opts of [{ maxEvents: 1 }, { maxEvents: 2 }, { aggregate: false }]) {
      const order = (r: ReturnType<typeof buildSiemResult>) => r.events.map((e) => e.description);
      expect(order(buildWindowsEventResult(tied, "x", opts))).toEqual(
        order(buildSiemResult(tied, "x", opts)),
      );
    }
  });
});
