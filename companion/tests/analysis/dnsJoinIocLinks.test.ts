import { describe, it, expect } from "vitest";
import { buildSiemResult } from "../../src/analysis/siemImport.js";
import { buildWindowsEventResult } from "../../src/analysis/siemBuildProgress.js";
import { parseEvtxXmlProgress } from "../../src/analysis/evtxXmlImport.js";
import { resolveExtractedFrom } from "../../src/analysis/iocSink.js";

// #1642: identical DNS records (same query, same answer) that get different connection outcomes
// split into two rows. The query's IOC must link to BOTH rows, and an IOC only one record carried
// must link to that record's row only.

const HOST = "WS-01.example.com";
const SYSMON = "Microsoft-Windows-Sysmon";
const SHA = "a".repeat(64);

const rec = (eid: number, ts: string, ed: Record<string, string>): Record<string, unknown> => ({
  "@timestamp": ts,
  log_name: `${SYSMON}/Operational`,
  computer_name: HOST,
  event_id: eid,
  event_data: { Image: "C:\\Windows\\System32\\svchost.exe", ...ed },
});
const dnsRec = (ts: string, extra: Record<string, string> = {}) =>
  rec(22, ts, {
    QueryName: "split.example",
    QueryStatus: "0",
    QueryResults: "::ffff:203.0.113.9;",
    ...extra,
  });

const records = [
  dnsRec("2026-03-01T10:00:00Z"),
  rec(3, "2026-03-01T10:00:05Z", { Protocol: "tcp", DestinationIp: "203.0.113.9", DestinationPort: "443" }),
  dnsRec("2026-03-01T11:00:00Z", { Hashes: `SHA256=${SHA}` }),
];

type Result = ReturnType<typeof buildSiemResult>;

function check(r: Result): void {
  const rows = r.events.filter((e) => e.description.includes("split.example"));
  expect(rows).toHaveLength(2);
  const joined = rows.find((e) => e.canonical?.dns?.joinState === "joined")!;
  const later = rows.find((e) => e !== joined)!;
  expect(joined).toBeDefined();
  expect(later.aggKey).not.toBe(joined.aggKey);

  const domain = r.iocs.find((i) => i.value === "split.example")!;
  expect(new Set(domain.sourceAggKeys)).toEqual(new Set([joined.aggKey, later.aggKey]));
  const hash = r.iocs.find((i) => i.value === SHA)!;
  expect(hash.sourceAggKeys).toEqual([later.aggKey]);

  const ids = new Map(r.events.map((e, i) => [e.aggKey!, `ev-${i}`]));
  const [d, h] = resolveExtractedFrom([domain, hash], ids);
  expect(new Set(d.extractedFrom)).toEqual(new Set([ids.get(joined.aggKey!), ids.get(later.aggKey!)]));
  expect(h.extractedFrom).toEqual([ids.get(later.aggKey!)]);
}

describe("DNS join keeps IOC links for every row a query splits into (#1642)", () => {
  it("SIEM JSON import", () => check(buildSiemResult(records, "x")));

  it("Windows-event streaming builder", () => check(buildWindowsEventResult(records, "x")));

  it("both builders give the same IOC links", () => {
    const view = (r: Result) => r.iocs.map((i) => ({ v: i.value, s: i.sourceAggKeys }));
    expect(view(buildWindowsEventResult(records, "x"))).toEqual(view(buildSiemResult(records, "x")));
  });

  it("with aggregation off, each record's row keeps its own link", () => {
    for (const r of [
      buildSiemResult(records, "x", { aggregate: false }),
      buildWindowsEventResult(records, "x", { aggregate: false }),
    ])
      check(r);
  });

  it("Windows Event XML import", async () => {
    const ev = (eid: number, time: string, data: Record<string, string>): string =>
      `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="${SYSMON}"/><EventID>${eid}</EventID><Level>4</Level><TimeCreated SystemTime="${time}"/><Channel>${SYSMON}/Operational</Channel><Computer>${HOST}</Computer></System><EventData>${Object.entries(
        { Image: "C:\\Windows\\System32\\svchost.exe", ...data },
      )
        .map(([k, v]) => `<Data Name="${k}">${v}</Data>`)
        .join("")}</EventData></Event>`;
    const q = { QueryName: "split.example", QueryStatus: "0", QueryResults: "::ffff:203.0.113.9;" };
    const xml = `<Events>${[
      ev(22, "2026-03-01T10:00:00.000Z", q),
      ev(3, "2026-03-01T10:00:05.000Z", {
        Protocol: "tcp",
        Initiated: "true",
        DestinationIp: "203.0.113.9",
        DestinationPort: "443",
      }),
      ev(22, "2026-03-01T11:00:00.000Z", { ...q, Hashes: `SHA256=${SHA}` }),
    ].join("")}</Events>`;
    check(await parseEvtxXmlProgress(xml));
  });
});
