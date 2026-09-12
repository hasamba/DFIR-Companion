import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { DNS_VARIANTS_MAX } from "../../src/analysis/dnsRecord.js";
import { canonicalConformanceIssues } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";

// #933 item 2, prerequisite phase: a DNS record says what it establishes.

const elastic = (...rows: object[]) => JSON.stringify(rows.map((r) => ({ _source: r })));

const sysmon22 = (ed: Record<string, string>, over: { ts?: string; host?: string } = {}): object => ({
  "@timestamp": over.ts ?? "2026-03-01T10:00:00Z",
  log_name: "Microsoft-Windows-Sysmon/Operational",
  computer_name: over.host ?? "WS-01",
  event_id: 22,
  event_data: { Image: "C:\\Windows\\System32\\svchost.exe", ProcessId: "1234", ...ed },
});

const dnsClient = (eid: number, ed: Record<string, string>, over: { ts?: string } = {}): object => ({
  "@timestamp": over.ts ?? "2026-03-01T10:00:00Z",
  log_name: "Microsoft-Windows-DNS-Client/Operational",
  computer_name: "WS-01",
  event_id: eid,
  event_data: ed,
});

// The import pipeline after the parser (platformImports.ts): keys stripped, the import's source
// stamped, then correlateEvents' re-import rule.
const afterImport = (events: SiemEvent[]): ForensicEvent[] =>
  correlateEvents(
    events.map(({ aggKey: _k, ...e }, i) => ({
      ...e,
      id: `d${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: e.sources?.length ? e.sources : ["SIEM export"],
    })),
  );

describe("Sysmon 22 — what one record establishes", () => {
  it("a resolved query and a NXDOMAIN of one name are two rows, each saying what it is", () => {
    const r = parseSiemExport(
      elastic(
        sysmon22({ QueryName: "cdn.example.net", QueryStatus: "0", QueryResults: "::ffff:203.0.113.5;" }),
        sysmon22({ QueryName: "cdn.example.net", QueryStatus: "9003" }, { ts: "2026-03-01T10:00:01Z" }),
      ),
    );
    expect(r.events).toHaveLength(2);
    const ok = r.events.find((e) => e.description.includes("[returned:"))!;
    const nx = r.events.find((e) => e.description.includes("[NXDOMAIN"))!;
    expect(ok.description).toContain("[query: cdn.example.net]");
    expect(ok.description).toContain("[returned: 203.0.113.5]");
    expect(ok.description).not.toContain("QueryName=");
    expect(nx.description).toContain("[NXDOMAIN — the name does not exist at this resolver]");
    expect(ok.aggKey).toContain("|dns:q15:");
    expect(nx.aggKey).toContain(":s9003:n-:r-");
    expect(ok.severity).toBe("Low");
    expect(nx.severity).toBe("Low");
  });

  it("the same answer set twice is one row; a different set is another", () => {
    const line = (results: string, ts: string) =>
      sysmon22({ QueryName: "cdn.example.net", QueryStatus: "0", QueryResults: results }, { ts });
    const r = parseSiemExport(
      elastic(
        line("::ffff:192.0.2.1;::ffff:192.0.2.2;", "2026-03-01T10:00:00Z"),
        line("::ffff:192.0.2.2;::ffff:192.0.2.1;", "2026-03-01T11:00:00Z"),
        line("::ffff:192.0.2.3;", "2026-03-01T12:00:00Z"),
      ),
    );
    expect(r.events).toHaveLength(2);
    const pair = r.events.find((e) => e.count === 2)!;
    expect(pair.timestamp).toBe("2026-03-01T10:00:00Z");
    expect(pair.endTimestamp).toBe("2026-03-01T11:00:00Z");
  });

  it("the queried name is a domain indicator; the returned addresses are not indicators", () => {
    const r = parseSiemExport(
      elastic(
        sysmon22({ QueryName: "cdn.example.net", QueryStatus: "0", QueryResults: "::ffff:203.0.113.5;" }),
        sysmon22({ QueryName: "gone.example", QueryStatus: "9003" }),
      ),
    );
    const iocs = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(iocs).toContain("domain:cdn.example.net");
    expect(iocs).toContain("domain:gone.example"); // a name that never resolved is still the lead
    const under = parseSiemExport(
      elastic(
        sysmon22({
          QueryName: "beacon_01.attacker.example",
          QueryStatus: "0",
          QueryResults: "::ffff:192.0.2.9;",
        }),
      ),
    );
    expect(under.iocs.map((i) => i.value)).toContain("beacon_01.attacker.example");
    expect(under.events[0].description).not.toContain("not a valid name");
    expect(iocs).not.toContain("ip:203.0.113.5");
    expect(iocs.some((i) => i.includes("203.0.113.5"))).toBe(false);
  });

  it("the querying Image cannot forge a DNS tag, and two Images that neutralise alike stay two rows", () => {
    const forged = sysmon22({
      Image: "C:\\Temp\\x] [NXDOMAIN — the name does not exist at this resolver].exe",
      QueryName: "ok.example",
      QueryStatus: "0",
      QueryResults: "::ffff:192.0.2.1;",
    });
    const paren = sysmon22({
      Image: "C:\\Temp\\x) (NXDOMAIN — the name does not exist at this resolver).exe",
      QueryName: "ok.example",
      QueryStatus: "0",
      QueryResults: "::ffff:192.0.2.1;",
    });
    const r = parseSiemExport(elastic(forged, paren));
    expect(r.events).toHaveLength(2);
    const f = r.events.find((e) => e.description.includes("Temp\\x)"))!;
    expect(f.description).not.toMatch(/\[NXDOMAIN/);
    expect(f.description).toContain("[returned: 192.0.2.1]");
    expect(afterImport(r.events)).toHaveLength(2);
  });

  it("a single-label query is a valid name that is not an indicator", () => {
    const r = parseSiemExport(elastic(sysmon22({ QueryName: "wpad", QueryStatus: "9003" })));
    expect(r.events[0].description).not.toContain("not a valid name");
    expect(r.events[0].description).toContain("[query: wpad]");
    expect(r.iocs.some((i) => i.type === "domain")).toBe(false);
  });

  it("a query name that is not a valid name mints no indicator and cannot forge a tag", () => {
    const r = parseSiemExport(
      elastic(sysmon22({ QueryName: "good.example] [returned: 203.0.113.66", QueryStatus: "123" })),
    );
    const e = r.events[0];
    expect(e.description).toContain("[query name is not a valid name]");
    expect(e.description).not.toMatch(/\[returned:/);
    expect(r.iocs.some((i) => i.type === "domain")).toBe(false);
    expect(r.iocs.some((i) => i.value.includes("203.0.113.66"))).toBe(false);
  });

  it("the envelope carries the dns block: query, state, returned values, ownership and vantage", () => {
    const r = parseSiemExport(
      elastic(
        sysmon22({
          QueryName: "cdn.example.net",
          QueryStatus: "0",
          QueryResults: "type:  5 edge.example.net;::ffff:203.0.113.5;",
        }),
      ),
    );
    const c = r.events[0].canonical!;
    expect(canonicalConformanceIssues(c)).toEqual([]);
    expect(c.dns).toEqual({
      query: "cdn.example.net",
      queryValid: true,
      indicator: true,
      status: 0,
      state: "success",
      returned: [
        { type: 5, value: "edge.example.net", kind: "name" },
        { value: "203.0.113.5", kind: "address" },
      ],
      ownership: "not in this record",
      vantage: "endpoint",
    });
    expect(c.event).toMatchObject({ category: "network", type: "query" });
  });

  it("a forty-address answer stays inside 600 characters and keeps the mark", () => {
    const many = Array.from({ length: 40 }, (_, i) => `::ffff:10.0.0.${i}`).join(";") + ";";
    const r = parseSiemExport(
      elastic(sysmon22({ QueryName: "big.example", QueryStatus: "0", QueryResults: many })),
    );
    const e = r.events[0];
    expect(e.description.length).toBeLessThanOrEqual(600);
    expect(e.description).toContain("+32 more");
    expect(e.description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    expect(e.canonical?.dns?.returned).toHaveLength(40);
  });
});

describe("Sysmon 22 — bounded variants", () => {
  it("returned-value churn on one query folds past the budget and never crowds out other evidence", () => {
    const churn = Array.from({ length: 300 }, (_, i) =>
      sysmon22(
        { QueryName: "txt.attacker.example", QueryStatus: "0", QueryResults: `type: 16 nonce-${i};` },
        { ts: `2026-03-01T10:${String(i % 60).padStart(2, "0")}:00Z` },
      ),
    );
    const other = sysmon22({ QueryName: "unrelated.example", QueryStatus: "9003" });
    const r = parseSiemExport(elastic(...churn, other), { maxEvents: 100 });
    const dns = r.events.filter((e) => e.description.includes("[query: txt.attacker.example]"));
    expect(dns.length).toBe(DNS_VARIANTS_MAX + 1);
    const overflow = dns.find((e) => e.description.includes("[overflow:"))!;
    expect(overflow.count).toBe(300 - DNS_VARIANTS_MAX);
    expect(overflow.description).toContain(
      "distinct returned-value sets beyond 64 for this query folded; none shown",
    );
    expect(overflow.description).not.toContain("[returned:");
    expect(r.events.some((e) => e.description.includes("[query: unrelated.example]"))).toBe(true);
    expect(r.iocs.find((i) => i.value === "txt.attacker.example")?.sourceAggKeys).toContain(overflow.aggKey);
    // with aggregation off nothing is rewritten
    const raw = parseSiemExport(elastic(...churn.slice(0, 70)), { aggregate: false });
    expect(raw.events.every((e) => !e.description.includes("[overflow:"))).toBe(true);
  });
});

describe("Sysmon 22 — through correlateEvents", () => {
  it("two records differing only past the shown values stay two rows after import", () => {
    const nine = (last: string) =>
      sysmon22({
        QueryName: "a.example",
        QueryStatus: "0",
        QueryResults:
          Array.from({ length: 8 }, (_, i) => `::ffff:10.0.0.${i}`).join(";") + `;::ffff:${last};`,
      });
    const r = parseSiemExport(elastic(nine("10.0.0.8"), nine("10.0.0.9")));
    expect(r.events).toHaveLength(2);
    expect(afterImport(r.events)).toHaveLength(2);
  });

  it("two long valid names sharing 140 characters stay two rows after import", () => {
    const long = (t: string) => `${"z".repeat(63)}.${"y".repeat(63)}.${"x".repeat(20)}${t}.example`;
    const r = parseSiemExport(
      elastic(
        sysmon22({ QueryName: long("1"), QueryStatus: "0", QueryResults: "::ffff:192.0.2.1;" }),
        sysmon22({ QueryName: long("2"), QueryStatus: "0", QueryResults: "::ffff:192.0.2.1;" }),
      ),
    );
    expect(r.events).toHaveLength(2);
    expect(afterImport(r.events)).toHaveLength(2);
  });

  it("a hash-shaped label or a TXT value cannot join a DNS row to a file event", () => {
    const md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const r = parseSiemExport(
      elastic(
        sysmon22({ QueryName: `${md5}.example`, QueryStatus: "0", QueryResults: "::ffff:192.0.2.1;" }),
        dnsClient(3008, {
          QueryName: "txt.example",
          QueryType: "16",
          QueryStatus: "0",
          QueryResults: `type: 16 ${md5};`,
        }),
      ),
    );
    expect(r.events).toHaveLength(2);
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2026-03-05T10:00:00Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WS-01",
      md5,
    };
    expect(correlateEvents([...afterImport(r.events), file])).toHaveLength(3);
  });

  it("a path-shaped invalid name cannot join a DNS row to a file event", () => {
    const r = parseSiemExport(elastic(sysmon22({ QueryName: "/tmp/payload.exe", QueryStatus: "123" })));
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2026-03-01T10:00:01Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WS-01",
      path: "/tmp/payload.exe",
    };
    expect(correlateEvents([...afterImport(r.events), file])).toHaveLength(2);
  });
});

describe("DNS Client operational log", () => {
  it("3008 reads like Sysmon 22 with a type; 3020 reads Status; 3006 says the outcome is not in it", () => {
    const r = parseSiemExport(
      elastic(
        dnsClient(3008, { QueryName: "a.example", QueryType: "1", QueryStatus: "9501", QueryResults: "" }),
        dnsClient(3008, { QueryName: "a.example", QueryType: "15", QueryStatus: "9501", QueryResults: "" }),
        dnsClient(3020, { QueryName: "b.example", QueryType: "1", Status: "9003", QueryResults: "" }),
        dnsClient(3006, { QueryName: "c.example", QueryType: "1", QueryOptions: "0", IsNetworkQuery: "0" }),
      ),
    );
    expect(r.events).toHaveLength(4);
    const byName = (n: string) => r.events.filter((e) => e.description.includes(`[query: ${n}]`));
    expect(byName("a.example")).toHaveLength(2); // no A record and no MX record are two rows
    expect(
      byName("a.example")
        .map((e) => e.description)
        .sort()[0],
    ).toContain("[A query] [no records of the queried type]");
    expect(byName("b.example")[0].description).toContain("DNS query result (EID 3020)");
    expect(byName("b.example")[0].description).toContain("[NXDOMAIN");
    expect(byName("c.example")[0].description).toContain("DNS query called (EID 3006)");
    expect(byName("c.example")[0].description).toContain("[not a network query");
    expect(byName("c.example")[0].description).toContain("[outcome not in this record]");
    expect(byName("c.example")[0].severity).toBe("Info");
    expect(r.iocs.map((i) => i.value)).toEqual(
      expect.arrayContaining(["a.example", "b.example", "c.example"]),
    );
  });

  it("an SRV query for DC discovery is a valid name and a domain indicator", () => {
    const r = parseSiemExport(
      elastic(
        dnsClient(3008, {
          QueryName: "_ldap._tcp.dc._msdcs.example",
          QueryType: "33",
          QueryStatus: "0",
          QueryResults: "type: 33 dc01.example;",
        }),
      ),
    );
    expect(r.events[0].description).not.toContain("not a valid name");
    expect(r.iocs.map((i) => i.value)).toContain("_ldap._tcp.dc._msdcs.example");
  });

  it("two TXT values that share 512 characters stay two rows after import; a case-only CNAME churn is one", () => {
    const txt = (t: string) =>
      dnsClient(3008, {
        QueryName: "txt.example",
        QueryType: "16",
        QueryStatus: "0",
        QueryResults: `type: 16 ${"k".repeat(512)}${t};`,
      });
    const r = parseSiemExport(elastic(txt("X"), txt("Y")));
    expect(r.events).toHaveLength(2);
    expect(afterImport(r.events)).toHaveLength(2);
    const cased = ["EDGE.Example", "edge.EXAMPLE", "Edge.example", "edge.example"].map((c, i) =>
      sysmon22(
        { QueryName: "a.example", QueryStatus: "0", QueryResults: `type: 5 ${c};` },
        { ts: `2026-03-01T10:0${i}:00Z` },
      ),
    );
    expect(parseSiemExport(elastic(...cased)).events).toHaveLength(1);
  });

  it("a returned-value tag the row could not fit is lossy: the two records stay two rows after import", () => {
    const eight = (c: string) =>
      dnsClient(3008, {
        QueryName: "txt.example",
        QueryType: "16",
        QueryStatus: "0",
        QueryResults: Array.from({ length: 8 }, (_, i) => `type: 16 ${c.repeat(59)}${i}`).join(";") + ";",
      });
    const r = parseSiemExport(elastic(eight("q"), eight("z")));
    expect(r.events).toHaveLength(2);
    expect(r.events.every((e) => e.description.length <= 600)).toBe(true);
    expect(afterImport(r.events)).toHaveLength(2);
  });

  it("two CNAME targets that differ past the shown width stay two rows after import", () => {
    const rec = (t: string) =>
      sysmon22({
        QueryName: "a.example",
        QueryStatus: "0",
        QueryResults: `type: 5 ${"x".repeat(59)}${t}.example;`,
      });
    const r = parseSiemExport(elastic(rec("1"), rec("2")));
    expect(r.events).toHaveLength(2);
    expect(afterImport(r.events)).toHaveLength(2);
  });

  it("a 3020 whose Status and a stray QueryStatus disagree is a conflict, never a pick", () => {
    const r = parseSiemExport(
      elastic(dnsClient(3020, { QueryName: "b.example", QueryType: "1", Status: "9003", QueryStatus: "0" })),
    );
    expect(r.events[0].description).toContain("[status fields disagree: Status=9003, QueryStatus=0]");
    expect(r.events[0].canonical?.dns?.state).toBe("conflict");
  });

  it("an Application-channel 3008 is not a DNS row", () => {
    const r = parseSiemExport(
      elastic({
        "@timestamp": "2026-03-01T10:00:00Z",
        log_name: "Application",
        computer_name: "WS-01",
        event_id: 3008,
        event_data: { QueryName: "a.example", QueryStatus: "0" },
      }),
    );
    expect(r.events[0].description).not.toContain("[query:");
    expect(r.events[0].canonical?.dns).toBeUndefined();
  });
});
