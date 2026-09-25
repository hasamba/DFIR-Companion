import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { channelTable, DNS_SERVER_EVENTS } from "../../src/analysis/winEventTables.js";
import { canonicalConformanceIssues } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";

// #996 — the DNS Server's own Analytical log (import only this pass, no join). Every fixture is
// parameterized over BOTH export shapes a real Windows Server might produce: named EventData
// (`Name="QNAME"`) and positional (`Data6`, per Microsoft's own message-template ordinals) — see
// dnsServerRecord.ts's header for why neither shape is verified against a real capture.

const elastic = (...rows: object[]) => JSON.stringify(rows.map((r) => ({ _source: r })));

// 257: RESPONSE_SUCCESS: TCP=%1; InterfaceIP=%2; Destination=%3; AA=%4; AD=%5; QNAME=%6; QTYPE=%7;
//      XID=%8; DNSSEC=%9; RCODE=%10; ...
const NAMED_ORDINAL: Record<257 | 258 | 259, Record<string, number>> = {
  257: { Destination: 3, QNAME: 6, QTYPE: 7, XID: 8, RCODE: 10 },
  258: { Reason: 3, Destination: 4, QNAME: 5, QTYPE: 6, XID: 7, RCODE: 8 },
  259: { Reason: 3, QNAME: 4, QTYPE: 5, XID: 6 },
};

const dnsServer = (
  eid: 257 | 258 | 259,
  fields: Record<string, string>,
  over: { ts?: string; host?: string; positional?: boolean } = {},
): object => {
  const ed: Record<string, string> = {};
  for (const [name, value] of Object.entries(fields)) {
    if (over.positional) ed[`Data${NAMED_ORDINAL[eid][name]}`] = value;
    else ed[name] = value;
  }
  return {
    "@timestamp": over.ts ?? "2026-03-01T10:00:00Z",
    log_name: "Microsoft-Windows-DNSServer/Analytical",
    computer_name: over.host ?? "DC-01",
    event_id: eid,
    event_data: ed,
  };
};

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

describe("channel routing (#996)", () => {
  it("Microsoft-Windows-DNSServer/Analytical routes to DNS_SERVER_EVENTS", () => {
    expect(channelTable("Microsoft-Windows-DNSServer/Analytical")).toBe(DNS_SERVER_EVENTS);
  });

  it("does not collide with the DNS-Client channel regex", () => {
    expect(channelTable("Microsoft-Windows-DNSServer/Analytical")).not.toBe(
      channelTable("Microsoft-Windows-DNS-Client/Operational"),
    );
  });

  it("an EID this importer doesn't model (260) still reads as a generic Windows event, not dropped", () => {
    const r = parseSiemExport(
      elastic({
        "@timestamp": "2026-03-01T10:00:00Z",
        log_name: "Microsoft-Windows-DNSServer/Analytical",
        computer_name: "DC-01",
        event_id: 260,
        event_data: { QNAME: "example.com." },
      }),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].canonical?.dns).toBeUndefined();
  });
});

for (const positional of [false, true]) {
  const shape = positional ? "positional Data1..17" : "named";

  describe(`257 response success — ${shape} fields`, () => {
    it("reads client/query/type/xid/rcode; returned stays empty", () => {
      const r = parseSiemExport(
        elastic(
          dnsServer(
            257,
            { Destination: "10.0.0.42", QNAME: "cdn.example.net.", QTYPE: "1", XID: "12345", RCODE: "0" },
            { positional },
          ),
        ),
      );
      expect(r.events).toHaveLength(1);
      const e = r.events[0];
      expect(e.canonical?.dns).toMatchObject({
        vantage: "resolver",
        query: "cdn.example.net",
        queryType: 1,
        client: "10.0.0.42",
        xid: "12345",
        rcode: "NOERROR",
        state: "answered",
        returned: [],
      });
      expect(e.description).toContain("[query: cdn.example.net.]");
      expect(e.description).toContain("asked by 10.0.0.42");
      expect(e.description).toContain("the returned values are not read by this importer");
      expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
    });

    it("an RCODE outside the known table shows undecoded, never crashes", () => {
      const r = parseSiemExport(
        elastic(
          dnsServer(
            257,
            { Destination: "10.0.0.42", QNAME: "x.example.", QTYPE: "1", XID: "1", RCODE: "9" },
            { positional },
          ),
        ),
      );
      expect(r.events).toHaveLength(1);
      expect(r.events[0].canonical?.dns?.rcode).toBe("RCODE 9");
    });

    it("XID '0' is a real transaction id, not a missing field — the string '0' is truthy", () => {
      const r = parseSiemExport(
        elastic(
          dnsServer(
            257,
            { Destination: "10.0.0.42", QNAME: "x.example.", QTYPE: "1", XID: "0", RCODE: "0" },
            { positional },
          ),
        ),
      );
      expect(r.events[0].canonical?.dns?.xid).toBe("0");
    });
  });

  describe(`258 response failure — ${shape} fields`, () => {
    it("reads Reason and RCODE, state is a failure", () => {
      const r = parseSiemExport(
        elastic(
          dnsServer(
            258,
            {
              Reason: "server failure",
              Destination: "10.0.0.42",
              QNAME: "bad.example.",
              QTYPE: "1",
              XID: "77",
              RCODE: "2",
            },
            { positional },
          ),
        ),
      );
      expect(r.events).toHaveLength(1);
      const dns = r.events[0].canonical?.dns;
      expect(dns).toMatchObject({
        vantage: "resolver",
        client: "10.0.0.42",
        rcode: "SERVFAIL",
        state: "response failure",
      });
      expect(r.events[0].description).toContain("server failure");
    });
  });

  describe(`259 ignored query — ${shape} fields`, () => {
    it("carries no client address — disclosed, not silently blank", () => {
      const r = parseSiemExport(
        elastic(
          dnsServer(
            259,
            { Reason: "policy", QNAME: "ignored.example.", QTYPE: "1", XID: "9" },
            { positional },
          ),
        ),
      );
      expect(r.events).toHaveLength(1);
      const dns = r.events[0].canonical?.dns;
      expect(dns).toMatchObject({ vantage: "resolver", state: "ignored" });
      expect(dns?.client).toBeUndefined();
      expect(r.events[0].description).toContain("no client address in this record");
    });
  });
}

describe("forensic timeline placement (#996)", () => {
  it("a resolver row survives correlateEvents and lands in the forensic timeline", () => {
    const r = parseSiemExport(
      elastic(
        dnsServer(257, {
          Destination: "10.0.0.42",
          QNAME: "cdn.example.net.",
          QTYPE: "1",
          XID: "1",
          RCODE: "0",
        }),
      ),
    );
    const events = afterImport(r.events);
    expect(events).toHaveLength(1);
    expect(events[0].canonical?.dns?.vantage).toBe("resolver");
  });
});

// #1643: a resolver-vantage record is not an endpoint query. It must not take part in the
// endpoint DNS→connection join (siemDnsConnJoin.ts) at all — no join state, no join wording, no
// `|conn:` fold in its key — even when the same host logged a connection in the same upload.
const sysmon = (eid: 3 | 22, ed: Record<string, string>, ts: string): object => ({
  "@timestamp": ts,
  log_name: "Microsoft-Windows-Sysmon/Operational",
  computer_name: "DC-01",
  event_id: eid,
  event_data: { Image: "C:\\Windows\\System32\\svchost.exe", ProcessId: "1234", ...ed },
});

const SERVER_FIELDS: Record<257 | 258 | 259, Record<string, string>> = {
  257: { Destination: "10.0.0.42", QNAME: "srv.example.net.", QTYPE: "1", XID: "7", RCODE: "0" },
  258: { Reason: "2", Destination: "10.0.0.42", QNAME: "srv.example.net.", QTYPE: "1", XID: "7", RCODE: "3" },
  259: { Reason: "2", QNAME: "srv.example.net.", QTYPE: "1", XID: "7" },
};

describe("resolver records stay out of the endpoint DNS→connection join (#1643)", () => {
  for (const eid of [257, 258, 259] as const) {
    for (const positional of [false, true]) {
      it(`DNS Server ${eid} (${positional ? "positional" : "named"}) gets no join state`, () => {
        const r = parseSiemExport(
          elastic(
            dnsServer(eid, SERVER_FIELDS[eid], { positional }),
            sysmon(
              22,
              { QueryName: "ep.example.com", QueryStatus: "0", QueryResults: "::ffff:203.0.113.9;" },
              "2026-03-01T10:00:01Z",
            ),
            sysmon(
              3,
              { Protocol: "tcp", Initiated: "true", DestinationIp: "203.0.113.9", DestinationPort: "443" },
              "2026-03-01T10:00:05Z",
            ),
          ),
        );
        const server = r.events.find((e) => e.canonical?.dns?.vantage === "resolver")!;
        expect(server).toBeDefined();
        expect(server.canonical?.dns?.joinState).toBeUndefined();
        expect(server.canonical?.dns?.leads).toBeUndefined();
        expect(server.canonical?.fieldProvenance?.["dns.joinState"]).toBeUndefined();
        expect(server.canonical?.fieldProvenance?.["dns.leads"]).toBeUndefined();
        expect(server.aggKey).not.toContain("|conn:");
        expect(server.description).not.toMatch(/no address|connection record/i);
        expect(canonicalConformanceIssues(server.canonical)).toEqual([]);
        // its query IOC still links to its own final row
        expect(r.iocs.find((i) => i.value === "srv.example.net")?.sourceAggKeys).toContain(server.aggKey);
        // control: the endpoint query in the same upload still joins
        const endpoint = r.events.find((e) => e.canonical?.dns?.vantage === "endpoint")!;
        expect(endpoint.canonical?.dns?.joinState).toBe("joined");
      });
    }
  }
});
