import { describe, expect, it } from "vitest";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { CONN_INDEX_MAX, DNS_OBSERVATIONS_MAX, gapBand } from "../../src/analysis/dnsConnJoin.js";
import { replyOfConnState, ttlOf, rttOf } from "../../src/analysis/dnsWireRead.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// ── fixtures ────────────────────────────────────────────────────────────────

const T0 = 1512115200; // 2017-12-01T08:00:00Z
const CLIENT = "10.0.0.5";
const SERVER = "10.0.0.1";
const A1 = "93.184.216.34";
const A2 = "198.51.100.7";

type Row = Record<string, unknown>;

function zeekDns(over: Row = {}): Row {
  return {
    ts: T0,
    _path: "dns",
    uid: "D1",
    "id.orig_h": CLIENT,
    "id.resp_h": SERVER,
    "id.resp_p": 53,
    query: "www.example.com",
    qtype_name: "A",
    rcode_name: "NOERROR",
    AA: false,
    RA: true,
    rejected: false,
    rtt: 0.02,
    answers: [A1],
    TTLs: [300],
    ...over,
  };
}
function zeekConn(over: Row = {}): Row {
  return {
    ts: T0 + 3,
    _path: "conn",
    uid: "C1",
    "id.orig_h": CLIENT,
    "id.resp_h": A1,
    "id.resp_p": 443,
    proto: "tcp",
    conn_state: "SF",
    duration: 2,
    ...over,
  };
}
const ndjson = (rows: Row[]): string => rows.map((r) => JSON.stringify(r)).join("\n");
const parse = (rows: Row[]) => parseNetworkLogs(ndjson(rows));
const dnsRows = (rows: Row[]) => parse(rows).events.filter((e) => e.description.startsWith("DNS "));
const one = (rows: Row[]) => {
  const r = dnsRows(rows);
  expect(r).toHaveLength(1);
  return r[0];
};

// ── the row ─────────────────────────────────────────────────────────────────

describe("a Zeek dns.log record is an Info exchange row", () => {
  it("says the ends, the query, the type, the outcome and the returned values — never resolves to", () => {
    const e = one([zeekDns()]);
    expect(e.severity).toBe("Info");
    expect(e.mitreTechniques ?? []).toEqual([]);
    expect(e.description).toContain(`DNS ${CLIENT} → ${SERVER}: [query: www.example.com] A → answered`);
    expect(e.description).toContain(`[returned: ${A1}]`);
    expect(e.description).not.toMatch(/resolves|C2|beacon|malicious/i);
    expect(e.description).toMatch(/ #[A-Za-z0-9_-]{22}$/); // identity mark
    expect(e.canonical?.dns?.vantage).toBe("sensor");
    expect(e.canonical?.dns?.ownership).toBe("not in this record");
    expect(e.canonical?.dns?.anchor).toBe("query");
    expect(e.canonical?.dns?.client).toBe(CLIENT);
    expect(e.canonical?.dns?.server).toBe(SERVER);
    expect(e.canonical?.network?.destination?.address).toBe(SERVER); // the server asked, never an answer
    expect(e.srcIp).toBe(CLIENT);
    expect(e.dstIp).toBe(SERVER);
  });

  it("NXDOMAIN, SERVFAIL, REFUSED, rejected, no response and NODATA each say what the record says", () => {
    const words = (over: Row) => one([zeekDns({ answers: undefined, TTLs: undefined, ...over })]).description;
    expect(words({ rcode_name: "NXDOMAIN" })).toContain(
      "→ NXDOMAIN — the name does not exist at this server",
    );
    expect(words({ rcode_name: "SERVFAIL" })).toContain("→ SERVFAIL — server failure");
    expect(words({ rcode_name: "REFUSED" })).toContain("→ REFUSED");
    expect(words({ rejected: true })).toContain("→ rejected by the server");
    expect(words({ rcode_name: undefined })).toContain("→ no response recorded");
    expect(words({ rcode_name: "NOERROR" })).toContain("→ NOERROR — no records of the queried type");
    // an unknown code is shown inside its own span, never read as success or failure
    expect(words({ rcode_name: "BADVERS] [returned: 1.2.3.4" })).toContain(
      "→ [rcode: BADVERS) (RETURNED: 1.2.]",
    ); // neutralised, bounded
  });

  it("a query that is not a valid name is shown neutralised, marked, and mints nothing", () => {
    const r = parse([
      zeekDns({ query: "good.example] [returned: 1.2.3.4", answers: undefined, TTLs: undefined }),
    ]);
    const e = r.events.find((x) => x.description.startsWith("DNS "))!;
    expect(e.description).toContain("[query: good.example) (returned: 1.2.3.4]");
    expect(e.description).toContain("[query name is not a valid name]");
    expect(r.iocs).toEqual([]);
  });

  it("mints the query as a domain indicator against the row key, by the one rule (wire form)", () => {
    const r = parse([zeekDns({ query: "Bücher.Example.COM" })]);
    const row = r.events.find((x) => x.description.startsWith("DNS "))!;
    expect(r.iocs).toHaveLength(1);
    expect(r.iocs[0]).toMatchObject({ type: "domain", value: "xn--bcher-kva.example.com" });
    expect(r.iocs[0].sourceAggKeys).toEqual([row.aggKey]);
  });

  it("a single-label query is a valid query and no indicator", () => {
    const r = parse([zeekDns({ query: "wpad" })]);
    expect(r.iocs).toEqual([]);
    expect(dnsRows([zeekDns({ query: "wpad" })])[0].description).not.toContain("not a valid name");
  });

  it("owner-less values: a CNAME step and an address read as returned, in record order, bounded to 8 shown", () => {
    const many = Array.from({ length: 12 }, (_, i) => `203.0.113.${i + 1}`);
    const e = one([zeekDns({ answers: ["cdn.example.net", ...many], TTLs: [60, ...many.map(() => 300)] })]);
    expect(e.description).toContain("[returned: cdn.example.net, 203.0.113.1, 203.0.113.2");
    expect(e.description).toContain("+5 more]");
    expect(e.canonical?.dns?.returnedTotal).toBe(13);
    // the TTL range is the one the windows were read against: addresses only, never a CNAME's
    expect(e.canonical?.dns?.ttl).toEqual({ min: 300, max: 300 });
  });

  it("more than 32 returned values: the rest are counted as not read and the identity still covers them", () => {
    const a = Array.from({ length: 40 }, (_, i) => `203.0.113.${i + 1}`);
    const b = [...a.slice(0, 39), "203.0.113.200"];
    const rows = dnsRows([
      zeekDns({ answers: a, TTLs: a.map(() => 60) }),
      zeekDns({ uid: "D2", answers: b, TTLs: b.map(() => 60) }),
    ]);
    expect(rows).toHaveLength(2);
    expect(rows[0].description).toContain("+32 more (not read)]");
  });

  it("flags: an authoritative answer is said; RA is envelope only", () => {
    const e = one([zeekDns({ AA: true })]);
    expect(e.description).toContain("[authoritative answer]");
    expect(e.canonical?.dns?.flags).toEqual({ aa: true, ra: true, rejected: false });
  });
});

// ── the join ────────────────────────────────────────────────────────────────

describe("the query → connection lead inside one upload", () => {
  it("a connection from the same client to a returned address inside the TTL window is the lead, with the reply", () => {
    const e = one([zeekDns(), zeekConn()]);
    expect(e.description).toContain(
      `[${A1}: connection record ≤10 s after the answer arrived, inside the window — answered by the peer]`,
    );
    expect(e.description).toContain("[window: TTL 300 s +1 s]");
    const lead = e.canonical?.dns?.leads?.[0];
    expect(lead).toMatchObject({
      address: A1,
      state: "connected inside the window",
      band: "≤10 s",
      reply: "answered by the peer",
      window: { basis: "ttl", slackSeconds: 1 },
    });
    // the connection record is in the envelope's evidence, attributed to the lead
    expect(e.canonical?.evidence.rawRecords.map((r) => r.locator)).toEqual(["record:0", "record:1"]);
    expect(e.canonical?.fieldProvenance["dns.leads"]?.recordLocators).toEqual(["record:0", "record:1"]);
  });

  it("a lone SYN is a connection record with no reply, never a connection", () => {
    const e = one([zeekDns(), zeekConn({ conn_state: "S0", duration: undefined })]);
    expect(e.description).toContain("inside the window — no reply from the peer]");
    expect(e.description).not.toMatch(/\bconnected\b/);
  });

  it("the window opens when the answer arrived: a flow that began between the query and the answer did not wait for it", () => {
    const e = one([zeekDns({ rtt: 0.8 }), zeekConn({ ts: T0 + 0.2 })]);
    expect(e.description).toContain(
      `[${A1}: a connection record began before this answer arrived — answered by the peer]`,
    );
  });

  it("a connection just outside the window is said as after the window, with the gap band", () => {
    const e = one([zeekDns(), zeekConn({ ts: T0 + 0.02 + 300 + 1 + 0.5 })]);
    expect(e.description).toContain(
      `[${A1}: first connection record ≤10 min after the answer arrived — after the window`,
    );
    expect(e.canonical?.dns?.leads?.[0].state).toBe("first connection after the window");
  });

  it("TTL 0 with a connection in the same second is inside the window by the stated slack", () => {
    const e = one([zeekDns({ TTLs: [0] }), zeekConn({ ts: T0 + 0.5 })]);
    expect(e.description).toContain("inside the window");
    expect(e.description).toContain("[window: TTL 0 s +1 s]");
  });

  it("no TTL in the record: a fixed window, worded as fixed", () => {
    const e = one([zeekDns({ TTLs: undefined }), zeekConn({ ts: T0 + 200 })]);
    expect(e.description).toContain("inside the window");
    expect(e.description).toContain("[window: fixed 300 s — no TTL in this record]");
    expect(e.canonical?.dns?.leads?.[0]?.window?.basis).toBe("fixed");
  });

  it("a TTL list that does not align with the answers leaves them without a TTL", () => {
    const e = one([zeekDns({ answers: [A1, A2], TTLs: [300] })]);
    expect(e.canonical?.dns?.ttl).toBeUndefined();
  });

  it("invalid TTLs and round trips are not in the record", () => {
    expect(ttlOf(-1)).toBeUndefined();
    expect(ttlOf(2 ** 31)).toBeUndefined();
    expect(ttlOf("300")).toBe(300);
    expect(ttlOf(1.5)).toBeUndefined();
    expect(rttOf(61)).toBeUndefined();
    expect(rttOf(0.02)).toBe(0.02);
    const e = one([zeekDns({ TTLs: [-5] }), zeekConn({ ts: T0 + 200 })]);
    expect(e.description).toContain("[window: fixed 300 s — no TTL in this record]");
  });

  it("changing answers: a connection matches the answer in force at that time, not any answer ever seen", () => {
    const morning = zeekDns({ uid: "D1", ts: T0, answers: [A1], TTLs: [300] });
    const noon = zeekDns({ uid: "D2", ts: T0 + 4 * 3600, answers: [A2], TTLs: [300] });
    const rows = dnsRows([morning, noon, zeekConn({ ts: T0 + 4 * 3600 + 5, "id.resp_h": A2 })]);
    expect(rows).toHaveLength(2);
    const m = rows.find((r) => r.description.includes(`[returned: ${A1}]`))!;
    const n = rows.find((r) => r.description.includes(`[returned: ${A2}]`))!;
    expect(m.description).toContain(`[${A1}: no connection from ${CLIENT} in this upload]`);
    expect(n.description).toContain(
      `[${A2}: connection record ≤10 s after the answer arrived, inside the window`,
    );
  });

  it("a cached answer: the client connected before this query only", () => {
    const e = one([zeekDns({ ts: T0 + 100 }), zeekConn({ ts: T0 + 3 })]);
    expect(e.description).toContain(`[${A1}: earlier connection records only — none after this answer]`);
  });

  it("a connection open at the time of the answer is said as such, not as none after", () => {
    const e = one([zeekDns({ ts: T0 + 100 }), zeekConn({ ts: T0 + 3, duration: 600 })]);
    expect(e.description).toContain(
      `[${A1}: a connection open at the time of this answer — started before it — answered by the peer]`,
    );
  });

  it("the DNS exchange's own connection is never the lead", () => {
    // the answer is the server asked; the query's own conn (shared uid) must not read as a contact
    const e = one([
      zeekDns({ answers: [SERVER], TTLs: [300] }),
      zeekConn({ uid: "D1", ts: T0, "id.resp_h": SERVER, "id.resp_p": 53, proto: "udp", duration: 0.02 }),
    ]);
    expect(e.description).toContain(`[${SERVER}: no connection from ${CLIENT} in this upload]`);
  });

  it("a forwarding resolver: other clients connected inside the window is said only when the client is also a queried server", () => {
    const forwarder = "10.0.0.1";
    const upstream = "192.0.2.53";
    // the forwarder asks upstream; a workstation asked the forwarder (so it IS a server); the workstation connects
    const rows = [
      zeekDns({ uid: "D1", "id.orig_h": forwarder, "id.resp_h": upstream }),
      zeekDns({ uid: "D2", ts: T0 - 1, "id.orig_h": "10.0.0.7", "id.resp_h": forwarder }),
      zeekConn({ "id.orig_h": "10.0.0.7" }),
    ];
    const f = dnsRows(rows).find((r) => r.description.startsWith(`DNS ${forwarder} → ${upstream}`))!;
    expect(f.description).toContain(
      `[${A1}: no connection from ${forwarder}; other clients connected inside the window — the record does not say they used this answer]`,
    );
    // a plain endpoint client never gets the suffix, even when other hosts connected
    const e = one([zeekDns(), zeekConn({ "id.orig_h": "10.0.0.7" })]);
    expect(e.description).toContain(`[${A1}: no connection from ${CLIENT} in this upload]`);
  });

  it("an address also returned for another name to the same client inside the window is said", () => {
    const rows = [zeekDns(), zeekDns({ uid: "D2", ts: T0 + 10, query: "cdn.example.org" }), zeekConn()];
    const r = dnsRows(rows);
    expect(r.find((x) => x.description.includes("www.example.com"))!.description).toContain(
      "inside the window — answered by the peer — also returned for other names to this client inside the window]",
    );
  });

  it("no address returned: no lead can be matched and the row says so", () => {
    const e = one([zeekDns({ answers: ["cdn.example.net"], TTLs: [60] }), zeekConn()]);
    expect(e.description).toContain("[no address returned — no connection can be matched]");
    expect(e.canonical?.dns?.joinState).toBe("answered with no address");
  });

  it("an upload with no connection records says the join was not attempted, once, not per address", () => {
    const e = one([zeekDns({ answers: [A1, A2], TTLs: [300, 300] })]);
    expect(e.description).toContain("[connection join: no connection records in this upload]");
    expect(e.description).not.toContain("no connection from");
    expect(e.canonical?.dns?.leads).toEqual([]);
  });

  it("records from two sensors never join", () => {
    const e = one([zeekDns({ "observer.name": "sensor-a" }), zeekConn({ "observer.name": "sensor-b" })]);
    expect(e.description).toContain(`[${A1}: no connection from ${CLIENT} in this upload]`);
  });

  it("in-window leads are worded first, then the rest", () => {
    const e = one([zeekDns({ answers: [A2, A1], TTLs: [300, 300] }), zeekConn()]);
    expect(e.description.indexOf(`[${A1}:`)).toBeLessThan(e.description.indexOf(`[${A2}:`));
  });

  it("gap bands", () => {
    expect(gapBand(500)).toBe("≤1 s");
    expect(gapBand(10_000)).toBe("≤10 s");
    expect(gapBand(59_000)).toBe("≤60 s");
    expect(gapBand(599_000)).toBe("≤10 min");
    expect(gapBand(3_599_000)).toBe("≤1 h");
    expect(gapBand(86_400_000)).toBe("≤24 h");
    expect(gapBand(86_400_001)).toBe(">24 h");
  });

  it("conn_state reply classes", () => {
    expect(replyOfConnState("SF")).toBe("answered by the peer");
    expect(replyOfConnState("REJ")).toBe("no reply from the peer");
    expect(replyOfConnState("RSTOS0")).toBe("no reply from the peer");
    expect(replyOfConnState(undefined)).toBe("reply not in this record");
    expect(replyOfConnState("XYZ")).toBe("reply not in this record");
  });
});

// ── folding and identity ────────────────────────────────────────────────────

describe("folding", () => {
  it("two identical re-queries with the same lead are one row with a count; the TTL counting down does not split them", () => {
    const rows = [
      zeekDns({ uid: "D1", ts: T0, TTLs: [300] }),
      zeekConn({ uid: "C1", ts: T0 + 3 }),
      zeekDns({ uid: "D2", ts: T0 + 60, TTLs: [240] }),
      zeekConn({ uid: "C2", ts: T0 + 63 }),
    ];
    const r = dnsRows(rows);
    expect(r).toHaveLength(1);
    expect(r[0].description).toContain("— 2 records");
    expect(r[0].description).toContain("[window: TTL 240–300 s +1 s]");
  });

  it("a different lead state is a different row", () => {
    const rows = [
      zeekDns({ uid: "D1", ts: T0 }),
      zeekConn({ ts: T0 + 3 }),
      zeekDns({ uid: "D2", ts: T0 + 7200 }),
    ];
    expect(dnsRows(rows)).toHaveLength(2);
  });

  it("the same name with a different answer set is a different row; case and order do not split", () => {
    const rows = [
      zeekDns({ uid: "D1", answers: [A1, A2], TTLs: [300, 300] }),
      zeekDns({ uid: "D2", query: "WWW.EXAMPLE.COM", answers: [A2, A1], TTLs: [300, 300] }),
      zeekDns({ uid: "D3", answers: [A1], TTLs: [300] }),
    ];
    expect(dnsRows(rows)).toHaveLength(2);
  });

  it("a hash-shaped TXT value cannot join the row to a file event through the merge", () => {
    const e = one([
      zeekDns({ qtype_name: "TXT", answers: ["d41d8cd98f00b204e9800998ecf8427e"], TTLs: [60] }),
    ]);
    const dns: ForensicEvent = {
      ...e,
      id: "d",
      asset: "sensor",
    } as ForensicEvent;
    const file: ForensicEvent = {
      id: "f",
      timestamp: e.timestamp,
      description: "File written",
      severity: "Info",
      asset: "sensor",
      md5: "d41d8cd98f00b204e9800998ecf8427e",
      mitreTechniques: [],
      sources: ["Velociraptor"],
      origin: "host",
    } as unknown as ForensicEvent;
    expect(correlateEvents([dns, file])).toHaveLength(2);
  });
});

// ── code round 1 ────────────────────────────────────────────────────────────

describe("code review round", () => {
  it("a loopback / link-local / multicast client is not joinable — never 'no address returned'", () => {
    for (const client of ["127.0.0.1", "fe80::1", "::1", "169.254.1.2"]) {
      const e = one([zeekDns({ "id.orig_h": client, "id.resp_h": "ff02::fb" }), zeekConn()]);
      expect(e.description).toContain(`DNS ${client} → ff02::fb:`);
      expect(e.description).toContain(`[returned: ${A1}]`);
      expect(e.description).toContain(
        "[connection join: the asking address is not one a sensor's connection records can be matched to",
      );
      expect(e.description).not.toContain("no address returned");
      expect(e.canonical?.dns?.joinState).toBe("client not joinable");
    }
  });

  it("'open at the time' names the record that WAS open, with its reply — not the latest earlier one", () => {
    const rows: Row[] = [
      zeekDns({ ts: T0 }),
      zeekConn({ uid: "LONG", ts: T0 - 2000, duration: 3000, conn_state: "S1" }),
    ];
    for (let i = 0; i < 70; i++)
      rows.push(zeekConn({ uid: `S${i}`, ts: T0 - 1000 + i, duration: 0.5, conn_state: "REJ" }));
    const e = one(rows);
    expect(e.description).toContain(
      `[${A1}: a connection open at the time of this answer — started before it — answered by the peer]`,
    );
    expect(e.canonical?.evidence.rawRecords.map((r) => r.recordId)).toEqual(["D1", "LONG"]);
  });

  it("an in-window contact is always said, with 'also began before' beside it, and ranks first", () => {
    const e = one([
      zeekDns({ rtt: 0.8 }),
      zeekConn({ uid: "C0", ts: T0 + 0.2, conn_state: "REJ", duration: 0.1 }),
      zeekConn({ uid: "C1", ts: T0 + 5 }),
    ]);
    expect(e.description).toContain(
      `[${A1}: connection record ≤10 s after the answer arrived, inside the window — answered by the peer; a record also began before this answer arrived]`,
    );
    expect(e.canonical?.dns?.leads?.[0]).toMatchObject({
      state: "connected inside the window",
      alsoBefore: "began before this answer arrived",
    });
  });

  it("a beacon — one name every second, a 2 s connection each time — says the in-window lead on every row", () => {
    const rows: Row[] = [];
    for (let i = 0; i < 2000; i++) {
      rows.push(zeekDns({ uid: `D${i}`, ts: T0 + i, rtt: 0.01 }));
      rows.push(zeekConn({ uid: `C${i}`, ts: T0 + i + 0.1, duration: 2 }));
    }
    const started = Date.now();
    const r = dnsRows(rows);
    expect(Date.now() - started).toBeLessThan(5000);
    // the first exchange had nothing open yet; every later one also had the previous beacon open
    expect(r).toHaveLength(2);
    const steady = r.find((x) => x.description.includes("— 1999 records"))!;
    expect(steady.description).toContain(
      `[${A1}: connection record ≤1 s after the answer arrived, inside the window — answered by the peer; a connection was also open at the time of this answer]`,
    );
  });

  it("the same address answered at 09:00 and 12:58 with a connection at 13:00: the 12:58 answer is the lead, the 09:00 one is 'after the window'", () => {
    const rows = [
      zeekDns({ uid: "D1", ts: T0 + 3600 }),
      zeekDns({ uid: "D2", ts: T0 + 3600 + 3 * 3600 + 58 * 60 }),
      zeekConn({ ts: T0 + 3600 + 4 * 3600 }),
    ];
    const r = dnsRows(rows);
    expect(r).toHaveLength(2);
    expect(
      r.some((x) =>
        x.description.includes("first connection record ≤24 h after the answer arrived — after the window"),
      ),
    ).toBe(true);
    expect(
      r.some((x) =>
        x.description.includes("connection record ≤10 min after the answer arrived, inside the window"),
      ),
    ).toBe(true);
  });

  it("a v6 answer joins a v6 connection whatever the case the records wrote it in", () => {
    const e = one([
      zeekDns({ answers: ["2606:2800:220:1:248:1893:25C8:1946"], TTLs: [300] }),
      zeekConn({ "id.resp_h": "2606:2800:220:1:248:1893:25c8:1946" }),
    ]);
    expect(e.description).toContain(
      "[2606:2800:220:1:248:1893:25c8:1946: connection record ≤10 s after the answer arrived, inside the window",
    );
  });

  it("a TXT answer that spells an address is data, not a lead", () => {
    const e = one([zeekDns({ qtype_name: "TXT", answers: [A1], TTLs: [60] }), zeekConn()]);
    expect(e.description).toContain("[no address returned — no connection can be matched]");
    expect(e.canonical?.dns?.returned[0]?.kind).toBe("other");
  });

  it("the sensor is shown, and Suricata's bare host names it", () => {
    const e = one([zeekDns({ "observer.name": "sensor-a" }), zeekConn({ "observer.name": "sensor-a" })]);
    expect(e.description).toMatch(/ @ sensor-a — 1 record #/);
    expect(e.canonical?.dns?.sensor).toBe("sensor-a");
    const s = one([zeekDns({ host: "sensor-b" }), zeekConn({ host: "sensor-c" })]);
    expect(s.description).toContain(`[${A1}: no connection from ${CLIENT} in this upload]`);
  });

  it("'-' placeholders are absent, not values", () => {
    const e = one([zeekDns({ rcode_name: "-", qtype_name: "-", answers: undefined, TTLs: undefined })]);
    expect(e.description).toContain("[query: www.example.com] → no response recorded");
  });

  it("the own exchange is never 'other clients connected'", () => {
    const forwarder = "10.0.0.1";
    const rows = [
      zeekDns({ uid: "D1", "id.orig_h": forwarder, "id.resp_h": A1, answers: [A1], TTLs: [300] }),
      zeekDns({ uid: "D2", ts: T0 - 1, "id.orig_h": "10.0.0.7", "id.resp_h": forwarder }),
      zeekConn({
        uid: "D1",
        ts: T0,
        "id.orig_h": forwarder,
        "id.resp_h": A1,
        "id.resp_p": 53,
        proto: "udp",
        duration: 0.02,
      }),
    ];
    const f = dnsRows(rows).find((r) => r.description.startsWith(`DNS ${forwarder} → ${A1}`))!;
    expect(f.description).toContain(`[${A1}: no connection from ${forwarder} in this upload]`);
  });

  it("an old endpoint envelope still validates against the widened block", async () => {
    const { canonicalEventEnvelopeSchema } = await import("../../src/analysis/canonicalEvent.js");
    const { createCanonicalEvent } = await import("../../src/analysis/canonicalEvent.js");
    const env = createCanonicalEvent({
      event: { category: "network", type: "query" },
      dns: {
        query: "a.example",
        queryValid: true,
        indicator: true,
        state: "success",
        returned: [],
        ownership: "not in this record",
        vantage: "endpoint",
      },
      time: { observed: "2026-01-01T00:00:00Z", normalized: "2026-01-01T00:00:00.000Z" },
      evidence: { rawRecords: [{ source: "sysmon", locator: "record:0" }] },
      producer: { importer: "siem", parserVersion: "1", mappingVersion: "t" },
    });
    expect(canonicalEventEnvelopeSchema.safeParse(env).success).toBe(true);
  });
});

// ── Suricata ────────────────────────────────────────────────────────────────

describe("Suricata dns and flow", () => {
  const stamp = (offset: number) => new Date((T0 + offset) * 1000).toISOString().replace("Z", "+0000");
  function v2Answer(over: Row = {}, dns: Row = {}): Row {
    return {
      timestamp: stamp(0),
      event_type: "dns",
      flow_id: 1,
      src_ip: SERVER,
      src_port: 53,
      dest_ip: CLIENT,
      dest_port: 51000,
      proto: "UDP",
      dns: {
        version: 2,
        type: "answer",
        id: 7,
        rrname: "www.example.com",
        rrtype: "A",
        rcode: "NOERROR",
        ra: true,
        answers: [
          { rrname: "www.example.com", rrtype: "CNAME", ttl: 60, rdata: "cdn.example.net" },
          { rrname: "cdn.example.net", rrtype: "A", ttl: 300, rdata: A1 },
        ],
        ...dns,
      },
      ...over,
    };
  }
  function flow(over: Row = {}, f: Row = {}): Row {
    return {
      timestamp: stamp(120),
      event_type: "flow",
      flow_id: 2,
      src_ip: CLIENT,
      src_port: 51001,
      dest_ip: A1,
      dest_port: 443,
      proto: "TCP",
      flow: { pkts_toserver: 5, pkts_toclient: 4, start: stamp(3), end: stamp(5), state: "closed" },
      ...f,
      ...over,
    };
  }

  it("a v2 answer with owners reads as answers, the client is the non-53 side, and a flow is the lead", () => {
    const e = one([v2Answer(), flow()]);
    expect(e.description).toContain(`DNS ${CLIENT} → ${SERVER}: [query: www.example.com] A → answered`);
    expect(e.description).toContain(
      `[answers: www.example.com CNAME cdn.example.net; cdn.example.net A ${A1}]`,
    );
    expect(e.description).toContain(
      `[${A1}: connection record ≤10 s after the answer arrived, inside the window — answered by the peer]`,
    );
    expect(e.canonical?.dns?.ownership).toBe("stated in the record");
    expect(e.canonical?.dns?.anchor).toBe("answer");
    expect(e.sources).toEqual(["Suricata"]);
  });

  it("the client is the non-53 side in both shapes; ambiguous ports assert no client", () => {
    const flowDirection = one([
      v2Answer({ src_ip: CLIENT, src_port: 51000, dest_ip: SERVER, dest_port: 53 }),
      flow(),
    ]);
    expect(flowDirection.description).toContain(`DNS ${CLIENT} → ${SERVER}:`);
    expect(flowDirection.description).toContain("inside the window");
    const ambiguous = one([v2Answer({ src_port: 53, dest_port: 53 }), flow()]);
    expect(ambiguous.description).toContain(`DNS ${SERVER} ↔ ${CLIENT} (direction not in this record):`);
    expect(ambiguous.canonical?.dns?.joinState).toBe("client not joinable");
    expect(ambiguous.description).not.toContain("no connection from");
  });

  it("a v1 per-RR answer event carries the RR owner, not the question: no query is asserted and nothing is minted", () => {
    const r = parse([
      v2Answer(
        {},
        { version: 1, answers: undefined, rrname: "cdn.example.net", rrtype: "A", rdata: A1, ttl: 300 },
      ),
    ]);
    const e = r.events[0];
    expect(e.description).toContain(
      "[query: (not in this record)] → answered [answers: cdn.example.net A 93.184.216.34]",
    );
    expect(r.iocs).toEqual([]);
  });

  it("a flow with no start time is not placeable — the row never says the upload had no connection records", () => {
    const e = one([v2Answer(), flow({}, { flow: { pkts_toserver: 5, pkts_toclient: 4, state: "closed" } })]);
    expect(e.description).toContain(
      "[connection join: the upload's connection records carry no start time — not joined]",
    );
  });

  it("an answer event with no rcode says the code is not in the record — the event is the response", () => {
    const e = one([v2Answer({}, { rcode: undefined })]);
    expect(e.description).toContain("→ response code not in this record");
  });

  it("a flow with no packets to the client is no reply", () => {
    const e = one([
      v2Answer(),
      flow({}, { flow: { pkts_toserver: 1, pkts_toclient: 0, start: stamp(3), state: "new" } }),
    ]);
    expect(e.description).toContain("inside the window — no reply from the peer]");
  });

  it("a v3 response reads queries[] and a query event stays IOC-only (v3 too)", () => {
    const v3 = v2Answer(
      {},
      {
        version: 3,
        type: "response",
        rrname: undefined,
        rrtype: undefined,
        queries: [{ rrname: "www.example.com", rrtype: "A" }],
      },
    );
    expect(one([v3]).description).toContain("[query: www.example.com] A → answered");
    const q = {
      timestamp: stamp(0),
      event_type: "dns",
      src_ip: CLIENT,
      dest_ip: SERVER,
      dns: { version: 3, type: "request", queries: [{ rrname: "evil.example", rrtype: "A" }] },
    };
    const r = parse([q]);
    expect(r.events).toHaveLength(0);
    expect(r.iocs).toEqual([{ type: "domain", value: "evil.example" }]);
  });

  it("v2 grouped without answers has no TTL and a fixed window; v1 top-level rdata is read", () => {
    const grouped = one([v2Answer({}, { answers: undefined, grouped: { A: [A1] } }), flow()]);
    expect(grouped.description).toContain("[window: fixed 300 s — no TTL in this record]");
    const v1 = one([v2Answer({}, { version: 1, answers: undefined, rdata: A1, ttl: 300 })]);
    expect(v1.description).toContain(
      `[query: (not in this record)] → answered [answers: www.example.com A ${A1}]`,
    );
  });

  it("a netflow record is a connection with no reply fact", () => {
    const nf = {
      timestamp: stamp(120),
      event_type: "netflow",
      src_ip: CLIENT,
      dest_ip: A1,
      dest_port: 443,
      proto: "TCP",
      netflow: { pkts: 3, bytes: 300, start: stamp(3), end: stamp(4) },
    };
    const e = one([v2Answer(), nf]);
    expect(e.description).toContain(
      `[${A1}: connection record ≤10 s after the answer arrived, inside the window]`,
    );
  });
});

// ── bounds and the shared budget ────────────────────────────────────────────

describe("bounds", () => {
  it("connection records past the index disable the join for every lead — no partial first", () => {
    const conns: Row[] = [];
    for (let i = 0; i <= CONN_INDEX_MAX; i++)
      conns.push({
        ts: T0 + 1000 + i,
        _path: "conn",
        "id.orig_h": "10.9.9.9",
        "id.resp_h": "10.8.8.8",
        proto: "tcp",
      });
    // the pair that matters arrives AFTER the bound
    conns.push(zeekConn());
    const e = one([zeekDns(), ...conns]);
    expect(e.description).toContain("[connection join: connection records exceed the index — not joined]");
    expect(e.description).not.toContain("no connection from");
  }, 120_000);

  it("DNS records past the retained bound fold into one overflow row that shows nothing", () => {
    const rows: Row[] = [];
    for (let i = 0; i <= DNS_OBSERVATIONS_MAX; i++)
      rows.push(
        zeekDns({
          uid: `D${i}`,
          ts: T0 + i,
          query: `n${i}.example.com`,
          answers: undefined,
          TTLs: undefined,
        }),
      );
    const r = parse(rows);
    // shapes past 8,192 and the one record past the retained count share the source's overflow row
    const over = r.events.find((e) => e.description.startsWith("[overflow: "));
    expect(over?.description).toMatch(
      /^\[overflow: \d+ DNS records beyond the retained bounds folded; none shown\]/,
    );
    expect(over?.canonical?.dns?.folded).toBe(true);
    // every record minted its indicator keyless in the loop — far more than the 8,192 shapes kept
    expect(r.iocs.length).toBe(5000); // the import's own indicator cap
  }, 120_000);

  it("the telemetry families share one budget: 3,000 DNS rows do not evict the 10 MB flow", () => {
    const rows: Row[] = [
      {
        ts: T0,
        _path: "conn",
        uid: "BIG",
        "id.orig_h": CLIENT,
        "id.resp_h": "10.0.0.9",
        "id.resp_p": 445,
        proto: "tcp",
        conn_state: "SF",
        orig_bytes: 10 * 1024 * 1024,
        resp_bytes: 0,
      },
    ];
    for (let i = 0; i < 3000; i++)
      rows.push(
        zeekDns({
          uid: `D${i}`,
          ts: T0 + 1 + i,
          query: `n${i}.example.com`,
          answers: undefined,
          TTLs: undefined,
        }),
      );
    const r = parse(rows);
    expect(
      r.events.some((e) => e.description.startsWith("Flow:") && e.description.includes("10.0 MB sent")),
    ).toBe(true);
  });
});

describe("Suricata query ↔ answer pairing by dns.id + flow_id (#996)", () => {
  const stamp = (offset: number) => new Date((T0 + offset) * 1000).toISOString().replace("Z", "+0000");
  const v1Answer = (over: Row = {}, dns: Row = {}): Row => ({
    timestamp: stamp(0),
    event_type: "dns",
    flow_id: 1,
    src_ip: SERVER,
    src_port: 53,
    dest_ip: CLIENT,
    dest_port: 51000,
    proto: "UDP",
    dns: { version: 1, type: "answer", id: 7, rrname: "cdn.example.net", rrtype: "A", rdata: A1, ...dns },
    ...over,
  });
  const suricataQuery = (over: Row = {}, dns: Row = {}): Row => ({
    timestamp: stamp(-1),
    event_type: "dns",
    flow_id: 1,
    src_ip: CLIENT,
    src_port: 51000,
    dest_ip: SERVER,
    dest_port: 53,
    proto: "UDP",
    dns: { type: "query", id: 7, rrname: "www.example.com", rrtype: "A", ...dns },
    ...over,
  });

  it("recovers a v1 answer's missing question from a matching separate query event", () => {
    const e = one([suricataQuery(), v1Answer()]);
    expect(e.description).toContain("[query: www.example.com]");
    expect(e.canonical?.dns?.query).toBe("www.example.com");
  });

  it("a v1 answer with no matching query anywhere in the upload reads exactly as before", () => {
    const e = one([v1Answer()]);
    expect(e.description).toContain("[query: (not in this record)]"); // unchanged placeholder, not a guess
    expect(e.canonical?.dns?.query ?? "").toBe("");
  });

  it("shares flow_id but a DIFFERENT dns.id — does not pair", () => {
    const e = one([suricataQuery({}, { id: 9 }), v1Answer()]);
    expect(e.canonical?.dns?.query ?? "").toBe("");
  });

  it("shares dns.id but a DIFFERENT flow_id — does not pair", () => {
    const e = one([suricataQuery({ flow_id: 2 }), v1Answer()]);
    expect(e.canonical?.dns?.query ?? "").toBe("");
  });

  it("a v2/v3 answer that already has its own question is untouched, even with a same-key candidate", () => {
    const v2Answer = (): Row => ({
      timestamp: stamp(0),
      event_type: "dns",
      flow_id: 1,
      src_ip: SERVER,
      src_port: 53,
      dest_ip: CLIENT,
      dest_port: 51000,
      proto: "UDP",
      dns: { version: 2, type: "answer", id: 7, rrname: "already.example", rrtype: "A", rcode: "NOERROR" },
    });
    const e = one([suricataQuery(), v2Answer()]);
    expect(e.canonical?.dns?.query).toBe("already.example");
  });

  it("a standalone query event with no matching answer produces no row — the pre-existing indicator scrape is unaffected either way", () => {
    const r = parse([suricataQuery()]);
    expect(dnsRows([suricataQuery()])).toHaveLength(0);
    // suricataIocs() already scraped this name from the query event before #996 — unrelated to pairing.
    expect(r.iocs.some((i) => i.value === "www.example.com")).toBe(true);
  });

  it("the query event's own type can sit at the record root or inside queries[]", () => {
    const rootType = one([suricataQuery(), v1Answer()]);
    expect(rootType.canonical?.dns?.queryType).toBe(1); // A

    const nestedType = one([
      suricataQuery({}, { rrtype: undefined, queries: [{ rrname: "www.example.com", rrtype: "AAAA" }] }),
      v1Answer(),
    ]);
    expect(nestedType.canonical?.dns?.queryType).toBe(28); // AAAA
  });

  it("pairs regardless of file order — the query line can come after the answer line", () => {
    const e = one([v1Answer(), suricataQuery()]);
    expect(e.canonical?.dns?.query).toBe("www.example.com");
  });

  it("two query lines sharing a key resolve to the last one in file order (disclosed, not defended)", () => {
    const e = one([
      suricataQuery({}, { rrname: "first.example" }),
      suricataQuery({}, { rrname: "second.example" }),
      v1Answer(),
    ]);
    expect(e.canonical?.dns?.query).toBe("second.example");
  });

  it("candidates past the retained bound never pair — the cap on suricataQueries is enforced at collection", () => {
    const rows: Row[] = [];
    for (let i = 0; i < DNS_OBSERVATIONS_MAX; i++)
      rows.push(suricataQuery({ flow_id: 1 }, { id: 100, rrname: "filler.example" }));
    rows.push(suricataQuery({ flow_id: 1 }, { id: 7 })); // the real candidate — pushed past the cap
    rows.push(v1Answer());
    const e = one(rows);
    expect(e.canonical?.dns?.query ?? "").toBe(""); // the one candidate that would have matched never got in
  }, 60_000);
});
