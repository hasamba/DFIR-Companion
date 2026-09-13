// #993 — web request chains inside one upload: Zeek http/files and Suricata http/fileinfo rows,
// joined only through identifiers both records carry; every missing hop named; a digest a file
// identity only when the sensor's counters say it covers the whole object.
import { describe, it, expect } from "vitest";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { buildIocProvenanceChains } from "../../src/analysis/iocProvenanceChain.js";
import { canonicalConformanceIssues, createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { resolveExtractedFrom, type SiemEvent } from "../../src/analysis/siemImport.js";
import { readZeekFiles, WEB_IDS_PER_RECORD } from "../../src/analysis/webChainRead.js";
import { coverageOf, WEB_BODIES_MAX, WEB_OBSERVATIONS_MAX } from "../../src/analysis/webChainJoin.js";
import { WEB_SHAPES_MAX } from "../../src/analysis/webChainRows.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

const SHA = "3a7b" + "0".repeat(56) + "c9e1";
const SHA_B = "ab".repeat(32);
const CLIENT = "203.0.113.9";
const SERVER = "198.51.100.7";

function http(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ts: 1512115202,
    _path: "http",
    uid: "CAb1",
    "id.orig_h": CLIENT,
    "id.resp_h": SERVER,
    "id.resp_p": 80,
    trans_depth: 1,
    method: "GET",
    host: "www.example.com",
    uri: "/dl/setup.exe",
    version: "1.1",
    status_code: 200,
    resp_fuids: ["FaB1"],
    response_body_len: 1258291,
    ...over,
  };
}
function files(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ts: 1512115203,
    _path: "files",
    fuid: "FaB1",
    uid: "CAb1",
    "id.orig_h": CLIENT,
    "id.resp_h": SERVER,
    source: "HTTP",
    mime_type: "application/x-dosexec",
    filename: "setup.exe",
    is_orig: false,
    seen_bytes: 1258291,
    total_bytes: 1258291,
    missing_bytes: 0,
    timedout: false,
    sha256: SHA,
    ...over,
  };
}
const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n");
const parse = (rows: object[]) => parseNetworkLogs(ndjson(rows));
const requests = (r: ReturnType<typeof parse>) => r.events.filter((e) => e.description.startsWith("HTTP "));
const transfers = (r: ReturnType<typeof parse>) =>
  r.events.filter((e) => e.description.startsWith("Transfer"));
const asForensic = (e: SiemEvent, id: string): ForensicEvent =>
  ({ ...e, id, asset: e.asset ?? "", sources: e.sources ?? [] }) as unknown as ForensicEvent;

describe("the full chain — request → response → body, transfer → request", () => {
  const r = parse([http(), files()]);
  const req = requests(r)[0];
  const xfer = transfers(r)[0];

  it("is two rows, each naming the other's evidence", () => {
    expect(r.events).toHaveLength(2);
    expect(req.description).toContain("HTTP GET [target: www.example.com/dl/setup.exe] → 200");
    expect(req.description).toContain(
      "[body: sha256 3a7b0000…c9e1; 1.2 MB whole; mime: application/x-dosexec]",
    );
    expect(xfer.description).toContain("Transfer over HTTP: sha256 3a7b0000…c9e1; 1.2 MB whole");
    expect(xfer.description).toContain("[request: GET [target: www.example.com/dl/setup.exe] → 200]");
    expect(xfer.description).toContain("[from 198.51.100.7 to 203.0.113.9]");
    expect(req.severity).toBe("Info");
    expect(req.mitreTechniques).toEqual([]);
    expect(req.origin).toBe("wire");
  });

  it("the transfer row carries the hash as a file identity and the request as a joined record", () => {
    expect(xfer.sha256).toBe(SHA);
    expect(xfer.canonical?.file?.sha256).toBe(SHA);
    expect(xfer.canonical?.transfer?.coverage).toBe("whole");
    expect(xfer.canonical?.transfer?.requestState).toBe("observed");
    expect(xfer.canonical?.transfer?.requests[0]).toMatchObject({
      method: "GET",
      host: "www.example.com",
      statusCode: 200,
    });
    expect(xfer.canonical?.evidence.rawRecords.map((x) => x.locator)).toEqual(["record:1", "record:0"]);
  });

  it("every joined leaf points at the record it came from", () => {
    // An array is one provenance leaf: it rests on the record that named the identifier AND on
    // every record the identifier joined.
    const prov = xfer.canonical!.fieldProvenance;
    expect(prov["transfer.requests"].recordLocators).toEqual(["record:1", "record:0"]);
    expect(prov["transfer.coverage"].recordLocators).toEqual(["record:1"]);
    const reqProv = req.canonical!.fieldProvenance;
    expect(reqProv["web.bodies"].recordLocators).toEqual(["record:0", "record:1"]);
    expect(reqProv["web.method"].recordLocators).toEqual(["record:0"]);
    expect(canonicalConformanceIssues(req.canonical)).toEqual([]);
    expect(canonicalConformanceIssues(xfer.canonical)).toEqual([]);
  });

  it("the hash IOC names the transfer row as its extraction (extractedFrom)", () => {
    const hash = r.iocs.find((i) => i.type === "hash" && i.value === SHA)!;
    expect(hash.sourceAggKeys).toEqual([xfer.aggKey]);
    const resolved = resolveExtractedFrom([hash], new Map([[xfer.aggKey, "ev-xfer"]]));
    expect(resolved[0].extractedFrom).toEqual(["ev-xfer"]);
  });

  it("the host is a domain indicator; a Zeek http `host` never becomes the sensor", () => {
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "www.example.com")).toBe(true);
    expect(r.hostname).toBe("");
    expect(req.asset).toBeUndefined();
    const withSensor = parse([http({ "observer.name": "sensor-1" })]);
    expect(withSensor.hostname).toBe("sensor-1");
  });
});

describe("the redirect hop — what the record says, never the target", () => {
  const go = http({
    uid: "CAb2",
    uri: "/go",
    host: "redirect.example.net",
    status_code: 302,
    resp_fuids: undefined,
    trans_depth: 1,
  });
  const landing = { ...go, ts: 1512115205, uri: "/landing", status_code: 200, trans_depth: 2 };

  it("names the next transaction on the connection as order, not as the target", () => {
    const req = requests(parse([go, landing])).find((e) => e.description.includes("→ 302"))!;
    expect(req.description).toContain("[redirect target: not in this record]");
    expect(req.description).toContain(
      "[next: GET [target: redirect.example.net/landing] → 200 (transaction 2) — order on the connection, not the redirect target]",
    );
    expect(req.canonical?.web?.redirect).toMatchObject({
      targetState: "not in this record",
      nextState: "observed",
    });
    expect(req.canonical?.fieldProvenance["web.redirect.next.method"].recordLocators).toEqual(["record:1"]);
    expect(req.canonical?.fieldProvenance["web.redirect.targetState"].recordLocators).toEqual(["record:0"]);
  });

  it("absence is 'not in this upload'; a gap names the later depth without calling it adjacent", () => {
    const alone = requests(parse([go]))[0];
    expect(alone.description).toContain("[next transaction (2) not in this upload]");
    const gap = requests(parse([go, { ...landing, trans_depth: 4 }])).find((e) =>
      e.description.includes("→ 302"),
    )!;
    expect(gap.description).toContain("[later on this connection: transaction 4 — not adjacent]");
    expect(gap.canonical?.web?.redirect).toMatchObject({
      nextState: "later transaction only",
      laterDepth: 4,
    });
  });

  it("an HTTP/2 stream is never ordered by depth; a 304 is not a redirect", () => {
    const h2 = requests(
      parse([
        { ...go, stream_id: "7" },
        { ...landing, stream_id: "9" },
      ]),
    ).find((e) => e.description.includes("→ 302"))!;
    expect(h2.description).toContain("[next transaction not read: HTTP/2 stream]");
    expect(h2.description).not.toContain("[next:");
    const notModified = requests(parse([http({ status_code: 304, resp_fuids: undefined })]))[0];
    expect(notModified.description).toContain("[not modified — no body]");
    expect(notModified.canonical?.web?.redirect).toBeUndefined();
  });

  it("Suricata's Location is the server's stated target, not an observed follow", () => {
    const row = {
      timestamp: "2017-12-01T08:00:04+0000",
      event_type: "http",
      flow_id: 11,
      tx_id: 0,
      src_ip: CLIENT,
      dest_ip: SERVER,
      dest_port: 80,
      http: {
        hostname: "redirect.example.net",
        url: "/go",
        http_method: "GET",
        status: 302,
        redirect: "https://landing.example.net/x",
        protocol: "HTTP/1.1",
      },
    };
    const req = requests(parse([row]))[0];
    expect(req.description).toContain(
      "[redirect target (stated by the server): https://landing.example.net/x]",
    );
    expect(req.description).toContain("[next transaction not read: no connection identity]");
    expect(req.canonical?.web?.redirect?.targetState).toBe("stated by the server");
  });
});

describe("coverage — the sensor's counters, never a claim of a complete transfer", () => {
  const xferOf = (over: Record<string, unknown>, reqOver?: Record<string, unknown>) =>
    transfers(parse(reqOver ? [http(reqOver), files(over)] : [files(over)]))[0];

  it("a truncated body keeps a partial digest that is no hash indicator and no file identity", () => {
    const r = parse([files({ seen_bytes: 400000 })]);
    const x = transfers(r)[0];
    expect(x.description).toContain(
      "partial digest sha256 3a7b0000…c9e1 over the bytes seen; 390.6 KB of 1.2 MB seen",
    );
    expect(x.sha256).toBeUndefined();
    expect(x.canonical?.file?.sha256).toBeUndefined();
    expect(x.canonical?.transfer?.coverage).toBe("partial");
    expect(x.canonical?.transfer?.digests).toEqual([{ alg: "sha256", value: SHA }]);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false);
  });

  it("a gap, a timeout, a 206 and a non-zero offset are each named", () => {
    expect(xferOf({ missing_bytes: 8192, sha256: undefined }).description).toContain(
      "no digest computed by the sensor; 1.2 MB seen, 8.0 KB missing",
    );
    expect(xferOf({ timedout: true }).description).toContain("timed out; 1.2 MB seen");
    const range = xferOf({}, { status_code: 206 });
    expect(range.description).toContain("a range (1.2 MB), not the whole object");
    expect(range.sha256).toBeUndefined();
    expect(coverageOf(readZeekFiles(files({ total_bytes: undefined }), 0))).toBe("unsized");
    expect(xferOf({ total_bytes: undefined }).description).toContain("1.2 MB seen; object size not recorded");
    expect(xferOf({ total_bytes: undefined }).sha256).toBe(SHA);
  });

  it("Suricata: CLOSED without gaps is whole; TRUNCATED, gaps, start > 0 and no state are not", () => {
    const fi = (over: Record<string, unknown>) => ({
      timestamp: "2017-12-01T08:00:02+0000",
      event_type: "fileinfo",
      flow_id: 11,
      src_ip: CLIENT,
      dest_ip: SERVER,
      app_proto: "http",
      http: { hostname: "www.example.com", url: "/dl/setup.exe", http_method: "GET", status: 200 },
      fileinfo: {
        filename: "/dl/setup.exe",
        sha256: SHA,
        size: 1258291,
        state: "CLOSED",
        gaps: false,
        tx_id: 0,
        ...over,
      },
    });
    expect(transfers(parse([fi({})]))[0].sha256).toBe(SHA);
    expect(transfers(parse([fi({ state: "TRUNCATED" })]))[0].sha256).toBeUndefined();
    expect(transfers(parse([fi({ gaps: true })]))[0].canonical?.transfer?.coverage).toBe("gapped");
    expect(transfers(parse([fi({ start: 4096 })]))[0].canonical?.transfer?.coverage).toBe("range");
    expect(transfers(parse([fi({ state: undefined })]))[0].canonical?.transfer?.coverage).toBe(
      "not-recorded",
    );
    const inline = transfers(parse([fi({})]))[0];
    expect(inline.description).toContain("[request (inline): GET www.example.com/dl/setup.exe → 200]");
    expect(inline.description).toContain("[flow 203.0.113.9 ↔ 198.51.100.7 — sender not recorded]");
    expect(inline.canonical?.transfer?.requestState).toBe("inline on this record");
  });
});

describe("missing partners are named, never silent", () => {
  it("a fuid with no files record, and a files record with no request", () => {
    const req = requests(parse([http()]))[0];
    expect(req.description).toContain("[body: FaB1 — no files record in this upload]");
    expect(req.canonical?.web?.bodies[0]).toMatchObject({
      state: "no files record in this upload",
      direction: "response",
    });
    const x = transfers(parse([files({ uid: "CAb9" })]))[0];
    expect(x.description).toContain("[request: not in this upload]");
    const smtp = transfers(
      parse([
        files({
          source: "SMTP",
          uid: undefined,
          fuid: undefined,
          conn_uids: undefined,
          "id.orig_h": undefined,
          "id.resp_h": undefined,
          is_orig: undefined,
        }),
      ]),
    )[0];
    expect(smtp.description).toContain("Transfer over SMTP:");
    expect(smtp.description).not.toContain("[request");
    expect(smtp.canonical?.transfer?.requestState).toBe("no request identity");
  });

  it("a request body is 'sent by the client'; the old files schema (conn_uids, tx/rx hosts) joins too", () => {
    const upload = http({ method: "POST", orig_fuids: ["FuP1"], resp_fuids: undefined });
    const body = files({
      fuid: "FuP1",
      uid: undefined,
      "id.orig_h": undefined,
      "id.resp_h": undefined,
      is_orig: undefined,
      conn_uids: ["CAb1"],
      tx_hosts: [CLIENT],
      rx_hosts: [SERVER],
    });
    const r = parse([upload, body]);
    expect(requests(r)[0].description).toContain(
      "[body sent by the client: sha256 3a7b0000…c9e1; 1.2 MB whole; mime: application/x-dosexec]",
    );
    expect(transfers(r)[0].description).toContain("[from 203.0.113.9 to 198.51.100.7]");
    expect(transfers(r)[0].description).toContain(
      "[request: POST [target: www.example.com/dl/setup.exe] → 200]",
    );
  });

  it("a CONNECT is a tunnel with no URL; a Suricata http row with a fileinfo joins by flow + tx", () => {
    const tunnel = requests(
      parse([
        http({ method: "CONNECT", uri: "mail.example.net:443", host: undefined, resp_fuids: undefined }),
      ]),
    )[0];
    expect(tunnel.description).toContain(
      "[tunnel attempt to mail.example.net:443 — the requests inside are not in this record]",
    );
    const sHttp = {
      timestamp: "2017-12-01T08:00:02+0000",
      event_type: "http",
      flow_id: 11,
      tx_id: 0,
      src_ip: CLIENT,
      dest_ip: SERVER,
      http: { hostname: "www.example.com", url: "/dl/setup.exe", http_method: "GET", status: 200 },
    };
    const sFile = {
      timestamp: "2017-12-01T08:00:02+0000",
      event_type: "fileinfo",
      flow_id: 11,
      src_ip: CLIENT,
      dest_ip: SERVER,
      app_proto: "http",
      http: sHttp.http,
      fileinfo: { filename: "/dl/setup.exe", sha256: SHA, size: 10, state: "CLOSED", gaps: false, tx_id: 0 },
    };
    const r = parse([sHttp, sFile]);
    expect(requests(r)[0].description).toContain(
      "[body (direction not recorded): sha256 3a7b0000…c9e1; 10 B whole]",
    );
    expect(transfers(r)[0].description).toContain(
      "[request: GET [target: www.example.com/dl/setup.exe] → 200]",
    );
  });
});

describe("identity — one row per chain", () => {
  it("two records of one shape fold; a different body, target or hop is another row", () => {
    const same = parse([
      http(),
      http({ ts: 1512115300, uid: "CAb5" }),
      files(),
      files({ ts: 1512115301, fuid: "FaB1" }),
    ]);
    expect(requests(same)).toHaveLength(1);
    expect(requests(same)[0].description).toContain("— 2 records");
    const otherBody = parse([
      http(),
      files(),
      http({ uid: "CAb5", resp_fuids: ["FaB2"] }),
      files({ fuid: "FaB2", sha256: SHA_B }),
    ]);
    expect(requests(otherBody)).toHaveLength(2);
    const longA = "/" + "a".repeat(200) + "x";
    const longB = "/" + "a".repeat(200) + "y";
    const pastClip = parse([
      http({ uri: longA, resp_fuids: undefined }),
      http({ uri: longB, resp_fuids: undefined }),
    ]);
    expect(requests(pastClip)).toHaveLength(2);
    expect(requests(pastClip)[0].description).not.toBe(requests(pastClip)[1].description);
  });

  it("the ninth body still changes the row", () => {
    const fuids = Array.from({ length: WEB_BODIES_MAX + 1 }, (_, i) => `F${i}`);
    const rowsA = [http({ resp_fuids: fuids }), ...fuids.map((f) => files({ fuid: f, sha256: SHA }))];
    const rowsB = [
      http({ resp_fuids: fuids }),
      ...fuids.map((f, i) => files({ fuid: f, sha256: i === WEB_BODIES_MAX ? SHA_B : SHA })),
    ];
    const a = requests(parse(rowsA))[0];
    const b = requests(parse(rowsB))[0];
    // The words show what fits and count the rest truthfully: shown + "+n more" = every body.
    const shown = (a.description.match(/\[body: /g) ?? []).length;
    const more = Number(/\[\+(\d+) more bod/.exec(a.description)?.[1] ?? 0);
    expect(shown).toBeGreaterThan(0);
    expect(shown + more).toBe(WEB_BODIES_MAX + 1);
    expect(a.canonical?.web?.bodies).toHaveLength(WEB_BODIES_MAX);
    expect(a.canonical?.web?.bodiesTotal).toBe(WEB_BODIES_MAX + 1);
    expect(a.aggKey).not.toBe(b.aggKey);
  });

  it("identifier lists are bounded at read time and the row says so", () => {
    const many = Array.from({ length: WEB_IDS_PER_RECORD + 5 }, (_, i) => `F${i}`);
    const req = requests(parse([http({ resp_fuids: many })]))[0];
    expect(req.canonical?.web?.identifiersDropped).toBe(5);
    expect(req.description).toContain("[+5 identifiers not read]");
  });
});

describe("bounds", () => {
  it("shapes past the bound fold into one overflow row that shows no shape", () => {
    const rows = Array.from({ length: WEB_SHAPES_MAX + 3 }, (_, i) =>
      http({ uri: `/p/${i}`, resp_fuids: undefined, uid: `C${i}` }),
    );
    const r = parseNetworkLogs(ndjson(rows), { maxEvents: WEB_SHAPES_MAX + 10 });
    const over = r.events.find((e) => e.description.startsWith("[overflow:"))!;
    expect(over.description).toContain("3 request records beyond the retained bound folded; none shown");
    expect(over.canonical?.web?.folded).toBe(true);
    expect(requests(r)).toHaveLength(WEB_SHAPES_MAX);
  });

  it("records past the retained bound are counted, never joined", () => {
    expect(WEB_OBSERVATIONS_MAX).toBeGreaterThan(WEB_SHAPES_MAX);
  });

  it("under the budget a row naming a file outranks a thousand plain requests", () => {
    const plain = Array.from({ length: 1000 }, (_, i) =>
      http({ uri: `/p/${i}`, resp_fuids: undefined, uid: `C${i}`, ts: 1512115000 + i }),
    );
    const r = parseNetworkLogs(ndjson([...plain, http({ ts: 1512119999 }), files({ ts: 1512119999 })]), {
      maxEvents: 5,
    });
    expect(r.events.some((e) => e.description.includes("[body: sha256 3a7b0000…c9e1"))).toBe(true);
    expect(r.events.some((e) => e.description.startsWith("Transfer over HTTP: sha256"))).toBe(true);
  });
});

describe("grading and neutralisation", () => {
  it("an attack pattern in a Zeek-seen target grades as it would in an Apache line", () => {
    const req = requests(
      parse([http({ uri: "/cgi-bin/x?cmd=cat%20/etc/passwd", resp_fuids: undefined })]),
    )[0];
    expect(req.severity).toBe("Medium");
    expect(req.mitreTechniques).toContain("T1190");
    expect(req.description).toMatch(/\[web-attack: /);
    expect(req.description).toContain("[matched:");
  });

  it("sensor-read text cannot spell a tag or feed a free-text hash/path scrape", () => {
    const evil = parse([
      http({
        uri: "/x",
        user: "bob] [request: GET evil",
        username: "bob] [request: GET evil",
        resp_fuids: undefined,
      }),
      files({ fuid: "F9", filename: "x] [request: GET evil", uid: "C9", mime_type: "/tmp/payload.exe" }),
    ]);
    for (const e of evil.events) {
      expect(e.description).not.toContain("] [request: GET evil");
      expect(e.description).not.toMatch(/\[request: GET evil\]/);
    }
    // A path-shaped MIME and a hash-shaped filename union with nothing.
    const wire = transfers(
      parse([files({ filename: SHA_B, mime_type: "/tmp/payload.exe", sha256: undefined, uid: "C9" })]),
    )[0];
    const endpoint: ForensicEvent = {
      id: "e1",
      timestamp: "2017-12-01T08:00:03.000Z",
      description: "File created /tmp/payload.exe",
      severity: "Info",
      asset: "ws01",
      path: "/tmp/payload.exe",
      sha256: SHA_B,
      sources: ["Sysmon"],
    } as ForensicEvent;
    const merged = correlateEvents([asForensic(wire, "w1"), endpoint], {});
    expect(merged).toHaveLength(2);
  });
});

describe("transfer → endpoint file: joined by the hash and by nothing else", () => {
  const r = parse([http(), files()]);
  const wire = asForensic(transfers(r)[0], "w1");
  const endpoint = {
    id: "e1",
    timestamp: "2017-12-01T08:00:09.000Z",
    description: "File created C:\\Users\\a\\Downloads\\setup.exe",
    severity: "Info",
    asset: "ws01",
    path: "C:\\Users\\a\\Downloads\\setup.exe",
    sha256: SHA,
    sources: ["Sysmon"],
  } as ForensicEvent;

  it("the two rows never merge — no asset, the same asset, both missing, cross-host on", () => {
    expect(correlateEvents([wire, endpoint], {})).toHaveLength(2);
    expect(correlateEvents([{ ...wire, asset: "ws01" }, endpoint], {})).toHaveLength(2);
    expect(correlateEvents([wire, { ...endpoint, asset: "" }], {})).toHaveLength(2);
    expect(correlateEvents([wire, endpoint], { crossHostArtifacts: true })).toHaveLength(2);
    // Wire with wire still dedups a re-import.
    expect(correlateEvents([wire, { ...wire, id: "w2" }], {})).toHaveLength(1);
  });

  it("the hash IOC's provenance chain lists the linked transfer AND the unlinked endpoint event", () => {
    const ioc = { id: "i1", type: "hash", value: SHA, extractedFrom: ["w1"] } as unknown as IOC;
    const chains = buildIocProvenanceChains([ioc], [wire, endpoint], []);
    const ids = chains["i1"].extraction.map((x) => x.eventId).sort();
    expect(ids).toEqual(["e1", "w1"]);
    expect(chains["i1"].extractionAuthoritative).toBe(true);
    // Description tokens are still not unioned with an authoritative link.
    const textOnly = {
      ...endpoint,
      id: "e2",
      sha256: undefined,
      description: `mentions ${SHA} in passing`,
    } as ForensicEvent;
    expect(
      buildIocProvenanceChains([ioc], [wire, textOnly], [])["i1"].extraction.map((x) => x.eventId),
    ).toEqual(["w1"]);
  });
});

describe("createCanonicalEvent locatorMap", () => {
  it("attributes a prefixed path to the named record and refuses an unknown locator", () => {
    const env = createCanonicalEvent({
      event: { category: "network", type: "http" },
      web: {
        method: "GET",
        targetForm: "origin",
        responseState: "recorded",
        bodies: [{ direction: "response", id: "F1", state: "observed", transfer: { coverage: "whole" } }],
        bodiesTotal: 1,
        records: 1,
      },
      time: { observed: "2017-12-01T08:00:02.000Z", normalized: "2017-12-01T08:00:02.000Z" },
      evidence: {
        rawRecords: [
          { source: "zeek-http", locator: "record:0" },
          { source: "zeek-files", locator: "record:1" },
        ],
      },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "web-chain-v1" },
      locatorMap: { "web.bodies.0.transfer": "record:1" },
    });
    expect(env.fieldProvenance["web.bodies"].recordLocators).toEqual(["record:0", "record:1"]);
    expect(env.fieldProvenance["web.method"].recordLocators).toEqual(["record:0"]);
    expect(() =>
      createCanonicalEvent({
        event: { category: "network", type: "http" },
        time: { observed: "2017-12-01T08:00:02.000Z", normalized: "2017-12-01T08:00:02.000Z" },
        evidence: { rawRecords: [{ source: "zeek-http", locator: "record:0" }] },
        producer: { importer: "network", parserVersion: "1", mappingVersion: "web-chain-v1" },
        locatorMap: { web: "record:9" },
      }),
    ).toThrow(/record:9/);
  });
});
