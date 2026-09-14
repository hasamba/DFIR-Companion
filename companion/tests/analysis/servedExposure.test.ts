import { describe, expect, it } from "vitest";
import {
  mapRequestPath,
  relativeUnderRoot,
  servedExposure,
  FILE_ROWS_PER_LOCATION_MAX,
} from "../../src/analysis/servedExposure.js";
import { validateServedLocation, type ServedLocation } from "../../src/analysis/servedLocation.js";
import { mapCombinedLogLine } from "../../src/analysis/combinedLogImport.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

// #930 item 4: a request path equals a local file only through a declared served location;
// status and size are what the server said, never a transfer; disclosure needs confirmed
// sensitivity; every stage is judged over a complete read or says what was not read.

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const SHA = "a".repeat(64);
const NOW = at(100);

function loc(over: Partial<Parameters<typeof validateServedLocation>[0]> = {}): ServedLocation {
  const v = validateServedLocation(
    { host: "WEB01", urlPrefix: "/", localRoot: "C:\\inetpub\\wwwroot", ...over },
    T,
  );
  if (!v.ok) throw new Error(v.error);
  return v.location;
}

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e",
  timestamp: at(1),
  description: "d",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WEB01",
  ...over,
});
const create = (path: string, ts: string, sha?: string, id = `c-${ts}`): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    path,
    sources: ["Sysmon"],
    ...(sha ? { sha256: sha } : {}),
    canonical: { event: { category: "file", type: "create" }, file: { path } } as never,
  });
const del = (path: string, ts: string, id = `d-${ts}`): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    path,
    sources: ["Sysmon"],
    canonical: { event: { category: "file", type: "delete" }, file: { path } } as never,
  });
const mft = (path: string, ts: string, id = `m-${ts}`): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    path,
    sources: ["MFT"],
    canonical: { event: { category: "file", type: "observation" } } as never,
  });
const amcache = (path: string, id = "am"): ForensicEvent => ev({ id, path, sources: ["Amcache"] });

/** A real access-log row through the importer, dated at `ts` (Apache date), size as logged. */
function req(
  target: string,
  status: number,
  size: string,
  ts: string,
  over: { method?: string; client?: string; id?: string; count?: number; endTimestamp?: string } = {},
): ForensicEvent {
  const d = new Date(ts);
  const apache = `${String(d.getUTCDate()).padStart(2, "0")}/${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()]}/${d.getUTCFullYear()}:${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}:${String(d.getUTCSeconds()).padStart(2, "0")} +0000`;
  const line = `${over.client ?? "203.0.113.9"} - - [${apache}] "${over.method ?? "GET"} ${target} HTTP/1.1" ${status} ${size} "-" "curl/8"`;
  const mapped = mapCombinedLogLine(line, new Map<string, SiemIoc>())!;
  return {
    ...mapped,
    id: over.id ?? `r-${target}-${status}-${ts}`,
    asset: "WEB01",
    mitreTechniques: mapped.mitre,
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(over.count ? { count: over.count } : {}),
    ...(over.endTimestamp ? { endTimestamp: over.endTimestamp } : {}),
  };
}
const stateOf = (events: ForensicEvent[]) => ({ ...emptyState("c1"), forensicTimeline: events });
const DUMP = "C:\\inetpub\\wwwroot\\backup\\db.sql";

describe("the served location", () => {
  it("validates, normalises the prefix and root, defaults the case policy from a drive letter, keeps public descriptive", () => {
    const l = loc({
      urlPrefix: "/dumps//",
      localRoot: "C:\\inetpub\\wwwroot\\",
      sensitive: ["\\backup\\db.sql"],
      sensitiveDigests: [SHA.toUpperCase()],
    });
    expect(l).toMatchObject({
      urlPrefix: "/dumps",
      localRoot: "C:\\inetpub\\wwwroot",
      caseInsensitive: true,
      public: false,
      sensitive: ["backup/db.sql"],
      sensitiveDigests: [SHA],
    });
    expect(loc({ localRoot: "/var/www/html" }).caseInsensitive).toBe(false);
    expect(validateServedLocation({ host: "h", urlPrefix: "dumps", localRoot: "/x" }, T)).toMatchObject({
      ok: false,
    });
    expect(
      validateServedLocation({ host: "h", urlPrefix: "/", localRoot: "relative/root" }, T),
    ).toMatchObject({ ok: false });
    expect(
      validateServedLocation({ host: "h", urlPrefix: "/", localRoot: "/x", sensitiveDigests: ["nope"] }, T),
    ).toMatchObject({ ok: false });
    expect(
      validateServedLocation({ host: "h", urlPrefix: "/", localRoot: "/x", indexFiles: ["a/b"] }, T),
    ).toMatchObject({ ok: false });
  });
});

describe("the path contract — fail closed", () => {
  const l = loc({ urlPrefix: "/dump", indexFiles: ["index.html"] });
  it("maps a plain path, a once-encoded path, a query-stripped path, a directory through its index; refuses every ambiguity", () => {
    expect(mapRequestPath(l, "/dump/backup/db.sql")).toEqual({
      ok: true,
      relative: "backup/db.sql",
      directory: false,
    });
    expect(mapRequestPath(l, "/dump/backup/db%20x.sql?download=1#f")).toEqual({
      ok: true,
      relative: "backup/db x.sql",
      directory: false,
    });
    expect(mapRequestPath(l, "/DUMP/Backup/DB.SQL")).toEqual({
      ok: true,
      relative: "Backup/DB.SQL",
      directory: false,
    });
    expect(mapRequestPath(l, "/dump/a/../backup/db.sql")).toEqual({
      ok: true,
      relative: "backup/db.sql",
      directory: false,
    });
    expect(mapRequestPath(l, "/dump/backup/")).toEqual({ ok: true, relative: "backup", directory: true });
    // Absolute-form (a proxy row): the authority must be this location's declared vhost.
    expect(mapRequestPath(l, "http://web01.example/dump/backup/db.sql")).toEqual({
      ok: false,
      why: "foreign authority",
    });
    const vhl = loc({ urlPrefix: "/dump", vhost: "web01.example", indexFiles: ["index.html"] });
    expect(mapRequestPath(vhl, "http://web01.example/dump/backup/db.sql")).toEqual({
      ok: true,
      relative: "backup/db.sql",
      directory: false,
    });
    expect(mapRequestPath(vhl, "http://external.example/dump/backup/db.sql")).toEqual({
      ok: false,
      why: "foreign authority",
    });
    expect(mapRequestPath(vhl, "ftp://web01.example/dump/x")).toEqual({
      ok: false,
      why: "foreign authority",
    });
    // A Windows name with a trailing dot or space is an alias: ambiguous on a drive-letter root.
    expect(mapRequestPath(l, "/dump/backup/db.sql.")).toEqual({ ok: false, why: "ambiguous windows name" });
    expect(mapRequestPath(l, "/dump/backup%20/db.sql")).toEqual({ ok: false, why: "ambiguous windows name" });
    expect(mapRequestPath(l, "/dump/backup%2Fdb.sql")).toEqual({ ok: false, why: "encoded separator" });
    // ONE decoding pass: `%252F` is a literal "%2F" in a filename, never a separator.
    expect(mapRequestPath(l, "/dump/backup%252Fdb.sql")).toEqual({
      ok: true,
      relative: "backup%2Fdb.sql",
      directory: false,
    });
    expect(mapRequestPath(l, "/dump/backup/db%zz.sql")).toEqual({ ok: false, why: "malformed escape" });
    expect(mapRequestPath(l, "/dump/../../etc/passwd")).toEqual({ ok: false, why: "escaping dot segment" });
    expect(mapRequestPath(l, "/dump2/backup/db.sql")).toEqual({ ok: false, why: "outside the prefix" });
    expect(mapRequestPath(l, "/other/db.sql")).toEqual({ ok: false, why: "outside the prefix" });
    expect(mapRequestPath(l, "/dump/backup/db%00.sql")).toEqual({ ok: false, why: "encoded separator" });
    expect(mapRequestPath(loc({ urlPrefix: "/dump" }), "/dump/backup/")).toEqual({
      ok: false,
      why: "directory without index",
    });
    const posix = loc({ urlPrefix: "/dump", localRoot: "/var/www" });
    expect(mapRequestPath(posix, "/DUMP/backup/db.sql")).toEqual({ ok: false, why: "outside the prefix" });
    const vh = loc({ urlPrefix: "/", vhost: "files.example" });
    expect(mapRequestPath(vh, "/db.sql", "files.example")).toEqual({
      ok: true,
      relative: "db.sql",
      directory: false,
    });
    expect(mapRequestPath(vh, "/db.sql", undefined)).toEqual({ ok: false, why: "vhost mismatch" });
    expect(relativeUnderRoot(l, "C:/inetpub/wwwroot/backup/db.sql")).toBe("backup/db.sql");
    expect(relativeUnderRoot(l, "C:\\inetpub\\wwwroot2\\x")).toBeNull();
    expect(relativeUnderRoot(l, "C:/inetpub//wwwroot//backup/db.sql")).toBe("backup/db.sql");
    expect(relativeUnderRoot(loc({ localRoot: "/var/www" }), "/var/WWW/x")).toBeNull();
  });
});

describe("servedExposure — stages over versions", () => {
  it("file created → request 200 with a size → confirmed sensitive: corroborated disclosure; size words never claim a transfer", () => {
    const l = loc({ sensitive: ["backup/db.sql"] });
    const s = servedExposure(
      stateOf([create(DUMP, at(1), SHA), req("/backup/db.sql", 200, "48213", at(2))]),
      [l],
      NOW,
    );
    const r = s.locations[0].resources[0];
    expect(r).toMatchObject({
      relativePath: "backup/db.sql",
      url: "/backup/db.sql",
      stage: "corroborated-disclosure",
      sensitivity: "confirmed-by-analyst",
    });
    expect(r.requests[0]).toMatchObject({
      status: 200,
      size: 48213,
      sizeRecorded: true,
      placement: "covered",
      client: "203.0.113.9",
    });
    expect(r.requests[0].sizeWords).toContain("the response's size, not the document's; not client receipt");
    expect(JSON.stringify(s)).not.toMatch(/"transfer(red)?"/);
    expect(r.evidence["corroborated-disclosure"]).toEqual([r.requests[0].eventId]);
    expect(s.locations[0].gaps).toEqual([]);
  });
  it("content identity: the covering version's digest is the sensitive document; a later replaced version is not", () => {
    const l = loc({ sensitiveDigests: [SHA] });
    const s = servedExposure(
      stateOf([
        create(DUMP, at(1), SHA),
        create(DUMP, at(5), "b".repeat(64), "c2"),
        req("/backup/db.sql", 200, "100", at(2), { id: "q1" }),
        req("/backup/db.sql", 200, "100", at(6), { id: "q2" }),
      ]),
      [l],
      NOW,
    );
    const r = s.locations[0].resources[0];
    expect(r.versions.map((v) => [v.sha256?.slice(0, 1), v.to !== undefined])).toEqual([
      ["a", true],
      ["b", false],
    ]);
    expect(r.stage).toBe("corroborated-disclosure");
    expect(r.evidence["corroborated-disclosure"]).toEqual(["q1"]);
    expect(r.evidence["response-size-recorded"]).toEqual(["q1", "q2"]);
  });
  it("what the server said: 206, 304, 404, 200 with 0 or '-', HEAD — none is a body-bearing response but 206; an unconfirmed 200 stops at response-size-recorded with the reason", () => {
    const l = loc();
    const rows = [
      create(DUMP, at(1)),
      req("/backup/db.sql", 206, "500", at(2), { id: "p206" }),
      req("/backup/db.sql", 304, "-", at(3), { id: "p304" }),
      req("/backup/db.sql", 404, "312", at(4), { id: "p404" }),
      req("/backup/db.sql", 200, "0", at(5), { id: "p0" }),
      req("/backup/db.sql", 200, "-", at(6), { id: "pdash" }),
      req("/backup/db.sql", 200, "999", at(7), { id: "phead", method: "HEAD" }),
    ];
    const r = servedExposure(stateOf(rows), [l], NOW).locations[0].resources[0];
    const words = Object.fromEntries(r.requests.map((q) => [q.eventId, [q.sizeRecorded, q.sizeWords]]));
    expect(words.p206[0]).toBe(true);
    expect(words.p206[1]).toContain("partial (206)");
    expect(words.p304).toEqual([false, "bodiless status 304"]);
    expect(words.p404[1]).toContain("error response 404; a logged size is the error page's");
    expect(words.p0).toEqual([false, "size 0 logged"]);
    expect(words.pdash).toEqual([false, "size not recorded (-)"]);
    expect(words.phead).toEqual([false, "no body by definition (HEAD)"]);
    expect(r.stage).toBe("response-size-recorded");
    expect(r.stageReason).toContain(
      "sensitivity not established — confirm the path or add the document's digest (a complete read)",
    );
    expect(r.sensitivity).toBe("not-established");
  });
  it("time: a request before the file existed or after its deletion is 'not established'; a folded row across the boundary is ambiguous; an MFT row is a point observation; Amcache is a lead", () => {
    const l = loc({ sensitive: ["backup/db.sql"] });
    const rows = [
      create(DUMP, at(10)),
      del(DUMP, at(20)),
      req("/backup/db.sql", 200, "10", at(5), { id: "before" }),
      req("/backup/db.sql", 200, "10", at(15), { id: "during" }),
      req("/backup/db.sql", 200, "10", at(25), { id: "after" }),
      req("/backup/db.sql", 200, "10", at(18), { id: "folded", count: 3, endTimestamp: at(22) }),
      amcache(DUMP),
    ];
    const r = servedExposure(stateOf(rows), [l], NOW).locations[0].resources[0];
    const place = Object.fromEntries(r.requests.map((q) => [q.eventId, q.placement]));
    expect(place).toEqual({
      before: "not-established",
      during: "covered",
      after: "not-established",
      folded: "ambiguous",
    });
    expect(r.evidence["corroborated-disclosure"]).toEqual(["during"]);
    expect(r.historicalLeads).toEqual(["am"]);
    const point = servedExposure(
      stateOf([
        mft(DUMP, at(3)),
        req("/backup/db.sql", 200, "10", at(3), { id: "same" }),
        req("/backup/db.sql", 200, "10", at(4), { id: "later" }),
      ]),
      [l],
      NOW,
    ).locations[0].resources[0];
    expect(Object.fromEntries(point.requests.map((q) => [q.eventId, q.placement]))).toEqual({
      same: "point-observation",
      later: "not-established",
    });
  });
  it("public is descriptive: an unconfirmed resource is a negative control, a confirmed one a surfaced conflict; unevidenced requests are leads; unmapped requests are counted by reason", () => {
    const l = loc({ public: true, sensitive: ["backup/db.sql"] });
    const rows = [
      create(DUMP, at(1)),
      create("C:\\inetpub\\wwwroot\\pub\\readme.txt", at(1), undefined, "cr"),
      req("/backup/db.sql", 200, "10", at(2), { id: "q1" }),
      req("/pub/readme.txt", 200, "10", at(2), { id: "q2" }),
      req("/nothing/here.zip", 404, "10", at(2), { id: "q3" }),
      req("/x%2Fy", 200, "10", at(2), { id: "q4" }),
    ];
    const e = servedExposure(stateOf(rows), [l], NOW).locations[0];
    const dump = e.resources.find((r) => r.relativePath === "backup/db.sql")!;
    const readme = e.resources.find((r) => r.relativePath === "pub/readme.txt")!;
    expect(dump).toMatchObject({ negativeControl: false, stage: "corroborated-disclosure" });
    expect(dump.conflict).toContain("declared public location, but this resource is confirmed sensitive");
    expect(readme).toMatchObject({ negativeControl: true, stage: "response-size-recorded" });
    expect(readme.conflict).toBeUndefined();
    expect(e.unevidencedRequests).toEqual([
      { path: "nothing/here.zip", count: 1, statuses: [404], eventIds: ["q3"] },
    ]);
    expect(e.unmapped).toEqual({ count: 1, reasons: { "encoded separator": 1 } });
  });
  it("gaps and bounds: only web rows / only file rows are said; past the read bound the reason is 'unknown', never a complete-read negative; another host and a second prefix stay apart", () => {
    const l = loc();
    const onlyWeb = servedExposure(stateOf([req("/backup/db.sql", 200, "10", at(2))]), [l], NOW).locations[0];
    expect(onlyWeb.gaps[0]).toContain("no file rows under this root");
    expect(onlyWeb.unevidencedRequests).toHaveLength(1);
    const onlyFile = servedExposure(stateOf([create(DUMP, at(1))]), [l], NOW).locations[0];
    expect(onlyFile.gaps[0]).toContain("no web access-log rows for this host");
    expect(onlyFile.resources[0].stageReason).toBe("no request mapped to this path (a complete read)");
    const many = Array.from({ length: FILE_ROWS_PER_LOCATION_MAX + 3 }, (_, i) =>
      create(`C:\\inetpub\\wwwroot\\f${i}.txt`, at(1), undefined, `f${i}`),
    );
    const bounded = servedExposure(stateOf([...many, create(DUMP, at(1), undefined, "late")]), [l], NOW)
      .locations[0];
    expect(bounded.read.fileRowsUnread).toBe(4);
    expect(bounded.gaps.some((g) => g.startsWith("read bound reached"))).toBe(true);
    expect(bounded.resources[0].stageReason).toContain("unknown beyond that: 4 row(s) unread");
    const other = servedExposure(
      stateOf([create(DUMP, at(1)), { ...req("/backup/db.sql", 200, "10", at(2)), asset: "WEB02" }]),
      [l],
      NOW,
    ).locations[0];
    expect(other.resources[0].requests).toEqual([]);
    const two = [
      loc({ urlPrefix: "/a", localRoot: "C:\\srv\\a" }),
      loc({ urlPrefix: "/b", localRoot: "C:\\srv\\b" }),
    ];
    const both = servedExposure(
      stateOf([create("C:\\srv\\a\\x.sql", at(1), undefined, "ax"), req("/b/x.sql", 200, "10", at(2))]),
      two,
      NOW,
    );
    expect(both.locations[0].resources[0].requests).toEqual([]);
    expect(both.locations[1].unevidencedRequests).toHaveLength(1);
  });
});

describe("servedExposure — Codex code round 1", () => {
  it("a body-bearing response is GET-only with 200 or 206: POST 200, GET 201, GET 205 and a missing status are all 'not recorded'", () => {
    const rows = [
      create(DUMP, at(1)),
      req("/backup/db.sql", 200, "999", at(2), { id: "ppost", method: "POST" }),
      req("/backup/db.sql", 201, "999", at(3), { id: "p201" }),
      req("/backup/db.sql", 205, "999", at(4), { id: "p205" }),
      req("/backup/db.sql", 200, "999", at(5), { id: "pdel", method: "DELETE" }),
    ];
    const r = servedExposure(stateOf(rows), [loc()], NOW).locations[0].resources[0];
    const words = Object.fromEntries(r.requests.map((q) => [q.eventId, [q.sizeRecorded, q.sizeWords]]));
    expect(words.ppost).toEqual([false, "POST: a response to it is not the resource's body"]);
    expect(words.pdel[0]).toBe(false);
    expect(words.p201).toEqual([false, "status 201 is not read as the resource's body"]);
    expect(words.p205).toEqual([false, "status 205 is not read as the resource's body"]);
    expect(r.stage).toBe("retrieval-requested");
    const noStatus = { ...req("/backup/db.sql", 200, "999", at(6), { id: "ns" }) };
    noStatus.canonical = {
      ...noStatus.canonical,
      web: { ...noStatus.canonical?.web, statusCode: undefined },
    } as never;
    const r2 = servedExposure(stateOf([create(DUMP, at(1)), noStatus]), [loc()], NOW).locations[0]
      .resources[0];
    expect(r2.requests[0]).toMatchObject({ sizeRecorded: false, sizeWords: "status not recorded" });
  });
  it("a digest on a point observation binds only at that instant: a later 200 is not covered and never corroborated", () => {
    const l = loc({ sensitiveDigests: [SHA] });
    const rows = [
      { ...mft(DUMP, at(3), "msha"), sha256: SHA },
      req("/backup/db.sql", 200, "10", at(3), { id: "same" }),
      req("/backup/db.sql", 200, "10", at(9), { id: "later" }),
    ];
    const r = servedExposure(stateOf(rows), [l], NOW).locations[0].resources[0];
    expect(r.versions).toEqual([]);
    expect(r.observations).toEqual([{ eventId: "msha", at: at(3), sha256: SHA }]);
    expect(r.sensitivity).toBe("content-identity");
    expect(Object.fromEntries(r.requests.map((q) => [q.eventId, q.placement]))).toEqual({
      same: "point-observation",
      later: "not-established",
    });
    expect(r.evidence["corroborated-disclosure"]).toEqual(["same"]);
  });
  it("provenance before canonical type: an MFT row whose canonical type says delete is a point observation, not a close", () => {
    const mftDel: ForensicEvent = {
      ...mft(DUMP, at(3), "mdel"),
      canonical: { event: { category: "file", type: "delete" } } as never,
    };
    const r = servedExposure(
      stateOf([create(DUMP, at(1)), mftDel, req("/backup/db.sql", 200, "10", at(5), { id: "q" })]),
      [loc()],
      NOW,
    ).locations[0].resources[0];
    expect(r.versions).toEqual([{ from: at(1), openedBy: "c-" + at(1) }]);
    expect(r.observations.map((o) => o.eventId)).toEqual(["mdel"]);
    expect(r.requests[0].placement).toBe("covered");
  });
  it("a delete and a create at the same instant: the close is applied first whatever the ids, one version covers on", () => {
    for (const [dId, cId] of [
      ["a", "b"],
      ["b", "a"],
    ]) {
      const rows = [
        create(DUMP, at(1), undefined, "c1"),
        del(DUMP, at(10), dId),
        create(DUMP, at(10), undefined, cId),
        req("/backup/db.sql", 200, "10", at(10), { id: "q" }),
      ];
      const r = servedExposure(stateOf(rows), [loc()], NOW).locations[0].resources[0];
      expect(r.versions.map((v) => [v.from, v.to ?? null, v.openedBy])).toEqual([
        [at(1), at(10), "c1"],
        [at(10), null, cId],
      ]);
      expect(r.requests[0].placement).toBe("covered");
    }
  });
  it("a folded row whose interval crosses an interior boundary (covered → gap → covered) is ambiguous", () => {
    const rows = [
      create(DUMP, at(1)),
      del(DUMP, at(5)),
      create(DUMP, at(7), undefined, "c7"),
      req("/backup/db.sql", 200, "10", at(3), { id: "fold", count: 4, endTimestamp: at(9) }),
      req("/backup/db.sql", 200, "10", at(8), { id: "inside", count: 2, endTimestamp: at(9) }),
    ];
    const r = servedExposure(stateOf(rows), [loc({ sensitive: ["backup/db.sql"] })], NOW).locations[0]
      .resources[0];
    expect(Object.fromEntries(r.requests.map((q) => [q.eventId, q.placement]))).toEqual({
      fold: "ambiguous",
      inside: "covered",
    });
    expect(r.evidence["corroborated-disclosure"]).toEqual(["inside"]);
  });
  it("the read bound is charged to file readings only: path-bearing process rows never push a real create past it", () => {
    const noise = Array.from({ length: FILE_ROWS_PER_LOCATION_MAX }, (_, i) =>
      ev({
        id: `p${i}`,
        path: `C:\\inetpub\\wwwroot\\tool${i}.exe`,
        sources: ["Sysmon"],
        canonical: { event: { category: "process", type: "start" } } as never,
      }),
    );
    const e = servedExposure(
      stateOf([...noise, create(DUMP, at(1)), req("/backup/db.sql", 200, "10", at(2))]),
      [loc()],
      NOW,
    ).locations[0];
    expect(e.read).toMatchObject({ fileRows: 1, fileRowsUnread: 0 });
    expect(e.resources).toHaveLength(1);
    expect(e.resources[0].stage).toBe("response-size-recorded");
  });
  it("host names fold case for the join and for coverage: 'web01' file rows and 'WEB01' web rows are one host", () => {
    const e = servedExposure(
      stateOf([{ ...create(DUMP, at(1)), asset: "web01" }, req("/backup/db.sql", 200, "10", at(2))]),
      [loc({ host: "Web01" })],
      NOW,
    ).locations[0];
    expect(e.resources[0].requests).toHaveLength(1);
    expect(e.coverage.length).toBeGreaterThan(0);
    expect(e.gaps).toEqual([]);
  });
  it("unevidenced paths: the total and the not-shown count are said when the list is capped", () => {
    const rows = Array.from({ length: 501 }, (_, i) =>
      req(`/lead${i}.zip`, 404, "10", at(2), { id: `u${i}` }),
    );
    const e = servedExposure(stateOf(rows), [loc()], NOW).locations[0];
    expect(e.unevidencedRequestsTotal).toBe(501);
    expect(e.unevidencedRequestsNotShown).toBe(1);
    expect(e.unevidencedRequests).toHaveLength(500);
  });
  it("a directory request resolves to the first declared index file with evidence, else the first declared one as a lead", () => {
    const idx = loc({ indexFiles: ["index.html", "default.htm"] });
    const evidenced = servedExposure(
      stateOf([
        create("C:\\inetpub\\wwwroot\\pub\\default.htm", at(1), undefined, "dh"),
        req("/pub/", 200, "10", at(2), { id: "dq" }),
      ]),
      [idx],
      NOW,
    ).locations[0];
    expect(evidenced.resources[0]).toMatchObject({
      relativePath: "pub/default.htm",
      stage: "response-size-recorded",
    });
    const lead = servedExposure(stateOf([req("/pub/", 200, "10", at(2), { id: "dq" })]), [idx], NOW)
      .locations[0];
    expect(lead.unevidencedRequests).toHaveLength(1);
    expect(lead.resources).toEqual([]);
  });
  it("end to end: /Secret.bin and /secret.bin stay two rows through the importer and map to two resources on a case-sensitive root", () => {
    const rows = [
      create("/var/www/Secret.bin", at(1), undefined, "cs"),
      create("/var/www/secret.bin", at(1), undefined, "cl"),
      req("/Secret.bin", 200, "10", at(2), { id: "qS" }),
      req("/secret.bin", 200, "10", at(2), { id: "qs" }),
    ];
    expect((rows[2] as { aggKey?: string }).aggKey).not.toBe((rows[3] as { aggKey?: string }).aggKey);
    const e = servedExposure(stateOf(rows), [loc({ localRoot: "/var/www", sensitive: ["Secret.bin"] })], NOW)
      .locations[0];
    const byPath = Object.fromEntries(
      e.resources.map((r) => [r.relativePath, [r.stage, r.requests.map((q) => q.eventId)]]),
    );
    expect(byPath).toEqual({
      "Secret.bin": ["corroborated-disclosure", ["qS"]],
      "secret.bin": ["response-size-recorded", ["qs"]],
    });
  });
});
