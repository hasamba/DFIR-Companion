import { describe, expect, it } from "vitest";
import { sensitiveAccess } from "../../src/analysis/sensitiveAccess.js";
import { validateSensitiveLocation, type SensitiveLocation } from "../../src/analysis/sensitiveLocation.js";
import { objectAccessBlocks } from "../../src/analysis/objectAccess.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #930 item 7: a 4663 says a process exercised rights on an object; the read is a read only when
// the object is evidenced as a file; the instance and the session are candidates; suspicious is
// what the candidate's own rows carry; accessed / later archive / later connection never imply
// each other.

const T = "2026-06-01T00:00:00.000Z";
const at = (m: number) => new Date(Date.parse(T) + m * 60_000).toISOString();
const NOW = at(100_000);
const DOC = "C:\\Finance\\Board\\minutes.docx";

function loc(over: Partial<Parameters<typeof validateSensitiveLocation>[0]> = {}): SensitiveLocation {
  const v = validateSensitiveLocation({ host: "FS01", path: DOC, kind: "file", ...over }, T);
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
  asset: "FS01",
  ...over,
});
const canon = (c: object) => ({ canonical: c as never });

/** A 4663 through the envelope reader, as the importer would map it. */
const access = (
  path: string,
  ts: string,
  over: {
    id?: string;
    mask?: string;
    pid?: string;
    image?: string;
    logonId?: string;
    eid?: number;
    objectType?: string;
    handleId?: string;
    host?: string;
  } = {},
): ForensicEvent => {
  const ed: Record<string, string> = {
    ObjectName: path,
    ObjectType: over.objectType ?? "File",
    AccessMask: over.mask ?? "0x1",
    ProcessId: over.pid ?? "0x1a4",
    ProcessName: over.image ?? "C:\\Windows\\System32\\notepad.exe",
    SubjectLogonId: over.logonId ?? "0x3e7",
    HandleId: over.handleId ?? "0x1234",
    SubjectUserName: "jdoe",
    SubjectDomainName: "CORP",
    SubjectUserSid: "S-1-5-21-1-2-3-1001",
  };
  const b = objectAccessBlocks(over.eid ?? 4663, false, (k) => ed[k] ?? "");
  return ev({
    id: over.id ?? `a-${ts}`,
    timestamp: ts,
    asset: over.host ?? "FS01",
    ...canon({
      ...b,
      actor: { kind: "account", name: "CORP\\jdoe", domain: "CORP" },
      account: { id: "S-1-5-21-1-2-3-1001", name: "CORP\\jdoe", domain: "CORP" },
    }),
  });
};
const start = (
  pid: number,
  image: string,
  ts: string,
  over: {
    id?: string;
    guid?: string;
    severity?: ForensicEvent["severity"];
    mitre?: string[];
    host?: string;
  } = {},
): ForensicEvent =>
  ev({
    id: over.id ?? `s-${pid}-${ts}`,
    timestamp: ts,
    asset: over.host ?? "FS01",
    severity: over.severity ?? "Low",
    mitreTechniques: over.mitre ?? [],
    ...canon({
      event: { category: "process", type: "start" },
      process: { pid, executable: image, ...(over.guid ? { id: over.guid } : {}) },
    }),
  });
const end = (pid: number, ts: string, id = `x-${pid}-${ts}`): ForensicEvent =>
  ev({ id, timestamp: ts, ...canon({ event: { category: "process", type: "end" }, process: { pid } }) });
const logon = (
  sessionId: string,
  ts: string,
  over: { id?: string; type?: number; src?: string; severity?: ForensicEvent["severity"] } = {},
): ForensicEvent =>
  ev({
    id: over.id ?? `l-${ts}`,
    timestamp: ts,
    severity: over.severity ?? "Info",
    ...canon({
      event: { category: "authentication", type: "logon", outcome: "success" },
      actor: { kind: "account", name: "CORP\\jdoe", domain: "CORP" },
      authentication: { sessionId, logonType: over.type ?? 10 },
      ...(over.src ? { network: { source: { address: over.src } } } : {}),
    }),
  });
const logoff = (sessionId: string, ts: string, id = `lo-${ts}`): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    ...canon({ event: { category: "authentication", type: "logoff" }, authentication: { sessionId } }),
  });
const fileRow = (
  path: string,
  ts: string,
  kind: "create" | "delete" | "observation" = "create",
  id = `f-${kind}-${ts}`,
): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    path,
    sources: [kind === "observation" ? "MFT" : "Sysmon"],
    ...canon({ event: { category: "file", type: kind }, file: { path } }),
  });
const guidRow = (guid: string, ts: string, kind: "archive" | "connection", id: string): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    ...canon(
      kind === "archive"
        ? {
            event: { category: "file", type: "create" },
            file: { path: "C:\\Users\\jdoe\\AppData\\Local\\Temp\\out.zip" },
            process: { id: guid },
          }
        : {
            event: { category: "network", type: "connection" },
            network: { destination: { address: "203.0.113.9", port: 443 } },
            process: { id: guid },
          },
    ),
  });
const stateOf = (events: ForensicEvent[]) => ({ ...emptyState("c1"), forensicTimeline: events });

describe("sensitiveAccess — stages over candidates", () => {
  it("declared file + file row + 4663 0x1 by a pid with one matching start (graded High) + a session: every stage; three columns never imply each other", () => {
    const rows = [
      fileRow(DOC, at(0)),
      logon("0x3e7", at(1), { id: "l1", type: 10, src: "203.0.113.9" }),
      start(420, "C:\\Windows\\System32\\notepad.exe", at(2), {
        id: "s1",
        guid: "{G1}",
        severity: "High",
        mitre: ["T1059.001"],
      }),
      access(DOC, at(5), { id: "a1" }),
      guidRow("{G1}", at(10), "archive", "z1"),
      guidRow("{G1}", at(20), "connection", "n1"),
      guidRow("{G1}", at(90), "connection", "late"),
    ];
    const r = sensitiveAccess(stateOf(rows), [loc()], NOW);
    const o = r.locations[0].objects[0];
    expect(o).toMatchObject({ path: DOC, stage: "corroborated-suspicious-read" });
    const a = o.accesses[0];
    expect(a).toMatchObject({
      eventId: "a1",
      classes: ["read-or-listing"],
      dataRead: true,
      fileEvidence: "evidenced as a file by f-create-" + at(0),
      pid: 420,
      instance: { state: "candidate", startEventId: "s1", processGuid: "{G1}" },
      session: { state: "candidate", logonEventId: "l1", logonType: 10, sourceAddress: "203.0.113.9" },
    });
    expect(a.corroboration[0]).toContain("process row s1 is graded High (T1059.001)");
    expect(a.pivots).toMatchObject({ archiveCreates: ["z1"], connections: ["n1"] });
    expect(a.pivots.note).toContain("subsequent activity by that process, not staging or transfer");
    expect(JSON.stringify(r)).not.toMatch(/exfil|staged|transferred/i);
    expect(o.evidence).toEqual({
      "access-recorded": ["a1"],
      "data-read": ["a1"],
      "read-by-candidate-instance": ["a1"],
      "corroborated-suspicious-read": ["a1"],
    });
  });
  it("0x1 with no file row is read-or-listing; a declared folder does not make the object a file; 0x80 is metadata; 4656 is a handle request; 5145 a share check; a Key object is not a document", () => {
    const rows = [
      access(DOC, at(5), { id: "a1" }),
      access("C:\\Finance\\Board\\q3", at(6), { id: "dir" }),
      access(DOC, at(7), { id: "meta", mask: "0x80" }),
      access(DOC, at(8), { id: "h", eid: 4656 }),
      access(DOC, at(9), { id: "key", objectType: "Key" }),
    ];
    const folder = loc({ path: "C:\\Finance\\Board", kind: "folder" });
    const r = sensitiveAccess(stateOf(rows), [folder], NOW).locations[0];
    const doc = r.objects.find((o) => o.path === DOC)!;
    expect(doc.stage).toBe("access-recorded");
    expect(doc.stageReason).toContain("read or listing only");
    const by = Object.fromEntries(doc.accesses.map((a) => [a.eventId, [a.kind, a.classes, a.dataRead]]));
    expect(by.a1).toEqual(["access", ["read-or-listing"], false]);
    expect(by.meta).toEqual(["access", ["metadata"], false]);
    expect(by.h).toEqual(["handle-request", ["read-or-listing"], false]);
    expect(by.key[2]).toBe(false);
    expect(doc.accesses.find((a) => a.eventId === "key")!.objectType).toBe("Key");
    expect(r.objects.find((o) => o.path === "C:\\Finance\\Board\\q3")!.stage).toBe("access-recorded");
  });
  it("process instance: pid reused with another image → ambiguous; two same-image starts with no termination → ambiguous; a termination before the access → not established; no start → not established", () => {
    const base = [fileRow(DOC, at(0))];
    const other = sensitiveAccess(
      stateOf([
        ...base,
        start(420, "C:\\Windows\\System32\\cmd.exe", at(2), { id: "s-cmd" }),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(other.accesses[0].instance).toMatchObject({ state: "ambiguous" });
    expect(other.accesses[0].instance.reason).toContain("pid 420 reused");
    expect(other.stage).toBe("data-read");
    const twice = sensitiveAccess(
      stateOf([
        ...base,
        start(420, "C:\\Windows\\System32\\notepad.exe", at(1), { id: "s1" }),
        start(420, "C:\\Windows\\System32\\notepad.exe", at(2), { id: "s2" }),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(twice.accesses[0].instance).toMatchObject({ state: "ambiguous", startEventId: "s2" });
    const separated = sensitiveAccess(
      stateOf([
        ...base,
        start(420, "C:\\Windows\\System32\\notepad.exe", at(1), { id: "s1" }),
        end(420, at(1.5)),
        start(420, "C:\\Windows\\System32\\notepad.exe", at(2), { id: "s2" }),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(separated.accesses[0].instance).toMatchObject({ state: "candidate", startEventId: "s2" });
    const ended = sensitiveAccess(
      stateOf([
        ...base,
        start(420, "C:\\Windows\\System32\\notepad.exe", at(2), { id: "s1" }),
        end(420, at(3)),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(ended.accesses[0].instance.state).toBe("not-established");
    const none = sensitiveAccess(stateOf([...base, access(DOC, at(5), { id: "a1" })]), [loc()], NOW)
      .locations[0].objects[0];
    expect(none.accesses[0].instance).toMatchObject({ state: "not-established" });
    expect(none.accesses[0].instance.reason).toContain("name and pid only");
    expect(none.accesses[0].pivots.archiveCreates).toEqual([]);
  });
  it("session: one 4624 with the logon id before the access is a candidate; two → ambiguous; a logoff between → ambiguous; none → not established; a High logon corroborates", () => {
    const base = [fileRow(DOC, at(0)), start(420, "C:\\Windows\\System32\\notepad.exe", at(2), { id: "s1" })];
    const one = sensitiveAccess(
      stateOf([
        ...base,
        logon("0x3e7", at(1), { id: "l1", severity: "High" }),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(one.accesses[0].session).toMatchObject({ state: "candidate", logonEventId: "l1" });
    expect(one.stage).toBe("corroborated-suspicious-read");
    expect(one.accesses[0].corroboration[0]).toContain("logon l1 is graded High");
    const two = sensitiveAccess(
      stateOf([
        ...base,
        logon("0x3e7", at(1), { id: "l1" }),
        logon("0x3E7", at(3), { id: "l2" }),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(two.accesses[0].session.state).toBe("ambiguous");
    const off = sensitiveAccess(
      stateOf([
        ...base,
        logon("0x3e7", at(1), { id: "l1" }),
        logoff("0x3e7", at(4)),
        access(DOC, at(5), { id: "a1" }),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(off.accesses[0].session).toMatchObject({ state: "ambiguous" });
    expect(off.accesses[0].session.reason).toContain("logged off");
    const none = sensitiveAccess(stateOf([...base, access(DOC, at(5), { id: "a1" })]), [loc()], NOW)
      .locations[0].objects[0];
    expect(none.accesses[0].session.state).toBe("not-established");
    expect(none.stage).toBe("read-by-candidate-instance");
    expect(none.stageReason).toContain("not shown suspicious by the case");
  });
  it("file evidence in time: a delete before the access voids it (path reuse), a later create does not count, an MFT observation counts", () => {
    const reuse = sensitiveAccess(
      stateOf([
        fileRow(DOC, at(0)),
        fileRow(DOC, at(1), "delete"),
        access(DOC, at(5), { id: "a1" }),
        fileRow(DOC, at(6), "create", "later"),
      ]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(reuse.accesses[0].dataRead).toBe(false);
    expect(reuse.accesses[0].fileEvidence).toContain("delete");
    const mft = sensitiveAccess(
      stateOf([fileRow(DOC, at(0), "observation", "m1"), access(DOC, at(5), { id: "a1" })]),
      [loc()],
      NOW,
    ).locations[0].objects[0];
    expect(mft.accesses[0]).toMatchObject({ dataRead: true, fileEvidence: "evidenced as a file by m1" });
  });
  it("deletion candidate: a 4660 with the same host, pid, logon id and handle within five minutes of a DELETE access; another handle never joins", () => {
    const del = access(DOC, at(5), { id: "d1", mask: "0x10000", handleId: "0x1234" });
    const ed = { HandleId: "0x1234", ProcessId: "0x1a4", SubjectLogonId: "0x3e7" };
    const gone = ev({
      id: "g1",
      timestamp: at(6),
      ...canon(objectAccessBlocks(4660, false, (k) => ed[k as keyof typeof ed] ?? "")),
    });
    const otherHandle = ev({
      id: "g2",
      timestamp: at(6),
      ...canon(
        objectAccessBlocks(4660, false, (k) => ({ ...ed, HandleId: "0x9999" })[k as keyof typeof ed] ?? ""),
      ),
    });
    const r = sensitiveAccess(stateOf([fileRow(DOC, at(0)), del, gone, otherHandle]), [loc()], NOW)
      .locations[0].objects[0];
    expect(r.accesses[0]).toMatchObject({ classes: ["delete"], deletionCandidates: ["g1"] });
  });
  it("the collection facet: ten distinct evidenced files read by one candidate instance within 15 minutes; indeterminate when the host read is truncated over the window", () => {
    const files = Array.from({ length: 10 }, (_, i) => `C:\\Finance\\Board\\doc${i}.docx`);
    const rows = [
      ...files.map((f, i) => fileRow(f, at(0), "create", `f${i}`)),
      start(420, "C:\\Windows\\System32\\notepad.exe", at(1), { id: "s1", guid: "{G1}" }),
      ...files.map((f, i) => access(f, at(2 + i), { id: `a${i}` })),
    ];
    const r = sensitiveAccess(stateOf(rows), [loc({ path: "C:\\Finance\\Board", kind: "folder" })], NOW);
    expect(r.collections).toHaveLength(1);
    expect(r.collections[0]).toMatchObject({ host: "FS01", instance: "{G1}", objects: 10, state: "shape" });
    expect(r.collections[0].note).toContain("the record does not say which");
    const nine = sensitiveAccess(
      stateOf(rows.filter((e) => e.id !== "a9")),
      [loc({ path: "C:\\Finance\\Board", kind: "folder" })],
      NOW,
    );
    expect(nine.collections).toEqual([]);
  });
  it("host context: a host with a declared location and no 4663 says absence establishes nothing; a filename never sets sensitivity; another host stays apart", () => {
    const r = sensitiveAccess(
      stateOf([
        fileRow(DOC, at(0)),
        access("C:\\Users\\jdoe\\passwords.xlsx", at(5), { id: "pw" }),
        access(DOC, at(6), { id: "a1", host: "FS02" }),
      ]),
      [loc()],
      NOW,
    );
    expect(r.locations[0].objects).toEqual([]);
    expect(r.locations[0].note).toContain("no conclusion is available for this location and interval");
    expect(r.hosts.find((h) => h.host === "FS01")!.note).toContain(
      "context only, not coverage of any location",
    );
    expect(JSON.stringify(r.locations)).not.toContain("passwords.xlsx");
    const any = sensitiveAccess(
      stateOf([fileRow(DOC, at(0)), access(DOC, at(6), { id: "a1", host: "FS02" })]),
      [loc({ host: "" })],
      NOW,
    );
    expect(any.locations[0].objects[0]).toMatchObject({ host: "FS02", stage: "access-recorded" });
  });
});
