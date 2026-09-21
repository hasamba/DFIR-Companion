import { describe, it, expect } from "vitest";
import { HostRenameMap, renameEvidence } from "../../src/analysis/hostRenameEvidence.js";

type Row = Record<string, unknown>;

// #1489 — a GUI/notebook JSONL export carries no Fqdn, so every Computer value in a renamed
// machine's own logs became its own host. The files still hold three facts Windows wrote about the
// machine itself: the System 6011 rename event, the machine's own account under the SYSTEM logon
// session, and the SAM domain name of a local account. Each is a per-record claim about the record's
// writer; none is free text an intruder types.

const BOX = "WIN-UK1GV882OK6"; // Vagrant base image name
const MID = "WIN-0NNTB2RTNB1"; // post-sysprep name
const FINAL = "DESKTOP-16OJFO6"; // the provisioned name

// Raw Windows.EventLogs.Evtx row (System + EventData at the top level).
function rawEvtx(eid: number, computer: string, ed: Record<string, unknown>, over: object = {}): Row {
  return {
    System: {
      Provider: { Name: eid === 6011 ? "EventLog" : "Microsoft-Windows-Security-Auditing" },
      EventID: { Value: eid },
      TimeCreated: { SystemTime: 1787752201 },
      Channel: eid === 6011 ? "System" : "Security",
      Computer: computer,
    },
    EventData: ed,
    ...over,
  };
}

// Windows.EventLogs.CondensedAccountUsage — flat, the logon fields collapsed to one set.
function condensed(computer: string, user: string, domain: string, logonId: unknown, eid = 4648): Row {
  return {
    EventTime: "2026-08-26T13:49:52Z",
    Computer: computer,
    EventID: eid,
    DomainName: domain,
    UserName: user,
    LogonId: logonId,
  };
}

// Windows.EventLogs.Chainsaw flat row (verdict at the top level, System block under SystemData).
function chainsawFlat(eid: number, computer: string, ed: Record<string, unknown>): Row {
  return {
    EventTime: "2026-08-26T13:52:13Z",
    Detection: "User Added to Local Administrators",
    Severity: "medium",
    Computer: computer,
    Channel: "Security",
    EventID: eid,
    SystemData: { EventID: eid, Computer: computer, Channel: "Security" },
    EventData: ed,
  };
}

describe("renameEvidence — rule a: the System 6011 rename event", () => {
  it("reads old and new name from the structured Data pair", () => {
    const ev = renameEvidence(rawEvtx(6011, MID, { Data: [BOX, MID] }));
    expect(ev).toMatchObject({ formerName: BOX, currentName: MID, rule: "6011" });
    expect(ev?.timestamp).toBe("2026-08-26T13:50:01.000Z");
  });
  it("reads the nested `Event` shape and the param1/param2 spelling", () => {
    const ev = renameEvidence({
      Event: {
        System: {
          Provider: { Name: "EventLog" },
          EventID: 6011,
          TimeCreated: { SystemTime: "2026-08-26T13:50:01Z" },
          Computer: MID,
        },
        EventData: { param1: BOX, param2: MID },
      },
    });
    expect(ev).toMatchObject({ formerName: BOX, currentName: MID });
  });
  it("never reads the rendered Message, and refuses a malformed Data pair", () => {
    expect(
      renameEvidence(rawEvtx(6011, MID, { Data: [BOX] }, { Message: `changed from ${BOX} to ${MID}.` })),
    ).toBeNull();
    expect(renameEvidence(rawEvtx(6011, MID, { Data: ["not a host name!", MID] }))).toBeNull();
    expect(renameEvidence(rawEvtx(6011, MID, { Data: [MID, MID] }))).toBeNull();
  });
  it("requires the System channel or the EventLog provider", () => {
    const row = rawEvtx(6011, MID, { Data: [BOX, MID] }) as { System: Record<string, unknown> };
    row.System.Channel = "Application";
    row.System.Provider = { Name: "SomeApp" };
    expect(renameEvidence(row)).toBeNull();
  });
});

describe("renameEvidence — rule b: the machine's own account under the SYSTEM session", () => {
  it("condensed 4648: `OLD$` with logon id 999 on a record written as NEW", () => {
    const ev = renameEvidence(condensed(MID, `${BOX}$`, "WORKGROUP", 999));
    expect(ev).toMatchObject({ formerName: BOX, currentName: MID, rule: "machine-account" });
  });
  it("raw 4624: SubjectUserName `OLD$` with SubjectLogonId 0x3e7, on a domain-joined host too", () => {
    const ev = renameEvidence(
      rawEvtx(4624, "WS02", {
        SubjectUserSid: "S-1-5-18",
        SubjectUserName: "WS01$",
        SubjectDomainName: "CORP",
        SubjectLogonId: "0x3e7",
        TargetUserName: "SYSTEM",
        TargetDomainName: "NT AUTHORITY",
        LogonType: 5,
      }),
    );
    expect(ev).toMatchObject({ formerName: "WS01", currentName: "WS02" });
  });
  it("the SYSTEM session id is mandatory — a chosen `X$` account without it is not evidence", () => {
    expect(renameEvidence(condensed(MID, `${BOX}$`, "WORKGROUP", undefined))).toBeNull();
    expect(renameEvidence(condensed(MID, `${BOX}$`, "WORKGROUP", 757245))).toBeNull();
    expect(renameEvidence(condensed(MID, `${BOX}$`, "WORKGROUP", "0x1234"))).toBeNull();
  });
  it("never reads the Target account: an explicit-credential logon to another machine's account", () => {
    expect(
      renameEvidence(
        rawEvtx(4648, "WS02", {
          SubjectUserName: "alice",
          SubjectDomainName: "WS02",
          SubjectLogonId: "0x5f2a1",
          TargetUserName: "WS01$",
          TargetDomainName: "WORKGROUP",
          TargetLogonId: "0x3e7",
          TargetServerName: "WS01",
        }),
      ),
    ).toBeNull();
  });
  it("the machine's own current name, or a non-machine account, yields nothing", () => {
    expect(renameEvidence(condensed(MID, `${MID}$`, "WORKGROUP", 999))).toBeNull();
    expect(renameEvidence(condensed(MID, "SYSTEM", "NT AUTHORITY", 999))).toBeNull();
    expect(renameEvidence(condensed("", `${BOX}$`, "WORKGROUP", 999))).toBeNull();
  });
});

describe("renameEvidence — rule c: the SAM domain of a local account", () => {
  const samEd = {
    TargetUserName: "vagrant",
    TargetDomainName: MID,
    TargetSid: "S-1-5-21-908230818-3748298786-230204725-1001",
    SubjectUserSid: "S-1-5-18",
    SubjectUserName: `${FINAL}$`,
    SubjectDomainName: "WORKGROUP",
  };
  it("4720 on DESKTOP with TargetDomainName = the old name is a candidate edge (needs the name seen)", () => {
    const ev = renameEvidence(chainsawFlat(4720, FINAL, samEd));
    expect(ev).toMatchObject({
      formerName: MID,
      currentName: FINAL,
      rule: "sam-domain",
      needsFormerSeen: true,
    });
  });
  it("a domain admin creating a domain account on a DC is not host evidence", () => {
    expect(
      renameEvidence(
        chainsawFlat(4720, "DC01", {
          ...samEd,
          TargetDomainName: "CONTOSO",
          SubjectUserName: "admin",
          SubjectDomainName: "CONTOSO",
        }),
      ),
    ).toBeNull();
  });
  it("well-known domains and domain-group events are ignored", () => {
    expect(renameEvidence(chainsawFlat(4732, FINAL, { ...samEd, TargetDomainName: "Builtin" }))).toBeNull();
    expect(renameEvidence(chainsawFlat(4728, FINAL, samEd))).toBeNull(); // domain global group
    expect(renameEvidence(chainsawFlat(4781, FINAL, samEd))).toBeNull(); // account rename
    expect(renameEvidence(chainsawFlat(4648, FINAL, samEd))).toBeNull(); // explicit credentials
  });
});

describe("HostRenameMap — chains, conflicts, cycles, time bound", () => {
  const T0 = "2025-12-05T03:00:00Z"; // a record under the base-image name
  const T1 = "2026-08-26T13:49:52Z"; // 4648 OLD$ on MID
  const T2 = "2026-08-26T13:52:06Z"; // 4648 MID$ on FINAL
  const chain = [
    condensed(MID, `${BOX}$`, "WORKGROUP", 999),
    { ...condensed(FINAL, `${MID}$`, "WORKGROUP", 999), EventTime: T2 },
  ];

  it("follows X→Y→Z to the current name; unknown names come back unchanged", () => {
    const m = new HostRenameMap();
    m.learn(chain);
    expect(m.currentNameOf(BOX, T0)).toBe(FINAL);
    expect(m.currentNameOf(MID, T1)).toBe(FINAL);
    expect(m.currentNameOf(`${BOX}.localdomain`, T0)).toBe(FINAL); // short-name compare
    expect(m.currentNameOf(FINAL, T2)).toBe(FINAL);
    expect(m.currentNameOf("SRV-9", T0)).toBe("SRV-9");
    expect(m.formerNames()).toEqual([
      { formerName: BOX, currentName: FINAL },
      { formerName: MID, currentName: FINAL },
    ]);
  });
  it("a record after the evidence time is a later machine reusing the name, not the old one", () => {
    const m = new HostRenameMap();
    m.learn(chain);
    expect(m.currentNameOf(BOX, "2026-09-01T00:00:00Z")).toBe(BOX);
    expect(m.currentNameOf(BOX, "")).toBe(BOX); // no time: fail closed
  });
  it("two different current names for one former name: no alias at all (fails closed)", () => {
    const m = new HostRenameMap();
    m.learn([condensed(MID, `${BOX}$`, "WORKGROUP", 999), condensed("OTHER-1", `${BOX}$`, "WORKGROUP", 999)]);
    expect(m.currentNameOf(BOX, T0)).toBe(BOX);
  });
  it("a cycle yields no alias for any name on it", () => {
    const m = new HostRenameMap();
    m.learn([condensed(MID, `${BOX}$`, "WORKGROUP", 999), condensed(BOX, `${MID}$`, "WORKGROUP", 999)]);
    expect(m.currentNameOf(BOX, T0)).toBe(BOX);
    expect(m.currentNameOf(MID, T0)).toBe(MID);
  });
  it("a SAM-domain edge counts only once the former name was seen as a record's Computer", () => {
    const sam = chainsawFlat(4720, FINAL, {
      TargetUserName: "vagrant",
      TargetDomainName: MID,
      SubjectUserSid: "S-1-5-18",
      SubjectUserName: `${FINAL}$`,
      SubjectDomainName: "WORKGROUP",
    });
    const only = new HostRenameMap();
    only.learn([sam]);
    expect(only.currentNameOf(MID, T1)).toBe(MID);
    const withSeen = new HostRenameMap();
    withSeen.learn([sam, { EventTime: T1, Computer: MID, EventID: 7023, Channel: "System" }]);
    expect(withSeen.currentNameOf(MID, T1)).toBe(FINAL);
  });
  it("learning is incremental and order-independent", () => {
    const a = new HostRenameMap();
    a.learn([chain[1]]);
    a.learn([chain[0]]);
    expect(a.currentNameOf(BOX, T0)).toBe(FINAL);
  });
});

describe("HostRenameMap — the time bound is the EARLIEST observation, never widened", () => {
  it("a 6011 at T1 and a repeated machine-account observation at T2 leave a T1<t<T2 record alone", () => {
    const m = new HostRenameMap();
    m.learn([
      {
        System: {
          Provider: { Name: "EventLog" },
          EventID: 6011,
          Channel: "System",
          Computer: MID,
          TimeCreated: { SystemTime: "2026-08-26T13:50:01Z" },
        },
        EventData: { Data: [BOX, MID] },
      },
      { ...condensed(MID, `${BOX}$`, "WORKGROUP", 999), EventTime: "2026-08-27T09:00:00Z" },
    ]);
    expect(m.currentNameOf(BOX, "2026-08-26T13:00:00Z")).toBe(MID);
    expect(m.currentNameOf(BOX, "2026-08-26T20:00:00Z")).toBe(BOX); // a machine reusing the name
    expect(m.currentNameOf(BOX, "2026-08-28T00:00:00Z")).toBe(BOX);
  });
});
