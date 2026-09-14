import { describe, expect, it } from "vitest";
import {
  kerberoastChain,
  splitAccount,
  realmCompatible,
  normaliseAddress,
  TICKET_ROWS_PER_ACCOUNT_MAX,
} from "../../src/analysis/kerberoastChain.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #930 item 6: a ticket request names a service account; a later row where that exact account
// acts is a use; the baseline is what the case holds before the request; nothing says "cracked".

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const NOW = at(1000);

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e",
  timestamp: at(1),
  description: "d",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS01",
  ...over,
});
const canon = (c: object) => ({ canonical: c as never });

/** A 4769 on the DC: requester R from client C for service S, enc type E. */
const tgs = (
  service: string,
  ts: string,
  over: {
    id?: string;
    enc?: string;
    requester?: string;
    client?: string;
    dc?: string;
    outcome?: string;
  } = {},
): ForensicEvent =>
  ev({
    id: over.id ?? `t-${service}-${ts}`,
    timestamp: ts,
    asset: over.dc ?? "DC01.corp.local",
    severity: "Medium",
    mitreTechniques: ["T1558.003"],
    ...canon({
      event: { category: "authentication", type: "ticket-request", outcome: over.outcome ?? "success" },
      actor: { kind: "account", name: over.requester ?? "attacker@CORP.LOCAL", domain: "CORP.LOCAL" },
      object: { kind: "account", name: service },
      authentication: { protocol: "kerberos", mechanism: over.enc ?? "0x17" },
      ...(over.client === "" ? {} : { network: { source: { address: over.client ?? "10.0.0.66" } } }),
    }),
  });
const logon = (
  account: string,
  host: string,
  ts: string,
  over: { id?: string; type?: number; src?: string; sid?: string; outcome?: string; domain?: string } = {},
): ForensicEvent =>
  ev({
    id: over.id ?? `l-${account}-${host}-${ts}`,
    timestamp: ts,
    asset: host,
    ...canon({
      event: { category: "authentication", type: "logon", outcome: over.outcome ?? "success" },
      actor: {
        kind: "account",
        name: account,
        ...(over.domain
          ? { domain: over.domain }
          : account.includes("\\")
            ? { domain: account.split("\\")[0] }
            : {}),
      },
      account: { name: account, ...(over.sid ? { id: over.sid } : {}) },
      authentication: { logonType: over.type ?? 3 },
      ...(over.src ? { network: { source: { address: over.src } } } : {}),
    }),
  });
const proc = (
  account: string,
  host: string,
  ts: string,
  exe = "C:\\Windows\\System32\\cmd.exe",
  id?: string,
): ForensicEvent =>
  ev({
    id: id ?? `p-${host}-${ts}`,
    timestamp: ts,
    asset: host,
    ...canon({
      event: { category: "process", type: "start" },
      actor: {
        kind: "account",
        name: account,
        ...(account.includes("\\") ? { domain: account.split("\\")[0] } : {}),
      },
      process: { executable: exe },
    }),
  });
const anyRow = (host: string, ts: string, id?: string): ForensicEvent =>
  ev({
    id: id ?? `x-${host}-${ts}`,
    timestamp: ts,
    asset: host,
    ...canon({ event: { category: "other", type: "event" } }),
  });
const tool = (host: string, account: string, ts: string, id = "tool"): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    asset: host,
    severity: "High",
    mitreTechniques: ["T1558.003"],
    ...canon({
      event: { category: "process", type: "start" },
      actor: { kind: "account", name: account, domain: account.split("\\")[0] },
      process: { executable: "C:\\Users\\a\\Rubeus.exe", commandLine: "Rubeus.exe kerberoast" },
    }),
  });
const stateOf = (events: ForensicEvent[]) => ({ ...emptyState("c1"), forensicTimeline: events });

describe("identity helpers", () => {
  it("splits DOMAIN\\user, user@realm and a bare name; realms are compatible only when both exist and match by label", () => {
    expect(splitAccount("CORP\\svc_sql")).toEqual({ name: "svc_sql", realm: "CORP" });
    expect(splitAccount("svc_sql@corp.local")).toEqual({ name: "svc_sql", realm: "corp.local" });
    expect(splitAccount("svc_sql")).toEqual({ name: "svc_sql" });
    expect(realmCompatible("CORP", "corp.local")).toBe(true);
    expect(realmCompatible("corp.local", "CORP")).toBe(true);
    expect(realmCompatible("CORP", "corp")).toBe(true);
    expect(realmCompatible("CORP", "other.local")).toBe(false);
    expect(realmCompatible("CORP", "corp.local.example")).toBe(true);
    expect(realmCompatible(undefined, "CORP")).toBe(false);
    expect(realmCompatible("CORP", undefined)).toBe(false);
  });
  it("normalises IPv4-mapped IPv6 and refuses placeholders", () => {
    expect(normaliseAddress("::ffff:10.0.0.66")).toBe("10.0.0.66");
    expect(normaliseAddress("10.0.0.66")).toBe("10.0.0.66");
    for (const bad of ["-", "", "::1", "127.0.0.1", "0.0.0.0", "::", "fe80::1", "169.254.1.1"])
      expect(normaliseAddress(bad)).toBeNull();
  });
});

describe("kerberoastChain — stages over exact identity", () => {
  it("RC4 request → later type-3 logon of CORP\\svc_sql on a host not seen before from the same address: every stage; nothing says cracked", () => {
    const rows = [
      anyRow("FS01", at(0)),
      tgs("svc_sql", at(10), { id: "t1" }),
      logon("CORP\\svc_sql", "FS01", at(12), { id: "u1", src: "::ffff:10.0.0.66", sid: "S-1-5-21-1" }),
      proc("CORP\\svc_sql", "FS01", at(13), "C:\\Windows\\System32\\cmd.exe", "u2"),
    ];
    const c = kerberoastChain(stateOf(rows), NOW);
    expect(c.accounts).toHaveLength(1);
    const a = c.accounts[0];
    expect(a).toMatchObject({
      service: "svc_sql",
      realm: "corp.local",
      realmSource: "dc-fqdn",
      t0: at(10),
      t0Anchors: true,
      stage: "first-seen-host-use",
    });
    expect(a.requests[0]).toMatchObject({
      eventId: "t1",
      rc4: true,
      outcome: "success",
      clientAddress: "10.0.0.66",
      dc: "DC01.corp.local",
      requester: "attacker@CORP.LOCAL",
    });
    expect(a.uses.map((u) => [u.eventId, u.kind, u.placement, u.firstSeenHost, u.hostBaseline])).toEqual([
      ["u1", "logon", "after", true, "available"],
      ["u2", "process-start", "after", true, "available"],
    ]);
    expect(a.uses[0].sameObservedAddress).toEqual({
      requestEventId: "t1",
      requestObserver: "DC01.corp.local",
      requestAddress: "10.0.0.66",
      useAddress: "::ffff:10.0.0.66",
    });
    expect(a.uses[1].sameObservedAddress).toBeUndefined();
    expect(a.evidence["ticket-requested"]).toEqual(["t1"]);
    expect(a.evidence["account-used-after"]).toEqual(["u1", "u2"]);
    expect(a.evidence["first-seen-host-use"]).toEqual(["u1", "u2"]);
    expect(a.sameObservedAddressCount).toBe(1);
    expect(a.acquisition).toContain("not observable in any row");
    expect(JSON.stringify(c)).not.toMatch(/password was cracked|cracking succeeded|attacker used/i);
    expect(a.baseline.hostsBefore).toEqual([]);
    expect(a.baseline.note).toContain("no prior use of this account observed in the case");
  });
  it("use on a host the account was already seen on before T0 is continuing operation: account-used-after only, the baseline said", () => {
    const rows = [
      logon("CORP\\svc_sql", "SQL01", at(1), { id: "b1", type: 5 }),
      logon("CORP\\svc_sql", "SQL01", at(2), { id: "b2", type: 5 }),
      tgs("svc_sql", at(10), { id: "t1" }),
      logon("CORP\\svc_sql", "SQL01", at(12), { id: "u1", type: 5 }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.stage).toBe("account-used-after");
    expect(a.baseline.hostsBefore).toEqual([{ host: "SQL01", count: 2, first: at(1), last: at(2) }]);
    expect(a.uses[0]).toMatchObject({ eventId: "u1", firstSeenHost: false, placement: "after" });
    expect(a.stageReason).toContain(
      "every use after the request is on a host the account was seen on before it (a complete read)",
    );
  });
  it("a host with no rows before T0 has no baseline: first-seen is suppressed for it and the host is named", () => {
    const rows = [
      tgs("svc_sql", at(10), { id: "t1" }),
      logon("CORP\\svc_sql", "NEW01", at(12), { id: "u1" }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.uses[0]).toMatchObject({ firstSeenHost: false, hostBaseline: "unavailable" });
    expect(a.hostsWithoutBaseline).toEqual(["NEW01"]);
    expect(a.stage).toBe("account-used-after");
    expect(a.stageReason).toContain("baseline unavailable");
  });
  it("uses before T0 only → ticket-requested with 'no use after'; a failed logon is not a use but is counted", () => {
    const rows = [
      anyRow("FS01", at(0)),
      logon("CORP\\svc_sql", "FS01", at(5), { id: "b1" }),
      tgs("svc_sql", at(10), { id: "t1" }),
      logon("CORP\\svc_sql", "FS01", at(12), { id: "f1", outcome: "failed" }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.stage).toBe("ticket-requested");
    expect(a.stageReason).toContain("no row after the request shows this account acting (a complete read)");
    expect(a.failedLogonsAfter).toBe(1);
    expect(a.uses).toEqual([]);
  });
  it("identity: svc_sql2, OTHER\\svc_sql and a use with no realm never join; a bare-name use is a candidate that advances nothing", () => {
    const rows = [
      anyRow("FS01", at(0)),
      tgs("svc_sql", at(10), { id: "t1" }),
      logon("CORP\\svc_sql2", "FS01", at(12), { id: "x1" }),
      logon("OTHER\\svc_sql", "FS01", at(12), { id: "x2" }),
      logon("svc_sql", "FS01", at(12), { id: "c1" }),
      logon("SVC_SQL@corp.local", "FS01", at(13), { id: "u1" }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.uses.map((u) => u.eventId)).toEqual(["u1"]);
    expect(a.candidates.map((u) => [u.eventId, u.realmState])).toEqual([["c1", "not-established"]]);
    expect(a.stage).toBe("first-seen-host-use");
  });
  it("the service account's realm comes from the DC's FQDN; a DC named without a domain leaves it not established and every use a candidate", () => {
    const rows = [
      anyRow("FS01", at(0)),
      tgs("svc_sql", at(10), { id: "t1", dc: "DC01" }),
      logon("CORP\\svc_sql", "FS01", at(12), { id: "u1" }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.realm).toBeUndefined();
    expect(a).toMatchObject({ realmSource: "not-established", stage: "ticket-requested" });
    expect(a.candidates.map((u) => u.eventId)).toEqual(["u1"]);
    expect(a.stageReason).toContain("realm not established");
  });
  it("a machine account, krbtgt, an SPN-form and a UPN-form service name are excluded or unjoined, each by reason; an AES-only account is listed only next to an RC4 request by the same requester", () => {
    const rows = [
      tgs("DC01$", at(1), { id: "m" }),
      tgs("krbtgt", at(1), { id: "k" }),
      tgs("MSSQLSvc/db01.corp.local:1433", at(1), { id: "spn" }),
      tgs("svc_web@corp.local", at(1), { id: "upn" }),
      tgs("svc_sql", at(2), { id: "rc4" }),
      tgs("svc_aes", at(2), { id: "aes", enc: "0x12" }),
      tgs("svc_lonely", at(2), { id: "aes2", enc: "0x12", requester: "someone@CORP.LOCAL" }),
      logon("CORP\\svc_aes", "FS01", at(3), { id: "ua" }),
    ];
    const c = kerberoastChain(stateOf(rows), NOW);
    expect(c.accounts.map((a) => [a.service, a.listedBecause])).toEqual([
      ["svc_sql", "rc4-request"],
      ["svc_aes", "aes-request-by-an-rc4-requester"],
    ]);
    expect(c.excluded).toEqual({
      "machine account": 1,
      "krbtgt (TGT service)": 1,
      "SPN form — owner not established from the record": 1,
      "UPN form — owner not established from the record": 1,
      "AES only": 1,
    });
    const aes = c.accounts[1];
    expect(aes.t0).toBeUndefined();
    expect(aes.uses[0].placement).toBe("undetermined");
    expect(aes.stage).toBe("ticket-requested");
    expect(aes.stageReason).toContain("no RC4 request anchors a before / after split");
  });
  it("a refused request (Status ≠ 0) is said as refused and anchors nothing; the RC4 wording names the KDC, not the requester's intent", () => {
    const rows = [
      tgs("svc_sql", at(5), { id: "r", outcome: "failed" }),
      tgs("svc_sql", at(10), { id: "t1" }),
      logon("CORP\\svc_sql", "FS01", at(12), { id: "u1" }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.refusedCount).toBe(1);
    expect(a.t0).toBe(at(10));
    expect(a.rc4Words).toBe(
      "the KDC issued a ticket encrypted with RC4 (0x17 / 0x18), an offline-cracking-compatible type; the record does not say who chose the type",
    );
  });
  it("tool evidence attaches to an account only through the requester's identity; alone it is a lead with the gap said", () => {
    const withTicket = [
      anyRow("FS01", at(0)),
      tool("WS09", "CORP\\attacker", at(9)),
      tgs("svc_sql", at(10), { id: "t1", requester: "CORP\\attacker" }),
    ];
    const c1 = kerberoastChain(stateOf(withTicket), NOW);
    expect(c1.accounts[0].toolEvidence).toEqual(["tool"]);
    expect(c1.toolLeads).toEqual([]);
    const adjacent = [tool("WS09", "CORP\\someone", at(9)), tgs("svc_sql", at(10), { id: "t1" })];
    const c2 = kerberoastChain(stateOf(adjacent), NOW);
    expect(c2.accounts[0].toolEvidence).toEqual([]);
    expect(c2.toolLeads).toEqual([
      {
        eventId: "tool",
        host: "WS09",
        account: "CORP\\someone",
        at: at(9),
        detail: "C:\\Users\\a\\Rubeus.exe",
      },
    ]);
    const alone = kerberoastChain(stateOf([tool("WS09", "CORP\\someone", at(9))]), NOW);
    expect(alone.accounts).toEqual([]);
    expect(alone.gaps).toContain(
      "no ticket-request rows (4769) in the case — the account → use join cannot start; the tool rows are leads",
    );
  });
  it("bounds: past the ticket read bound T0 anchors nothing and every use is undetermined; unread counts are said", () => {
    const many = Array.from({ length: TICKET_ROWS_PER_ACCOUNT_MAX + 2 }, (_, i) =>
      tgs("svc_sql", at(50 + i / 1000), { id: `t${i}` }),
    );
    const rows = [
      anyRow("FS01", at(0)),
      ...many,
      tgs("svc_sql", at(1), { id: "early" }),
      logon("CORP\\svc_sql", "FS01", at(60), { id: "u1" }),
    ];
    const a = kerberoastChain(stateOf(rows), NOW).accounts[0];
    expect(a.requestsTotal).toBe(TICKET_ROWS_PER_ACCOUNT_MAX + 3);
    expect(a.read.ticketRowsUnread).toBe(3);
    expect(a.t0Anchors).toBe(false);
    expect(a.uses[0].placement).toBe("undetermined");
    expect(a.stage).toBe("ticket-requested");
    expect(a.stageReason).toContain("unknown: 3 ticket row(s) unread");
    expect(a.requests).toHaveLength(20);
  });
});
