import { describe, it, expect } from "vitest";
import { flagCaseLookalikesScoped } from "../../src/routes/importSettleLookalike.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { memoryRowStore } from "../helpers/memoryRowStore.js";

// #1971 review: the look-alike check read only the SIEM/EVTX rendering "(EID 4720)". Hayabusa renders
// "(EID 4720 Sec)" and carries the account in its detail fields, so its account changes never entered
// the check. Every row here is built by the real importer and then run through the settle step.

type Row = Omit<ForensicEvent, "id" | "relatedFindingIds" | "sourceScreenshots">;

const asRows = (events: readonly Row[], prefix: string): ForensicEvent[] =>
  events.map((e, i) => ({ ...e, id: `${prefix}${i}`, relatedFindingIds: [], sourceScreenshots: [] }));

// A real account's logon, from the SIEM importer: the case already holds "svc-backup".
const siemLogon = asRows(
  parseSiemExport(
    JSON.stringify({
      data: [
        {
          _index: "win",
          _type: "winevtx",
          _source: {
            "@timestamp": "2026-08-26T13:50:08.000Z",
            log_name: "Security",
            computer_name: "DC01",
            event_id: 4624,
            event_data: { TargetUserName: "svc-backup", TargetDomainName: "CORP", LogonType: "3" },
          },
        },
      ],
    }),
  ).events,
  "s",
)[0];

// A Hayabusa json-timeline record, in the shape its built-in Security rules print.
function haya(eid: number, title: string, details: object, extra: object = {}): object {
  return {
    Timestamp: "2026-08-26 14:00:00.000 +00:00",
    Computer: "DC01.example.com",
    Channel: "Sec",
    EventID: eid,
    Level: "med",
    RuleTitle: title,
    RecordID: 1000 + eid,
    Details: details,
    ...extra,
  };
}

function hayabusaRows(...records: object[]): ForensicEvent[] {
  const text = records.map((r) => JSON.stringify(r)).join("\n");
  return asRows(parseHayabusaTimeline(text, { aggregate: false }).events, "h");
}

// A Chainsaw hunt detection on a Security record.
function chainsaw(eid: number, data: Record<string, string>): object {
  return {
    group: "Sigma",
    kind: "individual",
    document: {
      kind: "evtx",
      path: "Security.evtx",
      data: {
        Event: {
          System: {
            Provider: { "#attributes": { Name: "Microsoft-Windows-Security-Auditing" } },
            EventID: eid,
            Channel: "Security",
            Computer: "DC01.example.com",
            TimeCreated: { "#attributes": { SystemTime: "2026-08-26T14:00:00Z" } },
          },
          EventData: data,
        },
      },
    },
    rule: { name: `Security ${eid}`, level: "medium", tags: ["attack.t1098"] },
    timestamp: "2026-08-26T14:00:00Z",
  };
}

const chainsawRows = (...records: object[]): ForensicEvent[] =>
  asRows(parseChainsawReport(JSON.stringify(records)).events, "c");

const caseWith = (...events: ForensicEvent[]): InvestigationState =>
  ({ caseId: "c1", iocs: [], forensicTimeline: events }) as unknown as InvestigationState;

async function settle(pool: ForensicEvent[], added: ForensicEvent): Promise<ForensicEvent | undefined> {
  const store = memoryRowStore(caseWith(...pool, added));
  expect(await flagCaseLookalikesScoped(store, "c1", [added])).toBe(1);
  return (await store.load()).forensicTimeline.find((e) => e.id === added.id);
}

const NOTE = '[look-alike account: "svc-backupl" is one edit from case account "svc-backup"';

describe("look-alike check over Hayabusa rows (#1971 review)", () => {
  it("flags a Hayabusa account creation", async () => {
    const [created] = hayabusaRows(
      haya(4720, "Local User Created", { User: "svc-backupl", SID: "S-1-5-21-1-2-3-1110" }),
    );
    expect(created?.description).toContain("(EID 4720 Sec)");
    expect(created?.severity).toBe("Medium");
    const row = await settle([siemLogon], created);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain(NOTE);
  });

  it("flags a Hayabusa account creation that keeps the raw TargetUserName field", async () => {
    const [created] = hayabusaRows(
      haya(4720, "Local User Created", { TgtUser: "CORP\\svc-backupl", SrcUser: "operator" }),
    );
    const row = await settle([siemLogon], created);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain(NOTE);
  });

  it("flags a Hayabusa group add that names the member by DN", async () => {
    const [added] = hayabusaRows(
      haya(4728, "User Added To Global Security Group", {
        User: "CN=svc-backupl,CN=Users,DC=example,DC=com",
        SID: "S-1-5-21-1-2-3-1110",
        Group: "Backup Operators",
      }),
    );
    const row = await settle([siemLogon], added);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain(NOTE);
  });

  it("reads the member, never the group, from a raw-field Hayabusa group add", async () => {
    const [added] = hayabusaRows(
      haya(
        4732,
        "User Added To Local Group",
        { MemberSid: "S-1-5-21-1-2-3-1110" },
        { ExtraFieldInfo: { TargetUserName: "svc-backups", MemberName: "svc-backupl" } },
      ),
    );
    const row = await settle([siemLogon], added);
    expect(row?.description).toContain(NOTE);
  });

  it("finds the case account in an earlier Hayabusa row too", async () => {
    const [prior, created] = hayabusaRows(
      haya(4648, "Explicit Logon", { TgtUser: "svc-backup", SrcUser: "operator" }),
      haya(4720, "Local User Created", { User: "svc-backupl" }),
    );
    const row = await settle([prior], created);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain(NOTE);
  });

  it("skips a Hayabusa group add that names the member by SID only", async () => {
    const [added] = hayabusaRows(
      haya(4732, "User Added To Local Group", { SID: "S-1-5-21-1-2-3-1110", Group: "Administrators" }),
    );
    const store = memoryRowStore(caseWith(siemLogon, added));
    expect(await flagCaseLookalikesScoped(store, "c1", [added])).toBe(0);
  });
});

describe("look-alike check over Chainsaw rows (#1971 review)", () => {
  it("flags a Chainsaw account creation", async () => {
    const [created] = chainsawRows(
      chainsaw(4720, {
        TargetUserName: "svc-backupl",
        TargetDomainName: "CORP",
        SubjectUserName: "operator",
      }),
    );
    const row = await settle([siemLogon], created);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain(NOTE);
  });

  it("flags a Chainsaw group add", async () => {
    const [added] = chainsawRows(
      chainsaw(4732, {
        MemberName: "CN=svc-backupl,CN=Users,DC=example,DC=com",
        TargetUserName: "Backup Operators",
        SubjectUserName: "operator",
      }),
    );
    const row = await settle([siemLogon], added);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain(NOTE);
  });
});
