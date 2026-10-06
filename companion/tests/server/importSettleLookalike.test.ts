import { describe, it, expect } from "vitest";
import { flagCaseLookalikesScoped } from "../../src/routes/importSettleLookalike.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { memoryRowStore } from "../helpers/memoryRowStore.js";

// #1971: the settle step compares this import's new accounts with the case's own account names.

const win = (eid: number, data: Record<string, string>) => ({
  "@timestamp": "2026-08-26T13:50:08.000Z",
  log_name: "Security",
  computer_name: "H1",
  event_id: eid,
  event_data: data,
});

function rows(...records: object[]): ForensicEvent[] {
  const json = JSON.stringify({
    data: records.map((s) => ({ _index: "win", _type: "winevtx", _source: s })),
  });
  return parseSiemExport(json).events.map((e, i) => ({
    ...e,
    id: `r${i}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
}

const parsed = rows(
  win(4624, {
    TargetUserName: "svc-backup",
    TargetDomainName: "CORP",
    LogonType: "3",
    IpAddress: "10.0.0.5",
  }),
  win(4720, {
    TargetUserName: "svc-backupl",
    TargetDomainName: "CORP",
    SubjectUserName: "operator",
    SubjectDomainName: "CORP",
  }),
);
const byEid = (eid: number): ForensicEvent => {
  const e = parsed.find((r) => r.description.includes(`(EID ${eid})`));
  if (!e) throw new Error(`no ${eid} row`);
  return e;
};
const logon = byEid(4624);
const created = byEid(4720);

function caseWith(...events: ForensicEvent[]): InvestigationState {
  return { caseId: "c1", iocs: [], forensicTimeline: events } as unknown as InvestigationState;
}

describe("flagCaseLookalikesScoped (#1971)", () => {
  it("raises a new account one edit from an existing case account to High with a note", async () => {
    expect(created.severity).toBe("Medium");
    const store = memoryRowStore(caseWith(logon, created));
    expect(await flagCaseLookalikesScoped(store, "c1", [created])).toBe(1);
    const row = (await store.load()).forensicTimeline.find((e) => e.id === created.id);
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain('[look-alike account: "svc-backupl" is one edit from case account');
  });

  it("does not scan the case when the import added no account change", async () => {
    const store = memoryRowStore(caseWith(logon, created));
    let scans = 0;
    const batches = store.forensicTimelineBatches.bind(store);
    store.forensicTimelineBatches = (...args) => {
      scans++;
      return batches(...args);
    };
    expect(await flagCaseLookalikesScoped(store, "c1", [logon])).toBe(0);
    expect(scans).toBe(0);
  });

  it("does not add the note twice on a later settle", async () => {
    const store = memoryRowStore(caseWith(logon, created));
    await flagCaseLookalikesScoped(store, "c1", [created]);
    const first = (await store.load()).forensicTimeline.find((e) => e.id === created.id);
    expect(await flagCaseLookalikesScoped(store, "c1", [first as ForensicEvent])).toBe(0);
    const row = (await store.load()).forensicTimeline.find((e) => e.id === created.id);
    expect(row?.description.match(/\[look-alike account:/g)).toHaveLength(1);
  });

  it("leaves a new account with no look-alike in the case alone", async () => {
    const store = memoryRowStore(caseWith(created));
    expect(await flagCaseLookalikesScoped(store, "c1", [created])).toBe(0);
  });
});
