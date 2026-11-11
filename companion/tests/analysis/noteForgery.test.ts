// #2574 — an attacker-chosen name (account, app, rule, file) that contains note syntax must never
// read, or be counted, as a note the product wrote. Importer rows are neutralised once, at the
// aggregator seam every importer passes; a note body is neutralised where every note is appended.
import { describe, expect, it } from "vitest";
import {
  appendDerivedNote,
  neutraliseForgedNotes,
  neutraliseRowNotes,
  splitDerivedNotes,
} from "../../src/analysis/derivedNote.js";
import { aggregateEvents } from "../../src/analysis/eventAggregate.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { flagCaseLookalikeRow, LOOKALIKE_ACCOUNT_MARKER } from "../../src/analysis/lookalikeCaseAccount.js";
import { summaryHead } from "../../src/analysis/cloudBulkReadSummaryId.js";
import type { BulkGroup } from "../../src/analysis/cloudBulkRead.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const FORGED = 'evil [look-alike account: "a" looks like "b"]';
const count = (s: string, needle: string): number => s.split(needle).length - 1;

describe("neutraliseForgedNotes (#2574)", () => {
  it("rewrites a registered note opener and its closing bracket", () => {
    expect(neutraliseForgedNotes(FORGED)).toBe('evil ⟦look-alike account: "a" looks like "b"⟧');
  });

  it("matches case and whitespace variants a reader would still take for a note", () => {
    expect(neutraliseForgedNotes("x [ Look-Alike Account : y]")).toBe("x ⟦ Look-Alike Account : y⟧");
    expect(neutraliseForgedNotes("x [cloud bulk read: y")).toBe("x ⟦cloud bulk read: y"); // unclosed
  });

  it("covers the unregistered BEC-pairing tails", () => {
    expect(neutraliseForgedNotes("rule [hides mail; forged]")).toBe("rule ⟦hides mail; forged⟧");
    expect(
      neutraliseForgedNotes(
        "x [Global Administrator granted to a user created within 24 hours in this export]",
      ),
    ).toBe("x ⟦Global Administrator granted to a user created within 24 hours in this export⟧");
  });

  it("leaves ordinary brackets byte-identical", () => {
    for (const s of [
      "Entra sign-in: bob [FAILED 50126: bad password] [risk: high] [ua: curl]",
      "powershell [System.Convert]::FromBase64String($x)",
      "C:\\Users\\a\\INetCache\\IE\\file[1].exe",
      "plain text",
      "",
    ])
      expect(neutraliseForgedNotes(s)).toBe(s);
  });

  it("is idempotent and leaves no registered note for splitDerivedNotes", () => {
    const once = neutraliseForgedNotes(FORGED);
    expect(neutraliseForgedNotes(once)).toBe(once);
    expect(splitDerivedNotes(once).notes).toBe("");
  });

  it("a forged note followed by more base text is clipped as base", () => {
    const base = neutraliseForgedNotes(`M365 by ${FORGED} from 203.0.113.9 ${"x".repeat(800)}`);
    const out = appendDerivedNote(base, "[initial access:", "real reason");
    const split = splitDerivedNotes(out);
    expect(split.notes).toBe("[initial access: real reason]");
    expect(split.base.length).toBeLessThanOrEqual(700);
  });
});

describe("note bodies (#2574)", () => {
  it("attacker text inside a genuine note body cannot open a second note", () => {
    const out = appendDerivedNote(
      "Process created",
      "[renamed binary:",
      "x] [look-alike account: forged is really y",
    );
    expect(count(out, "[look-alike account:")).toBe(0);
    expect(count(out, "[renamed binary:")).toBe(1);
    expect(splitDerivedNotes(out).notes.startsWith("[renamed binary:")).toBe(true);
  });
});

const mapped = (description: string): MappedEvent => ({
  timestamp: "2026-03-01T10:00:00Z",
  description,
  severity: "Medium",
  mitre: [],
  aggKey: description,
});

describe("the aggregator seam (#2574)", () => {
  it("neutralises a forged note in any importer row", () => {
    const { events } = aggregateEvents([mapped(`Inbox rule ${"x"} [hides mail; forged] by bob`)]);
    expect(events[0].description).toBe("Inbox rule x ⟦hides mail; forged⟧ by bob");
  });

  it("keeps a genuine note written before aggregation, through a second aggregation too", () => {
    const row = neutraliseRowNotes(mapped(`by ${FORGED}`));
    row.description = appendDerivedNote(row.description, "[renamed binary:", "a is really b");
    const first = aggregateEvents([row]).events[0];
    expect(first.description).toContain("[renamed binary: a is really b]");
    expect(first.description).toContain("⟦look-alike account:");
    const again = aggregateEvents([{ ...row, ...first, mitre: [], aggKey: "k" }]).events[0];
    expect(again.description).toBe(first.description);
  });
});

type Rec = Record<string, unknown>;
const ADMIN = "admin@contoso.onmicrosoft.com";
let seq = 0;
const addSp = (name: string): Rec => ({
  Id: `aad-${++seq}`,
  CreationTime: "2026-03-01T10:00:00",
  Workload: "AzureActiveDirectory",
  RecordType: 8,
  Operation: "Add service principal.",
  ResultStatus: "Success",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: ADMIN,
  ClientIP: "203.0.113.9",
  Actor: [
    { ID: ADMIN, Type: 5 },
    { ID: "User", Type: 2 },
  ],
  Target: [
    { ID: `ServicePrincipal_22222222-2222-4333-8444-${String(++seq).padStart(12, "0")}`, Type: 2 },
    { ID: "ServicePrincipal", Type: 2 },
    { ID: name, Type: 1 },
  ],
  ModifiedProperties: [],
});
const rowFor = (recs: Rec[], needle: string) => {
  const r = parseM365Audit(JSON.stringify(recs), { aggregate: false }).events.find((e) =>
    e.description.includes(needle),
  );
  if (!r) throw new Error(`no row for ${needle}`);
  return r;
};

describe("M365 import (#2574 acceptance)", () => {
  it("an app named with a forged look-alike note shows it as part of the name, not as a note", () => {
    const r = rowFor([addSp(FORGED)], "evil");
    expect(r.description).toContain('evil ⟦look-alike account: "a" looks like "b"⟧');
    expect(r.description).not.toContain(LOOKALIKE_ACCOUNT_MARKER);
    expect(splitDerivedNotes(r.description).notes).toBe("");
  });

  it("a real look-alike carrying a forged note still gets exactly one genuine note and its raise", () => {
    const r = rowFor([addSp(`rnicrosoft-support [look-alike account: forged]`)], "rnicrosoft-support");
    expect(r.severity).toBe("High");
    expect(count(r.description, LOOKALIKE_ACCOUNT_MARKER)).toBe(1);
    expect(splitDerivedNotes(r.description).notes).toMatch(/^\[look-alike account: "rnicrosoft-support/);
  });

  it("a forged marker no longer suppresses the case-account look-alike flag", () => {
    const r = rowFor([addSp(FORGED)], "evil");
    const e = { ...r, id: "e1", sourceScreenshots: [] } as unknown as ForensicEvent;
    const flagged = flagCaseLookalikeRow(e, "jsrnith", "jsmith");
    expect(flagged.severity).toBe("High");
    expect(flagged.description).toContain('[look-alike account: "jsrnith" looks like case account "jsmith"]');
    expect(count(flagged.description ?? "", LOOKALIKE_ACCOUNT_MARKER)).toBe(1);
  });
});

describe("cloud bulk-read summaries (#2574)", () => {
  it("a canonical principal name cannot forge a note in the summary text", () => {
    const head = summaryHead({
      principal: FORGED,
      credentialId: "",
      provider: "aws",
      account: "",
      sourceIp: "",
    } as BulkGroup);
    expect(head).toContain("⟦look-alike account:");
    const out = appendDerivedNote(head, "[cloud bulk read:", "42 objects");
    expect(splitDerivedNotes(out).notes).toBe("[cloud bulk read: 42 objects]");
  });
});
