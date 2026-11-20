import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { deriveSemanticKey } from "../../src/analysis/semanticKey.js";
import { findingVerdictKey } from "../../src/analysis/timeline/watsonVerdicts.js";
import { buildRedactedExport, type RedactedExportDeps } from "../../src/reports/redactedExportBuilder.js";
import { DEFAULT_REDACTED_EXPORT_OPTIONS } from "../../src/analysis/redactedExport.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { redactDerivedKeys } from "../../src/analysis/redactedDerivedKeys.js";

// The redacted package must not carry raw user/host words inside identifiers DERIVED from text
// (a finding's semanticKey, a Watson verdict's match key): the redactor sees those as one
// underscore-joined, lowercased blob and has no detector for it.

const USER_WORDS = ["alice", "bob"];
const HOST_WORDS = ["dc01", "alice01"];

function finding(id: string, title: string): Finding {
  const f = {
    id,
    title,
    description: title,
    severity: "High",
    status: "open",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1059"],
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
  } as unknown as Finding;
  return { ...f, semanticKey: deriveSemanticKey(f) };
}

function seededState(): InvestigationState {
  const base = emptyState("c1");
  const f1 = finding("f-1", "CORP\\alice logged on to dc01.corp.example.com");
  const f2 = finding("f-2", "bob@corp.example.com ran powershell on WS-ALICE01");
  return {
    ...base,
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: "CORP\\alice logged on from 10.20.30.40 to dc01.corp.example.com",
        severity: "High",
        asset: "dc01.corp.example.com",
        mitreTechniques: [],
        relatedFindingIds: ["f-1"],
        sourceScreenshots: [],
      },
      {
        id: "e2",
        timestamp: "2026-01-01T00:01:00Z",
        description: "bob@corp.example.com ran powershell on WS-ALICE01",
        severity: "High",
        asset: "WS-ALICE01",
        mitreTechniques: [],
        relatedFindingIds: ["f-2"],
        sourceScreenshots: [],
      },
    ],
    findings: [f1, f2],
    watsonFindingVerdicts: [
      {
        key: findingVerdictKey(f2),
        action: "dismiss",
        reason: "benign",
        eventIds: [],
        consideredEventIds: [],
        proposalId: "p1",
        approvedBy: "analyst",
        at: "2026-01-02T00:00:00Z",
        title: f2.title,
      },
      {
        key: `title:${f1.title.trim().toLowerCase()}`,
        action: "dismiss",
        reason: "benign",
        eventIds: [],
        consideredEventIds: [],
        proposalId: "p2",
        approvedBy: "analyst",
        at: "2026-01-02T00:00:00Z",
        title: f1.title,
      },
    ],
  };
}

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-redacted-keys-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  await stateStore.save(seededState());
});

function deps(): RedactedExportDeps {
  return {
    store: caseStore,
    reportWriter: new ReportWriter(caseStore, stateStore),
    stateStore,
    customEntities: { load: async () => [] } as unknown as RedactedExportDeps["customEntities"],
    discoveredEntities: {
      load: async () => ({ discovered: [], suppressed: [] }),
    } as unknown as RedactedExportDeps["discoveredEntities"],
    ocrRunner: { recognize: async () => [] },
    listScreenshots: async () => [],
  };
}

describe("redacted export — derived keys carry no raw user/host words", () => {
  it("state-export.json (and every other file) names neither the user nor the host", async () => {
    const { zip } = await buildRedactedExport(deps(), "c1", DEFAULT_REDACTED_EXPORT_OPTIONS);
    const entries = readZip(zip);
    const stateJson = entries.find((e) => e.path === "report/state-export.json")!.data.toString("utf8");
    const parsed = JSON.parse(stateJson) as InvestigationState;
    // The keys are still there, so the package keeps its shape; only their words changed.
    expect(parsed.findings.every((f) => typeof f.semanticKey === "string" && f.semanticKey.length > 0)).toBe(
      true,
    );
    for (const e of entries) {
      const text = e.data.toString("utf8").toLowerCase();
      for (const word of [...USER_WORDS, ...HOST_WORDS]) {
        expect(text, `${e.path} contains "${word}"`).not.toMatch(
          new RegExp(`(^|[^a-z0-9])${word}([^a-z0-9]|$)`),
        );
      }
    }
  });
});

describe("redactDerivedKeys", () => {
  it("rebuilds keys from the already-redacted title, and leaves the input untouched", () => {
    const state = {
      ...emptyState("c1"),
      findings: [{ ...finding("f-1", "ANON_USER_1 ran powershell"), semanticKey: "T1059:alice_powershell" }],
      watsonFindingVerdicts: [
        { key: "key:T1059:alice_powershell", title: "ANON_USER_1 ran powershell" },
        { key: "title:alice ran powershell", title: "ANON_USER_1 ran powershell" },
        { key: "id:f-det-1", title: "ANON_USER_1 ran powershell" },
      ],
    } as unknown as InvestigationState;
    const out = redactDerivedKeys(state);
    expect(out.findings[0].semanticKey).toBe("T1059:anon_powershell_ran_user");
    expect(out.watsonFindingVerdicts!.map((v) => v.key)).toEqual([
      "key:T1059:anon_powershell_ran_user",
      "title:anon_user_1 ran powershell",
      "id:f-det-1",
    ]);
    expect(state.findings[0].semanticKey).toBe("T1059:alice_powershell");
  });
});
