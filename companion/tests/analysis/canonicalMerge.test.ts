import { describe, it, expect } from "vitest";
import { createCanonicalEvent, type CanonicalEventEnvelope } from "../../src/analysis/canonicalEvent.js";
import { mergeCanonicalEvents } from "../../src/analysis/canonicalMerge.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #965 — the canonical envelope must survive both merge paths: correlate.mergeGroup (which used to
// spread only the primary) and the state merge of a re-imported row (which used to keep the first
// envelope's normalised fields whatever the re-import had learned).

const TS = "2026-06-01T10:00:05.000Z";

function envelope(
  input: Partial<Parameters<typeof createCanonicalEvent>[0]> & { importer?: string; locator?: string },
): CanonicalEventEnvelope {
  const { importer = "windows-event", locator = "row:0", ...rest } = input;
  return createCanonicalEvent({
    event: { category: "other", type: "event" },
    time: { observed: TS, normalized: TS },
    evidence: { rawRecords: [{ source: importer, locator }] },
    producer: { importer, parserVersion: "1", mappingVersion: `${importer}-v1` },
    ...rest,
  });
}

const generic = envelope({ locator: "row:0" });
const decoded = envelope({
  event: { category: "file", type: "action", action: "Allow", outcome: "success" },
  object: { kind: "file", id: "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}", name: "Trojan:Win32/Wacatac.B!ml" },
  file: { path: "C:\\Users\\a.mehta\\Downloads\\invoice.exe", name: "invoice.exe" },
  locator: "row:0",
});

describe("mergeCanonicalEvents (state merge of a re-imported row)", () => {
  it("a re-import from an importer that learned new fields upgrades the stored envelope in full", () => {
    const merged = mergeCanonicalEvents(generic, decoded);
    expect(merged?.event).toEqual({ category: "file", type: "action", action: "Allow", outcome: "success" });
    expect(merged?.object).toEqual(decoded.object);
    expect(merged?.file).toEqual(decoded.file);
  });

  it("the existing envelope fills what the re-import lacks", () => {
    const withActor = envelope({ actor: { kind: "account", name: "CORP\\a.mehta" }, locator: "row:0" });
    const merged = mergeCanonicalEvents(withActor, decoded);
    expect(merged?.actor).toEqual({ kind: "account", name: "CORP\\a.mehta" });
    expect(merged?.event.outcome).toBe("success");
  });

  it("a legacy-upgrade envelope echoed back never overwrites an importer's typed fields", () => {
    const echoed = envelope({
      importer: "legacy-upgrade",
      event: { category: "file", type: "observation" },
      actor: { kind: "account", name: "CORP\\a.mehta" },
      locator: "event:e1",
    });
    const merged = mergeCanonicalEvents(decoded, echoed);
    expect(merged?.event).toEqual(decoded.event);
    expect(merged?.object).toEqual(decoded.object);
    expect(merged?.actor).toEqual({ kind: "account", name: "CORP\\a.mehta" }); // a gap is still filled
  });

  it("a matching evidence pointer keeps the record id whichever side carried it", () => {
    const withId = envelope({ locator: "row:0" });
    withId.evidence.rawRecords[0].recordId = "Security/4711";
    const without = envelope({ locator: "row:0", event: { category: "file", type: "action" } });
    expect(mergeCanonicalEvents(withId, without)?.evidence.rawRecords).toEqual([
      { source: "windows-event", locator: "row:0", recordId: "Security/4711" },
    ]);
    expect(mergeCanonicalEvents(without, withId)?.evidence.rawRecords).toEqual([
      { source: "windows-event", locator: "row:0", recordId: "Security/4711" },
    ]);
  });

  it("an entity of a different kind is taken whole, never filled with the other kind's fields", () => {
    const network = envelope({
      target: { kind: "network", address: "10.0.0.5", port: 445 },
      locator: "row:0",
    });
    const account = envelope({ target: { kind: "account", name: "svc" }, locator: "row:0" });
    expect(mergeCanonicalEvents(network, account)?.target).toEqual({ kind: "account", name: "svc" });
    expect(mergeCanonicalEvents(account, network)?.target).toEqual({
      kind: "network",
      address: "10.0.0.5",
      port: 445,
    });
  });

  it("is idempotent and keeps evidence and provenance deduped", () => {
    const once = mergeCanonicalEvents(generic, decoded)!;
    const twice = mergeCanonicalEvents(once, decoded)!;
    expect(twice).toEqual(once);
    expect(once.evidence.rawRecords).toEqual([{ source: "windows-event", locator: "row:0" }]);
    for (const p of Object.values(once.fieldProvenance)) {
      expect(new Set(p.recordLocators).size).toBe(p.recordLocators.length);
    }
  });
});

const DEFENDER_RECORD = {
  "@timestamp": TS,
  log_name: "Microsoft-Windows-Windows Defender/Operational",
  computer_name: "WS-042.corp.example.invalid",
  event_id: 1117,
  message: "Microsoft Defender Antivirus has taken action to protect this machine.",
  event_data: {
    "Detection ID": "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}",
    "Threat Name": "Trojan:Win32/Wacatac.B!ml",
    "Severity Name": "Severe",
    Path: "file:_C:\\Users\\a.mehta\\Downloads\\invoice.exe",
    "Action Name": "Allow",
    "Error Code": "0x00000000",
  },
};

function defenderRow(): ForensicEvent {
  const [e] = parseSiemExport(JSON.stringify([DEFENDER_RECORD])).events;
  return { ...e, relatedFindingIds: [], sourceScreenshots: [], sources: ["Windows Event Log"] };
}

// A Hayabusa Sigma hit over the same record grades High from the rule level and carries no envelope
// of its own — the real shape that made a decoded Defender row lose its typed fields at the merge.
function sigmaRow(base: ForensicEvent, canonical?: CanonicalEventEnvelope): ForensicEvent {
  return {
    ...base,
    id: "hayabusa-1",
    description: "Windows Defender Threat Detected (Sigma: high) - Trojan:Win32/Wacatac.B!ml",
    severity: "High",
    sources: ["Hayabusa"],
    ...(canonical ? { canonical } : { canonical: undefined }),
  };
}

describe("correlateEvents keeps the canonical envelope across a group merge", () => {
  it.each([["defender first"], ["sigma first"]])(
    "a Defender row merged under a higher-severity primary keeps its typed fields (%s)",
    (order) => {
      const defender = defenderRow();
      const sigma = sigmaRow(defender);
      const input = order === "defender first" ? [defender, sigma] : [sigma, defender];
      const out = correlateEvents(input);
      expect(out).toHaveLength(1);
      expect(out[0].severity).toBe("High");
      expect(out[0].canonical?.event).toMatchObject({ type: "action", action: "Allow", outcome: "success" });
      expect(out[0].canonical?.object).toEqual(defender.canonical?.object);
      expect(out[0].canonical?.file?.path).toBe("C:\\Users\\a.mehta\\Downloads\\invoice.exe");
    },
  );

  it("on a conflict the primary's value wins and the member's record is cited in provenance", () => {
    const defender = defenderRow();
    const sigma = sigmaRow(
      defender,
      envelope({
        importer: "hayabusa",
        event: { category: "file", type: "detection", outcome: "unknown" },
        locator: "row:7",
      }),
    );
    const out = correlateEvents([defender, sigma]);
    expect(out).toHaveLength(1);
    expect(out[0].canonical?.event.outcome).toBe("unknown"); // the High primary's word
    expect(out[0].canonical?.event.action).toBe("Allow"); // the member fills the gap
    expect(out[0].canonical?.object).toEqual(defender.canonical?.object);
    expect(out[0].canonical?.evidence.rawRecords).toEqual([
      { source: "hayabusa", locator: "row:7" },
      ...defender.canonical!.evidence.rawRecords,
    ]);
    expect(out[0].canonical?.fieldProvenance["event.outcome"]?.recordLocators).toContain("row:7");
  });

  it("a second correlate pass over the merged row changes nothing", () => {
    const defender = defenderRow();
    const once = correlateEvents([defender, sigmaRow(defender)]);
    expect(correlateEvents(once)).toEqual(once);
  });
});
