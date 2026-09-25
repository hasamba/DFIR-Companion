import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport, mapWindows, type SiemIoc } from "../../src/analysis/siemImport.js";
import { regWriteIdentity, regWritePath, regWriteKeys } from "../../src/analysis/securityRegistryWrite.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1670: a Security 4657 exported with NO rendered message carried its key only in
// event_data.ObjectName, which the Windows mapper never rendered, so `win_run_key` could not grade a
// Run-key write. These run the REAL mapper and the SHIPPED ruleset.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

const RUN = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

type Tagged = { severity: string; ruleIds: string[]; description: string; path?: string };

function graded(rec: Record<string, unknown>): Tagged {
  const mapped = parseSiemExport(JSON.stringify([{ "@timestamp": "2026-01-02T03:04:05Z", ...rec }]));
  const event = {
    ...mapped.events[0],
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.events[0].mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return {
    severity: after.severity,
    ruleIds: proposal?.ruleIds ?? [],
    description: after.description,
    path: after.path,
  };
}

function security(eid: number, data: Record<string, string>, channel = "Security"): Record<string, unknown> {
  return { channel, computer_name: "H1", event_id: eid, event_data: data };
}

function mapped(rec: Record<string, unknown>) {
  const m = mapWindows(rec, "H1", new Map<string, SiemIoc>());
  if (!m) throw new Error("mapWindows returned null");
  return m;
}

const ACCOUNT = { SubjectUserName: "alice", SubjectDomainName: "EXAMPLE" };

describe("Security 4657 with no rendered message (#1670)", () => {
  it("grades a Run-key value write Medium through the shipped win_run_key rule", () => {
    const r = graded(
      security(4657, { ...ACCOUNT, ObjectName: RUN, ObjectValueName: "Updater", NewValue: "C:\\u.exe" }),
    );
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
    expect(r.description).toContain(`ObjectName=${RUN}`);
    expect(r.description).toContain("ObjectValueName=Updater");
    expect(r.path).toBe(RUN);
  });

  it("grades a RunOnce write Medium, and a key with no value name", () => {
    expect(graded(security(4657, { ...ACCOUNT, ObjectName: `${RUN}Once` })).severity).toBe("Medium");
  });

  it("grades it when the export names the provider, not the channel", () => {
    const r = graded({
      source_name: "Microsoft-Windows-Security-Auditing",
      computer_name: "H1",
      event_id: 4657,
      event_data: { ...ACCOUNT, ObjectName: RUN, ObjectValueName: "Updater" },
    });
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
  });

  it("grades it when a long key is capped out of the description", () => {
    const deep = `\\REGISTRY\\USER\\S-1-5-21-${"1".repeat(140)}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`;
    const r = graded(security(4657, { ...ACCOUNT, ObjectName: deep, ObjectValueName: "Updater" }));
    expect(r.description).not.toMatch(/currentversion\\run/i);
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
  });

  it("stays Info for a value write on a key that is not a Run key", () => {
    const key = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";
    const r = graded(security(4657, { ...ACCOUNT, ObjectName: key, ObjectValueName: "Hidden" }));
    expect(r.ruleIds).not.toContain("win_run_key");
    expect(r.severity).toBe("Info");
  });

  it("keeps different keys or value names on one host as separate rows", () => {
    const a = mapped(security(4657, { ...ACCOUNT, ObjectName: RUN, ObjectValueName: "A" }));
    const b = mapped(security(4657, { ...ACCOUNT, ObjectName: RUN, ObjectValueName: "B" }));
    const long = `${RUN}\\${"x".repeat(200)}`;
    const c = mapped(security(4657, { ...ACCOUNT, ObjectName: `${long}1`, ObjectValueName: "A" }));
    const d = mapped(security(4657, { ...ACCOUNT, ObjectName: `${long}2`, ObjectValueName: "A" }));
    expect(a.aggKey).not.toBe(b.aggKey);
    expect(c.aggKey).not.toBe(d.aggKey);
  });

  it("keeps writes apart when a key or value name holds the identity delimiter", () => {
    const base = `${RUN}\\${"y".repeat(200)}`;
    const e = mapped(security(4657, { ...ACCOUNT, ObjectName: `${base}","x`, ObjectValueName: "v" }));
    const f = mapped(security(4657, { ...ACCOUNT, ObjectName: base, ObjectValueName: `x","v` }));
    // Rendered subjects cap each field at 140 chars, so only the identity can tell these apart.
    const x = "z".repeat(150);
    const g = mapped(security(4657, { ...ACCOUNT, ObjectName: `${base}|regvalue=${x}`, ObjectValueName: x }));
    const h = mapped(security(4657, { ...ACCOUNT, ObjectName: base, ObjectValueName: `${x}|regvalue=${x}` }));
    expect(e.aggKey).not.toBe(f.aggKey);
    expect(g.aggKey).not.toBe(h.aggKey);
  });

  it("does not read another provider whose name contains Security as the Security log", () => {
    const r = graded(
      security(
        4657,
        { ObjectName: RUN, ObjectValueName: "Updater" },
        "Microsoft-Windows-SecurityHealthService",
      ),
    );
    expect(r.ruleIds).not.toContain("win_run_key");
    expect(r.path).toBeUndefined();
  });
});

describe("other events that carry ObjectName are unchanged (#1670)", () => {
  it("a 4663 keeps its description and its aggregation key", () => {
    const one = mapped(security(4663, { ...ACCOUNT, ObjectName: `${RUN}`, AccessMask: "0x2" }));
    const two = mapped(security(4663, { ...ACCOUNT, ObjectName: "C:\\secret.txt", AccessMask: "0x2" }));
    expect(one.description).not.toContain("ObjectName");
    expect(one.path).toBeUndefined();
    expect(one.aggKey).toBe(two.aggKey);
    expect(one.aggKey).not.toContain("|reg=");
  });

  it("the helpers are inert off Security 4657", () => {
    const ed = { ObjectName: RUN, ObjectValueName: "Updater" };
    for (const [channel, eid] of [
      ["Security", 4663],
      ["Security", 4656],
      ["Security", 5145],
      ["Microsoft-Windows-Sysmon/Operational", 4657],
      ["Application", 4657],
      ["Microsoft-Windows-SecurityHealthService", 4657],
    ] as const) {
      expect(regWriteKeys(["Image"], channel, eid)).toEqual(["Image"]);
      expect(regWritePath(channel, eid, ed)).toEqual({});
      expect(regWriteIdentity(channel, eid, ed)).toBe("");
    }
    expect(regWriteKeys(["Image"], "Security", 4657)).toEqual(["Image", "ObjectName", "ObjectValueName"]);
    expect(regWritePath("Security", 4657, { objectname: " - " })).toEqual({});
  });
});
