import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1666: `win_run_key` is for a Run key being WRITTEN. PersistenceSniper ENUMERATES every autostart
// that already exists, so on a clean image the rule graded the stock VMware Tools / OneDrive / Edge
// WebView Run and RunOnce rows Medium, although the mapper graded them Info. These tests run the
// REAL mappers and the SHIPPED ruleset: enumeration rows stay at the mapper's grade, and real
// registry-write telemetry still grades Medium.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

const RUN = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
const HKLM_RUN = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

type Tagged = { severity: string; ruleIds: string[] };

function apply(mapped: Partial<ForensicEvent>): Tagged {
  const event = {
    ...mapped,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { severity: after.severity, ruleIds: proposal?.ruleIds ?? [] };
}

function windows(rec: Record<string, unknown>): Tagged {
  const mapped = parseSiemExport(JSON.stringify([{ "@timestamp": "2026-01-02T03:04:05Z", ...rec }]));
  return apply(mapped.events[0] as Partial<ForensicEvent>);
}

function sysmon(eid: number, data: Record<string, string>, message?: string): Tagged {
  return windows({
    channel: "Microsoft-Windows-Sysmon/Operational",
    computer_name: "H1",
    event_id: eid,
    ...(message ? { message } : {}),
    event_data: data,
  });
}

function sniperRow(path: string, value: string, technique = "Registry Run Key"): Record<string, string> {
  return {
    Hostname: "WIN-EXAMPLE",
    Technique: technique,
    Classification: "MITRE ATT&CK T1547.001",
    Path: path,
    Value: value,
    "Access Gained": "System",
    Note: "Executables in properties of the key are run when the user logs in.",
    Reference: "https://attack.mitre.org/techniques/T1547/001/",
    Signature: "Status = Valid, Subject = CN=Example Vendor",
    IsBuiltinBinary: "False",
    IsLolbin: "False",
    VTEntries: "N/A",
  };
}

// A Velociraptor flow export: the artifact-map shape the lab cases were imported from.
function sniper(row: Record<string, string>): Tagged {
  const parsed = parseVelociraptorJson(JSON.stringify({ "Windows.Forensics.PersistenceSniper": [row] }));
  return apply(parsed.events[0] as Partial<ForensicEvent>);
}

describe("bundled data/tags.yaml — Run keys: enumeration vs write (#1666)", () => {
  it("keeps a PersistenceSniper Run key row at the mapper's Info, still tagged as an autorun", () => {
    const r = sniper(
      sniperRow(`${RUN}\\VMware User Process`, '"C:\\Program Files\\VMware\\vmtoolsd.exe" -n vmusr'),
    );
    expect(r.severity).toBe("Info");
    expect(r.ruleIds).not.toContain("win_run_key");
    expect(r.ruleIds).toContain("win_run_key_enumerated");
  });

  it("keeps a PersistenceSniper RunOnce row at Info", () => {
    const r = sniper(
      sniperRow(
        `${RUN}Once\\WebView2Setup`,
        '"C:\\Program Files (x86)\\Example\\setup.exe" --install',
        "Registry RunOnce Key",
      ),
    );
    expect(r.severity).toBe("Info");
    expect(r.ruleIds).not.toContain("win_run_key");
  });

  it("keeps a PersistenceSniper row at Info when the file name says nothing about the artifact", () => {
    // Dispatched by its column signature, not its name: the mapper's own description prefix is the mark.
    const parsed = parseVelociraptorJson(
      JSON.stringify([sniperRow(`${RUN}\\OneDrive`, '"C:\\Users\\u\\OneDrive.exe" /background')]),
      { artifact: "results" },
    );
    const r = apply(parsed.events[0] as Partial<ForensicEvent>);
    expect(r.severity).toBe("Info");
    expect(r.ruleIds).not.toContain("win_run_key");
  });

  it("does not veto other rules: the mapper's own High on a staged payload stands", () => {
    const row = {
      ...sniperRow(`${RUN}\\Updater`, "C:\\Users\\Public\\u.exe"),
      Signature: "Status = NotSigned",
    };
    expect(sniper(row).severity).toBe("High");
  });

  // ── writes: every one of these must still grade Medium ────────────────────────────────────────
  it("grades a Sysmon 13 Run-key value write Medium", () => {
    const r = sysmon(
      13,
      {
        EventType: "SetValue",
        TargetObject: `${HKLM_RUN}\\Updater`,
        Details: "C:\\Users\\Public\\u.exe",
        Image: "C:\\Windows\\regedit.exe",
      },
      `Registry value set:\nEventType: SetValue\nTargetObject: ${HKLM_RUN}\\Updater\nDetails: C:\\Users\\Public\\u.exe`,
    );
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
  });

  it("grades a Sysmon 13 Run-key write Medium when the record carries no rendered message", () => {
    const r = sysmon(13, {
      EventType: "SetValue",
      TargetObject: `${HKLM_RUN}\\Updater`,
      Details: "C:\\Users\\Public\\u.exe",
      Image: "C:\\Windows\\regedit.exe",
    });
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
  });

  it("grades a Sysmon 12 create of the RunOnce key itself Medium", () => {
    const r = sysmon(
      12,
      { EventType: "CreateKey", TargetObject: `${HKLM_RUN}Once`, Image: "C:\\Users\\Public\\x.exe" },
      `Registry object added or deleted:\nEventType: CreateKey\nTargetObject: ${HKLM_RUN}Once`,
    );
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
  });

  it("grades a Security 4657 Run-key value change Medium (the key name ends the Object Name line)", () => {
    const key = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const r = windows({
      channel: "Security",
      computer_name: "H1",
      event_id: 4657,
      message: `A registry value was modified.\n\nObject:\n\tObject Name:\t${key}\n\tObject Value Name:\tUpdater`,
      event_data: { ObjectName: key, ObjectValueName: "Updater", NewValue: "C:\\Users\\Public\\u.exe" },
    });
    expect(r.ruleIds).toContain("win_run_key");
    expect(r.severity).toBe("Medium");
  });

  it("does not read RunOnceEx or RunServices as a Run key", () => {
    for (const k of ["RunOnceEx", "RunServices"]) {
      const target = `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\${k}`;
      const r = sysmon(
        12,
        { EventType: "CreateKey", TargetObject: target, Image: "C:\\x.exe" },
        `Registry object added or deleted:\nTargetObject: ${target}`,
      );
      expect(r.ruleIds, k).not.toContain("win_run_key");
    }
  });
});
