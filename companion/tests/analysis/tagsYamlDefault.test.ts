import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Guards the shipped default ruleset: a YAML typo, an unknown field, or a bad regex here would ship
// a broken default. This compiles data/tags.yaml exactly as the app does.
describe("bundled data/tags.yaml", () => {
  it("compiles cleanly and defines multiple rules", () => {
    const path = fileURLToPath(new URL("../../data/tags.yaml", import.meta.url));
    const text = readFileSync(path, "utf8");
    const rs = compileText(text);
    expect(rs.rules.length).toBeGreaterThan(5);
    // every rule carries at least one action
    for (const r of rs.rules) {
      const hasAction =
        r.tags.length > 0 || r.mitre.length > 0 || r.severity !== undefined || r.view !== undefined;
      expect(hasAction, `rule ${r.id} has no action`).toBe(true);
    }
  });
});

// Removable media is why this rule exists: a mass-storage mount arrives from Velociraptor ungraded,
// and anything left at Info never reaches the forensic timeline, so the AI cannot reason about it.
// The rule lifts it to Low — present in the record, without shouting.
describe("bundled data/tags.yaml — removable media", () => {
  const RULESET = compileText(
    readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
  );

  function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
    return {
      timestamp: "2026-06-01T00:00:00Z",
      description: "d",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      ...p,
    };
  }

  it("raises a mass-storage mount above Info and tags it", () => {
    const res = runTagger([ev({ id: "e1", artifactName: "Windows.Mounted.Mass.Storage" })], RULESET);
    const hit = res.perEvent.find((e) => e.eventId === "e1");
    expect(hit?.severity).toBe("Low");
    expect(hit?.tags).toContain("removable-media");
    expect(hit?.mitre).toContain("T1091");
  });

  it("matches USB registry evidence in a message, whatever the artifact is called", () => {
    const res = runTagger(
      [ev({ id: "e2", message: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk" })],
      RULESET,
    );
    expect(res.perEvent.find((e) => e.eventId === "e2")?.severity).toBe("Low");
  });

  it("leaves an unrelated event alone", () => {
    const res = runTagger([ev({ id: "e3", description: "user opened a document" })], RULESET);
    expect(res.perEvent.find((e) => e.eventId === "e3")).toBeUndefined();
  });
});

// PersistenceSniper's grading (LOLBin -> High, non-valid signature -> Medium) is done directly in
// analysis/persistenceSniperImport.ts, from the module's own structured columns — see that file's
// tests. A tagger rule re-deriving the same verdict from the rendered description was tried first
// and reverted: it was spoofable via a crafted Value/Path (a file literally named "evil.exe
// [lolbin]" faked a High grade the module never gave) and lossy (the description's 600-char cap
// could truncate a genuine marker, leaving a real LOLBin at Info). There is deliberately no
// PersistenceSniper-specific rule in tags.yaml.

// End to end over the REAL importer: map a Windows record, then run the shipped ruleset over the
// event it produced. These rules key on `message`, which mapWindows did not populate — so twelve of
// them matched nothing on the very events they name, and the ruleset read as live while being dead.
// Populating it wakes them all at once, which is why the benign half of this table matters as much
// as the malicious half: three rules were broad enough to grade routine activity High the moment
// they could see anything.
describe("bundled data/tags.yaml — over real mapped Windows events", () => {
  const RULES = compileText(
    readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
  );

  // Map one Windows record the way an import does, then apply the ruleset to the result.
  function tagged(rec: Record<string, unknown>): { severity: string; ruleIds: string[] } {
    const mapped = parseSiemExport(JSON.stringify([{ "@timestamp": "2026-01-02T03:04:05Z", ...rec }]));
    const event = {
      ...mapped.events[0],
      id: "e1",
      relatedFindingIds: [],
      sourceScreenshots: [],
      mitreTechniques: mapped.events[0].mitreTechniques ?? [],
    } as unknown as ForensicEvent;
    const res = runTagger([event], RULES);
    const proposal = res.perEvent[0];
    const after = proposal ? applyToForensicEvent(event, proposal) : event;
    return { severity: after.severity, ruleIds: proposal?.ruleIds ?? [] };
  }

  const sysmon = (eid: number, data: Record<string, string>, message: string) => ({
    channel: "Microsoft-Windows-Sysmon/Operational",
    computer_name: "H1",
    event_id: eid,
    message,
    event_data: data,
  });

  it("fires the service-install rule on a real 7045 (it never could before)", () => {
    const r = tagged({
      channel: "System",
      computer_name: "H1",
      event_id: 7045,
      message: "A new service was installed in the system.\n\nService Name: PSEXESVC",
      event_data: { ServiceName: "PSEXESVC", ImagePath: "%SystemRoot%\\PSEXESVC.exe" },
    });
    expect(r.ruleIds).toContain("win_service_install");
  });

  it("fires the remote-logon rule on a 4624 type 10", () => {
    const r = tagged({
      channel: "Security",
      computer_name: "H1",
      event_id: 4624,
      message: "An account was successfully logged on.",
      event_data: {
        TargetUserName: "admin",
        TargetDomainName: "CORP",
        LogonType: "10",
        IpAddress: "10.0.0.9",
      },
    });
    expect(r.ruleIds).toContain("win_remote_logon");
  });

  it("grades a written lsass dump file High", () => {
    const r = tagged(
      sysmon(
        11,
        { TargetFilename: "C:\\Windows\\Temp\\lsass.dmp" },
        "File created: C:\\Windows\\Temp\\lsass.dmp",
      ),
    );
    expect(r.ruleIds).toContain("win_lsass_access");
    expect(r.severity).toBe("High");
  });

  // ── the benign half: each of these was graded High the moment `message` arrived ──────────────
  it("leaves Defender's own LSASS access at Low — the tagger must not overrule the source check", () => {
    const r = tagged(
      sysmon(
        10,
        {
          SourceImage: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
          TargetImage: "C:\\Windows\\System32\\lsass.exe",
          GrantedAccess: "0x1410",
        },
        "Process accessed:\nTargetImage: C:\\Windows\\System32\\lsass.exe\nGrantedAccess: 0x1410",
      ),
    );
    expect(r.ruleIds).not.toContain("win_lsass_access");
    expect(r.severity).toBe("Low");
  });

  it("leaves an ordinary `bcdedit /enum` alone — recovery inhibition names the actual flags", () => {
    const r = tagged(
      sysmon(
        1,
        { Image: "C:\\Windows\\System32\\bcdedit.exe", CommandLine: "bcdedit /enum" },
        "Process Create:\nCommandLine: bcdedit /enum",
      ),
    );
    expect(r.ruleIds).not.toContain("win_shadow_copy_delete");
  });

  it("leaves a routine VSS snapshot alone — a shadow copy is not credential-store theft", () => {
    const r = tagged({
      channel: "Application",
      computer_name: "H1",
      event_id: 12289,
      message:
        "Volume Shadow Copy Service: snapshot \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy12 created for volume C:.",
      event_data: {},
    });
    expect(r.ruleIds).not.toContain("win_ntds_shadow");
    expect(r.severity).toBe("Info");
  });

  it("still catches a shadow copy used to STEAL the hive", () => {
    const r = tagged(
      sysmon(
        1,
        {
          Image: "C:\\Windows\\System32\\cmd.exe",
          CommandLine:
            "cmd /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\",
        },
        "Process Create: copy ...\\NTDS\\ntds.dit",
      ),
    );
    expect(r.ruleIds).toContain("win_ntds_shadow");
    expect(r.severity).toBe("High");
  });
});
