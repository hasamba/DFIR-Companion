import { describe, it, expect } from "vitest";
import { gradeYaraHit, isHeuristicYaraRule } from "../../src/analysis/yaraGrade.js";

describe("gradeYaraHit — contextual YARA severity", () => {
  it("keeps a named-malware rule on a normal dropped path at High", () => {
    const g = gradeYaraHit("DITEKSHEN_MALWARE_Win_Asyncrat", "C:\\ProgramData\\svc\\payload.exe", "");
    expect(g.severity).toBe("High");
    expect(g.reason).toBe("");
    expect(g.volatile).toBe(false);
  });

  it("drops a page-file string to Low and flags it volatile", () => {
    const g = gradeYaraHit("SIGNATURE_BASE_Coinminer_Strings", "C:\\pagefile.sys", "");
    expect(g.severity).toBe("Low");
    expect(g.volatile).toBe(true);
    expect(g.reason).toBe("volatile-container");
  });

  it("drops a memory-dump hit to Low even for a strong rule (a memory string is not execution proof)", () => {
    const g = gradeYaraHit("RANSOM_Akira", "C:\\Windows\\MEMORY.DMP", "");
    expect(g.severity).toBe("Low");
    expect(g.volatile).toBe(true);
  });

  it("drops a self-scan of the collector's own tool tree to Info", () => {
    const g = gradeYaraHit(
      "SIGNATURE_BASE_Sigma_Rule",
      "C:\\Program Files\\Velociraptor\\Tools\\tmp123\\chainsaw\\EVTX-ATTACK-SAMPLES\\x.evtx",
      "",
    );
    expect(g.severity).toBe("Info");
    expect(g.reason).toBe("self-scan");
  });

  it("drops a hit on the Velociraptor collector binary (in its install tree) to Info (THOR PSAttack FP)", () => {
    // The real THOR row carries the full path; a BARE `velociraptor.exe` name is attacker-forgeable
    // and must NOT self-demote — only the collector ROOT context does.
    const g = gradeYaraHit("PSAttack_EXE", "", "C:\\Program Files\\Velociraptor\\Velociraptor.exe");
    expect(g.severity).toBe("Info");
    expect(g.reason).toBe("self-scan");
  });

  it("does NOT demote a payload that merely sits in an attacker-named \\sigma\\ or bare velociraptor.exe", () => {
    expect(gradeYaraHit("DITEKSHEN_MALWARE_Win_Asyncrat", "C:\\Users\\v\\sigma\\evil.dll", "").severity).toBe(
      "High",
    );
    expect(
      gradeYaraHit("DITEKSHEN_MALWARE_Win_Asyncrat", "C:\\Users\\v\\Downloads\\velociraptor.exe", "")
        .severity,
    ).toBe("High");
  });

  it("drops a cached simulation-repo copy to Info", () => {
    const g = gradeYaraHit(
      "GODMODERULES_IDDQD_God_Mode_Rule",
      "C:\\Users\\v\\Downloads\\Digital-Forensic-Artifacts-main\\002-BlackSuit_Simulation.ps1",
      "",
    );
    expect(g.severity).toBe("Info");
    expect(g.reason).toBe("self-scan");
  });

  it("drops a heuristic rule on a signed OS binary to Low (kept for review, out of the Medium+ tier)", () => {
    const g = gradeYaraHit(
      "DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Regkeycomb_Disablewindefender",
      "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
      "",
    );
    expect(g.severity).toBe("Low");
    expect(g.reason).toBe("heuristic-trusted");
  });

  it("demotes the underscore-delimited SUSP_/SUS_ tokens (word-boundary trap)", () => {
    expect(isHeuristicYaraRule("SECUINFRA_SUSP_Powershell_Base64_Decode")).toBe(true);
    expect(isHeuristicYaraRule("SECUINFRA_SUS_Unsigned_APPX_MSIX_Installer_Feb23")).toBe(true);
    // …and these on a trusted OS path leave the High tier.
    expect(
      gradeYaraHit(
        "SECUINFRA_SUS_Unsigned_APPX_MSIX_Installer_Feb23",
        "C:\\Windows\\WinSxS\\amd64_x\\a.exe",
        "",
      ).severity,
    ).toBe("Low");
  });

  it("drops a heuristic rule on a normal path to Medium, not High", () => {
    const g = gradeYaraHit("DELIVRTO_SUSP_ZIP_Smuggling_Jun01", "C:\\Users\\v\\Downloads\\lure.zip", "");
    expect(g.severity).toBe("Medium");
    expect(g.reason).toBe("heuristic");
  });

  it("never raises above High", () => {
    for (const r of ["EVIL", "MALWARE_X", "SUSP_Y"]) {
      const g = gradeYaraHit(r, "C:\\x.exe", "");
      expect(["High", "Medium", "Low", "Info"]).toContain(g.severity);
    }
  });

  it("classifies heuristic rule names", () => {
    expect(isHeuristicYaraRule("GODMODERULES_IDDQD_God_Mode_Rule")).toBe(true);
    expect(isHeuristicYaraRule("SIGNATURE_BASE_SUSP_Powershell_Caret_Obfuscation_2")).toBe(true);
    expect(isHeuristicYaraRule("DITEKSHEN_MALWARE_Win_Asyncrat")).toBe(false);
  });
});
