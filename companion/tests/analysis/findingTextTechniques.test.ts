import { describe, expect, it } from "vitest";
import { capabilityTechniques, withFindingTextTechniques } from "../../src/analysis/findingTextTechniques.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

/**
 * #1873: a finding that SAYS what the attacker's tools do must carry the technique for it.
 *
 * On scenario 023 one synthesis grouped 19 staged batch scripts into one finding whose text named
 * five roles — and tagged only staging and PowerShell. The MITRE panel, reports and exports lost
 * T1490, T1070.001, T1562.001, T1489 and T1531. The ids are derived from the finding's own words at
 * projection, never stored, as event tags are (#893).
 */

// The scenario-023 sentence that motivated the issue, verbatim in shape.
const SCENARIO_023 =
  "The names match the pre-ransomware toolset in CISA AA22-321A (Hive): shadow-copy deletion, log " +
  "clearing, Defender tampering, backup deletion and forced logoff. The shown timeline has no " +
  "process-creation event for any .bat file, so this is staging only (see t4).";

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "f1",
  severity: "High",
  title: "PowerShell staged batch scripts",
  description: SCENARIO_023,
  relatedIocs: [],
  sourceScreenshots: [],
  firstSeen: "2026-09-28T11:39:54Z",
  lastUpdated: "2026-09-28T11:39:58Z",
  mitreTechniques: ["T1074.001", "T1059.001"],
  status: "open",
  ...over,
});

const stateWith = (findings: Finding[], over: Partial<InvestigationState> = {}): InvestigationState => ({
  ...emptyState("c1"),
  findings,
  ...over,
});

describe("capabilityTechniques (#1873)", () => {
  it("reads every role the scenario-023 finding names", () => {
    expect(capabilityTechniques(SCENARIO_023).sort()).toEqual(
      ["T1070.001", "T1490", "T1531", "T1562.001"].sort(),
    );
  });

  it.each([
    ["deleting shadow copies", "T1490"],
    ["inhibit system recovery", "T1490"],
    ["the backup catalog deletion", "T1490"],
    ["clearing the Security log", "T1070.001"],
    ["wevtutil cl System", "T1070.001"],
    ["disable Microsoft Defender", "T1562.001"],
    ["tampering with Defender", "T1562.001"],
    ["stop SQL and Exchange services", "T1489"],
    ["service termination", "T1489"],
    ["log off all sessions", "T1531"],
  ])("maps %j to %s", (text, id) => {
    expect(capabilityTechniques(`The scripts support ${text}.`)).toEqual([id]);
  });

  it("keeps a staged capability whose non-execution is said in a separate clause", () => {
    expect(capabilityTechniques("It staged log-clearing and log clearing scripts, but none ran.")).toEqual([
      "T1070.001",
    ]);
    expect(
      capabilityTechniques(
        "The kit included log clearing and backup deletion; neither capability was executed.",
      ),
    ).toEqual(["T1070.001", "T1490"]);
    expect(
      capabilityTechniques("No execution was observed, although the staged scripts support log clearing."),
    ).toEqual(["T1070.001"]);
  });

  it.each([
    "No shadow-copy deletion, log clearing or impact was seen.",
    "Log clearing was not observed.",
    "There is no evidence of Defender tampering.",
    "Investigate whether backups were deleted or shadow copies removed.",
    "Controls prevent log clearing.",
    "The alert is designed to detect Defender tampering.",
    "The malware failed to disable Defender.",
    "It could stop services if it ran.",
    "Check for service termination after 11:39Z.",
    "Nothing was staged without log clearing.",
  ])("adds nothing for a negated or unasserted mention: %j", (text) => {
    expect(capabilityTechniques(text)).toEqual([]);
  });

  it.each([
    ["No execution of the staged log-clearing scripts was observed.", ["T1070.001"]],
    ["The log-clearing and backup deletion scripts were not executed.", ["T1070.001", "T1490"]],
    ["The kit supports log clearing; none of it has run.", ["T1070.001"]],
    ["No log clearing occurred.", []],
    ["The timeline shows no log clearing after the run.", []],
  ])("keeps a capability when only its execution is denied: %j", (text, expected) => {
    expect(capabilityTechniques(text)).toEqual(expected);
  });

  it("does not read a file name as a role — shadow.bat was a backdoor in scenario 023", () => {
    expect(capabilityTechniques("It wrote shadow.bat, clearlog.bat and LOGOFALL.bat.")).toEqual([]);
  });

  it("does not split a sentence at the dot inside a file name", () => {
    expect(capabilityTechniques("No script ran; shadow.bat is inert. Log clearing is its role.")).toEqual([
      "T1070.001",
    ]);
  });

  it("does not match across the title/description boundary", () => {
    const f = finding({ title: "Staged tooling: shadow copy", description: "Deletion of nothing else." });
    const out = withFindingTextTechniques(stateWith([f]));
    expect(out.findings[0].mitreTechniques).toEqual(f.mitreTechniques);
  });
});

describe("withFindingTextTechniques (#1873)", () => {
  it("adds the missing techniques to the finding and to the table, linked to it", () => {
    const out = withFindingTextTechniques(stateWith([finding()]));

    expect(out.findings[0].mitreTechniques).toEqual([
      "T1074.001",
      "T1059.001",
      "T1490",
      "T1070.001",
      "T1562.001",
      "T1531",
    ]);
    const row = out.mitreTechniques.find((t) => t.id === "T1490");
    expect(row).toEqual({ id: "T1490", name: "Inhibit System Recovery", findingIds: ["f1"] });
    expect(out.mitreTechniques.find((t) => t.id === "T1531")?.name).toBe("Account Access Removal");
  });

  it("appends the finding to an existing row instead of adding a second one", () => {
    const state = stateWith([finding()], {
      mitreTechniques: [{ id: "T1490", name: "Inhibit System Recovery", findingIds: ["f9"] }],
    });

    const rows = withFindingTextTechniques(state).mitreTechniques.filter((t) => t.id === "T1490");

    expect(rows).toEqual([{ id: "T1490", name: "Inhibit System Recovery", findingIds: ["f9", "f1"] }]);
  });

  it("links one technique to every finding that names it", () => {
    const state = stateWith([
      finding({ id: "f1", description: "The kit supports log clearing." }),
      finding({ id: "f2", description: "A second script also does log clearing." }),
    ]);

    const row = withFindingTextTechniques(state).mitreTechniques.find((t) => t.id === "T1070.001");

    expect(row?.findingIds).toEqual(["f1", "f2"]);
  });

  it("leaves a finding that already carries the technique alone", () => {
    const f = finding({ description: "The kit supports log clearing.", mitreTechniques: ["T1070.001"] });
    const state = stateWith([f], {
      mitreTechniques: [{ id: "T1070.001", name: "x", findingIds: ["f1"] }],
    });

    expect(withFindingTextTechniques(state)).toEqual(state);
  });

  it.each([
    ["a dismissed finding", { status: "dismissed" as const }],
    ["an Info finding", { severity: "Info" as const }],
    ["an auto finding", { id: "f-auto-e5" }],
    ["a Defender backfill finding", { id: "f-defender-1" }],
    ["a script-command backfill finding", { id: "f-cmd-1" }],
    ["a gap finding", { id: "f-gap-1" }],
  ])("ignores %s", (_label, over) => {
    const state = stateWith([finding(over)]);

    expect(withFindingTextTechniques(state)).toEqual(state);
  });

  it("skips a malformed finding instead of throwing (the live push may carry a partial state)", () => {
    const state = stateWith([{ secret: "x" } as unknown as Finding]);

    expect(withFindingTextTechniques(state)).toEqual(state);
  });

  it("is idempotent and does not change its input", () => {
    const state = stateWith([finding()]);
    const snapshot = structuredClone(state);

    const once = withFindingTextTechniques(state);

    expect(withFindingTextTechniques(once)).toEqual(once);
    expect(state).toEqual(snapshot);
  });
});
