import { describe, it, expect } from "vitest";
import { slimAttackMatrix, type StixObject } from "../../scripts/attackMatrixSlim.js";

const ref = (id: string) => [{ source_name: "mitre-attack", external_id: id }];
const tactic = (stix: string, id: string, shortname: string, name: string): StixObject => ({
  type: "x-mitre-tactic",
  id: stix,
  name,
  x_mitre_shortname: shortname,
  external_references: ref(id),
});
const technique = (
  stix: string,
  id: string,
  name: string,
  phases: string[],
  extra: Partial<StixObject> = {},
): StixObject => ({
  type: "attack-pattern",
  id: stix,
  name,
  kill_chain_phases: phases.map((p) => ({ kill_chain_name: "mitre-attack", phase_name: p })),
  x_mitre_platforms: ["Windows"],
  external_references: ref(id),
  ...extra,
});
const subOf = (child: string, parent: string): StixObject => ({
  type: "relationship",
  relationship_type: "subtechnique-of",
  source_ref: child,
  target_ref: parent,
});

const BASE: StixObject[] = [
  tactic("x-t-2", "TA0002", "execution", "Execution"),
  tactic("x-t-3", "TA0003", "persistence", "Persistence"),
  { type: "x-mitre-matrix", id: "m", tactic_refs: ["x-t-3", "x-t-2"] },
  technique("ap-1", "T1059", "Command and Scripting Interpreter", ["execution"]),
  technique("ap-2", "T1059.001", "PowerShell", ["execution"], { x_mitre_platforms: ["Windows", "PRE"] }),
  subOf("ap-2", "ap-1"),
  technique("ap-3", "T1078", "Valid Accounts", ["execution", "persistence", "not-a-tactic"]),
];

describe("slimAttackMatrix", () => {
  it("orders tactics by the matrix, and a technique's tactics by that order", () => {
    const m = slimAttackMatrix(BASE);
    expect(m.tactics.map((t) => t.shortname)).toEqual(["persistence", "execution"]);
    expect(m.techniques.find((t) => t.id === "T1078")?.tactics).toEqual(["persistence", "execution"]);
  });

  it("sets a sub-technique's parent and keeps platforms verbatim", () => {
    const m = slimAttackMatrix(BASE);
    expect(m.techniques.find((t) => t.id === "T1059.001")).toEqual({
      id: "T1059.001",
      name: "PowerShell",
      tactics: ["execution"],
      platforms: ["Windows", "PRE"],
      parent: "T1059",
    });
  });

  it("drops revoked and deprecated techniques", () => {
    const m = slimAttackMatrix([
      ...BASE,
      technique("ap-4", "T1000", "Old", ["execution"], { revoked: true }),
      technique("ap-5", "T1001", "Older", ["execution"], { x_mitre_deprecated: true }),
    ]);
    expect(m.techniques.map((t) => t.id)).toEqual(["T1059", "T1059.001", "T1078"]);
  });

  it("throws on a subtechnique-of relationship that contradicts the id prefix", () => {
    expect(() =>
      slimAttackMatrix([
        ...BASE,
        technique("ap-6", "T1566.001", "Spearphishing", ["execution"]),
        subOf("ap-6", "ap-1"),
      ]),
    ).toThrow(/mismatch/);
  });

  it("throws on a sub-technique with no parent relationship", () => {
    expect(() =>
      slimAttackMatrix([...BASE, technique("ap-7", "T1078.002", "Domain Accounts", ["execution"])]),
    ).toThrow(/no live/);
  });

  it("warns when a child's tactics differ from its parent's", () => {
    const m = slimAttackMatrix([
      ...BASE,
      technique("ap-8", "T1059.004", "Unix Shell", ["persistence"]),
      subOf("ap-8", "ap-1"),
    ]);
    expect(m.warnings).toEqual([expect.stringContaining("T1059.004")]);
  });
});
