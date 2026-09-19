import { describe, it, expect } from "vitest";
import { attributionGapLeads, GAP_LEADS_MAX } from "../../src/analysis/attributionGapLeads.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { AttributionAssertion } from "../../src/analysis/attributionAssertionStore.js";
import type { AdversaryGroup } from "../../src/analysis/adversaryTechniques.js";

// #1405: beside an analyst's own attribution assertion whose label matches a known ATT&CK group,
// the techniques that group is documented to use that this case's graded evidence has not shown —
// hunt leads, never evidence of absence, never attribution. Read-time only.

const groups: AdversaryGroup[] = [
  {
    id: "G0016",
    name: "APT29",
    aliases: ["Cozy Bear"],
    description: "d",
    techniques: [
      "T1566.001",
      "T1059.001",
      "T1059",
      "T1059.003",
      "T1003.001",
      "T1486",
      "T1021.001",
      "T1070.004",
    ],
  },
  { id: "G0001", name: "Other", aliases: [], description: "d", techniques: ["T1204"] },
];
const dataset = {
  groups,
  techniqueInfo: {
    T1486: { name: "Data Encrypted for Impact" },
    "T1003.001": { name: "LSASS Memory", dataSources: ["Process: OS API Execution"] },
  },
};

const assertion = (over: Partial<AttributionAssertion> = {}): AttributionAssertion =>
  ({
    id: "a1",
    tier: "operator",
    label: "APT29",
    status: "open",
    sources: "s",
    alternatives: "a",
    analystAssessment: "x",
    createdBy: "local",
    createdAt: "2026-09-19T10:00:00Z",
    buildsOn: [],
    ...over,
  }) as unknown as AttributionAssertion;

const finding = (techniques: string[]): Finding =>
  ({
    id: "f1",
    title: "t",
    description: "d",
    severity: "High",
    status: "open",
    mitreTechniques: techniques,
    relatedIocs: [],
    relatedEventIds: [],
    sourceScreenshots: [],
  }) as unknown as Finding;

const state = (techniques: string[] = []): InvestigationState => ({
  ...emptyState("c1"),
  findings: techniques.length ? [finding(techniques)] : [],
});

describe("attributionGapLeads", () => {
  it("lists the matched group's techniques the case has not shown, at base-or-better in both directions", () => {
    // Case shows T1059.001 (covers the group's T1059 AND T1059.001 — but NOT the sibling T1059.003),
    // T1021 (covers T1021.001), T1486.
    const { leads } = attributionGapLeads(state(["T1059.001", "T1021", "T1486"]), [assertion()], dataset);
    expect(leads).toHaveLength(1);
    const l = leads[0];
    expect(l.group).toMatchObject({ id: "G0016", name: "APT29" });
    expect(l.assertionId).toBe("a1");
    expect(l.techniques.map((t) => t.id)).toEqual(["T1003.001", "T1566.001", "T1070.004", "T1059.003"]); // Credential Access, Initial Access, Defense Evasion, Execution
    expect(l.observedCount).toBe(4);
    expect(l.total).toBe(4);
    expect(l.techniques[0]).toMatchObject({
      id: "T1003.001",
      name: "LSASS Memory",
      tactic: "Credential Access",
      dataSources: ["Process: OS API Execution"],
    });
    expect(l.techniques[0].url).toBe("https://attack.mitre.org/techniques/T1003/001/");
    expect(l.caveat).toMatch(/never evidence of absence/);
    expect(l.basis).toMatch(/not observed ≠ did not happen/);
  });

  it("orders by kill-chain stage, then id; an empty case makes every group technique a lead", () => {
    const { leads } = attributionGapLeads(state(), [assertion()], dataset);
    const ids = leads[0].techniques.map((t) => `${t.tactic}:${t.id}`);
    // Impact first, Credential Access, Lateral Movement, Persistence…, then Initial Access, Defense Evasion, Execution.
    expect(ids[0]).toBe("Impact:T1486");
    expect(ids[1]).toBe("Credential Access:T1003.001");
    expect(ids.at(-1)).toMatch(/^Execution:T1059/);
    expect(leads[0].observedCount).toBe(0);
    expect(leads[0].total).toBe(8);
  });

  it("skips retracted assertions and labels that match no group; an alias matches", () => {
    const { leads } = attributionGapLeads(
      state(),
      [
        assertion({ id: "a1", status: "retracted" as never }),
        assertion({ id: "a2", label: "UNC-nothing" }),
        assertion({ id: "a3", label: "cozy bear" }),
      ],
      dataset,
    );
    expect(leads.map((l) => l.assertionId)).toEqual(["a3"]);
    expect(leads[0].group.id).toBe("G0016");
  });

  it("is bounded per assertion and says the total", () => {
    const big: AdversaryGroup = {
      id: "G9999",
      name: "Wide",
      aliases: [],
      description: "",
      techniques: Array.from({ length: GAP_LEADS_MAX + 5 }, (_, i) => `T${1000 + i}`),
    };
    const { leads } = attributionGapLeads(state(), [assertion({ label: "Wide" })], {
      groups: [big],
      techniqueInfo: {},
    });
    expect(leads[0].techniques).toHaveLength(GAP_LEADS_MAX);
    expect(leads[0].total).toBe(GAP_LEADS_MAX + 5);
  });
});
