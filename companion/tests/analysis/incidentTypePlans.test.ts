import { describe, it, expect } from "vitest";
import { loadBuiltInIncidentTypes } from "../../src/analysis/incidentTypesData.js";
import { getCollectionStep } from "../../src/analysis/collectionPlan.js";

describe("incident-type collection plans", () => {
  const types = loadBuiltInIncidentTypes();

  it("every type declares a non-empty plan of DEFINED step ids", () => {
    for (const t of types) {
      expect(t.recommendedImportOrder.length, `${t.id} has no collection plan`).toBeGreaterThan(0);
      for (const id of t.recommendedImportOrder) {
        expect(getCollectionStep(id), `${t.id} references unknown step "${id}"`).toBeDefined();
      }
    }
  });

  it("no type repeats a step", () => {
    for (const t of types) {
      expect(new Set(t.recommendedImportOrder).size, `${t.id} repeats a step`).toBe(
        t.recommendedImportOrder.length,
      );
    }
  });

  it("matches the orders agreed in the design", () => {
    const byId = new Map(types.map((t) => [t.id, t.recommendedImportOrder]));
    expect(byId.get("ransomware")).toEqual([
      "edr",
      "memory",
      "windows-event-logs",
      "endpoint-triage",
      "network",
      "siem",
    ]);
    expect(byId.get("bec")).toEqual(["m365", "identity", "siem", "network"]);
    expect(byId.get("data-exfiltration")).toEqual([
      "network",
      "siem",
      "edr",
      "cloud-audit",
      "m365",
      "endpoint-triage",
    ]);
    expect(byId.get("intrusion")).toEqual([
      "network",
      "edr",
      "windows-event-logs",
      "endpoint-triage",
      "siem",
    ]);
    expect(byId.get("insider-threat")).toEqual([
      "siem",
      "endpoint-triage",
      "super-timeline",
      "m365",
      "cloud-audit",
      "physical-access",
    ]);
    expect(byId.get("cloud-compromise")).toEqual(["cloud-audit", "identity", "m365", "siem", "edr"]);
    expect(byId.get("web-app-intrusion")).toEqual([
      "web-logs",
      "network",
      "edr",
      "windows-event-logs",
      "siem",
    ]);
    expect(byId.get("malware-outbreak")).toEqual([
      "edr",
      "memory",
      "sandbox",
      "windows-event-logs",
      "network",
      "threat-scan",
    ]);
  });

  it("no longer carries the fictional hunt-bundle and report-framing fields", () => {
    for (const t of types) {
      expect(t).not.toHaveProperty("huntBundles");
      expect(t).not.toHaveProperty("reportFraming");
    }
  });

  // An analyst's custom type written against the old shape must keep working.
  it("ignores the removed fields rather than rejecting an older custom definition", async () => {
    const { parseIncidentType } = await import("../../src/analysis/incidentTypes.js");
    const parsed = parseIncidentType({
      id: "legacy",
      name: "Legacy",
      recommendedImportOrder: ["edr"],
      huntBundles: ["vss-delete"],
      reportFraming: { template: "ransomware-executive", audience: "board", summaryPrompt: "x" },
    });
    expect(parsed).not.toBeNull();
    expect(parsed).not.toHaveProperty("huntBundles");
    expect(parsed).not.toHaveProperty("reportFraming");
  });
});
