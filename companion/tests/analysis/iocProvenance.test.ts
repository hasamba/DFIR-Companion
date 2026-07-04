import { describe, it, expect } from "vitest";
import { deriveIocProvenance } from "../../src/analysis/iocProvenance.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; severity: ForensicEvent["severity"] }): ForensicEvent {
  return { timestamp: "t", description: "", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}
const ioc = (id: string, type: IOC["type"], value: string): IOC => ({ id, type, value });

describe("deriveIocProvenance", () => {
  it("classes an IOC seen in a High event as detection-linked", () => {
    const events = [ev({ id: "e1", severity: "High", dstIp: "8.8.8.8" })];
    expect(deriveIocProvenance([ioc("i1", "ip", "8.8.8.8")], events)).toEqual({ i1: "detection" });
  });
  it("classes an IOC seen only in Info events as telemetry-only", () => {
    const events = [ev({ id: "e1", severity: "Info", dstIp: "8.8.8.8" })];
    expect(deriveIocProvenance([ioc("i1", "ip", "8.8.8.8")], events)).toEqual({ i1: "telemetry" });
  });
  it("takes the max severity across events (detection wins)", () => {
    const events = [ev({ id: "e1", severity: "Info", dstIp: "8.8.8.8" }), ev({ id: "e2", severity: "Medium", dstIp: "8.8.8.8" })];
    expect(deriveIocProvenance([ioc("i1", "ip", "8.8.8.8")], events)).toEqual({ i1: "detection" });
  });
  it("is boundary-safe (10.0.0.1 does not match 10.0.0.10)", () => {
    const events = [ev({ id: "e1", severity: "High", dstIp: "10.0.0.10" })];
    expect(deriveIocProvenance([ioc("i1", "ip", "10.0.0.1")], events)).toEqual({ i1: "telemetry" });
  });
});
