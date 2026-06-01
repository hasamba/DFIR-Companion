import { describe, it, expect } from "vitest";
import { deltaSchema } from "../../src/analysis/responseSchema.js";

describe("deltaSchema", () => {
  it("parses a valid delta", () => {
    const delta = deltaSchema.parse({
      findings: [{
        id: "f1", severity: "High", title: "Suspicious PowerShell",
        description: "Encoded command observed", relatedIocs: [], mitreTechniques: ["T1059.001"],
        status: "open",
      }],
      iocs: [{ id: "i1", type: "process", value: "powershell.exe" }],
      mitreTechniques: [{ id: "T1059.001", name: "PowerShell" }],
      threadsOpened: [{ id: "t1", description: "trace parent process" }],
      threadsClosed: [],
      timelineNote: "Reviewed process list on WIN-01",
      summary: "Found encoded PowerShell on WIN-01",
    });
    expect(delta.findings[0].id).toBe("f1");
  });

  it("degrades unexpected enum values instead of rejecting the whole response", () => {
    // A model returning a novel severity / IOC type must NOT nuke the entire synthesis.
    const delta = deltaSchema.parse({
      findings: [{ id: "f1", severity: "Catastrophic", title: "x", description: "y",
        relatedIocs: [], mitreTechniques: [], status: "weird" }],
      iocs: [
        { id: "i1", type: "malware", value: "evil.exe" },  // unlisted type
        { id: "i2", type: "tool", value: "nxc" },
      ],
      mitreTechniques: [], threadsOpened: [], threadsClosed: [],
      timelineNote: "n", summary: "s",
    });
    expect(delta.findings[0].severity).toBe("Medium"); // fallback
    expect(delta.findings[0].status).toBe("open");      // fallback
    expect(delta.iocs.map((i) => i.type)).toEqual(["other", "other"]);
    expect(delta.iocs.map((i) => i.value)).toEqual(["evil.exe", "nxc"]); // kept, not dropped
  });
});
