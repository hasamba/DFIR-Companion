import { describe, it, expect } from "vitest";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  memoryNextStepResponseSchema,
  sanitizeMemoryNextSteps,
  isMemoryEvent,
  hasMemoryMaterial,
  memoryPluginsPresent,
  renderMemoryEvidence,
  MEMORY_NEXTSTEP_MAX_DEFAULT,
  type MemoryNextStep,
} from "../../src/analysis/memoryNextStep.js";

const NOW = "2026-06-10T00:00:00.000Z";

function event(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: NOW,
    description: "Volatility pslist: svchost.exe (PID 1234, PPID 4500) started 2026-06-10",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Volatility"],
    ...over,
  };
}

function suggestion(over: Partial<MemoryNextStep> = {}): MemoryNextStep {
  return {
    anomaly: "svchost.exe (PID 1234) is parented by explorer.exe, not services.exe",
    command: "vol -f <image> windows.malfind --pid 1234",
    plugin: "windows.malfind",
    rationale: "A mis-parented svchost is a strong injection signal; dump executable private memory and yara-scan it.",
    severity: "High",
    pid: "1234",
    mitreTechniques: ["T1055"],
    ...over,
  };
}

describe("memoryNextStepResponseSchema", () => {
  it("parses a well-formed response", () => {
    const parsed = memoryNextStepResponseSchema.parse({ suggestions: [suggestion()] });
    expect(parsed.suggestions).toHaveLength(1);
    expect(parsed.suggestions[0].command).toContain("windows.malfind");
  });

  it("is lenient: a bad severity maps to the fallback, missing fields default", () => {
    const parsed = memoryNextStepResponseSchema.parse({
      suggestions: [{ anomaly: "x", command: "vol -f <image> windows.netscan", severity: "Catastrophic" }],
    });
    expect(parsed.suggestions[0].severity).toBe("Medium"); // unknown enum → fallback
    expect(parsed.suggestions[0].rationale).toBe("");        // missing → ""
    expect(parsed.suggestions[0].pid).toBe("");
    expect(parsed.suggestions[0].mitreTechniques).toEqual([]);
  });

  it("defaults suggestions to [] when the field is absent or wrong-typed", () => {
    expect(memoryNextStepResponseSchema.parse({}).suggestions).toEqual([]);
    expect(memoryNextStepResponseSchema.parse({ suggestions: "nope" }).suggestions).toEqual([]);
  });
});

describe("sanitizeMemoryNextSteps", () => {
  it("drops suggestions with no command or no anomaly", () => {
    const out = sanitizeMemoryNextSteps([
      suggestion(),
      suggestion({ command: "   " }),   // empty command → dropped
      suggestion({ anomaly: "" }),       // empty anomaly → dropped
    ]);
    expect(out).toHaveLength(1);
  });

  it("trims/collapses fields and dedupes technique ids", () => {
    const out = sanitizeMemoryNextSteps([
      suggestion({
        command: "  vol  -f   <image>   windows.malfind  --pid 1234 ",
        mitreTechniques: ["T1055", "T1055", " T1036.005 "],
      }),
    ]);
    expect(out[0].command).toBe("vol -f <image> windows.malfind --pid 1234");
    expect(out[0].mitreTechniques).toEqual(["T1055", "T1036.005"]);
  });

  it("caps the number of suggestions", () => {
    const many = Array.from({ length: 20 }, (_, i) => suggestion({ anomaly: `a${i}` }));
    expect(sanitizeMemoryNextSteps(many, 3)).toHaveLength(3);
    expect(sanitizeMemoryNextSteps(many)).toHaveLength(MEMORY_NEXTSTEP_MAX_DEFAULT);
  });

  it("handles undefined input", () => {
    expect(sanitizeMemoryNextSteps(undefined)).toEqual([]);
  });

  it("truncates a runaway command blob", () => {
    const out = sanitizeMemoryNextSteps([suggestion({ command: "vol -f <image> " + "x".repeat(2000) })]);
    expect(out[0].command.length).toBeLessThanOrEqual(600);
  });
});

describe("isMemoryEvent / hasMemoryMaterial", () => {
  it("recognises Volatility and Rekall sources only", () => {
    expect(isMemoryEvent(event())).toBe(true);
    expect(isMemoryEvent(event({ sources: ["Rekall"] }))).toBe(true);
    expect(isMemoryEvent(event({ sources: ["THOR"] }))).toBe(false);
    expect(isMemoryEvent(event({ sources: undefined }))).toBe(false);
  });

  it("hasMemoryMaterial is false on an empty case, true once a memory event exists", () => {
    const empty = emptyState("c1");
    expect(hasMemoryMaterial(empty)).toBe(false);
    expect(hasMemoryMaterial({ ...empty, forensicTimeline: [event({ sources: ["Sysmon"] })] })).toBe(false);
    expect(hasMemoryMaterial({ ...empty, forensicTimeline: [event()] })).toBe(true);
  });
});

describe("memoryPluginsPresent", () => {
  it("recovers the plugin label from memory event descriptions, deduped + sorted", () => {
    const plugins = memoryPluginsPresent([
      event({ description: "Volatility pslist: explorer.exe (PID 4500)" }),
      event({ description: "Volatility netscan: TCP 10.0.0.5:443 → 1.2.3.4:8080", sources: ["Volatility"] }),
      event({ description: "Rekall netscan: another", sources: ["Rekall"] }),
      event({ description: "THOR alert: not a memory event", sources: ["THOR"] }), // not memory → ignored
    ]);
    expect(plugins).toEqual(["netscan", "pslist"]);
  });

  it("returns [] when no memory events have a parseable label", () => {
    expect(memoryPluginsPresent([event({ sources: ["Sysmon"] })])).toEqual([]);
  });
});

describe("renderMemoryEvidence", () => {
  it("renders only memory events, worst severity first", () => {
    const text = renderMemoryEvidence([
      event({ description: "Volatility pslist: benign", severity: "Info" }),
      event({ description: "Volatility malfind: injected code in evil.exe", severity: "High" }),
      event({ description: "Sysmon: ignored", severity: "Critical", sources: ["Sysmon"] }),
    ]);
    const lines = text.split("\n");
    expect(lines[0]).toContain("malfind");        // High sorts before Info
    expect(lines[0].startsWith("[High]")).toBe(true);
    expect(text).not.toContain("Sysmon");          // non-memory excluded
  });

  it("returns a placeholder when there is no memory evidence", () => {
    expect(renderMemoryEvidence([event({ sources: ["THOR"] })])).toBe("(no memory evidence)");
  });
});
