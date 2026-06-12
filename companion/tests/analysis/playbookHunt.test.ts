import { describe, it, expect } from "vitest";
import { emptyState, type ForensicEvent, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";
import {
  playbookHuntResponseSchema,
  knownEndpoints,
  deriveTaskEndpoints,
  buildTaskEndpointsMap,
  resolveHuntMode,
  sanitizePlaybookHuntSuggestions,
  renderPlaybookHuntTasks,
  renderKnownEndpoints,
  renderAvailableArtifacts,
  hasPlaybookHuntMaterial,
  PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT,
  type RawPlaybookHuntSuggestion,
} from "../../src/analysis/playbookHunt.js";

const NOW = "2026-06-10T00:00:00.000Z";

function event(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: NOW,
    description: "suspicious process",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "Critical",
    title: "Malicious service installed",
    description: "evil.exe registered as a service",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1543.003"],
    firstSeen: NOW,
    lastUpdated: NOW,
    status: "open",
    ...over,
  };
}

function task(over: Partial<PlaybookTask> = {}): PlaybookTask {
  return {
    id: "finding:f1",
    title: "Investigate & remediate: Malicious service installed",
    description: "evil.exe registered as a service",
    status: "todo",
    priority: "critical",
    source: "finding",
    sourceKey: "finding:f1",
    relatedFindingId: "f1",
    order: 0,
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

function state(over: Partial<InvestigationState> = {}): InvestigationState {
  return { ...emptyState("c1"), ...over };
}

function rawSuggestion(over: Partial<RawPlaybookHuntSuggestion> = {}): RawPlaybookHuntSuggestion {
  return {
    taskId: "finding:f1",
    endpointRelated: true,
    title: "Hunt the malicious service across the fleet",
    rationale: "A malicious service was installed; enumerate it everywhere.",
    vql: "SELECT Name, PathName FROM Artifact.Windows.System.Services() WHERE PathName =~ 'evil'",
    targetHost: "",
    severity: "High",
    mitreTechniques: ["T1543.003"],
    ...over,
  };
}

describe("playbookHuntResponseSchema", () => {
  it("parses a well-formed response", () => {
    const parsed = playbookHuntResponseSchema.parse({ suggestions: [rawSuggestion()] });
    expect(parsed.suggestions).toHaveLength(1);
    expect(parsed.suggestions[0].endpointRelated).toBe(true);
  });

  it("is lenient: bad/missing fields fall back", () => {
    const parsed = playbookHuntResponseSchema.parse({
      suggestions: [{ taskId: "t1", vql: "SELECT * FROM pslist()", severity: "Catastrophic" }],
    });
    expect(parsed.suggestions[0].severity).toBe("Medium");      // unknown enum → fallback
    expect(parsed.suggestions[0].endpointRelated).toBe(false);  // missing → false
    expect(parsed.suggestions[0].targetHost).toBe("");          // missing → ""
    expect(parsed.suggestions[0].mitreTechniques).toEqual([]);
  });

  it("defaults suggestions to [] when absent or wrong-typed", () => {
    expect(playbookHuntResponseSchema.parse({}).suggestions).toEqual([]);
    expect(playbookHuntResponseSchema.parse({ suggestions: "nope" }).suggestions).toEqual([]);
  });
});

describe("knownEndpoints", () => {
  it("collects distinct event hosts, case-folded", () => {
    const s = state({
      forensicTimeline: [
        event({ id: "e1", asset: "ALClient07" }),
        event({ id: "e2", asset: "alclient07" }),   // same host, different case → collapsed
        event({ id: "e3", asset: "WEB01" }),
        event({ id: "e4", asset: "  " }),            // blank → ignored
      ],
    });
    expect(knownEndpoints(s)).toEqual(["ALClient07", "WEB01"]);
  });

  it("is empty when no event carries an asset", () => {
    expect(knownEndpoints(state())).toEqual([]);
  });
});

describe("deriveTaskEndpoints", () => {
  it("derives the host from events linked to the task's finding", () => {
    const s = state({
      forensicTimeline: [
        event({ id: "e1", asset: "WEB01", relatedFindingIds: ["f1"] }),
        event({ id: "e2", asset: "DC02", relatedFindingIds: ["f9"] }),   // other finding → ignored
      ],
    });
    expect(deriveTaskEndpoints(s, task())).toEqual(["WEB01"]);
  });

  it("falls back to host names mentioned in the task text (next_step / custom tasks)", () => {
    const s = state({ forensicTimeline: [event({ asset: "ALCLIENT07", relatedFindingIds: [] })] });
    const t = task({ id: "next_step:n1", source: "next_step", sourceKey: "next_step:n1", relatedFindingId: undefined, title: "Pull Security.evtx on ALCLIENT07", description: "" });
    expect(deriveTaskEndpoints(s, t)).toEqual(["ALCLIENT07"]);
  });

  it("does not false-match a host name inside a larger token", () => {
    const s = state({ forensicTimeline: [event({ asset: "PC1" })] });
    const t = task({ relatedFindingId: undefined, title: "Investigate PC10 anomalies", description: "" });
    expect(deriveTaskEndpoints(s, t)).toEqual([]);
  });

  it("matches a short host name against an FQDN mention and vice-versa", () => {
    const s = state({ forensicTimeline: [event({ asset: "web01" })] });
    const t = task({ relatedFindingId: undefined, title: "Triage web01.corp.local", description: "" });
    expect(deriveTaskEndpoints(s, t)).toEqual(["web01"]);
  });

  it("returns multiple endpoints when the finding spans hosts", () => {
    const s = state({
      forensicTimeline: [
        event({ id: "e1", asset: "WEB01", relatedFindingIds: ["f1"] }),
        event({ id: "e2", asset: "WEB02", relatedFindingIds: ["f1"] }),
      ],
    });
    expect(deriveTaskEndpoints(s, task()).sort()).toEqual(["WEB01", "WEB02"]);
  });
});

describe("resolveHuntMode", () => {
  const known = ["WEB01", "DC02"];

  it("uses the model's targetHost when it matches a known endpoint (canonical casing)", () => {
    expect(resolveHuntMode("web01", [], known)).toEqual({ mode: "collection", targetHost: "WEB01" });
  });

  it("clamps a hallucinated targetHost to a fleet hunt", () => {
    expect(resolveHuntMode("GHOST99", [], known)).toEqual({ mode: "hunt" });
  });

  it("collects on the single derived endpoint when the model gave none", () => {
    expect(resolveHuntMode("", ["DC02"], known)).toEqual({ mode: "collection", targetHost: "DC02" });
  });

  it("falls back to a fleet hunt when several endpoints are derived", () => {
    expect(resolveHuntMode("", ["WEB01", "WEB02"], known)).toEqual({ mode: "hunt" });
  });

  it("falls back to a fleet hunt when nothing is known", () => {
    expect(resolveHuntMode("", [], known)).toEqual({ mode: "hunt" });
  });
});

describe("sanitizePlaybookHuntSuggestions", () => {
  const known = ["WEB01"];
  const epMap = new Map<string, string[]>([["finding:f1", ["WEB01"]]]);

  it("drops non-endpoint suggestions and empty vql/title", () => {
    const out = sanitizePlaybookHuntSuggestions([
      rawSuggestion(),
      rawSuggestion({ endpointRelated: false }),   // not endpoint-related → dropped
      rawSuggestion({ vql: "  " }),                 // empty query → dropped
      rawSuggestion({ title: "" }),                 // empty title → dropped
    ], epMap, known);
    expect(out).toHaveLength(1);
  });

  it("attaches a collection mode + canonical host for a single-endpoint task", () => {
    const out = sanitizePlaybookHuntSuggestions([rawSuggestion({ targetHost: "web01" })], epMap, known);
    expect(out[0].mode).toBe("collection");
    expect(out[0].targetHost).toBe("WEB01");
  });

  it("falls back to a fleet hunt (no targetHost) for a multi-endpoint task", () => {
    const epMulti = new Map<string, string[]>([["finding:f1", ["WEB01", "WEB02"]]]);
    const out = sanitizePlaybookHuntSuggestions([rawSuggestion({ targetHost: "" })], epMulti, ["WEB01", "WEB02"]);
    expect(out[0].mode).toBe("hunt");
    expect(out[0].targetHost).toBeUndefined();
  });

  it("trims, dedupes techniques, and caps lengths + count", () => {
    const out = sanitizePlaybookHuntSuggestions([
      rawSuggestion({ title: "  Spaced  ", mitreTechniques: ["T1059", "T1059", " T1003 "] }),
    ], epMap, known);
    expect(out[0].title).toBe("Spaced");
    expect(out[0].mitreTechniques).toEqual(["T1059", "T1003"]);

    const many = Array.from({ length: 20 }, (_, i) => rawSuggestion({ title: `h${i}` }));
    expect(sanitizePlaybookHuntSuggestions(many, epMap, known, 3)).toHaveLength(3);
    expect(sanitizePlaybookHuntSuggestions(many, epMap, known)).toHaveLength(PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT);
  });

  it("truncates a runaway VQL blob", () => {
    const out = sanitizePlaybookHuntSuggestions([rawSuggestion({ vql: "SELECT * FROM scope() -- " + "x".repeat(8000) })], epMap, known);
    expect(out[0].vql.length).toBeLessThanOrEqual(4000);
  });

  it("handles undefined input", () => {
    expect(sanitizePlaybookHuntSuggestions(undefined, epMap, known)).toEqual([]);
  });
});

describe("renderPlaybookHuntTasks", () => {
  it("renders open tasks with their derived endpoints and skips done/skipped", () => {
    const tasks = [
      task({ id: "finding:f1" }),
      task({ id: "finding:f2", status: "done", title: "Already handled" }),
    ];
    const epMap = new Map<string, string[]>([["finding:f1", ["WEB01"]], ["finding:f2", []]]);
    const text = renderPlaybookHuntTasks(tasks, epMap);
    expect(text).toContain("[finding:f1]");
    expect(text).toContain("[endpoints: WEB01]");
    expect(text).not.toContain("Already handled");
  });

  it("notes when no endpoints were derived", () => {
    const epMap = new Map<string, string[]>([["finding:f1", []]]);
    expect(renderPlaybookHuntTasks([task()], epMap)).toContain("[endpoints: none derived]");
  });

  it("returns a placeholder when there are no open tasks", () => {
    expect(renderPlaybookHuntTasks([task({ status: "skipped" })], new Map())).toBe("(no open playbook tasks)");
  });
});

describe("renderKnownEndpoints", () => {
  it("joins the hosts, or notes none", () => {
    expect(renderKnownEndpoints(["WEB01", "DC02"])).toBe("WEB01, DC02");
    expect(renderKnownEndpoints([])).toContain("no endpoints observed");
  });
});

describe("renderAvailableArtifacts", () => {
  it("dedupes and notes when empty", () => {
    expect(renderAvailableArtifacts(["Windows.EventLogs.Evtx", "Windows.EventLogs.Evtx", "Generic.System.Pstree"]))
      .toBe("Windows.EventLogs.Evtx, Generic.System.Pstree");
    expect(renderAvailableArtifacts([])).toContain("use raw VQL plugins only");
  });

  it("ranks Windows/DetectRaptor/Custom first and drops Admin/Server/Demo", () => {
    const out = renderAvailableArtifacts(["Linux.Sys.X", "Admin.Client.Uninstall", "Windows.System.Pslist", "DetectRaptor.Windows.Detection.MFT", "Custom.DFIR.Y", "Generic.System.Pstree"]);
    expect(out).not.toContain("Admin.Client.Uninstall");                 // dropped (never an endpoint hunt)
    expect(out.indexOf("Windows.System.Pslist")).toBeLessThan(out.indexOf("Linux.Sys.X"));        // Windows before Linux
    expect(out.indexOf("DetectRaptor.Windows.Detection.MFT")).toBeLessThan(out.indexOf("Custom.DFIR.Y")); // detect before custom
  });

  it("caps after ranking so the high-value artifacts survive", () => {
    const out = renderAvailableArtifacts(["Linux.A", "Linux.B", "Windows.X"], 1);
    expect(out).toBe("Windows.X");   // Windows wins the single slot despite coming last in the input
  });
});

describe("buildTaskEndpointsMap", () => {
  it("keys derived endpoints by task id", () => {
    const s = state({ forensicTimeline: [event({ asset: "WEB01", relatedFindingIds: ["f1"] })] });
    const map = buildTaskEndpointsMap(s, [task()]);
    expect(map.get("finding:f1")).toEqual(["WEB01"]);
  });
});

describe("hasPlaybookHuntMaterial", () => {
  it("is false with no open tasks, true once an open task + material exists", () => {
    const withMaterial = state({ findings: [finding()] });
    expect(hasPlaybookHuntMaterial(withMaterial, [])).toBe(false);                 // no tasks
    expect(hasPlaybookHuntMaterial(withMaterial, [task()])).toBe(true);            // open task + finding
    expect(hasPlaybookHuntMaterial(withMaterial, [task({ status: "done" })])).toBe(false);  // closed task
    expect(hasPlaybookHuntMaterial(state(), [task()])).toBe(false);               // open task, but no material
  });

  it("counts a forensic event as material", () => {
    const s = state({ forensicTimeline: [event()] });
    expect(hasPlaybookHuntMaterial(s, [task()])).toBe(true);
  });
});
