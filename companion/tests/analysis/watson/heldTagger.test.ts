import { describe, expect, it } from "vitest";
import { finalizeHeld } from "../../../src/analysis/ai/watson/heldTagger.js";
import type { BuildTimeWindow } from "../../../src/analysis/buildTimeWindow.js";
import type { ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { WATSON_MARKER } from "../../../src/analysis/timeline/watsonItems.js";

// The held candidates pass the settle's post-tagger corrections in its order — build-time cap,
// lab-setup cap, Defender engine start-up — so a proposal never carries a grade or a missing record
// the settle would not have produced.

const HOST = "vault.example.com";
const ENGINE = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe";
const RTP_KEY =
  "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring";

const ev = (p: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e1",
  timestamp: "2026-10-05T12:00:00Z",
  description: "x",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: HOST,
  ...p,
});

const engineWrite = (severity: ForensicEvent["severity"]): ForensicEvent =>
  ev({
    id: "w1",
    timestamp: "2026-10-05T12:01:00Z",
    severity,
    description: `Sysmon Registry value set (EID 13) - Image=${ENGINE} - TargetObject=${RTP_KEY} @ ${HOST}`,
    path: ENGINE,
    canonical: {
      event: { category: "registry", type: "event" },
      registry: { key: RTP_KEY },
    } as ForensicEvent["canonical"],
  });

const boot = ev({
  id: "b1",
  severity: "Info",
  description: `Windows System Event log service started (EID 6005) @ ${HOST}`,
  canonical: { event: { category: "other", type: "boot" } } as ForensicEvent["canonical"],
});

const window: BuildTimeWindow = {
  host: "VAULT",
  names: ["VAULT"],
  start: "2026-10-05T11:00:00.000Z",
  end: "2026-10-05T13:00:00.000Z",
  marker: "sysprep",
  markerCount: 3,
};

type Recorded = ForensicEvent & {
  defenderEngineBoot?: { bootAt: string };
  labSetup?: { cappedFrom?: string };
};

describe("finalizeHeld", () => {
  it("stamps the engine start-up anchor from this import's start-up row", () => {
    const [out] = finalizeHeld([engineWrite("High")], {
      windows: [],
      labPaths: [],
      offered: [boot, engineWrite("Info")],
    }) as Recorded[];
    expect(out.defenderEngineBoot?.bootAt).toBe("2026-10-05T12:00:00.000Z");
    expect(out.provenance).toContain(WATSON_MARKER);
  });

  it("caps a row inside a build-time window at Low and records the grade it had", () => {
    const row = ev({ id: "r1", description: "CommandLineEventConsumer registered", severity: "High" });
    const [out] = finalizeHeld([row], { windows: [window], labPaths: [], offered: [row] });
    expect(out.severity).toBe("Low");
    expect(out.buildTime).toMatchObject({ marker: "sysprep", cappedFrom: "High" });
  });

  it("caps a row in a lab-setup folder at Medium and records the grade it had", () => {
    const row = ev({ id: "r2", description: "dropped tool", path: "C:\\labdrop\\tool.exe" });
    const [out] = finalizeHeld([row], {
      windows: [],
      labPaths: ["\\labdrop\\"],
      offered: [row],
    }) as Recorded[];
    expect(out.severity).toBe("Medium");
    expect(out.labSetup?.cappedFrom).toBe("High");
  });

  it("does not hold a candidate the corrections return to Info", () => {
    const row = ev({ id: "r3", severity: "Info" });
    expect(finalizeHeld([row], { windows: [], labPaths: [], offered: [row] })).toEqual([]);
  });
});
