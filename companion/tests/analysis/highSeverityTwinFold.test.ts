import { describe, it, expect } from "vitest";
import { backfillHighSeverityFindings } from "../../src/analysis/highSeverityFindings.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1556. Fixtures copy the shapes of real rows from a scored scenario: Chainsaw fires two Sigma rules
// on one AdFind process (the AI cites one), and THOR LogScan repeats the VeeamHax command lines at
// scan time. Hostnames are invented.

const HOST = "WS01.example.com";
const OTHER_HOST = "WS02.example.com";
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const VEEAM = "C:\\ProgramData\\Sim\\VeeamHax.exe";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-09-22T14:38:27.546Z",
    description: "desc",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...over,
  };
}

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    severity: "High",
    title: `finding ${id}`,
    description: "model finding",
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "t0",
    lastUpdated: "t0",
    status: "confirmed",
    ...over,
  };
}

// A Chainsaw Sysmon EID 1 row. Chainsaw cuts the head of the command line and writes `…` instead.
function chainsaw(rule: string, image: string, tail: string, host = HOST): string {
  return (
    `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: ${rule} - Sysmon Process create (EID 1) - Image=${image}` +
    ` - CommandLine=… ${tail} - ParentImage=${PS} - ParentCommandLine=${PS} @ ${host}`
  );
}

// A THOR LogScan row: its own scan time in `timestamp`, the logged time inside the text, and the
// full command line with the quotes gone.
function thor(loggedAt: string, image: string, args: string, host = HOST): string {
  return (
    `THOR Warning [LogScan]: Suspicious Log Entry found — ${loggedAt} Engine:command line reported as lowfi: ` +
    `${image}(${image} ${args}) - @ ${host}`
  );
}

const ADFIND_TAIL = '/d /v:off /c echo EGG-CANARY adfind.exe -f "objectcategory=computer"';
const VEEAM_TAIL = `/d /v:off /c echo EGG-CANARY VeeamHax.exe --target 127.0.0.1 --sql "EXEC sp_configure 'xp_cmdshell','1'"`;
const VEEAM_ARGS = `/d /v:off /c echo EGG-CANARY VeeamHax.exe --target 127.0.0.1 --sql EXEC sp_configure 'xp_cmdshell','1'`;

function adFindPair(siblingHost = HOST): ReturnType<typeof emptyState> {
  const state = emptyState("c1");
  state.findings.push(finding("f6"));
  state.forensicTimeline.push(
    ev({
      id: "2e17",
      description: chainsaw("Renamed AdFind Execution", "C:\\Windows\\System32\\cmd.exe", ADFIND_TAIL),
      relatedFindingIds: ["f6"],
    }),
    ev({
      id: "2e18",
      asset: siblingHost,
      description: chainsaw(
        "PUA - AdFind Suspicious Execution",
        "C:\\Windows\\System32\\cmd.exe",
        ADFIND_TAIL,
        siblingHost,
      ),
    }),
  );
  return state;
}

function veeamPair(
  over: Partial<ForensicEvent> = {},
  f8: Partial<Finding> = {},
): ReturnType<typeof emptyState> {
  const state = emptyState("c1");
  state.findings.push(finding("f8", f8));
  state.forensicTimeline.push(
    ev({
      id: "2e62",
      timestamp: "2026-09-22T14:38:37.303Z",
      severity: "Medium",
      path: VEEAM,
      description: chainsaw("Potential Defense Evasion Via Binary Rename", VEEAM, VEEAM_TAIL),
      relatedFindingIds: ["f8"],
    }),
    ev({
      id: "21e6",
      timestamp: "2026-09-22T17:47:57Z",
      description: thor("2026-09-22T14:38:37.308", VEEAM, VEEAM_ARGS),
      ...over,
    }),
  );
  return state;
}

const idsOf = (s: ReturnType<typeof emptyState>): string[] => s.findings.map((f) => f.id).sort();
const linksOf = (s: ReturnType<typeof emptyState>, id: string): string[] | undefined =>
  s.forensicTimeline.find((e) => e.id === id)?.relatedFindingIds;

describe("backfillHighSeverityFindings — an uncovered event whose twin a finding already cites (#1556)", () => {
  it("folds the second Sigma rule on one process into the finding that cites the first", () => {
    const out = backfillHighSeverityFindings(adFindPair(), new Set(["2e17", "2e18"]), "t");
    expect(idsOf(out)).toEqual(["f6"]);
    expect(linksOf(out, "2e18")).toEqual(["f6"]);
  });

  it("folds a THOR LogScan repeat of a command line into the finding that cites the original", () => {
    const out = backfillHighSeverityFindings(veeamPair(), new Set(["2e62", "21e6"]), "t");
    expect(idsOf(out)).toEqual(["f8"]);
    expect(linksOf(out, "21e6")).toEqual(["f8"]);
  });

  it("never changes the severity of the folded event or the finding", () => {
    const state = veeamPair({}, { severity: "Medium" });
    const out = backfillHighSeverityFindings(state, new Set(["2e62", "21e6"]), "t");
    expect(out.forensicTimeline.find((e) => e.id === "21e6")?.severity).toBe("High");
    expect(out.findings.find((f) => f.id === "f8")?.severity).toBe("Medium");
  });

  it("does not fold across hosts", () => {
    const out = backfillHighSeverityFindings(adFindPair(OTHER_HOST), new Set(["2e17", "2e18"]), "t");
    expect(idsOf(out)).toEqual(["f-auto-2e18", "f6"]);
    expect(linksOf(out, "2e18")).toEqual(["f-auto-2e18"]);
  });

  it("does not fold into a dismissed finding", () => {
    const state = veeamPair({}, { status: "dismissed" });
    const out = backfillHighSeverityFindings(state, new Set(["2e62", "21e6"]), "t");
    expect(idsOf(out)).toEqual(["f-auto-21e6", "f8"]);
  });

  it("does not treat a twin that only an auto finding cites as covered", () => {
    const state = adFindPair();
    const autoOnly = {
      ...state,
      findings: [finding("f-auto-2e17", { status: "open" })],
      forensicTimeline: state.forensicTimeline.map((e) =>
        e.id === "2e17" ? { ...e, relatedFindingIds: ["f-auto-2e17"] } : e,
      ),
    };
    const out = backfillHighSeverityFindings(autoOnly, new Set(["2e17", "2e18"]), "t");
    expect(idsOf(out)).toEqual(["f-auto-2e17", "f-auto-2e18"]);
  });

  it("does not fold a different command line from the same image", () => {
    const state = veeamPair({
      description: thor(
        "2026-09-22T14:38:37.308",
        VEEAM,
        "/d /v:off /c echo EGG-CANARY VeeamHax.exe --sql RECONFIGURE",
      ),
    });
    const out = backfillHighSeverityFindings(state, new Set(["2e62", "21e6"]), "t");
    expect(idsOf(out)).toEqual(["f-auto-21e6", "f8"]);
  });

  it("folds on the same image at the same moment when the uncovered row carries no command line", () => {
    const state = veeamPair({
      timestamp: "2026-09-22T14:38:37.310Z",
      path: VEEAM,
      description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Suspicious File Write - Sysmon File create (EID 11) - Image=${VEEAM} - TargetFilename=C:\\ProgramData\\x.dat @ ${HOST}`,
    });
    const out = backfillHighSeverityFindings(state, new Set(["2e62", "21e6"]), "t");
    expect(idsOf(out)).toEqual(["f8"]);
    expect(linksOf(out, "21e6")).toEqual(["f8"]);
  });

  it("does not fold on the same image when the moments are seconds apart", () => {
    const state = veeamPair({
      timestamp: "2026-09-22T14:38:41.000Z",
      path: VEEAM,
      description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Suspicious File Write - Sysmon File create (EID 11) - Image=${VEEAM} - TargetFilename=C:\\ProgramData\\x.dat @ ${HOST}`,
    });
    const out = backfillHighSeverityFindings(state, new Set(["2e62", "21e6"]), "t");
    expect(idsOf(out)).toEqual(["f-auto-21e6", "f8"]);
  });
});

describe("backfillHighSeverityFindings — grouping titles ignore a per-row timestamp (#1556)", () => {
  it("groups THOR LogScan rows that differ only in the logged time into one finding", () => {
    const state = emptyState("c1");
    const times = ["35.258", "36.289", "37.308", "38.344", "39.373"];
    state.forensicTimeline.push(
      ...times.map((t, i) =>
        ev({
          id: `21e${4 + i}`,
          timestamp: "2026-09-22T17:47:57Z",
          description: thor(`2026-09-22T14:38:${t}`, VEEAM, `--sql step${i}`),
        }),
      ),
    );
    const out = backfillHighSeverityFindings(state, new Set(state.forensicTimeline.map((e) => e.id)), "t");
    expect(idsOf(out)).toEqual(["f-auto-21e4"]);
    expect(out.findings[0].title).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(out.findings[0].description).toContain("5 similar");
  });
});

describe("backfillHighSeverityFindings — a finding id the case already holds (#1556)", () => {
  it("links to the existing finding instead of appending a second row with the same id", () => {
    const state = emptyState("c1");
    // The model echoed a prior backfill finding by id — retitled and confirmed — but cited no events.
    state.findings.push(
      finding("f-auto-2e16", { title: "PUA - AdFind Suspicious Execution (Sigma detection)" }),
    );
    state.forensicTimeline.push(
      ev({
        id: "2e16",
        description: chainsaw(
          "PUA - AdFind Suspicious Execution",
          "C:\\Windows\\System32\\cmd.exe",
          ADFIND_TAIL,
        ),
      }),
    );
    const out = backfillHighSeverityFindings(state, new Set(["2e16"]), "t");
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].title).toBe("PUA - AdFind Suspicious Execution (Sigma detection)");
    expect(linksOf(out, "2e16")).toEqual(["f-auto-2e16"]);
  });
});
