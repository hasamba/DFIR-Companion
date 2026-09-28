import { describe, it, expect, afterEach } from "vitest";
import { buildAttackMatrix, aggregateCell, type MatrixHit } from "../../src/analysis/attackMatrix.js";
import {
  coerceAttackMatrix,
  loadAttackMatrix,
  resetAttackMatrixCacheForTests,
  EMPTY_ATTACK_MATRIX,
  type AttackMatrixData,
} from "../../src/analysis/attackMatrixData.js";

// A small catalogue with every shape the layout has to handle: a multi-tactic technique (T1078),
// a parent with sub-techniques on different platforms (T1059), a PRE technique (T1595), a
// Linux-only technique (T1548), and a cloud-only one (T1530).
const DATA: AttackMatrixData = {
  source: "test",
  attackVersion: "19.1",
  generated: "2026-09-28",
  tactics: [
    { id: "TA0043", shortname: "reconnaissance", name: "Reconnaissance" },
    { id: "TA0001", shortname: "initial-access", name: "Initial Access" },
    { id: "TA0002", shortname: "execution", name: "Execution" },
    { id: "TA0003", shortname: "persistence", name: "Persistence" },
    { id: "TA0004", shortname: "privilege-escalation", name: "Privilege Escalation" },
    { id: "TA0009", shortname: "collection", name: "Collection" },
  ],
  techniques: [
    { id: "T1595", name: "Active Scanning", tactics: ["reconnaissance"], platforms: ["PRE"] },
    {
      id: "T1078",
      name: "Valid Accounts",
      tactics: ["initial-access", "persistence", "privilege-escalation"],
      platforms: ["Windows", "Linux", "macOS", "IaaS"],
    },
    {
      id: "T1059",
      name: "Command and Scripting Interpreter",
      tactics: ["execution"],
      platforms: ["Windows", "Linux", "macOS"],
    },
    { id: "T1059.001", name: "PowerShell", tactics: ["execution"], platforms: ["Windows"], parent: "T1059" },
    {
      id: "T1059.004",
      name: "Unix Shell",
      tactics: ["execution"],
      platforms: ["Linux", "macOS"],
      parent: "T1059",
    },
    {
      id: "T1548",
      name: "Abuse Elevation Control Mechanism",
      tactics: ["privilege-escalation"],
      platforms: ["Linux"],
    },
    { id: "T1530", name: "Data from Cloud Storage", tactics: ["collection"], platforms: ["IaaS"] },
  ],
};

const hit = (id: string, worst: MatrixHit["worst"], extra: Partial<MatrixHit> = {}): MatrixHit => ({
  id,
  worst,
  findingIds: [],
  eventIds: [],
  ...extra,
});
const col = (m: ReturnType<typeof buildAttackMatrix>, shortname: string) =>
  m.columns.find((c) => c.tactic.shortname === shortname);
const ids = (m: ReturnType<typeof buildAttackMatrix>, shortname: string) =>
  (col(m, shortname)?.cells ?? []).map((c) => c.id);

describe("buildAttackMatrix", () => {
  it("keeps the catalogue's tactic order", () => {
    const m = buildAttackMatrix(DATA, [], { platform: "all", hitsOnly: false });
    expect(m.columns.map((c) => c.tactic.id)).toEqual([
      "TA0043",
      "TA0001",
      "TA0002",
      "TA0003",
      "TA0004",
      "TA0009",
    ]);
    expect(m.catalogueAvailable).toBe(true);
  });

  it("puts a multi-tactic technique in every one of its columns, with the same hit", () => {
    const m = buildAttackMatrix(DATA, [hit("T1078", "High")], { platform: "windows", hitsOnly: false });
    for (const t of ["initial-access", "persistence", "privilege-escalation"]) {
      const c = col(m, t)!.cells.find((x) => x.id === "T1078");
      expect(c?.hit?.worst).toBe("High");
      expect(col(m, t)!.hitCount).toBe(1);
    }
  });

  it("nests sub-techniques, expands a parent with a hit child, and aggregates the parent", () => {
    const m = buildAttackMatrix(
      DATA,
      [
        hit("T1059", "Low", { eventIds: ["e1"] }),
        hit("T1059.001", "Critical", { findingIds: ["F-1"], eventIds: ["e2"] }),
      ],
      {
        platform: "all",
        hitsOnly: false,
      },
    );
    const parent = col(m, "execution")!.cells[0];
    expect(parent.id).toBe("T1059");
    expect(parent.expanded).toBe(true);
    expect(parent.children.map((c) => c.id)).toEqual(["T1059.001", "T1059.004"]);
    expect(parent.hit?.worst).toBe("Low"); // the model keeps the parent's own hit
    expect(aggregateCell(parent)).toEqual({
      id: "T1059",
      worst: "Critical",
      findingIds: ["F-1"],
      eventIds: ["e1", "e2"],
    });
    expect(col(m, "execution")!.hitCount).toBe(2);
  });

  it("leaves a parent without child hits collapsed", () => {
    const m = buildAttackMatrix(DATA, [hit("T1059", "Low")], { platform: "all", hitsOnly: false });
    expect(col(m, "execution")!.cells[0].expanded).toBe(false);
  });

  it("filters gray cells by platform but always keeps a hit, and treats PRE as every platform", () => {
    const m = buildAttackMatrix(DATA, [hit("T1548", "Medium")], { platform: "windows", hitsOnly: false });
    expect(ids(m, "privilege-escalation")).toContain("T1548"); // Linux-only, but a hit
    expect(ids(m, "collection")).toEqual([]); // IaaS-only, no hit
    expect(ids(m, "reconnaissance")).toEqual(["T1595"]); // PRE
    const kids = col(m, "execution")!.cells[0].children.map((c) => c.id);
    expect(kids).toEqual(["T1059.001"]); // Unix Shell is not Windows
  });

  it("maps the cloud group onto the cloud platforms", () => {
    const m = buildAttackMatrix(DATA, [], { platform: "cloud", hitsOnly: false });
    expect(ids(m, "collection")).toEqual(["T1530"]);
    expect(ids(m, "execution")).toEqual([]);
  });

  it("hits only drops gray cells, gray children and empty columns", () => {
    const m = buildAttackMatrix(DATA, [hit("T1059.004", "High")], { platform: "windows", hitsOnly: true });
    expect(m.columns.map((c) => c.tactic.shortname)).toEqual(["execution"]);
    const parent = m.columns[0].cells[0];
    expect(parent.id).toBe("T1059");
    expect(parent.children.map((c) => c.id)).toEqual(["T1059.004"]);
  });

  it("sends an id the catalogue lacks to unmapped, never dropping it", () => {
    const m = buildAttackMatrix(DATA, [hit("t9999", "High"), hit("T1078", "Low")], {
      platform: "all",
      hitsOnly: true,
    });
    expect(m.unmapped.map((h) => h.id)).toEqual(["T9999"]);
  });

  it("merges duplicate hits: worst severity wins, ids union", () => {
    const m = buildAttackMatrix(
      DATA,
      [
        hit("T1530", "Low", { findingIds: ["F-1"] }),
        hit("T1530", "High", { findingIds: ["F-1", "F-2"], analystAccepted: true }),
      ],
      { platform: "all", hitsOnly: false },
    );
    expect(col(m, "collection")!.cells[0].hit).toEqual({
      id: "T1530",
      worst: "High",
      findingIds: ["F-1", "F-2"],
      eventIds: [],
      analystAccepted: true,
    });
  });

  it("with an empty catalogue puts every hit in unmapped", () => {
    const m = buildAttackMatrix(EMPTY_ATTACK_MATRIX, [hit("T1059", "High")], {
      platform: "windows",
      hitsOnly: false,
    });
    expect(m.catalogueAvailable).toBe(false);
    expect(m.columns).toEqual([]);
    expect(m.unmapped.map((h) => h.id)).toEqual(["T1059"]);
  });

  it("sorts cells by name", () => {
    const m = buildAttackMatrix(DATA, [], { platform: "all", hitsOnly: false });
    expect(ids(m, "privilege-escalation")).toEqual(["T1548", "T1078"]); // Abuse… before Valid…
  });
});

describe("attackMatrixData", () => {
  afterEach(() => resetAttackMatrixCacheForTests());

  it("loads the bundled 19.1 catalogue", () => {
    resetAttackMatrixCacheForTests();
    const d = loadAttackMatrix();
    expect(d.attackVersion).toBe("19.1");
    expect(d.tactics.length).toBe(15);
    expect(d.tactics[0].name).toBe("Reconnaissance");
    expect(d.tactics[d.tactics.length - 1].name).toBe("Impact");
    expect(d.techniques.find((t) => t.id === "T1059.001")).toMatchObject({
      name: "PowerShell",
      parent: "T1059",
    });
  });

  it("keeps only well-formed entries from a damaged file", () => {
    const d = coerceAttackMatrix({
      tactics: [{ id: "TA0002" }, { id: "TA0002", shortname: "execution", name: "Execution" }],
      techniques: [null, { id: "T1059", name: "X", tactics: [1, "execution"] }],
    });
    expect(d.tactics).toHaveLength(1);
    expect(d.techniques).toEqual([{ id: "T1059", name: "X", tactics: ["execution"], platforms: [] }]);
    expect(coerceAttackMatrix(null)).toEqual(EMPTY_ATTACK_MATRIX);
  });

  it("uses only platform names the filter groups know or deliberately leave to 'all'", async () => {
    const { PLATFORM_GROUPS } = await import("../../src/analysis/attackMatrix.js");
    resetAttackMatrixCacheForTests();
    const seen = new Set(loadAttackMatrix().techniques.flatMap((t) => t.platforms));
    const grouped = new Set([...Object.values(PLATFORM_GROUPS).flat(), "PRE", "ESXi", "Network Devices"]);
    // A new MITRE platform name fails here, so someone decides which filter it belongs to.
    expect([...seen].filter((p) => !grouped.has(p))).toEqual([]);
  });
});
