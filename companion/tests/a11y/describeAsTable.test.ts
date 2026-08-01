import { describe, expect, it } from "vitest";
import { buildTableModel, laneRows } from "../../../public/js/a11y/describe-as-table.js";

describe("buildTableModel", () => {
  it("projects rows onto the requested columns, in order", () => {
    const model = buildTableModel([{ time: "02:30", host: "FS01", user: "jsmith" }], ["time", "host"]);
    expect(model.columns).toEqual(["time", "host"]);
    expect(model.rows).toEqual([["02:30", "FS01"]]);
  });

  it("renders a missing value as an empty cell rather than the string 'undefined'", () => {
    const model = buildTableModel([{ time: "02:30" }], ["time", "host"]);
    expect(model.rows).toEqual([["02:30", ""]]);
  });

  it("keeps row order, because a timeline read out of order is worse than no table", () => {
    const model = buildTableModel([{ t: "1" }, { t: "2" }, { t: "3" }], ["t"]);
    expect(model.rows).toEqual([["1"], ["2"], ["3"]]);
  });

  it("handles an empty row set", () => {
    expect(buildTableModel([], ["t"])).toEqual({ columns: ["t"], rows: [] });
  });
});

describe("laneRows", () => {
  const lanes = [
    {
      label: "WKSTN-JSMITH",
      events: [
        { timestamp: "2026-05-18T02:30:00Z", severity: "High", description: "File staged" },
        { timestamp: "2026-05-18T02:31:00Z", severity: "Critical", description: "Archive created" },
      ],
    },
    {
      label: "DC01",
      events: [{ timestamp: "2026-05-19T22:15:00Z", severity: "Critical", description: "encrypt.exe" }],
    },
  ];

  it("flattens lanes into one row per event, carrying the lane name", () => {
    const rows = laneRows(lanes);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toEqual({
      lane: "WKSTN-JSMITH",
      timestamp: "2026-05-18T02:30:00Z",
      severity: "High",
      description: "File staged",
    });
    expect(rows[2].lane).toBe("DC01");
  });

  it("sorts chronologically across lanes, since the canvas conveys order by position", () => {
    const rows = laneRows([lanes[1], lanes[0]]);
    expect(rows.map((r) => r.timestamp)).toEqual([
      "2026-05-18T02:30:00Z",
      "2026-05-18T02:31:00Z",
      "2026-05-19T22:15:00Z",
    ]);
  });

  it("strips the corroboration suffix the detail panel also hides", () => {
    const rows = laneRows([
      {
        label: "FS01",
        events: [
          { timestamp: "t", severity: "Low", description: "Logon [corroborated by 3 sources: a, b, c]" },
        ],
      },
    ]);
    expect(rows[0].description).toBe("Logon");
  });

  it("survives a lane with no events and an event with no fields", () => {
    const rows = laneRows([{ label: "empty" }, { label: "x", events: [{}] }]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({ lane: "x", timestamp: "", severity: "", description: "" });
  });
});
