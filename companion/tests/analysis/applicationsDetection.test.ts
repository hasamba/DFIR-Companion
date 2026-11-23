// DetectRaptor.Windows.Detection.Applications — an installed program (Windows.Sys.Programs) whose
// KeyName/DisplayName matched one of the pack's application lists ("RMM", …). The row is
// `{Category, KeyName, DisplayName, DisplayVersion, Publisher, InstallLocation, KeyPath, Regex, …}`
// with no rule Name, so before this mapper it reached the generic dump titled only by its Category
// ("RMM") — the application itself never reached the title — and every app of one category on a
// host folded into one event.
import { describe, expect, it } from "vitest";
import { isApplicationsRow, mapApplications } from "../../src/analysis/applicationsDetection.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

const ARTIFACT = "DetectRaptor.Windows.Detection.Applications";

const app = (displayName = "TeamViewer", over: Record<string, unknown> = {}): Record<string, unknown> => ({
  Category: "RMM",
  KeyName: displayName,
  KeyLastWriteTimestamp: "2026-10-01T08:00:00Z",
  DisplayName: displayName,
  DisplayVersion: "15.40.8",
  InstallLocation: `C:\\Program Files\\${displayName}`,
  Publisher: `${displayName} Vendor - Example`,
  KeyPath: `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${displayName}`,
  Regex: `^${displayName}`,
  Comment: "remote management tool",
  ...over,
});

describe("isApplicationsRow", () => {
  it("claims the DetectRaptor Applications shape only", () => {
    expect(isApplicationsRow(app())).toBe(true);
    // A raw Windows.Sys.Programs row has no Category/Regex verdict.
    expect(isApplicationsRow({ KeyName: "TeamViewer", DisplayName: "TeamViewer" })).toBe(false);
    expect(isApplicationsRow({ Category: "RMM", Regex: "x" })).toBe(false); // nothing named
  });
});

describe("mapApplications", () => {
  it("puts the category AND the application in the title, details after the boundary", () => {
    const e = mapApplications(app(), ARTIFACT, "HOST01");
    const title = e.description.slice(0, e.description.indexOf(" - "));
    expect(title).toBe(`Velociraptor [${ARTIFACT}]: RMM — TeamViewer 15.40.8`);
    expect(e.description).toContain("Publisher: TeamViewer Vendor — Example");
    expect(e.description).toContain("@ HOST01");
    expect(e.message ?? "").toContain("InstallLocation: C:\\Program Files\\TeamViewer");
    expect(e.message ?? "").toContain("KeyPath: HKEY_LOCAL_MACHINE");
    expect(e.severity).toBe("Medium");
    expect(e.asset).toBe("HOST01");
    expect(e.timestamp).toContain("2026-10-01T08:00:00");
  });

  it("keeps two applications of one category apart, and one app's repeats together", () => {
    const a = mapApplications(app("TeamViewer"), ARTIFACT, "HOST01");
    const b = mapApplications(app("AnyDesk"), ARTIFACT, "HOST01");
    const a2 = mapApplications(app("TeamViewer", { DisplayVersion: "15.41" }), ARTIFACT, "HOST01");
    expect(a.aggKey).not.toBe(b.aggKey);
    expect(a.aggKey).toBe(a2.aggKey);
  });

  it("falls back to KeyName when DisplayName is empty", () => {
    const e = mapApplications(app("TeamViewer", { DisplayName: "", DisplayVersion: "" }), ARTIFACT, "");
    expect(e.description.startsWith(`Velociraptor [${ARTIFACT}]: RMM — TeamViewer`)).toBe(true);
  });
});

describe("Velociraptor import of an Applications file", () => {
  it("emits one titled event per application", () => {
    const rows = [app("TeamViewer"), app("AnyDesk")].map((r) => ({ ...r, Fqdn: "WS01", _Source: ARTIFACT }));
    const { events } = parseVelociraptorJson(JSON.stringify(rows));
    expect(events).toHaveLength(2);
    const titles = events.map((e) => e.description).sort();
    expect(titles[0]).toContain("RMM — AnyDesk");
    expect(titles[1]).toContain("RMM — TeamViewer");
    for (const e of events) expect(e.severity).toBe("Medium");
  });
});
