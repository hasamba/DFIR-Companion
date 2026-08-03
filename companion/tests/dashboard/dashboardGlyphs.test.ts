import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-glyphs.js — SVG glyph builders and severity colour ramps (#415).
//
// These return SVG SOURCE as a string. legendIcon() is the one called while the page is still
// parsing, which is why the whole helper set loads as a synchronous classic script rather than a
// deferred module — see public/js/dashboard-escape.js.

const g = loadDashboardModule("dashboard-glyphs.js");

describe("gearPath", () => {
  it("closes the path and emits four segments per tooth", () => {
    const d = g.gearPath(11, 11, 9, 6.3, 8);
    expect(d.startsWith("M")).toBe(true);
    expect(d.endsWith("Z")).toBe(true);
    expect((d.match(/L/g) ?? []).length).toBe(8 * 4 - 1); // first point is the M
  });

  it("rounds coordinates to one decimal, so the markup stays comparable", () => {
    expect(g.gearPath(0, 0, 1, 0.5, 1)).not.toMatch(/\d\.\d\d/);
  });
});

describe("assetIcon", () => {
  it.each([
    ["host", "<rect"],
    ["account", "<path"],
    ["service", "<path"],
  ])("draws a distinct shape for %s", (type, marker) => {
    expect(g.assetIcon(type, 11, 11, "#fff")).toContain(marker);
  });

  it("falls back to a plain circle for an unknown type", () => {
    const unknown = g.assetIcon("wormhole", 11, 11, "#fff");
    expect(unknown).toContain('r="6"');
    expect(unknown).not.toContain("<rect");
  });

  // Every icon opens with a transparent circle of radius 11. It is not decoration: the drawn
  // shapes are smaller and irregular, so without it the clickable area is the glyph's outline.
  it("always prepends a transparent hit target", () => {
    for (const type of ["host", "account", "service", "other"]) {
      expect(
        g
          .assetIcon(type, 11, 11, "#fff")
          .startsWith('<circle cx="11.0" cy="11.0" r="11" fill="transparent"/>'),
      ).toBe(true);
    }
  });

  it("uses the colour it is handed", () => {
    expect(g.assetIcon("host", 0, 0, "#abcdef")).toContain("#abcdef");
  });
});

describe("legendIcon", () => {
  it("wraps an asset icon in a sized svg element", () => {
    const svg = g.legendIcon("host");
    expect(svg).toMatch(/^<svg class="legend-ico" width="16" height="16" viewBox="0 0 22 22">/);
    expect(svg.endsWith("</svg>")).toBe(true);
    expect(svg).toContain("<rect"); // the host monitor
  });
});

describe("glyphDataUri", () => {
  it("wraps inner SVG in a data URI at the requested size", () => {
    const uri = g.glyphDataUri("<circle/>", 40);
    expect(uri.startsWith("data:image/svg+xml;utf8,")).toBe(true);
    expect(decodeURIComponent(uri)).toContain('width="40"');
    expect(decodeURIComponent(uri)).toContain("<circle/>");
  });

  it("defaults to 26 pixels", () => {
    expect(decodeURIComponent(g.glyphDataUri("<circle/>"))).toContain('width="26"');
  });

  // The payload is URI-encoded, so a `#` in an inner fill cannot terminate the URI early — which
  // is the classic way an inline SVG data URI silently renders as nothing.
  it("encodes a hash colour rather than truncating at it", () => {
    expect(g.glyphDataUri('<circle fill="#ff0000"/>')).toContain("%23ff0000");
  });
});

describe("evSevColor / geoSevColor", () => {
  it.each([
    ["Critical", "#ff5c5c"],
    ["High", "#ff5c5c"],
    ["Medium", "#ff9f43"],
    ["Low", "#6aa9ff"],
    ["Info", "#6aa9ff"],
    [undefined, "#6aa9ff"],
  ])("evSevColor(%s) -> %s", (sev, colour) => expect(g.evSevColor(sev)).toBe(colour));

  // The map layer uses named CSS colours rather than the event palette's hexes, and has a distinct
  // Low tier where evSevColor folds Low in with Info.
  it.each([
    ["Critical", "red"],
    ["High", "red"],
    ["Medium", "orange"],
    ["Low", "yellow"],
    ["Info", "gray"],
    [undefined, "gray"],
  ])("geoSevColor(%s) -> %s", (sev, colour) => expect(g.geoSevColor(sev)).toBe(colour));
});

describe("evNodeGlyph", () => {
  it("delegates hosts and accounts to assetIcon", () => {
    expect(g.evNodeGlyph({ kind: "host" }, 5, 5, "#fff")).toBe(g.assetIcon("host", 5, 5, "#fff"));
  });

  it.each([
    ["file", "<polygon"],
    ["network", "<circle"],
    ["process", "<rect"],
  ])("draws %s as its own shape", (kind, marker) => {
    expect(g.evNodeGlyph({ kind }, 5, 5, "#fff")).toContain(marker);
  });

  it("falls back to the node's severity colour when none is given", () => {
    expect(g.evNodeGlyph({ kind: "network", maxSeverity: "Critical" }, 5, 5, null)).toContain("#ff5c5c");
  });
});

describe("tagColor", () => {
  it.each([
    ["confirmed-malicious", "#ff6b6b"],
    ["c2-comms", "#ff6b6b"],
    ["exfil", "#ff6b6b"],
    ["false-positive", "#6bcB77"],
    ["benign-admin", "#6bcB77"],
    ["needs-review", "#ffd93b"],
    ["key-evidence", "#6aa9ff"],
    ["pivot-point", "#6aa9ff"],
    ["anything-else", "#9aa4b2"],
  ])("%s -> %s", (label, colour) => expect(g.tagColor(label)).toBe(colour));
});
