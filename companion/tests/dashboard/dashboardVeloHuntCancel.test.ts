// public/js/dashboard-velo-hunt-cancel.js — a running bundle hunt's Cancel button, and the line a
// cancelled hunt's card shows. The dialog's three choices are posted to routes/veloHuntCancel.ts,
// which tests/server/veloHuntCancel.test.ts covers.
import { describe, expect, it } from "vitest";
import type { VeloHuntCancelApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const mod = loadDashboardModule<VeloHuntCancelApi>("dashboard-velo-hunt-cancel.js", ["dashboard-escape.js"]);

describe("veloCancelHuntBtnHtml", () => {
  it("offers Cancel on a running or unreachable hunt", () => {
    for (const status of ["running", "unreachable"]) {
      const html = mod.veloCancelHuntBtnHtml({ status, huntId: "H.1", bundleName: "Best Practice" });
      expect(html).toContain('class="velo-cancel-hunt-btn"');
      expect(html).toContain('data-hid="H.1"');
      expect(html).toContain(">Cancel</button>");
    }
  });

  it("offers nothing once the hunt is finished, cancelled, or being collected", () => {
    for (const status of ["imported", "error", "deleted", "cancelled", "collecting"])
      expect(mod.veloCancelHuntBtnHtml({ status, huntId: "H.1" })).toBe("");
    expect(mod.veloCancelHuntBtnHtml({ status: "running", huntId: "H.1", collectActive: true })).toBe("");
    expect(mod.veloCancelHuntBtnHtml(null)).toBe("");
  });

  it("escapes the bundle name into its attribute", () => {
    const html = mod.veloCancelHuntBtnHtml({ status: "running", huntId: "H.1", bundleName: '"><img src=x>' });
    expect(html).not.toContain("<img");
  });
});

describe("veloCancelledDetail", () => {
  it("says what happened in Velociraptor for each choice", () => {
    expect(mod.veloCancelledDetail({ status: "cancelled", cancelled: { action: "stop" } })).toContain(
      "stopped in Velociraptor",
    );
    expect(mod.veloCancelledDetail({ status: "cancelled", cancelled: { action: "delete" } })).toContain(
      "deleted from Velociraptor",
    );
    expect(mod.veloCancelledDetail({ status: "cancelled", cancelled: { action: "none" } })).toContain(
      "may still be running in Velociraptor",
    );
  });

  it("never lets a refused stop read as a stopped hunt", () => {
    const line = mod.veloCancelledDetail({
      status: "cancelled",
      cancelled: { action: "delete", serverError: "PermissionDenied" },
    });
    expect(line).toContain("Velociraptor refused (PermissionDenied)");
    expect(line).not.toContain("deleted from Velociraptor");
  });

  // The job records the choice before Velociraptor answers; a restart in between leaves `pending`.
  it("never claims a stop or delete Velociraptor did not confirm", () => {
    const line = mod.veloCancelledDetail({
      status: "cancelled",
      cancelled: { action: "delete", pending: true },
    });
    expect(line).toContain("never confirmed the delete");
    expect(line).not.toContain("deleted from Velociraptor");
  });

  it("is empty for any other status", () => {
    expect(mod.veloCancelledDetail({ status: "running" })).toBe("");
    expect(mod.veloCancelledDetail(null)).toBe("");
  });
});
