// What a record teaches the principal-name ledger (#2490): an Entra service-principal sign-in names
// its principal by object id and app id; a Graph-shape directory audit names an app initiator and
// its service-principal targets. Nothing else is harvested.
import { describe, it, expect } from "vitest";
import { principalNamesFromRecords } from "../../src/analysis/principalNameHarvest.js";

const SP = "3f2a1b4c-1111-2222-3333-444455556666";
const APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const TARGET = "bbbbbbbb-1111-2222-3333-444455556666";

const spSignIn = (name: string, extra: Record<string, unknown> = {}) => ({
  createdDateTime: "2026-01-01T00:00:00Z",
  servicePrincipalId: SP,
  servicePrincipalName: name,
  appId: APP,
  appDisplayName: "ignored when servicePrincipalName is set",
  resourceDisplayName: "Microsoft Graph",
  status: {}, // outcome unknown → graded Info, still teaches the name
  ...extra,
});

describe("principalNamesFromRecords", () => {
  it("learns the object id and the app id of a service-principal sign-in, whatever its grade", () => {
    expect(principalNamesFromRecords([spSignIn("backup-automation")])).toEqual([
      { id: SP, names: ["backup-automation"] },
      { id: APP, names: ["backup-automation"] },
    ]);
  });

  it("keeps the full name, not the 50-character row text", () => {
    const long = `${"n".repeat(60)}-prod`;
    expect(principalNamesFromRecords([spSignIn(long)])[0].names).toEqual([long]);
  });

  it("falls back to appDisplayName", () => {
    const rec = { ...spSignIn(""), appDisplayName: "deployer" };
    expect(principalNamesFromRecords([rec])[0]).toEqual({ id: SP, names: ["deployer"] });
  });

  it("learns a Graph audit's app initiator and service-principal targets, not users or other targets", () => {
    const audit = {
      activityDisplayName: "Add app role assignment to service principal",
      activityDateTime: "2026-01-01T00:00:00Z",
      result: "success",
      initiatedBy: { app: { servicePrincipalId: SP, appId: APP, displayName: "backup-automation" } },
      targetResources: [
        { type: "ServicePrincipal", id: TARGET, displayName: "payroll-api" },
        { type: "User", id: "cccccccc-1111-2222-3333-444455556666", displayName: "Alice" },
      ],
    };
    expect(principalNamesFromRecords([audit])).toEqual([
      { id: SP, names: ["backup-automation"] },
      { id: APP, names: ["backup-automation"] },
      { id: TARGET, names: ["payroll-api"] },
    ]);
  });

  it("does not learn from a user-initiated audit's initiator or from a UAL-shape record", () => {
    const userAudit = {
      activityDisplayName: "Update user",
      activityDateTime: "2026-01-01T00:00:00Z",
      initiatedBy: { user: { id: "cccccccc-1111-2222-3333-444455556666", displayName: "Alice" } },
      targetResources: [],
    };
    const ual = {
      Workload: "AzureActiveDirectory",
      Operation: "Add service principal.",
      RecordType: 8,
      UserId: APP,
      Actor: [
        { ID: SP, Type: 2 },
        { ID: "backup-automation", Type: 1 },
      ],
    };
    expect(principalNamesFromRecords([userAudit, ual])).toEqual([]);
  });

  it("merges conflicting names across records into one conflicting record", () => {
    const out = principalNamesFromRecords([spSignIn("one"), spSignIn("two")]);
    expect(out[0]).toEqual({ id: SP, names: ["one", "two"] });
  });
});
