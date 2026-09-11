import { describe, expect, it } from "vitest";
import {
  capabilityOf,
  classSeverity,
  GRAPH_APP_ID,
  KNOWN_APIS,
  LOW_PRIVILEGE_SCOPES,
  roleTier,
} from "../../src/analysis/entraCapabilities.js";

describe("entraCapabilities", () => {
  it("identifies an API only by its immutable application id", () => {
    expect(KNOWN_APIS[GRAPH_APP_ID]).toBe("Microsoft Graph");
    expect(capabilityOf("11111111-2222-3333-4444-555555555555", "Mail.ReadWrite")).toBeNull();
  });
  it("names each class with the exact allowed action, case-insensitively", () => {
    expect(capabilityOf(GRAPH_APP_ID, "AppRoleAssignment.ReadWrite.All")?.class).toBe(
      "app-role grant management",
    );
    expect(capabilityOf(GRAPH_APP_ID, "rolemanagement.readwrite.directory")?.allows).toContain(
      "Global Administrator",
    );
    expect(capabilityOf(GRAPH_APP_ID, "Directory.ReadWrite.All")?.allows).toContain("not role assignments");
    expect(capabilityOf(GRAPH_APP_ID, "Mail.Send")?.allows).toBe("send mail as any user");
    expect(capabilityOf(GRAPH_APP_ID, "Mail.Read")?.class).toBe("data read");
    expect(capabilityOf(GRAPH_APP_ID, "Application.ReadWrite.OwnedBy")?.class).toBe("credential management");
    expect(capabilityOf(GRAPH_APP_ID, "Tasks.ReadWrite")).toEqual({
      class: "other",
      allows: "",
      delegated: "",
    });
  });
  it("grades every named class High and 'other' Medium", () => {
    expect(classSeverity("data read")).toBe("High");
    expect(classSeverity("identity takeover")).toBe("High");
    expect(classSeverity("other")).toBe("Medium");
  });
  it("knows the tier-0 and admin roles by template id, and nothing about a custom role", () => {
    expect(roleTier("62e90394-69f5-4237-9190-012177145e10")).toMatchObject({
      name: "Global Administrator",
      tier: "tier-0",
    });
    expect(roleTier("fe930be7-5e62-47db-91af-98c3a49a38b1")?.can).toContain("non-administrator");
    expect(roleTier("9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3")?.tier).toBe("tier-0");
    expect(roleTier("29232cdf-9323-42fd-ade2-1d097af3e4de")?.tier).toBe("admin");
    expect(roleTier("00000000-0000-0000-0000-000000000000")).toBeNull();
  });
  it("lists the scopes an ordinary one-user consent carries", () => {
    for (const s of ["openid", "profile", "email", "offline_access", "User.Read".toLowerCase()])
      expect(LOW_PRIVILEGE_SCOPES.has(s)).toBe(true);
    expect(LOW_PRIVILEGE_SCOPES.has("mail.read")).toBe(false);
  });
});
