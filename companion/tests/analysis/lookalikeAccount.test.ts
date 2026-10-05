import { describe, it, expect } from "vitest";
import { accountChangeOverlay, lookalikeBuiltin, memberCn } from "../../src/analysis/lookalikeAccount.js";

describe("lookalikeBuiltin", () => {
  it("flags a one- or two-edit typo of a long built-in name", () => {
    expect(lookalikeBuiltin("administratr")).toBe("administrator");
    expect(lookalikeBuiltin("Adminstrator")).toBe("administrator");
    expect(lookalikeBuiltin("adm1nistrator")).toBe("administrator");
    expect(lookalikeBuiltin("defaultacount")).toBe("defaultaccount");
  });

  it("flags a one-edit typo of a short built-in name", () => {
    expect(lookalikeBuiltin("krbtgr")).toBe("krbtgt");
    expect(lookalikeBuiltin("guesl")).toBe("guest");
    expect(lookalikeBuiltin("admim")).toBe("admin");
  });

  it("catches homoglyphs, even when every letter is swapped", () => {
    expect(lookalikeBuiltin("аdministrator")).toBe("administrator"); // Cyrillic а
    expect(lookalikeBuiltin("аdmіnіstrаtor")).toBe("administrator");
    expect(lookalikeBuiltin("4dmin")).toBe("admin");
  });

  it("does not flag the built-in account itself", () => {
    expect(lookalikeBuiltin("Administrator")).toBeNull();
    expect(lookalikeBuiltin("KRBTGT")).toBeNull();
    expect(lookalikeBuiltin("Guest")).toBeNull();
    expect(lookalikeBuiltin("EXAMPLE\\Administrator")).toBeNull();
  });

  it("does not flag localized built-in names", () => {
    for (const n of [
      "Administrateur",
      "Administrador",
      "Administratör",
      "Administrátor",
      "Invité",
      "Invitado",
    ])
      expect(lookalikeBuiltin(n), n).toBeNull();
  });

  it("does not flag numbered copies or RODC krbtgt accounts", () => {
    expect(lookalikeBuiltin("admin2")).toBeNull();
    expect(lookalikeBuiltin("admin01")).toBeNull();
    expect(lookalikeBuiltin("administrator2")).toBeNull();
    expect(lookalikeBuiltin("krbtgt_12345")).toBeNull();
  });

  it("does not flag short names, plurals, or longer names that contain admin", () => {
    expect(lookalikeBuiltin("gues")).toBeNull();
    expect(lookalikeBuiltin("adm")).toBeNull();
    expect(lookalikeBuiltin("Administrators")).toBeNull();
    expect(lookalikeBuiltin("admins")).toBeNull();
    expect(lookalikeBuiltin("sadmin")).toBeNull();
    expect(lookalikeBuiltin("radmin")).toBeNull();
  });

  it("does not flag ordinary accounts", () => {
    for (const n of ["svc_backup", "jsmith", "helpdesk", "-", "", "backupadmin"])
      expect(lookalikeBuiltin(n), n).toBeNull();
  });
});

describe("memberCn", () => {
  it("reads the CN of a member DN", () => {
    expect(memberCn("CN=administratr,CN=Users,DC=example,DC=com")).toBe("administratr");
    expect(memberCn("cn=jsmith")).toBe("jsmith");
  });

  it("unescapes an escaped comma", () => {
    expect(memberCn("CN=Smith\\, J,OU=Staff,DC=example,DC=com")).toBe("Smith, J");
  });

  it("returns empty for a missing member and passes a bare name through", () => {
    expect(memberCn("-")).toBe("");
    expect(memberCn("")).toBe("");
    expect(memberCn("jsmith")).toBe("jsmith");
  });
});

describe("accountChangeOverlay", () => {
  const field = (data: Record<string, string>) => (k: string) => data[k] ?? "";

  it("returns null for an event it does not grade", () => {
    expect(accountChangeOverlay(4624, field({ TargetUserName: "administratr" }), "d", "Low")).toBeNull();
  });

  it("grades a look-alike new account High and names both accounts", () => {
    const r = accountChangeOverlay(4720, field({ TargetUserName: "administratr" }), "created", "Medium");
    expect(r?.severity).toBe("High");
    expect(r?.description).toBe('created [look-alike of built-in account "administrator"]');
  });

  it("keeps the note when the description is at the length cap", () => {
    const r = accountChangeOverlay(
      4720,
      field({ TargetUserName: "administratr" }),
      "x".repeat(600),
      "Medium",
    );
    expect(r?.description.length).toBeLessThanOrEqual(600);
    expect(r?.description).toMatch(/look-alike of built-in account "administrator"\]$/);
  });

  it("grades a privileged group add High without a note", () => {
    const r = accountChangeOverlay(
      4728,
      field({ TargetUserName: "Domain Admins", MemberName: "CN=jsmith" }),
      "d",
      "Medium",
    );
    expect(r).toEqual({ description: "d", severity: "High" });
  });

  it("names a look-alike member of any group add", () => {
    const r = accountChangeOverlay(
      4732,
      field({ TargetUserName: "Users", MemberName: "CN=administratr,CN=Users,DC=example,DC=com" }),
      "d",
      "Medium",
    );
    expect(r?.severity).toBe("High");
    expect(r?.description).toContain('look-alike of built-in account "administrator"');
  });

  it("cannot name a member logged only by SID", () => {
    const r = accountChangeOverlay(
      4732,
      field({ TargetUserName: "Users", MemberName: "-", MemberSid: "S-1-5-21-1-2-3-1105" }),
      "d",
      "Medium",
    );
    expect(r).toEqual({ description: "d", severity: "Medium" });
  });
});
