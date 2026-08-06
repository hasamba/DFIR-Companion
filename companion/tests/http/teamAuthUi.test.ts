import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { validateLocalPassword } from "../../src/auth/password.js";

const loadPublic = (name: string) => readFile(new URL(`../../../public/${name}`, import.meta.url), "utf8");

describe("team authentication UI", () => {
  it("accepts local passwords from six characters and rejects shorter ones", () => {
    expect(() => validateLocalPassword("123456")).not.toThrow();
    expect(() => validateLocalPassword("12345")).toThrow(/at least 6 characters/i);
  });

  it("puts account and team actions in a profile menu after Settings", async () => {
    const dashboard = await loadPublic("dashboard.html");
    const settingsAt = dashboard.indexOf('id="settingsBtn"');
    const profileAt = dashboard.indexOf('id="profileMenuBtn"');

    expect(settingsAt).toBeGreaterThan(-1);
    expect(profileAt).toBeGreaterThan(settingsAt);
    expect(dashboard).toContain("Account &amp; team");
    expect(dashboard).toContain('id="profileSignOut"');
    expect(dashboard).not.toContain('id="teamIdentity"');
  });

  it("stops a read-only import before opening the picker or progress bar", async () => {
    // The import handler moved to js/dashboard-unified-import.js (#415 tier 3). The ordering this
    // asserts — permission check BEFORE the file picker opens and before the progress bar starts —
    // is the point of the test, and it went with the code, so the test reads the module. Reading
    // dashboard.html alone would have found nothing and every indexOf would have been -1 together,
    // which is how an ordering assertion passes vacuously.
    const dashboard = await loadPublic("js/dashboard-unified-import.js");
    const handlerStart = dashboard.indexOf('document.getElementById("importBtn").onclick');
    const guardAt = dashboard.indexOf("importPermissionMessage(caseId)", handlerStart);
    const pickerAt = dashboard.indexOf('document.getElementById("importFile").click()', handlerStart);

    expect(handlerStart).toBeGreaterThan(-1);
    expect(guardAt).toBeGreaterThan(handlerStart);
    expect(pickerAt).toBeGreaterThan(guardAt);
    expect(dashboard).toContain("investigator or administrator role");
    expect(dashboard).toContain("cancelImportProgress()");
    // And the guard is not merely present-and-ordered: importPermissionMessage still lives in the
    // page, so the module reaching it at all is what makes the check real rather than a local
    // stub that always returns "".
    const page = await loadPublic("dashboard.html");
    expect(page).toMatch(/function importPermissionMessage\(/);
  });

  it("uses the same six-character minimum and account wording on the HTML pages", async () => {
    const [login, account] = await Promise.all([loadPublic("login.html"), loadPublic("admin.html")]);

    expect(login).toMatch(/minlength="6"/);
    expect(account).toMatch(/minlength="6"/);
    expect(account).toContain("Account &amp; team");
    expect(account).not.toContain("Access administration");
  });
});
