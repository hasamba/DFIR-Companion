import { readFileSync } from "node:fs";
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
    // And the guard is not merely present-and-ordered. importPermissionMessage now lives in
    // js/dashboard-import-progress.js (#415 tier 3) — it must be declared THERE and nowhere in the
    // module that calls it, because a local copy would be a stub that always allows the import.
    const guard = await loadPublic("js/dashboard-import-progress.js");
    expect(guard).toMatch(/function importPermissionMessage\(/);
    expect(dashboard, "a local copy would defeat the check it is asked to make").not.toMatch(
      /function importPermissionMessage\(/,
    );
  });

  it("uses the same six-character minimum and account wording on the HTML pages", async () => {
    const [login, account] = await Promise.all([loadPublic("login.html"), loadPublic("admin.html")]);

    expect(login).toMatch(/minlength="6"/);
    expect(account).toMatch(/minlength="6"/);
    expect(account).toContain("Account &amp; team");
    expect(account).not.toContain("Access administration");
  });

  it("offers an all-my-cases token scope that drops the case picker and shows the scope plainly (#2474)", async () => {
    const account = await loadPublic("admin.html");
    expect(account).toMatch(
      /<select name="scope" id="tokenScope">[\s\S]*value="case" selected[\s\S]*value="all-cases"/,
    );
    // The hidden case picker must not block submission for someone who administers no case.
    expect(account).toContain("caseSelect.disabled = allCases;");
    expect(account).toContain("caseSelect.required = !allCases;");
    expect(account).toContain("expires.required = allCases;");
    expect(account).toContain("localDateTime(90)");
    expect(account).toContain("localDateTime(30)");
    expect(account).toContain("' can edit'");
    expect(account).toContain("<th>Scope</th>");
  });

  it("lets a global administrator edit a person: name, role and (local only) password", async () => {
    const account = await loadPublic("admin.html");
    expect(account).toContain("data-edit-user=");
    expect(account).toContain("data-edit-form=");
    expect(account).toContain('<option value="member"');
    expect(account).toContain("u.kind === 'local'");
    expect(account).toContain("New password (optional)");
    expect(account).toContain("{method:'PATCH', body:JSON.stringify(patch)}");
    expect(account).toContain("patch.displayName = name");
    expect(account).toContain("patch.globalRole");
    expect(account).toContain("if (user.kind === 'local' && password) patch.password");
    expect(account).toContain("esc(u.displayName)");
    expect(account).toContain("say(e.message)");
  });

  it("keeps the open case across the account page (?return=<caseId> to /dashboard?caseId=)", async () => {
    const [dashboard, account] = await Promise.all([loadPublic("dashboard.html"), loadPublic("admin.html")]);
    expect(dashboard).toContain(
      'id="profileAccountLink" href="/admin" role="menuitem" data-act="accountLink"',
    );
    const act = readFileSync(new URL("../../../public/js/dashboard-data-act.js", import.meta.url), "utf8");
    expect(act).toContain('"/admin?return=" + encodeURIComponent(id)');
    expect(act).toContain("/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/");
    expect(account).toContain('id="backToDashboard" href="/dashboard"');
    expect(account).toContain("get('return')");
    expect(account).toContain("'/dashboard?caseId=' + encodeURIComponent(id)");
    expect(account).toContain("/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/");
  });
});
