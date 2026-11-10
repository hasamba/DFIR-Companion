import { describe, expect, it } from "vitest";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import {
  fieldResolvers,
  GWS_SOURCES,
  gwsParameter,
  gwsSourceFor,
  SIGMA_NAME_VALUE_MAX_ELEMENTS,
  sourceResolver,
} from "../../src/analysis/sigmaLogSources.js";
import { reparseForRegrade, SIGMA_REGRADE_IMPORTERS } from "../../src/analysis/sigmaRegradeSources.js";
import { recordKey } from "../../src/analysis/sigmaRegrade.js";
import { GWS_REAL_SAMPLES, GWS_RULE, gwsActivity, gwsEvent } from "./fixtures/detectionSamples/gws.js";

// Import-time Sigma grading of Google Workspace Reports API activity (#2522): Suzaku's suzaku/gws
// rules and SigmaHQ's rules/cloud/gcp/gworkspace, read through the real importer. Records are
// synthetic, in the Reports API's own shape (fixtures/detectionSamples/gws.ts).

type Row = Record<string, unknown>;

const defaults = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot()!;
// SigmaHQ's three Workspace login rules are experimental: the reachability check loads them too.
const everyStatus = createSigmaImportGrader(
  loadBundledSigmaRuleSet({ statuses: ["stable", "test", "experimental"] }).set,
).snapshot()!;

const RULE_LINE = /^Sigma rule: .* \[([^\]]+)\] — level /gm;
const parse = (records: Row[], sigma = defaults) =>
  parseGoogleWorkspaceReport(JSON.stringify(records), { aggregate: false, sigma });
const ruleIds = (message: string | undefined): string[] =>
  [...(message ?? "").matchAll(RULE_LINE)].map((m) => m[1]).sort();

describe("the Workspace parameter resolver", () => {
  const rec = (params: Row[]): Row => gwsActivity("admin", [{ type: "x", name: "E", parameters: params }]);

  it("reads every typed value of the parameter, by name, case-insensitively", () => {
    const r = rec([
      { name: "NEW_VALUE", value: "true" },
      { name: "is_suspicious", boolValue: true },
      { name: "count", intValue: "12" },
      { name: "ids", multiValue: ["a", "b"] },
      { name: "nums", multiIntValue: ["1", "2"] },
    ]);
    expect(gwsParameter("new_value")(r)).toEqual({ present: true, values: ["true"], incomplete: false });
    expect(gwsParameter("IS_SUSPICIOUS")(r).values).toEqual(["true"]);
    expect(gwsParameter("count")(r).values).toEqual(["12"]);
    expect(gwsParameter("ids")(r).values).toEqual(["a", "b"]);
    expect(gwsParameter("nums")(r).values).toEqual(["1", "2"]);
  });

  it("is absent when no parameter has the name, and renders a message value as JSON", () => {
    const msg = { parameter: [{ name: "x", value: "y" }] };
    const r = rec([{ name: "m", messageValue: msg }]);
    expect(gwsParameter("other")(r)).toEqual({ present: false, values: [], incomplete: false });
    expect(gwsParameter("m")(r).values).toEqual([JSON.stringify(msg)]);
  });

  it("reads parameters written as a JSON string", () => {
    const r = gwsActivity("admin", [{ name: "E", parameters: JSON.stringify([{ name: "A", value: "1" }]) }]);
    expect(gwsParameter("a")(r).values).toEqual(["1"]);
  });

  it("marks a scan past the element cap incomplete, never absent", () => {
    const many = Array.from({ length: SIGMA_NAME_VALUE_MAX_ELEMENTS + 1 }, (_, i) => ({
      name: `p${i}`,
      value: "v",
    }));
    expect(gwsParameter("login_type")(rec(many))).toMatchObject({ present: false, incomplete: true });
  });
});

describe("the Workspace log sources", () => {
  const admin = gwsSourceFor("admin")!;

  it("are one per application, and a rule names its application", () => {
    expect(GWS_SOURCES.map((d) => d.id)).toEqual(["gws-admin", "gws-login", "gws-drive", "gws-calendar"]);
    expect(admin.matches({ product: "gcp", service: "google_workspace.admin" })).toBe(true);
    expect(admin.matches({ product: "gcp", service: "google_workspace.login" })).toBe(false);
    expect(gwsSourceFor("token")).toBeUndefined();
  });

  it("reads the event name in both spellings, and the service only for admin and login", () => {
    const read = sourceResolver(admin);
    const r = gwsActivity("admin", [gwsEvent("CREATE_ROLE")]);
    expect(read(r, "eventName").values).toEqual(["CREATE_ROLE"]);
    expect(read(r, "protoPayload.metadata.event.eventName").values).toEqual(["CREATE_ROLE"]);
    expect(read(r, "eventService").values).toEqual(["admin.googleapis.com"]);
    expect(read(r, "protoPayload.serviceName").values).toEqual(["admin.googleapis.com"]);
    const drive = gwsActivity("drive", [gwsEvent("change_owner")]);
    expect(sourceResolver(gwsSourceFor("drive")!)(drive, "eventService").present).toBe(false);
  });

  it("reads a bare name as a parameter, and refuses a dotted name it does not map", () => {
    expect(Array.isArray(fieldResolvers(admin, "NEW_VALUE"))).toBe(true);
    expect(fieldResolvers(admin, "protoPayload.request.foo")).toEqual({
      refused: "the field protoPayload.request.foo is not available in Google Workspace admin activity",
    });
  });
});

describe("every loadable Workspace rule is reachable from a real-shaped record", () => {
  it.each(GWS_REAL_SAMPLES.map((s) => [s.id, s] as const))("%s", (_id, s) => {
    const rows = parse([s.record], everyStatus).events;
    expect(rows).toHaveLength(1);
    expect(ruleIds(rows[0].message)).toEqual([...s.expect].sort());
  });

  it("covers every loaded Workspace rule", () => {
    const loaded = everyStatus.ruleSet.inventory
      .filter((e) => e.outcome === "loaded" && e.source?.startsWith("gws-"))
      .map((e) => e.id)
      .sort();
    expect(loaded).toHaveLength(18 + 10);
    expect([...new Set(GWS_REAL_SAMPLES.flatMap((s) => s.expect))].sort()).toEqual(loaded);
    expect(Object.values(GWS_RULE).sort()).toEqual(loaded);
  });

  it("imports calendar records, but no calendar rule loads: its one rule is a correlation", () => {
    const refused = everyStatus.ruleSet.inventory.filter(
      (e) => e.outcome === "refused" && /suzaku\/gws\//.test(e.path),
    );
    expect(refused.map((e) => e.path).sort()).toEqual([
      "suzaku/gws/calendar/gws_calendar_mass_invite.yml",
      "suzaku/gws/login/gws_login_many_source_ips.yml",
    ]);
    const calendar = gwsActivity("calendar", [gwsEvent("add_event_guest", { event_guest: "x@example.net" })]);
    const rows = parse([calendar]).events;
    expect(rows).toHaveLength(1);
    expect(ruleIds(rows[0].message)).toEqual([]);
  });
});

describe("Workspace import grading", () => {
  it("grades each event of a record on its own row", () => {
    const rec = gwsActivity("login", [gwsEvent("login_success"), gwsEvent("2sv_disable")]);
    const rows = parse([rec]).events;
    const byEvent = (name: string) => rows.find((r) => r.description.includes(`: ${name} `))?.message;
    expect(rows).toHaveLength(2);
    expect(ruleIds(byEvent("login_success"))).toEqual([]);
    expect(ruleIds(byEvent("2sv_disable"))).toEqual([GWS_RULE.twoSvDisabled]);
  });

  it("never reads a sibling event's parameters", () => {
    const rec = gwsActivity("login", [
      gwsEvent("login_success", { login_type: "google_password" }),
      gwsEvent("login_verification", { is_suspicious: true }),
    ]);
    expect(parse([rec]).events.map((e) => ruleIds(e.message))).toEqual([[], []]);
  });

  it("does not match when a parameter scan behind a negation is incomplete", () => {
    const filler = Object.fromEntries(
      Array.from({ length: SIGMA_NAME_VALUE_MAX_ELEMENTS }, (_, i) => [`p${i}`, "v"]),
    );
    const rec = gwsActivity("login", [gwsEvent("login_success", { is_suspicious: true, ...filler })]);
    expect(ruleIds(parse([rec]).events[0].message)).toEqual([]);
  });

  it("labels without changing severity at the defaults, and counts the matched rows", () => {
    const records = [gwsActivity("login", [gwsEvent("suspicious_login")])];
    const plain = parseGoogleWorkspaceReport(JSON.stringify(records), { aggregate: false });
    const graded = parse(records);
    expect(graded.events[0].severity).toBe(plain.events[0].severity);
    expect(graded.events[0].message).toMatch(/Sigma note: not graded/);
    expect(graded.sigmaRowsMatched).toBe(1);
    expect(plain.sigmaRowsMatched).toBe(0);
  });

  it("stamps the provenance on a generic row, which states no outcome", () => {
    const [row] = parse([gwsActivity("login", [gwsEvent("login_failure")])]).events;
    expect(row.canonical?.event).toEqual({ category: "cloud", type: "activity", action: "login_failure" });
    expect(row.canonical?.producer?.ruleVersions).toContain(defaults.token);
    expect(recordKey(row)).toBe("google-workspace|record:0/event:0");
  });

  it("leaves an OAuth token row's own envelope (and its outcome) as it was", () => {
    const rec = gwsActivity("token", [
      gwsEvent("authorize", {
        client_id: "123.apps.googleusercontent.com",
        app_name: "Example",
        scope: ["openid"],
      }),
    ]);
    const [row] = parse([rec]).events;
    expect(row.canonical?.event?.outcome).toBe("success");
    expect(ruleIds(row.message)).toEqual([]);
  });

  it("re-grades a stored Workspace file the same way", () => {
    expect(SIGMA_REGRADE_IMPORTERS.has("google-workspace")).toBe(true);
    const text = JSON.stringify([gwsActivity("admin", [gwsEvent("GRANT_ADMIN_PRIVILEGE")])]);
    const rows = reparseForRegrade("google-workspace", text, defaults);
    expect(rows.map((r) => ruleIds(r.message))).toEqual([
      [GWS_RULE.roleGranted, GWS_RULE.hqAdminGranted].sort(),
    ]);
  });
});
