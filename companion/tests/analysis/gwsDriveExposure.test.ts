// #1064 (second half of #931 item 11): a Drive document's broadening sharing changes, joined in
// time order to the access records that follow — per independent dimension, never through a
// claimed permission, never by matching an accessor to a sharing target.
import { describe, expect, it } from "vitest";
import { gwsDriveExposureRows, GWS_EXPOSURE_MAX } from "../../src/analysis/gwsDriveExposure.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

const TENANT = "C01abc";
const DOC = "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
let q = 0;

const p = (name: string, value: string | boolean) =>
  typeof value === "boolean" ? { name, boolValue: value } : { name, value };

const docParams = (over: Record<string, string | boolean> = {}) => {
  const base: Record<string, string | boolean> = {
    doc_id: DOC,
    doc_title: "Q3 plan",
    doc_type: "spreadsheet",
    owner: "alice@corp.example",
    owner_is_shared_drive: false,
    primary_event: true,
  };
  return Object.entries({ ...base, ...over }).map(([k, v]) => p(k, v));
};

const rec = (
  time: string,
  eventType: string,
  name: string,
  params: unknown[],
  actor: Record<string, unknown> = { email: "alice@corp.example", profileId: "1000" },
) => ({
  kind: "admin#reports#activity",
  id: {
    time,
    uniqueQualifier: String(--q),
    applicationName: "drive",
    customerId: TENANT,
  },
  actor,
  ipAddress: "203.0.113.10",
  events: [{ type: eventType, name, parameters: params }],
});

const visibility = (time: string, from: string, to: string, visibilityChange = "none") =>
  rec(
    time,
    "acl_change",
    "change_document_visibility",
    docParams({ old_value: from, new_value: to, visibility_change: visibilityChange, visibility: to }),
  );

const userAccess = (time: string, from: string, to: string, target: string) =>
  rec(
    time,
    "acl_change",
    "change_user_access",
    docParams({ old_value: from, new_value: to, target_user: target, visibility_change: "none" }),
  );

const scopeChange = (time: string, from: string, to: string, targetDomain: string) =>
  rec(
    time,
    "acl_change",
    "change_document_access_scope",
    docParams({ old_value: from, new_value: to, target_domain: targetDomain, visibility_change: "none" }),
  );

const inherit = (time: string, enable: boolean) =>
  rec(time, "acl_change", enable ? "enable_inherited_permissions" : "disable_inherited_permissions", docParams());

const ownerChange = (time: string, to: string) =>
  rec(time, "acl_change", "change_owner", docParams({ new_value: to }));

const access = (
  time: string,
  name: string,
  actor: Record<string, unknown> = { email: "carol@example.com", profileId: "2000" },
) => rec(time, "access", name, docParams(), actor);

const noActorAccess = (time: string, name: string) => {
  const r = access(time, name);
  delete (r as Record<string, unknown>).actor;
  return r as Record<string, unknown>;
};

const appAccess = (time: string, name: string, appId = "555123456789") =>
  rec(time, "access", name, docParams(), {
    callerType: "APPLICATION",
    applicationInfo: { oauthClientId: appId, applicationName: "Some App" },
  });

const rows = (records: Record<string, unknown>[]) => gwsDriveExposureRows(records);

describe("Drive document exposure: one row per document with a broadening change", () => {
  it("no broadening in the export -> no row", () => {
    expect(rows([userAccess(at(0), "can_edit", "can_view", "bob@corp.example")])).toHaveLength(0);
    expect(rows([access(at(0), "view")])).toHaveLength(0);
  });

  it("a broadening with no access after it: the row exists, absence sentence, graded by the broadening", () => {
    const r = rows([userAccess(at(0), "none", "can_edit", "bob@corp.example")]);
    expect(r).toHaveLength(1);
    expect(r[0].severity).toBe("Medium");
    expect(r[0].description).toContain("fell inside an exposure window");
    expect(r[0].description).not.toContain("no access after the broadening");
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    expect(env.driveExposure?.docId).toBe(DOC);
    expect(env.driveExposure?.tenant).toBe(TENANT);
    expect(env.driveExposure?.accessors).toEqual([]);
  });

  it("a broadening then a download by a named user: strongest verb leads, window named, never 'through the share'", () => {
    const r = rows([
      userAccess(at(0), "none", "can_edit", "bob@corp.example"),
      access(at(100), "view"),
      access(at(200), "download"),
    ]);
    expect(r).toHaveLength(1);
    expect(r[0].description).toContain("download recorded");
    expect(r[0].description).not.toMatch(/through (this|the) share/);
    expect(r[0].description).toContain("access through a specific share is not established");
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    const carol = env.driveExposure?.accessors.find((a) => a.identity === "carol@example.com");
    expect(carol?.kind).toBe("named");
    expect(carol?.records.map((x) => x.meaning)).toEqual(
      expect.arrayContaining(["viewed", "download recorded"]),
    );
    expect(carol?.records[0].windowsOpen.length).toBeGreaterThan(0);
  });

  it("two independent dimensions: a narrowing on one never closes the other's window", () => {
    const r = rows([
      visibility(at(0), "private", "people_with_link"),
      userAccess(at(50), "none", "can_edit", "bob@corp.example"),
      userAccess(at(80), "can_edit", "none", "bob@corp.example"), // narrows the ACL dimension only
      access(at(100), "download"), // after the ACL narrowing, but visibility is still open
    ]);
    expect(r).toHaveLength(1);
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    const carol = env.driveExposure?.accessors.find((a) => a.identity === "carol@example.com");
    expect(carol?.records).toHaveLength(1);
    expect(carol?.records[0].windowsOpen.some((w) => w.startsWith("visibility"))).toBe(true);
    expect(carol?.records[0].windowsOpen.some((w) => w.startsWith("acl:"))).toBe(false);
  });

  it("a narrowing that closes every window: later access is excluded, absence sentence covers it", () => {
    const r = rows([
      userAccess(at(0), "none", "can_edit", "bob@corp.example"),
      userAccess(at(50), "can_edit", "none", "bob@corp.example"),
      access(at(100), "download"),
    ]);
    expect(r).toHaveLength(1);
    expect(r[0].description).toContain("fell inside an exposure window");
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    expect(env.driveExposure?.accessors).toEqual([]);
    expect(env.driveExposure?.accessRecordsTotal).toBe(1);
  });

  it("inheritance events appear chronologically and never gate a window", () => {
    const r = rows([inherit(at(0), true), access(at(10), "download")]);
    expect(r).toHaveLength(0);
  });

  it("owner change and acl-editors change gate nothing but a real broadening still creates the row", () => {
    const r = rows([
      ownerChange(at(0), "mallory@corp.example"),
      userAccess(at(10), "none", "can_view", "bob@corp.example"),
      access(at(50), "view"),
    ]);
    expect(r).toHaveLength(1);
    expect(r[0].description).toContain("change_owner");
  });

  it("equal timestamps establish no order: an access at the exact open instant is excluded", () => {
    const r = rows([userAccess(at(0), "none", "can_edit", "bob@corp.example"), access(at(0), "download")]);
    expect(r).toHaveLength(1);
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    expect(env.driveExposure?.accessors).toEqual([]);
  });

  it("a target-less ACL broadening alone opens no window and creates no row", () => {
    const r = rows([userAccess(at(0), "none", "can_edit", ""), access(at(10), "download")]);
    expect(r).toHaveLength(0);
  });

  it("two target-domain-less scope changes never gate each other", () => {
    const r = rows([
      scopeChange(at(0), "can_view", "can_edit", ""),
      scopeChange(at(50), "can_edit", "can_view", ""), // would look like a narrow if bucketed together
      access(at(100), "download"),
    ]);
    expect(r).toHaveLength(0);
  });

  it("same-instant broaden + narrow on one dimension: window state unchanged, worded as a conflict, order-independent", () => {
    const forward = [
      userAccess(at(0), "none", "can_edit", "bob@corp.example"),
      userAccess(at(0), "can_edit", "none", "bob@corp.example"),
      access(at(10), "download"),
    ];
    const reversed = [forward[1], forward[0], forward[2]];
    for (const set of [forward, reversed]) {
      const r = rows(set);
      expect(r).toHaveLength(1);
      expect(r[0].description).toContain("conflicting same-instant sharing changes");
      const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
      // The window never opened (conflict at the very first bucket) -> no access counted.
      expect(env.driveExposure?.accessors).toEqual([]);
      expect(env.driveExposure?.conflicts.length).toBeGreaterThan(0);
      // The conflict itself, not the export's coverage.first, sets the row's observed time and
      // its evidence — the row is never anchored to a fact unrelated to what it reports.
      expect(env.driveExposure?.conflicts[0].locators.length).toBe(2);
      expect(r[0].timestamp).toBe(at(0));
    }
  });

  it("an unparseable id.time is excluded from ordering and counted, never dropped silently", () => {
    const bad = userAccess(at(0), "none", "can_edit", "bob@corp.example");
    (bad as Record<string, unknown> & { id: Record<string, unknown> }).id.time = "not-a-time";
    const r = rows([bad, userAccess(at(10), "none", "can_view", "carol@corp.example"), access(at(20), "download")]);
    expect(r).toHaveLength(1);
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    expect(env.driveExposure?.timeNotEstablished).toBe(1);
  });

  it("an application accessor groups separately from a named user and from no-identity records", () => {
    const r = rows([
      visibility(at(0), "private", "people_with_link"),
      access(at(10), "download"),
      appAccess(at(20), "sync_item_content"),
      noActorAccess(at(30), "download"),
    ]);
    expect(r).toHaveLength(1);
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    const kinds = env.driveExposure?.accessors.map((a) => a.kind).sort();
    expect(kinds).toEqual(["application", "named", "none"]);
    expect(env.driveExposure?.accessors.find((a) => a.kind === "application")?.identity).toBe("555123456789");
  });

  it("a reconciled or side-effect row never opens a window and never appears chronologically", () => {
    const reconciled = rec(
      at(0),
      "acl_change",
      "change_user_access_hierarchy_reconciled",
      docParams({ old_value: "none", new_value: "can_edit", target_user: "bob@corp.example" }),
    );
    const r = rows([reconciled, access(at(10), "download")]);
    expect(r).toHaveLength(0);
  });

  it("coverage and bounds are stated", () => {
    const r = rows([userAccess(at(0), "none", "can_edit", "bob@corp.example"), access(at(10), "download")]);
    const env = canonicalEventEnvelopeSchema.parse(r[0].canonical);
    expect(env.driveExposure?.coverage.records).toBeGreaterThan(0);
    expect(env.driveExposure?.windowsBeyond).toBe(0);
    expect(env.driveExposure?.accessorsBeyond).toBe(0);
  });

  it("more documents than GWS_EXPOSURE_MAX produce an overflow row", () => {
    const records: Record<string, unknown>[] = [];
    for (let i = 0; i < GWS_EXPOSURE_MAX + 3; i++) {
      const doc = `${DOC}${i}`;
      records.push(
        rec(at(i), "acl_change", "change_user_access", [
          ...docParams({ old_value: "none", new_value: "can_edit", target_user: "bob@corp.example" }).filter(
            (x) => x.name !== "doc_id",
          ),
          { name: "doc_id", value: doc },
        ]),
      );
    }
    const r = rows(records);
    expect(r.length).toBe(GWS_EXPOSURE_MAX + 1);
    expect(r[r.length - 1].description).toContain("further document");
  });
});
