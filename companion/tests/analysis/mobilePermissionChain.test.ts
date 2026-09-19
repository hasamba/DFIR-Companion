import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  mobilePermissionChains,
  MOBILE_PERMISSION_CHAIN_CAVEAT,
  MAX_CHAINS,
  MAX_ROWS_PER_PERMISSION,
  MAX_PACKAGE_LEVEL_ROWS,
  VOCABULARY_SENTENCE,
} from "../../src/analysis/mobilePermissionChain.js";
import { registryEntry } from "../../src/analysis/mobileOriginRegistry.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import { parseMobsfPermissions } from "../../src/analysis/mobsfPermissionImport.js";
import type { StaticReportAttestation } from "../../src/analysis/staticReportAttestationStore.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1363 (932.15's second half): requested (MobSF, per attested report) ↔ granted (a stored
// state) ↔ used (a dated AppOps access) by package on the analyst's subject device. Presence
// only; every row names its artifact, column, value and locator; nothing is graded.

const T = "2026-06-01T10:00:00";
const SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const OTHER_SHA = "a".repeat(64);
let seq = 0;

/** One imported row of a registered Android artifact, through the real importer. */
function row(
  artifact: string,
  values: Record<string, string>,
  device: string | undefined = "Subject Pixel",
): ForensicEvent {
  const entry = registryEntry(artifact)!;
  const cells = entry.headers.map((h) => values[h] ?? "");
  const events = parseLeappTsv([entry.headers.join("\t"), cells.join("\t")].join("\n"), `${entry.name}.tsv`, {
    platform: "android",
    ...(device ? { device } : {}),
  }).events;
  return {
    ...(events[0] as ForensicEvent),
    id: `lp${++seq}`,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

const grant = (pkg: string, permission: string, granted: string, device?: string) =>
  row(
    "Permission Grants (Permission Store)",
    { "Package Name": pkg, Permission: permission, Granted: granted },
    device,
  );
const mode = (pkg: string, permission: string, value: string) =>
  row("App Ops Permission Modes", { "Package Name": pkg, Permission: permission, Mode: value });
const access = (pkg: string, op: string, at = T, extra: Record<string, string> = {}, device?: string) =>
  row(
    "App Ops Permissions",
    { "Access Timestamp": at, "Package Name": pkg, Permission: op, ...extra },
    device,
  );
const reject = (pkg: string, op: string, at = T) =>
  row("App Ops Permissions", { "Reject Timestamp": at, "Package Name": pkg, Permission: op });
const recent = (pkg: string, op: string, opMode: string, at = T) =>
  row("App Ops Recent Accesses", {
    "Access Timestamp": at,
    "Package Name": pkg,
    Permission: op,
    "Op Mode": opMode,
  });
const usage = (pkg: string) =>
  row("Usage Stats", { "Timestamp / Last Time Active": T, Package: pkg, "Usage Type": "MOVE_TO_FOREGROUND" });
const inventory = (pkg: string, sha: string) =>
  row("installedappsGass", { "Bundle ID": pkg, "SHA-256 Hash": sha, "Version Code": "1" });

/** A MobSF Android report's requested-permission rows, through the real importer. */
function mobsf(
  pkg: string,
  permissions: Record<string, string>,
  sha256: string = SHA,
): { events: ForensicEvent[]; fingerprint: string } {
  const text = JSON.stringify({
    version: "4.5.0",
    file_name: "sample.apk",
    app_name: "Sample",
    package_name: pkg,
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256,
    apkid: {},
    permissions: Object.fromEntries(
      Object.entries(permissions).map(([p, status]) => [p, { status, info: "i", description: "d" }]),
    ),
  });
  const events = parseMobsfPermissions(text)!.events.map((e) => ({
    ...(e as unknown as ForensicEvent),
    id: `mb${++seq}`,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
  return { events, fingerprint: createHash("sha256").update(text).digest("hex") };
}

function attest(
  fingerprint: string,
  subjectHost = "Subject Pixel",
  extra: Partial<StaticReportAttestation> = {},
): StaticReportAttestation {
  return {
    id: `att-${++seq}`,
    reportFingerprint: fingerprint,
    tool: "mobsf",
    subjectHost,
    toolReportedSha256: SHA,
    digestCrossCheck: "none",
    attestedBy: "ana",
    attestedAt: "2026-06-02T00:00:00Z",
    ...extra,
  };
}

const run = (
  events: ForensicEvent[],
  attestations: StaticReportAttestation[] = [],
  device = "Subject Pixel",
) => mobilePermissionChains({ device, events, attestations });

describe("mobilePermissionChains — the chain and its named cases", () => {
  it("requested + Granted: Yes + a dated AppOps access of the same name → requested-granted-used, each row cited", () => {
    const r = mobsf("com.example.app", { "android.permission.CAMERA": "dangerous" });
    const g = grant("com.example.app", "android.permission.CAMERA", "Yes");
    const a = access("com.example.app", "CAMERA", "2026-06-03 09:00:00");
    const out = run([...r.events, g, a], [attest(r.fingerprint)]);
    expect(out.caveat).toBe(MOBILE_PERMISSION_CHAIN_CAVEAT);
    expect(out.chains).toHaveLength(1);
    const chain = out.chains[0];
    expect(chain.package).toBe("com.example.app");
    expect(chain.reports).toEqual([
      expect.objectContaining({
        fingerprint: r.fingerprint,
        attestedBy: "ana",
        hashAgreement: "no-inventory-hash",
      }),
    ]);
    expect(chain.permissions).toHaveLength(1);
    const p = chain.permissions[0];
    expect(p).toMatchObject({
      name: "CAMERA",
      grantState: "granted",
      case: "requested-granted-used",
    });
    expect(p.requested).toEqual([
      expect.objectContaining({
        asWritten: "android.permission.CAMERA",
        mobsfClassification: "dangerous",
        reportFingerprint: r.fingerprint,
        eventId: r.events[0].id,
      }),
    ]);
    expect(p.granted).toEqual([
      expect.objectContaining({
        artifact: "Permission Grants (Permission Store)",
        column: "Granted",
        value: "Yes",
        eventId: g.id,
        locator: "Permission Grants (Permission Store):row:1",
      }),
    ]);
    expect(p.used).toEqual([
      expect.objectContaining({
        artifact: "App Ops Permissions",
        outcome: "accessed",
        at: "2026-06-03T09:00:00Z",
        eventId: a.id,
      }),
    ]);
    expect(p.used[0]).not.toHaveProperty("proxied");
    expect(chain.packageLevel).toEqual([]);
  });

  it("requested + Granted: No → requested-not-granted; requested alone → requested-only with no-grant-record", () => {
    const r = mobsf("com.a", {
      "android.permission.READ_SMS": "dangerous",
      "android.permission.CAMERA": "dangerous",
    });
    const out = run(
      [...r.events, grant("com.a", "android.permission.READ_SMS", "No")],
      [attest(r.fingerprint)],
    );
    const byName = Object.fromEntries(out.chains[0].permissions.map((p) => [p.name, p]));
    expect(byName.READ_SMS).toMatchObject({ grantState: "not-granted", case: "requested-not-granted" });
    expect(byName.CAMERA).toMatchObject({
      grantState: "no-grant-record",
      case: "requested-only",
      granted: [],
      used: [],
    });
  });

  it("F1 — requested + NO state row + a dated access → requested-used, never requested-granted-used", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run([...r.events, access("com.a", "CAMERA")], [attest(r.fingerprint)]);
    expect(out.chains[0].permissions[0]).toMatchObject({
      grantState: "no-grant-record",
      case: "requested-used",
    });
  });

  it("requested + granted state, nothing dated → requested-granted", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run([...r.events, mode("com.a", "CAMERA", "ALLOWED")], [attest(r.fingerprint)]);
    expect(out.chains[0].permissions[0]).toMatchObject({ grantState: "granted", case: "requested-granted" });
  });

  it("a Reject-dated AppOps row is listed with outcome rejected and never counts as used", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run(
      [...r.events, grant("com.a", "android.permission.CAMERA", "Yes"), reject("com.a", "CAMERA")],
      [attest(r.fingerprint)],
    );
    const p = out.chains[0].permissions[0];
    expect(p.used).toEqual([expect.objectContaining({ outcome: "rejected" })]);
    expect(p.case).toBe("requested-granted");
  });

  it("F11 — a row with both clocks is dated by Access and reads accessed", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const both = access("com.a", "CAMERA", "2026-06-03 09:00:00", {
      "Reject Timestamp": "2026-06-03 09:30:00",
    });
    const out = run([...r.events, both], [attest(r.fingerprint)]);
    expect(out.chains[0].permissions[0].used[0]).toMatchObject({
      outcome: "accessed",
      at: "2026-06-03T09:00:00Z",
    });
  });

  it("a Legacy per-mode clock row is listed as legacy-clock and never counts as used", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const legacy = row("App Ops Permissions - Legacy", {
      "Timestamp TT": T,
      "Package Name": "com.a",
      Permission: "CAMERA",
    });
    const out = run([...r.events, legacy], [attest(r.fingerprint)]);
    const p = out.chains[0].permissions[0];
    expect(p.used).toEqual([
      expect.objectContaining({ outcome: "legacy-clock", artifact: "App Ops Permissions - Legacy" }),
    ]);
    expect(p.case).toBe("requested-only");
  });

  it("F7 — a proxied access is listed with the proxy named and never satisfies the used prong", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const via = access("com.a", "CAMERA", T, { "Proxy Package Name": "com.android.systemui" });
    const out = run(
      [...r.events, grant("com.a", "android.permission.CAMERA", "Yes"), via],
      [attest(r.fingerprint)],
    );
    const p = out.chains[0].permissions[0];
    expect(p.used).toEqual([
      expect.objectContaining({ outcome: "accessed", proxied: "com.android.systemui" }),
    ]);
    expect(p.case).toBe("requested-granted");
    expect(out.chains[0].proxiedRows).toBe(1);
  });

  it("F2 — two vocabularies: an AppOps op that is not the manifest's exact short name stays at package level, with the sentence, and yields no case", () => {
    const r = mobsf("com.a", { "android.permission.ACCESS_COARSE_LOCATION": "dangerous" });
    const out = run(
      [...r.events, access("com.a", "COARSE_LOCATION"), mode("com.a", "COARSE_LOCATION", "ALLOWED")],
      [attest(r.fingerprint)],
    );
    const chain = out.chains[0];
    expect(chain.permissions).toEqual([
      expect.objectContaining({
        name: "ACCESS_COARSE_LOCATION",
        case: "requested-only",
        used: [],
        granted: [],
      }),
    ]);
    expect(chain.packageLevel).toHaveLength(2);
    for (const pl of chain.packageLevel) {
      expect(pl.permissionAsWritten).toBe("COARSE_LOCATION");
      expect(pl.permissionMatch).toBe("different-vocabulary");
      expect(pl.note).toBe(VOCABULARY_SENTENCE);
    }
    expect(out.chains[0].permissions.map((p) => p.case)).not.toContain("used-not-requested");
  });

  it("matching is exact on the normalized short name, case-folded, prefix stripped — never a substring", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run(
      [...r.events, access("com.a", "camera"), access("com.a", "CAMERA_X")],
      [attest(r.fingerprint)],
    );
    expect(out.chains[0].permissions[0].used).toHaveLength(1);
    expect(out.chains[0].packageLevel).toEqual([
      expect.objectContaining({ permissionAsWritten: "CAMERA_X" }),
    ]);
  });

  it("F4 — the state table: FOREGROUND is granted, IGNORED/ERRORED not-granted, DEFAULT/raw int/raw flags unrecognized, every value verbatim", () => {
    const r = mobsf("com.a", {
      "android.permission.A": "normal",
      "android.permission.B": "normal",
      "android.permission.C": "normal",
      "android.permission.D": "normal",
      "android.permission.E": "normal",
      "android.permission.F": "normal",
    });
    const out = run(
      [
        ...r.events,
        mode("com.a", "A", "FOREGROUND"),
        mode("com.a", "B", "IGNORED"),
        mode("com.a", "C", "ERRORED"),
        mode("com.a", "D", "DEFAULT"),
        mode("com.a", "E", "7"),
        grant("com.a", "android.permission.F", "USER_SET|GRANTED_BY_DEFAULT"),
      ],
      [attest(r.fingerprint)],
    );
    const byName = Object.fromEntries(out.chains[0].permissions.map((p) => [p.name, p]));
    expect(byName.A.grantState).toBe("granted");
    expect(byName.B.grantState).toBe("not-granted");
    expect(byName.C.grantState).toBe("not-granted");
    expect(byName.D.grantState).toBe("unrecognized");
    expect(byName.E.grantState).toBe("unrecognized");
    expect(byName.F.grantState).toBe("unrecognized");
    expect(byName.A.granted[0]).toMatchObject({ column: "Mode", value: "FOREGROUND" });
    expect(byName.F.granted[0]).toMatchObject({ column: "Granted", value: "USER_SET|GRANTED_BY_DEFAULT" });
    expect(byName.D.case).toBe("requested-only");
    expect(byName.B.case).toBe("requested-not-granted");
  });

  it("F3 — two state rows that disagree → conflicting, both listed, no case asserted from the state", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run(
      [
        ...r.events,
        grant("com.a", "android.permission.CAMERA", "Yes"),
        mode("com.a", "CAMERA", "IGNORED"),
        access("com.a", "CAMERA"),
      ],
      [attest(r.fingerprint)],
    );
    const p = out.chains[0].permissions[0];
    expect(p.grantState).toBe("conflicting");
    expect(p.granted).toHaveLength(2);
    expect(p.case).toBe("requested-state-conflict");
  });

  it("Usage Stats is corroborating presence on the chain, never a grant or a use", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run([...r.events, usage("com.a"), usage("com.a")], [attest(r.fingerprint)]);
    expect(out.chains[0].usagePresence).toBe(2);
    expect(out.chains[0].permissions[0]).toMatchObject({ case: "requested-only", used: [], granted: [] });
  });

  it("an Op Mode on a Recent Accesses row rides on the used row as the mode in force, never as a state", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run([...r.events, recent("com.a", "CAMERA", "ALLOWED")], [attest(r.fingerprint)]);
    const p = out.chains[0].permissions[0];
    expect(p.used).toEqual([expect.objectContaining({ outcome: "accessed", mode: "ALLOWED" })]);
    expect(p.granted).toEqual([]);
    expect(p.grantState).toBe("no-grant-record");
    expect(p.case).toBe("requested-used");
  });
});

describe("mobilePermissionChains — device binding", () => {
  it("a package name alone never binds: an unattested report with a matching package is an unbound candidate, not a chain", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run([...r.events, access("com.a", "CAMERA")], []);
    expect(out.chains).toHaveLength(1);
    expect(out.chains[0].reports).toEqual([]);
    expect(out.chains[0].permissions).toEqual([]);
    expect(out.chains[0].packageLevel).toHaveLength(1);
    expect(out.unboundCandidates).toEqual([
      expect.objectContaining({
        fingerprint: r.fingerprint,
        package: "com.a",
        reason: expect.stringContaining("not attested"),
      }),
    ]);
  });

  it("an attested report whose package no device row names → boundButAbsent", () => {
    const r = mobsf("com.ghost", { "android.permission.CAMERA": "dangerous" });
    const out = run([...r.events, access("com.a", "CAMERA")], [attest(r.fingerprint)]);
    expect(out.boundButAbsent).toEqual([
      expect.objectContaining({ fingerprint: r.fingerprint, package: "com.ghost" }),
    ]);
    expect(out.chains.map((c) => c.package)).toEqual(["com.a"]);
  });

  it("a revoked attestation, an attestation for another device, and a non-mobsf attestation are all ignored", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const out = run(
      [...r.events, access("com.a", "CAMERA")],
      [
        attest(r.fingerprint, "Subject Pixel", { revokedAt: "2026-06-03T00:00:00Z", revokedBy: "ana" }),
        attest(r.fingerprint, "Other Phone"),
        attest(r.fingerprint, "Subject Pixel", { tool: "capa" }),
      ],
    );
    expect(out.chains[0].reports).toEqual([]);
    expect(out.unboundCandidates).toHaveLength(1);
    expect(out.diagnostics.attestations).toBe(0);
  });

  it("device labels fold through canonicalHostName on both sides, and through the alias index when given", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const rows = [...r.events, access("com.a", "CAMERA", T, {}, "SUBJECT PIXEL")];
    expect(
      run(rows, [attest(r.fingerprint, "subject pixel ")], "Subject Pixel").chains[0].reports,
    ).toHaveLength(1);
    const aliasIndex = buildHostAliasIndex([], { "pixel-7": "subject pixel" });
    const out = mobilePermissionChains({
      device: "pixel-7",
      events: rows,
      attestations: [attest(r.fingerprint)],
      aliasIndex,
    });
    expect(out.device).toBe("subject pixel");
    expect(out.chains[0].reports).toHaveLength(1);
  });

  it("rows of another device, undated-device rows and iOS rows on the same asset are never read", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const other = access("com.a", "CAMERA", T, {}, "Other Phone");
    const noDevice = access("com.a", "CAMERA", T, {}, ""); // "" — an explicit undefined would take the fixture default
    const ios = {
      ...access("com.a", "CAMERA"),
      canonical: {
        ...access("com.a", "CAMERA").canonical!,
        mobile: { ...access("com.a", "CAMERA").canonical!.mobile!, platform: "ios" as const },
      },
    } as ForensicEvent;
    const out = run([...r.events, other, noDevice, ios], [attest(r.fingerprint)]);
    expect(out.boundButAbsent).toHaveLength(1);
    expect(out.chains).toEqual([]);
    expect(out.diagnostics).toMatchObject({ deviceRows: 1, androidRows: 0 });
  });

  it("hash corroboration is sha256-only and never gating: agrees, disagrees, no-inventory-hash", () => {
    const agree = mobsf("com.a", { "android.permission.CAMERA": "dangerous" }, SHA);
    const out1 = run(
      [...agree.events, inventory("com.a", SHA), access("com.a", "CAMERA")],
      [attest(agree.fingerprint)],
    );
    expect(out1.chains[0].reports[0].hashAgreement).toBe("agrees");
    expect(out1.chains[0].inventory).toEqual({ sha256: SHA });

    const out2 = run(
      [...agree.events, inventory("com.a", OTHER_SHA), access("com.a", "CAMERA")],
      [attest(agree.fingerprint)],
    );
    expect(out2.chains[0].reports[0]).toMatchObject({ hashAgreement: "disagrees" });
    expect(out2.chains[0].reports[0].note).toMatch(/differs from the installed build/);
    // Still joined — the analyst attested it; the disagreement is said, not enforced.
    expect(out2.chains[0].permissions[0].case).toBe("requested-used");

    const analystSha = attest(agree.fingerprint, "Subject Pixel", {
      documentSha256: OTHER_SHA,
      digestCrossCheck: "tool-sha256",
    });
    const out3 = run([...agree.events, inventory("com.a", OTHER_SHA)], [analystSha]);
    expect(out3.chains[0].reports[0].hashAgreement).toBe("agrees");
  });

  it("F5 — two active attested reports naming one package: both listed, each requested permission names its report(s)", () => {
    const r1 = mobsf("com.a", { "android.permission.CAMERA": "dangerous" }, SHA);
    const r2 = mobsf(
      "com.a",
      { "android.permission.CAMERA": "dangerous", "android.permission.READ_SMS": "dangerous" },
      OTHER_SHA,
    );
    const out = run(
      [...r1.events, ...r2.events, access("com.a", "CAMERA")],
      [attest(r1.fingerprint), attest(r2.fingerprint)],
    );
    const chain = out.chains[0];
    expect(chain.reports.map((x) => x.fingerprint).sort()).toEqual([r1.fingerprint, r2.fingerprint].sort());
    const byName = Object.fromEntries(chain.permissions.map((p) => [p.name, p]));
    expect(byName.CAMERA.requested.map((x) => x.reportFingerprint).sort()).toEqual(
      [r1.fingerprint, r2.fingerprint].sort(),
    );
    expect(byName.READ_SMS.requested.map((x) => x.reportFingerprint)).toEqual([r2.fingerprint]);
    expect(chain.note).toMatch(/two attested reports/i);
  });
});

describe("mobilePermissionChains — bounds and disclosure", () => {
  it("caps chains, per-permission rows and package-level rows, and says so", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < MAX_CHAINS + 2; i++) events.push(access(`com.p${i}`, "CAMERA"));
    const r = mobsf("com.p0", { "android.permission.CAMERA": "dangerous" });
    for (let i = 0; i < MAX_ROWS_PER_PERMISSION + 3; i++)
      events.push(access("com.p0", "CAMERA", `2026-06-0${(i % 9) + 1} 0${i % 10}:00:00`));
    for (let i = 0; i < MAX_PACKAGE_LEVEL_ROWS + 3; i++) events.push(access("com.p0", `OP_${i}`));
    const out = run([...r.events, ...events], [attest(r.fingerprint)]);
    expect(out.chains).toHaveLength(MAX_CHAINS);
    expect(out.diagnostics.truncated).toEqual(expect.arrayContaining(["chains", "used", "packageLevel"]));
    const p0 = out.chains.find((c) => c.package === "com.p0")!;
    expect(p0.permissions[0].used).toHaveLength(MAX_ROWS_PER_PERMISSION);
    expect(p0.packageLevel).toHaveLength(MAX_PACKAGE_LEVEL_ROWS);
  });

  it("the caveat names the guardrails: not a grant event, not use, not malicious, MobSF's own label, the pre-15 store", () => {
    expect(MOBILE_PERMISSION_CHAIN_CAVEAT).toMatch(/never proof the user consciously granted/);
    expect(MOBILE_PERMISSION_CHAIN_CAVEAT).toMatch(/state at collection time/);
    expect(MOBILE_PERMISSION_CHAIN_CAVEAT).toMatch(/never .*malicious/);
    expect(MOBILE_PERMISSION_CHAIN_CAVEAT).toMatch(/MobSF's own/);
    expect(MOBILE_PERMISSION_CHAIN_CAVEAT).toMatch(/runtime-permissions\.xml/);
    expect(MOBILE_PERMISSION_CHAIN_CAVEAT).not.toMatch(/surveillance|spyware|stalkerware/i);
  });

  it("is pure: input events and attestations are not mutated", () => {
    const r = mobsf("com.a", { "android.permission.CAMERA": "dangerous" });
    const events = [...r.events, access("com.a", "CAMERA")];
    const atts = [attest(r.fingerprint)];
    const before = JSON.stringify({ events, atts });
    run(events, atts);
    expect(JSON.stringify({ events, atts })).toBe(before);
  });
});
