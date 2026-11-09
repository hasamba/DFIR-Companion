import { mkdir, mkdtemp, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { bundledSigmaDir, loadSigmaBundle, loadSigmaRuleDir } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader, sigmaProvenanceToken } from "../../src/analysis/sigmaImportGrade.js";
import { buildSigmaRuleSet, matchSigmaRecord, type SigmaRuleSet } from "../../src/analysis/sigmaRuleSet.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { bundledSuzakuDir, loadSuzakuRules, SUZAKU_ORIGIN_KEY } from "../../src/analysis/sigmaSuzakuRules.js";
import { createZip } from "../../src/analysis/zipArchive.js";
import { sigmaGradingsInCase } from "../../src/reports/detectionRules.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The Suzaku project's own CloudTrail rules bundled beside the SigmaHQ release (#2499). Records are
// synthetic and shaped like the CloudTrail exports the importer already accepts.

const SIGMA_DIR = bundledSigmaDir() as string;
const SUZAKU_DIR = bundledSuzakuDir() as string;

const trail = (records: object[]) => JSON.stringify({ Records: records });
const ct = (o: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: {
    type: "IAMUser",
    userName: "alice",
    accountId: "111111111111",
    arn: "arn:aws:iam::111111111111:user/alice",
  },
  recipientAccountId: "111111111111",
  readOnly: false,
  ...o,
});
const secretRead = (extra: Record<string, unknown> = {}) =>
  ct({ eventSource: "secretsmanager.amazonaws.com", eventName: "GetSecretValue", ...extra });

async function store(env: NodeJS.ProcessEnv = {}): Promise<SigmaRuleStore> {
  const root = await mkdtemp(join(tmpdir(), "dfir-sigma-suzaku-"));
  const s = new SigmaRuleStore(root, SIGMA_DIR, env, SUZAKU_DIR);
  await s.init();
  return s;
}

const titles = (set: SigmaRuleSet, rec: Record<string, unknown>): string[] =>
  matchSigmaRecord(set, "aws-cloudtrail", rec).matches.map((m) => m.ref.title);

describe("the bundled Suzaku folder", () => {
  it("reads every rule file with its upstream path and the Suzaku origin", () => {
    const load = loadSuzakuRules(SUZAKU_DIR, 10_000, {});
    expect(load.problems).toEqual([]);
    expect(load.files).toHaveLength(741);
    expect(
      load.files.every((f) => f.path.startsWith("suzaku/aws/cloudtrail/") && f.origin === SUZAKU_ORIGIN_KEY),
    ).toBe(true);
    expect(load.origin).toMatchObject({
      name: "Suzaku",
      release: "suzaku-2026-11-01",
      commit: "56c5275e99fce54b40c75e586d670ce771fe0fd8",
      statuses: ["stable", "test", "experimental"],
      minLevel: "critical",
    });
  });

  it("is switched off by DFIR_SIGMA_SUZAKU_RULES=off and reports a missing folder", () => {
    expect(loadSuzakuRules(SUZAKU_DIR, 10_000, { DFIR_SIGMA_SUZAKU_RULES: "off" })).toEqual({
      files: [],
      problems: [],
    });
    expect(loadSuzakuRules(undefined, 10_000, {}).problems[0]).toMatch(/no bundled Suzaku rules folder/);
  });
});

describe("source isolation", () => {
  // Windows needs a privilege to create a symlink; the Linux run covers this path.
  it.skipIf(process.platform === "win32")(
    "still loads the Suzaku rules when the SigmaHQ folder cannot be read",
    async () => {
      const broken = await mkdtemp(join(tmpdir(), "dfir-sigma-broken-"));
      await mkdir(join(broken, "rules"));
      // A dangling link: the folder walk's stat throws, as an unreadable file would.
      await symlink(join(broken, "missing.yml"), join(broken, "rules", "x.yml"));
      const { set, problem } = loadSigmaBundle(broken, SUZAKU_DIR);
      expect(problem).toMatch(/the bundled Sigma rules could not be read/);
      expect(set.inventory.filter((e) => e.origin === "Suzaku" && e.outcome === "loaded")).toHaveLength(736);
    },
  );

  it("still loads the Suzaku rules when there is no SigmaHQ folder", () => {
    const { set, problem } = loadSigmaBundle(undefined, SUZAKU_DIR);
    expect(problem).toMatch(/no bundled Sigma rules folder/);
    expect(set.origins[0]?.name).toBe("Suzaku");
  });
});

describe("a Suzaku rule in the rule set", () => {
  const RULE = `title: Synthetic Suzaku\nid: 99999999-0000-0000-0000-000000000001\nstatus: experimental\nauthor: Example Author\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: SyntheticCall\n  condition: sel\nlevel: high\n`;
  const origin = {
    name: "Suzaku",
    release: "suzaku-x",
    commit: "abc1234",
    urlBase: "https://github.com/Yamato-Security/suzaku-rules/blob",
    statuses: ["experimental"],
    minLevel: "critical" as const,
  };
  const build = (statuses: string[]) =>
    buildSigmaRuleSet(
      [{ path: "suzaku/aws/cloudtrail/x.yml", text: RULE, origin: "suzaku" }],
      { release: "r-hq", commit: "def5678" },
      { statuses: ["stable"], origins: new Map([["suzaku", { ...origin, statuses }]]) },
    );

  it("links the Suzaku repo, names its release and carries its own floor", () => {
    const set = build(["experimental"]);
    const [m] = matchSigmaRecord(set, "aws-cloudtrail", { eventName: "SyntheticCall" }).matches;
    expect(m.ref).toMatchObject({
      origin: "Suzaku",
      release: "suzaku-x",
      gradeFloor: "critical",
      url: "https://github.com/Yamato-Security/suzaku-rules/blob/abc1234/suzaku/aws/cloudtrail/x.yml",
    });
    expect(set.inventory[0]).toMatchObject({ origin: "Suzaku", outcome: "loaded" });
    expect(set.origins).toEqual([
      {
        name: "Suzaku",
        release: "suzaku-x",
        commit: "abc1234",
        statuses: ["experimental"],
        minLevel: "critical",
      },
    ]);
  });

  it("filters by the Suzaku statuses, not the SigmaHQ ones", () => {
    expect(build(["stable"]).inventory[0].outcome).toBe("status");
  });

  it("refuses a file whose source is unknown", () => {
    const set = buildSigmaRuleSet([{ path: "x.yml", text: RULE, origin: "nope" }], {
      release: "r",
      commit: "c",
    });
    expect(set.inventory[0]).toMatchObject({ outcome: "refused", reasons: ["unknown rule source nope"] });
  });
});

describe("Suzaku rules grading CloudTrail (defaults)", () => {
  const set = loadSigmaRuleDir(SIGMA_DIR, {}, SUZAKU_DIR);
  const sigma = createSigmaImportGrader(set).snapshot();

  it("splits a successful call from a failed attempt with `exists`", () => {
    expect(titles(set, secretRead())).toContain("AWS SecretsManager GetSecretValue");
    expect(titles(set, secretRead())).not.toContain("AWS SecretsManager GetSecretValue Attempt");
    expect(titles(set, secretRead({ errorCode: "AccessDenied" }))).toContain(
      "AWS SecretsManager GetSecretValue Attempt",
    );
    expect(titles(set, secretRead({ errorMessage: "denied" }))).toContain(
      "AWS SecretsManager GetSecretValue Attempt",
    );
    // A flattened export writes an empty errorCode column on every row: still a success.
    expect(titles(set, secretRead({ errorCode: "", errorMessage: "" }))).toContain(
      "AWS SecretsManager GetSecretValue",
    );
  });

  it("labels with a High Suzaku rule but does not raise severity below the Suzaku floor", () => {
    const without = parseCloudTrail(trail([secretRead()])).events[0];
    const e = parseCloudTrail(trail([secretRead()]), { sigma }).events[0];
    expect(e.severity).toBe(without.severity);
    expect(e.message).toContain(
      "Suzaku suzaku-2026-11-01, https://github.com/Yamato-Security/suzaku-rules/blob/56c5275e99fce54b40c75e586d670ce771fe0fd8/suzaku/aws/cloudtrail/aws_cloudtrail_get_secret_value.yml",
    );
    expect(e.message).toMatch(/Suzaku rules below the "critical" level label events/);
  });

  it("raises severity with a Critical Suzaku rule", () => {
    const rec = ct({
      eventSource: "iam.amazonaws.com",
      eventName: "AttachUserPolicy",
      requestParameters: { userName: "bob", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" },
    });
    expect(parseCloudTrail(trail([rec]), { sigma }).events[0].severity).toBe("Critical");
  });

  it("keeps a not-found StopLogging at the importer's Low even with Suzaku's rules at medium (#2351)", async () => {
    const s = await store({ DFIR_SIGMA_MIN_LEVEL: "medium", DFIR_SIGMA_SUZAKU_MIN_LEVEL: "medium" });
    const medium = createSigmaImportGrader(() => s.activeRuleSet(), { minLevel: () => "medium" }).snapshot();
    const rec = ct({
      eventSource: "cloudtrail.amazonaws.com",
      eventName: "StopLogging",
      requestParameters: { name: "missing-trail" },
      errorCode: "TrailNotFoundException",
    });
    const e = parseCloudTrail(trail([rec]), { sigma: medium }).events[0];
    expect(e.message).toMatch(/^Sigma rule: CloudTrail Logging Stopped \[/m);
    expect(e.severity).toBe("Low");
  });

  it("names Suzaku in the provenance token, and the report reads it back", () => {
    const token = sigma!.token;
    expect(token).toMatch(/:suzaku=suzaku-2026-11-01=stable\+test\+experimental=critical$/);
    const ev = { canonical: { producer: { ruleVersions: [token] } } } as unknown as ForensicEvent;
    expect(sigmaGradingsInCase([ev])[0].origins).toEqual([
      {
        name: "Suzaku",
        release: "suzaku-2026-11-01",
        statuses: ["stable", "test", "experimental"],
        minLevel: "critical",
      },
    ]);
  });

  it("still reads a token written before #2499", () => {
    const old = "sigma:r2026-07-01:0123456789ab:stable+test:high:none:none";
    const ev = { canonical: { producer: { ruleVersions: [old] } } } as unknown as ForensicEvent;
    const [g] = sigmaGradingsInCase([ev]);
    expect(g).toMatchObject({ release: "r2026-07-01", statuses: ["stable", "test"] });
    expect(g.origins).toBeUndefined();
  });
});

describe("the rule store with Suzaku", () => {
  const suzakuLoaded = (set: SigmaRuleSet) =>
    set.inventory.filter((e) => e.origin === "Suzaku" && e.outcome === "loaded").length;

  it("loads Suzaku by default and drops it when switched off", async () => {
    expect(suzakuLoaded((await store()).activeRuleSet())).toBe(736);
    const off = (await store({ DFIR_SIGMA_SUZAKU_RULES: "off" })).activeRuleSet();
    expect(suzakuLoaded(off)).toBe(0);
    expect(off.origins).toEqual([]);
  });

  it("applies the Suzaku statuses and floor, and they change the provenance token", async () => {
    const def = (await store()).activeRuleSet();
    const strict = (
      await store({ DFIR_SIGMA_SUZAKU_STATUSES: "stable,test", DFIR_SIGMA_SUZAKU_MIN_LEVEL: "high" })
    ).activeRuleSet();
    expect(suzakuLoaded(strict)).toBeLessThan(suzakuLoaded(def));
    expect(strict.origins[0]).toMatchObject({ statuses: ["stable", "test"], minLevel: "high" });
    expect(sigmaProvenanceToken(strict, "high")).not.toBe(sigmaProvenanceToken(def, "high"));
  });

  it("judges a SigmaHQ release on its own rules: Suzaku never makes an unusable release installable", async () => {
    const s = await store();
    const win = `title: W\nid: w1\nstatus: test\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4624\n  condition: sel\nlevel: high\n`;
    const zip = createZip([{ path: "rules/windows/w.yml", data: Buffer.from(win) }]);
    const p = await s.preview(zip, { source: "file", verified: false, fileName: "w.zip" });
    expect(p.usable).toBe(false);
    expect(p.loads["aws-cloudtrail"] ?? 0).toBe(0);
    await expect(s.install(p.token)).rejects.toThrow(/no rule in this release loads/);
  });

  it("reports a missing Suzaku folder while the setting is on, and keeps SigmaHQ grading", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-sigma-suzaku-"));
    const s = new SigmaRuleStore(root, SIGMA_DIR, {}, null);
    const set = s.activeRuleSet();
    expect(set.problems).toContain("no bundled Suzaku rules folder (data/sigma-suzaku/rules) was found");
    expect(set.inventory.some((e) => !e.origin && e.outcome === "loaded")).toBe(true);
    const off = new SigmaRuleStore(root, SIGMA_DIR, { DFIR_SIGMA_SUZAKU_RULES: "off" }, null).activeRuleSet();
    expect(off.problems).toEqual([]);
  });

  it("re-grade lookups see Suzaku rules even when switched off", async () => {
    const s = await store({ DFIR_SIGMA_SUZAKU_RULES: "off" });
    expect(s.lookupRuleSet().inventory.some((e) => e.origin === "Suzaku" && e.outcome === "loaded")).toBe(
      true,
    );
  });
});
