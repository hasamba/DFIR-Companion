import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseCombinedLog } from "../../src/analysis/combinedLogImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader, type SigmaGradingSnapshot } from "../../src/analysis/sigmaImportGrade.js";
import {
  finalizeRegradedRow,
  planSigmaRegrade,
  regradeMergeRow,
  sigmaTokensOf,
  splitSigmaOverlay,
  type StoredRow,
} from "../../src/analysis/sigmaRegrade.js";
import {
  reparseForRegrade,
  sigmaRuleMitreIndex,
  storedFileChanged,
} from "../../src/analysis/sigmaRegradeSources.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Re-grade an imported case with the current Sigma rules (#2206): the pure diff. Records are
// synthetic CloudTrail, parsed by the real importer under the bundled SigmaHQ rules.

const FILE = "0001_cloudtrail.json";
const { set: setOn } = loadBundledSigmaRuleSet();
const snapOn = createSigmaImportGrader(setOn).snapshot()!;

const ct = (i: number, o: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: `2026-03-01T10:00:0${i}Z`,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: {
    type: "IAMUser",
    userName: "alice",
    accountId: "111122223333",
    arn: "arn:aws:iam::111122223333:user/alice",
  },
  recipientAccountId: "111122223333",
  readOnly: false,
  eventID: `id-${i}`,
  ...o,
});

const TEXT = JSON.stringify({
  Records: [
    ct(1, { eventSource: "securityhub.amazonaws.com", eventName: "BatchUpdateFindings" }),
    ct(2, { eventSource: "s3.amazonaws.com", eventName: "ListBuckets", readOnly: true }),
  ],
});

/** The rule that grades BatchUpdateFindings, and a rule set with it switched off. */
const graded = parseCloudTrail(TEXT, { sigma: snapOn }).events.find((e) => /^Sigma: /.test(e.description))!;
const RULE_ID = splitSigmaOverlay(graded.description, graded.message).ruleIds[0];
const { set: setOff } = loadBundledSigmaRuleSet({ disabled: new Map([[RULE_ID, "noisy here"]]) });
const snapOff = createSigmaImportGrader(setOff).snapshot()!;
const ruleMitre = sigmaRuleMitreIndex(setOn);

/** The rows an import would have stored, as forensic copies (or super copies). */
function stored(
  snapshot: SigmaGradingSnapshot | undefined,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent[] {
  return parseCloudTrail(TEXT, { sigma: snapshot }).events.map((e, i) => ({
    ...(e as SiemEvent),
    id: `a1e${i + 1}`,
    relatedFindingIds: [],
    sourceScreenshots: [FILE],
    ...extra,
  }));
}

function plan(
  rows: ForensicEvent[],
  snapshot: SigmaGradingSnapshot,
  copy: "forensic" | "super" = "forensic",
) {
  const map = new Map<string, StoredRow>(rows.map((e) => [e.id, { [copy]: e }]));
  return planSigmaRegrade({
    files: [
      {
        file: FILE,
        importer: "aws-cloudtrail",
        rows: map,
        reparsed: reparseForRegrade("aws-cloudtrail", TEXT, snapshot),
      },
    ],
    token: snapshot.token,
    gate: "Low",
    ruleMitre,
  });
}

const sigmaRow = (rows: ForensicEvent[]) => rows.find((e) => /BatchUpdateFindings/.test(e.description))!;

describe("planSigmaRegrade (#2206)", () => {
  it("moves nothing when the rules are unchanged", () => {
    const p = plan(stored(snapOn), snapOn);
    expect(p.rows.length).toBe(2);
    expect(p.rows.every((r) => r.kind === "unchanged")).toBe(true);
    expect(p.counts).toMatchObject({ raised: 0, lowered: 0, unchanged: 2, changed: 0, tokenOnly: 0 });
    expect(p.files).toEqual([{ file: FILE, importer: "aws-cloudtrail", rows: 2, status: "current" }]);
  });

  it("lowers a row whose rule is switched off, and strips the old Sigma head, lines, ATT&CK and token", () => {
    const before = sigmaRow(stored(snapOn));
    const base = parseCloudTrail(TEXT).events.find((e) => /BatchUpdateFindings/.test(e.description))!;
    const p = plan(stored(snapOn), snapOff);
    const r = p.rows.find((x) => x.id === before.id)!;
    expect(r.kind).toBe("changed");
    expect(r.before).toBe("High");
    expect(r.after).toBe(base.severity);
    expect(p.counts.lowered).toBe(1);
    const after = r.forensic!.after;
    expect(after.description).toBe(base.description);
    expect(after.message ?? "").not.toMatch(/Sigma rule: /);
    expect(after.mitreTechniques).toEqual(base.mitreTechniques);
    expect(sigmaTokensOf(after)).toEqual([snapOff.token]);
    expect(after.canonical?.producer.ruleVersions).toContain("cloudtrail-action-severity-v1");
    expect(r.leavesForensic).toBe(base.severity === "Info");
  });

  it("raises a row a rule matches now; a super-only row joins the forensic timeline without promotedAt", () => {
    const p = plan(stored(snapOff), snapOn, "super");
    const r = p.rows.find((x) => /BatchUpdateFindings/.test(x.super!.before.description))!;
    expect(r.after).toBe("High");
    expect(p.counts.raised).toBe(1);
    expect(r.entersForensic).toBe(true);
    expect(r.super!.after.description).toMatch(/^Sigma: /);
    expect(r.super!.after.promotedAt).toBeUndefined();
    expect(regradeMergeRow(r).promotedAt).toBeUndefined();
  });

  it("keeps an analyst-promoted row in the forensic timeline, with its promotedAt, at the new grade", () => {
    const p = plan(stored(snapOn, { promotedAt: "2026-03-02T00:00:00Z" }), snapOff);
    const r = p.rows.find((x) => /BatchUpdateFindings/.test(x.forensic!.before.description))!;
    expect(r.kind).toBe("changed");
    expect(r.leavesForensic).toBe(false);
    expect(r.forensic!.after.promotedAt).toBe("2026-03-02T00:00:00Z");
  });

  it("keeps the content tagger's grade when it is above the new one", () => {
    const rows = stored(snapOn).map((e) =>
      /BatchUpdateFindings/.test(e.description)
        ? { ...e, severity: "Critical" as const, taggerRaisedFrom: "High" as const }
        : e,
    );
    const r = plan(rows, snapOff).rows.find((x) =>
      /BatchUpdateFindings/.test(x.forensic!.before.description),
    )!;
    expect(r.after).toBe("Critical");
  });

  it("changes only the token when only the token differs", () => {
    const snapNew = { ...snapOn, token: `${snapOn.token}x` };
    const p = plan(stored(snapOn), snapNew);
    expect(p.rows.every((r) => r.kind === "token-only")).toBe(true);
    expect(p.counts).toMatchObject({ raised: 0, lowered: 0, changed: 0, tokenOnly: 2 });
    const r = p.rows[0];
    expect(r.forensic!.after.description).toBe(r.forensic!.before.description);
    expect(sigmaTokensOf(r.forensic!.after)).toEqual([snapNew.token]);
    expect(p.files[0].status).toBe("other");
  });

  it("flags an import never graded by Sigma", () => {
    expect(plan(stored(undefined), snapOn).files[0].status).toBe("never");
  });

  it("reports a skipped file and never re-grades its rows", () => {
    const map = new Map<string, StoredRow>(stored(snapOn).map((e) => [e.id, { forensic: e }]));
    const p = planSigmaRegrade({
      files: [{ file: FILE, importer: "aws-cloudtrail", rows: map, reparsed: { skipped: "file-changed" } }],
      token: snapOff.token,
      gate: "Low",
      ruleMitre,
    });
    expect(p.rows).toEqual([]);
    expect(p.counts.unmatched).toBe(2);
    expect(p.files[0]).toMatchObject({ status: "skipped", reason: "file-changed" });
  });

  it("does not pair a row whose text differs from its record", () => {
    const rows = stored(snapOn).map((e) => ({
      ...e,
      description: "something else entirely, not this record at all",
    }));
    const p = plan(rows, snapOff);
    expect(p.rows).toEqual([]);
    expect(p.unmatched.every((u) => u.reason === "text-differs")).toBe(true);
  });
});

describe("storedFileChanged (#2206)", () => {
  it("is true when the stored file is not the text the row was parsed from", () => {
    const e = stored(snapOn)[0];
    expect(storedFileChanged(e, TEXT)).toBe(false);
    expect(storedFileChanged(e, `${TEXT} `)).toBe(true);
  });
});

describe("finalizeRegradedRow (#2206)", () => {
  it("replaces the merged token and techniques, keeps promotedAt, and is idempotent", () => {
    const r = plan(stored(snapOn, { promotedAt: "2026-03-02T00:00:00Z" }), snapOff).rows.find(
      (x) => x.kind === "changed",
    )!;
    const merged: ForensicEvent = {
      ...r.forensic!.before,
      canonical: {
        ...r.forensic!.before.canonical!,
        producer: {
          ...r.forensic!.before.canonical!.producer,
          ruleVersions: [...(r.forensic!.before.canonical!.producer.ruleVersions ?? []), snapOff.token],
        },
      },
    };
    const out = finalizeRegradedRow(merged, r.forensic!.after);
    expect(sigmaTokensOf(out)).toEqual([snapOff.token]);
    expect(out.mitreTechniques).toEqual(r.forensic!.after.mitreTechniques);
    expect(out.promotedAt).toBe("2026-03-02T00:00:00Z");
    expect(finalizeRegradedRow(out, r.forensic!.after)).toBe(out);
  });

  it("gives a lifted row its original import time and never a promotedAt", () => {
    const e = { ...stored(snapOn)[0] };
    delete e.importedAt;
    const out = finalizeRegradedRow(e, e, { importedAt: "2026-03-01T11:00:00Z", importBatchId: "a1" });
    expect(out.importedAt).toBe("2026-03-01T11:00:00Z");
    expect(out.promotedAt).toBeUndefined();
  });
});

describe("pairing holds for every Sigma-graded importer (#2206)", () => {
  const entra = JSON.stringify({
    value: [
      {
        id: "s-1",
        createdDateTime: "2026-03-01T10:00:00Z",
        userPrincipalName: "alice@example.test",
        appDisplayName: "Azure Portal",
        ipAddress: "198.51.100.7",
        clientAppUsed: "Browser",
        userAgent: "azurehound/v2.1.0",
        status: { errorCode: 0 },
      },
      {
        id: "a-1",
        activityDateTime: "2026-03-01T10:00:00Z",
        activityDisplayName: "Set device registration policies",
        category: "Policy",
        result: "success",
        loggedByService: "Core Directory",
        initiatedBy: { user: { userPrincipalName: "alice@example.test" } },
        targetResources: [{ id: "t1", displayName: "Device Registration Policy", type: "Policy" }],
      },
    ],
  });
  const web = [
    '203.0.113.5 - - [14/May/2024:19:00:00 +0000] "GET /console/css/%2e%2e%2fconsole.portal HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    '203.0.113.5 - - [14/May/2024:19:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
  ].join("\n");
  const sources = [
    {
      importer: "m365",
      text: entra,
      parse: (s?: SigmaGradingSnapshot) => parseM365Audit(entra, { sigma: s }).events,
    },
    {
      importer: "combined-log",
      text: web,
      parse: (s?: SigmaGradingSnapshot) => parseCombinedLog(web, { sigma: s }).events,
    },
  ];

  function planFor(importer: string, text: string, rows: SiemEvent[]) {
    const map = new Map<string, StoredRow>(
      rows.map((e, i) => [
        `x${i + 1}`,
        { forensic: { ...e, id: `x${i + 1}`, relatedFindingIds: [], sourceScreenshots: [FILE] } },
      ]),
    );
    return planSigmaRegrade({
      files: [{ file: FILE, importer, rows: map, reparsed: reparseForRegrade(importer, text, snapOn) }],
      token: snapOn.token,
      gate: "Low",
      ruleMitre,
    });
  }

  for (const c of sources) {
    it(`${c.importer}: pairs every stored row with its record and moves nothing under the same rules`, () => {
      const p = planFor(c.importer, c.text, c.parse(snapOn));
      expect(p.rows.length).toBeGreaterThan(0);
      expect(p.counts.unmatched).toBe(0);
      expect(p.rows.every((r) => r.kind === "unchanged")).toBe(true);
      expect(p.files[0].status).toBe("current");
    });

    it(`${c.importer}: raises the rows a rule grades now, on an import never graded by Sigma`, () => {
      const p = planFor(c.importer, c.text, c.parse(undefined));
      expect(p.files[0].status).toBe("never");
      expect(p.counts.unmatched).toBe(0);
      expect(p.counts.raised).toBeGreaterThan(0);
      const high = p.rows.filter((r) => r.after === "High");
      expect(high.every((r) => /^Sigma: /.test(r.forensic!.after.description))).toBe(true);
    });
  }
});
