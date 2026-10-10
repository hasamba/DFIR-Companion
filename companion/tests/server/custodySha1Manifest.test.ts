import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore, hashHandleBoth, type CustodyRecord } from "../../src/analysis/custody.js";
import {
  assembleCustodyManifest,
  verifyCustodyManifest,
  type CustodyManifest,
} from "../../src/analysis/custodyManifest.js";
import { redactCustodyRecords } from "../../src/analysis/redactedExport.js";
import { chainOfCustodySection } from "../../src/reports/custodySection.js";
import { createApp } from "../../src/server.js";
import { dashboardClientSource } from "../helpers/dashboardModule.js";
import { open } from "node:fs/promises";

const sha = (algo: "sha256" | "sha1", s: string | Buffer): string => createHash(algo).update(s).digest("hex");
const SECRET = Buffer.from("frozen-test-secret-0123456789abcdef", "utf8");

// A v1 manifest produced by the code BEFORE #2111 (generated on 81c28fed, signed with SECRET), kept
// verbatim so "v1 manifests still verify" is checked against bytes the new code never produced.
const FROZEN_V1: CustodyManifest = JSON.parse(
  '{"version":1,"caseId":"c1","generatedAt":"2026-10-10T13:39:09.493Z","generatedBy":"0.43.0","chain":{"records":1,"headSeq":1,"headHash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","breaks":[]},"artifacts":[{"path":"imports/a.csv","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","chain":[{"artifactPath":"imports/a.csv","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","collectedBy":"companion","collectedAt":"2026-01-01T00:00:00.000Z","source":"","trigger":"import","caseId":"c1","event":"collected","seq":1,"prevHash":""}]}],"signature":{"algorithm":"HMAC-SHA256","value":"d2d0ceb96a89169e0f05e733c9d70158bf326a1d69bae2df88841ccb5b169ec7"}}',
);

function rec(over: Partial<CustodyRecord> = {}): CustodyRecord {
  return {
    artifactPath: "/cases/INC-1/imports/0001_evidence.csv",
    sha256: "a".repeat(64),
    collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z",
    source: "WORKSTATION-7",
    trigger: "import",
    caseId: "INC-1",
    event: "collected",
    seq: 1,
    prevHash: "",
    ...over,
  };
}

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-sha1-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { cases, custody: new CustodyStore(cases), root };
}

describe("SHA-1 alongside SHA-256 (#2111)", () => {
  it("hashHandleBoth returns both digests in one pass", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-sha1-h-"));
    const p = join(dir, "f.bin");
    await writeFile(p, "hello custody");
    const h = await open(p, "r");
    try {
      expect(await hashHandleBoth(h)).toEqual({
        sha256: sha("sha256", "hello custody"),
        sha1: sha("sha1", "hello custody"),
      });
    } finally {
      await h.close();
    }
  });

  it("a stored import carries sha1 on its collected record", async () => {
    const { cases, custody } = await makeStore();
    custodyHook(cases, custody);
    const text = "ts,message\n2026-01-01T00:00:00Z,hi\n";
    await cases.saveImport("c1", "0001_e.csv", text);
    const [r] = await custody.load("c1");
    expect(r.sha1).toBe(sha("sha1", text));
    expect(r.sha256).toBe(sha("sha256", text));
  });

  it("POST /custody records sha1 of the named file", async () => {
    const { cases, custody } = await makeStore();
    const app = createApp(cases, { custodyStore: custody });
    const file = join(cases.importsDir("c1"), "x.bin");
    await import("node:fs/promises").then((fs) => fs.mkdir(cases.importsDir("c1"), { recursive: true }));
    await writeFile(file, "abc");
    const res = await request(app).post("/cases/c1/custody").send({ artifactPath: file });
    expect(res.status).toBe(201);
    const [r] = await custody.load("c1");
    expect(r.sha1).toBe(sha("sha1", "abc"));
  });

  it("verify: a legacy record without sha1 still verifies; a sha1 mismatch with equal sha256 is flagged", async () => {
    const { cases, custody } = await makeStore();
    const file = join(cases.importsDir("c1"), "y.bin");
    await import("node:fs/promises").then((fs) => fs.mkdir(cases.importsDir("c1"), { recursive: true }));
    await writeFile(file, "abc");
    const base = {
      artifactPath: file,
      collectedBy: "a",
      collectedAt: "2026-01-01T00:00:00.000Z",
      source: "",
      trigger: "t",
      caseId: "c1",
    };
    await custody.record("c1", { ...base, sha256: sha("sha256", "abc") });
    expect(await custody.verifyIntegrity("c1")).toEqual([]);
    await custody.record("c1", { ...base, sha256: sha("sha256", "abc"), sha1: "0".repeat(40) });
    const bad = await custody.verifyIntegrity("c1");
    expect(bad).toHaveLength(1);
    expect(bad[0]).toMatchObject({
      reason: "hash-mismatch",
      recordedSha1: "0".repeat(40),
      actualSha1: sha("sha1", "abc"),
    });
  });
});

function custodyHook(cases: CaseStore, custody: CustodyStore): void {
  cases.onArtifactStored(async (a) => {
    await custody.record(a.caseId, {
      artifactPath: a.path,
      sha256: a.sha256,
      sha1: a.sha1,
      collectedBy: "companion",
      collectedAt: new Date().toISOString(),
      source: "",
      trigger: a.kind,
      caseId: a.caseId,
    });
  });
}

describe("manifest version 2 (#2111)", () => {
  const head = { records: 1, headSeq: 1, headHash: "c".repeat(64) };

  it("new manifests are version 2, carry sha1, and verify", () => {
    const m = assembleCustodyManifest({
      caseId: "INC-1",
      records: [rec({ sha1: "1".repeat(40) })],
      head,
      breaks: [],
      secret: SECRET,
    });
    expect(m.version).toBe(2);
    expect(m.artifacts[0].sha1).toBe("1".repeat(40));
    expect(verifyCustodyManifest(m, SECRET)).toBe(true);
  });

  it("a frozen v1 manifest still verifies unchanged", () => {
    expect(FROZEN_V1.version).toBe(1);
    expect(verifyCustodyManifest(FROZEN_V1, SECRET)).toBe(true);
  });

  it("tampering with sha1 breaks the signature; version 3 is unverifiable", () => {
    const m = assembleCustodyManifest({
      caseId: "INC-1",
      records: [rec({ sha1: "1".repeat(40) })],
      head,
      breaks: [],
      secret: SECRET,
    });
    const tampered = { ...m, artifacts: [{ ...m.artifacts[0], sha1: "2".repeat(40) }] };
    expect(verifyCustodyManifest(tampered, SECRET)).toBe(false);
    const v3 = { ...m, version: 3 } as unknown as CustodyManifest;
    expect(verifyCustodyManifest(v3, SECRET)).toBe(false);
  });

  it("a receipt-only artifact is published as-is and marked not stored", () => {
    const m = assembleCustodyManifest({
      caseId: "INC-1",
      records: [rec({ artifactPath: "received:import-thor/t.json", event: "received" })],
      head,
      breaks: [],
      caseDir: "/cases/INC-1",
      secret: SECRET,
    });
    expect(m.artifacts[0].path).toBe("received:import-thor/t.json");
    expect(m.artifacts[0].stored).toBe(false);
  });
});

describe("redaction, report appendix and dashboard (#2111)", () => {
  it("redacted export keeps sha1 but still tokenizes artifactPath and source", () => {
    const [out] = redactCustodyRecords([rec({ sha1: "1".repeat(40), bytes: 1234 })], () => "TOKEN");
    expect(out.sha1).toBe("1".repeat(40));
    expect(out.artifactPath).toBe("TOKEN");
    expect(out.source).toBe("TOKEN");
  });

  it("report appendix prints a SHA-1 line only when present", () => {
    const withSha1: string[] = [];
    chainOfCustodySection([rec({ sha1: "1".repeat(40) })], withSha1);
    expect(withSha1.join("\n")).toMatch(/- SHA-1: ` ?1{40} ?`/);
    const without: string[] = [];
    chainOfCustodySection([rec()], without);
    expect(without.join("\n")).not.toContain("SHA-1");
  });

  it("report appendix labels a receipt-only artifact as received, not stored", () => {
    const lines: string[] = [];
    chainOfCustodySection([rec({ artifactPath: "received:import-thor/t.json", event: "received" })], lines);
    expect(lines.join("\n")).toContain("received — not stored");
  });

  it("dashboard custody panel shows SHA-1 and a received-not-stored badge", () => {
    const src = dashboardClientSource();
    const panel = src.slice(src.indexOf("function renderCustody()"), src.indexOf("function loadCustody("));
    expect(panel).toContain("sha1");
    expect(panel).toContain("received — not stored");
    expect(panel).toContain("escAttr(last.sha1)");
    expect(panel).toContain("esc(last.sha1)");
  });
});
