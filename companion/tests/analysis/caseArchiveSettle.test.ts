import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { archiveCase } from "../../src/analysis/caseArchive.js";
import { exportEncryptedCase } from "../../src/analysis/caseExportArchive.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { decryptBuffer } from "../../src/analysis/caseEncryption.js";

// #2784: an auto-enrichment run after an IOC add records its analysis run while the case is being
// archived. The record puts down state/analysis-runs/pending.json and removes it a moment later, so
// the walk listed a file the read no longer found, and archive / ZIP delete / encrypted delete /
// encrypted export failed with a raw "ENOENT ... lstat" 500. The archive is now built again from a
// fresh walk — never by quietly dropping the file — and still fails with a named message when the
// folder never holds still.

// A one-shot hook run once the encrypted export has made its staging folder — after the walk, before
// the snapshot and the reads — so a test can change the case in exactly that gap.
const hooks = vi.hoisted(() => ({ afterStaging: null as null | (() => Promise<unknown>) }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    mkdtemp: (async (...args: Parameters<typeof actual.mkdtemp>) => {
      const out = await actual.mkdtemp(...args);
      const hook = hooks.afterStaging;
      hooks.afterStaging = null;
      if (hook) await hook();
      return out;
    }) as typeof actual.mkdtemp,
  };
});

afterEach(() => {
  hooks.afterStaging = null;
});

const PASSWORD = "correct horse battery staple";
const PENDING = "state/analysis-runs/pending.json";
const HEAD = "state/analysis-runs/head.json";

async function caseWithLedger(root: string, caseId: string): Promise<string> {
  const caseDir = join(root, caseId);
  await mkdir(join(caseDir, "state", "analysis-runs"), { recursive: true });
  await writeFile(join(caseDir, "case.json"), JSON.stringify({ caseId }));
  await writeFile(join(caseDir, PENDING), '{"id":"run-1"}');
  await writeFile(join(caseDir, HEAD), '{"sequence":0}');
  return caseDir;
}

describe("ZIP archive — a background write overlapping the walk (#2784)", () => {
  it("builds again when a listed file vanishes before its read, and archives the settled folder", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-settle-zip-"));
    try {
      const caseDir = await caseWithLedger(root, "c1");
      let removed = false;
      const result = await archiveCase(root, "c1", {
        readFile: async (p) => {
          if (!removed && p === join(caseDir, PENDING)) {
            removed = true;
            await rm(p); // the run record finished between the walk and this read
          }
          return readFile(p);
        },
        writeFile: async () => undefined,
      });
      const paths = result.manifest.files.map((f) => f.path).sort();
      expect(paths).toEqual(["case.json", HEAD]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("builds again when a file appears during the reads, so head and manifest come from one moment", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-settle-zip-new-"));
    try {
      const caseDir = await caseWithLedger(root, "c1");
      let added = false;
      const result = await archiveCase(root, "c1", {
        readFile: async (p) => {
          if (!added) {
            added = true;
            await writeFile(join(caseDir, "state", "analysis-runs", "run-1.json"), "{}");
          }
          return readFile(p);
        },
        writeFile: async () => undefined,
      });
      expect(result.manifest.files.map((f) => f.path)).toContain("state/analysis-runs/run-1.json");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails with a named message, not a raw ENOENT, when the folder never holds still", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-settle-zip-fail-"));
    try {
      const caseDir = await caseWithLedger(root, "c1");
      const enoent = Object.assign(new Error("ENOENT: no such file or directory, lstat"), { code: "ENOENT" });
      await expect(
        archiveCase(root, "c1", {
          readFile: async (p) => {
            if (p === join(caseDir, PENDING)) throw enoent;
            return readFile(p);
          },
          writeFile: async () => undefined,
        }),
      ).rejects.toThrow(
        /"state\/analysis-runs\/pending\.json" disappeared while the case was being packaged/,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("does not retry an error that is not a vanished file", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-settle-zip-other-"));
    try {
      await caseWithLedger(root, "c1");
      let reads = 0;
      await expect(
        archiveCase(root, "c1", {
          readFile: async () => {
            reads++;
            throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
          },
          writeFile: async () => undefined,
        }),
      ).rejects.toThrow(/EACCES/);
      expect(reads).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("encrypted export — a background write overlapping the walk (#2784)", () => {
  it("builds again when the run record's pending.json vanishes between the walk and the read", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-settle-enc-")));
    try {
      await store.createCase({ caseId: "INC-1", name: "n", investigator: "i", aiProvider: null });
      const caseDir = store.caseDir("INC-1");
      await mkdir(join(caseDir, "state", "analysis-runs"), { recursive: true });
      await writeFile(join(caseDir, PENDING), '{"id":"run-1"}');
      hooks.afterStaging = () => rm(join(caseDir, PENDING));

      const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
      const paths = readZip(await decryptBuffer(archive, PASSWORD)).map((e) => e.path);
      expect(paths).not.toContain(PENDING);
      expect(paths).toContain("case.json");
    } finally {
      await rm(store.casesRoot, { recursive: true, force: true });
    }
  });
});
