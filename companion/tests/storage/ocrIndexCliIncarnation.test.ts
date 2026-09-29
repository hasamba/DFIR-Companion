// #1866 (item 3): `npm run ocr-index` writes the OCR index from another process. It reads the case's
// generation at start and refuses to write once the case was deleted, or deleted and re-created
// under the same id, during the run. The "other process" here removes and rewrites the folder with
// plain fs calls, so none of this process's in-memory tombstones help the CLI.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { backfillOcrIndex, type OcrBackfillDeps } from "../../scripts/ocr-index.js";

const CASE_ID = "c1866";
let root: string;
let store: CaseStore;
let errors: string[];

async function seedCase(): Promise<void> {
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const shots = store.screenshotsDir(CASE_ID);
  await mkdir(shots, { recursive: true });
  const lines: string[] = [];
  for (const n of [1, 2, 3]) {
    await writeFile(join(shots, `s${n}.png`), "png");
    lines.push(JSON.stringify({ sequenceNumber: n, screenshotFile: `s${n}.png` }));
  }
  await writeFile(store.capturesLogPath(CASE_ID), lines.join("\n") + "\n", "utf8");
}

function deps(recognize: OcrBackfillDeps["recognize"]): OcrBackfillDeps {
  return { store, caseId: CASE_ID, force: false, recognize, log: () => {}, error: (l) => errors.push(l) };
}

const word = [{ text: "hello", confidence: 99 }] as never;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-1866-ocr-"));
  store = new CaseStore(root);
  errors = [];
  await seedCase();
});

describe("ocr-index CLI and the case incarnation (#1866)", () => {
  it("indexes every screenshot of a live case", async () => {
    expect(await backfillOcrIndex(deps(async () => word))).toBe("done");
    expect(Object.keys(await store.loadOcrIndex(CASE_ID)).sort()).toEqual(["s1.png", "s2.png", "s3.png"]);
  });

  it("stops, and recreates nothing, when the case is deleted during the run", async () => {
    let calls = 0;
    const outcome = await backfillOcrIndex(
      deps(async () => {
        calls += 1;
        if (calls === 2) await rm(join(root, CASE_ID), { recursive: true, force: true }); // the server deleted it
        return word;
      }),
    );
    expect(outcome).toBe("case-changed");
    expect(calls).toBe(2);
    expect(existsSync(join(root, CASE_ID)), "the deleted case folder must not come back").toBe(false);
    expect(errors.join("\n")).toMatch(/deleted or replaced during the run/);
  });

  it("never writes into a same-id case created while the run was OCRing", async () => {
    let calls = 0;
    const outcome = await backfillOcrIndex(
      deps(async () => {
        calls += 1;
        if (calls === 2) {
          await rm(join(root, CASE_ID), { recursive: true, force: true });
          const other = new CaseStore(root); // the server, re-creating the id
          await other.createCase({ caseId: CASE_ID, name: "new", investigator: "i", aiProvider: null });
        }
        return word;
      }),
    );
    expect(outcome).toBe("case-changed");
    expect(
      existsSync(store.ocrIndexPath(CASE_ID)),
      "the new case must get no OCR index from the old run",
    ).toBe(false);
    expect(JSON.parse(await readFile(join(root, CASE_ID, "case.json"), "utf8")).name).toBe("new");
  });

  it("reports the change even when the failing step after it is not a write", async () => {
    let calls = 0;
    const outcome = await backfillOcrIndex(
      deps(async () => {
        calls += 1;
        await rm(join(root, CASE_ID), { recursive: true, force: true });
        await new CaseStore(root).createCase({
          caseId: CASE_ID,
          name: "new",
          investigator: "i",
          aiProvider: null,
        });
        throw new Error("tesseract crashed"); // not a refused write: the old code logged "skip" and said "done"
      }),
    );
    expect(outcome).toBe("case-changed");
    expect(calls).toBe(1);
  });

  it("refuses a case that does not exist", async () => {
    await rm(join(root, CASE_ID), { recursive: true, force: true });
    expect(await backfillOcrIndex(deps(async () => word))).toBe("missing");
    expect(existsSync(join(root, CASE_ID))).toBe(false);
  });
});
