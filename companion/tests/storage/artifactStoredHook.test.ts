import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, open, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore, type StoredArtifact } from "../../src/storage/caseStore.js";

let store: CaseStore;
let seen: StoredArtifact[];

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");
const sha1 = (data: Buffer | string) => createHash("sha1").update(data).digest("hex");

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-artifacthook-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  seen = [];
  store.onArtifactStored(async (artifact) => {
    seen.push(artifact);
  });
});

describe("CaseStore artifact-stored hook", () => {
  it("notifies with the stored path and sha256 when a screenshot is saved", async () => {
    const bytes = Buffer.from("not-really-an-image");

    const path = await store.saveScreenshot("c1", "000001_shot.webp", bytes);

    expect(seen).toEqual([
      {
        caseId: "c1",
        path,
        sha256: sha256(bytes),
        sha1: sha1(bytes),
        kind: "screenshot",
        provenance: undefined,
      },
    ]);
  });

  it("passes the caller's provenance through to the listener", async () => {
    const provenance = {
      source: "https://mail.example.com/inbox",
      trigger: "navigation",
      collectedBy: "extension",
    };

    await store.saveScreenshot("c1", "000001_shot.webp", Buffer.from("x"), provenance);

    expect(seen[0]?.provenance).toEqual(provenance);
  });

  it("notifies with the stored path and sha256 when an import is saved", async () => {
    const text = "ts,message\n2026-01-01T00:00:00Z,hello\n";

    const path = await store.saveImport("c1", "evidence.csv", text);

    expect(seen).toEqual([
      {
        caseId: "c1",
        path,
        sha256: sha256(Buffer.from(text, "utf8")),
        sha1: sha1(Buffer.from(text, "utf8")),
        kind: "import",
        provenance: undefined,
      },
    ]);
  });

  it("notifies with path and sha256 when an import is saved from an open handle", async () => {
    // POST /cases/:id/import-file copies by handle; it must land in custody like saveImport (#2055).
    const bytes = Buffer.from("ts,message\n2026-01-01T00:00:00Z,big file\n");
    const src = join(await mkdtemp(join(tmpdir(), "dfir-handle-src-")), "src.csv");
    await writeFile(src, bytes);
    const handle = await open(src, "r");
    try {
      const saved = await store.saveImportFromHandle("c1", "0001_x.csv", handle);

      expect(saved.bytes).toBe(bytes.length);
      expect(seen).toEqual([
        {
          caseId: "c1",
          path: saved.path,
          sha256: sha256(bytes),
          sha1: sha1(bytes),
          kind: "import",
          provenance: undefined,
        },
      ]);
    } finally {
      await handle.close();
    }
  });

  it("does not notify when the write fails", async () => {
    await store.saveImport("c1", "evidence.csv", "first");
    // `wx` refuses to overwrite evidence already on disk (#214) — no artifact was stored, so
    // custody must not gain a record claiming one was.
    await expect(store.saveImport("c1", "evidence.csv", "second")).rejects.toThrow();

    expect(seen).toHaveLength(1);
  });

  it("surfaces a listener failure to the caller rather than dropping the record silently", async () => {
    store.onArtifactStored(async () => {
      throw new Error("custody log is full");
    });

    await expect(store.saveImport("c1", "evidence.csv", "data")).rejects.toThrow("custody log is full");
  });
});
