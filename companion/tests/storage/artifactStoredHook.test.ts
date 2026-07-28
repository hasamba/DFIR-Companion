import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore, type StoredArtifact } from "../../src/storage/caseStore.js";

let store: CaseStore;
let seen: StoredArtifact[];

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-artifacthook-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  seen = [];
  store.onArtifactStored(async (artifact) => { seen.push(artifact); });
});

describe("CaseStore artifact-stored hook", () => {
  it("notifies with the stored path and sha256 when a screenshot is saved", async () => {
    const bytes = Buffer.from("not-really-an-image");

    const path = await store.saveScreenshot("c1", "000001_shot.webp", bytes);

    expect(seen).toEqual([
      { caseId: "c1", path, sha256: sha256(bytes), kind: "screenshot", provenance: undefined },
    ]);
  });

  it("passes the caller's provenance through to the listener", async () => {
    const provenance = { source: "https://mail.example.com/inbox", trigger: "navigation", collectedBy: "extension" };

    await store.saveScreenshot("c1", "000001_shot.webp", Buffer.from("x"), provenance);

    expect(seen[0]?.provenance).toEqual(provenance);
  });

  it("notifies with the stored path and sha256 when an import is saved", async () => {
    const text = "ts,message\n2026-01-01T00:00:00Z,hello\n";

    const path = await store.saveImport("c1", "evidence.csv", text);

    expect(seen).toEqual([
      { caseId: "c1", path, sha256: sha256(Buffer.from(text, "utf8")), kind: "import", provenance: undefined },
    ]);
  });

  it("does not notify when the write fails", async () => {
    await store.saveImport("c1", "evidence.csv", "first");
    // `wx` refuses to overwrite evidence already on disk (#214) — no artifact was stored, so
    // custody must not gain a record claiming one was.
    await expect(store.saveImport("c1", "evidence.csv", "second")).rejects.toThrow();

    expect(seen).toHaveLength(1);
  });

  it("surfaces a listener failure to the caller rather than dropping the record silently", async () => {
    store.onArtifactStored(async () => { throw new Error("custody log is full"); });

    await expect(store.saveImport("c1", "evidence.csv", "data")).rejects.toThrow("custody log is full");
  });
});
