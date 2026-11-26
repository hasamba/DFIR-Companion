import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  archiveProfile,
  editProfile,
  isArchivedProfile,
  newProfile,
  unarchiveProfile,
} from "../../src/analysis/clientProfile.js";
import { ClientProfileStore } from "../../src/analysis/clientProfileStore.js";
import { findLinkedCases } from "../../src/analysis/clientProfileLinks.js";

// Edit / archive / delete a client (#2941): the pure edits, the locked delete, and the linked-case scan.

const base = newProfile({ name: "Client A", defaultServerSetId: "set-1" }, "admin", "2026-01-01T00:00:00Z");
const dirs: string[] = [];
const tempDir = async (prefix: string) => {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
};
afterEach(async () => {
  for (const d of dirs.splice(0))
    await rm(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("client profile edits (#2941)", () => {
  it("edit renames and changes the server set without a new baseline version", () => {
    const next = editProfile(base, { name: "Client B" }, "admin", "2026-01-02T00:00:00Z");
    expect(next).not.toBe(base);
    expect(base.name).toBe("Client A");
    expect(next.name).toBe("Client B");
    expect(next.defaultServerSetId).toBeUndefined();
    expect(next.version).toBe(base.version);
    expect(next.audit.at(-1)).toMatchObject({ action: "profile", by: "admin", version: 0 });
    expect(next.audit.at(-1)?.detail).toBe('name "Client A" → "Client B"; default server set "set-1" → none');
  });

  it("archive and unarchive keep the baseline and add one audit entry each; repeats change nothing", () => {
    const archived = archiveProfile(base, "admin", "2026-01-03T00:00:00Z");
    expect(isArchivedProfile(archived)).toBe(true);
    expect(isArchivedProfile(base)).toBe(false);
    expect(archived).toMatchObject({ archivedAt: "2026-01-03T00:00:00Z", archivedBy: "admin" });
    expect(archived.baseline).toBe(base.baseline);
    expect(archived.versions).toBe(base.versions);
    expect(archiveProfile(archived, "admin", "later")).toBe(archived);
    const back = unarchiveProfile(archived, "admin", "2026-01-04T00:00:00Z");
    expect("archivedAt" in back).toBe(false);
    expect(back.audit.map((a) => a.action)).toEqual(["create", "archive", "unarchive"]);
    expect(unarchiveProfile(back, "admin", "later")).toBe(back);
  });
});

describe("ClientProfileStore.remove (#2941)", () => {
  it("deletes only when the guard allows, and reports a missing profile", async () => {
    const store = new ClientProfileStore(await tempDir("dfir-clients-rm-"));
    await store.create(base);
    expect(await store.remove(base.id, async () => ["c1"])).toEqual({ status: "refused", reason: ["c1"] });
    expect(await store.get(base.id)).not.toBeNull();
    expect(await store.remove(base.id, async () => null)).toMatchObject({ status: "deleted" });
    expect(await store.get(base.id)).toBeNull();
    expect(await store.remove(base.id, async () => null)).toEqual({ status: "missing" });
    expect(await store.remove("../escape", async () => null)).toEqual({ status: "missing" });
  });

  it("holds the profile's lock across the guard: an exclusive section queued meanwhile runs after", async () => {
    const store = new ClientProfileStore(await tempDir("dfir-clients-lock-"));
    await store.create(base);
    const order: string[] = [];
    let release: () => void = () => {};
    let started: () => void = () => {};
    const guardStarted = new Promise<void>((r) => (started = r));
    const removing = store.remove(base.id, async () => {
      order.push("guard");
      const held = new Promise<void>((r) => (release = r));
      started();
      await held;
      return null;
    });
    await guardStarted;
    const linking = store.exclusive(base.id, async () => {
      order.push(`link sees ${(await store.get(base.id)) ? "client" : "nothing"}`);
    });
    release();
    await Promise.all([removing, linking]);
    expect(order).toEqual(["guard", "link sees nothing"]);
  });
});

describe("findLinkedCases (#2941)", () => {
  async function caseFolder(root: string, rel: string, name: string | null, link: string | null) {
    await mkdir(join(root, rel, "state"), { recursive: true });
    if (name !== null)
      await writeFile(join(root, rel, "case.json"), name ? JSON.stringify({ name }) : "{bad");
    if (link !== null) await writeFile(join(root, rel, "state", "hunt-client.json"), link);
  }
  const folders = (root: string) => ({
    casesRoot: root,
    stateDir: (id: string) => join(root, id, "state"),
    getCaseMeta: async (id: string) => {
      const { readFile } = await import("node:fs/promises");
      for (const p of [join(root, id, "case.json"), join(root, "_archived", id, "case.json")]) {
        try {
          return JSON.parse(await readFile(p, "utf8")) as { name: string };
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        }
      }
      return null;
    },
  });

  it("finds active, archived, damaged-metadata and unreadable-link cases; ignores others", async () => {
    const root = await tempDir("dfir-linked-");
    const link = (id: string) => JSON.stringify({ clientId: id, linkedAt: "", linkedBy: "" });
    await caseFolder(root, "c-active", "Active", link("client-a"));
    await caseFolder(root, "_archived/c-old", "Old", link("client-a"));
    await caseFolder(root, "c-damaged", "", link("client-a"));
    await caseFolder(root, "c-corrupt", "Corrupt", "{not json");
    await caseFolder(root, "c-other", "Other", link("client-b"));
    await caseFolder(root, "c-none", "None", null);
    await mkdir(join(root, ".hidden-not-a-case", "state"), { recursive: true });
    expect(await findLinkedCases(folders(root), "client-a")).toEqual([
      { caseId: "c-active", name: "Active" },
      { caseId: "c-corrupt", name: "Corrupt", unreadable: true },
      { caseId: "c-damaged", name: "c-damaged" },
      { caseId: "c-old", name: "Old" },
    ]);
  });

  it("answers an empty list when there is no cases folder yet", async () => {
    const root = join(await tempDir("dfir-linked-empty-"), "cases");
    expect(await findLinkedCases(folders(root), "client-a")).toEqual([]);
  });
});
