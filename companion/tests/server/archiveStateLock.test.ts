import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2247: the plain ZIP archive and both delete-with-archive paths read the case without the case's
// state lock, so a backup restore (which renames a database over the live file under that lock)
// could land mid-walk: a 500 that reads like tampering, or a ZIP that mixes the old database with
// restored sidecar files. The encrypted export already held the lock. Every route that zips the case
// now does: while another holder has the state lock, the archive waits, and builds once it is free.

const HOLD_MS = 200;
// The encrypted path derives its key (scrypt) before it zips, which alone can outlast HOLD_MS — so
// it holds the lock long enough that an unlocked export would have finished and deleted the case.
const ENCRYPTED_HOLD_MS = 2_000;

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-archive-state-lock-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState("c1"));
  const stateLock = new StateLock();
  const app = createApp(store, { stateStore, stateLock });
  return { root, store, app, stateLock };
}

/** Hold the case's state lock (as a restore-backup would) until the returned release is called. */
function holdStateLock(stateLock: StateLock, caseId: string) {
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  const done = stateLock.runExclusive(caseId, () => held);
  return { release, done };
}

const zipsIn = async (root: string) => (await readdir(root)).filter((f) => f.endsWith(".zip"));

/** Fire the request and report whether it answered within holdMs while the lock is held. */
async function answeredWhileHeld(pending: PromiseLike<request.Response>, holdMs = HOLD_MS) {
  let answered = false;
  const response = Promise.resolve(pending).then((r) => {
    answered = true;
    return r;
  });
  await new Promise((r) => setTimeout(r, holdMs));
  return { answeredEarly: answered, response };
}

describe("archive routes hold the case state lock (#2247)", () => {
  it("POST /archive waits for the state lock, then builds the zip", async () => {
    const { root, app, stateLock } = await setup();
    const lock = holdStateLock(stateLock, "c1");
    const { answeredEarly, response } = await answeredWhileHeld(
      request(app).post("/cases/c1/archive").send({}),
    );
    expect(answeredEarly).toBe(false);
    expect(await zipsIn(root)).toEqual([]);
    lock.release();
    await lock.done;
    const res = await response;
    expect(res.status).toBe(200);
    expect(await zipsIn(root)).toHaveLength(1);
  });

  it("delete with archiveFirst zip waits for the state lock before archiving and deleting", async () => {
    const { root, store, app, stateLock } = await setup();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    const lock = holdStateLock(stateLock, "c1");
    const { answeredEarly, response } = await answeredWhileHeld(
      request(app).post("/cases/c1/delete").send({ archiveFirst: "zip" }),
    );
    expect(answeredEarly).toBe(false);
    expect(await zipsIn(root)).toEqual([]);
    expect(existsSync(store.caseDir("c1"))).toBe(true);
    lock.release();
    await lock.done;
    const res = await response;
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ deleted: true });
    expect(await zipsIn(root)).toHaveLength(1);
  });

  it(
    "delete with archiveFirst encrypted waits for the state lock before exporting and deleting",
    { timeout: 15_000 },
    async () => {
      const { store, app, stateLock } = await setup();
      await request(app).patch("/cases/c1/status").send({ status: "closed" });
      const lock = holdStateLock(stateLock, "c1");
      const { answeredEarly, response } = await answeredWhileHeld(
        request(app)
          .post("/cases/c1/delete")
          .send({ archiveFirst: "encrypted", password: "a-long-enough-pass" }),
        ENCRYPTED_HOLD_MS,
      );
      expect(answeredEarly).toBe(false);
      expect(existsSync(store.caseDir("c1"))).toBe(true);
      lock.release();
      await lock.done;
      const res = await response;
      expect(res.status).toBe(200);
      expect(res.headers["x-case-deleted"]).toBe("true");
    },
  );
});
