// #1866 (item 2): per-case in-memory state keys on (case id, generation). A deleted case's late
// callback cannot read, cancel, coalesce with or clear a same-id successor's entry, and a delete
// drops every entry the old case left (clearing its timers).
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { capturedGeneration, runInCaseScope } from "../../src/storage/caseIncarnation.js";
import { CaseKeyedMap, CaseKeyedSet, forgetCaseKeyedState } from "../../src/storage/caseKeyedState.js";
import { clearStateOutlivingCase } from "../../src/routes/caseIdentity.js";
import type { RouteContext } from "../../src/routes/context.js";
import { LiveHub, type SocketLike } from "../../src/live/hub.js";

let root: string;
let store: CaseStore;
const ID = "k1";
const create = () => store.createCase({ caseId: ID, name: "n", investigator: "i", aiProvider: null });
async function deleteCase(): Promise<void> {
  await store.updateCaseMeta(ID, { status: "closed" });
  await store.deleteCaseFolder(ID);
}
/** Work of the incarnation live right now: its scope, kept for later calls. */
function oldWork(): <T>(fn: () => T) => T {
  const gen = runInCaseScope(root, ID, () => capturedGeneration(root, ID))!;
  return (fn) => runInCaseScope(root, ID, fn, gen);
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-1866-keyed-"));
  store = new CaseStore(root);
});

describe("CaseKeyedMap / CaseKeyedSet (#1866)", () => {
  it("behaves like a Map for one live case, scoped or not", async () => {
    await create();
    const map = new CaseKeyedMap<number>(root);
    map.set(ID, 1);
    expect(runInCaseScope(root, ID, () => map.get(ID))).toBe(1);
    runInCaseScope(root, ID, () => map.set(ID, 2));
    expect(map.get(ID)).toBe(2);
    expect(map.delete(ID)).toBe(true);
    expect(map.has(ID)).toBe(false);
  });

  it("an old incarnation's late callback cannot see, clear or overwrite a successor's entry", async () => {
    await create();
    const inFlight = new CaseKeyedSet(root);
    const old = oldWork();
    old(() => inFlight.add(ID));
    old(() => expect(inFlight.has(ID)).toBe(true)); // the old run sees its own mark
    await deleteCase(); // CaseStore.deleteCaseFolder also forgets the case's entries
    await create(); // same id, new incarnation
    expect(inFlight.has(ID), "the successor starts with nothing in flight").toBe(false);
    inFlight.add(ID);
    old(() => inFlight.delete(ID)); // the old run's `finally`
    expect(inFlight.has(ID), "the old finally must not clear the successor's mark").toBe(true);
  });

  it("forgetCaseKeyedState drops every entry of the case, runs the disposer, and spares other roots", async () => {
    await create();
    const fired: string[] = [];
    const timers = new CaseKeyedMap<string>(root, (value) => fired.push(value));
    const elsewhere = new CaseKeyedMap<string>(join(root, "other-root"));
    timers.set(ID, "t-old");
    timers.set("other", "t-other");
    elsewhere.set(ID, "keep");
    forgetCaseKeyedState(root, ID);
    expect(fired).toEqual(["t-old"]);
    expect(timers.has(ID)).toBe(false);
    expect(timers.get("other")).toBe("t-other");
    expect(elsewhere.get(ID)).toBe("keep");
  });

  it("the delete route's clearStateOutlivingCase forgets the case's in-memory state", async () => {
    await create();
    const buffers = new CaseKeyedMap<number[]>(root);
    buffers.set(ID, [1, 2]);
    const ctx = {
      store,
      options: {},
      serverLogger: { error: () => {} },
      captureBuffers: () => buffers,
    } as unknown as RouteContext;
    await clearStateOutlivingCase(ctx, ID);
    expect(buffers.size).toBe(0);
  });

  it("a dashboard socket left open on the deleted case gets none of the same-id successor's pushes", async () => {
    await create();
    const hub = new LiveHub(root);
    const received: string[] = [];
    let terminated = false;
    const socket: SocketLike = {
      readyState: 1,
      OPEN: 1,
      send: (data) => void received.push(data),
      terminate: () => void (terminated = true),
    };
    hub.subscribe(ID, socket);
    await deleteCase();
    await create();
    hub.broadcastTo(ID, { type: "new-case-news" });
    expect(terminated).toBe(true);
    expect(received).toEqual([]);
  });
});
