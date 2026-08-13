import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HostScopeStore, type HostScopeDecision } from "../../src/analysis/hostScopeStore.js";

let dir = "";
const cases = { stateDir: () => dir } as unknown as ConstructorParameters<typeof HostScopeStore>[0];

function decision(over: Partial<HostScopeDecision> = {}): HostScopeDecision {
  return {
    host: "ws-042.corp.local",
    from: "suspected",
    to: "cleared",
    reason: "EDR and event logs cover the window",
    analyst: "a.analyst@example.invalid",
    at: "2026-08-13T09:41:00Z",
    basis: {
      sources: ["Microsoft Defender"],
      windowCovered: true,
      tacticsCovered: ["Credential Access"],
      evidenceFingerprint: "abc123",
    },
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "host-scope-"));
});

describe("HostScopeStore", () => {
  it("returns an empty list when the file does not exist", async () => {
    expect(await new HostScopeStore(cases).load("c1")).toEqual([]);
  });

  it("appends decisions in order and never overwrites earlier ones", async () => {
    const store = new HostScopeStore(cases);
    await store.append("c1", decision());
    const all = await store.append("c1", decision({ to: "confirmed", at: "2026-08-13T10:00:00Z" }));
    expect(all).toHaveLength(2);
    expect(all[0].to).toBe("cleared");
    expect(all[1].to).toBe("confirmed");
    expect(await store.load("c1")).toHaveLength(2);
  });

  it("keeps every decision when two analysts append concurrently", async () => {
    const store = new HostScopeStore(cases);
    // Both calls start before either finishes — the read-modify-write that used to race.
    await Promise.all([
      store.append("c1", decision({ host: "ws-1", at: "2026-08-13T09:00:00Z" })),
      store.append("c1", decision({ host: "ws-2", at: "2026-08-13T09:00:01Z" })),
      store.append("c1", decision({ host: "ws-3", at: "2026-08-13T09:00:02Z" })),
    ]);
    const all = await store.load("c1");
    expect(all).toHaveLength(3);
    expect(all.map((d) => d.host).sort()).toEqual(["ws-1", "ws-2", "ws-3"]);
  });

  it("does not let one failed append poison the queue for the next writer", async () => {
    const store = new HostScopeStore(cases);
    await expect(
      // `to` is not a valid status — this rejects before it ever reaches the queue.
      store.append("c1", decision({ to: "nonsense" as never })),
    ).rejects.toBeTruthy();
    await store.append("c1", decision({ host: "ws-9" }));
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("throws on a corrupt file and leaves it untouched", async () => {
    await writeFile(join(dir, "host-scope.json"), "{ not json", "utf8");
    await expect(new HostScopeStore(cases).load("c1")).rejects.toThrow(/host-scope\.json/);
  });

  it("throws when the file parses but does not match the schema", async () => {
    await writeFile(join(dir, "host-scope.json"), JSON.stringify({ version: 1 }), "utf8");
    await expect(new HostScopeStore(cases).load("c1")).rejects.toThrow(/host-scope\.json/);
  });
});
