import { describe, expect, it } from "vitest";
import { collectHostResolved } from "../../src/routes/veloDeploy.js";
import { VeloClientNotKnownError } from "../../src/integrations/velociraptor/vqlDiagnostics.js";
import type { RouteContext } from "../../src/routes/context.js";
import type { VeloTarget } from "../../src/routes/veloServers.js";

// #2986: the host is in the saved client list, but Velociraptor no longer knows that client id
// (the endpoint re-enrolled, or it lives in another org). Refresh once, retry once on a NEW,
// unambiguous id; otherwise refuse definitely so the launch reads as "nothing ran".

const HOST = "web01.example.test";
const STALE = "C.stale0001";
const FRESH = "C.fresh0002";
const rec = (clientId: string, hostname = HOST) => ({ clientId, hostname, fqdn: hostname });

function setup(opts: {
  before: ReturnType<typeof rec>[];
  after?: ReturnType<typeof rec>[];
  refreshFails?: boolean;
  truncatedAfter?: boolean;
  refuse?: (id: string) => Error | undefined;
}) {
  let clients = opts.before;
  let truncated = false;
  const calls: string[] = [];
  let refreshes = 0;
  const store = { load: async () => ({ updatedAt: "", clients, truncated }) };
  const ctx = {
    options: { clientInventoryFor: () => store },
    refreshVeloClients: async () => {
      refreshes++;
      if (opts.refreshFails) throw new Error("server unreachable");
      clients = opts.after ?? clients;
      truncated = opts.truncatedAfter === true;
      return clients.length;
    },
  } as unknown as RouteContext;
  const refuse =
    opts.refuse ??
    ((id: string) => (id === STALE ? new VeloClientNotKnownError("not known", id) : undefined));
  const vc = {
    setId: "default",
    client: {
      collectOnClient: async (id: string) => {
        calls.push(id);
        const err = refuse(id);
        if (err) throw err;
        return { clientId: id, flowId: "F.SAMPLE1", hostname: HOST, artifact: "A", sources: [], guiUrl: "" };
      },
    },
  } as unknown as VeloTarget;
  const run = () => collectHostResolved(ctx, vc, HOST, "SELECT 1 FROM scope()", "d");
  return { run, calls, refreshes: () => refreshes };
}

describe("collectHostResolved with a stale client id", () => {
  it("refreshes once and retries on the host's new client id", async () => {
    const s = setup({ before: [rec(STALE)], after: [rec(FRESH)] });
    const r = await s.run();
    expect(r.clientId).toBe(FRESH);
    expect(s.calls).toEqual([STALE, FRESH]);
    expect(s.refreshes()).toBe(1);
  });

  it("refuses definitely when the refresh still lists the same id", async () => {
    const s = setup({ before: [rec(STALE)], after: [rec(STALE)] });
    await expect(s.run()).rejects.toBeInstanceOf(VeloClientNotKnownError);
    expect(s.calls).toEqual([STALE]);
  });

  it("refuses definitely when the host is gone after the refresh", async () => {
    const s = setup({ before: [rec(STALE)], after: [rec(FRESH, "db01.example.test")] });
    await expect(s.run()).rejects.toThrow(/no longer in the client list/);
    expect(s.calls).toEqual([STALE]);
  });

  it("does not guess when the refreshed list has two candidates for the host", async () => {
    const s = setup({
      before: [rec(STALE, "web01")],
      after: [rec(FRESH, "web01.a.example.test"), rec("C.other0003", "web01.b.example.test")],
    });
    // Neither refreshed record matches HOST exactly; both match its first label "web01".
    await expect(s.run()).rejects.toBeInstanceOf(VeloClientNotKnownError);
    expect(s.calls).toEqual([STALE]);
  });

  it("does not retry on a new id when the refreshed list was cut at the row limit", async () => {
    const s = setup({
      before: [rec(STALE)],
      after: [rec(FRESH, "web01.lab.example.test")],
      truncatedAfter: true,
    });
    await expect(s.run()).rejects.toThrow(/cut at the row limit/);
    expect(s.calls).toEqual([STALE]);
  });

  it("keeps the definite refusal when the refresh itself fails", async () => {
    const s = setup({ before: [rec(STALE)], refreshFails: true });
    const err = await s.run().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VeloClientNotKnownError);
    expect((err as Error).message).toMatch(/server unreachable/);
  });

  it("a retry that is refused for the new id too is still a definite refusal", async () => {
    const s = setup({
      before: [rec(STALE)],
      after: [rec(FRESH)],
      refuse: (id) => new VeloClientNotKnownError("not known", id),
    });
    await expect(s.run()).rejects.toBeInstanceOf(VeloClientNotKnownError);
    expect(s.calls).toEqual([STALE, FRESH]);
  });

  it("does not refresh or retry on any other launch error", async () => {
    const s = setup({ before: [rec(STALE)], refuse: () => new Error("Velociraptor timed out") });
    await expect(s.run()).rejects.not.toBeInstanceOf(VeloClientNotKnownError);
    expect(s.calls).toEqual([STALE]);
    expect(s.refreshes()).toBe(0);
  });
});
