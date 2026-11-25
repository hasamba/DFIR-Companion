// #2887: the enrolled-client list is read with one row limit. A read that comes back AT that limit may
// have left clients out, and nothing used to say so — the snapshot now carries `truncated`, logs a
// warning, and the host-miss message says the list was cut instead of blaming the host.
import { afterEach, describe, expect, it, vi } from "vitest";

const logs = vi.hoisted(() => ({ lines: [] as string[] }));
vi.mock("../../../src/logging/serverLogger.js", async (orig) => {
  const real = await orig<typeof import("../../../src/logging/serverLogger.js")>();
  return { ...real, warnLine: (m: string) => logs.lines.push(m) };
});

import {
  CLIENT_LOOKUP_LIMIT,
  clientSnapshot,
  hostMissMessage,
} from "../../../src/integrations/velociraptor/clientSnapshot.js";
import { CLIENT_LOOKUP_LIMIT as RUNS_LIMIT } from "../../../src/integrations/velociraptor/aiAgentRuns.js";

const rows = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ client_id: `C.c${i}`, os_info: { hostname: `ws${i}` } }));

afterEach(() => {
  logs.lines.length = 0;
});

describe("clientSnapshot", () => {
  it("is one limit, shared with the AI Agent Run endpoint check", () => {
    expect(CLIENT_LOOKUP_LIMIT).toBe(100_000);
    expect(RUNS_LIMIT).toBe(CLIENT_LOOKUP_LIMIT);
  });

  it("a read below the limit is complete: no flag, no warning", () => {
    const snap = clientSnapshot(rows(CLIENT_LOOKUP_LIMIT - 1));
    expect(snap.truncated).toBe(false);
    expect(snap.clients).toHaveLength(CLIENT_LOOKUP_LIMIT - 1);
    expect(logs.lines).toEqual([]);
  });

  it("compares the RAW row count with the limit, so a dropped invalid row still counts as cut", () => {
    const raw = [...rows(CLIENT_LOOKUP_LIMIT - 1), { client_id: "bogus" }];
    const snap = clientSnapshot(raw);
    expect(snap.clients).toHaveLength(CLIENT_LOOKUP_LIMIT - 1);
    expect(snap.truncated).toBe(true);
    expect(logs.lines).toHaveLength(1);
    expect(logs.lines[0]).toContain("100,000");
  });

  it("the host-miss message says the list was cut only when it was", () => {
    expect(hostMissMessage("GHOST", false)).toMatch(/No enrolled Velociraptor client matches host "GHOST"/);
    expect(hostMissMessage("GHOST", false)).not.toMatch(/first 100,000/);
    const cut = hostMissMessage("GHOST", true);
    expect(cut).toMatch(/No enrolled Velociraptor client matches host "GHOST"/);
    expect(cut).toContain("the server returned only the first 100,000 clients");
    expect(cut).toMatch(/fleet hunt/);
    expect(cut).not.toMatch(/search/i);
  });
});
