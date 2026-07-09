import { describe, it, expect } from "vitest";
import { pollHuntStatusOnce, isHuntStoppedEarly, type HuntPollDeps } from "../../src/integrations/velociraptor/huntStatusPoller.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

function job(over: Partial<VeloHuntJob> = {}): VeloHuntJob {
  return {
    bundleId: "best-practice",
    bundleName: "Best Practice",
    artifacts: ["Windows.System.Pslist"],
    huntId: "H.ABC123",
    launchedAt: "2026-07-01T10:00:00.000Z",
    waitMinutes: 10,
    collectAt: "2026-07-01T10:10:00.000Z",
    status: "running",
    ...over,
  };
}

describe("pollHuntStatusOnce", () => {
  it("reschedules and normalizes RUNNING to status running", async () => {
    const deps: HuntPollDeps = { getState: async () => ({ state: "RUNNING" }) };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("reschedule");
    expect(out.job.status).toBe("running");
  });

  it("reschedules and normalizes PAUSED to status running (still active, not done)", async () => {
    const deps: HuntPollDeps = { getState: async () => ({ state: "PAUSED" }) };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("reschedule");
    expect(out.job.status).toBe("running");
  });

  it("reschedules as running but logs when Velociraptor reports an unrecognized state", async () => {
    let logged = "";
    const deps: HuntPollDeps = { getState: async () => ({ state: "UNKNOWN_STATE" }), log: (m) => { logged = m; } };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("reschedule");
    expect(out.job.status).toBe("running");
    expect(logged).toContain("UNKNOWN_STATE");
  });

  it("triggers a collect when Velociraptor reports STOPPED", async () => {
    const deps: HuntPollDeps = { getState: async () => ({ state: "STOPPED" }) };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("collect");
  });

  it("triggers a collect when Velociraptor reports ARCHIVED", async () => {
    const deps: HuntPollDeps = { getState: async () => ({ state: "ARCHIVED" }) };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("collect");
  });

  it("is case-insensitive when matching Velociraptor's state string", async () => {
    const deps: HuntPollDeps = { getState: async () => ({ state: "stopped" }) };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("collect");
  });

  it("marks the job deleted and stops when the hunt is not found", async () => {
    const deps: HuntPollDeps = { getState: async () => null };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("stop");
    expect(out.job.status).toBe("deleted");
  });

  it("marks the job unreachable and reschedules when the query throws", async () => {
    let logged = "";
    const deps: HuntPollDeps = { getState: async () => { throw new Error("velo down"); }, log: (m) => { logged = m; } };
    const out = await pollHuntStatusOnce(job(), deps);
    expect(out.action).toBe("reschedule");
    expect(out.job.status).toBe("unreachable");
    expect(logged).toContain("velo down");
  });

  it("recovers from unreachable back to running once Velociraptor answers again", async () => {
    const deps: HuntPollDeps = { getState: async () => ({ state: "RUNNING" }) };
    const out = await pollHuntStatusOnce(job({ status: "unreachable" }), deps);
    expect(out.action).toBe("reschedule");
    expect(out.job.status).toBe("running");
  });

  it("never polls a job already in a terminal status (defensive, caller-level guard duplicated here)", async () => {
    for (const status of ["collecting", "imported", "error", "deleted"] as const) {
      const j = job({ status });
      const deps: HuntPollDeps = { getState: async () => { throw new Error("should not be called"); } };
      const out = await pollHuntStatusOnce(j, deps);
      expect(out.action).toBe("stop");
      expect(out.job).toBe(j);   // untouched, same reference
    }
  });
});

// A hunt DELETED from the Velociraptor GUI does not disappear from hunts() (confirmed against a live
// server) — it just reports STOPPED, identical to natural completion. The only signal Velociraptor
// still exposes is the hunt's own `expires`: natural completion happens AT (or just after) expires;
// a hunt an analyst stopped/deleted partway through reports terminal well BEFORE it. isHuntStoppedEarly
// is the collect-time check that tells these apart so the UI can stop saying "collect again later"
// for a hunt that will never produce anything again.
describe("isHuntStoppedEarly", () => {
  const NOW = new Date("2026-07-09T08:00:00.000Z").getTime();

  it("is false when the hunt is still running, regardless of expires", () => {
    expect(isHuntStoppedEarly({ state: "RUNNING", expires: "2026-07-09T09:00:00.000Z" }, NOW)).toBe(false);
  });

  it("is false when there's no result (hunt truly not found)", () => {
    expect(isHuntStoppedEarly(null, NOW)).toBe(false);
  });

  it("is false when a terminal state is reported at/after its own expiry (natural completion)", () => {
    expect(isHuntStoppedEarly({ state: "STOPPED", expires: "2026-07-09T07:59:00.000Z" }, NOW)).toBe(false);
  });

  it("is true when a terminal state is reported well before its own expiry (stopped/deleted early)", () => {
    expect(isHuntStoppedEarly({ state: "STOPPED", expires: "2026-07-09T09:00:00.000Z" }, NOW)).toBe(true);
  });

  it("is case-insensitive on state and also recognizes ARCHIVED", () => {
    expect(isHuntStoppedEarly({ state: "archived", expires: "2026-07-09T09:00:00.000Z" }, NOW)).toBe(true);
  });

  it("is false when expires is missing (nothing to compare against)", () => {
    expect(isHuntStoppedEarly({ state: "STOPPED" }, NOW)).toBe(false);
  });

  it("stays false within the grace window just before expiry (housekeeping lag, not an early stop)", () => {
    expect(isHuntStoppedEarly({ state: "STOPPED", expires: "2026-07-09T08:00:30.000Z" }, NOW)).toBe(false);
  });
});
