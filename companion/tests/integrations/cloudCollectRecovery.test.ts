import { describe, expect, it, vi } from "vitest";
import { startCloudCollectRecovery } from "../../src/integrations/cloudAccounts/collectRecovery.js";

// #2308: the public demo never recovers a cloud collect job at startup.
describe("cloud collect startup recovery", () => {
  it("skips every recovery step in demo mode", async () => {
    const step = vi.fn();
    const log = vi.fn();
    expect(await startCloudCollectRecovery({ demoMode: true, recoverers: [step], log })).toBe("skipped-demo");
    expect(step).not.toHaveBeenCalled();
    expect(log.mock.calls[0][0]).toMatch(/demo mode/);
  });

  it("runs every step outside the demo, and one failure does not stop the rest", async () => {
    const order: string[] = [];
    const log = vi.fn();
    const result = await startCloudCollectRecovery({
      demoMode: false,
      recoverers: [
        () => {
          order.push("a");
          throw new Error("ledger gone");
        },
        async () => void order.push("b"),
      ],
      log,
    });
    expect(result).toBe("done");
    expect(order).toEqual(["a", "b"]);
    expect(log.mock.calls[0][0]).toContain("ledger gone");
  });
});
