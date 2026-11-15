import { describe, expect, it } from "vitest";
import { withCallMetrics } from "../../../src/analysis/ai/callMetrics.js";
import type { ProviderCallContext } from "../../../src/analysis/ai/providerCallContext.js";
import { ProviderError, type AIProvider } from "../../../src/providers/provider.js";

// Task 5 review Minor 3: a fetch the caller aborted (an analyst's Stop) is not a transport failure.

function ctxWith(records: unknown[]): ProviderCallContext {
  const operationalMetrics = { record: async (r: unknown) => void records.push(r) };
  return { log: console, opts: { operationalMetrics } } as unknown as ProviderCallContext;
}

const provider = { name: "fake", model: "fake-model" } as AIProvider;
const transport = () => Promise.reject(new ProviderError("fetch failed: aborted", "transport"));

describe("withCallMetrics and a cancelled call", () => {
  it("records no transport error when the caller's signal was aborted", async () => {
    const records: unknown[] = [];
    const ctl = new AbortController();
    ctl.abort();
    await expect(
      withCallMetrics(ctxWith(records), provider, "watson", ctl.signal, transport),
    ).rejects.toThrow();
    expect(records).toEqual([]);
  });

  it("still records a real transport error", async () => {
    const records: unknown[] = [];
    const signal = new AbortController().signal;
    await expect(withCallMetrics(ctxWith(records), provider, "watson", signal, transport)).rejects.toThrow();
    expect(records).toMatchObject([{ success: false, errorKind: "transport" }]);
  });
});
