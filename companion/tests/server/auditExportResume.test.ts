import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";
import { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";
import { startPostListenTasks } from "../../src/composition/maintenanceTasks.js";
import type { AuditExporter } from "../../src/integrations/audit/auditExporter.js";

// #929: the delivery position only advances on an accepted batch, so a crash or a collector outage
// leaves records pending on purpose. The ONLY other thing that drains a case is its own next
// activity append — which a quiet or closed case never gets. So the restart has to drain, and this
// is the seam that does it.

async function deps(auditExporter?: AuditExporter) {
  const root = await mkdtemp(join(tmpdir(), "dfir-audit-resume-"));
  const store = new CaseStore(root);
  return {
    store,
    demoMode: false,
    velociraptorClientStore: new VelociraptorClientStore(join(root, "velo-clients.json")),
    updateCheckStore: new UpdateCheckStore(join(root, "update-check.json")),
    updateRepo: "hasamba/DFIR-Companion",
    ...(auditExporter ? { auditExporter } : {}),
  };
}

const fakeExporter = (resume: () => Promise<never[]>): AuditExporter => ({
  resume,
  exportCase: async () => [],
  seed: async () => {},
  backfill: async () => [],
  test: async () => [],
  status: () => [],
});

const settle = () => new Promise((r) => setTimeout(r, 20));

describe("startPostListenTasks — audit export resume", () => {
  it("drains pending audit records once the server is up", async () => {
    const resume = vi.fn(async () => [] as never[]);
    startPostListenTasks(await deps(fakeExporter(resume)));
    await settle();
    expect(resume).toHaveBeenCalledTimes(1);
  });

  it("does nothing when the feature is not configured", async () => {
    // No exporter in the deps at all — the absence must not throw on the path that binds the port.
    const bare = await deps();
    expect(() => startPostListenTasks(bare)).not.toThrow();
    await settle();
  });

  it("a resume that rejects never breaks startup", async () => {
    // Startup must survive an unreachable collector. This ran on the path that binds the port.
    const resume = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    startPostListenTasks(await deps(fakeExporter(resume)));
    await settle();
    expect(resume).toHaveBeenCalledTimes(1);
  });
});
