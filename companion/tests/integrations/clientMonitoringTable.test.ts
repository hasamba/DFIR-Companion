import { describe, it, expect } from "vitest";
import {
  enableClientMonitoringVql,
  disableClientMonitoringVql,
  ensureClientMonitoring,
  releaseClientMonitoring,
  type ClientMonitoringTableClient,
} from "../../src/integrations/velociraptor/clientMonitoringTable.js";

// A fake Velociraptor: the monitoring table is a mutable set, `run` applies add/rm VQL to it, and
// every VQL program is recorded so a test can assert what was (not) sent.
function fakeClient(initial: string[], opts: { addFails?: boolean } = {}) {
  const table = new Set(initial);
  const programs: string[] = [];
  const client: ClientMonitoringTableClient = {
    listMonitoredArtifacts: async () => [...table],
    run: async (vql) => {
      programs.push(vql);
      const m = /(add|rm)_client_monitoring\(artifact='([^']+)'\)/.exec(vql);
      if (m && !opts.addFails) {
        if (m[1] === "add") table.add(m[2]);
        else table.delete(m[2]);
      }
      return { rows: [{}], total: 1, truncated: false };
    },
  };
  return { client, table, programs };
}

describe("clientMonitoringTable — VQL builders", () => {
  it("builds the add/rm calls for a valid artifact name", () => {
    expect(enableClientMonitoringVql("Windows.Events.DNSQueries")).toBe(
      "SELECT add_client_monitoring(artifact='Windows.Events.DNSQueries') AS Added FROM scope()",
    );
    expect(disableClientMonitoringVql("Windows.Events.DNSQueries")).toBe(
      "SELECT rm_client_monitoring(artifact='Windows.Events.DNSQueries') AS Removed FROM scope()",
    );
  });

  it("refuses an artifact name that could break out of the VQL literal", () => {
    expect(() => enableClientMonitoringVql("X') OR 1=1 --")).toThrow(/invalid artifact name/);
    expect(() => disableClientMonitoringVql("")).toThrow(/invalid artifact name/);
  });
});

describe("ensureClientMonitoring", () => {
  it("adds an artifact that is missing from the table and reports 'added'", async () => {
    const { client, table, programs } = fakeClient(["Generic.Client.Stats"]);
    const r = await ensureClientMonitoring(client, "Custom.Windows.Events.Kerberoasting");
    expect(r).toBe("added");
    expect(table.has("Custom.Windows.Events.Kerberoasting")).toBe(true);
    expect(programs).toHaveLength(1);
    expect(programs[0]).toContain("add_client_monitoring(artifact='Custom.Windows.Events.Kerberoasting')");
  });

  it("leaves an artifact that is already configured alone and reports 'present'", async () => {
    const { client, programs } = fakeClient(["Windows.Events.ProcessCreation"]);
    const r = await ensureClientMonitoring(client, "Windows.Events.ProcessCreation");
    expect(r).toBe("present");
    expect(programs).toHaveLength(0);
  });

  it("throws a plain-language error when the add did not land in the table", async () => {
    const { client } = fakeClient([], { addFails: true });
    await expect(ensureClientMonitoring(client, "Windows.Events.DNSQueries")).rejects.toThrow(
      /could not enable Windows\.Events\.DNSQueries in Velociraptor → Client Monitoring/,
    );
  });
});

describe("releaseClientMonitoring", () => {
  it("removes the artifact from the table", async () => {
    const { client, table } = fakeClient(["Windows.Events.DNSQueries", "Generic.Client.Stats"]);
    await releaseClientMonitoring(client, "Windows.Events.DNSQueries");
    expect([...table]).toEqual(["Generic.Client.Stats"]);
  });

  it("is a no-op when the artifact is not in the table", async () => {
    const { client, programs } = fakeClient(["Generic.Client.Stats"]);
    await releaseClientMonitoring(client, "Windows.Events.DNSQueries");
    expect(programs).toHaveLength(0);
  });
});
