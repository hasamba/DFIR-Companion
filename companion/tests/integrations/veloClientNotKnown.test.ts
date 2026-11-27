import { describe, expect, it } from "vitest";
import {
  collectLaunchError,
  VeloClientNotKnownError,
} from "../../src/integrations/velociraptor/vqlDiagnostics.js";
import { hostClientIds } from "../../src/integrations/velociraptor/clientInventory.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

// #2986: collect_client refused a client id the server does not know (stale inventory or another
// org). That refusal is definite — nothing was scheduled — and must not read as "maybe it ran".

const STALE = "C.stale0001";
const notKnown = (id: string) =>
  `[INFO] 2026-11-27T10:00:00Z collect_client: Client ID ${id} not known in this org: NotFoundError `;
const cfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
};

describe("collectLaunchError", () => {
  it("is a VeloClientNotKnownError when collect_client says it does not know THIS client", () => {
    const err = collectLaunchError(STALE, notKnown(STALE));
    expect(err).toBeInstanceOf(VeloClientNotKnownError);
    expect((err as VeloClientNotKnownError).clientId).toBe(STALE);
    expect(err.message).toContain(STALE);
    expect(err.message).toMatch(/re-enrolled/);
    expect(err.message).toMatch(/another org|different org/);
    expect(err.message).not.toMatch(/download URL|ARTIFACT_WRITER/);
  });

  it("stays the generic no-flow-id error when the log names a different client", () => {
    const err = collectLaunchError(STALE, notKnown("C.other0002"));
    expect(err).not.toBeInstanceOf(VeloClientNotKnownError);
    expect(err.message).toMatch(/ARTIFACT_WRITER and COLLECT_CLIENT/);
  });

  it("stays generic for an unrelated 'not known' line or an empty log", () => {
    expect(
      collectLaunchError(STALE, "[INFO] t artifact_set: artifact Foo not known in this org"),
    ).not.toBeInstanceOf(VeloClientNotKnownError);
    expect(collectLaunchError(STALE, "")).not.toBeInstanceOf(VeloClientNotKnownError);
  });

  it("finds the refusal even after a long log the display cut would truncate", () => {
    const noise = Array.from(
      { length: 40 },
      (_, i) => `[WARN] t plugin_${i}: something long went wrong here`,
    );
    const err = collectLaunchError(STALE, [...noise, notKnown(STALE)].join("\n"));
    expect(err).toBeInstanceOf(VeloClientNotKnownError);
  });
});

describe("collectOnClient refused for an unknown client", () => {
  it("throws VeloClientNotKnownError", async () => {
    const runner: VqlRunner = async () => ({
      rows: [{ Flow: null }],
      raw: '{"Flow":null}',
      stderr: notKnown(STALE),
    });
    await expect(
      new VelociraptorClient(cfg, runner).collectOnClient(STALE, "SELECT * FROM pslist()", "ps"),
    ).rejects.toBeInstanceOf(VeloClientNotKnownError);
  });
});

describe("hostClientIds", () => {
  const rec = (clientId: string, hostname: string, fqdn = "") => ({ clientId, hostname, fqdn });
  it("prefers exact matches over first-label matches", () => {
    const recs = [rec("C.a1", "web01.corp.example"), rec("C.b2", "web01", "web01.lab.example")];
    expect(hostClientIds(recs, "web01.corp.example")).toEqual(["C.a1"]);
  });
  it("returns every distinct first-label candidate when no exact match exists", () => {
    const recs = [rec("C.a1", "web01.corp.example"), rec("C.b2", "web01.lab.example")];
    expect(hostClientIds(recs, "WEB01")).toEqual(["C.a1", "C.b2"]);
  });
  it("is empty when nothing matches", () => {
    expect(hostClientIds([rec("C.a1", "db01")], "web01")).toEqual([]);
  });
});
