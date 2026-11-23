import { describe, expect, it } from "vitest";
import { deleteHuntOnServer, stopHuntOnServer } from "../../../src/integrations/velociraptor/huntControl.js";

// A fake client that records each VQL program and answers from a script.
function fakeClient(answers: Array<{ rows?: unknown[]; reason?: string } | Error> = []) {
  const programs: string[] = [];
  return {
    programs,
    async runProgram(program: string) {
      programs.push(program);
      const next = answers.shift() ?? { rows: [{}], reason: "" };
      if (next instanceof Error) throw next;
      return { rows: next.rows ?? [{}], reason: next.reason ?? "" };
    },
  };
}

describe("stopHuntOnServer", () => {
  it("stops the hunt with hunt_update(stop=TRUE)", async () => {
    const client = fakeClient();
    expect(await stopHuntOnServer(client, "H.ABC123")).toEqual({ ok: true });
    expect(client.programs).toEqual([
      "SELECT hunt_update(hunt_id='H.ABC123', stop=TRUE) AS Stopped FROM scope()",
    ]);
  });

  it("reports the reason Velociraptor logged, e.g. a missing permission", async () => {
    const client = fakeClient([{ rows: [{ Stopped: null }], reason: "PermissionDenied: START_HUNT" }]);
    expect(await stopHuntOnServer(client, "H.1")).toEqual({
      ok: false,
      error: "PermissionDenied: START_HUNT",
    });
  });

  it("treats no row or Stopped=false as a refusal, even with nothing in the log", async () => {
    expect((await stopHuntOnServer(fakeClient([{ rows: [] }]), "H.1")).ok).toBe(false);
    expect((await stopHuntOnServer(fakeClient([{ rows: [{ Stopped: false }] }]), "H.1")).ok).toBe(false);
  });

  it("reports a network failure instead of throwing", async () => {
    const client = fakeClient([new Error("connect ECONNREFUSED")]);
    expect(await stopHuntOnServer(client, "H.1")).toEqual({ ok: false, error: "connect ECONNREFUSED" });
  });

  it("refuses a hunt id that is not a Velociraptor hunt id, and runs nothing", async () => {
    const client = fakeClient();
    const out = await stopHuntOnServer(client, "H.1') FROM scope() --");
    expect(out.ok).toBe(false);
    expect(client.programs).toEqual([]);
  });
});

describe("deleteHuntOnServer", () => {
  it("stops the hunt first, then deletes it for real", async () => {
    const client = fakeClient();
    expect(await deleteHuntOnServer(client, "H.XYZ")).toEqual({ ok: true });
    expect(client.programs).toEqual([
      "SELECT hunt_update(hunt_id='H.XYZ', stop=TRUE) AS Stopped FROM scope()",
      "SELECT * FROM hunt_delete(hunt_id='H.XYZ', really_do_it=TRUE)",
    ]);
  });

  it("reports a refused delete (it needs SERVER_ADMIN)", async () => {
    const client = fakeClient([{}, { rows: [], reason: "PermissionDenied: SERVER_ADMIN" }]);
    expect(await deleteHuntOnServer(client, "H.XYZ")).toEqual({
      ok: false,
      error: "stopped, but not deleted: PermissionDenied: SERVER_ADMIN",
    });
  });

  it("does not try to delete when the stop failed", async () => {
    const client = fakeClient([new Error("timeout")]);
    expect(await deleteHuntOnServer(client, "H.XYZ")).toEqual({ ok: false, error: "timeout" });
    expect(client.programs).toHaveLength(1);
  });
});
