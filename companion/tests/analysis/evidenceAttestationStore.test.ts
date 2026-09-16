import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EvidenceAttestationStore,
  type EvidenceAttestation,
} from "../../src/analysis/evidenceAttestationStore.js";

let dir = "";
const cases = { stateDir: () => dir } as unknown as ConstructorParameters<typeof EvidenceAttestationStore>[0];

function attestation(
  over: Partial<Pick<EvidenceAttestation, "evidenceClass" | "confirmedBy" | "confirmedAt" | "reason">> = {},
): Pick<EvidenceAttestation, "evidenceClass" | "confirmedBy" | "confirmedAt" | "reason"> {
  return {
    evidenceClass: "execution",
    confirmedBy: "a.analyst@example.invalid",
    confirmedAt: "2026-08-13T09:41:00Z",
    reason: "Reviewed the full Prefetch and Sysmon export against the incident window",
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "evidence-attestation-"));
});

describe("EvidenceAttestationStore", () => {
  it("returns an empty list and no active classes when the file does not exist", async () => {
    const store = new EvidenceAttestationStore(cases);
    expect(await store.load("c1")).toEqual([]);
    expect(await store.activeClasses("c1")).toEqual(new Set());
  });

  it("rejects an attestation with no reason — never a bare checkbox", async () => {
    const store = new EvidenceAttestationStore(cases);
    await expect(store.attest("c1", attestation({ reason: "" }))).rejects.toBeTruthy();
  });

  it("attests a class and it becomes active", async () => {
    const store = new EvidenceAttestationStore(cases);
    await store.attest("c1", attestation());
    expect(await store.activeClasses("c1")).toEqual(new Set(["execution"]));
  });

  it("appends, never overwrites — attesting twice keeps both entries in the audit trail", async () => {
    const store = new EvidenceAttestationStore(cases);
    await store.attest("c1", attestation({ reason: "first pass" }));
    const all = await store.attest(
      "c1",
      attestation({ reason: "second pass, more thorough", confirmedAt: "2026-08-14T00:00:00Z" }),
    );
    expect(all).toHaveLength(2);
    expect(all[0].reason).toBe("first pass");
    expect(all[1].reason).toBe("second pass, more thorough");
  });

  it("revoking the current attestation removes the class from activeClasses", async () => {
    const store = new EvidenceAttestationStore(cases);
    await store.attest("c1", attestation());
    await store.revoke("c1", "execution", "b.reviewer@example.invalid", "2026-08-15T00:00:00Z");
    expect(await store.activeClasses("c1")).toEqual(new Set());
  });

  it("revoke targets the LATEST entry, not an earlier superseded one, when re-attested without revoking first", async () => {
    // A real bug this test pins: revoking must never mark the OLDEST unrevoked entry for a class
    // when a newer, un-revoked re-attestation exists — activeClasses() only ever looks at the
    // latest entry, so revoke must agree about which row that is.
    const store = new EvidenceAttestationStore(cases);
    await store.attest("c1", attestation({ reason: "first pass", confirmedAt: "2026-08-13T00:00:00Z" }));
    await store.attest("c1", attestation({ reason: "second pass", confirmedAt: "2026-08-14T00:00:00Z" }));
    const after = await store.revoke("c1", "execution", "b.reviewer@example.invalid", "2026-08-15T00:00:00Z");
    expect(await store.activeClasses("c1")).toEqual(new Set());
    // The FIRST entry stays exactly as it was — only the latest (second) entry gets the revocation.
    expect(after[0].revokedAt).toBeUndefined();
    expect(after[1].revokedAt).toBe("2026-08-15T00:00:00Z");
  });

  it("re-attesting after a revoke makes the class active again", async () => {
    const store = new EvidenceAttestationStore(cases);
    await store.attest("c1", attestation());
    await store.revoke("c1", "execution", "b.reviewer@example.invalid", "2026-08-15T00:00:00Z");
    await store.attest(
      "c1",
      attestation({ reason: "re-reviewed after new evidence arrived", confirmedAt: "2026-08-16T00:00:00Z" }),
    );
    expect(await store.activeClasses("c1")).toEqual(new Set(["execution"]));
  });

  it("revoking a class with nothing active is a no-op, not an error", async () => {
    const store = new EvidenceAttestationStore(cases);
    const before = await store.load("c1");
    const after = await store.revoke("c1", "execution", "b.reviewer@example.invalid", "2026-08-15T00:00:00Z");
    expect(after).toEqual(before);
  });

  it("tracks multiple distinct evidence classes independently", async () => {
    const store = new EvidenceAttestationStore(cases);
    await store.attest("c1", attestation({ evidenceClass: "execution" }));
    await store.attest(
      "c1",
      attestation({ evidenceClass: "network", reason: "Full PCAP for the window reviewed" }),
    );
    expect(await store.activeClasses("c1")).toEqual(new Set(["execution", "network"]));
    await store.revoke("c1", "execution", "b.reviewer@example.invalid", "2026-08-15T00:00:00Z");
    expect(await store.activeClasses("c1")).toEqual(new Set(["network"]));
  });

  it("keeps every attestation when two analysts append concurrently", async () => {
    const store = new EvidenceAttestationStore(cases);
    await Promise.all([
      store.attest("c1", attestation({ evidenceClass: "execution" })),
      store.attest("c1", attestation({ evidenceClass: "network", reason: "Full PCAP reviewed" })),
      store.attest(
        "c1",
        attestation({ evidenceClass: "persistence", reason: "Registry/task review complete" }),
      ),
    ]);
    const all = await store.load("c1");
    expect(all).toHaveLength(3);
  });

  it("does not let one failed attest poison the queue for the next writer", async () => {
    const store = new EvidenceAttestationStore(cases);
    await expect(store.attest("c1", attestation({ evidenceClass: "bogus" as never }))).rejects.toBeTruthy();
    await store.attest("c1", attestation());
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("throws on a corrupt file and leaves it untouched", async () => {
    await writeFile(join(dir, "evidence-attestations.json"), "{ not json", "utf8");
    await expect(new EvidenceAttestationStore(cases).load("c1")).rejects.toThrow(
      /evidence-attestations\.json/,
    );
  });

  it("throws when the file parses but does not match the schema", async () => {
    await writeFile(join(dir, "evidence-attestations.json"), JSON.stringify({ version: 1 }), "utf8");
    await expect(new EvidenceAttestationStore(cases).load("c1")).rejects.toThrow(
      /evidence-attestations\.json/,
    );
  });
});
