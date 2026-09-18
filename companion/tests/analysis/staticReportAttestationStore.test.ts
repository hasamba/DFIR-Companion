import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  StaticReportAttestationStore,
  InvalidStaticReportAttestationError,
  volumeToken,
} from "../../src/analysis/staticReportAttestationStore.js";

import { mkdir } from "node:fs/promises";
import { ZodError } from "zod";

let dir = "";
// Per-case dirs like the real CaseStore, so a cross-case isolation test means something.
const cases = {
  stateDir: (caseId: string) => join(dir, caseId),
} as unknown as ConstructorParameters<typeof StaticReportAttestationStore>[0];

type NewInput = Parameters<StaticReportAttestationStore["create"]>[1];

const FP_A = "a".repeat(64);
const FP_B = "b".repeat(64);
const SHA_1 = "1".repeat(64);
const SHA_2 = "2".repeat(64);

function attestation(over: Partial<NewInput> = {}): NewInput {
  return {
    reportFingerprint: FP_A,
    tool: "olevba",
    subjectHost: "WS-01",
    attestedBy: "a.analyst@example.invalid",
    attestedAt: "2026-09-18T00:00:00Z",
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "static-report-attestation-"));
  await mkdir(join(dir, "c1"));
  await mkdir(join(dir, "c2"));
});

describe("volumeToken (review finding M-7)", () => {
  it("parses a drive letter, a volume GUID and an NT device token with filePath's own grammar", () => {
    expect(volumeToken("E:")).toEqual({ volume: "e", volumeKind: "drive" });
    expect(volumeToken("c:\\")).toEqual({ volume: "c", volumeKind: "drive" });
    expect(volumeToken("\\VOLUME{ABC-123}")).toEqual({ volume: "{abc-123}", volumeKind: "guid" });
    expect(volumeToken("\\Device\\HarddiskVolume3")).toEqual({
      volume: "harddiskvolume3",
      volumeKind: "device",
    });
  });

  it("returns null for a token that names no volume — a bare letter, a POSIX mount, empty", () => {
    expect(volumeToken("C")).toBeNull();
    expect(volumeToken("/mnt/img1")).toBeNull();
    expect(volumeToken("")).toBeNull();
  });
});

describe("StaticReportAttestationStore", () => {
  it("returns an empty list when the file does not exist", async () => {
    const store = new StaticReportAttestationStore(cases);
    expect(await store.load("c1")).toEqual([]);
    expect(await store.active("c1")).toEqual([]);
  });

  it("creates an attestation with server-derived id and stores the host raw", async () => {
    const store = new StaticReportAttestationStore(cases);
    const a = await store.create("c1", attestation({ subjectHost: "  WS-01.corp.local  " }));
    expect(a.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(a.subjectHost).toBe("WS-01.corp.local");
    expect(a.digestCrossCheck).toBe("none");
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("rejects a malformed fingerprint, an empty host and an unknown tool", async () => {
    const store = new StaticReportAttestationStore(cases);
    await expect(store.create("c1", attestation({ reportFingerprint: "abc" }))).rejects.toBeInstanceOf(
      ZodError,
    );
    await expect(store.create("c1", attestation({ subjectHost: "   " }))).rejects.toBeInstanceOf(ZodError);
    await expect(
      store.create("c1", attestation({ tool: "pesieve" as unknown as "olevba" })),
    ).rejects.toBeInstanceOf(ZodError);
  });

  it("normalizes evidenceVolume tokens at write time and rejects one that names no volume", async () => {
    const store = new StaticReportAttestationStore(cases);
    const a = await store.create(
      "c1",
      attestation({ evidenceVolume: { mountPoint: "E:\\", originalVolume: "c:" } }),
    );
    expect(a.evidenceVolume).toEqual({
      mountPoint: { volume: "e", volumeKind: "drive" },
      originalVolume: { volume: "c", volumeKind: "drive" },
    });
    await expect(
      store.create("c1", attestation({ evidenceVolume: { mountPoint: "C" } })),
    ).rejects.toBeInstanceOf(InvalidStaticReportAttestationError);
  });

  it("rejects a documentSha256 equal to the report fingerprint — the analyst hashed the report, not the document (M-3)", async () => {
    const store = new StaticReportAttestationStore(cases);
    await expect(store.create("c1", attestation({ documentSha256: FP_A }))).rejects.toThrow(
      /report, not the document/,
    );
  });

  it("vetoes a documentSha256 that disagrees with the tool-reported sha256 and records the cross-check when they agree (M-3)", async () => {
    const store = new StaticReportAttestationStore(cases);
    await expect(
      store.create("c1", attestation({ documentSha256: SHA_1, toolReportedSha256: SHA_2 })),
    ).rejects.toThrow(/disagrees/);
    const ok = await store.create(
      "c1",
      attestation({ documentSha256: SHA_1, toolReportedSha256: SHA_1.toUpperCase() }),
    );
    expect(ok.digestCrossCheck).toBe("tool-sha256");
    expect(ok.documentSha256).toBe(SHA_1);
  });

  it("records md5-only-unchecked when the tool reported only an md5 and the analyst supplied none, tool-md5 when both agree, and rejects a disagreeing analyst md5 (M-3, code review #6/#13)", async () => {
    const store = new StaticReportAttestationStore(cases);
    const a = await store.create(
      "c1",
      attestation({ documentSha256: SHA_1, toolReportedMd5: "f".repeat(32) }),
    );
    expect(a.digestCrossCheck).toBe("md5-only-unchecked");
    await store.revoke("c1", a.id, "x", "2026-09-18T01:00:00Z");
    const b = await store.create(
      "c1",
      attestation({ documentSha256: SHA_1, documentMd5: "F".repeat(32), toolReportedMd5: "f".repeat(32) }),
    );
    expect(b.digestCrossCheck).toBe("tool-md5");
    expect(b.documentMd5).toBe("f".repeat(32));
    await expect(
      store.create(
        "c1",
        attestation({
          reportFingerprint: FP_B,
          documentMd5: "e".repeat(32),
          toolReportedMd5: "f".repeat(32),
        }),
      ),
    ).rejects.toThrow(/documentMd5 .* disagrees/);
  });

  it("allows only one ACTIVE attestation per fingerprint (M-1)", async () => {
    const store = new StaticReportAttestationStore(cases);
    await store.create("c1", attestation());
    await expect(store.create("c1", attestation({ subjectHost: "WS-02" }))).rejects.toThrow(
      /already has an active attestation/,
    );
  });

  it("enforces one-active inside the append queue — two concurrent creates cannot both land (M-1)", async () => {
    const store = new StaticReportAttestationStore(cases);
    const results = await Promise.allSettled([
      store.create("c1", attestation({ subjectHost: "WS-01" })),
      store.create("c1", attestation({ subjectHost: "WS-02" })),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await store.active("c1")).toHaveLength(1);
  });

  it("rejects a second ACTIVE attestation binding the same document digest to a different host (M-2)", async () => {
    const store = new StaticReportAttestationStore(cases);
    await store.create("c1", attestation({ documentSha256: SHA_1, subjectHost: "ws-01" }));
    await expect(
      store.create(
        "c1",
        attestation({ reportFingerprint: FP_B, toolReportedSha256: SHA_1, subjectHost: "WS-02" }),
      ),
    ).rejects.toThrow(/different subject host/);
    // Same host spelled differently is NOT a conflict — canonicalHostName folds case and a trailing dot.
    const same = await store.create(
      "c1",
      attestation({ reportFingerprint: FP_B, toolReportedSha256: SHA_1, subjectHost: "WS-01." }),
    );
    expect(same.subjectHost).toBe("WS-01.");
  });

  it("revokes by id, 404-style error on an unknown id, no-op on an already-revoked known id (M-8)", async () => {
    const store = new StaticReportAttestationStore(cases);
    const a = await store.create("c1", attestation());
    const after = await store.revoke("c1", a.id, "b.analyst", "2026-09-18T01:00:00Z", "wrong host");
    expect(after[0].revokedAt).toBe("2026-09-18T01:00:00Z");
    expect(after[0].revokedReason).toBe("wrong host");
    expect(await store.active("c1")).toEqual([]);
    const again = await store.revoke("c1", a.id, "c.analyst", "2026-09-18T02:00:00Z");
    expect(again[0].revokedBy).toBe("b.analyst");
    await expect(store.revoke("c1", "nope", "x", "2026-09-18T03:00:00Z")).rejects.toThrow(/not found/);
  });

  it("frees the fingerprint for a new attestation once the old one is revoked, and records supersedesId", async () => {
    const store = new StaticReportAttestationStore(cases);
    const a = await store.create("c1", attestation({ subjectHost: "WS-01" }));
    await store.revoke("c1", a.id, "b", "2026-09-18T01:00:00Z");
    const b = await store.create("c1", attestation({ subjectHost: "WS-02", supersedesId: a.id }));
    expect(b.supersedesId).toBe(a.id);
    expect(await store.active("c1")).toHaveLength(1);
  });

  it("rejects supersedesId that is unknown or still active", async () => {
    const store = new StaticReportAttestationStore(cases);
    const a = await store.create("c1", attestation({ reportFingerprint: FP_A }));
    await expect(
      store.create("c1", attestation({ reportFingerprint: FP_B, supersedesId: "ghost" })),
    ).rejects.toBeInstanceOf(InvalidStaticReportAttestationError);
    await expect(
      store.create("c1", attestation({ reportFingerprint: FP_B, supersedesId: a.id })),
    ).rejects.toThrow(/must be revoked/);
  });

  it("fails closed on a corrupt file and leaves it untouched", async () => {
    const store = new StaticReportAttestationStore(cases);
    await writeFile(join(dir, "c1", "static-report-attestations.json"), "{not json");
    await expect(store.load("c1")).rejects.toThrow(/not valid JSON/);
    await writeFile(join(dir, "c1", "static-report-attestations.json"), JSON.stringify({ version: 1 }));
    await expect(store.load("c1")).rejects.toThrow(/does not match/);
  });

  it("keeps cases isolated on the same store — c2 never sees c1's attestation and may attest the same fingerprint", async () => {
    const store = new StaticReportAttestationStore(cases);
    await store.create("c1", attestation({ subjectHost: "ws-01" }));
    expect(await store.load("c2")).toEqual([]);
    const other = await store.create("c2", attestation({ subjectHost: "ws-02" }));
    expect(other.subjectHost).toBe("ws-02");
    expect(await store.load("c1")).toHaveLength(1);
  });
});
