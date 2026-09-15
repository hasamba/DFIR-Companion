import { describe, it, expect } from "vitest";
import {
  parseAzureStorageLog,
  mapAzureStorageLogRecord,
  AZURE_STORAGE_LOG_SOURCE,
} from "../../src/analysis/azureStorageLogImport.js";

function rec(over: Record<string, unknown> = {}) {
  return {
    time: "2024-05-14T12:00:49.745Z",
    resourceId:
      "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct1/blobServices/default",
    category: "StorageRead",
    operationName: "GetBlob",
    statusCode: 200,
    callerIpAddress: "203.0.113.9:44123",
    uri: "https://acct1.blob.core.windows.net/cont1/obj1.png",
    identity: {
      type: "OAuth",
      // A fake, obviously-not-real fingerprint — real ones are opaque hex (Microsoft's own docs
      // example is a genuine-looking SHA-256 hex string, which trips secret-scanner heuristics).
      tokenHash: "test-fake-token-hash-not-a-real-fingerprint",
      requester: { upn: "alice@corp.test", objectId: "obj-1", tenantId: "ten-1" },
      authorization: [{ result: "Granted" }],
    },
    properties: { accountName: "acct1" },
    ...over,
  };
}

function ndjson(...recs: object[]): string {
  return recs.map((r) => JSON.stringify(r)).join("\n");
}

describe("mapAzureStorageLogRecord — OAuth read", () => {
  it("maps a successful OAuth GetBlob as a Low read with actor identity", () => {
    const m = mapAzureStorageLogRecord(rec(), new Map(), 0)!;
    expect(m.severity).toBe("Low");
    // The RENDERED action, not the raw operationName (Codex review, P1) — cloudBulkRead.ts's
    // readCloudRecord() prefers canonical.event.action and only matches "get blob"/"list blobs".
    expect(m.canonical?.event.action).toBe("get blob");
    expect(m.canonical?.event.outcome).toBe("success");
    expect(m.canonical?.actor?.name).toBe("alice@corp.test");
    expect(m.canonical?.authentication?.mechanism).toBe("oauth");
    expect(m.canonical?.cloud?.resource).toBe("acct1/cont1/obj1.png");
    expect(m.sources).toEqual([AZURE_STORAGE_LOG_SOURCE]);
  });

  it("feeds the shared bulk-read pass with the exact 'get blob' action text", () => {
    // cloudBulkRead.ts's READ_ACTION_RE matches "get blob" verbatim — this is the one real
    // integration point with that file.
    const m = mapAzureStorageLogRecord(rec({ operationName: "GetBlob" }), new Map(), 0)!;
    expect(m.aggKey).toContain("azure-storage|getblob|");
    // The rendered action lives on canonical.event.action AND is what cloudBulkRead reads first.
  });

  // Codex review (P1) regression: a description-only assertion would not have caught this — only
  // running the row through cloudBulkRead.ts's own reader proves the integration actually works.
  it("is actually readable by cloudBulkRead.ts's readCloudRecord (end to end, not just aggKey text)", async () => {
    const { readCloudRecord } = await import("../../src/analysis/cloudBulkRead.js");
    const m = mapAzureStorageLogRecord(rec(), new Map(), 0)!;
    const forensic = { id: "e1", timestamp: m.timestamp, description: m.description, canonical: m.canonical };
    const r = readCloudRecord(forensic as never);
    expect(r).not.toBeNull();
    // splitResource() splits at the FIRST slash — container is the account name, object is the
    // rest of the path (matches cloudBulkRead.ts's own documented "bucket/key/parts" contract).
    expect(r?.container).toBe("acct1");
    expect(r?.object).toBe("cont1/obj1.png");
  });

  // Codex review (P1): two different requesters reading the same object must stay two rows, or
  // one reader's identity is lost and neither can reach the bulk-read threshold correctly.
  it("keeps two different requesters of the same object as distinct aggKeys", () => {
    const a = mapAzureStorageLogRecord(
      rec({
        identity: {
          type: "OAuth",
          requester: { upn: "alice@corp.test" },
          authorization: [{ result: "Granted" }],
        },
      }),
      new Map(),
      0,
    )!;
    const b = mapAzureStorageLogRecord(
      rec({
        identity: {
          type: "OAuth",
          requester: { upn: "bob@corp.test" },
          authorization: [{ result: "Granted" }],
        },
      }),
      new Map(),
      0,
    )!;
    expect(a.aggKey).not.toBe(b.aggKey);
  });
});

describe("mapAzureStorageLogRecord — IPv6 caller address", () => {
  it("preserves a bracketed IPv6 caller address with a port, not just its first hextet", () => {
    const m = mapAzureStorageLogRecord(rec({ callerIpAddress: "[2001:db8::1]:44123" }), new Map(), 0)!;
    expect(m.srcIp).toBe("2001:db8::1");
  });

  it("preserves a bare (portless) IPv6 caller address", () => {
    const m = mapAzureStorageLogRecord(rec({ callerIpAddress: "2001:db8::1" }), new Map(), 0)!;
    expect(m.srcIp).toBe("2001:db8::1");
  });

  it("still strips the port from a plain IPv4 caller address", () => {
    const m = mapAzureStorageLogRecord(rec({ callerIpAddress: "203.0.113.9:44123" }), new Map(), 0)!;
    expect(m.srcIp).toBe("203.0.113.9");
  });
});

describe("mapAzureStorageLogRecord — credential-only (Account Key / SAS)", () => {
  it("leaves actor unset for Account Key auth, carries the credential fingerprint instead", () => {
    const m = mapAzureStorageLogRecord(
      rec({
        identity: {
          type: "Account Key",
          tokenHash: "key1(test-fake-not-a-real-fingerprint)",
          authorization: [{ result: "Granted" }],
        },
      }),
      new Map(),
      0,
    )!;
    expect(m.canonical?.actor).toBeUndefined();
    expect(m.canonical?.authentication?.mechanism).toBe("account-key");
    expect(m.canonical?.authentication?.credentialId).toContain("key1(");
  });

  it("normalizes 'SAS Key' and 'Anonymous' auth-type spellings", () => {
    const sas = mapAzureStorageLogRecord(
      rec({ identity: { type: "SAS Key", authorization: [{ result: "Granted" }] } }),
      new Map(),
      0,
    )!;
    expect(sas.canonical?.authentication?.mechanism).toBe("sas");
    const anon = mapAzureStorageLogRecord(
      rec({ category: "StorageWrite", operationName: "PutBlob", identity: { type: "Anonymous" } }),
      new Map(),
      0,
    )!;
    expect(anon.canonical?.authentication?.mechanism).toBe("anonymous");
    expect(anon.severity).toBe("Medium"); // anonymous write is real signal
  });
});

describe("mapAzureStorageLogRecord — outcome handling", () => {
  it("a denied/failed read never gets the bulk-read action label", () => {
    const m = mapAzureStorageLogRecord(rec({ statusCode: 403 }), new Map(), 0)!;
    expect(m.canonical?.event.action).not.toBe("get blob"); // raw op name kept, not the grouped token
    expect(m.severity).toBe("Info");
    expect(m.description).toContain("statusCode 403");
  });

  it("a Denied authorization result on a write is flagged and graded Medium", () => {
    const m = mapAzureStorageLogRecord(
      rec({
        category: "StorageWrite",
        operationName: "PutBlob",
        identity: { type: "OAuth", authorization: [{ result: "Denied" }] },
      }),
      new Map(),
      0,
    )!;
    expect(m.severity).toBe("Medium");
    expect(m.mitre).toContain("T1530");
    expect(m.description).toContain("authorization denied");
  });
});

describe("mapAzureStorageLogRecord — SAS signature never leaks", () => {
  it("strips the query string (where a SAS signature lives) from every field", () => {
    const m = mapAzureStorageLogRecord(
      rec({ uri: "https://acct1.blob.core.windows.net/cont1/obj1.png?sv=2021&sig=SECRETSIGNATURE" }),
      new Map(),
      0,
    )!;
    expect(m.description).not.toContain("SECRETSIGNATURE");
    expect(m.description).not.toContain("sig=");
    expect(m.canonical?.cloud?.resource).not.toContain("SECRETSIGNATURE");
    expect(JSON.stringify(m)).not.toContain("SECRETSIGNATURE");
  });
});

describe("mapAzureStorageLogRecord — not a storage log", () => {
  it("returns null for a record with no recognizable category", () => {
    expect(mapAzureStorageLogRecord({ time: "x", operationName: "GetBlob" }, new Map(), 0)).toBeNull();
  });
});

describe("parseAzureStorageLog — end to end", () => {
  it("parses NDJSON and produces one bounded, aggregated event set", () => {
    const r = parseAzureStorageLog(ndjson(rec(), rec({ operationName: "ListBlobs" })));
    expect(r.total).toBe(2);
    expect(r.format).toBe("azure-storage-log");
    expect(r.events.length).toBeGreaterThan(0);
  });
});
