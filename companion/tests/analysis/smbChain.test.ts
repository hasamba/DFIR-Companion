// Importer half of #933 item 4, #1085: Suricata `event_type: "smb"` rows, joined by file identity
// (fuid), never by share context (session_id/tree_id) alone.
import { describe, it, expect } from "vitest";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { readSuricataSmb } from "../../src/analysis/smbChainRead.js";
import {
  addSmb,
  emptySmbOperations,
  joinSmbChains,
  shareLeaf,
  SMB_BUCKET_MAX,
} from "../../src/analysis/smbChainJoin.js";
import { mapSmbRows, tallySmbChains } from "../../src/analysis/smbChainRows.js";

const CLIENT = "203.0.113.9";
const SERVER = "198.51.100.7";

function smb(over: Record<string, unknown> = {}): Record<string, unknown> {
  const { smb: smbOver, ...rest } = over;
  return {
    timestamp: "2024-01-01T00:00:00.000000+0000",
    event_type: "smb",
    src_ip: CLIENT,
    dest_ip: SERVER,
    dest_port: 445,
    flow_id: "FL1",
    tx_id: "1",
    smb: {
      id: 1,
      session_id: "S1",
      tree_id: "T1",
      command: "SMB2_COMMAND_CREATE",
      status: "STATUS_SUCCESS",
      status_code: "0x0",
      dialect: "3.1.1",
      share: "Finance$",
      share_type: "FILE",
      filename: "report.xlsx",
      fuid: "F1",
      disposition: "FILE_OPEN",
      access: "normal",
      ...(smbOver as Record<string, unknown> | undefined),
    },
    ...rest,
  };
}

const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n");
const parse = (rows: object[]) => parseNetworkLogs(ndjson(rows));
const smbEvents = (r: ReturnType<typeof parse>) => r.events.filter((e) => e.description.startsWith("SMB "));

describe("open-vs-create outcome wording", () => {
  it("FILE_OPEN + success says an existing object was opened", () => {
    const r = parse([smb()]);
    const rows = smbEvents(r);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain("opened an existing object");
    expect(rows[0].canonical?.smb?.outcome).toBe("opened-existing");
    expect(rows[0].severity).toBe("Info");
  });

  it("FILE_CREATE + success says a new object was created", () => {
    const r = parse([smb({ smb: { disposition: "FILE_CREATE", fuid: "F2" } })]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("created a new object");
    expect(row.canonical?.smb?.outcome).toBe("created-new");
  });

  it("FILE_OVERWRITE + success says an existing object was overwritten", () => {
    const r = parse([smb({ smb: { disposition: "FILE_OVERWRITE", fuid: "F3" } })]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("overwrote an existing object");
    expect(row.canonical?.smb?.outcome).toBe("overwritten-existing");
  });

  it.each(["FILE_OPEN_IF", "FILE_OVERWRITE_IF", "FILE_SUPERSEDE"])(
    "%s + success is worded as ambiguous, never guessed",
    (disposition) => {
      const r = parse([smb({ smb: { disposition, fuid: "F4" } })]);
      const row = smbEvents(r)[0];
      expect(row.description).toContain("outcome not determinable from this record");
      expect(row.canonical?.smb?.outcome).toBe("requested-ambiguous");
    },
  );

  it("a denied CREATE is worded as a denial and stays Info severity", () => {
    const r = parse([
      smb({ smb: { status: "STATUS_ACCESS_DENIED", status_code: "0xc0000022", fuid: "F5" } }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("denied");
    expect(row.description).toContain("STATUS_ACCESS_DENIED");
    expect(row.canonical?.smb?.outcome).toBe("denied");
    expect(row.severity).toBe("Info");
  });

  it("a not-found open is a denial, not silently dropped", () => {
    const r = parse([
      smb({ smb: { status: "STATUS_OBJECT_NAME_NOT_FOUND", status_code: "0xc0000034", fuid: "F6" } }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("denied");
    expect(row.canonical?.smb?.outcome).toBe("denied");
  });

  it("a non-CREATE command has no outcome claim at all", () => {
    const r = parse([
      smb({ smb: { command: "SMB2_COMMAND_TREE_CONNECT", disposition: undefined, fuid: undefined } }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.canonical?.smb?.outcome).toBeUndefined();
  });
});

describe("share type", () => {
  it("a PIPE share is shown distinctly from a FILE share", () => {
    const r = parse([
      smb({
        smb: {
          command: "SMB2_COMMAND_TREE_CONNECT",
          disposition: undefined,
          fuid: undefined,
          share: "\\\\SERVER\\PIPE\\svcctl".slice(0, 260),
          share_type: "PIPE",
          filename: undefined,
        },
      }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("[share type: PIPE]");
  });
});

describe("file-identity join — never share context alone", () => {
  it("two files opened concurrently under the same session+tree stay two separate chains", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "FA", filename: "alpha.txt" } }), 0));
    addSmb(
      ops,
      readSuricataSmb(smb({ smb: { fuid: "FB", filename: "beta.txt", disposition: "FILE_CREATE" } }), 1),
    );
    addSmb(
      ops,
      readSuricataSmb(smb({ smb: { command: "SMB2_COMMAND_WRITE", fuid: "FA", disposition: undefined } }), 2),
    );
    const chains = joinSmbChains(ops);
    const alpha = chains.find((c) => c.create?.fuid === "FA");
    const beta = chains.find((c) => c.create?.fuid === "FB");
    expect(alpha?.operations).toHaveLength(1);
    expect(alpha?.operations[0]?.command).toBe("SMB2_COMMAND_WRITE");
    expect(beta?.operations).toHaveLength(0);
  });

  it("the same session_id/tree_id/fuid value on two different flows never collides", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ flow_id: "FLOW-A", smb: { fuid: "SAME" } }), 0));
    addSmb(ops, readSuricataSmb(smb({ flow_id: "FLOW-B", smb: { fuid: "SAME" } }), 1));
    const chains = joinSmbChains(ops);
    const creates = chains.filter((c) => c.create);
    expect(creates).toHaveLength(2);
    expect(new Set(creates.map((c) => c.key)).size).toBe(2);
  });

  it("a record with no fuid at all is its own unjoined chain, never attached to the latest CREATE", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "FA" } }), 0));
    addSmb(
      ops,
      readSuricataSmb(
        smb({ smb: { command: "SMB2_COMMAND_CLOSE", fuid: undefined, disposition: undefined } }),
        1,
      ),
    );
    const chains = joinSmbChains(ops);
    const unattached = chains.find((c) => c.joinState === "no fuid on this record");
    expect(unattached).toBeDefined();
    expect(unattached?.operations).toHaveLength(1);
    const createChain = chains.find((c) => c.create?.fuid === "FA");
    expect(createChain?.operations).toHaveLength(0);
  });

  it("a READ with no matching CREATE in the upload says so explicitly", () => {
    const ops = emptySmbOperations();
    addSmb(
      ops,
      readSuricataSmb(
        smb({ smb: { command: "SMB2_COMMAND_READ", fuid: "ORPHAN", disposition: undefined } }),
        0,
      ),
    );
    const chains = joinSmbChains(ops);
    expect(chains[0].joinState).toBe("no matching file record in this upload");
    expect(chains[0].create).toBeUndefined();
  });

  it("a record missing every identifier is its own row, never dropped", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb({ event_type: "smb", timestamp: "2024-01-01T00:00:00Z" }, 0));
    const chains = joinSmbChains(ops);
    expect(chains).toHaveLength(1);
    expect(chains[0].operations[0].command).toBe("-");
  });

  it("overflow past SMB_BUCKET_MAX keeps the CREATE plus the most recent operations, states the true total", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "BUSY" } }), 0));
    const total = SMB_BUCKET_MAX + 10;
    for (let i = 0; i < total; i++) {
      addSmb(
        ops,
        readSuricataSmb(
          smb({
            smb: {
              command: "SMB2_COMMAND_WRITE",
              fuid: "BUSY",
              disposition: undefined,
              filename: `op-${i}.bin`,
            },
          }),
          i + 1,
        ),
      );
    }
    const chains = joinSmbChains(ops);
    const chain = chains.find((c) => c.create?.fuid === "BUSY")!;
    expect(chain.operationsTotal).toBe(total);
    expect(chain.operations).toHaveLength(SMB_BUCKET_MAX);
    // most recent kept, not the earliest
    expect(chain.operations[0].filename).toBe(`op-${total - SMB_BUCKET_MAX}.bin`);
    expect(chain.operations.at(-1)?.filename).toBe(`op-${total - 1}.bin`);
  });

  it("a fuid with no flow id never joins another record sharing that fuid, even from what looks like the same flow", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ flow_id: undefined, smb: { fuid: "NOFLOW" } }), 0));
    addSmb(
      ops,
      readSuricataSmb(
        smb({
          flow_id: undefined,
          smb: { command: "SMB2_COMMAND_WRITE", fuid: "NOFLOW", disposition: undefined },
        }),
        1,
      ),
    );
    const chains = joinSmbChains(ops);
    expect(chains.every((c) => c.joinState !== "joined")).toBe(true);
    expect(chains).toHaveLength(2);
    expect(chains.every((c) => c.operations.length === 1)).toBe(true);
  });

  it("the row for a fuid-but-no-flow-id record discloses that it could not be joined", () => {
    const r = parse([smb({ flow_id: undefined, smb: { fuid: "NOFLOW" } })]);
    const row = smbEvents(r)[0];
    expect(row.canonical?.smb?.createJoinState).toBe("no flow id on this record");
    expect(row.description).toContain("[create: no flow id on this record]");
  });
});

describe("TREE_CONNECT share context propagates to operations on its tree (#1092)", () => {
  it("shareLeaf takes the last UNC segment", () => {
    expect(shareLeaf("\\\\admin-pc\\c$")).toBe("c$");
    expect(shareLeaf("C$")).toBe("C$");
  });

  it("a CREATE with no share of its own inherits its tree's TREE_CONNECT share, as a bare leaf", () => {
    const ops = emptySmbOperations();
    addSmb(
      ops,
      readSuricataSmb(
        smb({
          smb: {
            command: "SMB2_COMMAND_TREE_CONNECT",
            disposition: undefined,
            fuid: undefined,
            share: "\\\\admin-pc\\c$",
            share_type: "FILE",
            filename: undefined,
          },
        }),
        0,
      ),
    );
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "F1", share: undefined } }), 1));
    const chains = joinSmbChains(ops);
    const fileChain = chains.find((c) => c.create?.fuid === "F1");
    expect(fileChain?.create?.share).toBe("c$");
    expect(fileChain?.create?.shareType).toBe("FILE");
  });

  it("an operation's own share, when present, is never overridden by the tree's", () => {
    const ops = emptySmbOperations();
    addSmb(
      ops,
      readSuricataSmb(
        smb({
          smb: {
            command: "SMB2_COMMAND_TREE_CONNECT",
            disposition: undefined,
            fuid: undefined,
            share: "\\\\admin-pc\\c$",
            filename: undefined,
          },
        }),
        0,
      ),
    );
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "F1", share: "Finance$" } }), 1));
    const chains = joinSmbChains(ops);
    const fileChain = chains.find((c) => c.create?.fuid === "F1");
    expect(fileChain?.create?.share).toBe("Finance$");
  });

  it("a different tree_id (or flow) never inherits an unrelated tree's share", () => {
    const ops = emptySmbOperations();
    addSmb(
      ops,
      readSuricataSmb(
        smb({
          smb: {
            command: "SMB2_COMMAND_TREE_CONNECT",
            disposition: undefined,
            fuid: undefined,
            tree_id: "T1",
            share: "\\\\admin-pc\\c$",
            filename: undefined,
          },
        }),
        0,
      ),
    );
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "F1", tree_id: "T2", share: undefined } }), 1));
    const chains = joinSmbChains(ops);
    const fileChain = chains.find((c) => c.create?.fuid === "F1");
    expect(fileChain?.create?.share).toBeUndefined();
  });
});

describe("truncation and join-state disclosure on the row itself", () => {
  it("an operation with no matching CREATE in the upload discloses it in its own description", () => {
    const r = parse([smb({ smb: { command: "SMB2_COMMAND_READ", fuid: "ORPHAN", disposition: undefined } })]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("[create: no matching file record in this upload]");
    expect(row.canonical?.smb?.createJoinState).toBe("no matching file record in this upload");
  });

  it("a truncated chain's operation rows state how many earlier operations are not shown", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "BUSY" } }), 0));
    const total = SMB_BUCKET_MAX + 5;
    for (let i = 0; i < total; i++) {
      addSmb(
        ops,
        readSuricataSmb(
          smb({ smb: { command: "SMB2_COMMAND_WRITE", fuid: "BUSY", disposition: undefined } }),
          i + 1,
        ),
      );
    }
    const chains = joinSmbChains(ops);
    const rows = mapSmbRows(chains, []);
    const writeRow = rows.find((e) => e.description.includes("SMB2_COMMAND_WRITE"));
    expect(writeRow?.description).toContain(`[+5 earlier operations on this file not shown]`);
  });
});

describe("global observation overflow", () => {
  it("is disclosed as its own row, never silently absorbed into the generic drop count", () => {
    const rows = mapSmbRows([], [], 42);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain("42 records not read");
  });

  it("emits nothing when there is no overflow", () => {
    expect(mapSmbRows([], [], 0)).toEqual([]);
  });
});

describe("authentication context is not discarded", () => {
  it("shows an NTLM domain/user on the row that carries it", () => {
    const r = parse([
      smb({
        smb: {
          command: "SMB2_COMMAND_SESSION_SETUP",
          disposition: undefined,
          fuid: undefined,
          ntlmssp: { domain: "CORP", user: "alice" },
        },
      }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("[ntlm: CORP\\alice]");
    expect(row.canonical?.smb?.ntlmDomain).toBe("CORP");
    expect(row.canonical?.smb?.ntlmUser).toBe("alice");
  });

  it("hostile characters in an NTLM user never read as a trusted tag", () => {
    const r = parse([
      smb({
        smb: {
          command: "SMB2_COMMAND_SESSION_SETUP",
          disposition: undefined,
          fuid: undefined,
          ntlmssp: { domain: "CORP", user: "alice[admin]" },
        },
      }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.description).not.toMatch(/\[admin\]/);
    expect(row.description).toContain("(admin)");
  });
});

describe("fileinfo join rejects a mismatched sensor or endpoint", () => {
  function fileinfo(over: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      timestamp: "2024-01-01T00:00:00.000000+0000",
      event_type: "fileinfo",
      app_proto: "smb",
      src_ip: SERVER,
      dest_ip: CLIENT,
      flow_id: "FL1",
      tx_id: "1",
      fileinfo: { filename: "report.xlsx", size: 4096, sha256: "c".repeat(64), state: "CLOSED" },
      ...over,
    };
  }

  it("a candidate from a different sensor is not matched, even with identical flow_id + tx_id", () => {
    const r = parse([
      smb({
        smb: { command: "SMB2_COMMAND_READ", fuid: "F1", disposition: undefined },
        "observer.name": "sensor-a",
      }),
      { ...fileinfo(), "observer.name": "sensor-b" },
    ]);
    const rows = smbEvents(r);
    const readRow = rows.find((e) => e.description.includes("SMB SMB2_COMMAND_READ"));
    expect(readRow?.canonical?.smb?.fileinfoJoin).toBe("no match");
  });

  it("a candidate whose endpoints contradict this operation's is not matched", () => {
    const r = parse([
      smb({ smb: { command: "SMB2_COMMAND_READ", fuid: "F1", disposition: undefined } }),
      { ...fileinfo(), src_ip: "203.0.113.200", dest_ip: "198.51.100.200" },
    ]);
    const rows = smbEvents(r);
    const readRow = rows.find((e) => e.description.includes("SMB SMB2_COMMAND_READ"));
    expect(readRow?.canonical?.smb?.fileinfoJoin).toBe("no match");
  });
});

describe("success and a later denial never silently collapse", () => {
  it("two operations on the same file that differ only in status/disposition stay two rows through aggregation", () => {
    const r = parse([
      smb({ smb: { fuid: "DUP" } }),
      smb({
        smb: {
          command: "SMB2_COMMAND_WRITE",
          fuid: "DUP",
          disposition: undefined,
          status: "STATUS_ACCESS_DENIED",
          status_code: "0xc0000022",
        },
      }),
    ]);
    const rows = smbEvents(r);
    expect(rows).toHaveLength(2);
    expect(rows.some((e) => e.description.includes("opened an existing object"))).toBe(true);
    expect(rows.some((e) => e.description.includes("denied"))).toBe(true);
  });

  it("two byte-for-byte identical operations DO fold into one aggregated row", () => {
    const r = parse([smb(), smb()]);
    const rows = smbEvents(r);
    expect(rows).toHaveLength(1);
    expect(rows[0].count).toBe(2);
  });
});

describe("fileinfo join", () => {
  function fileinfo(over: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      timestamp: "2024-01-01T00:00:00.000000+0000",
      event_type: "fileinfo",
      app_proto: "smb",
      src_ip: SERVER,
      dest_ip: CLIENT,
      flow_id: "FL1",
      tx_id: "1",
      fileinfo: { filename: "report.xlsx", size: 4096, sha256: "a".repeat(64), state: "CLOSED" },
      ...over,
    };
  }

  it("matches a READ/WRITE to its fileinfo record by flow_id + tx_id", () => {
    const r = parse([
      smb({
        smb: { command: "SMB2_COMMAND_READ", fuid: "F1", disposition: undefined },
      }),
      fileinfo(),
    ]);
    const rows = smbEvents(r);
    const readRow = rows.find((e) => e.description.includes("SMB SMB2_COMMAND_READ"));
    expect(readRow?.description).toContain("bytes observed");
    expect(readRow?.description).toContain("sha256");
    expect(readRow?.canonical?.smb?.fileinfoJoin).toBe("matched");
  });

  it("says so explicitly when no fileinfo record matches", () => {
    const r = parse([smb({ smb: { command: "SMB2_COMMAND_READ", fuid: "F1", disposition: undefined } })]);
    const row = smbEvents(r)[0];
    expect(row.description).toContain("no matching fileinfo record in this upload");
    expect(row.canonical?.smb?.fileinfoJoin).toBe("no match");
  });

  it("states a conflict rather than picking one of two candidates", () => {
    const r = parse([
      smb({ smb: { command: "SMB2_COMMAND_READ", fuid: "F1", disposition: undefined } }),
      fileinfo(),
      fileinfo({ fileinfo: { filename: "other.bin", size: 10, sha256: "b".repeat(64) } }),
    ]);
    const rows = smbEvents(r);
    const readRow = rows.find((e) => e.description.includes("SMB SMB2_COMMAND_READ"));
    expect(readRow?.description).toContain("conflicting fileinfo records");
    expect(readRow?.canonical?.smb?.fileinfoJoin).toBe("conflict");
  });

  it("the existing fileinfo/app_proto:smb transfer row still parses unchanged", () => {
    const r = parse([fileinfo()]);
    expect(r.events.some((e) => e.description.startsWith("Transfer over SMB"))).toBe(true);
  });
});

describe("hostile client-controlled text", () => {
  it("brackets in a filename never read as a trusted [tag]", () => {
    const r = parse([smb({ smb: { filename: "report[proxy: served from cache].xlsx" } })]);
    const row = smbEvents(r)[0];
    expect(row.description).not.toMatch(/\[proxy: served from cache\]/);
    expect(row.description).toContain("(proxy: served from cache)");
  });

  it("a long run of hex in a share name is broken so it is never read as a bare hash", () => {
    const hexRun = "a".repeat(40);
    const r = parse([smb({ smb: { share: hexRun, filename: undefined } })]);
    const row = smbEvents(r)[0];
    expect(row.description).not.toContain(hexRun);
  });
});

describe("budget and tally", () => {
  it("tallySmbChains truncates to the budget without reordering the kept chains", () => {
    const ops = emptySmbOperations();
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "A" } }), 0));
    addSmb(ops, readSuricataSmb(smb({ smb: { fuid: "B" } }), 1));
    const chains = joinSmbChains(ops);
    const kept = tallySmbChains(chains, 1);
    expect(kept).toHaveLength(1);
  });

  it("mapSmbRows produces no rows for an empty chain list", () => {
    expect(mapSmbRows([], [])).toEqual([]);
  });
});

describe("top-level file identity, promoted for downstream correlation (#1092)", () => {
  it("a CREATE with a filename sets path at the top level", () => {
    const r = parse([smb()]);
    const row = smbEvents(r)[0];
    expect(row.path).toBe("report.xlsx");
  });

  it("a matched fileinfo join promotes sha256/md5 to the top level", () => {
    const r = parse([
      smb({ smb: { command: "SMB2_COMMAND_WRITE", fuid: "F1", disposition: undefined } }),
      {
        timestamp: "2024-01-01T00:00:00.000000+0000",
        event_type: "fileinfo",
        app_proto: "smb",
        src_ip: SERVER,
        dest_ip: CLIENT,
        flow_id: "FL1",
        tx_id: "1",
        fileinfo: { filename: "report.xlsx", size: 4096, sha256: "d".repeat(64), state: "CLOSED" },
      },
    ]);
    const rows = smbEvents(r);
    const writeRow = rows.find((e) => e.description.includes("SMB SMB2_COMMAND_WRITE"));
    expect(writeRow?.sha256).toBe("d".repeat(64));
  });

  it("a denied operation still names its target path (a fact worth showing either way)", () => {
    const r = parse([
      smb({ smb: { status: "STATUS_ACCESS_DENIED", status_code: "0xc0000022", fuid: "F7" } }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.path).toBe("report.xlsx");
  });

  it("a row with no filename sets no path", () => {
    const r = parse([
      smb({
        smb: {
          command: "SMB2_COMMAND_TREE_CONNECT",
          disposition: undefined,
          fuid: undefined,
          filename: undefined,
        },
      }),
    ]);
    const row = smbEvents(r)[0];
    expect(row.path).toBeUndefined();
  });
});
