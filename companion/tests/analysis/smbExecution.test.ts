import { describe, it, expect } from "vitest";
import {
  corroborateSmbExecution,
  isSmbStagedWrite,
  isRpcPipeCall,
  isServiceOrTaskCreation,
  resolveShareToLocal,
  SMB_WRITE_EXECUTED_MARKER,
  RAN_SMB_STAGED_MARKER,
  PIPE_CALL_CORROBORATED_MARKER,
  SERVICE_TASK_FROM_PIPE_MARKER,
  STAGING_EXT as SMB_STAGING_EXT,
  BUCKET_MAX,
} from "../../src/analysis/smbExecution.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import { STAGING_EXT } from "../../src/analysis/stagingPaths.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

// #933 item 4, correlation half (#1092): a share write of an executable-shaped file corroborated
// by the evidence it ran; a service-control/task-scheduling pipe call corroborated by the
// service/task it may have preceded. Only ever raises; recomputed each merge.

interface Ev {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  path?: string;
  asset?: string;
  sha256?: string;
  md5?: string;
  sources?: string[];
  canonical?: {
    event?: { category?: string; type?: string };
    smb?: {
      command?: string;
      status?: string;
      outcome?: string;
      shareType?: string;
      share?: string;
      filename?: string;
    };
  };
}

const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();

const smbWrite = (over: Partial<Ev> = {}): Ev => ({
  id: "w1",
  timestamp: T,
  description: "SMB SMB2_COMMAND_CREATE report.exe — created a new object",
  severity: "Info",
  mitreTechniques: [],
  path: "report.exe",
  canonical: {
    event: { category: "network", type: "smb" },
    smb: {
      command: "SMB2_COMMAND_CREATE",
      status: "STATUS_SUCCESS",
      outcome: "created-new",
      shareType: "FILE",
      share: "Finance$",
    },
  },
  ...over,
});

const execProcess = (over: Partial<Ev> = {}): Ev => ({
  id: "p1",
  timestamp: at(300),
  description: "Sysmon 1 Process create: report.exe",
  severity: "Low",
  mitreTechniques: [],
  path: "C:\\Windows\\report.exe",
  asset: "WS-01",
  sources: ["Sysmon"],
  canonical: { event: { category: "process", type: "start" } },
  ...over,
});

const serviceCreated = (over: Partial<Ev> = {}): Ev => ({
  id: "svc1",
  timestamp: at(300),
  description: "EventLog Service installed (Security) (EID 4697)",
  severity: "Medium",
  mitreTechniques: ["T1543.003"],
  path: "C:\\Windows\\report.exe",
  asset: "WS-01",
  canonical: { event: { category: "service", type: "observation" } },
  ...over,
});

const taskCreated = (over: Partial<Ev> = {}): Ev => ({
  id: "task1",
  timestamp: at(300),
  description: "EventLog Scheduled task created (EID 4698)",
  severity: "Medium",
  mitreTechniques: ["T1053.005"],
  asset: "WS-01",
  canonical: { event: { category: "task", type: "observation" } },
  ...over,
});

// Suricata's own documented pipe-open shape: the pipe name is `smb.filename`, and the record
// carries no `share`/`share_type` at all (docs.suricata.io eve-json-format).
const pipeCall = (over: Partial<Ev> = {}): Ev => ({
  id: "pipe1",
  timestamp: T,
  description: "SMB SMB2_COMMAND_CREATE svcctl",
  severity: "Info",
  mitreTechniques: [],
  canonical: {
    event: { category: "network", type: "smb" },
    smb: { command: "SMB2_COMMAND_CREATE", status: "STATUS_SUCCESS", filename: "svcctl" },
  },
  ...over,
});

const run = (events: Ev[]) => corroborateSmbExecution(events);
const find = (out: Ev[], id: string) => out.find((e) => e.id === id)!;

describe("restated staging-extension list, pinned against the ingest-layer original (#1092)", () => {
  it("matches stagingPaths.ts's STAGING_EXT exactly — the timeline layer may not import it", () => {
    expect(SMB_STAGING_EXT).toBe(STAGING_EXT);
  });
});

describe("derived note registration (#1092)", () => {
  it("every new marker is registered in DERIVED_NOTE_NAMES", () => {
    for (const marker of [
      SMB_WRITE_EXECUTED_MARKER,
      RAN_SMB_STAGED_MARKER,
      PIPE_CALL_CORROBORATED_MARKER,
      SERVICE_TASK_FROM_PIPE_MARKER,
    ]) {
      expect(DERIVED_NOTE_NAMES).toContain(marker.slice(1, -1));
    }
  });
});

describe("isSmbStagedWrite guardrails", () => {
  it("a confirmed new object is a candidate", () => {
    expect(isSmbStagedWrite(smbWrite())).toBe(true);
  });
  it("an existing-file open is never a candidate", () => {
    expect(
      isSmbStagedWrite(
        smbWrite({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: {
              command: "SMB2_COMMAND_CREATE",
              status: "STATUS_SUCCESS",
              outcome: "opened-existing",
              shareType: "FILE",
            },
          },
        }),
      ),
    ).toBe(false);
  });
  it("an ambiguous _IF disposition is never a candidate", () => {
    expect(
      isSmbStagedWrite(
        smbWrite({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: {
              command: "SMB2_COMMAND_CREATE",
              status: "STATUS_SUCCESS",
              outcome: "requested-ambiguous",
              shareType: "FILE",
            },
          },
        }),
      ),
    ).toBe(false);
  });
  it("a denied CREATE is never a candidate", () => {
    expect(
      isSmbStagedWrite(
        smbWrite({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: {
              command: "SMB2_COMMAND_CREATE",
              status: "STATUS_ACCESS_DENIED",
              outcome: "denied",
              shareType: "FILE",
            },
          },
        }),
      ),
    ).toBe(false);
  });
  it("a WRITE with no success status is never a candidate", () => {
    expect(
      isSmbStagedWrite(
        smbWrite({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: { command: "SMB2_COMMAND_WRITE", status: "STATUS_ACCESS_DENIED", shareType: "FILE" },
          },
        }),
      ),
    ).toBe(false);
  });
  it("a WRITE with a success status is a candidate", () => {
    expect(
      isSmbStagedWrite(
        smbWrite({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: { command: "SMB2_COMMAND_WRITE", status: "STATUS_SUCCESS", shareType: "FILE" },
          },
        }),
      ),
    ).toBe(true);
  });
  it("a non-executable extension is never a candidate", () => {
    expect(isSmbStagedWrite(smbWrite({ path: "report.xlsx" }))).toBe(false);
  });
  it("a PIPE share is never a Join A candidate (that's Join B's job)", () => {
    expect(
      isSmbStagedWrite(
        smbWrite({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: {
              command: "SMB2_COMMAND_CREATE",
              status: "STATUS_SUCCESS",
              outcome: "created-new",
              shareType: "PIPE",
            },
          },
        }),
      ),
    ).toBe(false);
  });
});

describe("resolveShareToLocal", () => {
  it("a drive-letter admin share resolves to that local drive", () => {
    expect(resolveShareToLocal("C$", "temp\\a.exe")).toEqual({
      volume: "c",
      volumeKind: "drive",
      relative: "temp\\a.exe",
    });
  });
  it("ADMIN$ resolves to the Windows directory", () => {
    expect(resolveShareToLocal("ADMIN$", "a.exe")).toEqual({
      volume: "c",
      volumeKind: "drive",
      relative: "windows\\a.exe",
    });
  });
  it("a custom share resolves to nothing — no path guess", () => {
    expect(resolveShareToLocal("Finance$", "a.exe")).toBeNull();
    expect(resolveShareToLocal("Software", "a.exe")).toBeNull();
    expect(resolveShareToLocal("IPC$", "a.exe")).toBeNull();
  });
});

describe("service/task creation detection by literal event id", () => {
  it("4697 and 7045 are service creation", () => {
    expect(isServiceOrTaskCreation(serviceCreated())).toBe("service");
    expect(
      isServiceOrTaskCreation(serviceCreated({ description: "System Service installed (EID 7045)" })),
    ).toBe("service");
  });
  it("4698 is task creation", () => {
    expect(isServiceOrTaskCreation(taskCreated())).toBe("task");
  });
  it("4699/4700/4702 (deleted/enabled/updated) are never read as a creation", () => {
    expect(
      isServiceOrTaskCreation({
        ...taskCreated(),
        description: "EventLog Scheduled task deleted (EID 4699)",
      }),
    ).toBeNull();
    expect(
      isServiceOrTaskCreation({
        ...taskCreated(),
        description: "EventLog Scheduled task enabled (EID 4700)",
      }),
    ).toBeNull();
    expect(
      isServiceOrTaskCreation({
        ...taskCreated(),
        description: "EventLog Scheduled task updated (EID 4702)",
      }),
    ).toBeNull();
  });
});

describe("isRpcPipeCall", () => {
  it("a successful svcctl pipe CREATE is a service pipe call", () => {
    expect(isRpcPipeCall(pipeCall())).toBe("service");
  });
  it("a successful atsvc pipe CREATE is a task pipe call", () => {
    expect(
      isRpcPipeCall(
        pipeCall({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: { command: "SMB2_COMMAND_CREATE", status: "STATUS_SUCCESS", filename: "atsvc" },
          },
        }),
      ),
    ).toBe("task");
  });
  it("a denied pipe CREATE is never a match", () => {
    expect(
      isRpcPipeCall(
        pipeCall({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: { command: "SMB2_COMMAND_CREATE", status: "STATUS_ACCESS_DENIED", filename: "svcctl" },
          },
        }),
      ),
    ).toBeNull();
  });
  it("an unrelated pipe name is never a match", () => {
    expect(
      isRpcPipeCall(
        pipeCall({
          canonical: {
            event: { category: "network", type: "smb" },
            smb: { command: "SMB2_COMMAND_CREATE", status: "STATUS_SUCCESS", filename: "spoolss" },
          },
        }),
      ),
    ).toBeNull();
  });
});

describe("join A: staged write → execution", () => {
  it("a match with no established host identity is noted but never raised (Info stays Info)", () => {
    // SMB rows carry no `asset` today (#1085 never sets one), so host identity is not established
    // by default — this is the realistic case. Promoting an unconfirmed cross-host coincidence
    // into the forensic timeline would risk a false chain between two unrelated hosts, so this
    // stays Info (note only, super-timeline-visible, promotable by the analyst) until confirmed.
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
      }),
      execProcess(),
    ]);
    const w = find(out, "w1");
    expect(w.description).toContain("smb-staged file executed");
    expect(w.description).toContain("host identity not established");
    expect(w.severity).toBe("Info");
    expect(w.mitreTechniques).toEqual([]);
  });

  it("an admin-share write with a matching later execution on the same host is raised, T1021.002", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
        asset: "WS-01",
      }),
      execProcess(),
    ]);
    const w = find(out, "w1");
    expect(w.description).toContain("smb-staged file executed");
    expect(w.severity).toBe("High");
    expect(w.mitreTechniques).toContain("T1021.002");
  });

  it("a custom (non-admin) share write with no hash match cannot be path-matched at all", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "Finance$",
          },
        },
      }),
      execProcess(),
    ]);
    const w = find(out, "w1");
    expect(w.description).not.toContain("smb-staged file executed");
  });

  it("a custom share write CAN be matched by hash, and raises T1570 (not T1021.002)", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "Finance$",
          },
        },
        sha256: "e".repeat(64),
        asset: "WS-01",
      }),
      { ...execProcess(), sha256: "e".repeat(64) },
    ]);
    const w = find(out, "w1");
    expect(w.description).toContain("smb-staged file executed");
    expect(w.mitreTechniques).toContain("T1570");
    expect(w.mitreTechniques).not.toContain("T1021.002");
  });

  it("the corroborating execution row is raised to Medium (never higher) and names the write", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
        asset: "WS-01",
      }),
      execProcess(),
    ]);
    const p = find(out, "p1");
    expect(p.description).toContain("ran a share-staged file");
    expect(p.severity).toBe("Medium");
  });

  it("a match within the order tolerance gets a note but no severity raise", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
      }),
      { ...execProcess(), timestamp: at(1) },
    ]);
    const w = find(out, "w1");
    expect(w.description).toContain("order not established");
    expect(w.severity).toBe("Info");
  });

  it("a hash mismatch on an otherwise path-matching candidate is vetoed", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
        sha256: "a".repeat(64),
      }),
      { ...execProcess(), sha256: "b".repeat(64) },
    ]);
    const w = find(out, "w1");
    expect(w.description).not.toContain("smb-staged file executed");
  });

  it("no corroborating execution anywhere leaves the write untouched", () => {
    const out = run([
      smbWrite({
        path: "windows\\report.exe",
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
      }),
    ]);
    const w = find(out, "w1");
    expect(w.description).toBe(smbWrite().description);
    expect(w.severity).toBe("Info");
  });

  it("a service-creation event (4697) whose own path matches is Join A evidence too", () => {
    const out = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
      }),
      serviceCreated(),
    ]);
    const w = find(out, "w1");
    expect(w.description).toContain("smb-staged file executed");
  });
});

describe("join B: pipe call → service/task creation", () => {
  it("a svcctl pipe call then a service install with no established host is noted but never raised", () => {
    const out = run([pipeCall(), serviceCreated()]);
    const pipe = find(out, "pipe1");
    expect(pipe.description).toContain("service/task creation after a pipe call");
    expect(pipe.description).toContain("host identity not established");
    expect(pipe.severity).toBe("Info");
    const svc = find(out, "svc1");
    expect(svc.description).toContain("preceded by a service-control pipe call");
    expect(svc.severity).toBe("Medium"); // svc1's own base severity in this fixture
  });

  it("raises the pipe call to High once both sides name the same host", () => {
    const out = run([pipeCall({ asset: "WS-01" }), serviceCreated()]);
    expect(find(out, "pipe1").severity).toBe("High");
  });

  it("an atsvc pipe call then 4698 (created) is corroborated; 4699 (deleted) is not", () => {
    const atsvc = pipeCall({
      id: "pipeT",
      canonical: {
        event: { category: "network", type: "smb" },
        smb: { command: "SMB2_COMMAND_CREATE", status: "STATUS_SUCCESS", filename: "atsvc" },
      },
    });
    const out = run([atsvc, taskCreated()]);
    expect(find(out, "pipeT").description).toContain("service/task creation after a pipe call");

    const outDeleted = run([
      atsvc,
      { ...taskCreated(), description: "EventLog Scheduled task deleted (EID 4699)" },
    ]);
    expect(find(outDeleted, "pipeT").description).not.toContain("service/task creation after a pipe call");
  });

  it("a service creation more than 15 minutes after the pipe call is not matched", () => {
    const out = run([pipeCall(), { ...serviceCreated(), timestamp: at(16 * 60) }]);
    expect(find(out, "pipe1").description).not.toContain("service/task creation after a pipe call");
  });

  it("never claims the RPC call itself created the object", () => {
    const out = run([pipeCall(), serviceCreated()]);
    const pipe = find(out, "pipe1");
    expect(pipe.description).not.toMatch(/created the service/i);
  });

  it("a driver-load event (T1543.003, unrelated to a pipe call) is never mistaken for a service install", () => {
    const driverLoad = {
      ...serviceCreated(),
      id: "drv1",
      description: "Sysmon 6 Driver loaded: evil.sys",
      mitreTechniques: ["T1543.003"],
    };
    const out = run([pipeCall(), driverLoad]);
    expect(find(out, "pipe1").description).not.toContain("service/task creation after a pipe call");
  });
});

describe("bucket overflow is disclosed, never silently dropped (#1092)", () => {
  it("execution records at the same path beyond BUCKET_MAX are counted, never silently missing", () => {
    const write = smbWrite({
      canonical: {
        event: { category: "network", type: "smb" },
        smb: {
          command: "SMB2_COMMAND_CREATE",
          status: "STATUS_SUCCESS",
          outcome: "created-new",
          shareType: "FILE",
          share: "C$",
        },
      },
      path: "windows\\report.exe",
      asset: "WS-01",
    });
    // Every record shares the SAME path, so they all land in one bucket; the first BUCKET_MAX
    // are read, the rest are counted as beyond the index — never silently dropped.
    const flood = Array.from({ length: BUCKET_MAX + 5 }, (_, i) => ({
      ...execProcess(),
      id: `flood${i}`,
    }));
    const out = run([write, ...flood]);
    const w = find(out, "w1");
    expect(w.description).toContain("smb-staged file executed");
    expect(w.description).toContain("beyond the index, not read");
  });
});

describe("idempotence", () => {
  it("running the pass twice does not duplicate notes", () => {
    const once = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
      }),
      execProcess(),
    ]);
    const twice = run(once);
    const w = find(twice, "w1");
    expect(w.description.split("smb-staged file executed").length).toBe(2); // appears exactly once
  });

  it("stale notes are removed when the corroborating evidence leaves the case", () => {
    const withEvidence = run([
      smbWrite({
        canonical: {
          event: { category: "network", type: "smb" },
          smb: {
            command: "SMB2_COMMAND_CREATE",
            status: "STATUS_SUCCESS",
            outcome: "created-new",
            shareType: "FILE",
            share: "C$",
          },
        },
        path: "windows\\report.exe",
      }),
      execProcess(),
    ]);
    const writeOnly = withEvidence.filter((e) => e.id === "w1");
    const rerun = run(writeOnly);
    expect(find(rerun, "w1").description).not.toContain("smb-staged file executed");
  });
});
