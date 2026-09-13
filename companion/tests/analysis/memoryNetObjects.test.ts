// A memory socket record says what it establishes: its stored state, how it was reported, its own
// owner fields, and whether the submitted process rows are consistent with them (#933 item 14).
import { describe, it, expect } from "vitest";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import {
  indexProcessRows,
  ownerConsistency,
  readState,
  readTime,
  socketProvenance,
  tupleShape,
} from "../../src/analysis/memoryNetObjects.js";

const sock = (over: Record<string, unknown> = {}) => ({
  __children: [],
  Offset: "0xe0001a2b3c40",
  Proto: "TCPv4",
  LocalAddr: "10.0.0.5",
  LocalPort: 50122,
  ForeignAddr: "203.0.113.50",
  ForeignPort: 443,
  State: "ESTABLISHED",
  PID: 3120,
  Owner: "evil.exe",
  Created: "2021-04-29 21:41:00.000000",
  ...over,
});
const proc = (over: Record<string, unknown> = {}) => ({
  __children: [],
  PID: 3120,
  PPID: 1000,
  ImageFileName: "evil.exe",
  Offset: "0xe0000aaa0000",
  Threads: 3,
  Handles: 50,
  SessionId: 1,
  Wow64: false,
  CreateTime: "2021-04-29 21:40:00.000000",
  ExitTime: null,
  ...over,
});
const run = (map: Record<string, unknown[]>) => parseMemory(JSON.stringify(map), { minSeverity: "Info" });
const socketRow = (map: Record<string, unknown[]>) =>
  run(map).events.find((e) => /netscan|netstat/.test(e.description) && e.description.includes("→"));

describe("state: the token verbatim, then Volatility's own enum reading", () => {
  it("reads every token the enum renders, and nothing more", () => {
    expect(readState("LISTENING", "TCPv4").reading).toBe("listening endpoint");
    expect(readState("ESTABLISHED", "TCPv4").reading).toBe("stored state ESTABLISHED");
    for (const t of ["SYN_SENT", "SYN_RCVD"])
      expect(readState(t, "TCPv4").reading, t).toBe("connection setup state");
    for (const t of ["FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT"]) {
      expect(readState(t, "TCPv4").reading, t).toBe(
        "TCP teardown state (a half-closed direction may still carry data)",
      );
    }
    for (const t of ["CLOSED", "DELETE_TCB"])
      expect(readState(t, "TCPv4").reading, t).toBe("closed-state object");
    expect(readState("", "UDPv4").reading).toBe("UDP endpoint (no connection state)");
    expect(readState("-", "UDPv6").reading).toBe("UDP endpoint (no connection state)");
    expect(readState("", "TCPv4").reading).toBe("state not in the record");
    const odd = readState("WEIRD] [x", "TCPv4");
    expect(odd.reading).toBe("state not in the table");
    expect(odd.token).toBe("WEIRD) (x");
  });
  it("the row never says residual, live or outlived", () => {
    for (const State of ["CLOSED", "TIME_WAIT", "ESTABLISHED", "LISTENING"]) {
      const e = socketRow({ "windows.netscan.NetScan": [sock({ State })] });
      expect(e?.description, State).not.toMatch(/residual|\blive\b|outlived/i);
      expect(e?.description, State).toContain(`[state: ${State}`);
    }
  });
});

describe("provenance: how the plugin reported the object, never whether it was live", () => {
  it("netstat is a traversal; anything else a pool scan", () => {
    expect(socketProvenance("windows.netstat.NetStat")).toContain(
      "reported by traversal of the network tracking structures",
    );
    expect(socketProvenance("windows.netscan.NetScan")).toContain(
      "reported by pool scan — an allocated or a freed object",
    );
    expect(socketProvenance("connscan")).toContain("pool scan");
    const e = socketRow({ "windows.netstat.NetStat": [sock()] });
    expect(e?.description).toContain("[reported by traversal of the network tracking structures]");
    expect(e?.description).not.toMatch(/\blive\b/i);
  });
});

describe("the owner's two fields are read separately", () => {
  it("both, PID only, name only, neither — and an absent field names no cause", () => {
    expect(socketRow({ "windows.netscan.NetScan": [sock()] })?.description).toContain(
      "[owner: evil.exe, PID 3120",
    );
    expect(socketRow({ "windows.netscan.NetScan": [sock({ PID: "-" })] })?.description).toContain(
      "[owner: evil.exe, PID not in the record",
    );
    expect(socketRow({ "windows.netscan.NetScan": [sock({ Owner: null })] })?.description).toContain(
      "[owner: PID 3120, name not in the record",
    );
    const none =
      socketRow({ "windows.netscan.NetScan": [sock({ Owner: "-", PID: null })] })?.description ?? "";
    expect(none).toContain("[owner: not in the record — not an indicator of concealment]");
    const ownerTag = /\[owner:[^\]]*\]/.exec(none)?.[0] ?? "";
    expect(ownerTag).not.toMatch(/freed|overwritten|hidden|stealth/i);
  });
});

describe("consistency with submitted process rows is a comparison, never validation", () => {
  const created = readTime({ Created: "2021-04-29 21:41:00.000000" }, ["Created"]);
  it("no process rows; no row at the PID; ambiguous; the same object in two tables is one candidate", () => {
    expect(ownerConsistency("3120", "evil.exe", created, indexProcessRows([])).words).toBe(
      "no process rows submitted to compare",
    );
    const other = indexProcessRows([
      { plugin: "windows.pslist", rows: [proc({ PID: 4, ImageFileName: "System" })] },
    ]);
    expect(ownerConsistency("3120", "evil.exe", created, other).words).toBe(
      "no submitted process row has PID 3120",
    );
    const two = indexProcessRows([
      {
        plugin: "windows.pslist",
        rows: [proc(), proc({ Offset: "0xe0000bbb0000", ImageFileName: "other.exe" })],
      },
    ]);
    expect(ownerConsistency("3120", "evil.exe", created, two).words).toBe(
      "ambiguous: 2 distinct submitted process rows have PID 3120",
    );
    const same = indexProcessRows([
      { plugin: "windows.pslist", rows: [proc()] },
      { plugin: "windows.psscan", rows: [proc()] },
    ]);
    const c = ownerConsistency("3120", "evil.exe", created, same);
    expect(c.consistent).toBe(true);
    expect(c.words).toBe(
      "consistent with one submitted process row: evil.exe, created 2021-04-29T21:40:00.000Z",
    );
  });
  it("a name that differs, a create after the socket, an exit before it — each is 'not consistent' with no cause", () => {
    const named = indexProcessRows([
      { plugin: "windows.pslist", rows: [proc({ ImageFileName: "other.exe" })] },
    ]);
    const n = ownerConsistency("3120", "evil.exe", created, named);
    expect(n.consistent).toBe(false);
    expect(n.words).toBe("not consistent: the submitted process row at PID 3120 is named other.exe");
    const late = indexProcessRows([
      { plugin: "windows.pslist", rows: [proc({ CreateTime: "2021-04-29 21:50:00" })] },
    ]);
    expect(ownerConsistency("3120", "evil.exe", created, late).words).toBe(
      "not consistent: the submitted process row was created at 2021-04-29T21:50:00.000Z, after this socket's Created value",
    );
    const gone = indexProcessRows([
      { plugin: "windows.psscan", rows: [proc({ ExitTime: "2021-04-29 21:40:30" })] },
    ]);
    expect(ownerConsistency("3120", "evil.exe", created, gone).words).toBe(
      "not consistent: the submitted process row reports exit at 2021-04-29T21:40:30.000Z, before this socket's Created value",
    );
    for (const w of [
      n,
      ownerConsistency("3120", "evil.exe", created, late),
      ownerConsistency("3120", "evil.exe", created, gone),
    ]) {
      expect(w.words).not.toMatch(/reuse|overwrit|smear|hidden/i);
    }
  });
  it("an exit after the socket is reported as the two values; an unreadable time is 'not comparable'", () => {
    const after = indexProcessRows([
      { plugin: "windows.psscan", rows: [proc({ ExitTime: "2021-04-29 22:00:00" })] },
    ]);
    const a = ownerConsistency("3120", "evil.exe", created, after);
    expect(a.consistent).toBe(true);
    expect(a.words).toBe(
      "consistent with one submitted process row: evil.exe, created 2021-04-29T21:40:00.000Z; that row reports exit at 2021-04-29T22:00:00.000Z, after this socket's Created value",
    );
    expect(a.words).not.toMatch(/outlived|residual/);
    const noTime = ownerConsistency("3120", "evil.exe", readTime({}, ["Created"]), after);
    expect(noTime.words).toContain(
      "lifetime not comparable (this socket's Created value is not in the record)",
    );
    const bad = indexProcessRows([{ plugin: "windows.pslist", rows: [proc({ CreateTime: "yesterday" })] }]);
    expect(ownerConsistency("3120", "evil.exe", created, bad).words).toContain(
      "lifetime not comparable (the process row's create time is not readable)",
    );
  });
  it("the socket's own owner fields are never rewritten by the comparison", () => {
    const e = socketRow({
      "windows.netscan.NetScan": [sock()],
      "windows.pslist.PsList": [proc({ ImageFileName: "other.exe" })],
    });
    expect(e?.description).toContain(
      "[owner: evil.exe, PID 3120 — not consistent: the submitted process row at PID 3120 is named other.exe]",
    );
    expect(e?.processName).toBeUndefined();
  });
  it("processName and the process indicator exist only on one consistent row", () => {
    const alone = run({ "windows.netscan.NetScan": [sock()] });
    expect(alone.events[0].processName).toBeUndefined();
    expect(alone.events[0].description).toContain("no process rows submitted to compare");
    expect(alone.iocs.some((i) => i.type === "process")).toBe(false);
    const withProc = run({ "windows.netscan.NetScan": [sock()], "windows.pslist.PsList": [proc()] });
    const s = withProc.events.find((e) => e.description.includes("→"));
    expect(s?.processName).toBe("evil.exe");
  });
});

describe("tuple shape", () => {
  it("a UDP or listening wildcard foreign side is the normal shape; a non-listening TCP needs a peer", () => {
    expect(
      tupleShape({ proto: "UDPv4", laddr: "0.0.0.0", lport: "137", faddr: "*", fport: "0", state: "" }).ok,
    ).toBe(true);
    expect(
      tupleShape({
        proto: "TCPv4",
        laddr: "0.0.0.0",
        lport: "445",
        faddr: "0.0.0.0",
        fport: "0",
        state: "LISTENING",
      }).ok,
    ).toBe(true);
    const est = tupleShape({
      proto: "TCPv4",
      laddr: "10.0.0.5",
      lport: "50122",
      faddr: "0.0.0.0",
      fport: "0",
      state: "ESTABLISHED",
    });
    expect(est.ok).toBe(false);
    expect(est.problem).toContain("foreign endpoint = 0.0.0.0:0");
  });
  it("a bad port, proto or address is incomplete: a row, no indicator, no fields", () => {
    for (const over of [
      { ForeignPort: 70000 },
      { Proto: "FOO" },
      { ForeignAddr: "not.an.ip" },
      { LocalAddr: "" },
    ]) {
      const r = run({ "windows.netscan.NetScan": [sock(over)] });
      const e = r.events[0];
      expect(e.description, JSON.stringify(over)).toContain("[tuple incomplete:");
      expect(e.dstIp, JSON.stringify(over)).toBeUndefined();
      expect(e.port, JSON.stringify(over)).toBeUndefined();
      expect(e.severity, JSON.stringify(over)).toBe("Info");
      expect(
        r.iocs.some((i) => i.type === "ip"),
        JSON.stringify(over),
      ).toBe(false);
    }
  });
  it("a listener's foreign side and a wildcard never mint an ip indicator; a peer does", () => {
    const r = run({
      "windows.netscan.NetScan": [
        sock({
          Offset: "0x1",
          LocalAddr: "0.0.0.0",
          LocalPort: 445,
          ForeignAddr: "0.0.0.0",
          ForeignPort: 0,
          State: "LISTENING",
        }),
        sock({ Offset: "0x2" }),
      ],
    });
    expect(r.iocs.filter((i) => i.type === "ip").map((i) => i.value)).toEqual(["203.0.113.50"]);
  });
});

describe("identity is the object", () => {
  it("the same offset folds with a count; different offsets and a missing offset do not", () => {
    const twice = run({ "windows.netscan.NetScan": [sock(), sock()] });
    expect(twice.events).toHaveLength(1);
    expect(twice.events[0].count).toBe(2);
    const two = run({ "windows.netscan.NetScan": [sock({ Offset: "0x1" }), sock({ Offset: "0x2" })] });
    expect(two.events).toHaveLength(2);
    const none = run({ "windows.netscan.NetScan": [sock({ Offset: null }), sock({ Offset: null })] });
    expect(none.events).toHaveLength(2);
  });
  it("a listener and an established object to one host are two rows", () => {
    const r = run({
      "windows.netscan.NetScan": [
        sock({
          Offset: "0x1",
          State: "LISTENING",
          ForeignAddr: "0.0.0.0",
          ForeignPort: 0,
          LocalPort: 443,
          LocalAddr: "0.0.0.0",
        }),
        sock({ Offset: "0x2" }),
      ],
    });
    expect(r.events).toHaveLength(2);
  });
});

describe("severity and corroboration", () => {
  it("an externally addressed ESTABLISHED object is Low with narrow words; a listener Info", () => {
    const r = run({ "windows.netscan.NetScan": [sock()] });
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].description).toContain("triage priority, not a claim of traffic");
    const l = run({
      "windows.netscan.NetScan": [sock({ State: "LISTENING", ForeignAddr: "0.0.0.0", ForeignPort: 0 })],
    });
    expect(l.events[0].severity).toBe("Info");
  });
  it("malfind counts a socket as corroboration only with one consistent process row", () => {
    const malfind = {
      __children: [],
      PID: 3120,
      Process: "evil.exe",
      "Start VPN": "0x400000",
      "End VPN": "0x401fff",
      Tag: "VadS",
      Protection: "PAGE_EXECUTE_READWRITE",
      CommitCharge: 1,
      PrivateMemory: 1,
      "File output": "Disabled",
      Notes: "MZ header",
      Hexdump: "",
      Disasm: "",
    };
    const unchecked = run({ "windows.netscan.NetScan": [sock()], "windows.malfind.Malfind": [malfind] });
    expect(unchecked.events.find((e) => e.severity === "High")?.description).not.toContain("network object");
    const mismatch = run({
      "windows.netscan.NetScan": [sock()],
      "windows.malfind.Malfind": [malfind],
      "windows.pslist.PsList": [proc({ ImageFileName: "other.exe" })],
    });
    expect(mismatch.events.find((e) => e.severity === "High")?.description).not.toContain("network object");
    const ok = run({
      "windows.netscan.NetScan": [sock()],
      "windows.malfind.Malfind": [malfind],
      "windows.pslist.PsList": [proc()],
    });
    expect(ok.events.find((e) => e.severity === "High")?.description).toContain(
      "a network object with the same PID is reported in this image, and one submitted process row is consistent with it",
    );
  });
});

describe("every shown value is neutralised", () => {
  // Markup and pipes are each report exporter's escaping (HTML, Markdown tables, CSV); the row's
  // own guarantee is: no tag the reader trusts, no control character, no bare hash run.
  it("owner, state and a candidate name carrying brackets, a newline or a hash run", () => {
    const md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const r = run({
      "windows.netscan.NetScan": [sock({ Owner: `] [x | <b>${md5}\nz`, State: "ESTAB] [LISHED" })],
      "windows.pslist.PsList": [proc({ ImageFileName: `other] [y|${md5}` })],
    });
    const d = r.events.find((e) => e.description.includes("→"))?.description ?? "";
    expect(d).not.toContain("] [x");
    expect(d).not.toContain("] [y");
    expect(d).not.toContain("\n");
    expect(d).not.toMatch(/[0-9a-f]{32}/);
    expect(d).toContain("[state: ESTAB) (LISHED");
  });
});
