import { describe, expect, it } from "vitest";
import {
  CONN_INDEX_MAX,
  DNS_FIXED_WINDOW_S,
  DNS_OBSERVATIONS_MAX,
  DNS_WINDOW_SLACK_S,
} from "../../src/analysis/dnsConnJoin.js";
import {
  collectWindowsConnCandidate,
  joinWindowsDnsConn,
  runWindowsDnsConnJoin,
  type SiemConnCandidate,
  type SiemDnsCandidate,
} from "../../src/analysis/siemDnsConnJoin.js";

const T0 = 1_700_000_000_000;
const H = "WS-01";
const A1 = "93.184.216.34";
const A2 = "198.51.100.7";

const dns = (over: Partial<SiemDnsCandidate> = {}): SiemDnsCandidate => ({
  mappedIndex: 0,
  host: H,
  ts: T0,
  addresses: [A1],
  ...over,
});
const conn = (over: Partial<SiemConnCandidate> = {}): SiemConnCandidate => ({
  host: H,
  ts: T0 + 5_000,
  destinationIp: A1,
  ...over,
});

describe("joinWindowsDnsConn", () => {
  it("connects inside the window", () => {
    const r = joinWindowsDnsConn([dns()], [conn()]);
    const c = r.get(0)!;
    expect(c.joinState).toBe("joined");
    expect(c.leads).toEqual([
      {
        address: A1,
        state: "connected inside the window",
        band: "≤10 s",
        window: { basis: "fixed", seconds: DNS_FIXED_WINDOW_S },
      },
    ]);
  });

  it("first connection after the window", () => {
    const afterMs = (DNS_FIXED_WINDOW_S + DNS_WINDOW_SLACK_S) * 1000 + 60_000;
    const r = joinWindowsDnsConn([dns()], [conn({ ts: T0 + afterMs })]);
    expect(r.get(0)!.leads[0].state).toBe("first connection after the window");
  });

  it("earlier connections only", () => {
    const r = joinWindowsDnsConn([dns()], [conn({ ts: T0 - 5_000 })]);
    expect(r.get(0)!.leads[0].state).toBe("earlier connections only");
  });

  it("no connection in this upload — host has connections, but not to this address", () => {
    const r = joinWindowsDnsConn([dns()], [conn({ destinationIp: A2 })]);
    expect(r.get(0)!.leads[0].state).toBe("no connection in this upload");
  });

  it("no connection records in this upload — host has no connection records at all", () => {
    const r = joinWindowsDnsConn([dns()], [conn({ host: "WS-02" })]);
    expect(r.get(0)!.joinState).toBe("no connection records in this upload");
    expect(r.get(0)!.leads).toEqual([]);
  });

  it("answered with no address", () => {
    const r = joinWindowsDnsConn([dns({ addresses: [] })], [conn()]);
    expect(r.get(0)!.joinState).toBe("answered with no address");
  });

  it("client not joinable — no host on the record", () => {
    const r = joinWindowsDnsConn([dns({ host: "" })], [conn()]);
    expect(r.get(0)!.joinState).toBe("client not joinable");
  });

  it("two hosts in one upload never cross-join", () => {
    const r = joinWindowsDnsConn(
      [dns({ mappedIndex: 0, host: "WS-01" }), dns({ mappedIndex: 1, host: "WS-02" })],
      [conn({ host: "WS-01" })],
    );
    expect(r.get(0)!.leads[0].state).toBe("connected inside the window");
    expect(r.get(1)!.joinState).toBe("no connection records in this upload");
  });

  it("connection records exceed the index disables the join entirely", () => {
    const conns = Array.from({ length: CONN_INDEX_MAX + 1 }, () => conn());
    const r = joinWindowsDnsConn([dns()], conns);
    expect(r.get(0)!.joinState).toBe("connection records exceed the index");
    expect(r.get(0)!.leads).toEqual([]);
  });

  it("DNS candidates past DNS_OBSERVATIONS_MAX get no annotation at all", () => {
    const many = Array.from({ length: DNS_OBSERVATIONS_MAX + 1 }, (_, i) => dns({ mappedIndex: i }));
    const r = joinWindowsDnsConn(many, [conn()]);
    expect(r.has(0)).toBe(true);
    expect(r.has(DNS_OBSERVATIONS_MAX)).toBe(false);
  });

  it("a mixed A/AAAA answer joins whichever address the host actually connected to", () => {
    const v6 = "2001:db8::1";
    const r = joinWindowsDnsConn([dns({ addresses: [A1, v6] })], [conn({ destinationIp: v6 })]);
    const leads = r.get(0)!.leads;
    expect(leads.find((l) => l.address === A1)!.state).toBe("no connection in this upload");
    expect(leads.find((l) => l.address === v6)!.state).toBe("connected inside the window");
  });

  it("an IPv6 address rendered expanded by one record and compressed by another still joins", () => {
    const compressed = "2001:db8::1";
    const expanded = "2001:0db8:0000:0000:0000:0000:0000:0001";
    const r = joinWindowsDnsConn([dns({ addresses: [compressed] })], [conn({ destinationIp: expanded })]);
    expect(r.get(0)!.leads[0].state).toBe("connected inside the window");
  });

  it("a port-53 connection concurrent with the query is excluded from that query's own lead", () => {
    const r = joinWindowsDnsConn([dns()], [conn({ ts: T0 + 100, destinationPort: 53 })]);
    expect(r.get(0)!.leads[0].state).toBe("no connection in this upload");
  });

  it("a port-53 connection concurrent with query A stays usable for a different, later query B", () => {
    // C sits 500ms after A's own timestamp — inside A's exclusion tolerance (excluded from A), but
    // 4.5s away from B's — outside B's tolerance, so it stays a candidate for B (an earlier one,
    // since C.ts < B.ts): proof the exclusion is scoped per-DNS-record, not dropped globally.
    const queryA = dns({ mappedIndex: 0, ts: T0 });
    const queryB = dns({ mappedIndex: 1, ts: T0 + 5_000 });
    const r = joinWindowsDnsConn([queryA, queryB], [conn({ ts: T0 + 500, destinationPort: 53 })]);
    expect(r.get(0)!.leads[0].state).toBe("no connection in this upload");
    expect(r.get(1)!.leads[0].state).toBe("earlier connections only");
  });
});

describe("runWindowsDnsConnJoin with pre-collected connections (#1636)", () => {
  const row = () => ({
    aggKey: "k",
    description: "Sysmon DNS query",
    timestamp: new Date(T0).toISOString(),
    canonical: {
      target: { kind: "host", name: H },
      dns: { returned: [{ kind: "address", value: A1 }] },
      network: { destination: { address: A1, port: 443 } },
      evidence: { rawRecords: [{ locator: "r0" }] },
    },
  });

  it("uses the passed list as the whole connection side — a held row's own destination is not counted again", () => {
    const r = row();
    runWindowsDnsConnJoin([r], new Map(), []);
    expect(r.canonical.dns).toMatchObject({ joinState: "no connection records in this upload" });
  });

  it("without a passed list it still collects connections from the rows, as before", () => {
    const r = row();
    runWindowsDnsConnJoin([r], new Map());
    expect(r.canonical.dns).toMatchObject({ joinState: "joined" });
  });

  it("the connection collector keeps a candidate only when the row has a host, a time and a destination", () => {
    const conns: SiemConnCandidate[] = [];
    collectWindowsConnCandidate(conns, row());
    collectWindowsConnCandidate(conns, { ...row(), timestamp: "not a time" });
    collectWindowsConnCandidate(conns, { ...row(), canonical: { target: { kind: "host", name: H } } });
    expect(conns).toEqual([{ host: H, ts: T0, destinationIp: A1, destinationPort: 443 }]);
  });
});
