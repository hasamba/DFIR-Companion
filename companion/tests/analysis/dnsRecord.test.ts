import { describe, it, expect } from "vitest";
import {
  asciiName,
  dnsOverlay,
  isIndicatorName,
  isValidQueryName,
  readQueryResults,
  readQueryStatus,
  RESULTS_SHOWN_MAX,
  RESULTS_KEPT_MAX,
  SYSMON_22_DNS,
  DNS_CLIENT_EVENTS,
  type DnsEventSchema,
} from "../../src/analysis/dnsRecord.js";

// The unit tests read every field unless a schema is given: the gating is tested apart.
const ALL: DnsEventSchema = { status: "QueryStatus", type: true, results: true, networkQuery: true };
const overlay = (
  fields: Record<string, string>,
  opts: { statusField?: "QueryStatus" | "Status" | ""; description?: string; schema?: DnsEventSchema } = {},
) =>
  dnsOverlay(
    (k) => fields[k],
    opts.schema ?? { ...ALL, status: opts.statusField ?? "QueryStatus" },
    opts.description ?? "Sysmon DNS query (EID 22) - Image=C:\\Windows\\System32\\svchost.exe @ WS-01",
  );

describe("readQueryStatus — the WinError.h table, nothing guessed", () => {
  it("names every code in the table and keeps the code", () => {
    expect(readQueryStatus("0")).toMatchObject({ code: 0, state: "success" });
    expect(readQueryStatus("9003")).toMatchObject({ code: 9003, state: "nxdomain" });
    expect(readQueryStatus("9003").words).toBe("NXDOMAIN — the name does not exist at this resolver");
    expect(readQueryStatus("9501")).toMatchObject({ state: "no-records" });
    expect(readQueryStatus("9002")).toMatchObject({ state: "server-failure" });
    expect(readQueryStatus("9005")).toMatchObject({ state: "refused" });
    expect(readQueryStatus("1460")).toMatchObject({ state: "timeout" });
    expect(readQueryStatus("123")).toMatchObject({ state: "invalid-name" });
    expect(readQueryStatus("9560")).toMatchObject({ state: "invalid-name-char" });
    expect(readQueryStatus("9001")).toMatchObject({ state: "format-error" });
    expect(readQueryStatus("9004")).toMatchObject({ state: "not-implemented" });
    expect(readQueryStatus("9701")).toMatchObject({ state: "record-missing" });
  });
  it("a code outside the table is shown verbatim, never read as success or failure", () => {
    const r = readQueryStatus("1214");
    expect(r).toMatchObject({ code: 1214, state: "other" });
    expect(r.words).toBe("status 1214 (not in the table)");
  });
  it("absent and unreadable are their own states", () => {
    expect(readQueryStatus(undefined)).toMatchObject({
      state: "absent",
      words: "outcome not in this record",
    });
    expect(readQueryStatus("")).toMatchObject({ state: "absent" });
    expect(readQueryStatus("ok")).toMatchObject({ state: "unreadable", words: "status not readable" });
    expect(readQueryStatus("-1")).toMatchObject({ state: "unreadable" });
    expect(readQueryStatus("0x2329")).toMatchObject({ state: "unreadable" });
  });
});

describe("readQueryResults — the resolver's returned values, typed, validated, bounded", () => {
  it("reads the Sysmon grammar: CNAME steps, IPv4-mapped addresses, bare IPv6", () => {
    const r = readQueryResults("type:  5 cdn.example.net;::ffff:203.0.113.5;2001:db8::1;");
    expect(r.values).toEqual([
      { type: 5, value: "cdn.example.net", kind: "name" },
      { type: undefined, value: "203.0.113.5", kind: "address" },
      { type: undefined, value: "2001:db8::1", kind: "address" },
    ]);
    expect(r.total).toBe(3);
    expect(r.shown).toBe("cname cdn.example.net; 203.0.113.5, 2001:db8::1");
  });
  it("reads typed values the DNS Client writes, and keeps unknown types as typed text", () => {
    const r = readQueryResults("type: 16 v=spf1 -all;type: 28 2001:db8::9;type: 99 whatever;");
    expect(r.values[0]).toEqual({ type: 16, value: "v=spf1 -all", kind: "other" });
    expect(r.values[1]).toEqual({ type: 28, value: "2001:db8::9", kind: "address" });
    expect(r.values[2]).toEqual({ type: 99, value: "whatever", kind: "other" });
    expect(r.shown).toContain("type 16 v=spf1 -all");
    expect(r.shown).toContain("AAAA 2001:db8::9");
    // an A and an AAAA that carry one address are two facts, shown apart
    expect(readQueryResults("type: 1 192.0.2.1;").shown).toBe("A 192.0.2.1");
    expect(readQueryResults("type: 28 ::ffff:192.0.2.1;").shown).toBe("AAAA 192.0.2.1");
  });
  it("a value that is neither an address nor a name is other — neutralised and bounded", () => {
    const r = readQueryResults("type: 5 ]evil[;;;\u0000x;" + "a".repeat(300) + ";");
    expect(r.values.map((v) => v.kind)).toEqual(["other", "other", "other"]);
    expect(r.shown).not.toContain("]");
    expect(r.shown).not.toContain("\u0000");
    expect(r.values[2].value.length).toBe(300);
    expect(readQueryResults(`type: 16 ${"k".repeat(600)};`).values[0].value.length).toBe(512);
    expect(r.shown.length).toBeLessThan(200);
  });
  it("shows at most RESULTS_SHOWN_MAX values and keeps at most RESULTS_KEPT_MAX", () => {
    const many = Array.from({ length: 80 }, (_, i) => `::ffff:10.0.${i >> 8}.${i & 255}`).join(";") + ";";
    const r = readQueryResults(many);
    expect(r.total).toBe(80);
    expect(r.values.length).toBe(RESULTS_KEPT_MAX);
    expect(r.shown).toContain(`+${80 - RESULTS_SHOWN_MAX} more`);
    expect((r.shown.match(/10\.0\./g) ?? []).length).toBe(RESULTS_SHOWN_MAX);
  });
  it("only leading CNAME steps are chained; other names keep the record's order and imply nothing", () => {
    const r = readQueryResults("203.0.113.39;type: 2 ns1.example;type: 2 ns2.example;198.51.100.139;");
    expect(r.shown).toBe("203.0.113.39, ns ns1.example, ns ns2.example, 198.51.100.139");
    expect(r.shown).not.toContain("→");
    const mid = readQueryResults("::ffff:192.0.2.1;type: 5 x.example;::ffff:192.0.2.2;");
    expect(mid.shown).toBe("192.0.2.1, cname x.example, 192.0.2.2");
    const two = readQueryResults("type: 5 a.example;type: 5 b.example;::ffff:192.0.2.1;type: 2 ns.example;");
    expect(two.shown).toBe("cname a.example → cname b.example; 192.0.2.1, ns ns.example");
    // a CNAME followed by authority data (an NXDOMAIN's SOA) is never arrow-linked to it
    expect(readQueryResults("type: 5 alias.example;type: 6 ns1.example;").shown).toBe(
      "cname alias.example; soa ns1.example",
    );
  });
  it("a whole value of - is the placeholder for none; a typed - is data", () => {
    expect(readQueryResults("-")).toMatchObject({ values: [], total: 0 });
    expect(readQueryResults(" - ")).toMatchObject({ values: [], total: 0 });
    expect(readQueryResults("type: 16 -;").values).toEqual([{ type: 16, value: "-", kind: "other" }]);
    const nx = overlay({ QueryName: "missing.example", QueryStatus: "9003", QueryResults: "-" });
    expect(nx.description).not.toContain("also carries");
    expect(nx.dns.returned).toEqual([]);
  });
  it("a type marker with no data is said as such, never as a returned literal", () => {
    const r = readQueryResults("type: 16 ;type: 16");
    expect(r.values).toEqual([
      { type: 16, value: "", kind: "other" },
      { type: 16, value: "", kind: "other" },
    ]);
    expect(r.shown).toBe("type 16 (value not in this record), type 16 (value not in this record)");
    expect(r.shown).not.toContain("type: 16");
  });
  it("a hash-shaped value is shown as its ends", () => {
    const r = readQueryResults(`type: 16 ${"a".repeat(32)};`);
    expect(r.shown).toContain("aaaaaaaa…aaaa");
    expect(r.values[0].value).toBe("a".repeat(32));
  });
  it("empty and absent are no values", () => {
    expect(readQueryResults("")).toMatchObject({ values: [], clipped: false, shown: "", total: 0 });
    expect(readQueryResults(undefined)).toMatchObject({ values: [], shown: "", total: 0 });
  });
});

describe("isValidQueryName", () => {
  it("accepts real names and rejects what a resolver would never answer", () => {
    expect(isValidQueryName("cdn.example.net")).toBe(true);
    expect(isValidQueryName("cdn.example.net.")).toBe(true);
    expect(isValidQueryName("xn--80ak6aa92e.example")).toBe(true);
    expect(isValidQueryName("_ldap._tcp.dc._msdcs.example")).toBe(true); // an SRV owner, not a hostname
    expect(isValidQueryName("__x.example")).toBe(true); // underscores are legal anywhere in a label
    expect(isValidQueryName("beacon_01.attacker.example")).toBe(true);
    expect(isValidQueryName("bücher.example")).toBe(true); // a U-label
    expect(isValidQueryName("ū̃.attacker.example")).toBe(true); // a U-label needing a combining mark
    // the IDNA label separators are dots
    expect(asciiName("bücher\u3002attacker.example")).toBe("xn--bcher-kva.attacker.example");
    expect(asciiName("bücher\uff0eattacker\uff61example")).toBe("xn--bcher-kva.attacker.example");
    expect(isIndicatorName("bücher\u3002attacker.example")).toBe(true);
    // a URL-host terminator inside a Unicode name never truncates it into a valid name
    for (const bad of [
      "safe.example/bücher.attacker",
      "safe.example\\ü.x",
      "ü?x.example",
      "ü#x.example",
      "ü:80.example",
    ]) {
      expect(isValidQueryName(bad)).toBe(false);
      expect(asciiName(bad)).toBe("");
    }
    expect(isValidQueryName(`${"ü".repeat(60)}.example`)).toBe(false); // its A-label exceeds 63 octets
    expect(isValidQueryName("a b.example")).toBe(false);
    expect(isValidQueryName("*.attacker.example")).toBe(true); // a wildcard first label
    expect(isIndicatorName("*.attacker.example")).toBe(true);
    expect(isValidQueryName("*")).toBe(false);
    expect(isValidQueryName("a.*.example")).toBe(false);
    expect(isValidQueryName("*a.example")).toBe(false);
    expect(isValidQueryName("a.example-")).toBe(false);
    expect(isValidQueryName("localhost")).toBe(true); // a valid single-label query…
    expect(isValidQueryName("wpad")).toBe(true);
    expect(isIndicatorName("wpad")).toBe(false); // …that is not an indicator (the mapper's dot rule)
    expect(isIndicatorName("wpad.example")).toBe(true);
    expect(isValidQueryName("good.example] [returned: 203.0.113.66")).toBe(false);
    expect(isValidQueryName("/tmp/payload.exe")).toBe(false);
    expect(isValidQueryName("-bad.example")).toBe(false);
    expect(isValidQueryName(`${"a".repeat(64)}.example`)).toBe(false);
    expect(
      isValidQueryName(`${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.e`),
    ).toBe(false);
    expect(isValidQueryName("")).toBe(false);
  });
});

describe("dnsOverlay — what one record establishes", () => {
  it("a resolved query says what was RETURNED, never what the name resolves to", () => {
    const o = overlay({
      QueryName: "cdn.example.net",
      QueryStatus: "0",
      QueryResults: "type:  5 edge.example.net;::ffff:203.0.113.5;",
    });
    expect(o.description).toBe(
      "Sysmon DNS query (EID 22) - Image=C:\\Windows\\System32\\svchost.exe @ WS-01 [query: cdn.example.net] [type not in this record] [returned: cname edge.example.net; 203.0.113.5]",
    );
    expect(o.description).not.toContain("resolved to");
    expect(o.dns).toMatchObject({
      query: "cdn.example.net",
      queryValid: true,
      indicator: true,
      status: 0,
      state: "success",
      ownership: "not in this record",
      vantage: "endpoint",
    });
    expect(o.dns.returned).toEqual([
      { type: 5, value: "edge.example.net", kind: "name" },
      { type: undefined, value: "203.0.113.5", kind: "address" },
    ]);
    expect(o.identity).toMatch(/^\|dns:q15:[0-9a-f]{32}:t-:s0:n-:r[0-9a-f]{32}$/);
  });
  it("NXDOMAIN, no records, timeout and an unknown code each say so; the code is the identity", () => {
    const nx = overlay({ QueryName: "gone.example", QueryStatus: "9003" });
    expect(nx.description).toContain("[NXDOMAIN — the name does not exist at this resolver]");
    expect(nx.identity).toContain(":s9003:n-:r-");
    const none = overlay({ QueryName: "gone.example", QueryStatus: "9501" });
    expect(none.description).toContain("[no records of the queried type]");
    const to = overlay({ QueryName: "gone.example", QueryStatus: "1460" });
    expect(to.description).toContain("[timed out — no answer]");
    const odd = overlay({ QueryName: "gone.example", QueryStatus: "1234" });
    expect(odd.description).toContain("[status 1234 (not in the table)]");
    expect(odd.identity).toContain(":s1234:");
    // two unknown codes are two rows; 123 and 9560 are two rows
    expect(overlay({ QueryName: "a.example", QueryStatus: "5678" }).identity).not.toBe(odd.identity);
    expect(overlay({ QueryName: "a.example", QueryStatus: "123" }).identity).not.toBe(
      overlay({ QueryName: "a.example", QueryStatus: "9560" }).identity,
    );
  });
  it("a record with no status says the outcome is not in it; unreadable says so", () => {
    expect(overlay({ QueryName: "a.example" }).description).toContain("[outcome not in this record]");
    expect(overlay({ QueryName: "a.example" }).identity).toContain(":s-:");
    expect(overlay({ QueryName: "a.example", QueryStatus: "ok" }).description).toContain(
      "[status not readable]",
    );
    expect(overlay({ QueryName: "a.example", QueryStatus: "ok" }).identity).toContain(":s?:");
  });
  it("success with no results, and failure with results, are both said as the record has them", () => {
    const empty = overlay({ QueryName: "a.example", QueryStatus: "0", QueryResults: "" });
    expect(empty.description).toContain("[resolved; the returned values are not in this record]");
    const contra = overlay({
      QueryName: "a.example",
      QueryStatus: "9003",
      QueryResults: "::ffff:203.0.113.5;",
    });
    expect(contra.description).toContain("[NXDOMAIN — the name does not exist at this resolver]");
    expect(contra.description).toContain("[the record also carries returned values: 203.0.113.5]");
    expect(contra.description.indexOf("[NXDOMAIN")).toBeLessThan(
      contra.description.indexOf("[the record also"),
    );
  });
  it("QueryType is evidence and identity; absent says so", () => {
    const a = overlay({ QueryName: "a.example", QueryType: "1", QueryStatus: "9501" });
    const mx = overlay({ QueryName: "a.example", QueryType: "15", QueryStatus: "9501" });
    expect(a.description).toContain("[A query]");
    expect(mx.description).toContain("[MX query]");
    expect(overlay({ QueryName: "a.example", QueryType: "99", QueryStatus: "0" }).description).toContain(
      "[type 99 query]",
    );
    expect(a.identity).toContain(":t1:");
    expect(mx.identity).toContain(":t15:");
    expect(a.identity).not.toBe(mx.identity);
    expect(a.dns.queryType).toBe(1);
    expect(overlay({ QueryName: "a.example", QueryType: "one", QueryStatus: "0" }).description).toContain(
      "[type not readable]",
    );
  });
  it("the status field is the event's own; the other spelling is never read", () => {
    const s3020 = overlay(
      { QueryName: "a.example", Status: "9003", QueryStatus: "0" },
      { statusField: "Status" },
    );
    expect(s3020.description).toContain("[NXDOMAIN");
    expect(s3020.dns.state).toBe("nxdomain");
    expect(s3020.identity).toContain(":s9003:");
    const s3008 = overlay({ QueryName: "a.example", QueryStatus: "0", Status: "9003" });
    expect(s3008.dns.state).toBe("success");
    expect(s3008.description).not.toContain("disagree");
    const agree = overlay(
      { QueryName: "a.example", Status: "9003", QueryStatus: "9003" },
      { statusField: "Status" },
    );
    expect(agree.description).toContain("[NXDOMAIN");
    expect(agree.identity).toContain(":s9003:");
    const none = overlay({ QueryName: "a.example", QueryType: "1" }, { statusField: "" });
    expect(none.description).toContain("[outcome not in this record]");
  });
  it("the query name is validated before it is an indicator, and neutralised before it is shown", () => {
    const forged = overlay({
      QueryName: "good.example] [returned: 203.0.113.66",
      QueryStatus: "123",
    });
    expect(forged.dns.queryValid).toBe(false);
    expect(forged.description).toContain("[query: good.example) (returned: 203.0.113.66]");
    expect(forged.description).toContain("[query name is not a valid name]");
    expect((forged.description.match(/\[returned:/g) ?? []).length).toBe(0);
    // …and the mark rides a neutralised name
    expect(forged.description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    const hashLabel = overlay({
      QueryName: `${"d41d8cd98f00b204e9800998ecf8427e"}.example`,
      QueryStatus: "0",
    });
    expect(hashLabel.dns.queryValid).toBe(true);
    expect(hashLabel.description).toContain("[query: d41d8cd9…427e.example]");
    expect(hashLabel.description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
  });
  it("identity is the full name and a sorted typed multiset; the display is the record's order", () => {
    const long = (tail: string) => `${"z".repeat(63)}.${"y".repeat(63)}.${"x".repeat(20)}${tail}.example`;
    const one = overlay({ QueryName: long("1"), QueryStatus: "0", QueryResults: "::ffff:192.0.2.1;" });
    const two = overlay({ QueryName: long("2"), QueryStatus: "0", QueryResults: "::ffff:192.0.2.1;" });
    expect(one.identity).not.toBe(two.identity);
    expect(one.description.replace(/ #[\w-]+$/, "")).toBe(two.description.replace(/ #[\w-]+$/, ""));
    expect(one.description).not.toBe(two.description); // the mark differs
    const ab = overlay({
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "::ffff:192.0.2.1;::ffff:192.0.2.2;",
    });
    const ba = overlay({
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "::ffff:192.0.2.2;::ffff:192.0.2.1;",
    });
    expect(ab.identity).toBe(ba.identity);
    expect(ab.description).toContain("[returned: 192.0.2.1, 192.0.2.2]");
    expect(ba.description).toContain("[returned: 192.0.2.2, 192.0.2.1]");
    // a ninth value beyond the shown eight still separates the rows, through the mark
    const nine = (last: string) =>
      overlay({
        QueryName: "a.example",
        QueryStatus: "0",
        QueryResults:
          Array.from({ length: 8 }, (_, i) => `::ffff:10.0.0.${i}`).join(";") + `;::ffff:${last};`,
      });
    expect(nine("10.0.0.8").identity).not.toBe(nine("10.0.0.9").identity);
    expect(nine("10.0.0.8").description).not.toBe(nine("10.0.0.9").description);
    expect(nine("10.0.0.8").description).toContain("+1 more");
    // a value that differs only past the display bound also separates, through the mark
    const txt = (t: string) =>
      overlay({ QueryName: "a.example", QueryStatus: "0", QueryResults: `type: 16 ${"z".repeat(70)}${t};` });
    expect(txt("1").description).not.toBe(txt("2").description);
  });
  it("a clipped CNAME target and a 65th value each keep the two records apart", () => {
    const cname = (t: string) =>
      overlay({
        QueryName: "a.example",
        QueryStatus: "0",
        QueryResults: `type: 5 ${"x".repeat(59)}${t}.example;`,
      });
    expect(cname("1").identity).not.toBe(cname("2").identity);
    expect(cname("1").description).not.toBe(cname("2").description);
    expect(cname("1").description).toMatch(/ #[\w-]{22}$/);
    const bulk = (last: string) =>
      overlay({
        QueryName: "bulk.example",
        QueryStatus: "0",
        QueryResults:
          Array.from({ length: 64 }, (_, i) => `::ffff:192.0.2.${i}`).join(";") + `;::ffff:${last};`,
      });
    expect(bulk("192.0.2.65").identity).not.toBe(bulk("192.0.2.66").identity);
    expect(bulk("192.0.2.65").dns.returned).toHaveLength(RESULTS_KEPT_MAX);
  });
  it("a value that differs past the envelope bound still separates; a name's case never does", () => {
    const txt = (t: string) =>
      overlay({
        QueryName: "txt.example",
        QueryStatus: "0",
        QueryResults: `type: 16 ${"k".repeat(512)}${t};`,
      });
    expect(txt("X").identity).not.toBe(txt("Y").identity);
    expect(txt("X").description).not.toBe(txt("Y").description);
    expect(txt("X").dns.returned[0].value.length).toBe(512);
    const srvUp = overlay({
      QueryName: "_ldap._tcp.example",
      QueryStatus: "0",
      QueryResults: "type: 33 DC01.EXAMPLE;",
    });
    const srvLo = overlay({
      QueryName: "_ldap._tcp.example",
      QueryStatus: "0",
      QueryResults: "type: 33 dc01.example;",
    });
    expect(srvUp.identity).toBe(srvLo.identity);
    expect(srvUp.dns.returned[0]).toEqual({ type: 33, value: "dc01.example", kind: "name" });
    const soa = (c: string) =>
      overlay({ QueryName: "example", QueryStatus: "0", QueryResults: `type: 6 ${c};` });
    expect(soa("NS1.Example").identity).toBe(soa("ns1.example").identity);
    const mx = (c: string) =>
      overlay({ QueryName: "example", QueryStatus: "0", QueryResults: `type: 15 ${c};` });
    expect(mx("MAIL.Example").identity).toBe(mx("mail.example").identity);
    // TXT is data, not a name: its case is evidence
    const txtCase = (c: string) =>
      overlay({ QueryName: "a.example", QueryStatus: "0", QueryResults: `type: 16 ${c};` });
    expect(txtCase("Abc").identity).not.toBe(txtCase("abc").identity);
    const upper = overlay({
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "type: 5 EDGE.Example;",
    });
    const lower = overlay({
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "type: 5 edge.example;",
    });
    expect(upper.identity).toBe(lower.identity);
    expect(upper.description).toBe(lower.description);
    expect(upper.dns.returned[0].value).toBe("edge.example");
  });
  it("the exact recorded name is validated; whitespace is not trimmed away into a valid name", () => {
    const padded = overlay({ QueryName: "good.example ", QueryStatus: "123" });
    expect(padded.dns.queryValid).toBe(false);
    expect(padded.description).toContain("[query name is not a valid name]");
    expect(padded.identity).not.toBe(overlay({ QueryName: "good.example", QueryStatus: "123" }).identity);
    expect(overlay({ QueryName: " a.example", QueryStatus: "0" }).identity).not.toBe(
      overlay({ QueryName: "a.example ", QueryStatus: "0" }).identity,
    );
  });
  it("a 3006 says whether the call went to the network; the two are two rows", () => {
    const local = overlay(
      { QueryName: "a.example", QueryType: "1", IsNetworkQuery: "0" },
      { statusField: "" },
    );
    const net = overlay({ QueryName: "a.example", QueryType: "1", IsNetworkQuery: "1" }, { statusField: "" });
    expect(local.description).toContain("[not a network query]");
    expect(local.description).not.toContain("answered");
    expect(net.description).toContain("[network query]");
    expect(local.identity).not.toBe(net.identity);
    expect(local.dns.networkQuery).toBe(false);
    expect(net.dns.networkQuery).toBe(true);
    expect(overlay({ QueryName: "a.example", QueryStatus: "0" }).dns.networkQuery).toBeUndefined();
  });
  it("a reversed CNAME chain is another row; a reordered address set after it is the same row", () => {
    const rec = (results: string) =>
      overlay({ QueryName: "a.example", QueryStatus: "0", QueryResults: results });
    const ab = rec("type: 5 a.example;type: 5 b.example;::ffff:192.0.2.1;::ffff:192.0.2.2;");
    const ba = rec("type: 5 b.example;type: 5 a.example;::ffff:192.0.2.1;::ffff:192.0.2.2;");
    const abSwapped = rec("type: 5 a.example;type: 5 b.example;::ffff:192.0.2.2;::ffff:192.0.2.1;");
    expect(ab.identity).not.toBe(ba.identity);
    expect(ab.identity).toBe(abSwapped.identity);
    // a CNAME that sorts to the front of the unordered section is not a longer chain
    const oneStep = rec("type: 5 b.example;type: 6 ns.example;type: 5 a.example;");
    const twoSteps = rec("type: 5 b.example;type: 5 a.example;type: 6 ns.example;");
    expect(oneStep.identity).not.toBe(twoSteps.identity);
    // an NS after the chain is unordered data, so its position is not identity
    const nsA = rec("type: 5 a.example;type: 2 ns.example;::ffff:192.0.2.1;");
    const nsB = rec("type: 5 a.example;::ffff:192.0.2.1;type: 2 ns.example;");
    expect(nsA.identity).toBe(nsB.identity);
  });
  it("a U-label name is keyed and reported in its A-label form", () => {
    const u = overlay({
      QueryName: "ū̃.attacker.example",
      QueryStatus: "0",
      QueryResults: "::ffff:192.0.2.1;",
    });
    expect(u.dns.query).toBe("xn--zga03f.attacker.example");
    expect(u.dns.indicator).toBe(true);
    expect(u.identity).toBe(
      overlay({
        QueryName: "xn--zga03f.attacker.example",
        QueryStatus: "0",
        QueryResults: "::ffff:192.0.2.1;",
      }).identity,
    );
    expect(u.description).toContain("[query: ū̃.attacker.example]");
    expect(u.description).toMatch(/ #[\w-]{22}$/); // the shown name is not the keyed name
  });
  it("two malformed Unicode names that would truncate alike are two identities and mint nothing", () => {
    const a = overlay({ QueryName: "safe.example/bücher.attacker", QueryStatus: "123", QueryResults: "-" });
    const b = overlay({ QueryName: "safe.example/über.attacker", QueryStatus: "123", QueryResults: "-" });
    expect(a.dns.queryValid).toBe(false);
    expect(a.dns.indicator).toBe(false);
    expect(a.identity).not.toBe(b.identity);
    expect(a.dns.query).toBe("safe.example/bücher.attacker");
    // a returned CNAME with the same shape is data, not a name
    const c = overlay({
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: "type: 5 safe.example/bücher.attacker;",
    });
    expect(c.dns.returned[0].kind).toBe("other");
  });
  it("a field the event does not define is decoration, never evidence", () => {
    // a 3006 carries no results: a QueryResults beside it forges nothing
    const s3006 = overlay(
      { QueryName: "a.example", QueryType: "1", IsNetworkQuery: "1", QueryResults: "type: 1 203.0.113.9;" },
      { schema: DNS_CLIENT_EVENTS[3006].dns },
    );
    expect(s3006.description).not.toContain("203.0.113.9");
    expect(s3006.dns.returned).toEqual([]);
    expect(s3006.identity).toContain(":r-");
    // a 3008 carries no IsNetworkQuery; a Sysmon 22 carries no QueryType
    const s3008 = overlay(
      { QueryName: "a.example", QueryType: "1", QueryStatus: "0", IsNetworkQuery: "1" },
      { schema: DNS_CLIENT_EVENTS[3008].dns },
    );
    expect(s3008.description).not.toContain("network query");
    expect(s3008.dns.networkQuery).toBeUndefined();
    const s22 = overlay(
      { QueryName: "a.example", QueryType: "1", QueryStatus: "0" },
      { schema: SYSMON_22_DNS },
    );
    expect(s22.description).toContain("[type not in this record]");
    expect(s22.dns.queryType).toBeUndefined();
  });
  it("a complete rendering carries no mark; the description stays inside 600 characters", () => {
    const plain = overlay({ QueryName: "a.example", QueryStatus: "0", QueryResults: "::ffff:192.0.2.1;" });
    expect(plain.description).not.toMatch(/ #[\w-]+$/);
    const big = overlay({
      QueryName: "a.example",
      QueryStatus: "0",
      QueryResults: Array.from({ length: 80 }, (_, i) => `type: 16 ${"t".repeat(50)}${i}`).join(";") + ";",
    });
    expect(big.description.length).toBeLessThanOrEqual(600);
    expect(big.description).toMatch(/ #[\w-]{22}$/);
    expect(big.dns.returned.length).toBe(RESULTS_KEPT_MAX);
  });
});
