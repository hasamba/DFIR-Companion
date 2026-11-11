import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { parseSigmaRule } from "../../src/analysis/sigmaRule.js";

// #2572 — the 🔍 hunt modal's KQL / SPL / ES|QL (and VQL, Sigma, YARA, Suricata) builders template
// evidence values: paths, URLs, domains, host names. Those are attacker-controlled. The old shared
// helper escaped `"` but not `\`, so `C:\Temp\` left the string open and `C:\a\evil\" or true //x`
// turned `or true` into live KQL. Each test below decodes the emitted literal with an INDEPENDENT
// reader written from the language's own rules, and checks the query skeleton (everything outside
// the literals, comments removed) is identical to the one a harmless value produces.

interface HuntCtx {
  hashes: string[];
  ips: string[];
  domains: string[];
  urls: string[];
  paths: string[];
  processes: string[];
  parent: string;
  host: string;
  label: string;
}

type Builder = (c: HuntCtx) => string;
interface HuntApi {
  huntKql: Builder;
  huntSpl: Builder;
  huntVql: Builder;
  huntVqlNotebook: Builder;
  huntSigma: Builder;
  huntEsql: Builder;
  huntYara: Builder;
  huntSuricata: Builder;
  kqlString: (v: unknown) => string;
  splString: (v: unknown) => string;
  esqlString: (v: unknown) => string;
  vqlString: (v: unknown) => string;
  yamlString: (v: unknown) => string;
  yaraString: (v: unknown) => string;
}

const api = loadDashboardModule<HuntApi>(
  "dashboard-sigma-hunt.js",
  ["dashboard-hunt-quote.js", "dashboard-bulk-findings.js"],
  { URL, DfirState: { lastState: () => null } },
);

const ctx = (over: Partial<HuntCtx> = {}): HuntCtx => ({
  hashes: [],
  ips: [],
  domains: [],
  urls: [],
  paths: [],
  processes: [],
  parent: "",
  host: "",
  label: "x",
  ...over,
});

// Every field set to the same value — the widest surface a single evidence string can reach.
const everywhere = (v: string): HuntCtx =>
  ctx({
    hashes: [v],
    ips: [v],
    domains: [v],
    urls: [v],
    paths: [v],
    processes: [v],
    parent: v,
    host: v,
    label: v,
  });

const VECTORS = [
  'say "hi"',
  "\\",
  "C:\\Temp\\",
  "C:\\Windows\\Temp\\x.ps1",
  "a//b",
  "a|b",
  "line1\nline2",
  "cr\rtab\t",
  'C:\\a\\evil\\" or true //x',
  'http://x/a\\" or true //',
];

// ── Independent literal readers ───────────────────────────────────────────────────────────────
// Each returns the decoded value and the index just past the closing quote, or throws on a literal
// the language would reject (unterminated, raw line break where none is allowed, bad escape).

interface Lit {
  value: string;
  end: number;
}
type Reader = (q: string, start: number) => Lit;

function readWith(
  escapes: Record<string, string>,
  opts: { rawBreaks: boolean; hex?: "x" | "u"; passUnknown?: boolean },
): Reader {
  return (q, start) => {
    let out = "";
    for (let i = start + 1; i < q.length; i++) {
      const ch = q[i];
      if (ch === '"') return { value: out, end: i + 1 };
      if ((ch === "\n" || ch === "\r") && !opts.rawBreaks)
        throw new Error(`raw line break in literal at ${i}`);
      if (ch !== "\\") {
        out += ch;
        continue;
      }
      const nx = q[i + 1];
      if (nx === undefined) break;
      if (nx in escapes) {
        out += escapes[nx];
        i++;
      } else if (opts.hex === "u" && nx === "u") {
        out += String.fromCharCode(parseInt(q.slice(i + 2, i + 6), 16));
        i += 5;
      } else if (opts.hex === "x" && nx === "x") {
        out += String.fromCharCode(parseInt(q.slice(i + 2, i + 4), 16));
        i += 3;
      } else if (opts.passUnknown) {
        out += "\\";
      } else {
        throw new Error(`unknown escape \\${nx} at ${i}`);
      }
    }
    throw new Error(`unterminated literal from ${start}`);
  };
}

const KQL = readWith(
  { '"': '"', "'": "'", "\\": "\\", n: "\n", t: "\t", r: "\r" },
  { rawBreaks: false, hex: "u" },
);
// SPL: \\ and \" are the escapes; any other backslash sequence passes through unchanged.
const SPL = readWith({ '"': '"', "\\": "\\", "|": "|" }, { rawBreaks: true, passUnknown: true });
const ESQL = readWith({ '"': '"', "\\": "\\", n: "\n", t: "\t", r: "\r" }, { rawBreaks: false });
// vfilter's utils.Unquote: \\ \" \' \n \r \t \xHH; any OTHER escape drops its backslash, so a raw
// backslash in a value is lost. Strict here: the builders must never emit an unknown escape.
const VQL = readWith(
  { '"': '"', "'": "'", "\\": "\\", n: "\n", r: "\r", t: "\t" },
  { rawBreaks: true, hex: "x" },
);
const YARA = readWith({ '"': '"', "\\": "\\", n: "\n", t: "\t", r: "\r" }, { rawBreaks: false, hex: "x" });

/** Split a query into its skeleton (literals → "S", line comments dropped) and the decoded literals. */
function scan(q: string, read: Reader, lineComment: string | null): { skeleton: string; literals: string[] } {
  let skeleton = "";
  const literals: string[] = [];
  let i = 0;
  while (i < q.length) {
    if (lineComment && q.startsWith(lineComment, i)) {
      const nl = q.indexOf("\n", i);
      i = nl === -1 ? q.length : nl;
      continue;
    }
    if (q[i] === '"') {
      const lit = read(q, i);
      literals.push(lit.value);
      skeleton += '"S"';
      i = lit.end;
      continue;
    }
    skeleton += q[i++];
  }
  return { skeleton, literals };
}

interface Lang {
  name: string;
  build: Builder;
  read: Reader;
  comment: string | null;
}
const LANGS: Lang[] = [
  { name: "KQL", build: (c) => api.huntKql(c), read: KQL, comment: "//" },
  { name: "SPL", build: (c) => api.huntSpl(c), read: SPL, comment: null },
  { name: "ES|QL", build: (c) => api.huntEsql(c), read: ESQL, comment: "//" },
  { name: "VQL", build: (c) => api.huntVql(c), read: VQL, comment: "--" },
  { name: "VQL notebook", build: (c) => api.huntVqlNotebook(c), read: VQL, comment: "--" },
];

describe("per-language quoting functions decode back to the original value", () => {
  const fns: Array<[string, (v: unknown) => string, Reader]> = [
    ["kqlString", api.kqlString, KQL],
    ["splString", api.splString, SPL],
    ["esqlString", api.esqlString, ESQL],
    ["vqlString", api.vqlString, VQL],
    ["yaraString", api.yaraString, YARA],
  ];
  for (const [name, fn, read] of fns) {
    it.each(VECTORS)(`${name} round-trips %j as one literal`, (v) => {
      const q = fn(v);
      const lit = read(q, 0);
      expect(lit.value).toBe(v);
      expect(lit.end).toBe(q.length); // the literal ends exactly at the last character
    });
  }

  it.each(VECTORS)("yamlString round-trips %j as one YAML scalar", (v) => {
    expect(parseYaml(`k: ${api.yamlString(v)}`)).toEqual({ k: v });
  });

  it("KQL writes a Windows path with doubled backslashes, so \\W, \\T, \\x are not read as escapes", () => {
    expect(api.kqlString("C:\\Windows\\Temp\\x.ps1")).toBe('"C:\\\\Windows\\\\Temp\\\\x.ps1"');
  });
});

describe("hunt builders: an evidence value can never change the query structure", () => {
  for (const lang of LANGS) {
    const base = scan(lang.build(everywhere("benign")), lang.read, lang.comment).skeleton;
    it.each(VECTORS)(`${lang.name}: %j stays inside its literals`, (v) => {
      const out = scan(lang.build(everywhere(v)), lang.read, lang.comment);
      expect(out.skeleton).toBe(base);
    });
  }

  it.each(VECTORS)("KQL / SPL / ES|QL carry an IP value through verbatim: %j", (v) => {
    const c = ctx({ ips: [v] });
    expect(scan(api.huntKql(c), KQL, "//").literals).toContain(v);
    expect(scan(api.huntSpl(c), SPL, null).literals).toContain(v);
    expect(scan(api.huntEsql(c), ESQL, "//").literals).toContain(v);
  });

  it("the reported KQL injection is inert: `or true //` sits inside the FolderPath literal", () => {
    const q = api.huntKql(ctx({ paths: ['C:\\a\\evil\\" or true //x'] }));
    const out = scan(q, KQL, "//");
    expect(out.literals).toContain('C:\\a\\evil\\" or true //x');
    expect(out.skeleton).not.toMatch(/or true/);
  });

  it("SPL contains-matches escape the value between the builder's own wildcards", () => {
    const out = scan(api.huntSpl(ctx({ domains: ['evil\\" OR index=*'] })), SPL, null);
    expect(out.literals).toContain('*evil\\" OR index=**');
  });

  it("a trailing backslash no longer leaves the SPL string open", () => {
    const out = scan(api.huntSpl(ctx({ host: "C:\\Temp\\", paths: ["C:\\Temp\\"] })), SPL, null);
    expect(out.literals).toContain("C:\\Temp\\");
  });

  it("the VQL notebook's FileFinder glob table keeps its \\n row separator", () => {
    const out = scan(api.huntVqlNotebook(ctx({ paths: ["C:\\Users\\x.exe"] })), VQL, "--");
    expect(out.literals).toContain("Glob\nC:/Users/x.exe");
  });
});

describe("Sigma skeleton — YAML structure holds", () => {
  it.each(VECTORS)("%j round-trips through the YAML and adds no keys", (v) => {
    const doc = parseYaml(api.huntSigma(everywhere(v)));
    expect(Object.keys(doc)).toEqual(["title", "status", "logsource", "detection", "level", "tags"]);
    expect(Object.keys(doc.detection.selection)).toEqual([
      "Image|endswith",
      "ParentImage|endswith",
      "Hashes|contains",
    ]);
    expect(doc.detection.selection["Hashes|contains"]).toBe(v);
    expect(doc.title).toBe(`Hunt - ${v.slice(0, 60)}`);
  });
});

describe("Sigma skeleton — the server's own Sigma parser reads it", () => {
  it("decodes Image|endswith to exactly \\evil.exe and keeps the hash verbatim", () => {
    const yaml = api.huntSigma(
      ctx({ processes: ["C:\\Windows\\Temp\\evil.exe"], parent: "cmd.exe", hashes: ['ab\\cd"ef'] }),
    );
    const res = parseSigmaRule(yaml);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const json = JSON.stringify(res.rule.detection.selections);
    expect(json).toContain(JSON.stringify("\\evil.exe"));
    expect(json).toContain(JSON.stringify("\\cmd.exe"));
    expect(json).toContain(JSON.stringify('ab\\cd"ef'));
  });
});

describe("YARA — the rule stays one rule", () => {
  it.each(VECTORS)("%j in the label and hash decodes back and adds no condition", (v) => {
    const q = api.huntYara(ctx({ hashes: [v], label: v }));
    const lits = scan(q, YARA, "//").literals;
    expect(lits).toContain(v.toLowerCase());
    expect(lits).toContain(`Retro-hunt for confirmed indicator: ${v.slice(0, 80)}`);
    const base = scan(api.huntYara(ctx({ hashes: ["benign"], label: "benign" })), YARA, "//").skeleton;
    expect(scan(q, YARA, "//").skeleton.replace(/rule \w+/, "rule R")).toBe(
      base.replace(/rule \w+/, "rule R"),
    );
  });
});

describe("Suricata — a value can never start a second rule", () => {
  it.each(VECTORS)("%j in a domain / URL keeps one rule per line, msg and content well-formed", (v) => {
    const q = api.huntSuricata(ctx({ domains: [v] }));
    const lines = q.split("\n");
    expect(lines).toHaveLength(3); // DNS, TLS SNI, HTTP host — never more
    for (const line of lines) {
      expect(line).toMatch(
        /^alert \w+ \$HOME_NET any -> any any \(msg:"[^"\\;\n]*"; [\w.]+; content:"[^"\\;\n]*"; nocase; sid:\d+; rev:1;\)$/,
      );
    }
  });

  it("drops an IP value that is not an address, instead of writing it into the rule header", () => {
    const q = api.huntSuricata(
      ctx({ ips: ["10.0.0.1", 'any any (msg:"x"; sid:1;)\nalert ip any any -> any any'] }),
    );
    expect(q.split("\n")).toHaveLength(1);
    expect(q).toContain("-> 10.0.0.1 any");
  });
});

describe("wiring — the quote module ships and loads before its callers", () => {
  const root = new URL("../../../public/", import.meta.url);
  const html = readFileSync(new URL("dashboard.html", root), "utf8");
  it("is tagged in dashboard.html ahead of dashboard-bulk-findings.js and served as JavaScript", () => {
    const quote = html.indexOf('<script src="/js/dashboard-hunt-quote.js"></script>');
    expect(quote).toBeGreaterThan(-1);
    expect(quote).toBeLessThan(html.indexOf('<script src="/js/dashboard-bulk-findings.js"></script>'));
    expect(STATIC_ASSETS["/js/dashboard-hunt-quote.js"]).toMatch(/javascript/);
  });

  it("no builder still uses the old quote-only helper", () => {
    for (const f of ["dashboard-bulk-findings.js", "dashboard-sigma-hunt.js"]) {
      expect(readFileSync(new URL(`js/${f}`, root), "utf8")).not.toMatch(/\bhq\(/);
    }
  });
});
