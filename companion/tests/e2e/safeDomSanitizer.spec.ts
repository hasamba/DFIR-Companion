import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { test, expect, type Page } from "@playwright/test";
import { renderStandalonePresentation } from "../../src/reports/presentationExport.js";

// Covers: NO USER STORY EXISTS.
// The browser half of the safe-dom policy (#1787). The unit test in
// tests/reports/safeDomPolicy.test.ts judges attributes by rule; only a real parser can prove the
// final LIVE DOM is clean after the sanitize → serialize → re-parse round trip, in every parse
// context a sink can use (div, table body, select, SVG), with and without Trusted Types (Firefox
// has none), and in the exported deck opened from file:// with no CSP. It needs no server.

const SAFE_DOM = new URL("../../../public/js/safe-dom.js", import.meta.url);
const GLYPHS = new URL("../../../public/js/dashboard-glyphs.js", import.meta.url);
const LEAFLET = new URL("../../../public/vendor/leaflet/leaflet.js", import.meta.url);
const CYTOSCAPE = new URL("../../../public/vendor/cytoscape/cytoscape.min.js", import.meta.url);

function esc(value: string): string {
  const map: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return value.replace(/[&<>"']/g, (c) => map[c]);
}

// Text the old attribute regexes deleted or rewrote on screen.
const EVIDENCE = [
  "<img src=x onerror=alert(2)> | pipe |",
  'powershell.exe -c "Start-Process x" onload=1',
  'cmdline: mshta.exe vbscript:Execute onclick="x"',
  "wmic process call create \"c:\\x.exe\" onerror='y'",
  "user typed: srcdoc=foo bar",
  "benign text with only=equals",
  "one=1 online=yes OneDrive=C:\\Users\\a\\OneDrive",
  'schtasks /create /tn x /tr "cmd /c evil" style=color:red',
];

// Each payload sets window.__xss if any part of it ever runs.
const X = "window.__xss=1";

interface AuditWindow {
  __audit(node: ParentNode): string[];
  __xss?: number;
}
const PAYLOADS = [
  `<img src=x onerror="${X}">`,
  `<IMG SRC=x ONERROR=${X}>`,
  `<script>${X}</script>`,
  `<svg onload="${X}"><rect onpointerenter="${X}"/><a href="javascript:${X}">a</a></svg>`,
  `<iframe srcdoc="<script>${X}</script>"></iframe>`,
  `<div style="background:url(https://attacker.invalid/leak)">field</div>`,
  `<form action="https://attacker.invalid"><button formaction="javascript:${X}">x</button></form>`,
  `<a href=" jav&#x09;ascript:${X}">tab-split scheme</a>`,
  `<svg></p><style><a id="</style><img src=1 onerror=${X}>">`,
  `<math><mtext><table><mglyph><style><img src=x onerror=${X}>`,
  `<form><math><mtext></form><form><mglyph><style></math><img src onerror=${X}>`,
  `<noscript><p title="</noscript><img src=x onerror=${X}>">`,
  `<svg><foreignObject><img src=x onerror=${X}></foreignObject></svg>`,
  `<svg><desc><img src=x onerror=${X}></desc><title><img src=x onerror=${X}></title></svg>`,
  `<xmp><img src=x onerror=${X}></xmp><textarea><img src=x onerror=${X}></textarea>`,
  `<table><tr><td><img src=x onerror=${X}></td></tr></table>`,
  `<select><option><img src=x onerror=${X}></option></select>`,
  `<svg><animate onbegin=${X} attributeName=x dur=1s></animate><set attributeName=onmouseover to=${X} /></svg>`,
  `<img srcset="x 1x" onerror=${X}><a href="/x" target="_blank" rel="opener">x</a>`,
  `<svg><a xlink:href="javascript:${X}"><text>t</text></a></svg>`,
  `<svg xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="data:image/svg+xml,x"/></svg>`,
  `<img src=x src=y onerror=${X} onerror=${X}><a href="/ok" href="javascript:${X}">dup</a>`,
  `<svg><circle ONLOAD=${X} Style="fill:url(https://attacker.invalid/x)"/></svg>`,
  `<div style="background-image:image-set('https://attacker.invalid/set' 1x)">set</div>`,
  `<div style="background-image:-webkit-image-set('https://attacker.invalid/wk' 1x)">wk</div>`,
  `<div style="background:cross-fade(image('https://attacker.invalid/img'),red)">img</div>`,
  `<svg><rect width=9 height=9 fill="url(https://attacker.invalid/paint.svg#g)"/></svg>`,
  `<svg><rect width=9 height=9 cursor="\\75rl(https://attacker.invalid/cur.png), auto" fill="\\75rl(https://attacker.invalid/esc.svg#g)"/></svg>`,
  `<img src="/\\attacker.invalid/bs"><img src="\\\\attacker.invalid/bs2">`,
];

// Every request the page makes to the attacker host. A sanitizer that leaves a fetchable URL fails
// here even when no attribute text looks suspicious.
function watchAttackerRequests(page: Page): string[] {
  const seen: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("attacker.invalid")) seen.push(request.url());
  });
  return seen;
}

// A routed http origin (no server): blob: URLs, relative links and URL-part setters behave as on
// the real dashboard, which about:blank (an opaque origin with no base URL) cannot show.
const APP_ORIGIN = "http://companion.example.com";
// The production Trusted Types directives (companion/src/http/securityHeaders.ts), so the "with
// Trusted Types" runs are enforced, as on the dashboard (#1864).
const TT_CSP = "require-trusted-types-for 'script'; trusted-types default dfir-parser dfir-safe-html";

// Reports every executable or fetch-capable leftover under a node. Installed in the page as
// window.__audit, next to the scripts under test.
function audit(node: ParentNode): string[] {
  const problems: string[] = [];
  const blocked =
    "script,iframe,object,embed,foreignobject,math,style,template,base,meta,link,noscript,animate,set";
  node.querySelectorAll(blocked).forEach((el) => problems.push(`element ${el.tagName}`));
  node.querySelectorAll("*").forEach((el) => {
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      if (/^on|^srcdoc$|^style$|^action$|^formaction$|^srcset$/.test(name))
        problems.push(`${el.tagName} ${name}`);
      if (/javascript:|vbscript:/i.test(attr.value.replace(/[\u0000-\u0020]/g, "")))
        problems.push(`${el.tagName} ${name}=${attr.value}`);
    }
    if (el.shadowRoot) problems.push(`${el.tagName} has a shadow root`);
  });
  return problems;
}

// The page carries safe-dom.js and any app or vendored script as static inline scripts, in load
// order, as the dashboard does. Playwright's addScriptTag builds a script element by script, which
// safe-dom now refuses by design (#1864). The last inline script proves static scripts still run.
async function pageHtml(withoutTrustedTypes: boolean, scripts: URL[]): Promise<string> {
  const sources = await Promise.all([SAFE_DOM, ...scripts].map((url) => readFile(url, "utf8")));
  const inline = sources.map((source) => `<script>${source.replace(/<\/script/gi, "<\\/script")}</script>`);
  const csp = withoutTrustedTypes ? "" : `<meta http-equiv="Content-Security-Policy" content="${TT_CSP}">`;
  return (
    `<!doctype html><html><head>${csp}${inline.join("")}</head><body><main id=root></main>` +
    `<script>window.__audit = ${audit.toString()}; window.__static = 1;</script></body></html>`
  );
}

interface GuardOptions {
  onAppOrigin?: boolean;
  scripts?: URL[];
  // Extra same-origin responses (path → [content type, body]); app origin only.
  responses?: Record<string, [string, string]>;
}

async function loadGuard(
  page: Page,
  withoutTrustedTypes: boolean,
  options: GuardOptions | boolean = {},
): Promise<void> {
  const {
    onAppOrigin = false,
    scripts = [],
    responses = {},
  } = typeof options === "boolean" ? { onAppOrigin: options } : options;
  if (withoutTrustedTypes) {
    await page.addInitScript(() => {
      Object.defineProperty(window, "trustedTypes", { value: undefined, configurable: true });
    });
  }
  const html = await pageHtml(withoutTrustedTypes, scripts);
  if (onAppOrigin) {
    await page.route(`${APP_ORIGIN}/**`, (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/") return route.fulfill({ contentType: "text/html", body: html });
      const extra = responses[path];
      return extra
        ? route.fulfill({ contentType: extra[0], body: extra[1] })
        : route.fulfill({ status: 404, body: "" });
    });
    await page.goto(`${APP_ORIGIN}/`);
  } else {
    await page.goto("about:blank");
    await page.setContent(html);
  }
  expect(await page.evaluate(() => (window as unknown as { __static?: number }).__static)).toBe(1);
}

// Every sink a renderer can reach, in every parse context: the native setter re-parses the
// sanitized markup there, which is where a mutation-XSS shape would come alive.
async function renderAllSinks(page: Page, html: string): Promise<string[]> {
  return page.evaluate(async (markup) => {
    const root = document.getElementById("root")!;
    root.textContent = "";
    const div = root.appendChild(document.createElement("div"));
    div.innerHTML = markup;
    const tbody = root
      .appendChild(document.createElement("table"))
      .appendChild(document.createElement("tbody"));
    tbody.innerHTML = markup;
    const select = root.appendChild(document.createElement("select"));
    select.innerHTML = markup;
    const svg = root.appendChild(document.createElementNS("http://www.w3.org/2000/svg", "svg"));
    svg.innerHTML = markup;
    const outer = root.appendChild(document.createElement("div")).appendChild(document.createElement("span"));
    outer.outerHTML = markup;
    root.appendChild(document.createElement("div")).insertAdjacentHTML("beforeend", markup);
    await new Promise((resolve) => setTimeout(resolve, 150));

    const problems: string[] = [];
    if ((window as unknown as { __xss?: number }).__xss) problems.push("payload executed");
    const blocked =
      "script,iframe,object,embed,foreignobject,math,style,template,base,meta,link,noscript,animate,set";
    root.querySelectorAll(blocked).forEach((el) => problems.push(`element ${el.tagName}`));
    root.querySelectorAll("*").forEach((el) => {
      for (const attr of Array.from(el.attributes)) {
        const name = attr.name.toLowerCase();
        if (/^on|^srcdoc$|^style$|^action$|^formaction$|^srcset$/.test(name))
          problems.push(`${el.tagName} ${name}`);
        if (/javascript:|vbscript:/i.test(attr.value.replace(/[\u0000-\u0020]/g, "")))
          problems.push(`${el.tagName} ${name}=${attr.value}`);
      }
      if (
        el.tagName === "A" &&
        el.getAttribute("target") === "_blank" &&
        el.getAttribute("rel") !== "noopener noreferrer"
      ) {
        problems.push("target=_blank without noopener");
      }
    });
    return problems;
  }, html);
}

for (const withoutTrustedTypes of [false, true]) {
  const label = withoutTrustedTypes ? "without Trusted Types" : "with Trusted Types";

  test.describe(`safe-dom live DOM (${label})`, () => {
    test("no raw XSS payload survives any sink or parse context", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes);
      for (const payload of PAYLOADS) {
        expect(await renderAllSinks(page, payload), payload).toEqual([]);
      }
      expect(requests).toEqual([]);
    });

    test("setAttribute and setAttributeNS apply the markup deny rules (#1813)", async ({ page }) => {
      await loadGuard(page, withoutTrustedTypes);
      const kept = await page.evaluate(() => {
        const svgNs = "http://www.w3.org/2000/svg";
        const xlink = "http://www.w3.org/1999/xlink";
        const cases: [Element, string, string][] = [
          [document.createElement("form"), "action", "https://attacker.invalid/"],
          [document.createElement("button"), "formaction", "javascript:window.__xss=1"],
          [document.createElement("img"), "srcset", "https://attacker.invalid/x 1x"],
          [document.createElement("a"), "ping", "https://attacker.invalid/"],
          [document.createElement("img"), "src", "/\\attacker.invalid/x"],
          [document.createElement("a"), "href", "javascript:window.__xss=1"],
          [document.createElementNS(svgNs, "rect"), "fill", "url(https://attacker.invalid/p.svg#g)"],
          [document.createElementNS(svgNs, "rect"), "cursor", "\\75rl(https://attacker.invalid/c.png), auto"],
        ];
        const out: string[] = [];
        for (const [el, name, value] of cases) {
          el.setAttribute(name, value);
          if (el.hasAttribute(name)) out.push(`${el.tagName} ${name}`);
        }
        const a = document.createElementNS(svgNs, "a");
        a.setAttributeNS(xlink, "evil:href", "javascript:window.__xss=1");
        if (a.attributes.length) out.push("svg a xlink href");
        const path = document.createElementNS(svgNs, "path");
        path.setAttribute("fill-rule", "evenodd");
        path.setAttribute("pointer-events", "none");
        if (path.getAttribute("fill-rule") !== "evenodd") out.push("fill-rule lost");
        if (path.getAttribute("pointer-events") !== "none") out.push("pointer-events lost");
        return out;
      });
      expect(kept).toEqual([]);
    });

    test("property setters and URL parts refuse what setAttribute refuses (#1858)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes, true);
      const kept = await page.evaluate(async () => {
        const X = "javascript:window.__xss=1";
        const root = document.getElementById("root")!;
        const out: string[] = [];
        const cases: [string, string, string, string][] = [
          ["a", "href", "href", X],
          ["a", "ping", "ping", "https://attacker.invalid/ping"],
          ["area", "href", "href", X],
          ["link", "href", "href", "https://attacker.invalid/x.css"],
          ["base", "href", "href", "https://attacker.invalid/"],
          ["form", "action", "action", "https://attacker.invalid/"],
          ["button", "formAction", "formaction", X],
          ["input", "formAction", "formaction", X],
          ["input", "src", "src", "https://attacker.invalid/input.png"],
          ["img", "src", "src", "https://attacker.invalid/img.png"],
          ["img", "srcset", "srcset", "https://attacker.invalid/set.png 1x"],
          ["source", "srcset", "srcset", "https://attacker.invalid/src.png 1x"],
          ["source", "src", "src", "https://attacker.invalid/src.mp4"],
          ["iframe", "src", "src", X],
          ["iframe", "srcdoc", "srcdoc", "<script>parent.__xss=1</script>"],
          ["object", "data", "data", "https://attacker.invalid/obj.html"],
          ["embed", "src", "src", "https://attacker.invalid/embed.swf"],
          ["video", "src", "src", "https://attacker.invalid/v.mp4"],
          ["video", "poster", "poster", "https://attacker.invalid/poster.png"],
          ["audio", "src", "src", "https://attacker.invalid/a.mp3"],
          ["track", "src", "src", "https://attacker.invalid/t.vtt"],
          ["script", "src", "src", "https://attacker.invalid/s.js"],
          ["meta", "httpEquiv", "http-equiv", "refresh"],
        ];
        for (const [tag, prop, attr, value] of cases) {
          const el = root.appendChild(document.createElement(tag)) as unknown as Record<string, unknown> &
            Element;
          try {
            el[prop] = value;
          } catch (error) {
            out.push(`${tag}.${prop} threw ${String(error)}`);
          }
          if (el.hasAttribute(attr)) out.push(`${tag}.${prop} kept ${el.getAttribute(attr)}`);
        }
        for (const tag of ["a", "area"]) {
          const link = root.appendChild(document.createElement(tag)) as HTMLAnchorElement;
          link.href = "mailto:analyst@example.com";
          link.protocol = "javascript";
          if (link.getAttribute("href") !== "mailto:analyst@example.com")
            out.push(`${tag}.protocol → ${link.getAttribute("href")}`);
          link.href = "/cases/demo";
          link.hash = "#section";
          if (!/\/cases\/demo#section$/.test(link.getAttribute("href") || ""))
            out.push(`${tag}.hash lost: ${link.getAttribute("href")}`);
        }
        const svgNs = "http://www.w3.org/2000/svg";
        const svg = root.appendChild(document.createElementNS(svgNs, "svg"));
        const svgA = svg.appendChild(document.createElementNS(svgNs, "a"));
        svgA.href.baseVal = X;
        if (svgA.hasAttribute("href")) out.push(`svg a href.baseVal kept ${svgA.getAttribute("href")}`);
        const use = svg.appendChild(document.createElementNS(svgNs, "use"));
        use.href.baseVal = "https://attacker.invalid/sprite.svg#x";
        if (use.hasAttribute("href")) out.push("svg use href.baseVal kept a remote sprite");
        use.href.baseVal = "#local";
        if (use.getAttribute("href") !== "#local") out.push("svg use lost a local #ref");
        const image = svg.appendChild(document.createElementNS(svgNs, "image"));
        image.href.baseVal = "https://attacker.invalid/svg-image.png";
        if (image.hasAttribute("href")) out.push("svg image href.baseVal kept a remote image");
        await new Promise((resolve) => setTimeout(resolve, 200));
        if ((window as unknown as { __xss?: number }).__xss) out.push("payload executed");
        return out;
      });
      expect(kept).toEqual([]);
      expect(requests).toEqual([]);
    });

    test("attribute nodes are judged like setAttribute (#1858)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes, true);
      const kept = await page.evaluate(async () => {
        const X = "javascript:window.__xss=1";
        const root = document.getElementById("root")!;
        const out: string[] = [];
        const attr = (name: string, value: string) => {
          const a = document.createAttribute(name);
          a.value = value;
          return a;
        };
        const a1 = root.appendChild(document.createElement("a"));
        a1.setAttributeNode(attr("href", X));
        a1.setAttributeNode(attr("onclick", "window.__xss=1"));
        if (a1.attributes.length) out.push(`setAttributeNode kept ${a1.getAttributeNames()}`);
        const a2 = root.appendChild(document.createElement("a"));
        a2.setAttributeNodeNS(attr("href", X));
        const xl = document.createAttributeNS("http://www.w3.org/1999/xlink", "evil:href");
        xl.value = X;
        const svgA = root
          .appendChild(document.createElementNS("http://www.w3.org/2000/svg", "svg"))
          .appendChild(document.createElementNS("http://www.w3.org/2000/svg", "a"));
        svgA.setAttributeNodeNS(xl);
        if (a2.attributes.length || svgA.attributes.length) out.push("setAttributeNodeNS kept a URL");
        const iframe = root.appendChild(document.createElement("iframe"));
        iframe.attributes.setNamedItem(attr("srcdoc", "<script>parent.__xss=1</script>"));
        iframe.attributes.setNamedItemNS(attr("src", X));
        if (iframe.attributes.length) out.push(`setNamedItem kept ${iframe.getAttributeNames()}`);
        const a3 = root.appendChild(document.createElement("a"));
        a3.setAttribute("href", "/cases/demo");
        a3.setAttribute("title", "tip");
        const href = a3.getAttributeNode("href")!;
        href.value = X;
        href.nodeValue = X;
        href.textContent = X;
        if (a3.getAttribute("href") !== "/cases/demo")
          out.push(`Attr value wrote ${a3.getAttribute("href")}`);
        const title = a3.getAttributeNode("title")!;
        title.value = "onload=1 still text";
        if (a3.getAttribute("title") !== "onload=1 still text") out.push("Attr value dropped a plain title");
        const img = root.appendChild(document.createElement("img"));
        img.setAttribute("alt", "x");
        img.getAttributeNode("alt")!.value = "fine";
        const src = document.createAttribute("src");
        img.setAttributeNode(src);
        img.getAttributeNode("src")!.value = "https://attacker.invalid/attr.png";
        if (img.getAttribute("src") !== "") out.push(`attached src Attr wrote ${img.getAttribute("src")}`);
        const svgG = root
          .appendChild(document.createElementNS("http://www.w3.org/2000/svg", "svg"))
          .appendChild(document.createElementNS("http://www.w3.org/2000/svg", "g"));
        svgG.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:base", "https://attacker.invalid/");
        svgG.setAttribute("xml:base", "https://attacker.invalid/");
        if (svgG.attributes.length) out.push("xml:base kept");
        const styled = root.appendChild(document.createElement("div"));
        styled.setAttribute("title", "t");
        const styleAttr = document.createAttribute("style");
        styled.setAttributeNode(styleAttr);
        if (styled.hasAttribute("style")) out.push("setAttributeNode attached a live style attribute");
        const detached = document.createAttribute("href");
        detached.value = X; // Not attached: harmless, and setAttributeNode judges it later.
        if (detached.value !== X) out.push("a detached Attr lost its value");
        await new Promise((resolve) => setTimeout(resolve, 200));
        if ((window as unknown as { __xss?: number }).__xss) out.push("payload executed");
        return out;
      });
      expect(kept).toEqual([]);
      expect(requests).toEqual([]);
    });

    test("every security-sensitive setter is wrapped in this engine (#1858, #1864)", async ({ page }) => {
      await loadGuard(page, withoutTrustedTypes);
      const unwrapped = await page.evaluate(() => {
        const expected: [string, string][] = [
          ["HTMLAnchorElement", "href"],
          ["HTMLAnchorElement", "ping"],
          ["HTMLAnchorElement", "protocol"],
          ["HTMLAnchorElement", "host"],
          ["HTMLAreaElement", "href"],
          ["HTMLAreaElement", "protocol"],
          ["HTMLLinkElement", "href"],
          ["HTMLBaseElement", "href"],
          ["HTMLFormElement", "action"],
          ["HTMLButtonElement", "formAction"],
          ["HTMLInputElement", "formAction"],
          ["HTMLInputElement", "src"],
          ["HTMLImageElement", "src"],
          ["HTMLImageElement", "srcset"],
          ["HTMLSourceElement", "src"],
          ["HTMLSourceElement", "srcset"],
          ["HTMLIFrameElement", "src"],
          ["HTMLIFrameElement", "srcdoc"],
          ["HTMLObjectElement", "data"],
          ["HTMLEmbedElement", "src"],
          ["HTMLMediaElement", "src"],
          ["HTMLVideoElement", "poster"],
          ["HTMLTrackElement", "src"],
          ["HTMLScriptElement", "src"],
          ["HTMLMetaElement", "httpEquiv"],
          ["HTMLLinkElement", "imageSrcset"],
          ["Attr", "value"],
          ["Attr", "nodeValue"],
          ["Attr", "textContent"],
          ["SVGAnimatedString", "baseVal"],
          ["HTMLScriptElement", "text"],
          ["HTMLScriptElement", "textContent"],
          ["HTMLScriptElement", "innerText"],
          ["HTMLScriptElement", "innerHTML"],
          ["SVGScriptElement", "textContent"],
          ["SVGScriptElement", "innerHTML"],
        ];
        const w = window as unknown as Record<string, { prototype: object }>;
        const out: string[] = [];
        for (const [iface, prop] of expected) {
          const d = Object.getOwnPropertyDescriptor(w[iface].prototype, prop);
          if (!d || !d.set || /\[native code\]/.test(Function.prototype.toString.call(d.set)))
            out.push(`${iface}.${prop}`);
        }
        for (const prop of ["textContent", "nodeValue"]) {
          const d = Object.getOwnPropertyDescriptor(Node.prototype, prop);
          if (!d || !d.set || !/\[native code\]/.test(Function.prototype.toString.call(d.set)))
            out.push(`Node.${prop} is wrapped (hot path)`);
        }
        for (const [iface, method] of [
          ["Element", "setAttributeNode"],
          ["Element", "setAttributeNodeNS"],
          ["NamedNodeMap", "setNamedItem"],
          ["NamedNodeMap", "setNamedItemNS"],
          ["Range", "createContextualFragment"],
          ["Range", "insertNode"],
          ["Range", "surroundContents"],
          ["DOMParser", "parseFromString"],
          ["Node", "appendChild"],
          ["Node", "insertBefore"],
          ["Node", "replaceChild"],
          ["Element", "append"],
          ["Element", "prepend"],
          ["Element", "replaceChildren"],
          ["Element", "before"],
          ["Element", "after"],
          ["Element", "replaceWith"],
          ["Element", "insertAdjacentElement"],
          ["DocumentFragment", "append"],
          ["Document", "append"],
          ["CharacterData", "before"],
          ["CharacterData", "after"],
          ["CharacterData", "replaceWith"],
        ]) {
          const fn = (w[iface].prototype as Record<string, unknown>)[method];
          if (typeof fn !== "function" || /\[native code\]/.test(Function.prototype.toString.call(fn)))
            out.push(`${iface}.${method}`);
        }
        const doc = document as unknown as Record<string, unknown>;
        for (const method of ["write", "writeln", "execCommand"]) {
          if (/\[native code\]/.test(Function.prototype.toString.call(doc[method])))
            out.push(`document.${method}`);
        }
        return out;
      });
      expect(unwrapped).toEqual([]);
    });

    test("every write the app makes today still lands (#1858 inventory)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes, { onAppOrigin: true, scripts: [GLYPHS] });
      const broken = await page.evaluate(async () => {
        const root = document.getElementById("root")!;
        const out: string[] = [];
        const download = (href: string) => {
          const a = document.createElement("a");
          a.href = href;
          a.download = "x";
          if (a.getAttribute("href") !== href) out.push(`download href dropped: ${href.slice(0, 40)}`);
        };
        const blobUrl = URL.createObjectURL(new Blob(["a,b\n1,2"], { type: "text/csv" }));
        download(blobUrl);
        URL.revokeObjectURL(blobUrl);
        const canvas = document.createElement("canvas");
        canvas.width = canvas.height = 4;
        download(canvas.toDataURL("image/png"));
        download("/cases/demo/custody/manifest");
        download("/auth/oidc/start?returnTo=%2Fdashboard");
        const load = (src: string) =>
          new Promise<string>((resolve) => {
            const img = root.appendChild(document.createElement("img"));
            img.onload = () => resolve(img.naturalWidth > 0 ? "" : `empty image ${src.slice(0, 40)}`);
            img.onerror = () => resolve(`image failed ${src.slice(0, 40)}`);
            img.src = src;
            if (img.getAttribute("src") !== src) resolve(`img.src dropped ${src.slice(0, 40)}`);
          });
        const glyphs = (
          window as unknown as { DfirGlyphs: { glyphDataUri(svg: string, size?: number): string } }
        ).DfirGlyphs;
        const glyph = glyphs.glyphDataUri('<circle cx="6" cy="6" r="5" fill="red"/>', 12);
        for (const problem of await Promise.all([
          load(glyph),
          load(canvas.toDataURL("image/png")),
          load("data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="),
        ])) {
          if (problem) out.push(problem);
        }
        return out;
      });
      expect(broken).toEqual([]);
      expect(requests).toEqual([]);
    });

    test("vendored Leaflet tiles and Cytoscape glyph images still load their URLs (#1858)", async ({
      page,
    }) => {
      await loadGuard(page, withoutTrustedTypes, {
        onAppOrigin: true,
        scripts: [GLYPHS, LEAFLET, CYTOSCAPE],
      });
      const result = await page.evaluate(async () => {
        const root = document.getElementById("root")!;
        const mapDiv = root.appendChild(document.createElement("div"));
        mapDiv.style.width = "256px";
        mapDiv.style.height = "256px";
        const L = (window as unknown as { L: any }).L; // eslint-disable-line @typescript-eslint/no-explicit-any
        const map = L.map(mapDiv).setView([0, 0], 1);
        L.tileLayer("/geo-tiles/{z}/{x}/{y}.png").addTo(map);
        const tiles = Array.from(mapDiv.querySelectorAll("img.leaflet-tile")).map(
          (t) => t.getAttribute("src") || "",
        );

        const glyphs = (
          window as unknown as { DfirGlyphs: { glyphDataUri(svg: string, size?: number): string } }
        ).DfirGlyphs;
        const glyph = glyphs.glyphDataUri('<circle cx="6" cy="6" r="5" fill="red"/>', 12);
        const cyDiv = root.appendChild(document.createElement("div"));
        cyDiv.style.width = "200px";
        cyDiv.style.height = "200px";
        const cytoscape = (window as unknown as { cytoscape: any }).cytoscape; // eslint-disable-line @typescript-eslint/no-explicit-any
        const cy = cytoscape({
          container: cyDiv,
          elements: [{ data: { id: "n1", glyph } }],
          style: [{ selector: "node", style: { "background-image": "data(glyph)" } }],
        });
        await new Promise((resolve) => setTimeout(resolve, 500));
        const cached = cy.renderer().imageCache?.[glyph]?.image as HTMLImageElement | undefined;
        return {
          tiles,
          glyphSrcKept: cached ? cached.getAttribute("src") === glyph : false,
          glyphDecoded: cached ? cached.complete && cached.naturalWidth > 0 : false,
        };
      });
      expect(result.tiles.length).toBeGreaterThan(0);
      for (const src of result.tiles) expect(src).toMatch(/^\/geo-tiles\/\d+\/\d+\/\d+\.png$/);
      expect(result.glyphSrcKept).toBe(true);
      expect(result.glyphDecoded).toBe(true);
    });

    test("Range.createContextualFragment output is sanitized in its context (#1864)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes);
      for (const payload of PAYLOADS) {
        const problems = await page.evaluate(async (markup) => {
          const w = window as unknown as AuditWindow;
          const root = document.getElementById("root")!;
          root.textContent = "";
          const div = root.appendChild(document.createElement("div"));
          const tbody = root
            .appendChild(document.createElement("table"))
            .appendChild(document.createElement("tbody"));
          const svg = root.appendChild(document.createElementNS("http://www.w3.org/2000/svg", "svg"));
          for (const host of [div, tbody, svg]) {
            const range = document.createRange();
            range.selectNodeContents(host);
            host.appendChild(range.createContextualFragment(markup));
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
          return [...w.__audit(root), ...(w.__xss ? ["payload executed"] : [])];
        }, payload);
        expect(problems, payload).toEqual([]);
      }
      expect(
        await page.evaluate(() => {
          const range = document.createRange();
          range.selectNodeContents(document.getElementById("root")!);
          const fragment = range.createContextualFragment('<b class="k" title="onload=1">kept</b>');
          return (fragment.firstChild as Element).outerHTML;
        }),
      ).toBe('<b class="k" title="onload=1">kept</b>');
      expect(requests).toEqual([]);
    });

    test("setHTMLUnsafe and Document.parseHTMLUnsafe go through the sanitizer (#1864)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes);
      const dsd = `<div><template shadowrootmode="open"><img src=x onerror="${X}"></template>host</div>`;
      for (const payload of [...PAYLOADS, dsd]) {
        const result = await page.evaluate(async (markup) => {
          const w = window as unknown as AuditWindow;
          const root = document.getElementById("root")!;
          root.textContent = "";
          const absent: string[] = [];
          const problems: string[] = [];
          const element = root.appendChild(document.createElement("div"));
          if (typeof element.setHTMLUnsafe === "function") element.setHTMLUnsafe(markup);
          else absent.push("Element.setHTMLUnsafe");
          // A detached host: the audit below reports any shadow root under #root as a planted one.
          const shadow = document.createElement("div").attachShadow({ mode: "open" });
          if (typeof shadow.setHTMLUnsafe === "function") {
            shadow.setHTMLUnsafe(markup);
            problems.push(...w.__audit(shadow));
          } else absent.push("ShadowRoot.setHTMLUnsafe");
          const parse = (Document as unknown as { parseHTMLUnsafe?: (html: string) => Document })
            .parseHTMLUnsafe;
          if (typeof parse === "function") {
            const doc = parse.call(Document, markup);
            problems.push(...w.__audit(doc.body).map((p) => `parsed: ${p}`));
            root.appendChild(document.importNode(doc.body, true));
          } else absent.push("Document.parseHTMLUnsafe");
          await new Promise((resolve) => setTimeout(resolve, 100));
          problems.push(...w.__audit(root));
          if (w.__xss) problems.push("payload executed");
          return { absent, problems };
        }, payload);
        expect(result.problems, payload).toEqual([]);
        if (result.absent.length)
          test.info().annotations.push({ type: "absent", description: result.absent.join(", ") });
      }
      expect(requests).toEqual([]);
    });

    test("DOMParser returns only sanitized nodes, for HTML and XML types (#1864)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes);
      const xml: [string, string][] = [
        [
          "image/svg+xml",
          `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" onload="${X}">` +
            `<a href="javascript:${X}"><text>t</text></a><a xlink:href="javascript:${X}"><text>u</text></a>` +
            `<script>${X}</script><image href="https://attacker.invalid/i.png"/>` +
            `<foreignObject><img xmlns="http://www.w3.org/1999/xhtml" src="x" onerror="${X}"/></foreignObject>` +
            `<set attributeName="href" to="javascript:${X}"/><rect width="4" height="4" fill="red"/></svg>`,
        ],
        [
          "application/xhtml+xml",
          `<html xmlns="http://www.w3.org/1999/xhtml"><body onload="${X}"><img src="x" onerror="${X}"/>` +
            `<script>${X}</script><a href="javascript:${X}">a</a><p class="k">kept</p></body></html>`,
        ],
        [
          "application/xml",
          `<data xmlns:h="http://www.w3.org/1999/xhtml"><h:img src="x" onerror="${X}"/><h:script>${X}</h:script>` +
            `<item>text</item></data>`,
        ],
      ];
      const result = await page.evaluate(
        async ({ payloads, xmlCases }) => {
          const w = window as unknown as AuditWindow;
          const root = document.getElementById("root")!;
          const problems: string[] = [];
          const parser = new DOMParser();
          for (const markup of payloads) {
            const doc = parser.parseFromString(markup, "text/html");
            problems.push(...w.__audit(doc.documentElement).map((p) => `html doc: ${p} (${markup})`));
            root.appendChild(document.importNode(doc.body, true));
            root.append(...Array.from(doc.body.childNodes).map((n) => document.adoptNode(n)));
          }
          for (const [type, markup] of xmlCases) {
            const doc = parser.parseFromString(markup, type as DOMParserSupportedType);
            problems.push(...w.__audit(doc).map((p) => `${type} doc: ${p}`));
            root.appendChild(document.importNode(doc.documentElement, true));
          }
          await new Promise((resolve) => setTimeout(resolve, 150));
          problems.push(...w.__audit(root));
          if (w.__xss) problems.push("payload executed");
          const kept = {
            svgRect: !!parser
              .parseFromString(xmlCases[0][1], "image/svg+xml")
              .querySelector("rect[fill=red]"),
            xhtmlText: parser.parseFromString(xmlCases[1][1], "application/xhtml+xml").querySelector("p")
              ?.textContent,
            xmlItem: parser.parseFromString(xmlCases[2][1], "application/xml").querySelector("item")
              ?.textContent,
            parseError:
              parser.parseFromString("<a><b></a>", "application/xml").getElementsByTagName("parsererror")
                .length > 0,
            title: parser.parseFromString("<title>t</title><p>x</p>", "text/html").body.textContent,
          };
          return { problems, kept };
        },
        { payloads: PAYLOADS, xmlCases: xml },
      );
      expect(result.problems).toEqual([]);
      expect(result.kept).toEqual({
        svgRect: true,
        xhtmlText: "kept",
        xmlItem: "text",
        parseError: true,
        title: "tx",
      });
      expect(requests).toEqual([]);
    });

    test("XSLT output and XHR documents are sanitized before they are returned (#1864)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      const evil = `<html><body><img src=x onerror="${X}"><script>${X}</script><p>kept</p></body></html>`;
      await loadGuard(page, withoutTrustedTypes, {
        onAppOrigin: true,
        responses: {
          "/evil.html": ["text/html", evil],
          "/evil.svg": [
            "image/svg+xml",
            `<svg xmlns="http://www.w3.org/2000/svg" onload="${X}"><script>${X}</script></svg>`,
          ],
        },
      });
      const result = await page.evaluate(async (payload) => {
        const w = window as unknown as AuditWindow;
        const root = document.getElementById("root")!;
        const problems: string[] = [];
        const absent: string[] = [];
        const XslProcessor = (window as unknown as { XSLTProcessor?: typeof XSLTProcessor }).XSLTProcessor;
        if (XslProcessor) {
          const xsl = new DOMParser().parseFromString(
            '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">' +
              '<xsl:element name="div" namespace="http://www.w3.org/1999/xhtml">' +
              '<xsl:element name="img" namespace="http://www.w3.org/1999/xhtml"><xsl:attribute name="src">x</xsl:attribute>' +
              `<xsl:attribute name="onerror">${payload}</xsl:attribute></xsl:element>` +
              `<xsl:element name="script" namespace="http://www.w3.org/1999/xhtml">${payload}</xsl:element>` +
              "</xsl:element></xsl:template></xsl:stylesheet>",
            "application/xml",
          );
          const processor = new XslProcessor();
          processor.importStylesheet(xsl);
          const input = new DOMParser().parseFromString("<r/>", "application/xml");
          const fragment = processor.transformToFragment(input, document);
          if (fragment) {
            problems.push(...w.__audit(fragment).map((p) => `xslt fragment: ${p}`));
            root.appendChild(fragment);
          }
          const doc = processor.transformToDocument(input);
          if (doc) problems.push(...w.__audit(doc).map((p) => `xslt document: ${p}`));
        } else absent.push("XSLTProcessor");
        const fetchDoc = (url: string, type: XMLHttpRequestResponseType) =>
          new Promise<Document | null>((resolve) => {
            const xhr = new XMLHttpRequest();
            xhr.open("GET", url);
            xhr.responseType = type;
            xhr.onload = () => resolve(type === "document" ? (xhr.response as Document) : xhr.responseXML);
            xhr.onerror = () => resolve(null);
            xhr.send();
          });
        const html = await fetchDoc("/evil.html", "document");
        const svg = await fetchDoc("/evil.svg", "");
        for (const [label, doc] of [
          ["xhr html", html],
          ["xhr svg", svg],
        ] as const) {
          if (!doc) {
            problems.push(`${label}: no document`);
            continue;
          }
          problems.push(...w.__audit(doc).map((p) => `${label}: ${p}`));
          root.appendChild(document.importNode(doc.documentElement, true));
        }
        await new Promise((resolve) => setTimeout(resolve, 150));
        problems.push(...w.__audit(root));
        if (w.__xss) problems.push("payload executed");
        return { problems, absent, kept: html?.querySelector("p")?.textContent };
      }, X);
      expect(result.problems).toEqual([]);
      expect(result.kept).toBe("kept");
      if (result.absent.length)
        test.info().annotations.push({ type: "absent", description: result.absent.join(", ") });
      expect(requests).toEqual([]);
    });

    test("document.write and writeln go through the sanitizer, split tokens included (#1864)", async ({
      page,
    }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes);
      const splits = [
        ["<img src=x on", `error="${X}">`],
        ["<scr", `ipt>${X}</scr`, "ipt>"],
        ['<a id=l href="java', `script:${X}">x</a>`],
        ["<svg><a href='", `javascript:${X}'>x</a></svg>`],
        ["<img src=x ", `onerror=${X}>`],
        ["<!--", `--><img src=x onerror=${X}>`],
        ["<textarea>", `</textarea><img src=x onerror=${X}>`],
      ];
      const result = await page.evaluate(
        async ({ payloads, chunks }) => {
          const w = window as unknown as AuditWindow;
          document.open();
          for (const payload of payloads) document.write(payload);
          for (const parts of chunks) for (const part of parts) document.write(part);
          for (const parts of chunks) document.writeln(...parts);
          document.write('<p id="w">written</p>');
          document.close();
          await new Promise((resolve) => setTimeout(resolve, 150));
          const problems = w.__audit(document.body);
          if (w.__xss) problems.push("payload executed");
          return { problems, written: document.getElementById("w")?.textContent };
        },
        { payloads: PAYLOADS, chunks: splits },
      );
      expect(result.problems).toEqual([]);
      expect(result.written).toBe("written");
      expect(requests).toEqual([]);
    });

    test("execCommand insertHTML is sanitized and copy still works (#1864)", async ({ page }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes);
      for (const payload of PAYLOADS) {
        const problems = await page.evaluate(async (markup) => {
          const w = window as unknown as AuditWindow;
          const root = document.getElementById("root")!;
          root.textContent = "";
          const editor = root.appendChild(document.createElement("div"));
          editor.contentEditable = "true";
          editor.focus();
          const range = document.createRange();
          range.selectNodeContents(editor);
          const selection = window.getSelection()!;
          selection.removeAllRanges();
          selection.addRange(range);
          document.execCommand("insertHTML", false, markup);
          await new Promise((resolve) => setTimeout(resolve, 100));
          return [...w.__audit(root), ...(w.__xss ? ["payload executed"] : [])];
        }, payload);
        expect(problems, payload).toEqual([]);
      }
      expect(
        await page.evaluate(() => {
          const area = document.getElementById("root")!.appendChild(document.createElement("textarea"));
          area.value = "copy me";
          area.select();
          return typeof document.execCommand("copy");
        }),
      ).toBe("boolean");
      expect(requests).toEqual([]);
    });

    test("script content, script URLs and inserting a script element are refused (#1864)", async ({
      page,
    }) => {
      const requests = watchAttackerRequests(page);
      await loadGuard(page, withoutTrustedTypes, true);
      const out = await page.evaluate(async () => {
        const X = "window.__xss=1";
        const svgNs = "http://www.w3.org/2000/svg";
        const root = document.getElementById("root")!;
        const out: string[] = [];
        const before = document.scripts.length;
        const script = document.createElement("script");
        for (const prop of ["text", "textContent", "innerText", "innerHTML"]) {
          try {
            (script as unknown as Record<string, string>)[prop] = X;
          } catch (error) {
            out.push(`script.${prop} threw ${String(error)}`);
          }
          if (script.textContent) out.push(`script.${prop} wrote ${script.textContent}`);
        }
        script.src = "/js/dashboard-render.js";
        script.setAttribute("src", "https://attacker.invalid/s.js");
        script.setAttributeNS(null, "src", "/js/x.js");
        const attr = document.createAttribute("src");
        attr.value = "/js/x.js";
        script.setAttributeNode(attr);
        if (script.hasAttribute("src")) out.push(`script src kept ${script.getAttribute("src")}`);
        const svgScript = document.createElementNS(svgNs, "script");
        svgScript.textContent = X;
        svgScript.innerHTML = X;
        svgScript.href.baseVal = "/js/x.js";
        svgScript.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", "/js/x.js");
        svgScript.setAttribute("href", "/js/x.js");
        if (svgScript.textContent || svgScript.attributes.length)
          out.push("svg script kept content or a URL");
        // A script that did get content (a child text node) and a clone of the page's own scripts:
        // no insertion method may connect either.
        const filled = document.createElement("script");
        filled.appendChild(document.createTextNode(X));
        const headClone = document.head.cloneNode(true) as HTMLElement;
        const svg = root.appendChild(document.createElementNS(svgNs, "svg"));
        svg.appendChild(document.createElementNS(svgNs, "script")).textContent = X;
        const anchor = root.appendChild(document.createElement("span"));
        const attempts: [string, () => unknown][] = [
          ["appendChild", () => root.appendChild(filled)],
          ["insertBefore", () => root.insertBefore(filled, anchor)],
          ["replaceChild", () => root.replaceChild(filled, anchor)],
          ["append", () => root.append("t", filled)],
          ["prepend", () => root.prepend(filled)],
          ["replaceChildren", () => root.replaceChildren(filled)],
          ["before", () => anchor.before(filled)],
          ["after", () => anchor.after(filled)],
          ["replaceWith", () => anchor.replaceWith(filled)],
          ["insertAdjacentElement", () => anchor.insertAdjacentElement("afterend", filled)],
          ["head clone", () => root.appendChild(headClone)],
          [
            "fragment",
            () => {
              const fragment = document.createDocumentFragment();
              fragment.appendChild(filled);
              root.appendChild(fragment);
            },
          ],
          [
            "Range.insertNode",
            () => {
              const range = document.createRange();
              range.selectNodeContents(root);
              range.insertNode(filled);
            },
          ],
          [
            "Range.surroundContents",
            () => {
              const range = document.createRange();
              range.selectNodeContents(anchor);
              range.surroundContents(filled);
            },
          ],
          ["svg script", () => svg.appendChild(document.createElementNS(svgNs, "script"))],
          [
            "moveBefore",
            () =>
              (root as unknown as { moveBefore?(n: Node, c: Node | null): void }).moveBefore?.(filled, null),
          ],
        ];
        for (const [label, attempt] of attempts) {
          try {
            attempt();
          } catch (error) {
            out.push(`${label} threw ${String(error)}`);
          }
          if (document.scripts.length !== before || root.querySelector("script"))
            out.push(`${label} connected a script`);
        }
        if (!anchor.isConnected) out.push("a refused call still removed the anchor");
        await new Promise((resolve) => setTimeout(resolve, 200));
        if ((window as unknown as { __xss?: number }).__xss) out.push("payload executed");
        // Ordinary insertion is untouched.
        const row = root.appendChild(document.createElement("div"));
        row.append("text", document.createElement("b"));
        anchor.after(document.createElement("i"));
        if (row.childNodes.length !== 2 || anchor.nextElementSibling?.tagName !== "I")
          out.push("ordinary insertion broke");
        return out;
      });
      expect(out).toEqual([]);
      expect(requests).toEqual([]);
    });

    test("script-built SVG animation cannot target href or carry a javascript: value (#1864)", async ({
      page,
    }) => {
      await loadGuard(page, withoutTrustedTypes, true);
      const result = await page.evaluate(async () => {
        const X = "javascript:window.__xss=1";
        const svgNs = "http://www.w3.org/2000/svg";
        const root = document.getElementById("root")!;
        const out: string[] = [];
        const svg = root.appendChild(document.createElementNS(svgNs, "svg"));
        const link = svg.appendChild(document.createElementNS(svgNs, "a"));
        link.setAttribute("href", "/cases/demo");
        link.appendChild(document.createElementNS(svgNs, "text")).textContent = "open";
        for (const tag of ["set", "animate"]) {
          const anim = document.createElementNS(svgNs, tag);
          anim.setAttribute("attributeName", "href");
          anim.setAttributeNS(null, "attributeName", "xlink:href");
          const name = document.createAttribute("attributeName");
          name.value = "href";
          anim.setAttributeNode(name);
          anim.setAttribute("to", X);
          anim.setAttribute("from", X);
          anim.setAttribute("by", X);
          anim.setAttribute("values", `/cases/demo;${X}`);
          anim.setAttribute("begin", "0s");
          anim.setAttribute("dur", "10s");
          link.appendChild(anim);
          for (const attr of ["attributeName", "to", "from", "by", "values"])
            if (anim.hasAttribute(attr)) out.push(`${tag} kept ${attr}=${anim.getAttribute(attr)}`);
        }
        const fade = svg.appendChild(document.createElementNS(svgNs, "rect"));
        fade.setAttribute("width", "10");
        fade.setAttribute("height", "10");
        const animate = fade.appendChild(document.createElementNS(svgNs, "animate"));
        const legit: [string, string][] = [
          ["attributeName", "opacity"],
          ["values", "0;1;0"],
          ["from", "0"],
          ["to", "1"],
          ["dur", "1s"],
          ["href", "#target"],
        ];
        for (const [attr, value] of legit) animate.setAttribute(attr, value);
        for (const [attr, value] of legit)
          if (animate.getAttribute(attr) !== value)
            out.push(`legit ${attr} lost: ${animate.getAttribute(attr)}`);
        await new Promise((resolve) => setTimeout(resolve, 200));
        if (link.href.animVal !== "/cases/demo") out.push(`link animated to ${link.href.animVal}`);
        if ((window as unknown as { __xss?: number }).__xss) out.push("payload executed");
        return out;
      });
      expect(result).toEqual([]);
    });

    test("kept SVG attributes keep their case (viewBox)", async ({ page }) => {
      await loadGuard(page, withoutTrustedTypes);
      const viewBox = await page.evaluate(() => {
        const root = document.getElementById("root")!;
        root.innerHTML = '<svg viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"></circle></svg>';
        return root.querySelector("svg")!.getAttribute("viewBox");
      });
      expect(viewBox).toBe("0 0 10 10");
    });

    test("escaped evidence text and tooltips render byte-identical (#1787)", async ({ page }) => {
      await loadGuard(page, withoutTrustedTypes);
      const rendered = await page.evaluate(
        (rows) => {
          const root = document.getElementById("root")!;
          return rows.map(({ markup }) => {
            root.innerHTML = markup;
            const cell = root.querySelector("span")!;
            return {
              text: cell.textContent,
              title: cell.getAttribute("title"),
              data: cell.getAttribute("data-cmd"),
            };
          });
        },
        EVIDENCE.map((text) => ({
          markup: `<span title="${esc(text)}" data-cmd='${esc(text)}'>${esc(text)}</span>`,
        })),
      );
      rendered.forEach((row, i) => {
        expect(row, EVIDENCE[i]).toEqual({ text: EVIDENCE[i], title: EVIDENCE[i], data: EVIDENCE[i] });
      });
    });
  });
}

test("the exported deck keeps evidence text and runs no payload from file://", async ({ page }, testInfo) => {
  const description = [...EVIDENCE, ...PAYLOADS].join("\n");
  const deck = {
    caseName: "Sanitizer check",
    slides: [{ kind: "event", severity: "High", timestamp: "2026-01-01T00:00:00Z", description }],
  };
  const file = testInfo.outputPath("deck.html");
  await writeFile(file, await renderStandalonePresentation(deck, "e2enonce"), "utf8");
  await page.goto(pathToFileURL(file).href);
  await page.locator(".desc").waitFor();
  expect(await page.locator(".desc").evaluate((el) => el.textContent)).toBe(description);
  await page.waitForTimeout(150);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
});
