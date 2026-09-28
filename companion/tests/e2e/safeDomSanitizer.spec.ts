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

async function loadGuard(page: Page, withoutTrustedTypes: boolean): Promise<void> {
  if (withoutTrustedTypes) {
    await page.addInitScript(() => {
      Object.defineProperty(window, "trustedTypes", { value: undefined, configurable: true });
    });
  }
  await page.goto("about:blank");
  await page.setContent("<!doctype html><html><head></head><body><main id=root></main></body></html>");
  await page.addScriptTag({ content: await readFile(SAFE_DOM, "utf8") });
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
