import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

const dashboard = (): Promise<string> =>
  readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

// Pull a function's source straight out of the shipped page and make it callable, so these assert
// the real behaviour of the code that ships rather than a copy of it that could drift.
async function extractFn(name: string): Promise<(s: unknown) => string> {
  const html = await dashboard();
  const start = html.indexOf(`function ${name}(`);
  expect(start, `${name} should be defined in dashboard.html`).toBeGreaterThan(-1);
  // Walk braces from the function's opening brace to its matching close.
  const open = html.indexOf("{", start);
  let depth = 0;
  let end = open;
  for (let i = open; i < html.length; i++) {
    if (html[i] === "{") depth++;
    else if (html[i] === "}" && --depth === 0) { end = i; break; }
  }
  const src = html.slice(start, end + 1);
  // esc() is escAttr's dependency; include it so the extracted source resolves.
  const escSrc = name === "esc" ? "" : (await extractSource("esc"));
  return new Function(`${escSrc}\n${src}\nreturn ${name};`)() as (s: unknown) => string;
}

async function extractSource(name: string): Promise<string> {
  const html = await dashboard();
  const start = html.indexOf(`function ${name}(`);
  const open = html.indexOf("{", start);
  let depth = 0;
  let end = open;
  for (let i = open; i < html.length; i++) {
    if (html[i] === "{") depth++;
    else if (html[i] === "}" && --depth === 0) { end = i; break; }
  }
  return html.slice(start, end + 1);
}

describe("dashboard IP rendering (#217)", () => {
  it("escapes apostrophes, so a value cannot close a JS string literal", async () => {
    const escAttr = await extractFn("escAttr");
    // The payload that broke out: an IP-like string from imported evidence or model output.
    const out = escAttr("1.2.3.4');alert(document.domain);//");
    expect(out).not.toContain("');");
    expect(out).not.toMatch(/'/);
  });

  it("still escapes the characters it already handled", async () => {
    const escAttr = await extractFn("escAttr");
    expect(escAttr('a"b')).not.toContain('"');
    expect(escAttr("<script>")).not.toContain("<");
    expect(escAttr("a&b")).toContain("&amp;");
  });

  it("builds no inline geoFocusIp handler anywhere in the page", async () => {
    const html = await dashboard();
    // Untrusted values must reach the handler as data, never as generated JavaScript source.
    expect(html).not.toMatch(/onclick\s*=\s*"geoFocusIp\('/);
    expect(html).not.toMatch(/geoFocusIp\('\$\{/);
  });

  it("routes the event and marker IP through a data attribute plus a delegated listener", async () => {
    const html = await dashboard();
    expect(html).toMatch(/class="ev-geo"[^>]*data-ip="\$\{escAttr\(/);
    expect(html).toMatch(/data-geo-ip="\$\{escAttr\(/);
    // A single delegated click handler reads the value back off the element.
    expect(html).toMatch(/getAttribute\("data-ip"\)/);
    expect(html).toMatch(/getAttribute\("data-geo-ip"\)/);
  });
});
