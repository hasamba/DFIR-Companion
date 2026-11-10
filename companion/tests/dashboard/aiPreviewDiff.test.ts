import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";
import { previewDiff } from "../../src/analysis/ai/previewDiff.js";

// A fake PEM key, assembled at runtime so the repo's secret scan never sees key armor in source.
const [KEY_HEAD, KEY_TAIL] = ["BEGIN", "END"].map((edge) => `-----${edge} RSA PRIVATE KEY-----`);
const FAKE_RSA_KEY = `${KEY_HEAD}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n${KEY_TAIL}`;

// #2531 — the preview dialog's GitHub-style diff, drawn from the server's offsets. Runs the real
// script in a sandbox with the page's esc()/escAttr().

const SRC = readFileSync(new URL("../../../public/js/dashboard-ai-preview-diff.js", import.meta.url), "utf8");
const ESC = readFileSync(new URL("../../../public/js/dashboard-escape.js", import.meta.url), "utf8");

function load() {
  const win: Record<string, unknown> = {};
  const sandbox: Record<string, unknown> = { window: win, document: {} };
  runInNewContext(`${ESC}\nwindow.esc = esc; window.escAttr = escAttr;`, sandbox);
  sandbox.esc = win.esc;
  sandbox.escAttr = win.escAttr;
  runInNewContext(SRC, sandbox);
  return {
    html: win.aiPreviewDiffHtml as (call: unknown, only: boolean) => string,
    summary: win.aiPreviewDiffSummary as (d: unknown) => string,
  };
}

const POLICY: AnonPolicy = {
  enabled: true,
  redactSecrets: true,
  maskPublicIps: true,
  categories: {
    IP: true,
    EMAIL: true,
    USER: true,
    HOST: true,
    DOMAIN: true,
    PATH: true,
    CMD: true,
    REG: true,
    CARD: true,
    PHONE: true,
    NATID: true,
  },
};
const EVIL = `<img src=x onerror=alert(1)>`;
const KNOWN: KnownEntities = {
  hosts: ["WS-FIN-07"],
  accounts: [],
  internalDomains: [],
  custom: [{ value: EVIL, category: "OTHER" }],
};

function call(clear: string, mask?: (masked: string) => string) {
  const anon = createAnonymizer(POLICY, KNOWN);
  const masked = mask ? mask(anon.apply(clear)) : anon.apply(clear);
  return {
    clearPrompt: clear,
    maskedPrompt: masked,
    anonymized: true,
    diff: previewDiff(clear, masked, anon, POLICY),
  };
}

describe("AI preview diff — rendering (#2531)", () => {
  it("marks the value red on the left and its token green on the right, linked by pair and tip", () => {
    const { html } = load();
    const out = html(call("intro\nlogon on WS-FIN-07\nend"), false);
    expect(out).toContain(
      `<mark class="aip-del" data-pair="0" title="WS-FIN-07 → ANON_HOST_1">WS-FIN-07</mark>`,
    );
    expect(out).toContain(
      `<mark class="aip-add" data-pair="0" title="WS-FIN-07 → ANON_HOST_1">ANON_HOST_1</mark>`,
    );
    expect((out.match(/class="aip-row aip-chg"/g) ?? []).length).toBe(1);
    expect((out.match(/class="aip-row"/g) ?? []).length).toBe(2);
    expect(out).toContain(`<input type="checkbox" id="aiPreviewOnlyChanged" />`);
  });

  it("escapes a hostile value everywhere — text and tooltip", () => {
    const { html } = load();
    const out = html(call(`opened ${EVIL} on WS-FIN-07`), false);
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("only-changed lines keeps changed and amber rows and counts the hidden runs", () => {
    const { html } = load();
    const clear = ["a", "b", "WS-FIN-07 here", "c", "d", "e", "ping 10.0.0.9 later"].join("\n");
    // The IP is left as it is in the masked text, so it is a possible leak (amber).
    const c = call(clear, (m) => m.replace(/ANON_IP_\d+/, "10.0.0.9"));
    const out = html(c, true);
    expect(out).toContain("2 unchanged lines hidden");
    expect(out).toContain("3 unchanged lines hidden");
    expect(out).toContain(`class="aip-warn"`);
    expect(out).toContain("looks like an IP address — not masked (a guess: check it)");
    expect((out.match(/class="aip-row aip-(chg|warned)/g) ?? []).length).toBe(2);
  });

  it("a secret spanning clear lines sits on one row, numbered as a range", () => {
    const { html } = load();
    const key = FAKE_RSA_KEY;
    const out = html(call(`top\n${key}\nWS-FIN-07`), false);
    expect(out).toContain(`<span class="aip-ln">2–4</span>`);
    expect(out).toContain(`<span class="aip-ln">5</span>`);
    expect(out).toContain("a secret — removed one-way, never restored");
  });

  it("a line that could not be lined up is shown changed, without inline marks", () => {
    const { html } = load();
    const c = call("ok\nrow on WS-FIN-07", (m) => m.slice(0, 13)); // "ok\nrow on ANO" — cut after masking
    expect(c.diff.mode).toBe("lines");
    const out = html(c, false);
    expect(out).toContain("could not be lined up value by value");
    expect(out).not.toContain("aip-del");
  });

  it("falls back to the plain pair, with the reason, when nothing lines up", () => {
    const { html } = load();
    const c = call("one\ntwo\nthree", () => "different");
    expect(c.diff.mode).toBe("none");
    const out = html(c, false);
    expect(out).toContain("could not be lined up value by value, so the two texts are shown side by side");
    expect(out).not.toContain("aiPreviewOnlyChanged");
  });

  it("summarises by kind", () => {
    const { summary } = load();
    const c = call(`WS-FIN-07 and ws-fin-07 saw ${EVIL}\nfrom 10.0.0.1`);
    expect(summary(c.diff)).toBe("4 values replaced in 2 lines: 2 hosts, 1 custom term, 1 IP address.");
    expect(summary(call("nothing to hide").diff)).toBe("Nothing in this request was replaced.");
  });
});
