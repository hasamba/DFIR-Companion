import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The Sigma → VQL card in the hunt modal (#798). The render helpers are pure (HTML in, HTML out)
// so they can be proven here without a DOM: what the card shows, when it is absent, and that a
// refusal line written by the parser is rendered as text, never as markup.

interface SigmaCompileApi {
  sigmaCompileCardHtml: (prefill?: string) => string;
  sigmaCompileResultHtml: (result: unknown) => string;
  sigmaCompileChip: (id: string) => string;
  launchHuntInto: (
    vql: string,
    description: string,
    res: unknown,
    btn: unknown,
    ctx?: Record<string, unknown>,
  ) => void;
}

// The page's escapers are inline in dashboard.html; these are the same two functions.
const esc = (s: unknown) =>
  String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
const escAttr = (s: unknown) => esc(s).replace(/"/g, "&quot;");

function load(opts: { platforms: string[]; velo: boolean }): SigmaCompileApi {
  return loadDashboardModule<SigmaCompileApi>("dashboard-sigma-hunt.js", [], {
    esc,
    escAttr,
    enabledHuntPlatforms: new Set(opts.platforms),
    veloEnabled: opts.velo,
    ICON_DOWNLOAD: "",
    ICON_HUNT: "<svg></svg>",
    document: { getElementById: () => null, querySelectorAll: () => [] },
  });
}

describe("sigmaCompileCardHtml — the paste card", () => {
  it("is absent when Velociraptor is not an enabled hunt platform, because it only ever produces VQL", () => {
    expect(load({ platforms: ["sigma", "defender"], velo: false }).sigmaCompileCardHtml()).toBe("");
  });

  it("renders the paste box and the Compile button when Velociraptor is enabled, even without the API", () => {
    const html = load({ platforms: ["velociraptor"], velo: false }).sigmaCompileCardHtml();
    expect(html).toContain('id="sigmaYamlIn"');
    expect(html).toContain('id="sigmaCompileBtn"');
    expect(html).toContain('id="sigmaCompileRes"');
    expect(html).toMatch(/Sigma rule/);
  });

  it("prefills the box with the given rule, escaped", () => {
    const html = load({ platforms: ["velociraptor"], velo: false }).sigmaCompileCardHtml("title: <x>\n");
    expect(html).toContain("title: &lt;x&gt;");
    expect(html).not.toContain("<x>");
  });
});

describe("sigmaCompileResultHtml — what the analyst sees after Compile", () => {
  const ok = {
    ok: true,
    vql: 'LET Procs <= SELECT * FROM pslist()\nSELECT * FROM Procs\nWHERE Image =~ "(?i)x"',
    coverage: "pslist(): running processes only, not process history",
    title: "T <b>",
    mitreTechniques: ["T1105"],
  };

  it("shows the coverage line and the VQL in an editable box, with Run only when the API is configured", () => {
    const withApi = load({ platforms: ["velociraptor"], velo: true }).sigmaCompileResultHtml(ok);
    expect(withApi).toContain("running processes only");
    expect(withApi).toContain('class="hunt-vql-edit"');
    expect(withApi).toContain('WHERE Image =~ "(?i)x"');
    expect(withApi).toContain('id="sigmaRunBtn"');
    expect(withApi).toContain("T &lt;b&gt;");

    const noApi = load({ platforms: ["velociraptor"], velo: false }).sigmaCompileResultHtml(ok);
    expect(noApi).toContain('class="hunt-vql-edit"');
    expect(noApi).not.toContain('id="sigmaRunBtn"');
    expect(noApi).toMatch(/not configured/i);
  });

  it("renders every refusal as escaped text with its path, and offers nothing to run", () => {
    const html = load({ platforms: ["velociraptor"], velo: true }).sigmaCompileResultHtml({
      ok: false,
      refusals: [
        {
          path: "detection.sel.Image|base64",
          message: "the base64 modifier is not supported <script>alert(1)</script>",
        },
        { path: "detection.sel.Foo", message: "Foo has no column" },
      ],
    });
    expect(html).toContain("detection.sel.Image|base64");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("Foo has no column");
    expect(html).not.toContain("hunt-vql-edit");
    expect(html).not.toContain("sigmaRunBtn");
    expect((html.match(/<li/g) ?? []).length).toBe(2);
  });

  it("renders a transport error as a single line", () => {
    const html = load({ platforms: ["velociraptor"], velo: true }).sigmaCompileResultHtml({
      error: "boom <i>",
    });
    expect(html).toContain("boom &lt;i&gt;");
    expect(html).not.toContain("<li");
  });
});

describe("sigmaCompileChip — the per-finding entry", () => {
  it("is a button that carries the finding id, escaped", () => {
    const html = load({ platforms: ["velociraptor"], velo: false }).sigmaCompileChip('f"1');
    expect(html).toContain('class="sigma-compile-btn"');
    expect(html).toContain('data-sigma-cid="f&quot;1"');
    expect(html).toMatch(/title="[^"]*VQL/);
  });

  it("is empty when Velociraptor is not an enabled platform", () => {
    expect(load({ platforms: ["sigma"], velo: false }).sigmaCompileChip("f1")).toBe("");
  });
});

describe("launchHuntInto with coverage: snapshot (#803)", () => {
  function launch(ctx: Record<string, unknown>) {
    const bodies: Array<Record<string, unknown>> = [];
    let consumed = 0;
    const api = loadDashboardModule<SigmaCompileApi>("dashboard-sigma-hunt.js", [], {
      esc,
      escAttr,
      enabledHuntPlatforms: new Set(["velociraptor"]),
      veloEnabled: true,
      ICON_DOWNLOAD: "",
      ICON_HUNT: "",
      document: { getElementById: () => null, querySelectorAll: () => [] },
      consumePendingHuntHypothesis: () => {
        consumed++;
        return "hyp-armed";
      },
      fetch: (_url: string, init: { body: string }) => {
        bodies.push(JSON.parse(init.body));
        return new Promise(() => {}); // never settles; only the request body is under test
      },
    });
    api.launchHuntInto("SELECT 1", "d", { innerHTML: "", querySelector: () => null }, null, {
      caseId: "c1",
      title: "t",
      ...ctx,
    });
    return { body: bodies[0], consumed };
  }

  it("sends coverage: snapshot and leaves an armed hypothesis un-consumed", () => {
    const { body, consumed } = launch({ coverage: "snapshot" });
    expect(body.coverage).toBe("snapshot");
    expect(body.relatedHypothesisId).toBeUndefined();
    expect(consumed).toBe(0);
  });

  it("an ordinary fleet hunt still consumes the armed hypothesis and sends no coverage", () => {
    const { body, consumed } = launch({});
    expect(body.coverage).toBeUndefined();
    expect(body.relatedHypothesisId).toBe("hyp-armed");
    expect(consumed).toBe(1);
  });
});
