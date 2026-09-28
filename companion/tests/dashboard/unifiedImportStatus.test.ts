import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// What the import status line tells the analyst.
//
// #1786: a file the server refused with a sentence (413 "upload exceeds the 1 MB limit — raise
// DFIR_MAX_BODY_MB…", 409, 429, 500, 501) reached the console only; the status line read
// "1 file(s) failed / unrecognized", which points at the file format, not the real cause. The
// screenshot loop gave no reason at all. Every failure now names its file and its reason.
//
// #1772: a Windows export with no collector column parks on the in-page "which host did this file
// come from?" overlay. The status line kept saying "importing 1/1: <file>…", so a run waiting on
// the analyst read as a hang. It now says it is waiting for the answer.

interface UnifiedImportApi {
  initUnifiedImport: () => void;
}

interface FakeFile {
  name: string;
  type: string;
  size: number;
}

interface FakeInput {
  files: FakeFile[];
  value: string;
  onchange: ((e: { target: FakeInput }) => Promise<void>) | null;
  click: () => void;
}

const settle = () => new Promise<void>((r) => setTimeout(r, 0));
const csv = (name: string): FakeFile => ({ name, type: "text/csv", size: 10 });
const png = (name: string): FakeFile => ({ name, type: "image/png", size: 10 });

function reply(status: number, body: unknown) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

function harness(overrides: Record<string, unknown> = {}) {
  const status = { textContent: "" };
  const els: Record<string, unknown> = {
    status,
    caseId: { value: "c1" },
    importFile: { files: [], value: "", onchange: null, click: () => {} } as FakeInput,
    importBtn: { onclick: null },
  };
  const progress: string[] = [];
  const api = loadDashboardModule<UnifiedImportApi>("dashboard-unified-import.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null },
    importPermissionMessage: () => "",
    cancelImportProgress: () => progress.push("cancel"),
    hideImportProgress: () => progress.push("hide"),
    showImportProgress: () => progress.push("show"),
    showImportProgressIndeterminate: () => progress.push("indeterminate"),
    fetchRawToolExts: async () => new Set<string>(),
    uploadExtOf: (n: string) => n.replace(/^.*\./, "").toLowerCase(),
    askRunToolsOnImport: () => {},
    undecodedBinaryImportHint: () => "",
    looksLikeBinaryImportName: () => false,
    readFileTextWithProgress: async () => "a,b\n1,2\n",
    fileToBase64: async () => "AAAA",
    askMinSeverity: async () => "info",
    fetch: vi.fn(async () => reply(202, { kind: "csv" })),
    ...overrides,
  });
  api.initUnifiedImport();
  const input = els.importFile as FakeInput;
  const pick = (files: FakeFile[]) => {
    input.files = files;
    input.value = "C:\\fakepath\\" + files[0].name;
    return input.onchange!({ target: input });
  };
  return { status, pick, progress };
}

const TOO_BIG =
  "upload exceeds the 1 MB limit — raise DFIR_MAX_BODY_MB and restart the companion, or split the export into smaller files";

describe("import status line names each failed file and its reason (#1786)", () => {
  it.each([
    [413, TOO_BIG],
    [409, "an import for this case is already running"],
    [429, "AI budget for this case is spent"],
    [500, "disk full"],
    [501, "AI provider not configured for CSV/log analysis"],
  ])("a %i with a server sentence shows `file: sentence`", async (code, sentence) => {
    const h = harness({ fetch: vi.fn(async () => reply(code, { error: sentence })) });
    await h.pick([csv("oversize.csv")]);
    expect(h.status.textContent).toContain("1 file(s) failed");
    expect(h.status.textContent).toContain(`oversize.csv: ${sentence}`);
  });

  it("a failure with no server sentence shows the HTTP status", async () => {
    const h = harness({ fetch: vi.fn(async () => ({ status: 502, ok: false, json: async () => { throw new Error("not json"); } })) });
    await h.pick([csv("a.csv")]);
    expect(h.status.textContent).toContain("a.csv: HTTP 502");
  });

  it("a network error shows its message", async () => {
    const h = harness({
      fetch: vi.fn(async () => {
        throw new Error("Failed to fetch");
      }),
    });
    await h.pick([csv("a.csv")]);
    expect(h.status.textContent).toContain("a.csv: Failed to fetch");
  });

  it("a structured 400 refusal is tied to its file in a multi-file batch", async () => {
    const fetch = vi.fn(async (_url: string, init: { body: string }) =>
      JSON.parse(init.body).filename === "bad.csv"
        ? reply(400, { refused: true, error: "this is a binary plist — use plutil" })
        : reply(202, { kind: "csv" }),
    );
    const h = harness({ fetch });
    await h.pick([csv("good.csv"), csv("bad.csv")]);
    expect(h.status.textContent).toContain("bad.csv: this is a binary plist — use plutil");
  });

  it("a sentence that already names the file is not prefixed twice", async () => {
    const h = harness({ fetch: vi.fn(async () => reply(413, { error: "a.csv is over the limit" })) });
    await h.pick([csv("a.csv")]);
    expect(h.status.textContent).toContain("a.csv is over the limit");
    expect(h.status.textContent).not.toContain("a.csv: a.csv");
  });

  it("a refused screenshot shows its file and the server sentence", async () => {
    const h = harness({ fetch: vi.fn(async () => reply(413, { error: TOO_BIG })) });
    await h.pick([png("shot.png")]);
    expect(h.status.textContent).toContain("1 failed");
    expect(h.status.textContent).toContain(`shot.png: ${TOO_BIG}`);
  });

  it("a screenshot that could not be read says so", async () => {
    const h = harness({ fileToBase64: async () => "" });
    await h.pick([png("shot.png")]);
    expect(h.status.textContent).toMatch(/shot\.png: could not read/);
  });

  it("a screenshot network error shows its message", async () => {
    const h = harness({
      fetch: vi.fn(async () => {
        throw new Error("Failed to fetch");
      }),
    });
    await h.pick([png("shot.png")]);
    expect(h.status.textContent).toContain("shot.png: Failed to fetch");
  });
});

describe("import status while the host prompt waits (#1772)", () => {
  it("says it is waiting for the analyst, sends nothing, then resumes on the answer", async () => {
    let answer!: (v: string | null) => void;
    const askImportAssetHost = vi.fn(
      () => new Promise<string | null>((r) => (answer = r)),
    );
    const fetch = vi.fn(async () => reply(202, { kind: "csv" }));
    const h = harness({
      probeBareWindowsExport: () => ({ bare: true, computers: ["WS-QA-01"] }),
      askImportAssetHost,
      fetch,
    });
    const run = h.pick([csv("sysmon-triage.csv")]);
    await settle();
    expect(askImportAssetHost).toHaveBeenCalledTimes(1);
    expect(h.status.textContent).toMatch(/waiting for your answer/);
    expect(h.status.textContent).toContain("sysmon-triage.csv");
    expect(h.status.textContent).not.toMatch(/^importing/);
    // The progress strip stops its "working" animation while nothing is working.
    expect(h.progress[h.progress.length - 1]).toBe("hide");
    expect(fetch).not.toHaveBeenCalled();

    answer("");
    await run;
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(h.status.textContent).toMatch(/imported csv/);
  });

  it("a file that does not need the prompt is not asked about", async () => {
    const askImportAssetHost = vi.fn(async () => "");
    const h = harness({ probeBareWindowsExport: () => ({ bare: false, computers: [] }), askImportAssetHost });
    await h.pick([csv("a.csv")]);
    expect(askImportAssetHost).not.toHaveBeenCalled();
    expect(h.status.textContent).toMatch(/imported csv/);
  });
});
