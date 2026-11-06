import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2336 — a file over the in-browser limit, or any .gz, is sent to POST /cases/:id/import-upload as
// the raw request body (the File itself, never read into a string). The analyst is no longer asked
// for a path on the server, which a case analyst on a remote or Docker deployment does not have.

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

const MB = 1024 * 1024;
const reply = (status: number, body: unknown) => ({
  status,
  ok: status >= 200 && status < 300,
  json: async () => body,
});

function harness(fetch: ReturnType<typeof vi.fn>, extra: Record<string, unknown> = {}) {
  const status = { textContent: "" };
  const els: Record<string, unknown> = {
    status,
    caseId: { value: "c 1" },
    importFile: { files: [], value: "", onchange: null, click: () => {} },
    importBtn: { onclick: null },
  };
  const readFileTextWithProgress = vi.fn(async () => "a,b\n1,2\n");
  const prompt = vi.fn(() => "/srv/x");
  const api = loadDashboardModule<UnifiedImportApi>("dashboard-unified-import.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null },
    importPermissionMessage: () => "",
    cancelImportProgress: () => {},
    hideImportProgress: () => {},
    showImportProgress: () => {},
    showImportProgressIndeterminate: () => {},
    fetchRawToolExts: async () => new Set<string>(),
    uploadExtOf: (n: string) => n.replace(/^.*\./, "").toLowerCase(),
    askRunToolsOnImport: () => {},
    undecodedBinaryImportHint: () => "",
    looksLikeBinaryImportName: () => false,
    readFileTextWithProgress,
    fileToBase64: async () => "AAAA",
    askMinSeverity: async () => "medium",
    prompt,
    fetch,
    ...extra,
  });
  api.initUnifiedImport();
  const input = els.importFile as FakeInput;
  const pick = (files: FakeFile[]) => {
    input.files = files;
    input.value = "C:\\fakepath\\" + files[0].name;
    return input.onchange!({ target: input });
  };
  return { status, pick, readFileTextWithProgress, prompt };
}

describe("dashboard uploads large and .gz files as the raw body (#2336)", () => {
  it("sends a file over the in-browser limit to /import-upload as the File itself", async () => {
    const fetch = vi.fn(async () => reply(202, { kind: "m365" }));
    const h = harness(fetch);
    const big = { name: "UAL export (1).csv", type: "text/csv", size: 300 * MB };
    await h.pick([big]);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] as unknown as [
      string,
      RequestInit & { headers: Record<string, string> },
    ];
    expect(url.startsWith("/cases/c%201/import-upload?")).toBe(true);
    const q = new URLSearchParams(url.slice(url.indexOf("?") + 1));
    expect(q.get("filename")).toBe("UAL export (1).csv");
    expect(q.get("minSeverity")).toBe("medium");
    expect(init.method).toBe("POST");
    expect(init.headers["content-type"]).toBe("application/octet-stream");
    expect(init.body).toBe(big); // the File, streamed by the browser — never a string
    expect(h.readFileTextWithProgress).not.toHaveBeenCalled();
    expect(h.prompt).not.toHaveBeenCalled();
    expect(h.status.textContent).toMatch(/imported m365/);
  });

  it("sends a small .gz file to /import-upload too", async () => {
    const fetch = vi.fn(async () => reply(202, { kind: "aws" }));
    const h = harness(fetch);
    const gz = { name: "ct.json.gz", type: "application/gzip", size: 2048 };
    await h.pick([gz]);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain("/import-upload?");
    expect(init.body).toBe(gz);
    expect(h.prompt).not.toHaveBeenCalled();
  });

  it("keeps a small plain file on the existing /import path", async () => {
    const fetch = vi.fn(async () => reply(202, { kind: "csv" }));
    const h = harness(fetch);
    await h.pick([{ name: "a.csv", type: "text/csv", size: 10 }]);
    const [url] = fetch.mock.calls[0] as unknown as [string];
    expect(url).toBe("/cases/c 1/import");
  });

  it("shows the server's over-cap sentence for the file", async () => {
    const error = "upload exceeds the 2048 MB limit — raise DFIR_MAX_UPLOAD_MB and restart the companion";
    const fetch = vi.fn(async () => reply(413, { error }));
    const h = harness(fetch);
    await h.pick([{ name: "huge.json", type: "application/json", size: 400 * MB }]);
    expect(h.status.textContent).toContain(`huge.json: ${error}`);
  });
});
