import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

// Issue #178: POST /settings/reload used to apply the just-saved DFIR_<PREFIX>_* group into
// process.env and stop there — every client built at startup (MISP push, the enrichment provider
// set, Notion/ClickUp, …) kept its boot-time config, so "change config without a restart" silently
// did nothing. The route now REBUILDS whatever live component the prefix feeds and reports which
// ones in `rebuilt`. These tests assert the EFFECT (the live client changed), not just the 200 —
// a status-only assertion passes even with the bug present.
//
// Env is resolved via resolveEnvFilePath() → DFIR_ENV_FILE, pointed at a per-test temp .env so this
// never touches the developer's real companion/.env (issue #173).
let envPath: string;
let envRoot: string;
let app: ReturnType<typeof createApp>;

// Every prefix the route accepts — the reload itself must stay a 200 for all of them, whether or
// not the prefix has anything to rebuild.
const ALL_PREFIXES = [
  "DFIR_VISION_", "DFIR_AI_", "DFIR_IRIS_", "DFIR_VELOCIRAPTOR_", "DFIR_TIMESKETCH_", "DFIR_NOTION_", "DFIR_CLICKUP_",
  "DFIR_VT_", "DFIR_ABUSEIPDB_", "DFIR_HUNTINGCH_", "DFIR_MB_", "DFIR_CROWDSTRIKE_", "DFIR_SHODAN_",
  "DFIR_MISP_", "DFIR_YETI_", "DFIR_OPENCTI_", "DFIR_ROCKYRACCOON_", "DFIR_GEOIP_",
  "DFIR_LEAKCHECK_", "DFIR_HIBP_", "DFIR_DEHASHED_", "DFIR_PUSH_TOKEN", "DFIR_NSRL_", "DFIR_TOOL_",
];

// Keys this file writes into the temp .env and therefore into the live process.env — cleared around
// every test so one case can't leak configuration into the next (or into another test file).
const TOUCHED = [
  "DFIR_MISP_URL", "DFIR_MISP_KEY", "DFIR_VT_KEY", "DFIR_NOTION_TOKEN", "DFIR_CLICKUP_TOKEN",
  "DFIR_CLICKUP_LIST_ID", "DFIR_LEAKCHECK_KEY",
];

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-reload-"));
  envRoot = await mkdtemp(join(tmpdir(), "dfir-reload-env-"));
  envPath = join(envRoot, ".env");
  process.env.DFIR_ENV_FILE = envPath;
  for (const k of TOUCHED) delete process.env[k];
  setServerLogger(createConsoleLogger("info"));
  app = createApp(new CaseStore(root), {});
});

afterEach(async () => {
  delete process.env.DFIR_ENV_FILE;
  for (const k of TOUCHED) delete process.env[k];
  await rm(envRoot, { recursive: true, force: true });
});

const reload = (prefix: string) => request(app).post("/settings/reload").send({ prefix });

describe("/settings/reload rebuilds the live client for the prefix (#178)", () => {
  it("rebuilds the MISP push client so a corrected URL takes effect without a restart", async () => {
    // Boot with the WRONG scheme live (the reported scenario: http:// in memory, https:// on disk).
    process.env.DFIR_MISP_URL = "http://127.0.0.1:4430";
    process.env.DFIR_MISP_KEY = "boot-key";
    app = createApp(new CaseStore(await mkdtemp(join(tmpdir(), "dfir-reload-misp-"))), {});
    expect((await request(app).get("/misp/status")).body).toMatchObject({ configured: false });

    await writeFile(envPath, "DFIR_MISP_URL=https://127.0.0.1:4430/\nDFIR_MISP_KEY=abc\n", "utf8");
    const res = await reload("DFIR_MISP_");

    expect(res.status).toBe(200);
    expect(res.body.rebuilt).toContain("misp");
    const status = await request(app).get("/misp/status");
    expect(status.body.configured).toBe(true);
    expect(status.body.baseUrl).toBe("https://127.0.0.1:4430/");
  });

  it("rebuilds the enrichment provider set so a newly-saved key is usable", async () => {
    expect((await request(app).get("/health")).body.enrichEnabled).toBe(false);

    await writeFile(envPath, "DFIR_VT_KEY=vt-secret\n", "utf8");
    const res = await reload("DFIR_VT_");

    expect(res.status).toBe(200);
    expect(res.body.rebuilt).toContain("enrichment");
    expect((await request(app).get("/health")).body.enrichEnabled).toBe(true);
    // The per-case provider list is derived from the SAME set the enrich engine uses, so it proves
    // the rebuild reached the live registry rather than only process.env.
    const control = await request(app).get("/cases/reload-case/enrich-control");
    expect(control.status).toBe(200);
    expect(control.body.providers.find((p: { name: string }) => p.name === "VirusTotal")?.configured).toBe(true);
  });

  it("rebuilds the customer-exposure provider set", async () => {
    expect((await request(app).get("/health")).body.customerExposureEnabled).toBe(false);

    await writeFile(envPath, "DFIR_LEAKCHECK_KEY=lc-secret\n", "utf8");
    const res = await reload("DFIR_LEAKCHECK_");

    expect(res.body.rebuilt).toContain("exposure");
    expect((await request(app).get("/health")).body.customerExposureEnabled).toBe(true);
  });

  it("rebuilds the Notion and ClickUp export clients", async () => {
    await writeFile(envPath, "DFIR_NOTION_TOKEN=ntn\nDFIR_CLICKUP_TOKEN=cu\nDFIR_CLICKUP_LIST_ID=901\n", "utf8");

    expect((await reload("DFIR_NOTION_")).body.rebuilt).toContain("notion");
    expect((await request(app).get("/notion/status")).body.configured).toBe(true);

    expect((await reload("DFIR_CLICKUP_")).body.rebuilt).toContain("clickup");
    const clickup = await request(app).get("/clickup/status");
    expect(clickup.body.configured).toBe(true);
    expect(clickup.body.defaultListId).toBe("901");
  });

  it("reports nothing rebuilt for a prefix with no live client to rebuild", async () => {
    await writeFile(envPath, "DFIR_TOOL_YARA_PATH=/usr/bin/yara\n", "utf8");
    const res = await reload("DFIR_TOOL_");
    expect(res.status).toBe(200);
    expect(res.body.applied).toContain("DFIR_TOOL_YARA_PATH");
    expect(res.body.rebuilt).toEqual([]);
  });

  it("stays a 200 for every allowlisted prefix, with or without a .env on disk", async () => {
    const failures: string[] = [];
    for (const prefix of ALL_PREFIXES) {
      const res = await reload(prefix);
      if (res.status !== 200 || !Array.isArray(res.body.rebuilt)) {
        failures.push(`${prefix} -> ${res.status} ${JSON.stringify(res.body)}`);
      }
    }
    expect(failures).toEqual([]);
  });
});
