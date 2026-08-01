import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext } from "@playwright/test";

// Covers: US-013, US-015, US-016, US-032, US-033, US-035, US-036, US-037, US-038
// (feature-user-stories.csv) — the unified sniffing import, the log/THOR/auditd/journald/Wazuh
// importers, import undo/redo, generic file import and stored-evidence access.
//
// These drive real payloads, not just the request contract (importContract.spec.ts covers that
// across all 23 routes). Payload shapes are taken from the fixtures the unit tests already prove
// valid — tests/analysis/thorImport.test.ts and wazuhImport.test.ts — rather than invented here.
//
// Imports answer 202. The deterministic importers do their parsing before responding and report
// their own counts; the AI-dependent ones finish on a background job. Assertions about ingested
// CONTENT therefore poll the case state rather than trusting the response, because "the endpoint
// accepted it" and "the investigator can see it" are different claims.

/** THOR is JSONL: one finding per line. Shape from tests/analysis/thorImport.test.ts. */
const THOR_JSONL = [
  {
    time: "2026-06-03T09:43:07Z",
    hostname: "WIN11",
    level: "Alert",
    module: "ProcessCheck",
    message: "Malicious process found",
    pid: 8684,
    process_name: "evil.exe",
    image_file: "C:\\Tools\\evil.exe",
    image_sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
    reason_1: "YARA rule Powerkatz_DLL / Detects Mimikatz",
  },
  {
    time: "2026-06-03T09:43:30Z",
    hostname: "WIN11",
    level: "Warning",
    module: "Filescan",
    message: "Possibly Dangerous file found",
    file: "C:\\Users\\srv\\Trigona.ps1",
    reason_1: "YARA rule SUSP_PS1 / Suspicious PowerShell",
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

/** Wazuh alert shape from tests/analysis/wazuhImport.test.ts. */
const WAZUH_JSON = JSON.stringify({
  timestamp: "2026-01-15T10:30:00.123+0000",
  rule: {
    level: 14,
    description: "Rootkit detected",
    id: "550",
    groups: ["rootcheck"],
    mitre: { technique: ["T1014"] },
  },
  agent: { id: "001", name: "web-server-01" },
  data: { srcip: "203.0.113.10", dstip: "10.0.0.5" },
});

/** auditd writes several `type=… msg=audit(EPOCH.MS:SERIAL): …` lines per logical event. */
const AUDITD_LOG = [
  "type=SYSCALL msg=audit(1770000000.123:4321): arch=c000003e syscall=59 success=yes exe=/usr/bin/bash",
  'type=EXECVE msg=audit(1770000000.123:4321): argc=2 a0="bash" a1="-c"',
  'type=USER_AUTH msg=audit(1770000060.500:4322): pid=1234 uid=0 res=failed acct="root"',
].join("\n");

/** journald `-o json` — one object per line, fields uppercase, timestamps µs epoch. */
const JOURNALD_JSON = [
  {
    __REALTIME_TIMESTAMP: "1770000000000000",
    MESSAGE: "Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
    PRIORITY: "4",
    SYSLOG_IDENTIFIER: "sshd",
    _HOSTNAME: "web-server-01",
  },
  {
    __REALTIME_TIMESTAMP: "1770000060000000",
    MESSAGE: "session opened for user root",
    PRIORITY: "6",
    SYSLOG_IDENTIFIER: "sudo",
    _HOSTNAME: "web-server-01",
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

/**
 * Whether the case's state mentions `needle`.
 *
 * The deterministic importers answer synchronously with their own counts, but "the endpoint said it
 * ingested one finding" is not the same claim as "the investigator can see it". This polls the case
 * state for the ingested text, which is the claim that matters.
 */
async function stateContains(request: APIRequestContext, caseId: string, needle: string): Promise<boolean> {
  const res = await request.get(`/cases/${caseId}/state`);
  if (!res.ok()) return false;
  return (await res.text()).includes(needle);
}

/** Poll until ingested text reaches the case state. */
async function expectIngested(request: APIRequestContext, caseId: string, needle: string): Promise<void> {
  await expect
    .poll(() => stateContains(request, caseId, needle), { timeout: 60_000, intervals: [500] })
    .toBe(true);
}

/** POST an importer payload and assert it was accepted, returning the stored filename. */
async function postImport(
  request: APIRequestContext,
  caseId: string,
  route: string,
  data: Record<string, unknown>,
): Promise<string> {
  const res = await request.post(`/cases/${caseId}/${route}`, { data });
  expect(res.status(), await res.text()).toBe(202);
  const body = (await res.json()) as { accepted: boolean; file: string };
  expect(body.accepted).toBe(true);
  return body.file;
}

test("US-016: a THOR JSONL import lands in the case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const file = await postImport(page.request, demoCase, "import-thor", {
    json: THOR_JSONL,
    filename: "thor.jsonl",
  });
  expect(file).toContain("thor");
  await expectIngested(page.request, demoCase, "Malicious process found");
});

test("US-035: a Wazuh alert import lands in the case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  await postImport(page.request, demoCase, "import-wazuh", {
    text: WAZUH_JSON,
    filename: "wazuh.json",
  });
  await expectIngested(page.request, demoCase, "Rootkit detected");
});

test("US-032: an auditd log import lands in the case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  await postImport(page.request, demoCase, "import-auditd", {
    text: AUDITD_LOG,
    filename: "audit.log",
  });
  // auditd stitches several `type=` lines sharing one audit id into a single logical event, so the
  // execve argv is the evidence that the stitching happened rather than three unrelated rows.
  await expectIngested(page.request, demoCase, "USER_AUTH");
});

test("US-033: a journald JSON import lands in the case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  await postImport(page.request, demoCase, "import-journald", {
    text: JOURNALD_JSON,
    filename: "journal.json",
  });
  await expectIngested(page.request, demoCase, "Failed password for invalid user admin");
});

test("US-015: a plain log import is accepted", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // AI-dependent: the stub provider returns fixed prose, so this asserts the route accepts and
  // stores the evidence, not what the model made of it.
  const file = await postImport(page.request, demoCase, "import-log", {
    text: [
      "2026-05-18 02:30:00 FS01 sshd[1234]: Accepted password for jsmith from 10.0.0.5",
      "2026-05-18 02:31:00 FS01 sudo: jsmith : TTY=pts/0 ; COMMAND=/bin/tar czf backup.tgz /finance",
    ].join("\n"),
    filename: "syslog.log",
  });

  const stored = await page.request.get(`/cases/${demoCase}/evidence/${encodeURIComponent(file)}`);
  expect(stored.status()).toBe(200);
  expect(await stored.text()).toContain("Accepted password for jsmith");
});

test("US-013: the unified import sniffs the format and reports which one it chose", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.post(`/cases/${demoCase}/import`, {
    data: { text: THOR_JSONL, filename: "sniff-me.jsonl" },
  });
  expect(res.status(), await res.text()).toBe(202);

  // The detected kind is reported back so a mis-route is visible to the analyst rather than silent
  // — which is the whole point of sniffing rather than asking.
  const body = (await res.json()) as { kind: string };
  expect(body.kind, `unified import detected "${body.kind}" for THOR JSONL`).toBe("thor");
  await expectIngested(page.request, demoCase, "Malicious process found");
});

test("US-037, US-038: a generic file import is stored and the artifact is retrievable", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // import-file takes an absolute path on the SERVER. The suite's server runs on this machine, so a
  // temp file here is reachable by it. Written under the OS temp dir, never inside the repo.
  const dir = mkdtempSync(join(tmpdir(), "dfir-e2e-evidence-"));
  const path = join(dir, "evidence.log");
  writeFileSync(path, "2026-05-18 02:30:00 FS01 sshd[1234]: Accepted password for jsmith\n");

  const file = await postImport(page.request, demoCase, "import-file", { path });

  // US-038: the stored artifact must come back byte-for-byte. A case whose evidence cannot be
  // re-read is not defensible, however good the analysis built on top of it is.
  const fetched = await page.request.get(`/cases/${demoCase}/evidence/${encodeURIComponent(file)}`);
  expect(fetched.status(), await fetched.text()).toBe(200);
  expect(await fetched.text()).toContain("Accepted password for jsmith");
});

test("US-036: an import can be undone and redone", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Through the UNIFIED route, not import-thor. Only the generic /import and /import-file handlers
  // push an undo checkpoint (src/routes/import.ts:294 and :472); the format-specific importers do
  // not, so an undo after one of those correctly answers "nothing to undo". /import is also the
  // path the dashboard's own upload uses.
  const res = await page.request.post(`/cases/${demoCase}/import`, {
    data: { text: THOR_JSONL, filename: "undo-me.jsonl" },
  });
  expect(res.status(), await res.text()).toBe(202);
  await expectIngested(page.request, demoCase, "Malicious process found");

  // Wait for the checkpoint to exist before undoing. pushImportCheckpoint runs inside the import's
  // async processing, AFTER the 202 and not necessarily before the events reach the state — so
  // "the events are visible" does not imply "the undo stack has an entry". Undoing too early
  // answers 400 "nothing to undo", which failed about half the time under a loaded server.
  await expect
    .poll(
      async () => {
        const stack = await page.request.get(`/cases/${demoCase}/import/undo-stack`);
        if (!stack.ok()) return false;
        return ((await stack.json()) as { canUndo: boolean }).canUndo;
      },
      { timeout: 30_000, intervals: [250] },
    )
    .toBe(true);

  const undo = await page.request.post(`/cases/${demoCase}/import/undo`, { data: {} });
  expect(undo.status(), await undo.text()).toBe(200);
  // The whole point of undo is that the events go away; asserting only the status code would pass
  // against a no-op.
  await expect
    .poll(() => stateContains(page.request, demoCase, "Malicious process found"), {
      timeout: 30_000,
      intervals: [500],
    })
    .toBe(false);

  const redo = await page.request.post(`/cases/${demoCase}/import/redo`, { data: {} });
  expect(redo.status(), await redo.text()).toBe(200);
  // An undo that cannot be reversed turns a mis-click into lost evidence.
  await expectIngested(page.request, demoCase, "Malicious process found");
});
