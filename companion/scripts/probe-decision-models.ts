/**
 * Does each OpenRouter decision model answer what the Decision model features actually ask? (#2224)
 *
 * OpenRouter lists every decision model behind one endpoint, but its catalog does not say which
 * question types a model supports. This runs the PRODUCTION code paths — the real transport and its
 * answer validation, the real question sets — against one SYNTHETIC event, never case data:
 *
 *   single      — the review's one-question grade (gradeEvents, shape "single")
 *   narrow      — the review's narrow-questions grade (gradeEvents, shape "decomposed")
 *   containment — the per-finding containment check's eleven questions
 *
 * A model passes only if all three come back complete and well-typed. It also prints the model id
 * the service answered under, which differs from the requested id for an alias like `~typesafe/jev-latest`.
 *
 *   npx tsx scripts/probe-decision-models.ts                       # every listed decision model
 *   npx tsx scripts/probe-decision-models.ts typesafe/jev-1.14 ~typesafe/jev-latest
 *
 * Key: DFIR_JEV_KEY, else DFIR_AI_KEY_OPENROUTER, from the environment (run with --env-file=.env).
 * Exit code 1 when any model fails. Cost: a few small requests per model.
 */
import { askJev, type JevRequestConfig } from "../src/analysis/ai/jev/jevClient.js";
import { gradeEvents, type JevGradeShape } from "../src/analysis/ai/jev/jevGrader.js";
import { CONTAINMENT_QUESTIONS } from "../src/analysis/ai/jev/containmentQuestions.js";
import { createDecisionModelCatalog } from "../src/analysis/ai/jev/decisionModels.js";
import type { ForensicEvent } from "../src/analysis/stateTypes.js";

const DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions";
const TIMEOUT_MS = 90_000;
const MAX_DETAIL_CHARS = 140;

const EVENT: ForensicEvent = {
  id: "probe-1",
  timestamp: "2026-01-01T03:12:44.000Z",
  description: "Process created: powershell.exe -nop -w hidden -enc SQBFAFgA (parent winword.exe)",
  severity: "Info",
  path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  processName: "powershell.exe",
  parentName: "winword.exe",
  asset: "WS-LAB01",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const CONTAINMENT_STATE = {
  finding: "Encoded PowerShell launched by Word on WS-LAB01 shortly after a phishing attachment was opened.",
  events: [EVENT.description],
};

function apiKey(): string {
  for (const name of ["DFIR_JEV_KEY", "DFIR_AI_KEY_OPENROUTER"]) {
    const value = process.env[name]?.trim();
    if (value) return value;
  }
  throw new Error("No key: set DFIR_JEV_KEY or DFIR_AI_KEY_OPENROUTER (e.g. node --env-file=.env).");
}

type Check = { ok: boolean; answeredAs?: string; detail?: string };

async function attempt(run: () => Promise<string>, key: string): Promise<Check> {
  try {
    return { ok: true, answeredAs: await run() };
  } catch (err) {
    const message = (err instanceof Error ? err.message : String(err)).split(key).join("[redacted]");
    return { ok: false, detail: message.slice(0, MAX_DETAIL_CHARS) };
  }
}

async function probe(model: string, key: string) {
  const cfg: JevRequestConfig = {
    baseUrl: DECISIONS_URL,
    model,
    apiKey: key,
    timeoutMs: TIMEOUT_MS,
    maxRetries: 1,
  };
  const grade = (shape: JevGradeShape) => async () => {
    const r = await gradeEvents({ mask: (t) => t, ask: (state, qs) => askJev(cfg, state, qs) }, [EVENT], {
      batchSize: 1,
      shape,
    });
    return r.model;
  };
  const [single, narrow, containment] = await Promise.all([
    attempt(grade("single"), key),
    attempt(grade("decomposed"), key),
    attempt(async () => (await askJev(cfg, CONTAINMENT_STATE, CONTAINMENT_QUESTIONS)).model, key),
  ]);
  return { model, single, narrow, containment };
}

const cell = (c: Check) => (c.ok ? "ok  " : "FAIL");

const key = apiKey();
const requested =
  process.argv.length > 2
    ? process.argv.slice(2)
    : (await createDecisionModelCatalog().list()).models.map((m) => m.id);
const results = await Promise.all(requested.map((m) => probe(m, key)));

console.log(`${"model".padEnd(42)} single narrow contain  answered as`);
for (const r of results) {
  const as = r.single.answeredAs ?? r.narrow.answeredAs ?? r.containment.answeredAs ?? "-";
  console.log(`${r.model.padEnd(42)} ${cell(r.single)}   ${cell(r.narrow)}   ${cell(r.containment)}   ${as}`);
  for (const [name, c] of [
    ["single", r.single],
    ["narrow", r.narrow],
    ["containment", r.containment],
  ] as const) {
    if (!c.ok) console.log(`    ${name}: ${c.detail}`);
  }
}
const passed = results.filter((r) => r.single.ok && r.narrow.ok && r.containment.ok).length;
console.log(`\n${passed}/${results.length} models answered every question set the app sends.`);
process.exitCode = passed === results.length ? 0 : 1;
