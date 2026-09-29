// #1866 (item 1): a per-case background starter must run its work in a case scope.
//
// #1855 gave every case incarnation a generation. Work captures it (runInCaseScope) and a write is
// refused once that case is deleted or replaced. Work that NEVER captured one is refused only while
// no case.json exists — so it can still write into a same-id successor. Inside a /cases/:id request
// the case gate captures for you, and every timer, promise tail and job started there inherits it.
// The gaps are the places that start per-case work OUTSIDE such a request:
//
//   1. recurring timers (setInterval) — a sweep started at boot, with no case in scope;
//   2. boot/poll sweeps over listCases() — each case's work must carry the generation just listed;
//   3. mutating routes outside /cases/:id — the case id rides in the body, a job id, a chat command.
//
// This test is a registry of all three. A new one fails here until someone classifies it: either it
// touches no case (say why), or it scopes its per-case work (and the file shows the helper). The
// escape hatch is the ledger below, with a reason — not a weaker pattern.
//
// The scope helpers (storage/caseIncarnation.ts): runInCaseScope, runInGenerationScope,
// captureCaseScope. Per-case in-memory state uses storage/caseKeyedState.ts.
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const SRC = join(__dirname, "..", "..", "src");
const SCOPE_HELPER = /\b(runInCaseScope|runInGenerationScope|captureCaseScope)\(/;

function sources(dir = SRC): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...sources(full));
    else if (name.endsWith(".ts") && !name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

/** Source without line comments and block comments, so prose never counts as a call. */
function code(file: string): string {
  return readFileSync(file, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}

const rel = (file: string) => relative(SRC, file).replace(/\\/g, "/");
const FILES = sources().map((file) => ({ path: rel(file), text: code(file) }));

// ── 1. Recurring timers ────────────────────────────────────────────────────────────────────────
// file → how many setInterval calls it holds, and whether a tick does per-case work. "per-case"
// entries must scope that work per case (the file must use a scope helper).
const INTERVALS: Record<string, { count: number; kind: "global" | "per-case"; why: string }> = {
  "analysis/operationalCapacity.ts": { count: 1, kind: "global", why: "capacity sampling; writes no case" },
  "composition/captureAnalysis.ts": {
    count: 1,
    kind: "per-case",
    why: "flush sweep: each buffer drains in runInGenerationScope (its own incarnation)",
  },
  "composition/enrichment.ts": {
    count: 1,
    kind: "per-case",
    why: "health poller: each pending case resumes in runInGenerationScope",
  },
  "composition/maintenanceTasks.ts": {
    count: 6,
    kind: "per-case",
    why:
      "session sweep, delivery-staging sweep, update check: global; integrity sweep: reads only; " +
      "backup: runInCaseScope with the listed generation; demo reseed: CaseStore.withSeedSlot",
  },
  "http/rateLimiter.ts": { count: 10, kind: "global", why: "in-memory limiter sweeps" },
  "integrations/mcp/mcpDelivery.ts": {
    count: 2,
    kind: "global",
    why: "keep-alive and progress of one delivery, inside the request that started it",
  },
  "live/wsGate.ts": { count: 1, kind: "global", why: "socket heartbeat" },
  "routes/mcp.ts": { count: 1, kind: "global", why: "heartbeat inside a /cases/:id request (gate-scoped)" },
};

// ── 2. listCases() sweeps in composition/ ──────────────────────────────────────────────────────
// A sweep that starts per-case work must pass the LISTED generation (generationOf) into the scope,
// so a case created between the listing and the work is not adopted.
const LIST_SWEEPS: Record<string, string> = {
  "composition/dropFolder.ts": "scanCaseDrops per case, in scope with generationOf(listed)",
  "composition/maintenanceTasks.ts": "scheduled backup per case, in scope with generationOf(listed)",
  "composition/veloMonitors.ts": "startup resume arms each monitor in scope with generationOf(listed)",
  "composition/veloHuntStatusTimers.ts": "startup resume arms each hunt poll with generationOf(listed)",
  "composition/runtimeStores.ts": "audit export lists case ids only; its writes are global (cursors)",
};
const LIST_SWEEPS_WITHOUT_GENERATION = new Set(["composition/runtimeStores.ts"]);

// ── 3. Mutating routes outside the /cases/:id gate ─────────────────────────────────────────────
// "global:" touches no case folder. "creates:" makes a new incarnation (it stamps a generation).
// "scoped:" writes to a case, so its file must use a scope helper.
const OUTSIDE_GATE_GLOBAL_PREFIXES = [
  "/auth/", // team-auth rows (global store), not case folders
  "/settings/",
  "/audit-export",
  "/importers",
  "/clickup/",
  "/jira/",
  "/misp/",
  "/notion/",
  "/servicenow/",
  "/timesketch/",
  "/iris/",
  "/enrichment/",
  "/kev",
  "/mcp/",
  "/notifications",
  "/diagnostics/",
  "/system/",
  "/log-level",
  "/update-check/",
  "/tagger/",
  "/bundles",
  "/dashboard-views",
  "/report-templates",
  "/templates",
  "/ioc-whitelist",
  "/nsrl/",
  "/tools/",
];
const OUTSIDE_GATE: Record<string, string> = {
  "post /cases": "creates: createCase stamps a new generation",
  "post /cases/seed-demo": "creates: withSeedSlot stamps a new generation",
  "post /cases/import/encrypted": "creates: restore stamps a fresh generation before publish",
  "post /cases/import/zip": "creates: restore stamps a fresh generation before publish",
  "post /captures": "scoped: runInCaseScope on the body case id, before the first await",
  "post /velociraptor/run": "scoped: runInCaseScope on the body case id (audit line)",
  "post /velociraptor/hunt": "scoped: runInCaseScope on the body case id (audit line)",
  "post /api/jobs/:id/resume": "scoped: the resumed run runs in its job's case scope",
  "post /api/jobs/:id/cancel": "global: aborts a job; writes nothing under a case itself",
  "post /integrations/slack/command": "scoped: captureCaseScope once the case guard passed",
  "post /integrations/teams/command": "scoped: captureCaseScope once the case guard passed",
  "post /integrations/telegram/command": "scoped: captureCaseScope once the case guard passed",
  "post /velociraptor/hunt-results": "global: reads hunt rows from the server; no case write",
  "post /velociraptor/clients/refresh": "global: fleet inventory file at the cases root",
  "post /velociraptor/reconnect": "global: client reconnect",
  "post /velociraptor/collect-host": "global: launches a server collection; no case write",
  "post /velociraptor/collect-results": "global: reads collection rows; no case write",
  "post /velociraptor/bundles/:id/time-scope-preview": "global: preview only",
  "put /velociraptor/bundles/:id/time-scope-param-names": "global: bundle settings",
};

function mutatingRoutesOutsideGate(): { key: string; file: string }[] {
  const found: { key: string; file: string }[] = [];
  const route = /\bapp\.(post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/g;
  for (const { path, text } of FILES) {
    for (const m of text.matchAll(route)) {
      if (m[2].startsWith("/cases/:id")) continue;
      found.push({ key: `${m[1]} ${m[2]}`, file: path });
    }
  }
  return found;
}

describe("per-case background starters run in a case scope (#1866)", () => {
  it("every setInterval is classified, and a per-case one scopes its work", () => {
    const actual = new Map<string, number>();
    for (const { path, text } of FILES) {
      const count = (text.match(/\bsetInterval\(/g) ?? []).length;
      if (count > 0) actual.set(path, count);
    }
    const problems: string[] = [];
    for (const [path, count] of actual) {
      const entry = INTERVALS[path];
      if (!entry) problems.push(`${path}: ${count} new setInterval — classify it in INTERVALS`);
      else if (entry.count !== count)
        problems.push(`${path}: ${count} setInterval, ledger says ${entry.count} — classify the change`);
      else if (entry.kind === "per-case" && !SCOPE_HELPER.test(FILES.find((f) => f.path === path)!.text))
        problems.push(`${path}: per-case interval, but the file uses no case-scope helper`);
    }
    for (const path of Object.keys(INTERVALS))
      if (!actual.has(path)) problems.push(`${path}: no setInterval any more — drop the ledger entry`);
    expect(problems).toEqual([]);
  });

  it("every listCases() sweep in composition/ passes the listed generation into its scope", () => {
    const problems: string[] = [];
    const sweeping = FILES.filter((f) => f.path.startsWith("composition/") && /\.listCases\(\)/.test(f.text));
    for (const { path, text } of sweeping) {
      if (!LIST_SWEEPS[path]) {
        problems.push(`${path}: new listCases() sweep — scope each case with generationOf(listed)`);
        continue;
      }
      if (LIST_SWEEPS_WITHOUT_GENERATION.has(path)) continue;
      if (!/\bgenerationOf\(/.test(text) || !SCOPE_HELPER.test(text))
        problems.push(`${path}: sweeps listCases() but does not scope with the listed generation`);
    }
    for (const path of Object.keys(LIST_SWEEPS))
      if (!sweeping.some((f) => f.path === path)) problems.push(`${path}: no sweep any more — drop the entry`);
    expect(problems).toEqual([]);
  });

  it("every mutating route outside /cases/:id is classified, and a scoped one uses a helper", () => {
    const problems: string[] = [];
    const routes = mutatingRoutesOutsideGate();
    for (const { key, file } of routes) {
      const path = key.slice(key.indexOf(" ") + 1);
      if (OUTSIDE_GATE_GLOBAL_PREFIXES.some((prefix) => path.startsWith(prefix)) && !OUTSIDE_GATE[key]) continue;
      const why = OUTSIDE_GATE[key];
      if (!why) {
        problems.push(`${key} (${file}): outside the case gate — classify it in OUTSIDE_GATE`);
        continue;
      }
      if (why.startsWith("scoped:") && !SCOPE_HELPER.test(FILES.find((f) => f.path === file)!.text))
        problems.push(`${key} (${file}): classified scoped, but the file uses no case-scope helper`);
    }
    for (const key of Object.keys(OUTSIDE_GATE))
      if (!routes.some((r) => r.key === key)) problems.push(`${key}: no such route any more — drop the entry`);
    expect(problems).toEqual([]);
  });

  it("the scan itself sees the routes it must (guards against a regex that matches nothing)", () => {
    const keys = mutatingRoutesOutsideGate().map((r) => r.key);
    expect(keys).toContain("post /captures");
    expect(keys).toContain("post /integrations/slack/command");
    expect(keys).toContain("post /velociraptor/run");
  });
});
