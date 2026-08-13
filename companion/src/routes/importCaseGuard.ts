import type { Express, NextFunction, Request, Response } from "express";
import type { CaseStore } from "../storage/caseStore.js";

// Every POST route that ingests evidence into a case: the unified sniffing import, the server-side
// file import, and each per-format importer. Kept as ONE list so the existence guard below is
// mounted across all of them at once — tests/server/importMissingCase.test.ts walks the live
// Express router and fails if a new /cases/:id/import* POST route is added without being listed.
//
// Excludes /cases/:id/import/undo and /import/redo (they replay state that is already in the case,
// and 501 without an undo store) and the GET /import-meta, /drop-status readers.
export const EVIDENCE_IMPORT_ROUTES = [
  "import",
  "import-file",
  "import-csv",
  "import-log",
  "import-thor",
  "import-siem",
  "import-chainsaw",
  "import-hayabusa",
  "import-velociraptor",
  "import-network",
  "import-kape",
  "import-cybertriage",
  "import-m365",
  "import-leapp",
  "import-aws",
  "import-cloud-activity",
  "import-plaso",
  "import-sandbox",
  "import-memory",
  "import-email",
  "import-thehive",
  "import-auditd",
  "import-journald",
  "import-sysdig",
  "import-wazuh",
] as const;

// Evidence-first guard for every import route — parity with POST /captures and GET /state, which
// already 404 an unknown case. The companion never creates a case as a side effect of ingesting
// evidence (see CaseStore.caseExists): creation is a deliberate dashboard action.
//
// The "Connect" toolbar action attaches to a case id WITHOUT creating it, so a typo'd or
// never-created id used to 202-"accept" an import and orphan it on disk — the raw evidence, an
// imports.jsonl line, a custody record and a session log, all under a directory with no case.json
// that GET /cases therefore never lists. The analyst saw success and the evidence was gone.
//
// Mounted as ONE handler ahead of the route handlers rather than repeated inside each of them:
// routes/import.ts is size-frozen (#384), and a single mount cannot drift route to route.
//
// Runs before each route's own payload parsing and before the closed/archived 423 check. Both are
// deliberate: an unknown case id is not a payload problem and nothing should touch disk before the
// case identity is settled, and an archived case still satisfies caseExists() (caseDir() falls back
// to _archived/), so archived/closed cases keep their 423 rather than collapsing into this 404.
export function registerImportCaseGuard(app: Express, store: CaseStore): void {
  const paths = EVIDENCE_IMPORT_ROUTES.map((route) => `/cases/:id/${route}`);
  app.post(paths, async (req: Request, res: Response, next: NextFunction) => {
    const caseId = req.params.id;
    try {
      if (await store.caseExists(caseId)) return next();
    } catch (err) {
      return next(err);
    }
    return res
      .status(404)
      .json({ error: `case ${caseId} does not exist — create it in the dashboard first` });
  });
}
