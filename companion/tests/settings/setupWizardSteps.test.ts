import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { RELOADABLE_ENV_PREFIXES, validateEnvUpdates } from "../../src/settings/envManager.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The wizard's step table (public/js/dashboard-wizard-steps.js) is pure data that only the BROWSER
// ever runs, and every entry in it is a claim about this server: that it will write these keys,
// apply this prefix, and answer this status field. Nothing checked those claims, so a step could
// be — and was — wired to a route that refuses it, with a fully green suite:
//
//   - the Presidio step's three keys are writable but DFIR_PRESIDIO_ is deliberately NOT on the
//     /settings/reload allowlist (the analyzer client is built once at startup). A step declaring
//     `reload: "DFIR_PRESIDIO_"` would 400 on every save, and the wizard's `.catch(() => {})`
//     around that call means it would 400 SILENTLY, reporting "Saved & configured";
//   - a step whose `status` key is absent from /setup/status renders as neither ✓ nor ○ forever.
//
// Both are one-line mistakes in a data table, and both are invisible until someone opens the
// wizard and reads the rail.

interface WizardField {
  key: string;
  label: string;
  secret?: boolean;
  hint?: string;
}
interface WizardProvider {
  id: string;
  reload?: string;
  fields: WizardField[];
}
interface WizardStep {
  id: string;
  label: string;
  status?: string;
  kind?: string;
  reload?: string;
  fields?: WizardField[];
  providers?: WizardProvider[];
}
interface WizardStepsApi {
  wizardOrder: () => string[];
  wizardStepById: (id: string) => WizardStep | undefined;
}

const wizard = loadDashboardModule<WizardStepsApi>("dashboard-wizard-steps.js");

/** Every non-AI step, in rail order. "ai" is rendered statically and has no table entry. */
const steps = (): WizardStep[] =>
  wizard
    .wizardOrder()
    .map((id) => wizard.wizardStepById(id))
    .filter((s): s is WizardStep => s !== undefined);

/** Every (prefix, source) pair a step will POST to /settings/reload — steps and sub-providers. */
const reloadPrefixes = (): Array<{ prefix: string; from: string }> =>
  steps().flatMap((s) => [
    ...(s.reload ? [{ prefix: s.reload, from: s.id }] : []),
    ...(s.providers ?? [])
      .filter((p) => p.reload)
      .map((p) => ({ prefix: p.reload as string, from: `${s.id}/${p.id}` })),
  ]);

/** Every env key the wizard renders an input for. */
const fieldKeys = (): Array<{ key: string; from: string }> =>
  steps().flatMap((s) => [
    ...(s.fields ?? []).map((f) => ({ key: f.key, from: s.id })),
    ...(s.providers ?? []).flatMap((p) => p.fields.map((f) => ({ key: f.key, from: `${s.id}/${p.id}` }))),
  ]);

describe("the setup wizard's step table ⇄ the routes it calls", () => {
  it("finds the step table at all", () => {
    // Guards every assertion below: a rename of the published accessors would empty all of them.
    expect(wizard.wizardOrder()[0], "the AI step is no longer first in the rail").toBe("ai");
    expect(steps().length).toBeGreaterThan(5);
  });

  it("only saves keys POST /settings/env will accept", () => {
    const rejected = fieldKeys().filter(({ key }) => validateEnvUpdates({ [key]: "x" }).length > 0);
    expect(rejected, `wizard fields the server refuses to write: ${JSON.stringify(rejected)}`).toEqual([]);
  });

  it("only applies prefixes POST /settings/reload will accept", () => {
    const rejected = reloadPrefixes().filter(({ prefix }) => !RELOADABLE_ENV_PREFIXES.has(prefix));
    expect(rejected, `steps that would 400 on apply, silently: ${JSON.stringify(rejected)}`).toEqual([]);
  });

  // The Presidio step is the reason the check above is not a formality. Its keys are writable, so
  // it renders and saves like any other step — but they reach the running server only through a
  // restart, which is why the step declares no reload prefix and says "restart" after a save.
  it("keeps the Presidio step off the reload path, because its keys need a restart", () => {
    const presidio = wizard.wizardStepById("presidio");
    expect(presidio, "the Presidio step is gone from the wizard").toBeDefined();
    expect(presidio?.fields?.map((f) => f.key)).toEqual([
      "DFIR_PRESIDIO_URL",
      "DFIR_PRESIDIO_MIN_SCORE",
      "DFIR_PRESIDIO_TIMEOUT_MS",
    ]);
    expect(presidio?.reload, "a Presidio reload prefix would 400 on every save").toBeUndefined();
    expect(RELOADABLE_ENV_PREFIXES.has("DFIR_PRESIDIO_")).toBe(false);
    expect(validateEnvUpdates({ DFIR_PRESIDIO_URL: "http://localhost:5002" })).toEqual([]);
  });

  it("answers /setup/status for every step that draws a rail tick", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-wizard-steps-"));
    setServerLogger(createConsoleLogger("info"));
    const res = await request(createApp(new CaseStore(root), {})).get("/setup/status");
    expect(res.status).toBe(200);

    const missing = steps()
      .filter((s) => s.status)
      .filter((s) => {
        const value = (res.body as Record<string, unknown>)[s.status as string];
        // The rail reads a plain boolean, or an object of them for the two provider steps.
        return typeof value !== "boolean" && (value === null || typeof value !== "object");
      })
      .map((s) => s.status);
    expect(missing, `rail ticks with no /setup/status field: ${missing.join(", ")}`).toEqual([]);
    expect(typeof (res.body as Record<string, unknown>).presidio).toBe("boolean");
  });
});
