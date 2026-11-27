import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AttackPathApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { seedDemoCase } from "../../src/analysis/seedDemoCase.js";

// #3023: the demo case's attack path is read by the same parser the dashboard uses. Step 9 was
// seeded as "— May 16 10:00." with nothing after the time, so the Attack Path panel printed a lone
// "." as its description. Every seeded step must parse into a step that says what happened.

const ap = loadDashboardModule<AttackPathApi>("dashboard-attack-path.js", [
  "dashboard-escape.js",
  "dashboard-text.js",
  "dashboard-fragments.js",
]);

let root: string;
let attackerPath: string;

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "demo-attack-path-"));
  const { caseDir } = await seedDemoCase(root, { caseId: "demo-ap" });
  const state = JSON.parse(await readFile(join(caseDir, "state", "investigation.json"), "utf8")) as {
    attackerPath: string;
  };
  attackerPath = state.attackerPath;
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("demo case attack path", () => {
  it("parses into twelve steps, each with a description that has words in it", () => {
    const steps = ap.attackSteps(attackerPath);
    expect(steps).toHaveLength(12);
    for (const step of steps) expect(step.desc).toMatch(/[A-Za-z]{3,}/);
  });

  it("describes the move to FS01 and WEB01 with its full time range", () => {
    const step = ap.attackSteps(attackerPath).find((s) => s.title === "Lateral Movement to FS01 + WEB01");
    expect(step).toMatchObject({ month: 5, day: 16, time: "10:00", timeEnd: "10:05" });
    expect(step?.desc).toMatch(/PsExec/);
    expect(step?.desc).toMatch(/FS01/);
    expect(step?.desc).toMatch(/WEB01/);
  });
});
