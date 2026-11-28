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
let timeline: unknown[];

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "demo-attack-path-"));
  const { caseDir } = await seedDemoCase(root, { caseId: "demo-ap" });
  const state = JSON.parse(await readFile(join(caseDir, "state", "investigation.json"), "utf8")) as {
    attackerPath: string;
    forensicTimeline: unknown[];
  };
  attackerPath = state.attackerPath;
  timeline = state.forensicTimeline;
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

  // #3082: the Hosts view drew the move only under WEB01, the last host it names, and its time link
  // opened FS01's event. It must sit under both hosts, each card linking an event on its own host.
  it("draws the move to FS01 and WEB01 under both hosts, each linking its own host's event", () => {
    const html = ap.attackPathHtml(attackerPath, timeline, "hosts");
    const assetOf = new Map(
      (timeline as { id: unknown; asset?: unknown }[]).map((e) => [
        String(e.id),
        String(e.asset ?? "").trim(),
      ]),
    );
    for (const host of ["FS01", "WEB01"]) {
      const at = html.indexOf(`<th scope="row"><span class="ap-host">${host}</span>`);
      expect(at).toBeGreaterThan(-1);
      const row = html.slice(at, html.indexOf("</tr>", at));
      const card =
        /<div class="ap-card[^"]*"[^>]*><span class="ap-ct">(.*?)<\/span><span class="ap-tac">Lateral Movement to FS01 \+ WEB01<\/span>/.exec(
          row,
        );
      expect(card).not.toBeNull();
      const id = /data-id="([^"]*)"/.exec(card?.[1] ?? "")?.[1];
      expect(assetOf.get(String(id))).toBe(host);
    }
  });
});
