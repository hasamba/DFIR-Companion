import { readFile } from "node:fs/promises";
import { config as loadDotenv } from "dotenv";
import { z } from "zod";
import type { AIProvider } from "../../src/providers/provider.js";
import { judgeForbiddenConclusions } from "./forbiddenJudge.js";
import { realProviderOrNull } from "./harness.js";
import type { CaseGolden, QualityOutput } from "./qualityScorer.js";

// #1704: reliability evidence for the forbidden-conclusion judge. Runs the REAL judge over a fixed
// set of findings whose verdict is known — real correct rejections from #1579 that the word list
// misread, and real accusations including paraphrases — and fails on any wrong verdict.
//   npm run eval:judge-calibration -- --runs 3

const itemSchema = z
  .object({
    id: z.string().min(1),
    source: z.string().min(1),
    statement: z.string().min(10),
    title: z.string().min(1),
    description: z.string().min(1),
    expected: z.boolean(),
  })
  .strict();

export const calibrationSchema = z
  .object({ schemaVersion: z.literal(1), note: z.string(), items: z.array(itemSchema).min(1) })
  .strict();

export type CalibrationItem = z.infer<typeof itemSchema>;

export async function loadCalibration(): Promise<CalibrationItem[]> {
  const raw = await readFile(new URL("./judgeCalibration.json", import.meta.url), "utf8");
  return calibrationSchema.parse(JSON.parse(raw) as unknown).items;
}

const EMPTY_GOLDEN: Omit<CaseGolden, "forbiddenConclusions"> = {
  claims: [],
  iocs: [],
  uncertainties: [],
  nextSteps: [],
  expectAbstention: false,
};

// One judge call per statement, grading all of its findings together — the same grid shape a
// real corpus case sends.
export async function gradeCalibration(
  items: readonly CalibrationItem[],
  judge: AIProvider,
): Promise<string[]> {
  const wrong: string[] = [];
  for (const statement of [...new Set(items.map((item) => item.statement))]) {
    const group = items.filter((item) => item.statement === statement);
    const output: QualityOutput = {
      evidenceEventIds: [],
      claims: group.map((item) => ({
        id: item.id,
        title: item.title,
        description: item.description,
        evidenceEventIds: [],
      })),
      iocs: [],
      uncertainties: [],
      nextSteps: [],
    };
    const golden: CaseGolden = {
      ...EMPTY_GOLDEN,
      forbiddenConclusions: [{ id: "s", terms: ["x"], claim: statement }],
    };
    const outcome = await judgeForbiddenConclusions(golden, output, judge);
    for (const item of group) {
      const detail = outcome.details.find((candidate) => candidate.findingId === item.id);
      if (detail?.asserts !== item.expected) {
        wrong.push(
          `${item.id}: expected asserts=${item.expected}, judge said ${detail?.asserts} (${JSON.stringify(detail?.reason)})`,
        );
      }
    }
  }
  return wrong;
}

async function main(): Promise<void> {
  loadDotenv({ quiet: true });
  const runsFlag = process.argv.indexOf("--runs");
  const runs = runsFlag >= 0 ? Number(process.argv[runsFlag + 1]) : 3;
  if (!Number.isInteger(runs) || runs < 1 || runs > 10)
    throw new Error("--runs must be an integer from 1 to 10");
  const judge = realProviderOrNull();
  if (!judge) throw new Error("no text AI provider is configured (DFIR_AI_SYNTH_* / DFIR_AI_*)");
  const items = await loadCalibration();
  let failures = 0;
  for (let run = 1; run <= runs; run += 1) {
    const wrong = await gradeCalibration(items, judge);
    failures += wrong.length;
    console.log(
      `run ${run}: ${items.length - wrong.length}/${items.length} correct (judge ${judge.name}/${judge.model})`,
    );
    for (const line of wrong) console.log(`  WRONG ${line}`);
  }
  console.log(failures === 0 ? "judge calibration: passed" : `judge calibration: ${failures} wrong verdicts`);
  process.exitCode = failures === 0 ? 0 : 1;
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "")) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  });
}
