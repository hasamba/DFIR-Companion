import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { COLLECTOR_CALLS } from "../../src/analysis/cloudCollectorFootprint.js";

// #2487: every AWS API the live collector calls must be in the collector-footprint allowlist, or a
// new collector call would come back in the evidence untagged. A call removed from the collector may
// stay listed (older collections still made it).

const AWS_DIR = fileURLToPath(new URL("../../src/integrations/cloudCollect/aws/", import.meta.url));

describe("the collector-footprint allowlist covers every AWS collector call (#2487)", () => {
  it("lists each `new XCommand(` the AWS collector sends", () => {
    const calls = new Set<string>();
    for (const file of readdirSync(AWS_DIR).filter((f) => f.endsWith(".ts"))) {
      const src = readFileSync(join(AWS_DIR, file), "utf8");
      for (const m of src.matchAll(/new (\w+)Command\(/g)) calls.add(m[1].toLowerCase());
    }
    expect(calls.size).toBeGreaterThan(5);
    for (const call of calls) expect(COLLECTOR_CALLS.aws, call).toContain(call);
  });
});
