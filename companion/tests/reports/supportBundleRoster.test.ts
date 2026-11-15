import { describe, it, expect } from "vitest";
import {
  buildSupportBundleZip,
  type SupportBundleDeps,
  type SupportBundleRequest,
} from "../../src/reports/supportBundleBuilder.js";
import { readZip } from "../../src/analysis/zipArchive.js";

// Watson's masking roster (H3) in the support bundle: a host or user name only a super-timeline or
// paste row showed is masked in the logs too, and a roster that cannot be read withholds the case.

const LINE = "case-fake1 pivot to WS-FAKE09 as fake.user\n";

const base: SupportBundleDeps = {
  store: {
    casesRoot: "/cases-fake",
    listCases: async () => [{ caseId: "case-fake1", name: "n" }],
    caseDir: (id: string) => `/cases-fake/${id}`,
    importsDir: (id: string) => `/cases-fake/${id}/imports`,
    caseExists: async () => true,
  } as unknown as SupportBundleDeps["store"],
  logPaths: { sessionLogPath: "/s.log" } as unknown as SupportBundleDeps["logPaths"],
  recentImportFailures: [],
  canSee: () => true,
  env: {},
  readTail: async () => {
    const bytes = Buffer.from(LINE, "utf8");
    return { bytes, size: bytes.length };
  },
};

const req: SupportBundleRequest = {
  generatedAt: "2026-11-15T00:00:00.000Z",
  version: "test",
  diagnosticsText: "",
  supportJson: "{}",
  includeCaseLog: false,
};

const allText = (zip: Buffer): string =>
  readZip(zip)
    .map((e) => e.data.toString("utf8"))
    .join("\n");

// The withheld count is not in redaction-summary.json; the bundle states it in README.txt only.
const summaryOf = (zip: Buffer): { withheldCases: number } => {
  const readme = readZip(zip)
    .find((e) => e.path === "README.txt")!
    .data.toString("utf8");
  const m = /Lines of (\d+) case\(s\)/.exec(readme);
  return { withheldCases: m ? Number(m[1]) : 0 };
};

describe("support bundle — Watson's masking roster", () => {
  it("shows the roster names in clear without a roster source (fixture check)", async () => {
    const zip = await buildSupportBundleZip(base, req);
    expect(allText(zip)).toContain("WS-FAKE09");
  });

  it("redacts a case's Watson roster names in the logs", async () => {
    const zip = await buildSupportBundleZip(
      { ...base, loadRawNames: async () => ({ hosts: ["ws-fake09"], usernames: ["fake.user"] }) },
      req,
    );
    expect(allText(zip).toLowerCase()).not.toMatch(/ws-fake09|fake\.user/);
  });

  it("withholds the case's lines when its roster cannot be read", async () => {
    const zip = await buildSupportBundleZip(
      {
        ...base,
        loadRawNames: async () => {
          throw new Error("EIO");
        },
      },
      req,
    );
    expect(allText(zip)).not.toContain("WS-FAKE09");
    expect(summaryOf(zip).withheldCases).toBe(1);
  });
});
