import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The Threat Hunt panel's coverage line names the partial artifacts whose items rarity skips
// (#2732): a partial artifact no longer switches rarity off for the whole case, so the analyst is
// told exactly which artifacts were not graded. A minimal fake DOM: the panel writes textContent only.

interface FakeNode {
  tag: string;
  textContent: string;
  className: string;
  children: FakeNode[];
  type?: string;
  appendChild(n: FakeNode): FakeNode;
  replaceChildren(): void;
  addEventListener(): void;
}

function node(tag: string): FakeNode {
  return {
    tag,
    textContent: "",
    className: "",
    children: [],
    appendChild(n) {
      this.children.push(n);
      return n;
    },
    replaceChildren() {
      this.children = [];
    },
    addEventListener() {},
  };
}

async function coverageLine(coverage: Record<string, unknown>): Promise<string> {
  const box = node("div");
  const status = { hunt: true, coverage, items: [] };
  const api = loadDashboardModule<{ loadHuntCase: (id: string) => Promise<void> }>(
    "dashboard-hunt-case.js",
    [],
    {
      document: { getElementById: () => box, createElement: node },
      fetch: async () => ({ ok: true, status: 200, json: async () => status }),
    },
  );
  await api.loadHuntCase("c1");
  return box.children.map((c) => c.textContent).find((t) => t.startsWith("Coverage:")) ?? "";
}

const known = {
  known: true,
  answered: 30,
  targeted: 30,
  notAnswered: 0,
  huntsWithCoverage: 1,
  huntsWithoutCoverage: 0,
  answeredHosts: [],
};

describe("the Threat Hunt panel coverage line (#2732)", () => {
  it("names the partial artifacts that rarity does not grade", async () => {
    const line = await coverageLine({
      ...known,
      partialArtifacts: 2,
      partialArtifactNames: ["Windows.Forensics.Amcache", "Windows.System.TaskScheduler"],
    });
    expect(line).toBe(
      "Coverage: 30 host(s) of 30 targeted answered cleanly; 2 partial artifact collection(s) (rarity not graded for the kinds of item they report: Windows.Forensics.Amcache, Windows.System.TaskScheduler).",
    );
  });

  it("says nothing extra when every artifact was read in full", async () => {
    const line = await coverageLine({ ...known, partialArtifacts: 0, partialArtifactNames: [] });
    expect(line).toBe("Coverage: 30 host(s) of 30 targeted answered cleanly.");
  });
});
