import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// Lateral Movement Paths. Five hosts that all ran the same installers gave a dozen chains that
// differed only in the order of the hosts, and Highlight dimmed nothing because every chain
// covered every host. The panel now shows one row per host SET and shared file, and Highlight
// numbers the hops, draws them as arrows, says when a chain covers every host, and scrolls to the
// graph.

interface Hop {
  actor: string;
  actorKind: "binary" | "account";
}
interface Path {
  hostIds: string[];
  hops: Hop[];
}
interface SharedLink {
  actor: string;
  actorKind: "binary" | "account";
  hosts: string[];
  firstSeen: string;
}
interface Api {
  lateralPathGroups(paths: Path[]): Array<{ key: string; members: number[]; rep: number }>;
  sharedHostLinksHtml(links: SharedLink[] | undefined): string;
}

const api = () =>
  loadDashboardModule<Api>("dashboard-evidence-graph.js", ["dashboard-escape.js"], {
    fetch: () => new Promise(() => {}),
    document: { getElementById: () => null, querySelectorAll: () => [], querySelector: () => null },
    DfirTimelineView: { timeQuery: () => "" },
  });

const HOSTS = ["host:a", "host:b", "host:c", "host:d", "host:e"];
const order = (ids: number[]) => ids.map((i) => HOSTS[i]);
const via = (...files: string[]): Hop[] => files.map((actor) => ({ actor, actorKind: "binary" }));
const account = (actor: string): Hop => ({ actor, actorKind: "account" });

describe("lateralPathGroups", () => {
  it("folds every ordering of the same hosts and the same shared file into one row", () => {
    const paths: Path[] = [
      { hostIds: order([0, 1, 2, 3, 4]), hops: [...via("instup.exe"), account("CORP\\alice")] },
      { hostIds: order([1, 0, 2, 3, 4]), hops: via("instup.exe") },
      { hostIds: order([4, 3, 2, 1, 0]), hops: [account("x"), ...via("INSTUP.EXE")] },
    ];
    const groups = api().lateralPathGroups(paths);
    expect(groups).toHaveLength(1);
    expect(groups[0].members).toEqual([0, 1, 2]);
    expect(groups[0].rep).toBe(0);
  });

  it("keeps rows apart when the shared file differs", () => {
    const paths: Path[] = [
      { hostIds: order([0, 1, 2]), hops: via("instup.exe") },
      { hostIds: order([0, 1, 2]), hops: via("instup.exe", "AVG_Protection_Free_1606.exe") },
    ];
    expect(api().lateralPathGroups(paths)).toHaveLength(2);
  });

  it("keeps rows apart when the host set differs", () => {
    const paths: Path[] = [
      { hostIds: order([0, 1, 2]), hops: via("instup.exe") },
      { hostIds: order([0, 1, 3]), hops: via("instup.exe") },
    ];
    expect(api().lateralPathGroups(paths)).toHaveLength(2);
  });

  it("groups a chain with no shared file by its accounts", () => {
    const paths: Path[] = [
      { hostIds: order([0, 1]), hops: [account("CORP\\alice")] },
      { hostIds: order([1, 0]), hops: [account("corp\\ALICE")] },
      { hostIds: order([0, 1]), hops: [account("CORP\\bob")] },
    ];
    expect(
      api()
        .lateralPathGroups(paths)
        .map((g) => g.members),
    ).toEqual([[0, 1], [2]]);
  });

  it("returns nothing for no paths", () => {
    expect(api().lateralPathGroups([])).toEqual([]);
  });
});

describe("Highlight and the grouped row, in the source", () => {
  const js = readFileSync(new URL("../../../public/js/dashboard-evidence-graph.js", import.meta.url), "utf8");
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

  it("draws numbered arrows, labels the start and end, and scrolls to the graph", () => {
    expect(js).toContain('classes: "ev-hop-arrow"');
    expect(js).toMatch(/hopNo: String\(i \+ 1\)/);
    expect(js).toContain('" (start)"');
    expect(js).toContain('" (end)"');
    expect(js).toMatch(/graphEl\.scrollIntoView/);
    expect(js).toMatch(/selector: "edge\.ev-hop-arrow"[\s\S]*label: "data\(hopNo\)"/);
  });

  it("clears the previous highlight before drawing the next", () => {
    expect(js).toContain('cy.remove(".ev-hop-arrow")');
    expect(js).toContain('removeClass("ev-hop-node")');
  });

  it("says so when a chain covers every host in the graph", () => {
    expect(js).toContain("This chain covers all");
    expect(js).toContain("no host is dimmed");
    expect(html).toContain('id="evPathNote"');
  });

  it("dismisses and restores every ordering a row stands for", () => {
    expect(js).toContain("data-path-idxs");
    expect(js).toMatch(/for \(const path of paths\)[\s\S]*lateral-path-dismissals/);
  });

  it("reloads and tells the analyst when some dismiss/restore requests fail", () => {
    expect(js).not.toMatch(/if \(ok\) await loadLateralPaths/);
    expect(js).toContain("chains - ${failed} failed");
    expect(js).toMatch(/showToast\(/);
  });
});

// #3085: hosts that share a binary or account are listed apart from the directed paths, and drawn
// in the graph without an arrowhead, so a shared link is never read as a move.
describe("hosts that share a binary or account", () => {
  it("lists each link's hosts and what they share, escaping every name", () => {
    const html = api().sharedHostLinksHtml([
      {
        actor: "<img src=x>.exe",
        actorKind: "binary",
        hosts: ["HOST-A", "<b>HOST-B"],
        firstSeen: "2026-05-20T09:00:00Z",
      },
      {
        actor: "CORP\\ops",
        actorKind: "account",
        hosts: ["HOST-C", "HOST-D"],
        firstSeen: "2026-05-20T10:00:00Z",
      },
    ]);
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>HOST-B");
    expect(html).toContain("&lt;img src=x&gt;.exe");
    expect(html).toContain("share file");
    expect(html).toContain("share account");
    expect(html).toContain("<b>HOST-C</b>, <b>HOST-D</b>");
  });

  it("says so when nothing is shared", () => {
    expect(api().sharedHostLinksHtml([])).toContain("No file or account seen on more than one host.");
    expect(api().sharedHostLinksHtml(undefined)).toContain("No file or account seen on more than one host.");
  });

  it("draws shared links without an arrowhead and gives them their own element id", () => {
    const js = readFileSync(
      new URL("../../../public/js/dashboard-evidence-graph.js", import.meta.url),
      "utf8",
    );
    const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(js).toMatch(/selector: "edge\[\?undirected\]",\s*style: \{ "target-arrow-shape": "none"/);
    expect(js).toContain('${e.undirected ? "|shared" : ""}');
    expect(js).toContain("renderEvidenceShared();");
    expect(html).toContain('id="evSharedList"');
  });
});
