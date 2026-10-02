import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { playbookSection } from "../../src/reports/playbookSection.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";
import type { ContainmentAttribution } from "../../src/analysis/playbookContainment.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// #1925: a Playbook task suggested by the Jev containment check says so in the report — which
// finding, which model, which rule, and the answers the step rests on.

function task(over: Partial<PlaybookTask>): PlaybookTask {
  return {
    id: "custom:1",
    shortId: "T001",
    title: "Contain host",
    description: "",
    status: "todo",
    priority: "high",
    source: "custom",
    order: 0,
    createdAt: "2026-10-02T00:00:00Z",
    updatedAt: "2026-10-02T00:00:00Z",
    ...over,
  };
}

function attribution(over: Partial<ContainmentAttribution> = {}): ContainmentAttribution {
  return {
    kind: "jev-containment",
    rule: "containment-v1",
    model: "typesafe/jev-1.13",
    checkedAt: "2026-10-02T10:00:00.000Z",
    findingId: "F3",
    stepId: "block-destination-org",
    basis: ["attacker_traffic", "reach"],
    answers: [
      {
        id: "attacker_traffic",
        label: "data/command traffic to attacker destination",
        kind: "yesno",
        value: 0.91,
        verdict: "yes",
        checkManually: false,
      },
      {
        id: "reach",
        label: "reach",
        kind: "choice",
        value: 0.72,
        verdict: "whole organization",
        checkManually: true,
      },
    ],
    inProgressCaveat: false,
    ...over,
  };
}

function render(tasks: PlaybookTask[]): string {
  const lines: string[] = [];
  playbookSection(tasks, lines);
  return lines.join("\n");
}

const PLAIN_EXPECTED = [
  "## Response Playbook",
  "",
  "_Actionable remediation/investigation checklist derived from the recommended next steps and high-severity findings, tracked by the analyst. **0/1 complete (0%)**._",
  "",
  "| # | Status | Priority | Task | Assignee | Due | Notes |",
  "| --- | --- | --- | --- | --- | --- | --- |",
  "| 1 | To do | HIGH | Contain host | — | — | — |",
  "",
].join("\n");

describe("playbookSection", () => {
  it("renders plain tasks exactly as before", () => {
    expect(render([task({})])).toBe(PLAIN_EXPECTED);
  });

  it("adds an attribution bullet for a containment-check task", () => {
    const md = render([task({ title: "Block the destination org-wide", containmentCheck: attribution() })]);
    expect(md).toContain("**Containment-check attribution**");
    expect(md).toContain(
      "- #1 (T001) — suggested by the Jev containment check of finding F3 (model typesafe/jev-1.13, 2026-10-02, rule containment-v1): " +
        "data/command traffic to attacker destination: yes (0.91); reach: whole organization (confidence 0.72).",
    );
    expect(md).not.toContain("check manually");
    expect(md).not.toContain("end of the collected evidence");
  });

  it("only cites the answers in the step's basis", () => {
    const md = render([task({ containmentCheck: attribution({ basis: ["reach"] }) })]);
    expect(md).not.toContain("data/command traffic");
    expect(md).toContain("reach: whole organization");
  });

  it("explains 'in progress' when the caveat is set", () => {
    const md = render([task({ containmentCheck: attribution({ inProgressCaveat: true }) })]);
    expect(md).toContain("end of the collected evidence");
  });

  it("escapes odd model and label text", () => {
    const md = render([
      task({
        containmentCheck: attribution({
          model: "evil|model\n## Forged",
          answers: [
            {
              id: "reach",
              label: "re|ach &lt;img onerror&gt;",
              kind: "choice",
              value: 0.5,
              verdict: "one\nentity",
              checkManually: true,
            },
          ],
          basis: ["reach"],
        }),
      }),
    ]);
    expect(md).toContain("evil\\|model ## Forged");
    expect(md).not.toMatch(/^## Forged/m);
    expect(md).toContain("re\\|ach");
    expect(md).toContain("one entity");
  });

  it("the attribution reaches the markdown and HTML reports", () => {
    const tasks = [task({ containmentCheck: attribution() })];
    const md = renderMarkdownReport(emptyState("c1"), undefined, undefined, undefined, undefined, tasks);
    expect(md).toContain("**Containment-check attribution**");
    expect(md).toContain("suggested by the Jev containment check of finding F3");
    const html = renderHtmlReport(emptyState("c1"), undefined, undefined, undefined, undefined, tasks);
    expect(html).toContain("Containment-check attribution");
    expect(html).toContain("suggested by the Jev containment check of finding F3");
  });

  it("an HTML-looking model string stays inert in the HTML report", () => {
    const evil = "x" + String.fromCharCode(60) + "img src=x onerror=alert(1)" + String.fromCharCode(62);
    const html = renderHtmlReport(emptyState("c1"), undefined, undefined, undefined, undefined, [
      task({ containmentCheck: attribution({ model: evil }) }),
    ]);
    expect(html).not.toContain(String.fromCharCode(60) + "img src=x");
  });
});
