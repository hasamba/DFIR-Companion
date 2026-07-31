import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { ReportWorkflowStore } from "../../src/reports/reportWorkflowStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const investigator = {
  id: "investigator-1",
  displayName: "Investigator One",
  kind: "local" as const,
};
const reviewer = {
  id: "reviewer-1",
  displayName: "Reviewer One",
  kind: "oidc" as const,
};

let workflows: ReportWorkflowStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-workflow-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  workflows = new ReportWorkflowStore(cases);
});

describe("ReportWorkflowStore", () => {
  it("moves a report through independent review without letting the reviewer alter evidence", async () => {
    const draft = await workflows.load("c1", "v1", investigator);
    expect(draft.status).toBe("draft");

    const inReview = await workflows.submit("c1", "v1", investigator, reviewer);
    expect(inReview.status).toBe("peer-review");
    expect(inReview.assignedReviewer).toEqual(reviewer);

    const annotated = await workflows.addAnnotation("c1", "v1", reviewer, {
      targetType: "finding",
      targetId: "f1",
      category: "uncertainty",
      impact: "high",
      message: "The conclusion needs a second evidence source.",
    });
    expect(annotated.annotations[0]).toMatchObject({
      targetId: "f1",
      impact: "high",
    });
    expect(annotated.annotations[0]).not.toHaveProperty("resolvedAt");

    await expect(workflows.approve("c1", "v1", reviewer, "checked")).rejects.toThrow(
      "unresolved high-impact",
    );
    await workflows.resolveAnnotation("c1", "v1", annotated.annotations[0].id, investigator, "linked e2");

    const approved = await workflows.approve("c1", "v1", reviewer, "evidence checked");
    expect(approved.status).toBe("approved");
    expect(approved.approvals).toEqual([
      expect.objectContaining({ actorId: reviewer.id, independent: true }),
    ]);
    expect(approved.history.map((event) => event.action)).toEqual([
      "created",
      "submitted-for-review",
      "annotation-added",
      "annotation-resolved",
      "approved",
    ]);
  });

  it("enforces separation of duties and the assigned reviewer", async () => {
    await expect(workflows.submit("c1", "v1", investigator, investigator)).rejects.toThrow(
      "different person",
    );
    await workflows.submit("c1", "v1", investigator, reviewer);

    await expect(workflows.approve("c1", "v1", investigator, "self approval")).rejects.toThrow(
      "assigned reviewer",
    );
    await expect(
      workflows.approve(
        "c1",
        "v1",
        { id: "reviewer-2", displayName: "Other Reviewer", kind: "local" },
        "approval",
      ),
    ).rejects.toThrow("assigned reviewer");
  });

  it("returns requested changes to draft while preserving reviewer annotations", async () => {
    await workflows.submit("c1", "v1", investigator, reviewer);
    await workflows.addAnnotation("c1", "v1", reviewer, {
      targetType: "evidence",
      targetId: "e1",
      category: "comment",
      impact: "medium",
      message: "Confirm the timestamp source.",
    });

    const changed = await workflows.requestChanges("c1", "v1", reviewer, "Timestamp needs checking");
    expect(changed.status).toBe("draft");
    expect(changed.annotations).toHaveLength(1);
  });

  it("records solo approval as self-review rather than independent review", async () => {
    const approved = await workflows.selfApprove("c1", "v1", investigator, "Solo case review completed");
    expect(approved.status).toBe("approved");
    expect(approved.approvals[0]).toMatchObject({
      actorId: investigator.id,
      independent: false,
      note: "Solo case review completed",
    });
  });
});
