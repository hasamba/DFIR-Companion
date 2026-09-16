import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderEvidenceAttestations(): string;
  loadEvidenceAttestations(caseId: string): Promise<void>;
}

// renderEvidenceAttestations() reads the module's OWN private `attestations` state, populated by
// loadEvidenceAttestations() — there is no seam to seed it directly, so every render test goes
// through the real load path with a stubbed fetch, exactly like the runtime does.
async function panel(attestations: unknown[]): Promise<Api> {
  const p = loadDashboardModule<Api>("dashboard-evidence-attestation.js", ["dashboard-escape.js"], {
    fetch: async () => ({ ok: true, status: 200, json: async () => ({ attestations }) }),
    document: { getElementById: () => null }, // paint() no-ops without the panel element
  });
  await p.loadEvidenceAttestations("c1");
  return p;
}

function attestation(over: Record<string, unknown> = {}) {
  return {
    evidenceClass: "execution",
    confirmedBy: "a.analyst@example.invalid",
    confirmedAt: "2026-08-13T09:41:00Z",
    reason: "Reviewed the full Prefetch and Sysmon export against the window",
    ...over,
  };
}

describe("evidence attestation panel", () => {
  it("shows all four classes as not-attested with nothing recorded", async () => {
    const html = (await panel([])).renderEvidenceAttestations();
    expect(html).toContain("Execution");
    expect(html).toContain("File activity");
    expect(html).toContain("Network");
    expect(html).toContain("Persistence");
    expect((html.match(/Not attested/g) || []).length).toBe(4);
  });

  it("shows an active attestation with who/when/why", async () => {
    const html = (await panel([attestation()])).renderEvidenceAttestations();
    expect(html).toContain("Attested by a.analyst@example.invalid");
    expect(html).toContain("2026-08-13");
    expect(html).toContain("Reviewed the full Prefetch and Sysmon export against the window");
    expect(html).toContain('data-ea-action="revoke"');
  });

  it("treats a revoked attestation as not-attested again", async () => {
    const html = (
      await panel([
        attestation({ revokedBy: "b.reviewer@example.invalid", revokedAt: "2026-08-15T00:00:00Z" }),
      ])
    ).renderEvidenceAttestations();
    expect(html).toContain("Not attested");
    expect(html).toContain('data-ea-action="attest"');
    expect(html).not.toContain("Attested by");
  });

  it("only the LATEST entry for a class matters, matching evidenceAttestationStore.ts's own rule", async () => {
    const html = (
      await panel([
        attestation({ reason: "first pass" }),
        attestation({ reason: "second pass", confirmedAt: "2026-08-14T00:00:00Z" }),
      ])
    ).renderEvidenceAttestations();
    expect(html).toContain("second pass");
    expect(html).not.toContain("first pass");
  });

  it("re-attesting after a revoke shows the class as active again", async () => {
    const html = (
      await panel([
        attestation({ revokedBy: "b.reviewer@example.invalid", revokedAt: "2026-08-15T00:00:00Z" }),
        attestation({ reason: "re-reviewed", confirmedAt: "2026-08-16T00:00:00Z" }),
      ])
    ).renderEvidenceAttestations();
    expect(html).toContain("re-reviewed");
    expect(html).toContain('<div class="ea-row ea-active" data-ea-class="execution">');
  });

  it("escapes a hostile reason", async () => {
    const html = (
      await panel([attestation({ reason: "<img src=x onerror=alert(1)>" })])
    ).renderEvidenceAttestations();
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("uses data attributes rather than inline handlers, which the CSP forbids", async () => {
    const html = (await panel([])).renderEvidenceAttestations();
    expect(html).not.toMatch(/\son(click|change|load)=/i);
  });
});

// The write path: attest/revoke surface the server's own error, matching decideHostScope's
// convention exactly (a rejected write must not look like it silently succeeded).
interface WriteApi {
  attestEvidenceClass(caseId: string, cls: string, reason: string): Promise<void>;
  revokeEvidenceClass(caseId: string, cls: string): Promise<void>;
}

function panelWithFetch(fetchStub: unknown) {
  return loadDashboardModule<WriteApi>("dashboard-evidence-attestation.js", ["dashboard-escape.js"], {
    fetch: fetchStub,
    document: { getElementById: () => null },
  });
}

describe("recording an evidence attestation", () => {
  it("throws the server's own error when the attestation is rejected", async () => {
    const p = panelWithFetch(async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: "a reason is required" }),
    }));
    await expect(p.attestEvidenceClass("c1", "execution", "")).rejects.toThrow("a reason is required");
  });

  it("falls back to the HTTP status when the error body is unreadable", async () => {
    const p = panelWithFetch(async () => ({
      ok: false,
      status: 502,
      json: async () => {
        throw new Error("not json");
      },
    }));
    await expect(p.revokeEvidenceClass("c1", "execution")).rejects.toThrow("HTTP 502");
  });

  it("resolves when the attestation lands", async () => {
    const p = panelWithFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ attestations: [] }),
    }));
    await expect(p.attestEvidenceClass("c1", "execution", "reviewed")).resolves.toBeUndefined();
  });
});
