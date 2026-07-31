import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// The dashboard is a single hand-written HTML file with inline JS and no DOM harness here (see
// dashboardCustodySection.test.ts), so this asserts the wiring the anonymizer modal's Presidio
// notice depends on — and, more importantly, the two ways the notice could LIE to an analyst:
// a "Real names" row that saves like a real category, or a local detector greyed out as if it
// needed Presidio.

let html: string;
let modal: string;

beforeAll(async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  html = await readFile(join(here, "..", "..", "..", "public", "dashboard.html"), "utf8");
  modal = html.slice(html.indexOf("function renderPresidioCategory()"), html.indexOf("function saveAnon("));
});

describe("anonymizer modal — Presidio availability notice", () => {
  it("has a note element under the category grid and fills it from the modal", () => {
    expect(html).toContain('id="anonPresidioNote"');
    expect(modal).toContain('document.getElementById("anonPresidioNote").innerHTML');
  });

  it("renders the notice when the modal opens", () => {
    expect(html).toContain("renderPresidioCategory();");
  });

  it("drives the notice off the server's presidioConfigured flag, not a client guess", () => {
    expect(modal).toContain("anonControl.presidioConfigured");
  });

  it("names Presidio and points at the setting when it is absent", () => {
    expect(modal).toContain("Presidio is not configured");
    expect(modal).toContain("DFIR_PRESIDIO_URL");
  });

  it("shows Real names as a disabled STATUS row, so saveAnon can never persist it as a category", () => {
    // PERSON has no entry in AnonControl.categories — the server would drop it, and a checkbox
    // that silently does nothing is worse than no checkbox. The row must be disabled and must not
    // carry the anon-cb class that saveAnon() reads back.
    const row = modal.slice(modal.indexOf("insertAdjacentHTML"), modal.indexOf("anonPresidioNote"));
    expect(row).toContain("Real names (people)");
    expect(row).toContain("disabled");
    expect(row).not.toContain("anon-cb");
  });

  it("greys out ONLY the Presidio-only row — the local detectors stay togglable", () => {
    // Cards, phones and national IDs have local detectors (Luhn + issuer prefix, E.164/IL/NANP,
    // checksummed ID) that run with Presidio off. Greying them would tell the analyst those values
    // reach the model unmasked when they do not.
    const list = html.slice(
      html.indexOf("const ANON_CATEGORIES = ["),
      html.indexOf("const ANON_ENTITY_CATEGORIES"),
    );
    for (const cat of ["CARD", "PHONE", "NATID", "EMAIL"]) expect(list).toContain(`"${cat}"`);
    expect(list).not.toContain("PERSON");
  });
});
