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
let js: string;
let modal: string;

beforeAll(async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const pub = join(here, "..", "..", "..", "public");
  html = await readFile(join(pub, "dashboard.html"), "utf8");
  // The panel moved out of the inline script (#415 tier 3). Markup assertions still read the page;
  // behaviour assertions read the module.
  js = await readFile(join(pub, "js", "dashboard-presidio.js"), "utf8");
  modal = js.slice(js.indexOf("function renderPresidioCategory()"), js.indexOf("function saveAnon("));
  // Assert the slice exists BEFORE anything asserts on its contents: an empty slice makes every
  // toContain below pass vacuously, which is how a moved function goes unnoticed.
  expect(modal.length, "renderPresidioCategory()..saveAnon() slice is empty").toBeGreaterThan(200);
});

describe("anonymizer modal — Presidio availability notice", () => {
  it("has a note element under the category grid and fills it from the modal", () => {
    expect(html).toContain('id="anonPresidioNote"');
    expect(modal).toContain('document.getElementById("anonPresidioNote").innerHTML');
  });

  it("renders the notice when the modal opens", () => {
    expect(js).toContain("renderPresidioCategory();");
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
    // Reads the MODULE: ANON_CATEGORIES moved there with the rest of the anonymization state
    // (#415). This is the second slice in this file to go vacuous rather than red when code moved,
    // so it gets the same non-empty guard the modal slice has — an empty string satisfies every
    // toContain below and satisfies not.toContain too, which is the failure that hides itself.
    const list = js.slice(
      js.indexOf("const ANON_CATEGORIES = ["),
      js.indexOf("const ANON_ENTITY_CATEGORIES"),
    );
    expect(list.length, "ANON_CATEGORIES..ANON_ENTITY_CATEGORIES slice is empty").toBeGreaterThan(50);
    for (const cat of ["CARD", "PHONE", "NATID", "EMAIL"]) expect(list).toContain(`"${cat}"`);
    expect(list).not.toContain("PERSON");
  });
});
