import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import type { DashboardGlobals } from "../helpers/dashboardModule.js";

// #672. An analyst importing a .dfircase written by 0.31.0-0.33.0 used to get no signal that the
// archive was encrypted under the weaker v1 key derivation. The import response now carries both
// the archive's version and the version this build writes, and this function turns that pair into
// the sentence the analyst reads.
//
// It is a pure function on purpose. The rest of the module is DOM wiring that only exists after
// initImportCase() has run against fifteen elements; the DECISION — warn or stay quiet — is the
// part worth pinning, and pinning it needs no DOM at all.
interface ImportCaseApi {
  encryptionUpgradeNotice(formatVersion: unknown, currentFormatVersion: unknown): string;
  importProvenanceNote(provenance: unknown, importedCaseId: unknown): string;
}

const { encryptionUpgradeNotice, importProvenanceNote } =
  loadDashboardModule<ImportCaseApi>("dashboard-import-case.js");

describe("encryptionUpgradeNotice", () => {
  it("warns when the archive is older than the version this build writes", () => {
    const notice = encryptionUpgradeNotice(1, 2);
    expect(notice).toMatch(/weaker key derivation/i);
    // It must say what to DO, not only what is wrong — re-exporting is the only thing that
    // upgrades a file the analyst already holds.
    expect(notice).toMatch(/export the case again/i);
  });

  it("says nothing when the archive is already current", () => {
    expect(encryptionUpgradeNotice(2, 2)).toBe("");
  });

  // A version ABOVE the current one cannot reach here — the server refuses to decrypt a container
  // written by a newer build — but if it ever did, "your encryption is weak" would be exactly
  // backwards. Staying silent is the only safe answer for a comparison this function cannot make.
  it("says nothing when the archive is newer than this build writes", () => {
    expect(encryptionUpgradeNotice(3, 2)).toBe("");
  });

  // Absent fields mean an older companion answered, not a weak archive. Guessing "weak" from a
  // missing field would put a security warning on every import from such a server.
  it("says nothing when either version is missing", () => {
    expect(encryptionUpgradeNotice(undefined, 2)).toBe("");
    expect(encryptionUpgradeNotice(1, undefined)).toBe("");
    expect(encryptionUpgradeNotice(undefined, undefined)).toBe("");
  });

  it("says nothing when either version is not a number", () => {
    expect(encryptionUpgradeNotice("1", 2)).toBe("");
    expect(encryptionUpgradeNotice(null, 2)).toBe("");
  });
});

// The warning has to SURVIVE, not merely be written. The first version of this feature appended it
// to the shared #status element and then called connect(), whose WebSocket onopen handler in
// js/dashboard-case-connect.js overwrites #status with "connected (live)" milliseconds later — so
// the sentence the whole change exists to deliver flashed and vanished, and every unit test still
// passed because they only checked the string.
//
// These drive the real click handler against a stub document, which is the only level at which
// "does the analyst actually end up looking at it" can be asked.

interface StubEl {
  id: string;
  textContent: string;
  value: string;
  disabled: boolean;
  hidden: boolean;
  files: unknown[];
  classes: Set<string>;
  classList: { add(c: string): void; remove(c: string): void; contains(c: string): boolean };
  onclick: ((e?: unknown) => unknown) | null;
  onchange: ((e?: unknown) => unknown) | null;
  addEventListener(type: string, fn: (e?: unknown) => unknown): void;
  focus(): void;
  click(): void;
}

function stubEl(id: string): StubEl {
  const classes = new Set<string>();
  return {
    id,
    textContent: "",
    value: "",
    disabled: false,
    hidden: false,
    files: [],
    classes,
    classList: {
      add: (c) => void classes.add(c),
      remove: (c) => void classes.delete(c),
      contains: (c) => classes.has(c),
    },
    onclick: null,
    onchange: null,
    addEventListener: () => {},
    focus: () => {},
    click: () => {},
  };
}

const EL_IDS = [
  "importCaseOverlay",
  "importCaseBtn",
  "importCaseCancel",
  "importCaseEncrypted",
  "importCaseIris",
  "importCaseHint",
  "encryptedImportFile",
  "importPasswordOverlay",
  "ipFilename",
  "ipPassword",
  "ipMsg",
  "ipImport",
  "ipCancel",
  "status",
  "caseId",
];

/** Run one full import through the real handler and hand back the DOM it left behind. */
async function runImport(responseBody: Record<string, unknown>) {
  const els = new Map(EL_IDS.map((id) => [id, stubEl(id)]));
  let connected = 0;
  const globals: DashboardGlobals = {
    document: { getElementById: (id: string) => els.get(id) ?? null },
    fetch: async () => ({ status: 201, json: async () => responseBody }),
    arrayBufferToBase64: () => "AAAA",
    loadCaseList: () => {},
    connect: () => {
      connected++;
      // What js/dashboard-case-connect.js really does on ws.onopen. If the warning lives in
      // #status, this is the line that destroys it.
      els.get("status")!.textContent = "connected (live)";
    },
    openIrisImportModal: () => {},
  };

  const mod = loadDashboardModule<{ initImportCase(): void }>("dashboard-import-case.js", [], globals);
  mod.initImportCase();

  // Pick a file, then press Import — the two steps the analyst takes.
  els.get("encryptedImportFile")!.onchange!({
    target: {
      files: [{ name: "case.dfircase", size: 1024, arrayBuffer: async () => new ArrayBuffer(8) }],
      value: "",
    },
  });
  els.get("ipPassword")!.value = "correct horse battery staple"; // the handler refuses an empty one
  await els.get("ipImport")!.onclick!();

  return { els, connected };
}

// #904: the archive names the case it was exported from. That id is only worth a sentence when the
// import RENAMED the case — which is exactly when the package's embedded ids go stale, and the
// analyst has to know the case they are now looking at is not the case the archive described.
describe("importProvenanceNote", () => {
  it("names the source case when the import renamed it", () => {
    const note = importProvenanceNote({ sourceCaseId: "INC-1" }, "INC-2");
    expect(note).toContain("INC-1");
    // Both ids, because the useful fact is the DISAGREEMENT between them: the case is INC-2 now,
    // and parts of the package it was built from still say INC-1.
    expect(note).toContain("INC-2");
  });

  it("says nothing when the case kept the id the archive gave it", () => {
    expect(importProvenanceNote({ sourceCaseId: "INC-1" }, "INC-1")).toBe("");
  });

  // No manifest means an archive written before provenance travelled with it, not a suspicious
  // one. An older companion answering with no field at all reaches here the same way.
  it("says nothing when the archive carried no provenance", () => {
    expect(importProvenanceNote(null, "INC-2")).toBe("");
    expect(importProvenanceNote(undefined, "INC-2")).toBe("");
    expect(importProvenanceNote({}, "INC-2")).toBe("");
  });

  it("says nothing when the source id is not a string", () => {
    expect(importProvenanceNote({ sourceCaseId: 7 }, "INC-2")).toBe("");
    expect(importProvenanceNote({ sourceCaseId: "" }, "INC-2")).toBe("");
  });
});

// #904, and the same trap #672 fell into. The provenance note first went to `#status`, which
// connect() overwrites with "connected (live)" milliseconds later — the disclosure was gone before
// it could be read. It belongs where the weak-encryption warning already lives.
describe("a renamed import's source case survives the reconnect", () => {
  it("keeps the source-case note where the automatic reconnect cannot overwrite it", async () => {
    const { els, connected } = await runImport({
      caseId: "INC-2",
      counts: {},
      formatVersion: 2,
      currentFormatVersion: 2,
      provenance: { sourceCaseId: "INC-1" },
    });

    expect(connected).toBe(1);
    expect(els.get("status")!.textContent).toBe("connected (live)"); // #status really is clobbered
    expect(els.get("ipMsg")!.textContent).toContain("INC-1");
    expect(els.get("importPasswordOverlay")!.classList.contains("open")).toBe(true);
  });

  it("leaves only a way out once the note is showing", async () => {
    const { els } = await runImport({
      caseId: "INC-2",
      counts: {},
      formatVersion: 2,
      currentFormatVersion: 2,
      provenance: { sourceCaseId: "INC-1" },
    });

    expect(els.get("ipImport")!.hidden).toBe(true);
    expect(els.get("ipCancel")!.textContent).toBe("Close");
  });

  it("closes the modal as before when the case kept the id the archive gave it", async () => {
    const { els } = await runImport({
      caseId: "INC-1",
      counts: {},
      formatVersion: 2,
      currentFormatVersion: 2,
      provenance: { sourceCaseId: "INC-1" },
    });

    expect(els.get("importPasswordOverlay")!.classList.contains("open")).toBe(false);
    expect(els.get("ipMsg")!.textContent).toBe("");
  });

  // A weak archive imported under a new id raises both. Neither may swallow the other — they are
  // separate facts about the package, and the analyst needs both.
  it("shows the weak-encryption warning and the source case together", async () => {
    const { els } = await runImport({
      caseId: "INC-2",
      counts: {},
      formatVersion: 1,
      currentFormatVersion: 2,
      provenance: { sourceCaseId: "INC-1" },
    });

    expect(els.get("ipMsg")!.textContent).toMatch(/weaker key derivation/i);
    expect(els.get("ipMsg")!.textContent).toContain("INC-1");
  });
});

describe("a weak-encryption warning survives the import that raised it", () => {
  it("keeps the warning where the automatic reconnect cannot overwrite it", async () => {
    const { els, connected } = await runImport({
      caseId: "INC-2",
      counts: {},
      formatVersion: 1,
      currentFormatVersion: 2,
    });

    expect(connected).toBe(1); // the case really did load
    expect(els.get("status")!.textContent).toBe("connected (live)"); // and really did clobber #status
    expect(els.get("ipMsg")!.textContent).toMatch(/weaker key derivation/i);
    expect(els.get("importPasswordOverlay")!.classList.contains("open")).toBe(true);
  });

  it("closes the modal as before when the archive is already current", async () => {
    const { els } = await runImport({
      caseId: "INC-2",
      counts: {},
      formatVersion: 2,
      currentFormatVersion: 2,
    });

    expect(els.get("importPasswordOverlay")!.classList.contains("open")).toBe(false);
    expect(els.get("ipMsg")!.textContent).toBe("");
  });

  // The Import button must not invite a second run against the file that was just consumed —
  // pressing it would report "no file selected" into ipMsg and wipe the warning off the screen.
  it("leaves only a way out once the warning is showing", async () => {
    const { els } = await runImport({
      caseId: "INC-2",
      counts: {},
      formatVersion: 1,
      currentFormatVersion: 2,
    });

    expect(els.get("ipImport")!.hidden).toBe(true);
    expect(els.get("ipCancel")!.disabled).toBe(false);
    // "Cancel" would read as "undo the import", which is not on offer — the case is already on
    // disk and the archive is already open. The only thing left to do is close the warning.
    expect(els.get("ipCancel")!.textContent).toBe("Close");
  });
});
