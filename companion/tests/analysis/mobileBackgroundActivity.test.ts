import { describe, expect, it } from "vitest";
import {
  markAppCorroboration,
  APP_CORROBORATION_MARKER,
} from "../../src/analysis/mobileBackgroundActivity.js";
import { markInfectionWindow } from "../../src/analysis/mobileInfectionWindow.js";
import { registryEntry } from "../../src/analysis/mobileOriginRegistry.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #932 item 16: an app named by two or more independent iOS artifacts (usage, power, permission,
// network, notification) gets one note on its group's primary row, saying which OTHER kinds also
// name it. Presence only, never a magnitude; the note never concludes anything.

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();

/** One imported row of a registered iOS artifact, with the given header→value cells. */
function leappRow(
  artifactName: string,
  device: string | undefined,
  values: Record<string, string>,
  id: string,
): ForensicEvent {
  const entry = registryEntry(artifactName)!;
  const cells = entry.headers.map((h) => values[h] ?? "");
  const events = parseLeappTsv([entry.headers.join("\t"), cells.join("\t")].join("\n"), `${entry.name}.tsv`, {
    platform: "ios",
    device,
  }).events;
  return {
    ...(events[0] as ForensicEvent),
    id,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

const powerRow = (device: string, id: string, ts = T) =>
  leappRow(
    "PowerLog - Application Runtime",
    device,
    { Timestamp: ts, "Bundle ID": "com.example.app", "Background Time (seconds)": "9999" },
    id,
  );
const usageRow = (device: string, id: string, ts = T) =>
  leappRow(
    "knowledgeC - App Usage",
    device,
    { "Start Time": ts, "End Time": ts, "Time Added": ts, Application: "com.example.app" },
    id,
  );
const networkRow = (device: string, id: string, ts = T) =>
  leappRow("App Data", device, { "Live Usage Timestamp": ts, "Bundle Name": "com.example.app" }, id);
const permissionRow = (device: string, id: string, ts = T, access = "Allowed") =>
  leappRow(
    "Application Permissions",
    device,
    { "Last Modified Timestamp": ts, "Bundle ID": "com.example.app", Service: "Camera", Access: access },
    id,
  );
const notificationRow = (device: string, id: string, ts = T) =>
  leappRow("Notification Duet", device, { "SEGB Timestamp": ts, "Bundle ID": "com.example.app" }, id);

describe("markAppCorroboration", () => {
  it("one artifact alone is not corroborated", () => {
    const out = markAppCorroboration([powerRow("Ana's iPhone", "p1")]);
    expect(out[0].description).not.toContain(APP_CORROBORATION_MARKER);
  });

  it("two kinds corroborate: the note lands on the power row and names the other kind, with the power/usage guardrail", () => {
    const rows = [powerRow("Ana's iPhone", "p1"), permissionRow("Ana's iPhone", "perm1")];
    const out = markAppCorroboration(rows);
    const p = out.find((e) => e.id === "p1")!;
    expect(p.description).toContain(`${APP_CORROBORATION_MARKER} com.example.app on Ana's iPhone`);
    expect(p.description).toContain("permission record (Access: Allowed)");
    expect(p.description).toContain("energy or usage presence does not establish which function ran");
    expect(p.description).not.toContain("a notification is a message received");
    // The corroborating row itself carries no note.
    expect(out.find((e) => e.id === "perm1")!.description).not.toContain(APP_CORROBORATION_MARKER);
  });

  it("precedence power > usage > network > permission > notification always finds a primary", () => {
    // power+usage -> power primary
    expect(
      markAppCorroboration([powerRow("D", "a"), usageRow("D", "b")]).find((e) => e.id === "a")!.description,
    ).toContain(APP_CORROBORATION_MARKER);
    // usage+network -> usage primary (no power present)
    const un = markAppCorroboration([usageRow("D", "a"), networkRow("D", "b")]);
    expect(un.find((e) => e.id === "a")!.description).toContain(APP_CORROBORATION_MARKER);
    expect(un.find((e) => e.id === "b")!.description).not.toContain(APP_CORROBORATION_MARKER);
    // network+permission -> network primary
    const np = markAppCorroboration([networkRow("D", "a"), permissionRow("D", "b")]);
    expect(np.find((e) => e.id === "a")!.description).toContain(APP_CORROBORATION_MARKER);
    // permission+notification -> permission primary (the partial-collection case with no
    // PowerLog/netusage/knowledgeC — the group must still get a note).
    const pn = markAppCorroboration([permissionRow("D", "a"), notificationRow("D", "b")]);
    const primary = pn.find((e) => e.id === "a")!;
    expect(primary.description).toContain(APP_CORROBORATION_MARKER);
    expect(primary.description).toContain("notification record");
    expect(primary.description).toContain("a notification is a message received, not read");
  });

  it("within the chosen primary kind, the earliest row wins", () => {
    const later = powerRow("D", "later", at(2));
    const earlier = powerRow("D", "earlier", at(1));
    const out = markAppCorroboration([later, earlier, usageRow("D", "u")]);
    expect(out.find((e) => e.id === "earlier")!.description).toContain(APP_CORROBORATION_MARKER);
    expect(out.find((e) => e.id === "later")!.description).not.toContain(APP_CORROBORATION_MARKER);
  });

  it("a group with no subject device is never corroborated", () => {
    const out = markAppCorroboration([powerRow("", "p1"), usageRow("", "u1")]);
    expect(out.every((e) => !e.description.includes(APP_CORROBORATION_MARKER))).toBe(true);
  });

  it("two devices sharing the same app never corroborate together", () => {
    const out = markAppCorroboration([powerRow("Device A", "pA"), usageRow("Device B", "uB")]);
    expect(out.every((e) => !e.description.includes(APP_CORROBORATION_MARKER))).toBe(true);
  });

  it("idempotent: recomputing twice does not duplicate the note, and it is stripped/rebuilt cleanly", () => {
    const rows = [powerRow("D", "p1"), permissionRow("D", "perm1")];
    const once = markAppCorroboration(rows);
    const twice = markAppCorroboration(once);
    const thrice = markAppCorroboration(twice);
    expect(thrice.find((e) => e.id === "p1")!.description).toBe(
      twice.find((e) => e.id === "p1")!.description,
    );
    for (const e of thrice)
      expect(e.description.split(APP_CORROBORATION_MARKER).length).toBeLessThanOrEqual(2);
  });

  it("removing a corroborating row on the next merge drops its kind from the note", () => {
    const withThree = [powerRow("D", "p1"), permissionRow("D", "perm1"), notificationRow("D", "notif1")];
    const marked = markAppCorroboration(withThree);
    const noteWithBoth = marked.find((e) => e.id === "p1")!.description;
    expect(noteWithBoth).toContain("permission record");
    expect(noteWithBoth).toContain("notification record");
    // The notification row is gone on the next merge (e.g. filtered by minSeverity elsewhere).
    const remaining = marked.filter((e) => e.id !== "notif1");
    const recomputed = markAppCorroboration(remaining);
    const noteAfter = recomputed.find((e) => e.id === "p1")!.description;
    expect(noteAfter).toContain("permission record");
    expect(noteAfter).not.toContain("notification record");
  });

  it("falling to one kind on the next merge removes the note entirely", () => {
    const marked = markAppCorroboration([powerRow("D", "p1"), permissionRow("D", "perm1")]);
    const recomputed = markAppCorroboration(marked.filter((e) => e.id !== "perm1"));
    expect(recomputed.find((e) => e.id === "p1")!.description).not.toContain(APP_CORROBORATION_MARKER);
  });

  it("coexists with the infection window's own note: neither pass strips the other's", () => {
    const rows = [powerRow("D", "p1"), permissionRow("D", "perm1")];
    const withCorroboration = markAppCorroboration(rows);
    const withBoth = markInfectionWindow(withCorroboration, [], at(1));
    expect(withBoth.find((e) => e.id === "p1")!.description).toContain(APP_CORROBORATION_MARKER);
    // Re-run app-corroboration on top; the infection-window note (absent here, no IOC given) and
    // structure both survive a second pass untouched.
    const again = markAppCorroboration(withBoth);
    expect(again.find((e) => e.id === "p1")!.description).toContain(APP_CORROBORATION_MARKER);
  });

  it("a Notification Duet row from before the app field existed contributes no notification kind, without erroring", () => {
    const staleNotification = notificationRow("D", "notif1");
    // Simulate a pre-#932-item-16 stored block: no app identity on the row at all.
    const stale: ForensicEvent = {
      ...staleNotification,
      canonical: {
        ...staleNotification.canonical!,
        mobile: { ...staleNotification.canonical!.mobile!, app: undefined },
      },
    };
    const out = markAppCorroboration([powerRow("D", "p1"), stale]);
    expect(out.find((e) => e.id === "p1")!.description).not.toContain(APP_CORROBORATION_MARKER);
  });

  it("an app no longer installed (historical traces only) correlates the same as any other app — no stronger 'removed' claim is made", () => {
    // No iOS app-inventory registry entry exists yet (#932 item 16's deferred half), so this pass
    // cannot know the app was removed; it must not imply removal either.
    const out = markAppCorroboration([powerRow("D", "p1"), permissionRow("D", "perm1")]);
    const note = out.find((e) => e.id === "p1")!.description;
    expect(note).not.toMatch(/remov|uninstall|no longer installed/i);
  });

  it("network kind gets its own attribution guardrail, symmetric with power/usage and notification", () => {
    const out = markAppCorroboration([usageRow("D", "u1"), networkRow("D", "n1")]);
    const note = out.find((e) => e.id === "u1")!.description;
    expect(note).toContain("a network record is this app's own logged usage, not traffic attributed to it");
  });

  it("when permission IS the primary kind, its own Access value is on that row's origin tag, not repeated in the note", () => {
    const out = markAppCorroboration([
      permissionRow("D", "perm1", T, "Not allowed"),
      notificationRow("D", "n1"),
    ]);
    const primary = out.find((e) => e.id === "perm1")!;
    // The row's own origin tag (from mobileOriginRegistry.ts) already carries the Access value.
    expect(primary.description).toContain("access Not allowed");
    // The corroboration note names only the OTHER kind, never repeats "permission" or its Access.
    const note = primary.description.slice(primary.description.indexOf(APP_CORROBORATION_MARKER));
    expect(note).toBe(
      `${APP_CORROBORATION_MARKER} com.example.app on D also appears in: notification record — a notification is a message received, not read]`,
    );
    expect(note).not.toContain("permission");
    expect(note).not.toContain("Allowed");
  });

  it("an app identity or device name containing a bracket stays idempotent across repeated recompute", () => {
    // A bracket in the analyst-supplied device name.
    const rows = [permissionRow("D]evice", "perm1"), powerRow("D]evice", "p1")];
    const once = markAppCorroboration(rows);
    const twice = markAppCorroboration(once);
    const thrice = markAppCorroboration(twice);
    expect(thrice.find((e) => e.id === "p1")!.description).toBe(
      twice.find((e) => e.id === "p1")!.description,
    );
    for (const e of thrice)
      expect(e.description.split(APP_CORROBORATION_MARKER).length).toBeLessThanOrEqual(2);
  });
});
