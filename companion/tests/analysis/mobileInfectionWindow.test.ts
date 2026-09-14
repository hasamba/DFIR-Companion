import { describe, expect, it } from "vitest";
import { markInfectionWindow, INFECTION_WINDOW_MARKER } from "../../src/analysis/mobileInfectionWindow.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import { registryEntry } from "../../src/analysis/mobileOriginRegistry.js";
import { cleanDescription } from "../../src/analysis/correlate.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

// #988: the infection window opens only on a malicious app-inventory row of the SUBJECT device,
// never on content a device merely holds; notes are recomputed and a revoked assertion takes the
// window away.

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const SHA = "a".repeat(64);

function rows(device?: string): ForensicEvent[] {
  const gass = registryEntry("installedappsGass")!;
  const inventory = parseLeappTsv(
    [gass.headers.join("\t"), [`user-${SHA.slice(0, 8)}`, "com.evil.app", "7", SHA].join("\t")].join("\n"),
    `${gass.name}.tsv`,
    { platform: "android", device },
  ).events;
  const safari = registryEntry("Safari Browser - History")!;
  const history = parseLeappTsv(
    [
      safari.headers.join("\t"),
      [at(-24), "t", "https://before.example", "1", "", "", "1", "Local Device", "Default"].join("\t"),
      [at(24), "t", "https://after.example", "1", "", "", "2", "Local Device", "Default"].join("\t"),
    ].join("\n"),
    `${safari.name}.tsv`,
    { platform: "ios", device },
  ).events;
  // The inventory row has no clock column of its own: give it one for the test, as a Purchase-time
  // style inventory would; undated stays undated in the second test.
  return [
    {
      ...(inventory[0] as ForensicEvent),
      id: "inv",
      timestamp: T,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    },
    ...history.map((e, i) => ({
      ...(e as ForensicEvent),
      id: `h${i}`,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    })),
  ];
}
const ioc = (over: Partial<IOC> = {}): IOC => ({
  id: "i1",
  type: "hash",
  value: SHA,
  firstSeen: T,
  enrichments: [
    { source: "VirusTotal", verdict: "malicious", fetchedAt: T, assertionId: "a1", status: "live" },
  ],
  ...over,
});

describe("markInfectionWindow", () => {
  it("a malicious installed app on the subject device opens the window; rows before and after say which side, never a conclusion", () => {
    const out = markInfectionWindow(rows("Ana's Pixel"), [ioc()], at(48));
    const inv = out.find((e) => e.id === "inv")!;
    expect(inv.description).toContain(`${INFECTION_WINDOW_MARKER} after the earliest sign`);
    expect(out.find((e) => e.id === "h0")!.description).toContain(
      "before the earliest sign of compromise on Ana's Pixel",
    );
    expect(out.find((e) => e.id === "h1")!.description).toContain(
      "POSSIBLE alternative source of this record; its capabilities are not read",
    );
    expect(out.find((e) => e.id === "h1")!.description).not.toMatch(/caused by|malware did|attributed/);
    expect(out.every((e) => e.severity === "Info")).toBe(true);
    // The note is derived: correlation's key strips it.
    expect(cleanDescription(out[1].description)).toBe(cleanDescription(rows("Ana's Pixel")[1].description));
  });
  it("no subject device → no window; content rows never open one; a revoked assertion takes the window away on the next merge", () => {
    expect(
      markInfectionWindow(rows(), [ioc()], at(48)).every(
        (e) => !e.description.includes(INFECTION_WINDOW_MARKER),
      ),
    ).toBe(true);
    // A malicious URL in a history row is content the device holds: no sign.
    const urlIoc = ioc({ id: "i2", type: "url", value: "https://after.example" });
    expect(
      markInfectionWindow(
        rows("P").filter((e) => e.id !== "inv"),
        [urlIoc],
        at(48),
      ).every((e) => !e.description.includes(INFECTION_WINDOW_MARKER)),
    ).toBe(true);
    const marked = markInfectionWindow(rows("P"), [ioc()], at(48));
    expect(marked.some((e) => e.description.includes(INFECTION_WINDOW_MARKER))).toBe(true);
    const revoked = ioc({
      enrichments: [
        {
          source: "VirusTotal",
          verdict: "malicious",
          fetchedAt: T,
          assertionId: "a1",
          status: "revoked",
          revoked: true,
        },
      ],
    });
    const cleared = markInfectionWindow(marked, [revoked], at(49));
    expect(cleared.every((e) => !e.description.includes(INFECTION_WINDOW_MARKER))).toBe(true);
    // Rerun with the live assertion: exactly one note per row.
    const again = markInfectionWindow(markInfectionWindow(marked, [ioc()], at(50)), [ioc()], at(51));
    for (const e of again) expect(e.description.split(INFECTION_WINDOW_MARKER).length).toBeLessThanOrEqual(2);
    // An undated malicious inventory row on the device: no window at all, even with a dated one.
    const withUndated = [...rows("P"), { ...rows("P")[0], id: "inv-undated", timestamp: "" }];
    expect(
      markInfectionWindow(withUndated, [ioc()], at(48)).every(
        (e) => !e.description.includes(INFECTION_WINDOW_MARKER),
      ),
    ).toBe(true);
    // A malicious value that only appears in the row's prose (not the typed package / digest)
    // opens nothing: a `file` IOC equal to a User cell.
    const userIoc = ioc({ id: "i3", type: "file", value: `user-${SHA.slice(0, 8)}` });
    expect(
      markInfectionWindow(rows("P"), [userIoc], at(48)).every(
        (e) => !e.description.includes(INFECTION_WINDOW_MARKER),
      ),
    ).toBe(true);
    // The package name as an `other` IOC does open one.
    const pkgIoc = ioc({ id: "i4", type: "other", value: "COM.EVIL.APP" });
    expect(
      markInfectionWindow(rows("P"), [pkgIoc], at(48)).some((e) =>
        e.description.includes(INFECTION_WINDOW_MARKER),
      ),
    ).toBe(true);
    // Another subject device is untouched by this one's sign.
    const two = [
      ...rows("P"),
      ...rows("Q")
        .filter((e) => e.id !== "inv")
        .map((e) => ({ ...e, id: `${e.id}-q` })),
    ];
    const outTwo = markInfectionWindow(two, [ioc()], at(48));
    expect(
      outTwo
        .filter((e) => e.id.endsWith("-q"))
        .every((e) => !e.description.includes(INFECTION_WINDOW_MARKER)),
    ).toBe(true);
  });
});
