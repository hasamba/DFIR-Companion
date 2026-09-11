import { describe, it, expect } from "vitest";
import { decodeDefenderEvent, parseDefenderPath } from "../../src/analysis/defenderEvents.js";

// #930 item 1, part A. A Defender Operational event used to land at Info with the message's first
// line as its label — threat, path, action and result unread. Now the disposition comes from the
// ACTION and its RESULT (never the event id), sits first in the label as a fixed slot spelled from
// the outcome vocabulary, and two actions on one file are two identities.

const CHANNEL = "Microsoft-Windows-Windows Defender/Operational";

const base = {
  "Product Name": "Microsoft Defender Antivirus",
  "Detection ID": "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}",
  "Threat ID": "2147735503",
  "Threat Name": "Trojan:Win32/Wacatac.B!ml",
  "Severity Name": "Severe",
  "Category Name": "Trojan",
  Path: "file:_C:\\Users\\a.mehta\\Downloads\\invoice.exe",
  "Process Name": "C:\\Windows\\explorer.exe",
  "Detection User": "CORP\\a.mehta",
};

describe("parseDefenderPath", () => {
  it("reads a single file", () => {
    expect(parseDefenderPath("file:_C:\\x\\a.exe")).toEqual({
      primary: "C:\\x\\a.exe",
      container: undefined,
      resources: ["C:\\x\\a.exe"],
      processes: [],
      others: [],
    });
  });
  it("prefers the archive member as primary and names the container", () => {
    const r = parseDefenderPath("containerfile:_C:\\x\\a.zip; file:_C:\\x\\a.zip->evil.exe");
    expect(r.primary).toBe("C:\\x\\a.zip->evil.exe");
    expect(r.container).toBe("C:\\x\\a.zip");
  });
  it("lists every resource, bounded, and keeps processes apart", () => {
    const many = Array.from({ length: 12 }, (_, i) => `file:_C:\\x\\f${i}.exe`).join("; ");
    const r = parseDefenderPath(`${many}; process:_pid:4321,ProcessStart:133700000000000000`);
    expect(r.resources).toHaveLength(8);
    expect(r.primary).toBe("C:\\x\\f0.exe");
    expect(r.processes).toEqual(["pid:4321,ProcessStart:133700000000000000"]);
  });
  it("keeps registry, service and behaviour resources instead of dropping them", () => {
    const r = parseDefenderPath("regkey:_HKLM\\SOFTWARE\\Bad; service:_evilsvc; behavior:_x");
    expect(r.primary).toBeUndefined();
    expect(r.others).toEqual(["regkey:HKLM\\SOFTWARE\\Bad", "service:evilsvc", "behavior:x"]);
  });
  it("is safe on malformed input", () => {
    for (const bad of ["", "file:", "junk", ";;;", "containerfile:_C:\\a.zip"]) {
      expect(() => parseDefenderPath(bad), bad).not.toThrow();
    }
    expect(parseDefenderPath("containerfile:_C:\\a.zip").primary).toBe("C:\\a.zip"); // a container alone is the file
  });
});

describe("decodeDefenderEvent", () => {
  it("ignores every other channel and unknown Defender event ids", () => {
    expect(decodeDefenderEvent("Security", 1116, base)).toBeNull();
    expect(decodeDefenderEvent(CHANNEL, 5007, base)).toBeNull();
  });

  it("1116: detected — the action is a later event, so the control is unknown", () => {
    const d = decodeDefenderEvent(CHANNEL, 1116, base)!;
    expect(d.def.severity).toBe("Medium");
    expect(d.def.label).toMatch(
      /^\[control: unknown\] detected Trojan:Win32\/Wacatac\.B!ml \[Severe\] — C:\\Users\\a\.mehta\\Downloads\\invoice\.exe/,
    );
    expect(d.image).toBe("C:\\Users\\a.mehta\\Downloads\\invoice.exe");
    expect(d.event).toEqual({ action: "detected", outcome: "unknown" });
    expect(d.eventType).toBe("detection");
    expect(d.object).toEqual({ kind: "file", id: base["Detection ID"], name: base["Threat Name"] });
  });

  it("1117: the disposition comes from the action and its result", () => {
    const quarantined = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "0x00000000",
    })!;
    expect(quarantined.def.label).toMatch(/^\[control: remediated\] Quarantine /);
    expect(quarantined.event).toEqual({ action: "Quarantine", outcome: "success" });
    expect(quarantined.eventType).toBe("action");

    const blocked = decodeDefenderEvent(CHANNEL, 1117, { ...base, "Action Name": "Block" })!;
    expect(blocked.def.label).toMatch(/^\[control: blocked\]/);

    const allowed = decodeDefenderEvent(CHANNEL, 1117, { ...base, "Action Name": "Allow" })!;
    expect(allowed.def.label).toMatch(/^\[control: allowed\]/);
    expect(allowed.def.severity).toBe("Medium"); // a disposition, not a verdict

    const none = decodeDefenderEvent(CHANNEL, 1117, { ...base, "Action Name": "NoAction" })!;
    expect(none.def.label).toMatch(/^\[control: none-observed\]/); // no action seen is not an allow

    const failed = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "0x80508023",
      "Error Description":
        "The program could not find the malware and other potentially unwanted software on this device.",
    })!;
    expect(failed.def.label).toMatch(
      /^\[control: remediation-failed\] Quarantine .* error 0x80508023 The program could not find/,
    );
    expect(failed.def.severity).toBe("Medium");
    expect(failed.event).toEqual({ action: "Quarantine", outcome: "failed" });
  });

  it("does not guess at actions or results outside Defender's own vocabulary", () => {
    const userDefined = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "UserDefined",
      "Error Code": "0",
    })!;
    expect(userDefined.def.label).toMatch(/^\[control: unknown\] UserDefined /);
    const odd = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Frobnicate",
      "Error Code": "0",
    })!;
    expect(odd.def.label).toMatch(/^\[control: unknown\]/);
    const malformed = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "N/A",
    })!;
    expect(malformed.def.label).toMatch(/^\[control: unknown\]/);
    expect(malformed.event.outcome).toBe("unknown");
    // an unknown action stays unknown whatever the result says — even a failure code, even a 1118
    for (const [eid, action, code] of [
      [1117, "UserDefined", "0x80508023"],
      [1117, "Frobnicate", "0x80508023"],
      [1118, "Frobnicate", "N/A"],
      [1119, "UserDefined", "0x80508023"],
    ] as const) {
      const d = decodeDefenderEvent(CHANNEL, eid, { ...base, "Action Name": action, "Error Code": code })!;
      expect(d.def.label, `${eid} ${action} ${code}`).toMatch(/^\[control: unknown\]/);
    }
    // a known action on a failed-action event id is a failure even with an unreadable code
    expect(
      decodeDefenderEvent(CHANNEL, 1118, { ...base, "Action Name": "Quarantine", "Error Code": "N/A" })!.def
        .label,
    ).toMatch(/^\[control: remediation-failed\]/);
    const decimal = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "2147500037",
    })!;
    expect(decimal.def.label).toMatch(/^\[control: remediation-failed\]/);
  });

  it("a registry-only detection is not a file event and keeps the key in the label and identity", () => {
    const d = decodeDefenderEvent(CHANNEL, 1116, { ...base, Path: "regkey:_HKLM\\SOFTWARE\\Bad" })!;
    expect(d.def.kind).toBeUndefined();
    expect(d.image).toBeUndefined();
    expect(d.object.kind).toBe("registry");
    expect(decodeDefenderEvent(CHANNEL, 1116, { ...base, Path: "service:_evilsvc" })!.object.kind).toBe(
      "service",
    );
    expect(decodeDefenderEvent(CHANNEL, 1116, { ...base, Path: "behavior:_x" })!.object.kind).toBe("other");
    expect(d.def.label).toContain("regkey:HKLM\\SOFTWARE\\Bad");
    const other = decodeDefenderEvent(CHANNEL, 1116, { ...base, Path: "regkey:_HKLM\\SOFTWARE\\Other" })!;
    expect(other.identity).not.toBe(d.identity);
  });

  it("1118 and 1119: a failed action, whatever the action said", () => {
    for (const eid of [1118, 1119]) {
      const d = decodeDefenderEvent(CHANNEL, eid, {
        ...base,
        "Action Name": "Remove",
        "Error Code": "0x80508023",
      })!;
      expect(d.def.label, String(eid)).toMatch(/^\[control: remediation-failed\]/);
      expect(d.event.outcome, String(eid)).toBe("failed");
    }
  });

  it("legacy 1006/1007/1008 and 1015 take the same shapes", () => {
    expect(decodeDefenderEvent(CHANNEL, 1006, base)!.def.label).toMatch(/^\[control: unknown\] detected/);
    expect(decodeDefenderEvent(CHANNEL, 1007, { ...base, "Action Name": "Clean" })!.def.label).toMatch(
      /^\[control: remediated\]/,
    );
    expect(decodeDefenderEvent(CHANNEL, 1008, { ...base, "Action Name": "Clean" })!.def.label).toMatch(
      /^\[control: remediation-failed\]/,
    );
    expect(decodeDefenderEvent(CHANNEL, 1015, base)!.def.label).toMatch(
      /^\[control: unknown\] detected suspicious behaviour/,
    );
  });

  it("reads the fields under spaced, unspaced and underscored names", () => {
    const unspaced = {
      ThreatName: "X",
      ActionName: "Quarantine",
      ErrorCode: "0",
      Path: "file:_C:\\a.exe",
      DetectionID: "d1",
    };
    const under = {
      threat_name: "X",
      action_name: "Quarantine",
      error_code: "0",
      path: "file:_C:\\a.exe",
      detection_id: "d1",
    };
    for (const ed of [unspaced, under]) {
      const d = decodeDefenderEvent(CHANNEL, 1117, ed)!;
      expect(d.def.label).toMatch(/^\[control: remediated\] Quarantine X — C:\\a\.exe/);
    }
  });

  it("degrades to (unknown) when fields are missing, never to undefined", () => {
    const d = decodeDefenderEvent(CHANNEL, 1116, {})!;
    expect(d.def.label).toBe("[control: unknown] detected (unknown threat)");
    expect(d.def.label).not.toContain("undefined");
    expect(d.image).toBeUndefined();
  });

  it("names the container and the extra resources, bounded", () => {
    const d = decodeDefenderEvent(CHANNEL, 1116, {
      ...base,
      Path: "containerfile:_C:\\x\\a.zip; file:_C:\\x\\a.zip->one.exe; file:_C:\\x\\a.zip->two.exe",
    })!;
    expect(d.image).toBe("C:\\x\\a.zip->one.exe");
    expect(d.def.label).toContain(
      "— C:\\x\\a.zip->one.exe (in C:\\x\\a.zip) (+1 more: C:\\x\\a.zip->two.exe)",
    );
    const proc = decodeDefenderEvent(CHANNEL, 1116, {
      ...base,
      Path: "process:_pid:4321,ProcessStart:1337",
    })!;
    expect(proc.image).toBeUndefined();
    expect(proc.def.label).toContain("process pid:4321");
  });

  it("gives two actions on one file two identities, and a re-import one", () => {
    const ok = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "0",
    })!;
    const fail = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "0x80508023",
    })!;
    const remove = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Remove",
      "Error Code": "0",
    })!;
    const again = decodeDefenderEvent(CHANNEL, 1117, {
      ...base,
      "Action Name": "Quarantine",
      "Error Code": "0",
    })!;
    expect(new Set([ok.identity, fail.identity, remove.identity]).size).toBe(3);
    expect(again.identity).toBe(ok.identity);
  });

  it("bounds every attacker-shaped component", () => {
    const d = decodeDefenderEvent(CHANNEL, 1116, {
      ...base,
      "Threat Name": "T".repeat(500),
      Path: `file:_C:\\${"p".repeat(2000)}.exe`,
    })!;
    expect(d.def.label.length).toBeLessThanOrEqual(460);
    expect(d.def.label.startsWith("[control: unknown] detected ")).toBe(true);
  });
});
