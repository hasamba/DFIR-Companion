import { describe, it, expect } from "vitest";
import {
  parseMobsfPermissions,
  parseMobsfIosPermissions,
  parseMobsfPermissionsAnyPlatform,
  isMobsfReport,
  isMobsfIosReport,
} from "../../src/analysis/mobsfPermissionImport.js";

// Shape verified live against MobSF's own db_interaction.py (get_context_from_analysis),
// manifest_analysis.py, manifest_utils.py, and dvm_permissions.py's own status values.
function report(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: "4.5.0",
    file_name: "sample.apk",
    app_name: "Sample App",
    package_name: "com.example.sample",
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    apkid: {},
    permissions: {
      "android.permission.CAMERA": {
        status: "dangerous",
        info: "take pictures and videos",
        description: "Allows the app to take pictures and videos with the camera.",
      },
    },
    ...overrides,
  };
}

describe("isMobsfReport", () => {
  it("recognizes a real MobSF Android static-analysis report", () => {
    expect(isMobsfReport(report())).toBe(true);
  });

  it("accepts a report with zero requested permissions", () => {
    expect(isMobsfReport(report({ permissions: {} }))).toBe(true);
  });

  it("rejects a report missing every MobSF-specific anchor (niap_analysis/sbom/apkid)", () => {
    const bad = report();
    delete bad.apkid;
    expect(isMobsfReport(bad)).toBe(false);
  });

  it("rejects a report missing sha256", () => {
    const bad = report();
    delete bad.sha256;
    expect(isMobsfReport(bad)).toBe(false);
  });

  it("rejects a report whose permissions field isn't an object", () => {
    expect(isMobsfReport(report({ permissions: [] }))).toBe(false);
  });

  it("rejects a plain unrelated JSON object", () => {
    expect(isMobsfReport({ hello: "world" })).toBe(false);
  });

  it("rejects a report whose only anchor is a primitive value, not an object/array (Codex code review finding)", () => {
    const bad = report({ apkid: true, sbom: "n/a" });
    delete bad.niap_analysis;
    expect(isMobsfReport(bad)).toBe(false);
  });

  it("still accepts a report whose anchor is an empty object or array", () => {
    expect(isMobsfReport(report({ apkid: {}, sbom: [] }))).toBe(true);
  });
});

describe("parseMobsfPermissions — malformed input", () => {
  it("returns null for text that isn't valid JSON", () => {
    expect(parseMobsfPermissions("not json at all")).toBeNull();
  });

  it("returns null for valid JSON that isn't a MobSF report", () => {
    expect(parseMobsfPermissions(JSON.stringify({ hello: "world" }))).toBeNull();
  });
});

describe("parseMobsfPermissions — a single requested permission", () => {
  it("maps to an Info-severity, undated event naming the permission/status/package, never claiming grant or use", () => {
    const r = parseMobsfPermissions(JSON.stringify(report()))!;
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    const block = e.canonical!.mobileRequestedPermission!;
    expect(block.permission).toBe("android.permission.CAMERA");
    expect(block.status).toBe("dangerous");
    expect(block.rawStatus).toBe("dangerous");
    expect(block.packageName).toBe("com.example.sample");
    expect(e.description).toContain("never proof of");
    expect(e.description).toContain("never a claim about this specific app");
  });

  it("pins the platform-neutral 'declared request' wording (#1136 — was 'manifest declaration', Android-only vocabulary)", () => {
    const r = parseMobsfPermissions(JSON.stringify(report()))!;
    expect(r.events[0].description).toContain("a declared request, never proof of");
    expect(r.events[0].description).not.toContain("manifest declaration");
  });

  it("records the SAME mappingVersion on the canonical block and the producer metadata", () => {
    const r = parseMobsfPermissions(JSON.stringify(report()))!;
    const e = r.events[0];
    expect(e.canonical!.mobileRequestedPermission!.mappingVersion).toBe("mobile-requested-permission-v2");
    expect(e.canonical!.producer.mappingVersion).toBe(e.canonical!.mobileRequestedPermission!.mappingVersion);
  });
});

// iOS shape verified live against MobSF's own db_interaction.py (get_context_from_analysis /
// get_context_from_db_entry) and kb/permission_analysis.py's own check_permissions() (#1136).
// Real iOS reports never carry `package_name`/`sha256`-required-together the way Android's own
// isMobsfReport() demands, and never carry any of Android's own MOBSF-specific anchors
// (niap_analysis/sbom/apkid) — so isMobsfReport() must reject every real iOS report.
function iosReport(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: "4.5.0",
    file_name: "sample.ipa",
    app_name: "Sample iOS App",
    bundle_id: "com.example.sample",
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ats_analysis: {},
    macho_analysis: {},
    bundle_url_types: [],
    permissions: {
      NSCameraUsageDescription: {
        status: "dangerous",
        info: "Access the Camera",
        description: "This app needs camera access to scan documents.",
      },
    },
    ...overrides,
  };
}

describe("isMobsfIosReport", () => {
  it("recognizes a real MobSF iOS static-analysis report", () => {
    expect(isMobsfIosReport(iosReport())).toBe(true);
  });

  it("accepts a report with zero requested permissions", () => {
    expect(isMobsfIosReport(iosReport({ permissions: {} }))).toBe(true);
  });

  it("rejects a report missing every iOS-specific anchor (ats_analysis/macho_analysis/bundle_url_types)", () => {
    const bad = iosReport();
    delete bad.ats_analysis;
    delete bad.macho_analysis;
    bad.bundle_url_types = undefined;
    delete bad.bundle_url_types;
    expect(isMobsfIosReport(bad)).toBe(false);
  });

  it("rejects a report missing bundle_id", () => {
    const bad = iosReport();
    delete bad.bundle_id;
    expect(isMobsfIosReport(bad)).toBe(false);
  });

  it("rejects a report missing md5", () => {
    const bad = iosReport();
    delete bad.md5;
    expect(isMobsfIosReport(bad)).toBe(false);
  });

  it("rejects a report whose permissions field isn't an object", () => {
    expect(isMobsfIosReport(iosReport({ permissions: [] }))).toBe(false);
  });

  it("rejects null and non-object input without throwing", () => {
    expect(isMobsfIosReport(null)).toBe(false);
    expect(isMobsfIosReport("not an object")).toBe(false);
    expect(isMobsfIosReport(undefined)).toBe(false);
  });

  it("rejects a plain unrelated JSON object", () => {
    expect(isMobsfIosReport({ hello: "world" })).toBe(false);
  });

  it("still accepts a report whose anchor is an empty object or array", () => {
    expect(isMobsfIosReport(iosReport({ ats_analysis: {}, bundle_url_types: [] }))).toBe(true);
  });

  it("a real Android MobSF report never satisfies the iOS detector", () => {
    expect(isMobsfIosReport(report())).toBe(false);
  });

  it("a real iOS MobSF report never satisfies the Android detector", () => {
    expect(isMobsfReport(iosReport())).toBe(false);
  });
});

describe("parseMobsfIosPermissions — malformed input", () => {
  it("returns null for text that isn't valid JSON", () => {
    expect(parseMobsfIosPermissions("not json at all")).toBeNull();
  });

  it("returns null for valid JSON that isn't an iOS MobSF report", () => {
    expect(parseMobsfIosPermissions(JSON.stringify({ hello: "world" }))).toBeNull();
  });

  it("returns null for a real Android MobSF report (routed to the Android parser instead)", () => {
    expect(parseMobsfIosPermissions(JSON.stringify(report()))).toBeNull();
  });
});

describe("parseMobsfIosPermissions — a single requested permission", () => {
  it("maps to an Info-severity, undated event naming the NS-permission/status/bundle id, never claiming grant or use", () => {
    const r = parseMobsfIosPermissions(JSON.stringify(iosReport()))!;
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    const block = e.canonical!.mobileRequestedPermission!;
    expect(block.platform).toBe("ios");
    expect(block.permission).toBe("NSCameraUsageDescription");
    expect(block.status).toBe("dangerous");
    expect(block.packageName).toBe("com.example.sample");
    expect(e.description).toContain("never proof of");
  });

  it("attributes the description text to the APP'S OWN declared purpose, never to MobSF's own reference text (this item's own real finding)", () => {
    const r = parseMobsfIosPermissions(JSON.stringify(iosReport()))!;
    const e = r.events[0];
    // The Android path's own "MobSF's own reference text (never a claim about this specific app)"
    // framing is FALSE for iOS: check_permissions()'s own real `description` field is the
    // developer's own Info.plist string, not a MobSF knowledge-base lookup.
    expect(e.description).not.toContain("MobSF's own reference text");
    expect(e.description).toContain("app's own declared purpose");
    expect(e.description).toContain("This app needs camera access to scan documents.");
  });

  it("records mappingVersion v2 and platform ios on the canonical block", () => {
    const r = parseMobsfIosPermissions(JSON.stringify(iosReport()))!;
    const block = r.events[0].canonical!.mobileRequestedPermission!;
    expect(block.mappingVersion).toBe("mobile-requested-permission-v2");
    expect(block.platform).toBe("ios");
  });

  it("registers a real sample hash as an IOC linked to the event, same as the Android path", () => {
    const rpt = iosReport();
    const r = parseMobsfIosPermissions(JSON.stringify(rpt))!;
    const hashIocs = r.iocs.filter((i) => i.type === "hash").map((i) => i.value);
    expect(hashIocs).toContain(rpt.sha256);
  });

  it("counts a malformed permission entry without crashing", () => {
    const rpt = iosReport({
      permissions: {
        NSCameraUsageDescription: { status: "dangerous", info: "i", description: "d" },
        NSBadEntry: "not-an-object",
      },
    });
    const r = parseMobsfIosPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedPermissions).toBe(1);
  });

  it("discloses permissionsTruncated once entries exceed the report-wide cap, same bound as Android", () => {
    const permissions: Record<string, unknown> = {};
    for (let i = 0; i < 2001; i++) {
      permissions[`NSCustomUsageDescription_${i}`] = { status: "normal", info: "i", description: "d" };
    }
    const r = parseMobsfIosPermissions(JSON.stringify(iosReport({ permissions })))!;
    expect(r.permissionsTruncated).toBe(true);
    expect(r.total).toBe(2000);
  });

  it("normalizes an unrecognized iOS status to 'unknown', preserving the raw string (mirrors Android's own coverage)", () => {
    const rpt = iosReport({
      permissions: {
        NSFutureUsageDescription: { status: "futureStatus", info: "i", description: "d" },
      },
    });
    const r = parseMobsfIosPermissions(JSON.stringify(rpt))!;
    const block = r.events[0].canonical!.mobileRequestedPermission!;
    expect(block.status).toBe("unknown");
    expect(block.rawStatus).toBe("futureStatus");
  });

  it("disambiguates two long NS-permission names sharing the same clipped prefix, mirroring Android's own coverage", () => {
    const longPrefix = "NSCustomUsageDescription" + "A".repeat(300);
    const rpt = iosReport({
      permissions: {
        [`${longPrefix}_ONE`]: { status: "normal", info: "i1", description: "d1" },
        [`${longPrefix}_TWO`]: { status: "normal", info: "i2", description: "d2" },
      },
    });
    const r = parseMobsfIosPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].description).not.toBe(r.events[1].description);
  });

  it("falls back to '(unknown)' in the description when bundle_id is empty", () => {
    const r = parseMobsfIosPermissions(JSON.stringify(iosReport({ bundle_id: "" })))!;
    expect(r.events[0].description).toContain("bundle id (unknown)");
  });
});

describe("isMobsfIosReport — hash-field requirement (Ollama code review finding)", () => {
  it("rejects a report missing sha1 even when md5 and bundle_id are present", () => {
    const bad = iosReport();
    delete bad.sha1;
    expect(isMobsfIosReport(bad)).toBe(false);
  });

  it("rejects a report missing sha256 even when md5 and bundle_id are present", () => {
    const bad = iosReport();
    delete bad.sha256;
    expect(isMobsfIosReport(bad)).toBe(false);
  });
});

describe("MobSF detector precedence (Ollama code review finding)", () => {
  it("resolves a synthetic object satisfying both detectors' anchors to Android (isMobsfReport checked first in importDetect.ts)", () => {
    // Not a real MobSF output — no genuine report carries both package_name AND bundle_id — but
    // the precedence must still be defined and stable rather than accidental.
    const dual = { ...report(), ...iosReport(), package_name: "com.example.sample" };
    expect(isMobsfReport(dual)).toBe(true);
    expect(isMobsfIosReport(dual)).toBe(true);
  });
});

describe("parseMobsfPermissionsAnyPlatform — single-parse dispatcher", () => {
  it("dispatches a real Android report to the Android parser", () => {
    const r = parseMobsfPermissionsAnyPlatform(JSON.stringify(report()))!;
    expect(r.format).toBe("MobsfAndroidStaticReport");
    expect(r.events[0].canonical!.mobileRequestedPermission!.platform).toBe("android");
  });

  it("dispatches a real iOS report to the iOS parser", () => {
    const r = parseMobsfPermissionsAnyPlatform(JSON.stringify(iosReport()))!;
    expect(r.format).toBe("MobsfIosStaticReport");
    expect(r.events[0].canonical!.mobileRequestedPermission!.platform).toBe("ios");
  });

  it("returns null for text that isn't valid JSON", () => {
    expect(parseMobsfPermissionsAnyPlatform("not json at all")).toBeNull();
  });

  it("returns null for valid JSON matching neither platform", () => {
    expect(parseMobsfPermissionsAnyPlatform(JSON.stringify({ hello: "world" }))).toBeNull();
  });
});

describe("parseMobsfPermissions — status normalization (Codex design review finding)", () => {
  it("normalizes an unrecognized status to 'unknown' in the structured field, while preserving the raw string", () => {
    const rpt = report({
      permissions: {
        "android.permission.FUTURE_THING": {
          status: "futureStatus",
          info: "some future capability",
          description: "a status value this build has never seen",
        },
      },
    });
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.mobileRequestedPermission!;
    expect(block.status).toBe("unknown");
    expect(block.rawStatus).toBe("futureStatus");
  });

  it.each(["dangerous", "normal", "signature", "signatureOrSystem", "internal", "unknown"] as const)(
    "accepts the real confirmed status value %s verbatim",
    (status) => {
      const rpt = report({
        permissions: { "android.permission.X": { status, info: "i", description: "d" } },
      });
      const r = parseMobsfPermissions(JSON.stringify(rpt))!;
      expect(r.events[0].canonical!.mobileRequestedPermission!.status).toBe(status);
    },
  );
});

describe("parseMobsfPermissions — sample hash and correlation", () => {
  it("validates, lowercases, and registers every valid hash as its own IOC linked to the event", () => {
    const rpt = report();
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    const hashIocs = r.iocs.filter((i) => i.type === "hash").map((i) => i.value);
    expect(hashIocs).toContain(rpt.md5);
    expect(hashIocs).toContain(rpt.sha1);
    expect(hashIocs).toContain(rpt.sha256);
    const sha256Ioc = r.iocs.find((i) => i.type === "hash" && i.value === rpt.sha256);
    expect(sha256Ioc?.sourceAggKeys).toEqual([r.events[0].aggKey]);
  });

  it("treats a malformed sample hash as absent, sets hashUnavailable only when none validate", () => {
    const rpt = report({ md5: "not-a-hash", sha1: "not-a-hash", sha256: "not-a-hash" });
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    const block = r.events[0].canonical!.mobileRequestedPermission!;
    expect(block.sampleHash.hashUnavailable).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false);
  });
});

describe("parseMobsfPermissions — report identity", () => {
  it("gives two separate reports different aggKeys and different descriptions even with identical permissions", () => {
    const r1 = parseMobsfPermissions(JSON.stringify(report()))!;
    const r2 = parseMobsfPermissions(JSON.stringify(report({ version: "4.5.1" })))!;
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
    expect(r1.events[0].description).not.toBe(r2.events[0].description);
  });

  it("gives two distinct permission names in the same report distinct aggKeys", () => {
    const rpt = report({
      permissions: {
        "android.permission.CAMERA": { status: "dangerous", info: "i1", description: "d1" },
        "android.permission.INTERNET": { status: "normal", info: "i2", description: "d2" },
      },
    });
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].aggKey).not.toBe(r.events[1].aggKey);
  });

  it("disambiguates two long permission names sharing the same clipped prefix in the persisted description, not only the aggKey (Codex code review finding)", () => {
    const longPrefix = "android.permission." + "A".repeat(300);
    const rpt = report({
      permissions: {
        [`${longPrefix}_ONE`]: { status: "normal", info: "i1", description: "d1" },
        [`${longPrefix}_TWO`]: { status: "normal", info: "i2", description: "d2" },
      },
    });
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].description).not.toBe(r.events[1].description);
  });
});

describe("parseMobsfPermissions — no severity escalation (this item's own guardrail)", () => {
  it("keeps a dangerous-status permission at Info severity — no synthesized lead", () => {
    const r = parseMobsfPermissions(JSON.stringify(report()))!;
    expect(r.events[0].severity).toBe("Info");
  });
});

describe("parseMobsfPermissions — malformed entries", () => {
  it("counts a permission entry that isn't an object as malformed, never crashes", () => {
    const rpt = report({
      permissions: {
        "android.permission.CAMERA": { status: "dangerous", info: "i", description: "d" },
        "android.permission.BAD": "not-an-object",
      },
    });
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedPermissions).toBe(1);
  });

  it("counts a permission entry missing status/info/description as malformed", () => {
    const rpt = report({
      permissions: {
        "android.permission.CAMERA": { status: "dangerous", info: "i", description: "d" },
        "android.permission.INCOMPLETE": { status: "dangerous" },
      },
    });
    const r = parseMobsfPermissions(JSON.stringify(rpt))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedPermissions).toBe(1);
  });

  it("returns an empty, non-crashing result for a report with zero requested permissions", () => {
    const r = parseMobsfPermissions(JSON.stringify(report({ permissions: {} })))!;
    expect(r.events).toHaveLength(0);
    expect(r.total).toBe(0);
  });
});

describe("parseMobsfPermissions — permission-scan volume bound", () => {
  it("discloses permissionsTruncated once the number of permission entries exceeds the report-wide cap", () => {
    const permissions: Record<string, unknown> = {};
    for (let i = 0; i < 2001; i++) {
      permissions[`android.permission.PERM_${i}`] = { status: "normal", info: "i", description: "d" };
    }
    const r = parseMobsfPermissions(JSON.stringify(report({ permissions })))!;
    expect(r.permissionsTruncated).toBe(true);
    expect(r.total).toBe(2000);
  });
});
