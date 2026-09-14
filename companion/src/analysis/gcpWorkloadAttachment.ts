// GCP workload attachment (#931 item 12, second half — #1065): a documented method matrix reading
// which service account a GCE instance, a Cloud Function or a Cloud Run service is attached to —
// runtime, build and trigger identities kept apart, never merged, never synthesised when the
// request omits the field. On an update call, a field is read only when the update mask names it
// (a parent path covers its children); Cloud Run v1 has no field mask, so its create/replace is
// always read, the same way a create always is everywhere else.
//
// Method names and field paths follow Google's documented Cloud Audit Log conventions; no captured
// export of one of these records exists in this repo or was available to check them against (the
// #1065 design doc states this basis explicitly). Matching is gated on `serviceName` first, then a
// method-name TAIL (the same tolerance `gcpIamRecord.ts`'s `isSetIamPolicy` already relies on for
// a `v1.`/`beta.`/fully-qualified prefix to vary) — never a bare substring, so an unrelated method
// under the same service cannot decode by accident.

import type { Severity } from "./stateTypes.js";
import type { GcpAttachment } from "./canonicalGcp.js";
import { field, lower, seg, show } from "./gcpIdentity.js";
import { getCI, isObject } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface GcpAttachmentReading {
  severity: Severity;
  mitre: string[];
  posture: string;
  keySegment: string;
  serviceAccount: { email: string };
  attachment: GcpAttachment;
}

const saFromResourceName = (name: string): string => {
  const m = /serviceAccounts\/([^/]+)/.exec(name);
  return m ? m[1] : "";
};

/** A FieldMask path or a target field, normalised to comparable lowercase, underscore-free segments. */
function normPath(p: string): string[] {
  return p
    .trim()
    .split(".")
    .map((s) => s.replace(/_/g, "").toLowerCase())
    .filter(Boolean);
}

/**
 * Does an update's field mask cover `targetField`? The mask may be a comma-separated string or a
 * `{paths: [...]}` array, in snake_case or lowerCamelCase; `*` or a PARENT path (`serviceConfig`
 * naming `serviceConfig.serviceAccountEmail`) covers it too.
 */
export function maskCovers(mask: unknown, targetField: string): boolean {
  const raw: string[] = Array.isArray(mask)
    ? mask.map((v) => String(v))
    : typeof mask === "string"
      ? mask.split(",")
      : isObject(mask) && Array.isArray((mask as Row).paths)
        ? ((mask as Row).paths as unknown[]).map((v) => String(v))
        : [];
  const target = normPath(targetField);
  return raw.some((p) => {
    if (p.trim() === "*") return true;
    const parts = normPath(p);
    return parts.length > 0 && parts.every((s, i) => target[i] === s);
  });
}

function reading(
  workloadKind: GcpAttachment["workloadKind"],
  workloadVersion: string | undefined,
  workloadName: string,
  identityRole: GcpAttachment["identityRole"],
  email: string,
  fromUpdateMask: boolean,
): GcpAttachmentReading {
  const attachment: GcpAttachment = {
    workloadKind,
    ...(workloadVersion ? { workloadVersion } : {}),
    ...(workloadName ? { workloadName } : {}),
    identityRole,
    serviceAccountEmail: email,
    fromUpdateMask,
  };
  const workloadWords = `${workloadKind}${workloadVersion ? ` ${workloadVersion}` : ""} ${show(workloadName || "(name not in this record)", 80)} (${identityRole})`;
  return {
    severity: "Low",
    mitre: [],
    posture: `attaches service account ${show(email, 80)} to ${workloadWords} — attachment (actAs), not credential minting${fromUpdateMask ? "; read because the update named this field" : ""}`,
    keySegment: `|attachment|${[workloadKind, workloadVersion ?? "", workloadName, identityRole, email].map(seg).join("|")}`,
    serviceAccount: { email },
    attachment,
  };
}

/** Zero, one, or more readings — a Cloud Functions v2 create/update can name three identities at once. */
export function decodeGcpWorkloadAttachment(pp: Row, service: string, method: string): GcpAttachmentReading[] {
  const svc = lower(service);
  const m = lower(method);
  const request = isObject(getCI(pp, "request")) ? (getCI(pp, "request") as Row) : {};
  const resourceName = field(pp, "resourceName");
  const out: GcpAttachmentReading[] = [];

  if (svc === "compute.googleapis.com") {
    if (/(^|\.)instances\.insert$/.test(m)) {
      const sas = getCI(request, "serviceAccounts");
      const list = Array.isArray(sas) ? sas.filter(isObject) : [];
      for (const sa of list) {
        const email = field(sa, "email");
        if (email) out.push(reading("gce-instance", undefined, resourceName, "runtime", email, false));
      }
    } else if (/(^|\.)instances\.setserviceaccount$/.test(m)) {
      // InstancesSetServiceAccountRequest: the address is `request.email`, with `request.scopes[]`
      // recorded alongside — never `request.serviceAccount.email`.
      const email = field(request, "email");
      if (email) out.push(reading("gce-instance", undefined, resourceName, "runtime", email, false));
    }
    return out;
  }

  if (svc === "cloudfunctions.googleapis.com") {
    const isV1 = m.includes(".v1.");
    const isV2 = m.includes(".v2.");
    const fn = isObject(getCI(request, "function")) ? (getCI(request, "function") as Row) : {};
    const name = field(fn, "name") || resourceName;
    const mask = getCI(request, "updateMask");
    if (isV1 && /createfunction$/.test(m)) {
      const email = field(fn, "serviceAccountEmail");
      if (email) out.push(reading("cloud-function", "v1", name, "runtime", email, false));
    } else if (isV1 && /updatefunction$/.test(m)) {
      const email = field(fn, "serviceAccountEmail");
      if (email && maskCovers(mask, "serviceAccountEmail"))
        out.push(reading("cloud-function", "v1", name, "runtime", email, true));
    } else if (isV2 && /createfunction$/.test(m)) {
      const runtime = field(fn, "serviceConfig", "serviceAccountEmail");
      const build = saFromResourceName(field(fn, "buildConfig", "serviceAccount"));
      const trigger = field(fn, "eventTrigger", "serviceAccountEmail");
      if (runtime) out.push(reading("cloud-function", "v2", name, "runtime", runtime, false));
      if (build) out.push(reading("cloud-function", "v2", name, "build", build, false));
      if (trigger) out.push(reading("cloud-function", "v2", name, "trigger", trigger, false));
    } else if (isV2 && /updatefunction$/.test(m)) {
      const runtime = field(fn, "serviceConfig", "serviceAccountEmail");
      const build = saFromResourceName(field(fn, "buildConfig", "serviceAccount"));
      const trigger = field(fn, "eventTrigger", "serviceAccountEmail");
      if (runtime && maskCovers(mask, "serviceConfig.serviceAccountEmail"))
        out.push(reading("cloud-function", "v2", name, "runtime", runtime, true));
      if (build && maskCovers(mask, "buildConfig.serviceAccount"))
        out.push(reading("cloud-function", "v2", name, "build", build, true));
      if (trigger && maskCovers(mask, "eventTrigger.serviceAccountEmail"))
        out.push(reading("cloud-function", "v2", name, "trigger", trigger, true));
    }
    return out;
  }

  if (svc === "run.googleapis.com") {
    const isV1 = m.includes(".v1.");
    const isV2 = m.includes(".v2.");
    const svcBody = isObject(getCI(request, "service")) ? (getCI(request, "service") as Row) : {};
    const name = field(svcBody, "metadata", "name") || resourceName;
    if (isV1 && /(createservice|replaceservice)$/.test(m)) {
      // Cloud Run v1 (Knative) has no field mask: create and replace always send the whole spec.
      const email = field(svcBody, "spec", "template", "spec", "serviceAccountName");
      if (email) out.push(reading("cloud-run-service", "v1", name, "runtime", email, false));
    } else if (isV2 && /createservice$/.test(m)) {
      const email = field(svcBody, "template", "serviceAccount");
      if (email) out.push(reading("cloud-run-service", "v2", name, "runtime", email, false));
    } else if (isV2 && /updateservice$/.test(m)) {
      const email = field(svcBody, "template", "serviceAccount");
      const mask = getCI(request, "updateMask");
      if (email && maskCovers(mask, "template.serviceAccount"))
        out.push(reading("cloud-run-service", "v2", name, "runtime", email, true));
    }
    return out;
  }

  return out;
}
