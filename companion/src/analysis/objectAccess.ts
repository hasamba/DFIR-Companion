// Windows object-access records (#930 item 7): the typed envelope blocks a 4663 / 4656 / 4658 /
// 4660 / 5145 / 4689 / logoff / boot record yields, read from named fields. The vocabulary
// (rights by bit, id and path normalisation) lives in canonicalObjectAccess.ts.
import {
  decodeFileAccessMask,
  normaliseId,
  normalisePid,
  type AccessClass,
} from "./canonicalObjectAccess.js";
import { processGuid } from "./processAccess.js";

// ───────────────────────────── the envelope blocks ─────────────────────────────

export interface ObjectAccessBlocks {
  event?: { category: "file" | "network" | "authentication" | "process" | "other"; type: string };
  file?: {
    path?: string;
    name?: string;
    access: {
      mask?: string;
      rights: string[];
      classes: AccessClass[];
      objectType?: string;
      handleId?: string;
    };
  };
  process?: { pid?: number; executable?: string; name?: string; id?: string };
  authentication?: { sessionId?: string };
}

const OBJECT_ACCESS = 4663;
const HANDLE_REQUEST = 4656;
const HANDLE_CLOSED = 4658;
const OBJECT_DELETED = 4660;
const SHARE_OBJECT_CHECK = 5145;
const PROCESS_EXIT = 4689;
const SYSMON_PROCESS_TERMINATE = 5;
const LOGOFF = new Set([4634, 4647]);
const BOOT = new Set([6005, 6006, 6009, 4608, 1074]);
const KERNEL_GENERAL_BOOT = 12;

type Field = (key: string) => string;

const baseName = (p: string): string => p.split(/[\\/]/).pop() || p;

// File rights decode only for a File object (a share object is one); a Key / Process / Token mask
// keeps its value and its rights read as unknown — the bits mean other things there.
function accessFile(field: Field, pathField: string, fileObject: boolean): ObjectAccessBlocks["file"] {
  const m = decodeFileAccessMask(field("AccessMask").trim() || undefined);
  const path = field(pathField).trim();
  const objectType = field("ObjectType").trim();
  const handleId = normaliseId(field("HandleId"));
  const isFile = fileObject || /^file$/i.test(objectType);
  return {
    ...(path && path !== "-" ? { path, name: baseName(path) } : {}),
    access: {
      ...(m.state === "value" ? { mask: `0x${m.bits.toString(16)}` } : {}),
      rights: isFile ? m.rights : [],
      classes: isFile ? m.classes : m.state === "value" ? ["unknown"] : [],
      ...(objectType ? { objectType } : {}),
      ...(handleId ? { handleId } : {}),
    },
  };
}

/** The process a termination row names: pid, and the image / GUID when the record carries them. */
function endedProcess(field: Field, imageField: string): Pick<ObjectAccessBlocks, "process"> {
  const pid = normalisePid(field("ProcessId"));
  const exe = field(imageField).trim();
  const guid = processGuid(field("ProcessGuid"));
  if (pid === null && !exe && !guid) return {};
  return {
    process: {
      ...(pid !== null ? { pid } : {}),
      ...(exe && exe !== "-" ? { executable: exe, name: baseName(exe) } : {}),
      ...(guid ? { id: guid } : {}),
    },
  };
}

function accessingProcess(field: Field): ObjectAccessBlocks["process"] | undefined {
  const pid = normalisePid(field("ProcessId"));
  const exe = field("ProcessName").trim();
  if (pid === null && !exe) return undefined;
  return {
    ...(pid !== null ? { pid } : {}),
    ...(exe && exe !== "-" ? { executable: exe, name: baseName(exe) } : {}),
  };
}

/** The typed blocks for a Security object-access / lifecycle record; empty for anything else. */
export function objectAccessBlocks(eid: number, isSysmon: boolean, field: Field): ObjectAccessBlocks {
  if (isSysmon) {
    if (eid !== SYSMON_PROCESS_TERMINATE) return {};
    return { event: { category: "process", type: "end" }, ...endedProcess(field, "Image") };
  }
  const session = normaliseId(field("SubjectLogonId"));
  const auth = session ? { authentication: { sessionId: session } } : {};
  const proc = accessingProcess(field);
  const procBlock = proc ? { process: proc } : {};
  switch (eid) {
    case OBJECT_ACCESS:
      return {
        event: { category: "file", type: "access" },
        file: accessFile(field, "ObjectName", false),
        ...procBlock,
        ...auth,
      };
    case HANDLE_REQUEST:
      return {
        event: { category: "file", type: "handle-request" },
        file: accessFile(field, "ObjectName", false),
        ...procBlock,
        ...auth,
      };
    case HANDLE_CLOSED: {
      const handleId = normaliseId(field("HandleId"));
      return {
        event: { category: "file", type: "handle-closed" },
        file: { access: { rights: [], classes: [], ...(handleId ? { handleId } : {}) } },
        ...procBlock,
        ...auth,
      };
    }
    case OBJECT_DELETED: {
      const handleId = normaliseId(field("HandleId"));
      return {
        event: { category: "file", type: "object-deleted" },
        file: { access: { rights: [], classes: ["delete"], ...(handleId ? { handleId } : {}) } },
        ...procBlock,
        ...auth,
      };
    }
    case SHARE_OBJECT_CHECK: {
      const local = field("ShareLocalPath")
        .trim()
        .replace(/^\\\?\?\\/, "");
      const rel = field("RelativeTargetName").trim();
      const path =
        local && rel && rel !== "\\" ? `${local.replace(/\\$/, "")}\\${rel.replace(/^\\/, "")}` : "";
      const f = accessFile(field, "__none__", true)!;
      return {
        event: { category: "network", type: "share-object-check" },
        file: { ...(path ? { path, name: baseName(path) } : {}), access: f.access },
        ...auth,
      };
    }
    case PROCESS_EXIT:
      return { event: { category: "process", type: "end" }, ...endedProcess(field, "ProcessName"), ...auth };
    default:
      if (LOGOFF.has(eid)) {
        const id = normaliseId(field("TargetLogonId"));
        return {
          event: { category: "authentication", type: "logoff" },
          ...(id ? { authentication: { sessionId: id } } : {}),
        };
      }
      // A boot / shutdown boundary: 6005 / 6006 / 6009 / 4608 / 1074, and Kernel-General 12
      // (System channel; it carries StartTime — Sysmon's 12 is a registry row and never reaches here).
      if (BOOT.has(eid) || (eid === KERNEL_GENERAL_BOOT && field("StartTime").trim()))
        return { event: { category: "other", type: "boot" } };
      return {};
  }
}
