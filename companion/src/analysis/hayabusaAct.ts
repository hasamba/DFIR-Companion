import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import { canonicalChannel } from "./evtxChannel.js";

// The act a native Hayabusa row records, stated on its envelope (#1557).
//
// correlate.ts keeps a file write and the launch of that file apart only when BOTH rows say which
// act they record: Sysmon EID 11 maps to file/create and EID 1 to process/start, read from the
// event id and never from the wording. The Chainsaw and Velociraptor Windows mappers say it. The
// native Hayabusa importer set no envelope, so the upgrade at the read boundary typed its rows
// "observation", and an "observation" records no act and joins any row on the same path. A Hayabusa
// write of a renamed binary folded in the Chainsaw launch of it 75 ms later: the High write's text
// won the row ("file created in a Public folder") and what the binary ran survived only in side
// fields the model never reads.
//
// Only three events state an act, and only on the channel where the id means it. Every other event
// keeps today's behaviour: no envelope here, the same upgrade as before.

const SYSMON_CHANNEL = /^microsoft-windows-sysmon\/operational$/i;

export type HayabusaAct = "file-write" | "process-start";

export function hayabusaAct(eid: string, rawChannel: string): HayabusaAct | undefined {
  const id = Number(eid);
  // Hayabusa abbreviates channels ("Sysmon", "Sec"); compare on the long name (#1996).
  const channel = canonicalChannel(rawChannel);
  if (SYSMON_CHANNEL.test(channel)) {
    if (id === 11) return "file-write";
    if (id === 1) return "process-start";
    return undefined;
  }
  if (channel.trim().toLowerCase() === "security" && id === 4688) return "process-start";
  return undefined;
}

export interface HayabusaActFields {
  act: HayabusaAct;
  eid: string;
  channel: string;
  host: string;
  observed: string; // the timestamp as the record wrote it
  normalized: string;
  recordId?: string;
  path?: string;
  processName?: string;
  commandLine?: string;
}

const WRITE_RULE = "a Sysmon EID 11 record is a file create";
const START_RULE = "a process-creation record (Sysmon EID 1, Security 4688) is a process start";

export function hayabusaActEnvelope(f: HayabusaActFields): CanonicalEventEnvelope {
  const write = f.act === "file-write";
  const rule = `hayabusa-act-v1: ${write ? WRITE_RULE : START_RULE}`;
  return createCanonicalEvent({
    event: write ? { category: "file", type: "create" } : { category: "process", type: "start" },
    ...(f.host ? { target: { kind: "host" as const, name: f.host } } : {}),
    ...(write && f.path ? { file: { path: f.path } } : {}),
    ...(!write && (f.processName || f.commandLine)
      ? {
          process: {
            ...(f.processName ? { name: f.processName } : {}),
            ...(f.commandLine ? { commandLine: f.commandLine } : {}),
          },
        }
      : {}),
    time: { observed: f.observed, normalized: f.normalized },
    evidence: {
      rawRecords: [
        {
          source: "hayabusa",
          locator: `${f.channel}:${f.eid}:${f.recordId ?? f.normalized}`,
          ...(f.recordId ? { recordId: f.recordId } : {}),
        },
      ],
    },
    producer: {
      importer: "hayabusa",
      parserVersion: "1",
      mappingVersion: "hayabusa-act-v1",
    },
    derivationMap: { "event.category": rule, "event.type": rule },
  });
}
