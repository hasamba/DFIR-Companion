import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { Severity, InvestigationQuestion, QuestionStatus } from "./stateTypes.js";

export interface CaseTemplate {
  id: string;
  name: string;
  description: string;
  builtIn: boolean;
  recommendedImports: string[];   // e.g. ["chainsaw", "thor", "hayabusa"]
  initialKeyQuestions: string[];  // pre-populated question strings
  severityFloor: Severity | null; // minimum severity shown initially
  huntPlatforms: string[];        // e.g. ["Velociraptor", "Security Onion"]
}

export const BUILT_IN_TEMPLATES: readonly CaseTemplate[] = [
  {
    id: "ransomware",
    name: "Ransomware",
    description: "Ransomware attack — encryption event, lateral movement, potential double-extortion.",
    builtIn: true,
    recommendedImports: ["chainsaw", "hayabusa", "thor", "velociraptor", "kape"],
    initialKeyQuestions: [
      "What was the initial access vector?",
      "When did encryption begin, and which hosts and shares were affected?",
      "Was data exfiltrated before encryption (double-extortion)?",
      "What ransom note or attacker-left IOC was found?",
      "How did the attacker achieve lateral movement or privilege escalation?",
      "How was persistence established?",
      "Are backups intact and isolated from the network?",
    ],
    severityFloor: "High",
    huntPlatforms: ["Velociraptor", "Security Onion"],
  },
  {
    id: "bec",
    name: "BEC / Email Compromise",
    description: "Business Email Compromise — account takeover, mail-rule manipulation, wire-fraud.",
    builtIn: true,
    recommendedImports: ["m365", "siem", "chainsaw"],
    initialKeyQuestions: [
      "Which mailboxes were compromised?",
      "How was initial access achieved (phishing, password spray, OAuth grant)?",
      "Were mail-forwarding rules or inbox rules created by the attacker?",
      "Were financial transactions or wire transfers initiated?",
      "What external IP addresses and user-agents accessed the account?",
      "Was MFA present and, if so, how was it bypassed?",
      "What data was accessed or exfiltrated from the mailbox?",
    ],
    severityFloor: "Medium",
    huntPlatforms: ["Microsoft 365", "Entra ID / Azure AD"],
  },
  {
    id: "insider-threat",
    name: "Insider Threat",
    description: "Malicious or negligent insider — data theft, sabotage, policy violation.",
    builtIn: true,
    recommendedImports: ["siem", "kape", "plaso", "m365", "aws"],
    initialKeyQuestions: [
      "Who is the subject of investigation and what is their role?",
      "What data or systems did the subject access outside their normal scope?",
      "Were large file copies, USB transfers, or cloud uploads observed?",
      "Did the subject access systems after a resignation or termination notice?",
      "Are there signs of data staging or collection before departure?",
      "What communication channels (email, Teams, Slack) were used?",
      "Was account or credentials sharing observed?",
    ],
    severityFloor: "Medium",
    huntPlatforms: ["Microsoft 365", "Velociraptor", "Elastic SIEM"],
  },
  {
    id: "web-intrusion",
    name: "Web App Intrusion",
    description: "Web application attack — SQL injection, RCE, webshell, server compromise.",
    builtIn: true,
    recommendedImports: ["network", "siem", "chainsaw", "hayabusa"],
    initialKeyQuestions: [
      "What web application or endpoint was targeted?",
      "What was the attack technique (SQLi, RCE, file upload, SSRF)?",
      "Was a webshell or backdoor installed?",
      "What OS commands were executed by the web process?",
      "Did the attacker pivot from the web server to internal systems?",
      "What data was accessed or exfiltrated?",
      "Has the vulnerability been patched or the system isolated?",
    ],
    severityFloor: "Medium",
    huntPlatforms: ["Security Onion", "Elastic SIEM"],
  },
  {
    id: "general-malware",
    name: "General Malware",
    description: "Malware infection — trojan, RAT, info-stealer, cryptominer, or unknown malware family.",
    builtIn: true,
    recommendedImports: ["thor", "chainsaw", "hayabusa", "velociraptor", "sandbox"],
    initialKeyQuestions: [
      "What malware family or IOC triggered the alert?",
      "What was the infection vector (email attachment, drive-by, USB)?",
      "How many hosts are affected?",
      "What C2 infrastructure (IP/domain/URL) was contacted?",
      "What persistence mechanisms were established?",
      "Was credential theft or lateral movement observed?",
      "Is the malware still active or has the system been cleaned?",
    ],
    severityFloor: "High",
    huntPlatforms: ["Velociraptor", "Security Onion"],
  },
];

// Build initial InvestigationQuestion objects from a template's question strings.
// Pinned so synthesis preserves them and can answer them over time.
export function buildInitialQuestions(template: CaseTemplate): InvestigationQuestion[] {
  return template.initialKeyQuestions.map((q) => ({
    id: randomUUID(),
    question: q,
    status: "unknown" as QuestionStatus,
    answer: "",
    pointer: "",
    pinned: true,
  }));
}

export class TemplateStore {
  constructor(private readonly root: string) {}

  private path(id: string): string {
    return join(this.root, `${id}.json`);
  }

  async list(): Promise<CaseTemplate[]> {
    return [...BUILT_IN_TEMPLATES, ...(await this.listCustom())];
  }

  private async listCustom(): Promise<CaseTemplate[]> {
    let entries: string[];
    try {
      entries = await readdir(this.root);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const templates: CaseTemplate[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const raw = JSON.parse(await readFile(join(this.root, entry), "utf8")) as CaseTemplate;
        if (!raw.builtIn) templates.push(raw);
      } catch {
        // skip malformed files
      }
    }
    return templates;
  }

  async get(id: string): Promise<CaseTemplate | null> {
    const builtin = BUILT_IN_TEMPLATES.find((t) => t.id === id);
    if (builtin) return builtin;
    try {
      return JSON.parse(await readFile(this.path(id), "utf8")) as CaseTemplate;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async save(input: Omit<CaseTemplate, "id" | "builtIn"> & { id?: string }): Promise<CaseTemplate> {
    const template: CaseTemplate = {
      id: input.id && String(input.id).trim() ? String(input.id).trim() : randomUUID(),
      name: String(input.name ?? "").trim(),
      description: String(input.description ?? "").trim(),
      builtIn: false,
      recommendedImports: Array.isArray(input.recommendedImports) ? input.recommendedImports.map(String) : [],
      initialKeyQuestions: Array.isArray(input.initialKeyQuestions) ? input.initialKeyQuestions.map(String) : [],
      severityFloor: input.severityFloor ?? null,
      huntPlatforms: Array.isArray(input.huntPlatforms) ? input.huntPlatforms.map(String) : [],
    };
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(template.id), JSON.stringify(template, null, 2));
    return template;
  }

  async delete(id: string): Promise<boolean> {
    if (BUILT_IN_TEMPLATES.some((t) => t.id === id)) {
      throw new Error(`cannot delete built-in template "${id}"`);
    }
    try {
      await unlink(this.path(id));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }
}
