/**
 * Audit log: one JSONL line per cell run, in the user's cellrun home.
 *
 * Default home is ~/.cellrun (overridable with CELLRUN_HOME, which is
 * what the tests use to keep the real log clean). The log is the
 * evidence trail: what ran, where, with what network mode, and how it
 * ended. `cells` and `audit` read it back.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AuditEntry } from "./types.js";

export function auditHome(): string {
  return process.env.CELLRUN_HOME || join(homedir(), ".cellrun");
}

export function auditFile(): string {
  return join(auditHome(), "audit.jsonl");
}

export function appendEntry(entry: AuditEntry): void {
  mkdirSync(auditHome(), { recursive: true });
  appendFileSync(auditFile(), JSON.stringify(entry) + "\n", "utf8");
}

export function readEntries(): AuditEntry[] {
  const file = auditFile();
  if (!existsSync(file)) return [];
  const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");
  const entries: AuditEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line) as AuditEntry);
    } catch {
      // A torn last line (killed mid-write) is skipped, never fatal.
    }
  }
  return entries;
}

export interface CellSummary {
  cellId: string;
  command: string;
  backend: string;
  network: string;
  networkEnforced: boolean;
  /** True when the run was refused by the sanitize gate before executing. */
  blockedBySanitize: boolean;
  exitCode: number | null;
  timedOut: boolean;
  endedAt: string;
  durationMs: number;
  alive: boolean;
}

/** One row per cell (latest entry wins), newest first. */
export function listCells(): CellSummary[] {
  const entries = readEntries();
  const byId = new Map<string, AuditEntry>();
  for (const entry of entries) byId.set(entry.cellId, entry);
  const rows = [...byId.values()]
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
    .map((e) => ({
      cellId: e.cellId,
      command: e.command,
      backend: e.backend,
      network: e.network,
      networkEnforced: e.networkEnforced,
      blockedBySanitize: e.blockedBySanitize,
      exitCode: e.exitCode,
      timedOut: e.timedOut,
      endedAt: e.endedAt,
      durationMs: e.durationMs,
      alive: existsSync(e.cellDir),
    }));
  return rows;
}
