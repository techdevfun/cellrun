#!/usr/bin/env node
/**
 * cellrun - run one agent task in a fresh, disposable cell, and sanitize
 * tool/MCP/web output for instruction injection before it enters agent
 * context.
 *
 *   cellrun run [--network off|proxy|on] [--timeout 300s] [--memory MB]
 *     [--copy <dir>] [--env KEY=VALUE]... [--isolate namespaces] [--strict]
 *     [--backend docker] [--image <img>] [--keep] [--sanitize <file>]
 *     [--allow-host <host>]... -- <command...>
 *   cellrun sanitize <file> [--quarantine] [--allow-host <host>]... [--format table|json]
 *   cellrun audit [--cell <id>] [--format table|json]
 *   cellrun cells [--format table|json]
 *
 * Exit codes: 0 = task clean / sanitize clean; 1 = task failed (its own
 * exit code is reported, run propagates it) or sanitize found HIGH
 * findings; 2 = usage or environment error; 124 = task timed out.
 * No model call, no account, no telemetry. Deterministic patterns only.
 */
import { existsSync } from "node:fs";
import { listCells, readEntries } from "./audit.js";
import { formatAge, formatDuration, renderTable, truncateMiddle } from "./render.js";
import { runCell, parseTimeout } from "./run.js";
import {
  quarantineFile,
  scanFile,
  truncateMatch,
} from "./sanitize.js";
import type { SanitizeResult } from "./types.js";

const VERSION = "0.1.0";

const USAGE = [
  "cellrun 0.1.0 - one task, one fresh cell; sanitize tool output before it reaches an agent",
  "",
  "Usage:",
  "  cellrun run [--network off|proxy|on] [--timeout 300s] [--memory MB]",
  "    [--copy <dir>] [--env KEY=VALUE]... [--isolate namespaces] [--strict]",
  "    [--backend docker] [--image <img>] [--keep] [--sanitize <file>]",
  "    [--allow-host <host>]... -- <command...>",
  "  cellrun sanitize <file> [--quarantine] [--allow-host <host>]... [--format table|json]",
  "  cellrun audit [--cell <id>] [--format table|json]",
  "  cellrun cells [--format table|json]",
  "",
  "Exit codes: 0 = clean; 1 = task failed or sanitize found HIGH findings;",
  "2 = usage/environment error; 124 = task timed out.",
  "",
  "Defaults: network off, timeout 300s, no memory limit, backend local,",
  "image node:22-slim (docker backend only). The cell is destroyed on exit",
  "unless --keep is given. Audit log: ~/.cellrun/audit.jsonl.",
].join("\n");

function fail(message: string): never {
  console.error(`cellrun: ${message}`);
  process.exit(2);
}

interface ParsedArgs {
  flags: Map<string, string[]>;
  bools: Set<string>;
  positionals: string[];
  /** Everything after the first "--" (run command only). */
  rest: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string[]>();
  const bools = new Set<string>();
  const positionals: string[] = [];
  const rest: string[] = [];
  const valueFlags = new Set([
    "--network", "--timeout", "--memory", "--copy", "--env", "--isolate",
    "--backend", "--image", "--sanitize", "--allow-host", "--cell", "--format",
    "--proxy-url",
  ]);
  const boolFlags = new Set(["--strict", "--keep", "--quarantine"]);
  let i = 0;
  let seenDashDash = false;
  while (i < argv.length) {
    const arg = argv[i];
    if (seenDashDash) {
      rest.push(arg);
      i++;
      continue;
    }
    if (arg === "--") {
      seenDashDash = true;
      i++;
      continue;
    }
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq === -1 ? arg : arg.slice(0, eq);
      const inline = eq === -1 ? undefined : arg.slice(eq + 1);
      if (boolFlags.has(name)) {
        bools.add(name);
      } else if (valueFlags.has(name)) {
        const value = inline ?? argv[i + 1];
        if (value === undefined || (inline === undefined && value.startsWith("--"))) {
          fail(`flag ${name} needs a value`);
        }
        if (!flags.has(name)) flags.set(name, []);
        flags.get(name)!.push(value);
        if (inline === undefined) i++;
      } else {
        fail(`unknown flag: ${name} (see --help)`);
      }
    } else {
      positionals.push(arg);
    }
    i++;
  }
  return { flags, bools, positionals, rest };
}

function flag(args: ParsedArgs, name: string): string | undefined {
  const values = args.flags.get(name);
  return values ? values[values.length - 1] : undefined;
}

function flagAll(args: ParsedArgs, name: string): string[] {
  return args.flags.get(name) ?? [];
}

function formatArg(args: ParsedArgs): "table" | "json" {
  const f = flag(args, "--format") ?? "table";
  if (f !== "table" && f !== "json") fail(`--format must be table or json, got: ${f}`);
  return f;
}

function renderFindings(result: SanitizeResult, format: "table" | "json"): void {
  if (format === "json") {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (result.findings.length === 0) {
    console.log(`cellrun: ${result.file}: clean (0 findings)`);
    return;
  }
  const rows = result.findings.map((f) => [
    f.severity,
    f.pattern,
    f.location,
    truncateMatch(f.match),
  ]);
  console.log(renderTable(["SEVERITY", "PATTERN", "LOCATION", "MATCH"], rows));
  console.log(
    `${result.high} HIGH, ${result.medium} MEDIUM - ${result.high > 0 ? "BLOCKED (exit 1)" : "warnings only (exit 0)"}`,
  );
}

async function cmdRun(args: ParsedArgs): Promise<number> {
  const network = flag(args, "--network") ?? "off";
  if (network !== "off" && network !== "proxy" && network !== "on") {
    fail(`--network must be off, proxy or on, got: ${network}`);
  }
  const backend = flag(args, "--backend") ?? "local";
  if (backend !== "local" && backend !== "docker") {
    fail(`--backend must be local or docker, got: ${backend}`);
  }
  const isolate = flag(args, "--isolate");
  if (isolate !== undefined && isolate !== "namespaces") {
    fail(`--isolate only supports "namespaces", got: ${isolate}`);
  }
  let timeoutMs = 300_000;
  const timeoutRaw = flag(args, "--timeout");
  if (timeoutRaw !== undefined) {
    try {
      timeoutMs = parseTimeout(timeoutRaw);
    } catch (err) {
      fail((err as Error).message);
    }
  }
  let memoryMb = 0;
  const memoryRaw = flag(args, "--memory");
  if (memoryRaw !== undefined) {
    memoryMb = Number(memoryRaw);
    if (!Number.isInteger(memoryMb) || memoryMb < 0) {
      fail(`--memory must be a non-negative integer (MB), got: ${memoryRaw}`);
    }
    if (memoryMb > 0 && memoryMb < 2048) {
      console.error(
        "cellrun: warning: --memory below 2048 MB breaks Node tasks (ulimit -v counts virtual memory; Node needs ~2 GB of address space to start)",
      );
    }
  }
  const envAdds: Record<string, string> = {};
  for (const pair of flagAll(args, "--env")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) fail(`--env needs KEY=VALUE, got: ${pair}`);
    envAdds[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  const command = args.rest;
  if (command.length === 0) {
    fail("run needs a command after -- (example: cellrun run -- node -e \"console.log(1)\")");
  }
  const sanitizeFile = flag(args, "--sanitize");
  if (sanitizeFile !== undefined && !existsSync(sanitizeFile)) {
    fail(`--sanitize file does not exist: ${sanitizeFile}`);
  }
  const copyDir = flag(args, "--copy");
  if (copyDir !== undefined && !existsSync(copyDir)) {
    fail(`--copy directory does not exist: ${copyDir}`);
  }

  let result;
  try {
    result = await runCell({
      command,
      network: network as "off" | "proxy" | "on",
      proxyUrl: flag(args, "--proxy-url") ?? process.env.CELLRUN_PROXY_URL,
      timeoutMs,
      memoryMb,
      copyDir,
      envAdds,
      isolateNamespaces: isolate !== undefined,
      strict: args.bools.has("--strict"),
      backend: backend as "local" | "docker",
      image: flag(args, "--image") ?? "node:22-slim",
      keep: args.bools.has("--keep"),
      sanitizeFile,
      allowHosts: flagAll(args, "--allow-host"),
    });
  } catch (err) {
    fail((err as Error).message);
  }
  if (result!.blockedBySanitize) {
    renderFindings(
      {
        file: sanitizeFile!,
        findings: result!.sanitizeFindings,
        high: result!.sanitizeFindings.filter((f) => f.severity === "HIGH").length,
        medium: result!.sanitizeFindings.filter((f) => f.severity === "MEDIUM").length,
        clean: false,
      },
      "table",
    );
    console.error("cellrun: run blocked by sanitize gate (HIGH findings in input)");
  }
  return result!.exitCode;
}

function cmdSanitize(args: ParsedArgs): number {
  const file = args.positionals[0];
  if (!file) fail("sanitize needs a file (example: cellrun sanitize output.json)");
  if (!existsSync(file)) fail(`file does not exist: ${file}`);
  const format = formatArg(args);
  const result = scanFile(file, flagAll(args, "--allow-host"));
  renderFindings(result, format);
  if (args.bools.has("--quarantine")) {
    const outPath = quarantineFile(file, result);
    console.log(`cellrun: quarantined copy written to ${outPath}`);
  }
  return result.high > 0 ? 1 : 0;
}

function cmdAudit(args: ParsedArgs): number {
  const format = formatArg(args);
  const cellFilter = flag(args, "--cell");
  const entries = readEntries().filter(
    (e) => !cellFilter || e.cellId === cellFilter || e.cellId.startsWith(cellFilter),
  );
  if (entries.length === 0) {
    console.log("cellrun: no audit entries yet");
    return 0;
  }
  if (format === "json") {
    console.log(JSON.stringify(entries, null, 2));
    return 0;
  }
  const rows = entries
    .slice()
    .reverse()
    .map((e) => [
      e.cellId,
      e.startedAt.slice(0, 19).replace("T", " "),
      truncateMiddle(e.command, 40),
      e.backend,
      e.blockedBySanitize ? "blocked" : `${e.network}${e.networkEnforced ? "" : "*"}`,
      e.blockedBySanitize ? "BLOCKED" : String(e.exitCode),
      formatDuration(e.durationMs),
    ]);
  console.log(
    renderTable(["CELL", "STARTED", "COMMAND", "BACKEND", "NETWORK", "EXIT", "DURATION"], rows),
  );
  if (entries.some((e) => !e.blockedBySanitize && !e.networkEnforced && e.network === "off")) {
    console.log("* network=off was best-effort only for this cell (no namespace/docker enforcement)");
  }
  return 0;
}

function cmdCells(args: ParsedArgs): number {
  const format = formatArg(args);
  const cells = listCells();
  if (cells.length === 0) {
    console.log("cellrun: no cells yet");
    return 0;
  }
  if (format === "json") {
    console.log(JSON.stringify(cells, null, 2));
    return 0;
  }
  const rows = cells.map((c) => [
    c.cellId,
    truncateMiddle(c.command, 36),
    c.backend,
    c.blockedBySanitize ? "blocked" : `${c.network}${c.networkEnforced ? "" : "*"}`,
    c.timedOut ? "TIMEOUT" : String(c.exitCode),
    formatAge(c.endedAt),
    c.alive ? "alive" : "destroyed",
  ]);
  console.log(
    renderTable(["CELL", "COMMAND", "BACKEND", "NETWORK", "EXIT", "AGE", "STATE"], rows),
  );
  if (cells.some((c) => !c.blockedBySanitize && !c.networkEnforced && c.network === "off")) {
    console.log("* network=off was best-effort only for this cell (no namespace/docker enforcement)");
  }
  return 0;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.length === 0) {
    console.error(USAGE);
    return 2;
  }
  if (argv[0] === "--help" || argv[0] === "-h") {
    console.log(USAGE);
    return 0;
  }
  if (argv[0] === "--version" || argv[0] === "-v") {
    console.log(`cellrun ${VERSION}`);
    return 0;
  }
  const [command, ...rest] = argv;
  const args = parseArgs(rest);
  switch (command) {
    case "run":
      return cmdRun(args);
    case "sanitize":
      return cmdSanitize(args);
    case "audit":
      return cmdAudit(args);
    case "cells":
      return cmdCells(args);
    default:
      console.error(`cellrun: unknown command: ${command}\n\n${USAGE}`);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    console.error(`cellrun: ${(err as Error).message}`);
    process.exit(2);
  });
