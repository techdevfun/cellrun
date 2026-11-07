/**
 * Run one task in a fresh cell.
 *
 * A cell is a fresh temporary directory, a scrubbed environment (HOME and
 * TMPDIR remapped inside the cell), and - on Linux, when user namespaces
 * are available - a network namespace with no interfaces when
 * --network off (the default). The cell directory is destroyed when the
 * task ends unless --keep is given. Everything is recorded in the audit
 * log, including whether the network mode was actually enforced by the
 * OS; a mode that was only "best effort" is recorded as such, never
 * claimed as enforced.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { buildCellEnv } from "./env.js";
import { appendEntry } from "./audit.js";
import { scanFile } from "./sanitize.js";
import { formatDuration } from "./render.js";
import type { AuditEntry, RunOptions, SanitizeFinding } from "./types.js";

export interface RunResult {
  cellId: string;
  cellDir: string;
  exitCode: number;
  timedOut: boolean;
  networkEnforced: boolean;
  durationMs: number;
  blockedBySanitize: boolean;
  filesCreated: string[];
  fileCount: number;
  sanitizeFindings: SanitizeFinding[];
}

export function newCellId(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `cell-${stamp}-${randomBytes(3).toString("hex")}`;
}

let namespacesProbe: boolean | null = null;

/** True when `unshare` can create a user+net+pid namespace here. */
export function namespacesAvailable(): boolean {
  if (namespacesProbe !== null) return namespacesProbe;
  if (process.platform === "win32") {
    namespacesProbe = false;
    return false;
  }
  try {
    const probe = spawnSync(
      "unshare",
      ["--user", "--map-root-user", "--net", "--pid", "--fork", "--", "true"],
      { stdio: "ignore", timeout: 10_000 },
    );
    namespacesProbe = probe.status === 0;
  } catch {
    namespacesProbe = false;
  }
  return namespacesProbe;
}

export function parseTimeout(value: string): number {
  const m = /^(\d+)(s|m)?$/.exec(value.trim());
  if (!m) throw new Error(`invalid --timeout value: ${value} (use like 300s, 5m, 90)`);
  const n = Number(m[1]);
  return m[2] === "m" ? n * 60_000 : n * 1000;
}

function listCellFiles(cellDir: string): { names: string[]; count: number } {
  try {
    const entries = readdirSync(cellDir);
    return { names: entries.slice(0, 20), count: entries.length };
  } catch {
    return { names: [], count: 0 };
  }
}

function record(entry: AuditEntry): void {
  try {
    appendEntry(entry);
  } catch (err) {
    console.error(
      `cellrun: warning: could not write audit log: ${(err as Error).message}`,
    );
  }
}

export async function runCell(options: RunOptions): Promise<RunResult> {
  const cellId = newCellId();
  const cellDir = mkdtempSync(join(tmpdir(), "cellrun-"));
  const startedAt = new Date().toISOString();
  const started = Date.now();
  const commandText = options.command.join(" ");

  const finish = (
    partial: Omit<
      AuditEntry,
      "cellId" | "cellDir" | "startedAt" | "endedAt" | "durationMs"
    >,
    endedAt: Date,
  ): AuditEntry => {
    const entry: AuditEntry = {
      cellId,
      cellDir,
      startedAt,
      endedAt: endedAt.toISOString(),
      durationMs: endedAt.getTime() - started,
      ...partial,
    };
    record(entry);
    return entry;
  };

  // Optional sanitize gate: refuse to run when the input is hostile.
  let sanitizeFindings: SanitizeFinding[] = [];
  if (options.sanitizeFile) {
    const result = scanFile(options.sanitizeFile, options.allowHosts);
    sanitizeFindings = result.findings;
    if (result.high > 0) {
      const ended = new Date();
      finish(
        {
          command: commandText,
          backend: options.backend,
          network: options.network,
          networkEnforced: false,
          isolateNamespaces: options.isolateNamespaces,
          exitCode: 1,
          timedOut: false,
          blockedBySanitize: true,
          filesCreated: [],
          fileCount: 0,
          sanitizeFindings,
        },
        ended,
      );
      rmSync(cellDir, { recursive: true, force: true });
      return {
        cellId,
        cellDir,
        exitCode: 1,
        timedOut: false,
        networkEnforced: false,
        durationMs: ended.getTime() - started,
        blockedBySanitize: true,
        filesCreated: [],
        fileCount: 0,
        sanitizeFindings,
      };
    }
  }

  // Snapshot a project directory into the cell, if asked.
  if (options.copyDir) {
    if (!existsSync(options.copyDir)) {
      rmSync(cellDir, { recursive: true, force: true });
      throw new Error(`--copy directory does not exist: ${options.copyDir}`);
    }
    cpSync(options.copyDir, cellDir, { recursive: true });
  }

  // Proxy mode needs a proxy URL, or it is just "on" with a nicer name.
  if (options.network === "proxy" && !options.proxyUrl) {
    rmSync(cellDir, { recursive: true, force: true });
    throw new Error(
      "--network proxy needs --proxy-url (or CELLRUN_PROXY_URL)",
    );
  }

  const { env, droppedCount } = buildCellEnv(
    cellDir,
    cellId,
    options.network,
    options.envAdds,
  );
  if (options.network === "proxy" && options.proxyUrl) {
    env.http_proxy = options.proxyUrl;
    env.https_proxy = options.proxyUrl;
    env.HTTP_PROXY = options.proxyUrl;
    env.HTTPS_PROXY = options.proxyUrl;
  }
  if (droppedCount > 0) {
    console.error(
      `cellrun: scrubbed environment (${droppedCount} host variables dropped, HOME/TMPDIR remapped into the cell)`,
    );
  }

  let networkEnforced = false;
  let argv: string[];
  let spawnEnv: Record<string, string> = env;
  let dockerName = "";

  if (options.backend === "docker") {
    const dockerCheck = spawnSync("docker", ["version"], { stdio: "ignore" });
    if (dockerCheck.error || dockerCheck.status !== 0) {
      rmSync(cellDir, { recursive: true, force: true });
      throw new Error(
        "docker is not available on this machine (--backend docker needs a local Docker daemon)",
      );
    }
    dockerName = `cellrun-${cellId}`;
    const dockerEnv: Record<string, string> = { ...env, HOME: "/cell", TMPDIR: "/cell" };
    const envArgs: string[] = [];
    for (const [k, v] of Object.entries(dockerEnv)) envArgs.push("-e", `${k}=${v}`);
    argv = [
      "docker",
      "run",
      "--rm",
      "--name",
      dockerName,
      "-v",
      `${cellDir}:/cell`,
      "-w",
      "/cell",
      ...(options.network === "off" ? ["--network", "none"] : []),
      ...envArgs,
      options.image,
      ...options.command,
    ];
    networkEnforced = options.network === "off";
    spawnEnv = process.env as Record<string, string>;
  } else {
    let cmd: string[] = [...options.command];
    // Optional virtual-memory guardrail. ulimit -v counts virtual memory;
    // Node needs ~2 GB of address space just to start, so values below
    // 2048 break Node tasks - the flag is opt-in for that reason.
    if (options.memoryMb > 0 && process.platform !== "win32") {
      cmd = [
        "sh",
        "-c",
        `ulimit -v ${options.memoryMb * 1024}; exec "$@"`,
        "sh",
        ...cmd,
      ];
    }
    const wantNamespaces =
      options.isolateNamespaces ||
      (options.network === "off" && process.platform === "linux");
    if (wantNamespaces) {
      if (namespacesAvailable()) {
        argv = [
          "unshare",
          "--user",
          "--map-root-user",
          ...(options.network === "off" ? ["--net"] : []),
          "--pid",
          "--fork",
          "--",
          ...cmd,
        ];
        networkEnforced = options.network === "off";
      } else if (options.strict) {
        rmSync(cellDir, { recursive: true, force: true });
        throw new Error(
          "user namespaces are unavailable on this machine (--isolate namespaces --strict refuses to run degraded)",
        );
      } else {
        console.error(
          "cellrun: warning: user namespaces unavailable - network=off is NOT enforced by the OS on this machine (environment scrubbed, no proxy set)",
        );
        argv = cmd;
      }
    } else {
      if (options.network === "off") {
        console.error(
          "cellrun: warning: network=off without namespaces on this platform is best-effort only (environment scrubbed, no proxy set)",
        );
      }
      argv = cmd;
    }
  }

  const result = await spawnAndWait(
    argv,
    spawnEnv,
    cellDir,
    options.timeoutMs,
    dockerName,
  );
  const ended = new Date();
  const { names, count } = listCellFiles(cellDir);
  finish(
    {
      command: commandText,
      backend: options.backend,
      network: options.network,
      networkEnforced,
      isolateNamespaces: options.isolateNamespaces,
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      blockedBySanitize: false,
      filesCreated: names,
      fileCount: count,
      sanitizeFindings,
    },
    ended,
  );

  if (!options.keep) {
    rmSync(cellDir, { recursive: true, force: true });
  }
  console.error(
    `cellrun: cell ${cellId} exited ${result.exitCode} in ${formatDuration(ended.getTime() - started)} (network enforced: ${networkEnforced ? "yes" : "no"})`,
  );

  return {
    cellId,
    cellDir,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    networkEnforced,
    durationMs: ended.getTime() - started,
    blockedBySanitize: false,
    filesCreated: names,
    fileCount: count,
    sanitizeFindings,
  };
}

function spawnAndWait(
  argv: string[],
  env: Record<string, string>,
  cellDir: string,
  timeoutMs: number,
  dockerName: string,
): Promise<{ exitCode: number; timedOut: boolean }> {
  return new Promise((resolve) => {
    let timedOut = false;
    const child: ChildProcess = spawn(argv[0], argv.slice(1), {
      env,
      cwd: cellDir,
      stdio: ["ignore", "inherit", "inherit"],
      detached: process.platform !== "win32",
    });
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
      if (dockerName) {
        spawnSync("docker", ["kill", dockerName], { stdio: "ignore" });
      }
    }, timeoutMs);
    if (typeof timer === "object" && "unref" in timer) {
      (timer as { unref: () => void }).unref();
    }
    child.on("error", (err) => {
      clearTimeout(timer);
      console.error(`cellrun: failed to start cell: ${(err as Error).message}`);
      resolve({ exitCode: 2, timedOut: false });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ exitCode: timedOut ? 124 : (code ?? 2), timedOut });
    });
  });
}
