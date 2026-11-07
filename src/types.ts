export type NetworkMode = "off" | "proxy" | "on";
export type Backend = "local" | "docker";

export interface RunOptions {
  command: string[];
  network: NetworkMode;
  proxyUrl?: string;
  timeoutMs: number;
  /** 0 = no virtual-memory limit. ulimit -v counts virtual memory; Node
   *  needs ~2 GB of address space just to start, so values below 2048
   *  will break Node tasks. The limit is a guardrail, not a sandbox. */
  memoryMb: number;
  copyDir?: string;
  envAdds: Record<string, string>;
  isolateNamespaces: boolean;
  strict: boolean;
  backend: Backend;
  image: string;
  keep: boolean;
  sanitizeFile?: string;
  allowHosts: string[];
}

export type Severity = "HIGH" | "MEDIUM";

export interface SanitizeFinding {
  pattern: string;
  severity: Severity;
  /** 1-based line for text input; JSON path (e.g. $.tools[0].description) for JSON input. */
  location: string;
  match: string;
}

export interface SanitizeResult {
  file: string;
  findings: SanitizeFinding[];
  high: number;
  medium: number;
  clean: boolean;
}

export interface AuditEntry {
  cellId: string;
  cellDir: string;
  command: string;
  backend: Backend;
  network: NetworkMode;
  /** True only when the network mode was enforced by the OS (network
   *  namespace or docker --network none). False means "best effort":
   *  env scrubbed, no proxy, but the kernel did not block the socket. */
  networkEnforced: boolean;
  isolateNamespaces: boolean;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  exitCode: number | null;
  timedOut: boolean;
  blockedBySanitize: boolean;
  filesCreated: string[];
  fileCount: number;
  sanitizeFindings: SanitizeFinding[];
}
