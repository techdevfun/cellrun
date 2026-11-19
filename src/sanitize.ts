/**
 * Pattern-based sanitizer for tool / MCP / web output.
 *
 * Scans text (or JSON string values) for instruction-injection patterns
 * before the output enters agent context. This is a pattern gate, not a
 * model judge: novel phrasings can slip past it, and legitimate docs can
 * trip the MEDIUM patterns. That is why the severities exist - HIGH is
 * the gate (exit 1), MEDIUM is a warning (exit 0) - and why the README
 * states the residual risk in plain language.
 *
 * Never prints full file contents: only flagged lines, truncated.
 */
import { readFileSync, writeFileSync } from "node:fs";
import type { SanitizeFinding, SanitizeResult, Severity } from "./types.js";

interface Pattern {
  id: string;
  severity: Severity;
  regex: RegExp;
}

const PATTERNS: Pattern[] = [
  {
    id: "ignore-previous-instructions",
    severity: "HIGH",
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
  },
  {
    id: "disregard-instructions",
    severity: "HIGH",
    regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidance)/i,
  },
  {
    id: "override-safety",
    severity: "HIGH",
    regex: /(override|bypass|disable)\s+(safety|policy|guardrails?|restrictions?|content\s+filters?)/i,
  },
  {
    id: "reveal-system-prompt",
    severity: "HIGH",
    regex: /(reveal|show|print|output|disclose|share)\s+(the\s+)?(system\s+prompt|your\s+instructions|hidden\s+instructions)/i,
  },
  {
    id: "exfiltrate-credentials",
    severity: "HIGH",
    regex: /(send|post|upload|share|exfiltrate|leak|transmit)\b[^.\n]{0,80}\b(api[-_ ]?key|secret|token|password|credential|private\s+key)/i,
  },
  {
    id: "credentials-then-send",
    severity: "HIGH",
    regex: /\b(api[-_ ]?key|secret|token|password|credential|private\s+key)\b[^.\n]{0,80}\b(send|post|upload|share|exfiltrate|leak|transmit)\b/i,
  },
  {
    id: "conceal-from-user",
    severity: "HIGH",
    regex: /(do\s+not|don't|never)\s+(tell|mention|reveal|disclose|show|inform)\s+(the\s+)?user/i,
  },
  {
    id: "imperative-you-must",
    severity: "MEDIUM",
    regex: /\byou\s+(must|have\s+to|need\s+to)\b/i,
  },
  {
    id: "pipe-to-shell",
    severity: "MEDIUM",
    regex: /\b(curl|wget)\b[^|\n]{0,80}\|\s*(sh|bash)\b/i,
  },
  {
    id: "ignore-warning",
    severity: "MEDIUM",
    regex: /ignore\s+(the\s+)?(warning|error|alert)/i,
  },
];

const URL_RE = /https?:\/\/([A-Za-z0-9._-]+)(?::\d+)?/g;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

export function truncateMatch(s: string, max = 120): string {
  return s.length > max ? s.slice(0, max - 3) + "..." : s;
}

function scanChunk(
  text: string,
  location: string,
  allowHosts: Set<string>,
  findings: SanitizeFinding[],
): void {
  for (const pattern of PATTERNS) {
    // Report every match, not just the first: one chunk can contain the
    // same injection twice, and the quarantine redaction keys off this
    // list - a missed second occurrence used to survive redaction.
    const flags = pattern.regex.flags.includes("g")
      ? pattern.regex.flags
      : `${pattern.regex.flags}g`;
    const re = new RegExp(pattern.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      findings.push({
        pattern: pattern.id,
        severity: pattern.severity,
        location,
        match: m[0],
      });
      // Guard against an empty match looping forever (no current
      // pattern can match empty, this is belt-and-braces).
      if (m[0].length === 0) re.lastIndex++;
    }
  }
  // External URLs: flagged MEDIUM unless the host is allowlisted.
  URL_RE.lastIndex = 0;
  let urlMatch: RegExpExecArray | null;
  while ((urlMatch = URL_RE.exec(text)) !== null) {
    const host = urlMatch[1].toLowerCase();
    if (LOCAL_HOSTS.has(host) || allowHosts.has(host)) continue;
    findings.push({
      pattern: "external-url",
      severity: "MEDIUM",
      location,
      match: urlMatch[0],
    });
  }
}

export function scanTextContent(
  content: string,
  allowHosts: string[],
): SanitizeFinding[] {
  const allow = new Set(allowHosts.map((h) => h.toLowerCase()));
  const findings: SanitizeFinding[] = [];
  const lines = content.split("\n");
  lines.forEach((line, i) => {
    scanChunk(line, `line ${i + 1}`, allow, findings);
  });
  return findings;
}

function walkJson(
  value: unknown,
  path: string,
  allow: Set<string>,
  findings: SanitizeFinding[],
): void {
  if (typeof value === "string") {
    scanChunk(value, path, allow, findings);
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => walkJson(item, `${path}[${i}]`, allow, findings));
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      walkJson(item, `${path}.${key}`, allow, findings);
    }
  }
}

export function scanFile(file: string, allowHosts: string[]): SanitizeResult {
  const content = readFileSync(file, "utf8");
  const allow = new Set(allowHosts.map((h) => h.toLowerCase()));
  let findings: SanitizeFinding[] = [];

  const trimmed = content.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(content);
      walkJson(parsed, "$", allow, findings);
    } catch {
      // Not valid JSON after all - fall back to a line scan.
      findings = scanTextContent(content, allowHosts);
    }
  } else {
    findings = scanTextContent(content, allowHosts);
  }

  const high = findings.filter((f) => f.severity === "HIGH").length;
  const medium = findings.length - high;
  return { file, findings, high, medium, clean: findings.length === 0 };
}

/** Replace every occurrence of each finding's matched span with [REDACTED]. */
export function redactContent(content: string, findings: SanitizeFinding[]): string {
  let out = content;
  for (const finding of findings) {
    // Replace ALL occurrences, not just the first: findings are recorded
    // per line, so a second copy of the same span later in the file used
    // to survive quarantine untouched - a rescan of the quarantined file
    // still flagged it HIGH.
    if (finding.match.length === 0) continue;
    out = out.split(finding.match).join("[REDACTED]");
  }
  return out;
}

export function quarantineFile(file: string, result: SanitizeResult): string {
  const content = readFileSync(file, "utf8");
  const redacted = redactContent(content, result.findings);
  const outPath = `${file}.quarantined`;
  writeFileSync(outPath, redacted, "utf8");
  return outPath;
}
