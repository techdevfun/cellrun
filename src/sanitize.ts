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
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    const m = re.exec(text);
    if (m) {
      findings.push({
        pattern: pattern.id,
        severity: pattern.severity,
        location,
        match: m[0],
      });
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

/** Replace each finding's matched span with [REDACTED] (first occurrence each). */
export function redactContent(content: string, findings: SanitizeFinding[]): string {
  let out = content;
  for (const finding of findings) {
    const idx = out.indexOf(finding.match);
    if (idx === -1) continue;
    out = out.slice(0, idx) + "[REDACTED]" + out.slice(idx + finding.match.length);
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
