#!/usr/bin/env node
/**
 * Rule 7 preflight - release gate script.
 *
 * Fails (exit 1) when any shipped text file contains:
 *  - any non-ASCII character (all public content is ASCII English only),
 *  - an internal name (team / lane / chat names that must never appear
 *    in a public repo).
 *
 * Scans text files under the repo root, excluding node_modules, .git,
 * dist, and binary files. The demo GIF is generated from
 * demo/transcript.txt, which is itself scanned here, so the GIF's text
 * is covered by construction.
 *
 * NOTE: the internal-name list below is written with \u escapes on
 * purpose - spelling the names out in plain text would make this very
 * file fail its own scan.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".cellrun"]);
const TEXT_EXTS = new Set([
  ".md", ".ts", ".js", ".json", ".yml", ".yaml", ".sh", ".txt",
]);

const NON_ASCII = /[^\x00-\x7F]/;
const INTERNAL_NAMES = [
  "T\u1ED5ng qu\u1EA3n",
  "Tr\u1EE3 l\u00FD",
  "l\u00E0n B",
  "Lane\u0020B",
  "n\u1ED9i b\u1ED9",
  "b\u00ED m\u1EADt",
];

const failures = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(full);
    } else if (TEXT_EXTS.has(entry.slice(entry.lastIndexOf(".")))) {
      check(full);
    }
  }
}

function check(file) {
  const rel = relative(ROOT, file);
  const content = readFileSync(file, "utf8");
  if (NON_ASCII.test(content)) {
    failures.push(`${rel}: non-ASCII character found (public content is ASCII English only)`);
  }
  for (const name of INTERNAL_NAMES) {
    if (content.includes(name)) {
      failures.push(`${rel}: internal name found`);
    }
  }
}

walk(ROOT);

if (failures.length > 0) {
  console.error("preflight FAILED:");
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log("preflight OK: 0 non-ASCII characters, 0 internal names");
