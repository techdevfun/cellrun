# Fixture provenance

Both fixtures are **synthetic, hand-written by the author** for the test
suite. They are not copied from any real service, tool, or web page.

- `tool-output-injection.json` - a fake MCP-style tool result whose
  `result.content` carries three HIGH-severity instruction-injection
  patterns (ignore-previous-instructions, exfiltrate-credentials,
  conceal-from-user) plus one MEDIUM external-URL finding (the
  `evil.example.com` exfiltration target). The `evil.example.com`
  domain is reserved for documentation (RFC 2606) and never resolves.
- `tool-output-clean.json` - the same shape with plain instructions and
  no URLs, no imperatives, no injection. Scans clean (0 findings).

Expected counts are asserted in `test/unit.test.js`; if a pattern is
added or changed, update the fixture counts in the same commit.
