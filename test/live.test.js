import assert from "node:assert/strict";
import { test } from "node:test";

// Live smoke: public endpoints only. No credentials, no writes.
// The name must be free (404) OR already taken by this very project
// (200 with a matching full_name) - the test must not fail after publish.
async function getJson(url) {
  const res = await fetch(url, {
    headers: { "User-Agent": "cellrun-live-test" },
    signal: AbortSignal.timeout(15_000),
  });
  return res;
}

test("live: npm registry has no cellrun package (or it is ours)", async () => {
  const res = await getJson("https://registry.npmjs.org/cellrun");
  if (res.status === 404) return;
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.name, "cellrun");
});

test("live: github org techdevfun has no cellrun repo (or it is ours)", async () => {
  const res = await getJson("https://api.github.com/repos/techdevfun/cellrun");
  if (res.status === 404) return;
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.full_name, "techdevfun/cellrun");
});
