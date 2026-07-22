import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeScanInput } from "./normalize-scan-input.ts";

const table = {
  schemaname: "public",
  tablename: "orders",
  rls_enabled: true,
  policies: [],
  columns: [],
};

test("passes through the existing direct table array unchanged", () => {
  const input = [table];
  assert.deepEqual(normalizeScanInput(input), input);
});

test("does not unwrap a normal one-element scan array that has no scan_result key", () => {
  const input = [table];
  assert.deepEqual(normalizeScanInput(input), input);
});

test("unwraps a one-element array wrapping scan_result (Supabase 'copy row' shape)", () => {
  const input = [{ scan_result: [table] }];
  assert.deepEqual(normalizeScanInput(input), [table]);
});

test("unwraps a bare object wrapping scan_result", () => {
  const input = { scan_result: [table] };
  assert.deepEqual(normalizeScanInput(input), [table]);
});

test("rejects a wrapper whose scan_result is not an array", () => {
  assert.equal(normalizeScanInput({ scan_result: "not an array" }), null);
  assert.equal(normalizeScanInput([{ scan_result: null }]), null);
});

test("rejects input that is neither a table array nor a recognized wrapper", () => {
  assert.equal(normalizeScanInput({ tables: [table] }), null);
  assert.equal(normalizeScanInput("just a string"), null);
  assert.equal(normalizeScanInput(42), null);
  assert.equal(normalizeScanInput(null), null);
});

test("does not recursively search nested objects for a scan_result key", () => {
  const input = { data: { scan_result: [table] } };
  assert.equal(normalizeScanInput(input), null);
});
