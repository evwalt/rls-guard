// Scale benchmark for detect(): builds synthetic schemas that mirror the
// 7-table real-Postgres verification mix (verification/schema.sql), runs the
// detector, checks findings against the known ground truth, and times it.
//
//   node --import tsx bench/detect-bench.ts

import { performance } from "node:perf_hooks";
import { detect, type TableScan, type PolicyRow } from "../lib/detect.ts";

const ownerSelect: PolicyRow = {
  policyname: "owner_select", permissive: "PERMISSIVE", roles: ["authenticated"],
  cmd: "SELECT", qual: "(auth.uid() = user_id)", with_check: null,
};
const openAll: PolicyRow = {
  policyname: "open_all", permissive: "PERMISSIVE", roles: ["anon"],
  cmd: "ALL", qual: "true", with_check: "true",
};
const restrictiveTrue: PolicyRow = {
  policyname: "restrictive_noop", permissive: "RESTRICTIVE", roles: ["authenticated"],
  cmd: "SELECT", qual: "true", with_check: null,
};

// Each kind: [table builder, expected high findings, expected info findings]
type Kind = [(i: number) => TableScan, number, number];
const cols = ["id", "user_id", "body"];
const kinds: Kind[] = [
  [(i) => ({ schemaname: "public", tablename: `t${i}_rls_off`, rls_enabled: false, policies: [], columns: cols }), 1, 0],
  [(i) => ({ schemaname: "public", tablename: `t${i}_no_policies`, rls_enabled: true, policies: [], columns: cols }), 0, 1],
  [(i) => ({ schemaname: "public", tablename: `t${i}_open`, rls_enabled: true, policies: [openAll], columns: cols }), 1, 0],
  [(i) => ({ schemaname: "public", tablename: `t${i}_owner`, rls_enabled: true, policies: [ownerSelect], columns: cols }), 0, 0],
  [(i) => ({ schemaname: "public", tablename: `t${i}_owner_restrictive`, rls_enabled: true, policies: [ownerSelect, restrictiveTrue], columns: cols }), 0, 0],
];

function build(n: number) {
  const tables: TableScan[] = [];
  let high = 0, info = 0;
  for (let i = 0; i < n; i++) {
    const [make, h, f] = kinds[i % kinds.length];
    tables.push(make(i)); high += h; info += f;
  }
  return { tables, high, info };
}

for (const n of [100, 1_000, 10_000]) {
  const { tables, high, info } = build(n);
  for (let w = 0; w < 5; w++) detect(tables);
  const runs: number[] = [];
  let findings = detect(tables);
  for (let r = 0; r < 20; r++) {
    const t = performance.now();
    findings = detect(tables);
    runs.push(performance.now() - t);
  }
  runs.sort((a, b) => a - b);
  const gotHigh = findings.filter((f) => f.severity === "high").length;
  const gotInfo = findings.filter((f) => f.severity === "info").length;
  const ok = gotHigh === high && gotInfo === info;
  console.log(
    `${String(n).padStart(6)} tables: median ${runs[10].toFixed(2)} ms, ` +
    `findings high ${gotHigh}/${high} info ${gotInfo}/${info} ${ok ? "OK (0 false positives, 0 misses)" : "MISMATCH"}`,
  );
  if (!ok) process.exitCode = 1;
}
