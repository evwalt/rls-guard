import { test } from "node:test";
import assert from "node:assert/strict";
import { detect, summarize, type TableScan } from "./detect.ts";

// These fixtures are hand-written to mimic the shape of the JSON produced by
// the scan query in README.md, not pulled from a real project. Verifying
// against a real Supabase test project before charging anyone money is a
// separate, required step — see validation-plan.md in founder-os.

test("flags RLS disabled entirely", () => {
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "orders",
      rls_enabled: false,
      policies: [],
      columns: ["id", "user_id", "total"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
  assert.match(findings[0].fixSql, /enable row level security/);
  assert.match(findings[0].fixSql, /auth\.uid\(\) = user_id/);
});

test("flags a permissive USING (true) policy open to anon", () => {
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "messages",
      rls_enabled: true,
      policies: [
        {
          policyname: "allow_all",
          permissive: "PERMISSIVE",
          roles: ["anon", "authenticated"],
          cmd: "SELECT",
          qual: "true",
          with_check: null,
        },
      ],
      columns: ["id", "author_id", "body"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
  assert.match(findings[0].detail, /anon, authenticated/);
});

test("does not flag a properly scoped policy", () => {
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "profiles",
      rls_enabled: true,
      policies: [
        {
          policyname: "owner_only",
          permissive: "PERMISSIVE",
          roles: ["authenticated"],
          cmd: "ALL",
          qual: "(auth.uid() = user_id)",
          with_check: "(auth.uid() = user_id)",
        },
      ],
      columns: ["id", "user_id"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 0);
});

test("does not flag a policy restricted to a non-open role", () => {
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "internal_jobs",
      rls_enabled: true,
      policies: [
        {
          policyname: "service_role_only",
          permissive: "PERMISSIVE",
          roles: ["service_role"],
          cmd: "ALL",
          qual: "true",
          with_check: null,
        },
      ],
      columns: ["id"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 0);
});

test("flags RLS enabled with zero policies as info, not high", () => {
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "locked_out",
      rls_enabled: true,
      policies: [],
      columns: ["id"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "info");
});

test("summarize counts severities correctly", () => {
  const scan: TableScan[] = [
    { schemaname: "public", tablename: "a", rls_enabled: false, policies: [], columns: [] },
    { schemaname: "public", tablename: "b", rls_enabled: true, policies: [], columns: [] },
  ];
  const findings = detect(scan);
  const summary = summarize(findings);
  assert.equal(summary.total, 2);
  assert.equal(summary.high, 1);
  assert.equal(summary.info, 1);
});
