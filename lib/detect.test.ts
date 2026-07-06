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

test("does not flag a properly scoped SELECT-only policy (with_check is null but inapplicable)", () => {
  // Real-project verification (2026-07-06) caught this: with_check is
  // legitimately null for SELECT policies (WITH CHECK doesn't apply to
  // SELECT), but the old code treated any null as "unrestricted," so this
  // shape — the single most common correct RLS pattern — was a false
  // positive on every real Supabase project tested.
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "profiles",
      rls_enabled: true,
      policies: [
        {
          policyname: "profiles_owner_only",
          permissive: "PERMISSIVE",
          roles: ["authenticated"],
          cmd: "SELECT",
          qual: "(user_id = auth.uid())",
          with_check: null,
        },
      ],
      columns: ["id", "user_id", "bio"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 0);
});

test("does not flag a RESTRICTIVE policy, even with USING (true) open to anon", () => {
  // Real-project verification also caught this: a RESTRICTIVE policy only
  // narrows access (ANDed with permissive policies) — it can never grant
  // access on its own, so USING (true) on a restrictive policy is a no-op,
  // not a vulnerability.
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "audit_log",
      rls_enabled: true,
      policies: [
        {
          policyname: "audit_log_base",
          permissive: "PERMISSIVE",
          roles: ["authenticated"],
          cmd: "SELECT",
          qual: "(owner_id = auth.uid())",
          with_check: null,
        },
        {
          policyname: "audit_log_restrictive",
          permissive: "RESTRICTIVE",
          roles: ["anon", "authenticated"],
          cmd: "SELECT",
          qual: "true",
          with_check: null,
        },
      ],
      columns: ["id", "owner_id", "entry"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 0);
});

test("flags an INSERT-only policy open via WITH CHECK (qual is null but inapplicable)", () => {
  const scan: TableScan[] = [
    {
      schemaname: "public",
      tablename: "signups",
      rls_enabled: true,
      policies: [
        {
          policyname: "signups_open_insert",
          permissive: "PERMISSIVE",
          roles: ["public"],
          cmd: "INSERT",
          qual: null,
          with_check: "true",
        },
      ],
      columns: ["id", "created_by", "email"],
    },
  ];
  const findings = detect(scan);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
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
