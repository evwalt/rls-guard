// Pure detection logic. Runs entirely in the browser — the pasted scan
// output (table/policy metadata, never row data) is never sent to our
// server. Keep this file free of side effects so it stays trivially
// testable and auditable by a skeptical technical reader.

export type PolicyRow = {
  policyname: string;
  permissive: string; // "PERMISSIVE" | "RESTRICTIVE"
  roles: string[];
  cmd: string; // "ALL" | "SELECT" | "INSERT" | "UPDATE" | "DELETE"
  qual: string | null;
  with_check: string | null;
};

export type TableScan = {
  schemaname: string;
  tablename: string;
  rls_enabled: boolean;
  policies: PolicyRow[];
  columns: string[];
};

export type Finding = {
  table: string;
  severity: "high" | "info";
  title: string;
  detail: string;
  fixSql: string;
};

const OPEN_ROLES = new Set(["anon", "authenticated", "public"]);
const OWNERSHIP_COLUMN_PATTERNS = [
  "user_id",
  "owner_id",
  "created_by",
  "author_id",
  "profile_id",
  "account_id",
];

function looksUnrestricted(qual: string | null): boolean {
  if (qual === null) return true;
  const normalized = qual.trim().toLowerCase();
  return normalized === "true" || normalized === "(true)";
}

// `qual` (USING) only governs SELECT/UPDATE/DELETE/ALL; `with_check` (WITH
// CHECK) only governs INSERT/UPDATE/ALL. Postgres leaves the inapplicable
// column null (e.g. a SELECT policy always has with_check = null) — that
// null must not be read as "no restriction," or every correctly-scoped
// single-purpose policy gets flagged as wide open.
function qualApplies(cmd: string): boolean {
  return cmd === "ALL" || cmd === "SELECT" || cmd === "UPDATE" || cmd === "DELETE";
}
function withCheckApplies(cmd: string): boolean {
  return cmd === "ALL" || cmd === "INSERT" || cmd === "UPDATE";
}

function guessOwnershipColumn(columns: string[]): string | null {
  const lower = columns.map((c) => c.toLowerCase());
  for (const pattern of OWNERSHIP_COLUMN_PATTERNS) {
    const idx = lower.indexOf(pattern);
    if (idx !== -1) return columns[idx];
  }
  return null;
}

export function detect(scan: TableScan[]): Finding[] {
  const findings: Finding[] = [];

  for (const table of scan) {
    const qualifiedName = `${table.schemaname}.${table.tablename}`;

    if (!table.rls_enabled) {
      const ownershipCol = guessOwnershipColumn(table.columns);
      const suggestedPolicy = ownershipCol
        ? `create policy "owner_can_access" on ${qualifiedName}\n  for all\n  using (auth.uid() = ${ownershipCol})\n  with check (auth.uid() = ${ownershipCol});`
        : `-- No obvious ownership column was found on this table.\n-- Review who should be able to read/write these rows before writing a policy.\ncreate policy "restrict_access" on ${qualifiedName}\n  for all\n  using (/* your condition here */ false);`;

      findings.push({
        table: qualifiedName,
        severity: "high",
        title: "Row-Level Security is not enabled",
        detail:
          "Any client holding your anon or service API key can read and write every row in this table, with no per-user restriction, unless something else in your stack is blocking it.",
        fixSql: `alter table ${qualifiedName} enable row level security;\n\n${suggestedPolicy}`,
      });
      continue;
    }

    if (table.policies.length === 0) {
      findings.push({
        table: qualifiedName,
        severity: "info",
        title: "RLS is enabled but no policies exist",
        detail:
          "With RLS on and zero policies, Postgres denies all access by default. This is not a security hole, but it commonly means the app's own reads/writes to this table are silently failing.",
        fixSql: `-- Add a policy scoped to how this table should actually be accessed, e.g.:\ncreate policy "owner_can_access" on ${qualifiedName}\n  for all\n  using (auth.uid() = /* your ownership column */);`,
      });
      continue;
    }

    for (const policy of table.policies) {
      // RESTRICTIVE policies can only narrow access (ANDed with permissive
      // policies) — they never grant it on their own, so one can never be
      // the thing that makes a table "unrestricted."
      if (policy.permissive === "RESTRICTIVE") continue;

      const openRoles = policy.roles.filter((r) => OPEN_ROLES.has(r));
      if (openRoles.length === 0) continue;

      const qualOpen = qualApplies(policy.cmd) && looksUnrestricted(policy.qual);
      const withCheckOpen =
        withCheckApplies(policy.cmd) && looksUnrestricted(policy.with_check);

      if (qualOpen || withCheckOpen) {
        const ownershipCol = guessOwnershipColumn(table.columns);
        const suggestion = ownershipCol
          ? `auth.uid() = ${ownershipCol}`
          : `/* replace with an actual ownership condition — no obvious owner column found */`;

        // Postgres rejects USING on a FOR INSERT policy and rejects WITH
        // CHECK on FOR SELECT/DELETE policies — only emit the clauses that
        // are valid for this policy's command, same rule qualApplies /
        // withCheckApplies already encode for detection.
        const clauses: string[] = [];
        if (qualApplies(policy.cmd)) clauses.push(`  using (${suggestion})`);
        if (withCheckApplies(policy.cmd)) clauses.push(`  with check (${suggestion})`);

        findings.push({
          table: qualifiedName,
          severity: "high",
          title: `Policy "${policy.policyname}" allows unrestricted access`,
          detail: `Role(s) ${openRoles.join(", ")} can ${policy.cmd} every row in this table with no restriction (USING/WITH CHECK evaluates to true).`,
          fixSql: `drop policy "${policy.policyname}" on ${qualifiedName};\n\ncreate policy "${policy.policyname}" on ${qualifiedName}\n  for ${policy.cmd.toLowerCase()}\n  to ${policy.roles.join(", ")}\n${clauses.join("\n")};`,
        });
      }
    }
  }

  return findings;
}

export function summarize(findings: Finding[]) {
  return {
    total: findings.length,
    high: findings.filter((f) => f.severity === "high").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
}
