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

export type FindingCategory =
  | "rls_disabled"
  | "rls_no_policies"
  | "policy_overly_permissive";

export type Finding = {
  table: string;
  severity: "high" | "info";
  category: FindingCategory;
  title: string;
  detail: string;
  fixSql: string;
  // Only set for policy_overly_permissive findings. Command type (SELECT,
  // INSERT, ...) is generic metadata, not an identifying detail, so it is
  // safe to surface in the pre-paywall category summary alongside the count.
  cmd?: string;
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
        category: "rls_disabled",
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
        category: "rls_no_policies",
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
          : `/* replace with an actual ownership condition: no obvious owner column found */`;

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
          category: "policy_overly_permissive",
          cmd: policy.cmd,
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

// Metadata about the scan itself (breadth of what was analyzed), as opposed
// to what was found. Derived from the same TableScan[] the user pasted in,
// not a separate source of truth.
export type ScanMeta = {
  tablesScanned: number;
  policiesAnalyzed: number;
};

export function scanMeta(scan: TableScan[]): ScanMeta {
  return {
    tablesScanned: scan.length,
    policiesAnalyzed: scan.reduce((sum, t) => sum + t.policies.length, 0),
  };
}

export type CategorySummaryLine = {
  category: FindingCategory;
  count: number;
  text: string;
};

function pluralize(count: number, singular: string, plural: string): string {
  return count === 1 ? singular : plural;
}

// Groups findings into the categories a first-time visitor can use to sanity
// check that real analysis happened, without leaking anything the paywall
// is meant to protect (no table names, no policy names, no SQL). Grouped
// straight off Finding.category (set where each finding is created above),
// never parsed back out of title/detail strings.
export function categorizeFindings(findings: Finding[]): CategorySummaryLine[] {
  const order: string[] = [];
  const groups = new Map<string, { category: FindingCategory; count: number; cmd?: string }>();

  for (const f of findings) {
    const key = f.category === "policy_overly_permissive" ? `${f.category}:${f.cmd}` : f.category;
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      groups.set(key, { category: f.category, count: 1, cmd: f.cmd });
      order.push(key);
    }
  }

  return order.map((key) => {
    const g = groups.get(key)!;
    return { category: g.category, count: g.count, text: categoryText(g) };
  });
}

function categoryText(g: { category: FindingCategory; count: number; cmd?: string }): string {
  const { category, count, cmd } = g;

  if (category === "rls_disabled") {
    const noun = pluralize(count, "table", "tables");
    const verb = pluralize(count, "has", "have");
    return `${count} ${noun} ${verb} RLS disabled`;
  }

  if (category === "rls_no_policies") {
    const noun = pluralize(count, "table", "tables");
    const verb = pluralize(count, "has", "have");
    return `${count} ${noun} ${verb} RLS enabled but ${verb} no policies`;
  }

  const noun = pluralize(count, "policy", "policies");
  const verb = pluralize(count, "is", "are");
  return `${count} ${cmd} ${noun} ${verb} overly permissive`;
}
