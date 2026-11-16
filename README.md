# RLS Guard

A developer security tool that audits Supabase/Postgres projects for broken
access control (missing or misconfigured Row-Level Security) and generates
ready-to-run remediation SQL.

Live: [rls-guard.evanwalter.dev](https://rls-guard.evanwalter.dev)

## The problem

Row-Level Security (RLS) is how Postgres enforces "a user can only see their own
rows." When it is turned off, or left wide open with an overly permissive
policy, every tenant can read every other tenant's data. This is broken access
control (OWASP A01), and it is easy to miss because the application still works.
It is one of the most common security mistakes in quickly-built Supabase apps.

## How it works

1. You run one short, readable `SELECT` (`lib/scan-query.ts`) in your own
   Supabase SQL Editor, a tool you already trust.
2. You paste the JSON result back into the page.
3. RLS Guard flags the tables with missing or permissive policies and generates
   the exact remediation SQL for you to review and run.

## Security by design

- **No database credentials are ever handled.** There is no connection-string
  field anywhere in the product. You run the read-only scan query yourself.
- **Detection runs entirely in the browser.** `lib/detect.ts` is a pure
  function called client-side; the pasted scan data never reaches a server.
- **No fixes are auto-applied.** The tool generates SQL; you review and run it.
  Auto-mutating a production database is intentionally out of scope.

## Verification

Detection is verified against a real Postgres instance that mirrors Supabase's
default roles and catalogs (see `verification/README.md`). That run found and
fixed two real false-positive bugs that the original fixture-only tests had
missed, which is the whole argument for testing against a real database.

## Performance

`node --import tsx bench/detect-bench.ts` runs the detector on synthetic
schemas that repeat the verification mix (RLS off, RLS on with no policies,
an open policy, an owner-scoped policy, owner-scoped plus a no-op RESTRICTIVE
policy) and checks every finding against the known answer. On a 2017 dual-core
Intel i5 laptop it audits 1,000 tables in under 1 ms and 10,000 tables in
about 5 ms (median of 20 runs), with zero false positives and zero misses.

## Tech

Next.js, TypeScript. Detection logic is a pure, unit-tested function
(`lib/detect.ts`); the UI is a single client-side page.

## Local development

```bash
npm install
npm test       # unit tests for the detection logic
npm run dev    # http://localhost:3000
npm run build  # production build check
```
