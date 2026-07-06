# Real-project verification (2026-07-06)

Verifies `lib/detect.ts` against a real Postgres instance instead of just
the hand-written fixtures in `lib/detect.test.ts`.

## What this is, and isn't

This is a **disposable local Postgres cluster**, not a hosted Supabase
project — creating a Supabase account is a founder-identity action, not
something to do autonomously. The substitution is close, not identical:
`pg_tables`, `pg_policies`, and `information_schema.columns` (everything
`SCAN_QUERY` touches) are vanilla Postgres system catalogs that Supabase
doesn't modify, and `anon`/`authenticated`/`service_role` are recreated
here as plain roles with a stub `auth.uid()` function. What this does
**not** verify: Supabase Studio's actual SQL Editor UI/copy-paste behavior
(e.g. whether long results get visually truncated in the grid before
copying), or anything involving real JWT-based auth.

## What it found

Running the exact query from `lib/scan-query.ts` against 7 real,
deliberately-varied tables (see `schema.sql`) surfaced two real bugs that
all 9 fixture-based unit tests had missed:

1. **False positive on the single most common correct RLS pattern.**
   `with_check` is legitimately `null` for SELECT/DELETE-only policies
   (WITH CHECK doesn't apply to them) — the old code treated any `null` as
   "unrestricted," so a textbook-correct `for select using (owner_id =
   auth.uid())` policy was flagged as a vulnerability.
2. **RESTRICTIVE policies were treated as if they grant access.** A
   RESTRICTIVE policy only narrows what permissive policies already allow
   — it can never grant access by itself, so `USING (true)` on one is a
   no-op, not a vulnerability. The old code never checked `permissive`.

Both are fixed in `lib/detect.ts`, and both now have regression tests in
`lib/detect.test.ts`. Re-running the real captured output
(`real_scan_output.json`) through the fixed `detect()` now matches the
ground truth in `schema.sql` exactly (3 real "high" findings, 1 "info",
3 correctly-scoped tables left unflagged).

## Reproducing

```
export PATH="/Applications/Postgres.app/Contents/Versions/latest/bin:$PATH"
initdb -D verification/pgdata -U postgres --auth=trust
pg_ctl -D verification/pgdata -l verification/pg.log \
  -o "-p 5477 -k verification/sockets -h ''" start
mkdir -p verification/sockets
createdb -h verification/sockets -p 5477 -U postgres rls_guard_verify
psql -h verification/sockets -p 5477 -U postgres -d rls_guard_verify \
  -c "create extension if not exists pgcrypto;"
psql -h verification/sockets -p 5477 -U postgres -d rls_guard_verify \
  -f verification/schema.sql
psql -h verification/sockets -p 5477 -U postgres -d rls_guard_verify \
  -t -A -f verification/scan_query.sql > verification/real_scan_output.json
npx tsx verification/verify_real.mjs
pg_ctl -D verification/pgdata stop -m fast
```

## Still open

Actual hosted-Supabase verification (real project, real Studio SQL Editor
copy-paste) is the one gap this doesn't close — recommended before the
first public post, but it's a much smaller residual risk now that the
core detection logic has been checked against real Postgres behavior
rather than only fixtures written by the same person who wrote the code
being tested.
