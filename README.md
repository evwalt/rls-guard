# RLS Guard (working name)

Checks a Supabase/Postgres project for the most common "vibe coding"
security mistake — missing or overly permissive Row-Level-Security — and
generates the exact fix SQL. Built as the validation MVP for founder-os
idea [003](../founder-os/pipeline/02-validating/003-ai-app-vuln-autofix/).

## Why this design

- **We never see a database credential.** The user runs one short,
  plainly-readable `select` query (`lib/scan-query.ts`) in their own
  Supabase SQL Editor — a tool they already trust — and pastes the JSON
  result back into this page. There is no connection-string field
  anywhere in this product.
- **Detection runs entirely in the browser.** `lib/detect.ts` is a pure
  function; `app/page.tsx` calls it client-side. The pasted scan data is
  never sent to our server. The only two backend routes
  (`app/api/create-checkout-session`, `app/api/verify-session`) talk to
  Stripe and never see scan data.
- **No fixes are ever auto-applied.** The product generates SQL; the user
  reviews and runs it themselves. Auto-mutating someone's production
  database is explicitly out of scope for v1 (see the validation plan).

## Status

Built 2026-07-04. `npm test` runs 9 unit tests, `npx next build` compiles
clean. Detection logic verified 2026-07-06 against a real Postgres
instance (see `verification/README.md`) — this run found and fixed two
real false-positive bugs that the original fixture-only tests had missed.

## Before this can take real money

1. ~~Verify detection against a real Supabase project~~ — done 2026-07-06
   against a disposable local Postgres cluster mirroring Supabase's
   catalogs (see `verification/README.md` for exactly what that does and
   doesn't cover). The one still-open piece: a real hosted Supabase
   project, mainly to check Studio's SQL Editor copy-paste behavior on a
   large result — smaller risk now, but not zero.
2. ~~Create a Stripe account and a one-time Price (~$12)~~ — done. No
   subscription offering at this time — one-time purchase only, to keep
   the first market test as small as possible. Test in Stripe test mode
   before switching to live keys.
3. ~~Deploy (Vercel)~~ — done, connected to the GitHub repo for
   auto-deploy on push. Pick a name/domain — "RLS Guard" is a placeholder,
   not a final decision.
4. Write/approve the actual launch post copy and decide where and when to
   post (see the validation plan's distribution section) — nothing here
   should be posted publicly without that review.

## Local development

```
npm install
npm test          # unit tests for the detection logic
npm run dev        # http://localhost:3000
npm run build       # production build check
```
