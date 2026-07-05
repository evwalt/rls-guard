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

Built and self-tested 2026-07-04. `npm test` runs 6 unit tests against
hand-written fixtures (not a real project). `npx next build` compiles
clean.

## Before this can take real money

1. **Verify detection against a real Supabase project**, not just
   fixtures — create a free/disposable test project, deliberately
   misconfigure a table's RLS, run the scan query, paste the output in
   locally (`npm run dev`), and confirm the report is accurate. Do this
   before anything below.
2. Create a Stripe account, add a one-time Price (~$12) and a recurring
   monthly Price (~$19), and fill in `.env.local` (see `.env.example`).
   Test in Stripe test mode before switching to live keys.
3. Deploy (Vercel is the least-friction choice for a Next.js app). Pick a
   name/domain — "RLS Guard" is a placeholder, not a final decision.
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
