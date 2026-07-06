-- Disposable verification schema.
-- Mirrors Supabase's default roles (anon, authenticated, service_role) and
-- reproduces every scenario from lib/detect.test.ts against a real Postgres
-- instance, plus a few real-world shapes fixtures couldn't anticipate.

create role anon nologin;
create role authenticated nologin;
create role service_role nologin;

-- Minimal stand-in for Supabase's auth schema/helper, just enough for
-- policy expressions referencing auth.uid() to be valid SQL.
create schema auth;
create function auth.uid() returns uuid
  language sql stable
  as $$ select null::uuid $$;

-- 1. RLS disabled entirely (the most common vibe-coded mistake)
create table public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);

-- 2. RLS enabled, permissive policy open to anon with USING (true)
create table public.comments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);
alter table public.comments enable row level security;
create policy "comments_open" on public.comments
  for select
  to anon, authenticated
  using (true);

-- 3. RLS enabled, zero policies (silent lockout, not a vuln, "info" only)
create table public.drafts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  body text
);
alter table public.drafts enable row level security;

-- 4. RLS enabled, properly scoped policy (should NOT be flagged)
create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  bio text
);
alter table public.profiles enable row level security;
create policy "profiles_owner_only" on public.profiles
  for select
  to authenticated
  using (user_id = auth.uid());

-- 5. RLS enabled, permissive policy but restricted to service_role only
--    (should NOT be flagged — service_role is not a public-facing role)
create table public.admin_notes (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null,
  note text
);
alter table public.admin_notes enable row level security;
create policy "admin_notes_service_only" on public.admin_notes
  for all
  to service_role
  using (true);

-- 6. Real-world shape fixtures didn't cover: WITH CHECK only (INSERT policy),
--    no USING clause at all, open to public role
create table public.signups (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null,
  email text
);
alter table public.signups enable row level security;
create policy "signups_open_insert" on public.signups
  for insert
  to public
  with check (true);

-- 7. Real-world shape: RLS enabled, restrictive (non-permissive) policy
--    open to anon with USING(true) — should NOT be flagged the same way,
--    since a RESTRICTIVE policy narrows rather than grants access.
create table public.audit_log (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  entry text
);
alter table public.audit_log enable row level security;
create policy "audit_log_base" on public.audit_log
  for select
  to authenticated
  using (owner_id = auth.uid());
create policy "audit_log_restrictive" on public.audit_log
  as restrictive
  for select
  to anon, authenticated
  using (true);
