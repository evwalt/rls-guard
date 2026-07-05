// The exact, single query users paste into their own Supabase SQL Editor.
// Deliberately a plain SELECT against system catalogs — nothing here can
// write to the user's database, and it's short enough for a skeptical
// technical reader to audit in ten seconds before running it.
export const SCAN_QUERY = `select json_agg(row_to_json(x)) as scan_result
from (
  select
    t.schemaname,
    t.tablename,
    t.rowsecurity as rls_enabled,
    coalesce(
      json_agg(
        json_build_object(
          'policyname', p.policyname,
          'permissive', p.permissive,
          'roles', p.roles,
          'cmd', p.cmd,
          'qual', p.qual,
          'with_check', p.with_check
        )
      ) filter (where p.policyname is not null),
      '[]'::json
    ) as policies,
    coalesce(
      (select json_agg(c.column_name)
       from information_schema.columns c
       where c.table_schema = t.schemaname and c.table_name = t.tablename),
      '[]'::json
    ) as columns
  from pg_tables t
  left join pg_policies p
    on p.schemaname = t.schemaname and p.tablename = t.tablename
  where t.schemaname = 'public'
  group by t.schemaname, t.tablename, t.rowsecurity
  order by t.tablename
) x;`;
