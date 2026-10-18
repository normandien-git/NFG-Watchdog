-- Watchdog 0.01: read-only summaries for the screens. SECURITY INVOKER: the caller's RLS applies (members at aal2 only).
create or replace function public.wd_traffic_summary(p_hours int default 24, p_target text default null)
returns jsonb language sql stable security invoker set search_path = '' as $$
  with t as (
    select * from public.wd_traffic
     where bucket >= now() - make_interval(hours => least(greatest(p_hours, 1), 2160))
       and (p_target is null or target_id = p_target))
  select jsonb_build_object(
    'totals', (select jsonb_build_object('requests', coalesce(sum(requests),0), 'bytes', coalesce(sum(bytes_out),0),
        'denied', coalesce(sum(requests) filter (where status in (401,403)),0), 'errors', coalesce(sum(requests) filter (where status >= 500),0),
        'ips', count(distinct ip), 'countries', count(distinct country), 'users', count(distinct auth_user),
        'secret_calls', coalesce(sum(requests) filter (where key_type in ('secret','service_role_jwt') and agent <> 'supabase'),0)) from t),
    'series', (select coalesce(jsonb_agg(x order by x.h), '[]') from (
        select date_trunc('hour', bucket) h, sum(requests) n, sum(bytes_out) b, sum(requests) filter (where status in (401,403)) d
          from t group by 1) x),
    'by_country', (select coalesce(jsonb_agg(x order by x.n desc), '[]') from (
        select coalesce(country,'?') country, sum(requests) n, sum(bytes_out) b, count(distinct ip) ips from t group by 1 order by 2 desc limit 30) x),
    'by_ip', (select coalesce(jsonb_agg(x order by x.n desc), '[]') from (
        select ip, max(country) country, max(city) city, max(asn_org) asn, sum(requests) n, sum(bytes_out) b,
               sum(requests) filter (where status in (401,403)) denied, array_agg(distinct key_type) filter (where key_type is not null) keys,
               array_agg(distinct agent) agents, array_agg(distinct target_id) targets, count(distinct auth_user) users, max(bucket) last
          from t where ip is not null group by ip order by n desc limit 200) x),
    'by_key', (select coalesce(jsonb_agg(x order by x.n desc), '[]') from (
        select target_id, coalesce(key_type,'function') key_type, key_id, agent, sum(requests) n, count(distinct ip) ips, max(bucket) last
          from t group by 1, 2, 3, 4) x),
    'by_target', (select coalesce(jsonb_agg(x order by x.n desc), '[]') from (
        select target_id, sum(requests) n, sum(bytes_out) b, sum(requests) filter (where status in (401,403)) denied,
               sum(requests) filter (where status >= 500) errors, count(distinct ip) ips, count(distinct auth_user) users from t group by 1) x),
    'by_path', (select coalesce(jsonb_agg(x order by x.n desc), '[]') from (
        select target_id, channel, method, path, sum(requests) n, sum(bytes_out) b, round(avg(avg_ms),1) ms,
               sum(requests) filter (where status >= 400) bad from t group by 1,2,3,4 order by 5 desc limit 300) x),
    'by_user', (select coalesce(jsonb_agg(x order by x.n desc), '[]') from (
        select target_id, auth_user, sum(requests) n, sum(bytes_out) b, count(distinct ip) ips, array_agg(distinct country) countries, max(bucket) last
          from t where auth_user is not null group by 1, 2 order by 3 desc limit 300) x)
  )
$$;
revoke all on function public.wd_traffic_summary(int, text) from public, anon;
grant execute on function public.wd_traffic_summary(int, text) to authenticated;

create or replace function public.wd_function_usage(p_hours int default 168)
returns table (target_id text, slug text, calls bigint, errors bigint, avg_ms numeric, ips bigint, last timestamptz)
language sql stable security invoker set search_path = '' as $$
  select target_id, split_part(path, '/', 4) slug, sum(requests), sum(requests) filter (where status >= 400), round(avg(avg_ms),1), count(distinct ip), max(bucket)
    from public.wd_traffic
   where channel = 'function' and bucket >= now() - make_interval(hours => least(greatest(p_hours,1), 2160))
   group by 1, 2
$$;
revoke all on function public.wd_function_usage(int) from public, anon;
grant execute on function public.wd_function_usage(int) to authenticated;

create or replace function public.wd_user_names() returns table (target_id text, actor_id text, email text)
language sql stable security invoker set search_path = '' as $$
  select distinct on (target_id, actor_id) target_id, actor_id, actor_email from public.wd_auth_event
   where actor_id is not null and actor_email is not null order by target_id, actor_id, at desc
$$;
revoke all on function public.wd_user_names() from public, anon;
grant execute on function public.wd_user_names() to authenticated;
