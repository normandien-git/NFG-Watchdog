-- Watchdog 0.01: which key and which signed-in user made each group of calls.
alter table public.wd_traffic add column key_id text, add column auth_user text;
comment on column public.wd_traffic.key_id is 'Which API key (its prefix, e.g. sb_secret_Zzl5_): never the key itself';
comment on column public.wd_traffic.auth_user is 'Signed-in user id (JWT subject) in the watched project';
create index on public.wd_traffic (auth_user, bucket desc) where auth_user is not null;

create or replace function public.wd_entra_counts() returns table (app_id text, n int) language sql stable set search_path = '' as $$
  select s.app_id, count(*)::int from public.wd_entra_signin s where s.at > now() - interval '30 days' group by s.app_id $$;
revoke all on function public.wd_entra_counts() from public, anon, authenticated;
grant execute on function public.wd_entra_counts() to service_role;
