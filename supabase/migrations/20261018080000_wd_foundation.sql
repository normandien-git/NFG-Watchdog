-- NFG Watchdog 0.01: foundation.
-- Watchdog has its OWN sign-in (this project's Supabase Auth), not NFG-Authentication. Email + password, then an
-- authenticator app (TOTP) every time: every policy needs aal2. Only people on the wd_user list see anything.
-- The collector (edge function wd-collect, service role) writes; people read, and change things only through wd_ functions.
-- Everything time-based is kept 90 days (collector job 'prune', nightly).
-- Applied to NFG-Watchdog as wd_000..wd_004 (same content, split in parts).

create extension if not exists pg_cron;
create extension if not exists pg_net;

create schema if not exists wd_private;
revoke all on schema wd_private from public, anon, authenticated;

-- ---------------------------------------------------------------- people
create table public.wd_user (
  id          uuid primary key default gen_random_uuid(),
  auth_id     uuid unique references auth.users(id) on delete set null,
  email       text not null unique check (email = lower(email)),
  full_name   text,
  role        text not null default 'viewer' check (role in ('admin','analyst','viewer')),
  active      boolean not null default true,
  created_at  timestamptz not null default now(),
  last_seen   timestamptz
);
comment on table public.wd_user is 'Who may open Watchdog. admin = everything; analyst = work findings and alerts; viewer = read only.';

insert into public.wd_user (email, full_name, role) values ('ryans@normandien.co.za', 'Ryan Smith', 'admin');

-- link a new login to its row on the list (by email). A login that is not on the list sees nothing.
create or replace function wd_private.on_auth_user() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  update public.wd_user set auth_id = new.id where email = lower(new.email) and auth_id is null;
  return new;
end $$;
create trigger wd_on_auth_user after insert on auth.users for each row execute function wd_private.on_auth_user();

-- the gate: on the list, active, and signed in with the authenticator app (aal2)
create or replace function wd_private.role() returns text language sql stable security definer set search_path = '' as $$
  select u.role from public.wd_user u
   where u.auth_id = auth.uid() and u.active and coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
$$;
create or replace function wd_private.member() returns boolean language sql stable set search_path = '' as $$
  select wd_private.role() is not null $$;
create or replace function wd_private.can_work() returns boolean language sql stable set search_path = '' as $$
  select coalesce(wd_private.role() in ('admin','analyst'), false) $$;
create or replace function wd_private.is_admin() returns boolean language sql stable set search_path = '' as $$
  select coalesce(wd_private.role() = 'admin', false) $$;
grant usage on schema wd_private to authenticated, service_role;
grant execute on function wd_private.role(), wd_private.member(), wd_private.can_work(), wd_private.is_admin() to authenticated, service_role;

-- ---------------------------------------------------------------- settings and runs
create table public.wd_setting (
  key        text primary key,
  value      jsonb not null,
  note       text,
  updated_at timestamptz not null default now(),
  updated_by text
);
insert into public.wd_setting (key, value, note) values
  ('allowed_countries', '["ZA"]', 'Countries people normally sign in and work from (ISO codes). Activity from elsewhere is flagged.'),
  ('known_ips', '[]', 'Office and server addresses (IP or CIDR) that may use secret keys and connect straight to databases.'),
  ('alert_emails', '["ryans@normandien.co.za"]', 'Who gets alert emails.'),
  ('alert_mailbox', '""', 'Microsoft 365 mailbox the alert emails are sent from (needs Mail.Send on the Watchdog Entra app).'),
  ('failed_login_threshold', '10', 'Failed sign-ins from one address in 15 minutes before it is flagged.'),
  ('denied_request_threshold', '200', 'Refused (401/403) requests from one address in 15 minutes before it is flagged.'),
  ('download_mb_threshold', '100', 'MB sent to one address in 15 minutes before it is flagged as a large download.'),
  ('slow_query_ms', '500', 'Average time (ms) above which a query that runs often is flagged.'),
  ('excluded_projects', '[]', 'Supabase project refs Watchdog leaves alone.'),
  ('connectors', '{}', 'Written by the collector: which connections are set up.');

create table public.wd_run (
  id          bigserial primary key,
  job         text not null,
  started_at  timestamptz not null default now(),
  finished_at timestamptz,
  ok          boolean,
  stats       jsonb not null default '{}',
  error       text,
  by_user     text
);
create index on public.wd_run (started_at desc);
create index on public.wd_run (job, started_at desc);

-- ---------------------------------------------------------------- what we watch
create table public.wd_target (
  id         text primary key,                    -- supabase:<ref>, netlify:<site id>, entra:<tenant>
  kind       text not null check (kind in ('supabase','netlify','entra')),
  ref        text not null,
  name       text not null,
  url        text,
  meta       jsonb not null default '{}',
  first_seen timestamptz not null default now(),
  last_seen  timestamptz not null default now(),
  active     boolean not null default true
);

-- ---------------------------------------------------------------- findings (security, posture, performance, activity)
create table public.wd_finding (
  id           bigserial primary key,
  fingerprint  text not null unique,
  scope        text not null,                       -- the collector pass that owns it (resolves it when it stops showing)
  source       text not null,                       -- supabase | netlify | entra | watchdog
  target_id    text references public.wd_target(id) on delete set null,
  check_code   text not null,
  category     text not null,                       -- access | data | config | secrets | exposure | activity | performance | reliability
  severity     text not null check (severity in ('critical','high','medium','low','info')),
  title        text not null,
  detail       text,
  remediation  text,
  meta         jsonb not null default '{}',
  first_seen   timestamptz not null default now(),
  last_seen    timestamptz not null default now(),
  seen_count   integer not null default 1,
  status       text not null default 'open' check (status in ('open','resolved','accepted')),
  resolved_at  timestamptz,
  accepted_by  text,
  accepted_until date,
  note         text,
  notified_at  timestamptz
);
create index on public.wd_finding (status, severity);
create index on public.wd_finding (target_id);
create index on public.wd_finding (scope, status);
create index on public.wd_finding (last_seen desc);

create or replace function wd_private.sev_rank(s text) returns int language sql immutable set search_path = '' as $$
  select case s when 'critical' then 5 when 'high' then 4 when 'medium' then 3 when 'low' then 2 else 1 end $$;
grant execute on function wd_private.sev_rank(text) to authenticated, service_role;

-- the change log: findings opened and closed, inventory added/removed/changed (90 days)
create table public.wd_change (
  id        bigserial primary key,
  at        timestamptz not null default now(),
  target_id text,
  kind      text not null,          -- finding | edge_function | secret | netlify_env | api_key | entra_app | entra_credential | user | setting | site | deploy
  item      text not null,
  action    text not null,          -- added | removed | changed | opened | resolved | reopened | accepted
  detail    jsonb not null default '{}',
  by_user   text
);
create index on public.wd_change (at desc);
create index on public.wd_change (target_id, at desc);

-- Collector hands over every finding of one pass; new ones open, missing ones resolve (unless the pass is activity).
-- p_findings: [{fingerprint, source, target_id, check_code, category, severity, title, detail, remediation, meta}]
create or replace function public.wd_findings_sync(p_scope text, p_findings jsonb, p_resolve_missing boolean default true)
returns jsonb language plpgsql set search_path = '' as $$
declare v_new int := 0; v_reopen int := 0; v_resolved int := 0; f jsonb; r public.wd_finding;
begin
  for f in select * from jsonb_array_elements(coalesce(p_findings, '[]')) loop
    select * into r from public.wd_finding where fingerprint = f->>'fingerprint';
    if not found then
      insert into public.wd_finding (fingerprint, scope, source, target_id, check_code, category, severity, title, detail, remediation, meta)
      values (f->>'fingerprint', p_scope, f->>'source', nullif(f->>'target_id',''), f->>'check_code', f->>'category', f->>'severity',
              f->>'title', f->>'detail', f->>'remediation', coalesce(f->'meta','{}'));
      insert into public.wd_change (target_id, kind, item, action, detail)
      values (nullif(f->>'target_id',''), 'finding', f->>'title', 'opened', jsonb_build_object('severity', f->>'severity', 'check', f->>'check_code'));
      v_new := v_new + 1;
    else
      update public.wd_finding set
        last_seen = now(), seen_count = seen_count + 1, severity = f->>'severity', title = f->>'title', detail = f->>'detail',
        remediation = f->>'remediation', meta = coalesce(f->'meta','{}'), scope = p_scope,
        status = case when status = 'resolved' then 'open'
                      when status = 'accepted' and accepted_until is not null and accepted_until < current_date then 'open'
                      else status end,
        resolved_at = case when status = 'resolved' then null else resolved_at end,
        notified_at = case when status = 'resolved' then null else notified_at end
      where id = r.id;
      if r.status = 'resolved' then
        v_reopen := v_reopen + 1;
        insert into public.wd_change (target_id, kind, item, action, detail)
        values (r.target_id, 'finding', r.title, 'reopened', jsonb_build_object('severity', f->>'severity', 'check', r.check_code));
      end if;
    end if;
  end loop;
  if p_resolve_missing then
    with gone as (
      update public.wd_finding set status = 'resolved', resolved_at = now()
       where scope = p_scope and status in ('open','accepted')
         and fingerprint not in (select x->>'fingerprint' from jsonb_array_elements(coalesce(p_findings,'[]')) x)
      returning target_id, title, check_code)
    , logged as (insert into public.wd_change (target_id, kind, item, action, detail)
      select target_id, 'finding', title, 'resolved', jsonb_build_object('check', check_code) from gone returning 1)
    select count(*) into v_resolved from logged;
  end if;
  return jsonb_build_object('new', v_new, 'reopened', v_reopen, 'resolved', v_resolved);
end $$;
revoke all on function public.wd_findings_sync(text, jsonb, boolean) from public, anon, authenticated;
grant execute on function public.wd_findings_sync(text, jsonb, boolean) to service_role;

-- activity findings (one per day per thing) close themselves after 7 quiet days
create or replace function public.wd_close_quiet_activity() returns int language sql set search_path = '' as $$
  with c as (update public.wd_finding set status = 'resolved', resolved_at = now()
    where category = 'activity' and status = 'open' and last_seen < now() - interval '7 days' returning 1)
  select count(*)::int from c $$;
revoke all on function public.wd_close_quiet_activity() from public, anon, authenticated;
grant execute on function public.wd_close_quiet_activity() to service_role;

-- ---------------------------------------------------------------- inventory
create table public.wd_edge_function (
  target_id   text not null references public.wd_target(id) on delete cascade,
  slug        text not null,
  name        text,
  version     integer,
  status      text,
  verify_jwt  boolean,
  created_src timestamptz,
  updated_src timestamptz,
  first_seen  timestamptz not null default now(),
  last_seen   timestamptz not null default now(),
  active      boolean not null default true,
  primary key (target_id, slug)
);

-- secrets and keys: names and fingerprints only, never values
create table public.wd_secret (
  target_id   text not null references public.wd_target(id) on delete cascade,
  kind        text not null,          -- edge_secret | netlify_env | api_key | entra_password | entra_certificate | vault
  name        text not null,
  digest      text,                   -- sha-256 of what the source reports (changes when the secret changes)
  is_secret   boolean,
  scopes      text[],
  expires_at  timestamptz,
  meta        jsonb not null default '{}',
  first_seen  timestamptz not null default now(),
  last_seen   timestamptz not null default now(),
  changed_at  timestamptz,
  active      boolean not null default true,
  primary key (target_id, kind, name)
);

create table public.wd_outbound (
  target_id   text not null references public.wd_target(id) on delete cascade,
  via         text not null,          -- cron | pg_net | edge_function | netlify_function
  host        text not null,
  detail      text not null default '',
  calls_24h   integer,
  first_seen  timestamptz not null default now(),
  last_seen   timestamptz not null default now(),
  active      boolean not null default true,
  primary key (target_id, via, host, detail)
);

create table public.wd_netlify_deploy (
  id          text primary key,
  target_id   text references public.wd_target(id) on delete cascade,
  state       text,
  context     text,
  branch      text,
  commit_ref  text,
  committer   text,
  title       text,
  created_src timestamptz,
  published_src timestamptz,
  observed_at timestamptz not null default now()
);
create index on public.wd_netlify_deploy (target_id, created_src desc);

create table public.wd_entra_app (
  app_id         text primary key,
  object_id      text,
  sp_id          text,
  display_name   text,
  created_src    timestamptz,
  audience       text,
  permissions    jsonb not null default '[]',   -- [{resource, name, type: Application|Delegated}]
  redirect_uris  text[],
  owners         text[],
  last_sign_in   timestamptz,
  sign_ins_30d   integer,
  meta           jsonb not null default '{}',
  first_seen     timestamptz not null default now(),
  last_seen      timestamptz not null default now(),
  active         boolean not null default true
);

-- ---------------------------------------------------------------- time series (90 days)
-- traffic in 15-minute buckets: who called which project, from where, with which key, how much data left
create table public.wd_traffic (
  id         bigserial primary key,
  bucket     timestamptz not null,
  target_id  text not null references public.wd_target(id) on delete cascade,
  channel    text not null,           -- rest | auth | storage | realtime | graphql | function | other
  method     text,
  path       text,
  status     integer,
  country    text,
  city       text,
  asn_org    text,
  ip         text,
  key_type   text,                    -- publishable | secret | anon_jwt | service_role_jwt | user_jwt | none
  agent      text,                    -- browser | server | supabase | bot | other
  requests   integer not null,
  bytes_out  bigint not null default 0,
  avg_ms     numeric(12,1)
);
create index on public.wd_traffic (bucket desc);
create index on public.wd_traffic (target_id, bucket desc);
create index on public.wd_traffic (ip, bucket desc);
create index on public.wd_traffic (key_type, bucket desc);

create table public.wd_auth_event (
  id          bigserial primary key,
  at          timestamptz not null,
  target_id   text not null references public.wd_target(id) on delete cascade,
  action      text not null,          -- login | logout | user_signedup | user_deleted | failed_login | mfa_* | ...
  actor_id    text,
  actor_email text,
  ip          text,
  country     text,
  user_agent  text,
  ok          boolean not null default true,
  meta        jsonb not null default '{}',
  src_id      text unique
);
create index on public.wd_auth_event (at desc);
create index on public.wd_auth_event (target_id, at desc);
create index on public.wd_auth_event (actor_email, at desc);

create table public.wd_db_connection (
  id          bigserial primary key,
  observed_at timestamptz not null default now(),
  target_id   text not null references public.wd_target(id) on delete cascade,
  role_name   text,
  app_name    text,
  client_addr text,
  state       text,
  connections integer not null
);
create index on public.wd_db_connection (observed_at desc);

create table public.wd_query_stat (
  id          bigserial primary key,
  observed_at timestamptz not null default now(),
  target_id   text not null references public.wd_target(id) on delete cascade,
  queryid     text,
  role_name   text,
  calls       bigint,
  total_ms    numeric(16,1),
  mean_ms     numeric(14,2),
  max_ms      numeric(14,2),
  rows_out    bigint,
  query       text
);
create index on public.wd_query_stat (observed_at desc);
create index on public.wd_query_stat (target_id, observed_at desc);

create table public.wd_audit_external (
  id        text primary key,           -- source:id
  source    text not null,              -- netlify | entra | supabase_org
  at        timestamptz not null,
  actor     text,
  action    text,
  target    text,
  ip        text,
  meta      jsonb not null default '{}'
);
create index on public.wd_audit_external (at desc);

create table public.wd_entra_signin (
  id            text primary key,
  at            timestamptz not null,
  app_id        text,
  app_name      text,
  principal     text,                    -- user UPN or service principal name
  is_sp         boolean not null default false,
  ip            text,
  city          text,
  country       text,
  ok            boolean,
  failure       text,
  client_app    text,
  resource      text
);
create index on public.wd_entra_signin (at desc);
create index on public.wd_entra_signin (app_id, at desc);

create table public.wd_posture_daily (
  day        date not null,
  target_id  text not null references public.wd_target(id) on delete cascade,
  critical   int not null default 0,
  high       int not null default 0,
  medium     int not null default 0,
  low        int not null default 0,
  score      int not null,
  primary key (day, target_id)
);

-- ---------------------------------------------------------------- alerts
create table public.wd_alert_rule (
  id            bigserial primary key,
  name          text not null,
  enabled       boolean not null default true,
  min_severity  text not null default 'high' check (min_severity in ('critical','high','medium','low','info')),
  categories    text[],                -- null = all
  sources       text[],                -- null = all
  channel       text not null default 'email' check (channel in ('email','teams','both')),
  recipients    text[],                -- null = alert_emails setting
  created_at    timestamptz not null default now(),
  created_by    text
);
insert into public.wd_alert_rule (name, min_severity, channel) values ('High and critical, everything', 'high', 'email');

create table public.wd_alert (
  id             bigserial primary key,
  at             timestamptz not null default now(),
  rule_id        bigint references public.wd_alert_rule(id) on delete set null,
  finding_id     bigint references public.wd_finding(id) on delete cascade,
  severity       text not null,
  title          text not null,
  channel        text not null,
  recipients     text[],
  delivered      boolean not null default false,
  delivered_at   timestamptz,
  delivery_error text,
  status         text not null default 'open' check (status in ('open','ack','closed')),
  ack_by         text,
  ack_at         timestamptz
);
create index on public.wd_alert (at desc);
create index on public.wd_alert (delivered) where not delivered;

-- open findings that match a rule and have not been sent -> alerts (the collector sends them)
create or replace function public.wd_alert_queue() returns int language plpgsql set search_path = '' as $$
declare n int := 0; v_default text[];
begin
  select array(select jsonb_array_elements_text(value)) into v_default from public.wd_setting where key = 'alert_emails';
  with cand as (
    select f.id fid, f.severity, f.title, r.id rid, r.channel, coalesce(r.recipients, v_default) rcp
      from public.wd_finding f
      join public.wd_alert_rule r on r.enabled
       and wd_private.sev_rank(f.severity) >= wd_private.sev_rank(r.min_severity)
       and (r.categories is null or f.category = any(r.categories))
       and (r.sources is null or f.source = any(r.sources))
     where f.status = 'open' and f.notified_at is null),
  ins as (insert into public.wd_alert (rule_id, finding_id, severity, title, channel, recipients)
          select rid, fid, severity, title, channel, rcp from cand returning finding_id)
  select count(*) into n from ins;
  update public.wd_finding set notified_at = now() where status = 'open' and notified_at is null;
  return n;
end $$;
revoke all on function public.wd_alert_queue() from public, anon, authenticated;
grant execute on function public.wd_alert_queue() to service_role;

-- ---------------------------------------------------------------- Watchdog's own access log
create table public.wd_access_log (
  id      bigserial primary key,
  at      timestamptz not null default now(),
  user_id uuid,
  email   text,
  action  text not null,
  detail  jsonb not null default '{}'
);
create index on public.wd_access_log (at desc);

-- ---------------------------------------------------------------- RLS: members read; nobody writes directly
do $$ declare t text; begin
  for t in select unnest(array['wd_user','wd_setting','wd_run','wd_target','wd_finding','wd_change','wd_edge_function','wd_secret',
      'wd_outbound','wd_netlify_deploy','wd_entra_app','wd_traffic','wd_auth_event','wd_db_connection','wd_query_stat',
      'wd_audit_external','wd_entra_signin','wd_posture_daily','wd_alert_rule','wd_alert','wd_access_log']) loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
    if t = 'wd_access_log' then
      execute format('create policy "admins read" on public.%I for select to authenticated using ((select wd_private.is_admin()))', t);
    elsif t = 'wd_user' then
      execute format('create policy "admins or self read" on public.%I for select to authenticated using ((select wd_private.is_admin()) or auth_id = (select auth.uid()))', t);
    else
      execute format('create policy "members read" on public.%I for select to authenticated using ((select wd_private.member()))', t);
    end if;
  end loop;
end $$;
revoke usage, select on all sequences in schema public from anon, authenticated;

-- ---------------------------------------------------------------- what the screens call
-- who am I (works at aal1 too, so the sign-in screen knows whether to ask for the app code)
create or replace function public.wd_me() returns jsonb language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('listed', u.id is not null, 'active', coalesce(u.active,false), 'role', u.role, 'name', u.full_name,
    'email', coalesce(u.email, auth.jwt() ->> 'email'), 'aal', auth.jwt() ->> 'aal')
  from (select 1) x left join public.wd_user u on u.auth_id = auth.uid()
$$;
revoke all on function public.wd_me() from public, anon;
grant execute on function public.wd_me() to authenticated;

create or replace function public.wd_touch(p_action text default 'open') returns void language plpgsql security definer set search_path = '' as $$
declare h jsonb := nullif(current_setting('request.headers', true), '')::jsonb;
begin
  if not wd_private.member() then return; end if;
  update public.wd_user set last_seen = now() where auth_id = auth.uid();
  insert into public.wd_access_log (user_id, email, action, detail)
  values (auth.uid(), auth.jwt() ->> 'email', left(coalesce(p_action,'open'), 60),
          jsonb_build_object('ip', coalesce(h ->> 'cf-connecting-ip', h ->> 'x-forwarded-for'), 'agent', left(h ->> 'user-agent', 200)));
end $$;
revoke all on function public.wd_touch(text) from public, anon;
grant execute on function public.wd_touch(text) to authenticated;

-- work a finding: accept (with a reason and optional end date), reopen, add a note
create or replace function public.wd_finding_set(p_id bigint, p_status text, p_note text, p_until date default null)
returns void language plpgsql security definer set search_path = '' as $$
declare r public.wd_finding;
begin
  if not wd_private.can_work() then raise exception 'You need the analyst or admin role for this.'; end if;
  if p_status not in ('open','accepted') then raise exception 'Status must be open or accepted.'; end if;
  if p_status = 'accepted' and coalesce(trim(p_note),'') = '' then raise exception 'Say why the risk is accepted.'; end if;
  select * into r from public.wd_finding where id = p_id for update;
  if not found then raise exception 'That finding is gone.'; end if;
  update public.wd_finding set status = p_status, note = nullif(trim(p_note),''),
    accepted_by = case when p_status = 'accepted' then auth.jwt() ->> 'email' end,
    accepted_until = case when p_status = 'accepted' then p_until end
   where id = p_id;
  insert into public.wd_change (target_id, kind, item, action, detail, by_user)
  values (r.target_id, 'finding', r.title, case when p_status = 'accepted' then 'accepted' else 'reopened' end,
          jsonb_build_object('note', p_note, 'until', p_until), auth.jwt() ->> 'email');
end $$;
revoke all on function public.wd_finding_set(bigint, text, text, date) from public, anon;
grant execute on function public.wd_finding_set(bigint, text, text, date) to authenticated;

create or replace function public.wd_alert_ack(p_ids bigint[], p_status text default 'ack') returns void language plpgsql security definer set search_path = '' as $$
begin
  if not wd_private.can_work() then raise exception 'You need the analyst or admin role for this.'; end if;
  if p_status not in ('ack','closed','open') then raise exception 'Bad status.'; end if;
  update public.wd_alert set status = p_status, ack_by = auth.jwt() ->> 'email', ack_at = now() where id = any(p_ids);
end $$;
revoke all on function public.wd_alert_ack(bigint[], text) from public, anon;
grant execute on function public.wd_alert_ack(bigint[], text) to authenticated;

create or replace function public.wd_setting_set(p_key text, p_value jsonb) returns void language plpgsql security definer set search_path = '' as $$
begin
  if not wd_private.is_admin() then raise exception 'Only a Watchdog admin can change settings.'; end if;
  if p_key = 'connectors' then raise exception 'The collector writes that one.'; end if;
  update public.wd_setting set value = p_value, updated_at = now(), updated_by = auth.jwt() ->> 'email' where key = p_key;
  if not found then raise exception 'Unknown setting %', p_key; end if;
  insert into public.wd_change (kind, item, action, detail, by_user) values ('setting', p_key, 'changed', jsonb_build_object('value', p_value), auth.jwt() ->> 'email');
end $$;
revoke all on function public.wd_setting_set(text, jsonb) from public, anon;
grant execute on function public.wd_setting_set(text, jsonb) to authenticated;

create or replace function public.wd_rule_save(p_id bigint, p_name text, p_enabled boolean, p_min text, p_categories text[], p_sources text[], p_channel text, p_recipients text[])
returns bigint language plpgsql security definer set search_path = '' as $$
declare v bigint;
begin
  if not wd_private.is_admin() then raise exception 'Only a Watchdog admin can change alert rules.'; end if;
  if p_id is null then
    insert into public.wd_alert_rule (name, enabled, min_severity, categories, sources, channel, recipients, created_by)
    values (p_name, p_enabled, p_min, nullif(p_categories,'{}'), nullif(p_sources,'{}'), p_channel, nullif(p_recipients,'{}'), auth.jwt() ->> 'email') returning id into v;
  else
    update public.wd_alert_rule set name = p_name, enabled = p_enabled, min_severity = p_min, categories = nullif(p_categories,'{}'),
      sources = nullif(p_sources,'{}'), channel = p_channel, recipients = nullif(p_recipients,'{}') where id = p_id returning id into v;
  end if;
  insert into public.wd_change (kind, item, action, by_user) values ('setting', 'alert rule: ' || p_name, 'changed', auth.jwt() ->> 'email');
  return v;
end $$;
revoke all on function public.wd_rule_save(bigint, text, boolean, text, text[], text[], text, text[]) from public, anon;
grant execute on function public.wd_rule_save(bigint, text, boolean, text, text[], text[], text, text[]) to authenticated;

create or replace function public.wd_user_save(p_email text, p_name text, p_role text, p_active boolean) returns void language plpgsql security definer set search_path = '' as $$
declare v_self boolean;
begin
  if not wd_private.is_admin() then raise exception 'Only a Watchdog admin can change who has access.'; end if;
  select auth_id = auth.uid() into v_self from public.wd_user where email = lower(trim(p_email));
  if coalesce(v_self,false) and (p_role <> 'admin' or not p_active) then raise exception 'You cannot take away your own admin access.'; end if;
  insert into public.wd_user (email, full_name, role, active) values (lower(trim(p_email)), p_name, p_role, p_active)
  on conflict (email) do update set full_name = excluded.full_name, role = excluded.role, active = excluded.active;
  update public.wd_user u set auth_id = a.id from auth.users a where u.email = lower(trim(p_email)) and u.auth_id is null and lower(a.email) = u.email;
  insert into public.wd_change (kind, item, action, detail, by_user) values ('user', lower(trim(p_email)), 'changed', jsonb_build_object('role', p_role, 'active', p_active), auth.jwt() ->> 'email');
end $$;
revoke all on function public.wd_user_save(text, text, text, boolean) from public, anon;
grant execute on function public.wd_user_save(text, text, text, boolean) to authenticated;

-- the collector's cron calls carry a secret that never leaves the database (vault)
select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'wd_cron_secret', 'Shared secret for pg_cron -> wd-collect');
create or replace function public.wd_cron_ok(p_secret text) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from vault.decrypted_secrets where name = 'wd_cron_secret' and decrypted_secret = p_secret) $$;
revoke all on function public.wd_cron_ok(text) from public, anon, authenticated;
grant execute on function public.wd_cron_ok(text) to service_role;

create or replace function wd_private.call_collector(p_job text) returns bigint language sql security definer set search_path = '' as $$
  select net.http_post(
    url := 'https://opckmndqounbhqksouxx.supabase.co/functions/v1/wd-collect?job=' || p_job,
    headers := jsonb_build_object('content-type', 'application/json',
      'x-wd-cron', (select decrypted_secret from vault.decrypted_secrets where name = 'wd_cron_secret')),
    body := '{}'::jsonb, timeout_milliseconds := 150000)
$$;
revoke all on function wd_private.call_collector(text) from public, anon, authenticated;

-- ---------------------------------------------------------------- posture score per target per day
create or replace function public.wd_posture_snapshot() returns void language sql set search_path = '' as $$
  insert into public.wd_posture_daily (day, target_id, critical, high, medium, low, score)
  select current_date, t.id,
    count(*) filter (where f.severity = 'critical'), count(*) filter (where f.severity = 'high'),
    count(*) filter (where f.severity = 'medium'), count(*) filter (where f.severity = 'low'),
    greatest(0, 100 - 25 * count(*) filter (where f.severity = 'critical') - 8 * count(*) filter (where f.severity = 'high')
                    - 2 * count(*) filter (where f.severity = 'medium') - count(*) filter (where f.severity = 'low') / 2)::int
  from public.wd_target t
  left join public.wd_finding f on f.target_id = t.id and f.status = 'open' and f.category not in ('performance')
  where t.active group by t.id
  on conflict (day, target_id) do update set critical = excluded.critical, high = excluded.high, medium = excluded.medium,
    low = excluded.low, score = excluded.score
$$;
revoke all on function public.wd_posture_snapshot() from public, anon, authenticated;
grant execute on function public.wd_posture_snapshot() to service_role;

-- ---------------------------------------------------------------- schedules (UTC). 90-day retention is the collector's nightly 'prune' job.
select cron.schedule('wd-logs',     '*/15 * * * *', $$select wd_private.call_collector('logs')$$);
select cron.schedule('wd-supabase', '7 * * * *',    $$select wd_private.call_collector('supabase')$$);
select cron.schedule('wd-netlify',  '22 * * * *',   $$select wd_private.call_collector('netlify')$$);
select cron.schedule('wd-entra',    '37 * * * *',   $$select wd_private.call_collector('entra')$$);
select cron.schedule('wd-prune',    '10 0 * * *',   $$select wd_private.call_collector('prune')$$);
