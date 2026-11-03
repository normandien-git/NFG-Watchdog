-- Guard 0.14: Exchange Online mailboxes. Forwarding, who else can open / read / send as each mailbox, and when it was last used.
-- Filled by the collector job "mail" (daily). Names and settings only, never mail content.
create table public.wd_mailbox (
  id               text primary key,                 -- Exchange mailbox GUID
  upn              text,
  smtp             text,
  display_name     text,
  kind             text,                             -- UserMailbox | SharedMailbox | RoomMailbox | EquipmentMailbox ...
  hidden           boolean,
  created_src      timestamptz,
  forward_smtp     text,                             -- mailbox forwarding to an address (set by an admin or the user in OWA)
  forward_to       text,                             -- mailbox forwarding to a recipient in the directory
  deliver_and_forward boolean,
  forward_rules    jsonb not null default '[]',      -- inbox rules that forward or redirect: [{name, enabled, to[], how}]
  forward_external text[] not null default '{}',     -- the forwarding addresses outside NFG's accepted domains
  full_access      jsonb not null default '[]',      -- [{who, rights[]}] from Get-MailboxPermission (not inherited)
  inbox_access     jsonb not null default '[]',      -- [{who, rights[]}] on the Inbox folder
  send_as          text[] not null default '{}',
  send_on_behalf   text[] not null default '{}',
  last_action      timestamptz,                      -- LastUserActionTime: the person (or a delegate) last did something
  last_logon       timestamptz,
  items            bigint,
  size_bytes       bigint,
  checked_at       timestamptz,                      -- when the per-mailbox details were last read
  meta             jsonb not null default '{}',
  first_seen       timestamptz not null default now(),
  last_seen        timestamptz not null default now(),
  active           boolean not null default true
);
alter table public.wd_mailbox enable row level security;
revoke all on public.wd_mailbox from anon, authenticated;
grant select on public.wd_mailbox to authenticated;
create policy "members read" on public.wd_mailbox for select to authenticated using ((select wd_private.member()));

insert into public.wd_setting (key, value, note) values
  ('mailbox_idle_days', '90', 'Days without use before a mailbox counts as not in use.')
on conflict (key) do nothing;

select cron.schedule('wd-mail', '52 3 * * *', $$select wd_private.call_collector('mail')$$);
