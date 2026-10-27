-- Guard 0.13: Known callers. Secret-key use is grouped by caller (key, agent, method, path) instead of by address,
-- and callers on this list are not flagged. For servers whose address changes on every run (Netlify functions, cloud jobs).
insert into public.wd_setting (key, value, note) values
  ('known_callers',
   '["GateControl report scheduler (Netlify function) | dlydqrczvrkryqhhkghq | sb_secret_KSTg3 | script | /rest/v1/report_ | amazon"]',
   'Servers and scheduled functions that may use a secret key from changing addresses. One per line: label | project | key | agent | path | network (blank or * = any).')
on conflict (key) do nothing;

-- One-off: close the per-address findings the old check raised for that scheduler.
update public.wd_finding
   set status = 'resolved', resolved_at = now(),
       note = coalesce(note || ' ', '') || 'Closed by Guard 0.13: GateControl report scheduler (Netlify function, changing AWS addresses), now a known caller.'
 where status = 'open' and check_code = 'activity.secret_key_unknown_ip'
   and target_id = 'supabase:dlydqrczvrkryqhhkghq' and meta->>'path' like '/rest/v1/report_%';
