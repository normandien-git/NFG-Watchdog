-- Watchdog 0.02: deploys are saved before their site row exists on a first scan; the 90-day prune keeps the table tidy instead of a foreign key.
alter table public.wd_netlify_deploy drop constraint wd_netlify_deploy_target_id_fkey;
