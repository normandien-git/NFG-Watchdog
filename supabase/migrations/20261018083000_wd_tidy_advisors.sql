-- Watchdog 0.01: the project template's rls_auto_enable() event-trigger function should not be callable over the API.
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
