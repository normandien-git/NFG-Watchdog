// NFG Watchdog collector: Supabase (every project the access token can see).
// Posture (hourly): advisors, auth settings, network/SSL/backups, API keys, edge functions, secrets, database checks,
// connections, slow queries, org members. Logs (every 15 minutes): traffic, sign-ins, failures, database errors.
import { db, q, sha, fp, iso, nowIso, pool, getJson, settings, setConnector, upsertTargets, patchTargetMeta, syncFindings,
  syncInventory, insertMany, ipInList, isPrivateIp, type Finding, type Sev } from "./lib.ts";

const API = "https://api.supabase.com/v1";
const PAT = Deno.env.get("SUPABASE_PAT") ?? "";
const H = () => ({ Authorization: `Bearer ${PAT}`, "content-type": "application/json" });
const mgmt = (path: string, init: RequestInit = {}) => getJson(API + path, { ...init, headers: { ...H(), ...(init.headers || {}) } });
const tid = (ref: string) => `supabase:${ref}`;

let readOnlyOk = true;
async function sql(ref: string, query: string): Promise<any[]> {
  if (readOnlyOk) {
    try { return await mgmt(`/projects/${ref}/database/query/read-only`, { method: "POST", body: JSON.stringify({ query }) }) ?? []; }
    catch (e: any) { if (e.status !== 404) throw e; readOnlyOk = false; }
  }
  return await mgmt(`/projects/${ref}/database/query`, { method: "POST", body: JSON.stringify({ query }) }) ?? [];
}
async function logs(ref: string, sqlText: string, start: string, end: string): Promise<any[]> {
  const u = `/projects/${ref}/analytics/endpoints/logs.all?` + new URLSearchParams({ sql: sqlText, iso_timestamp_start: start, iso_timestamp_end: end });
  const r = await mgmt(u);
  if (r?.error) throw new Error(`logs ${ref}: ${typeof r.error === "string" ? r.error : JSON.stringify(r.error).slice(0, 300)}`);
  return r?.result ?? [];
}

export const supabaseReady = () => !!PAT;

// the projects to watch (all ACTIVE ones the token sees, less the excluded list)
export async function projects() {
  const s = await settings();
  const all: any[] = await mgmt("/projects");
  const skip = new Set<string>(s.excluded_projects || []);
  const live = all.filter((p) => !skip.has(p.ref ?? p.id));
  await upsertTargets(live.map((p) => ({
    id: tid(p.ref ?? p.id), kind: "supabase", ref: p.ref ?? p.id, name: p.name, url: `https://${p.ref ?? p.id}.supabase.co`,
    meta: { region: p.region, status: p.status, org: p.organization_slug ?? p.organization_id, pg: p.database?.version, created: p.created_at },
  })));
  // projects that disappeared
  const ids = live.map((p) => tid(p.ref ?? p.id));
  if (ids.length) await q(db.from("wd_target").update({ active: false }).eq("kind", "supabase").not("id", "like", "supabase-org:%").not("id", "in", `(${ids.map((x) => `"${x}"`).join(",")})`));
  return live.filter((p) => p.status === "ACTIVE_HEALTHY").map((p) => ({ ref: p.ref ?? p.id, name: p.name, org: p.organization_slug ?? p.organization_id }));
}

// ================================================================== posture
const ADVISOR_SEV: Record<string, Sev> = {
  rls_disabled_in_public: "critical", policy_exists_rls_disabled: "critical", security_definer_view: "high",
  sensitive_columns_exposed: "critical", auth_users_exposed: "critical", rls_references_user_metadata: "high",
  anon_security_definer_function_executable: "high", authenticated_security_definer_function_executable: "medium",
  auth_leaked_password_protection: "medium", auth_insufficient_mfa_options: "low", function_search_path_mutable: "low",
  extension_in_public: "low", rls_enabled_no_policy: "info", materialized_view_in_api: "medium", foreign_table_in_api: "medium",
  unsupported_reg_types: "low", insecure_queue_exposed_in_api: "high", fkey_to_auth_unique: "low", vulnerable_postgres_version: "high",
  auth_otp_long_expiry: "low", auth_otp_short_length: "low",
};
const levelSev = (l: string): Sev => (l === "ERROR" ? "high" : l === "WARN" ? "medium" : "info");

async function advisors(ref: string, kind: "security" | "performance"): Promise<Finding[]> {
  const r = await mgmt(`/projects/${ref}/advisors/${kind}`);
  const lints: any[] = [];
  for (const l of r?.lints ?? []) {
    if (Array.isArray(l.findings)) for (const f of l.findings) lints.push({ ...l, ...f, metadata: f.metadata ?? l.metadata });
    else lints.push(l);
  }
  return lints.map((l) => {
    const m = l.metadata || {};
    const obj = [m.schema, m.name ?? m.entity, m.arguments].filter(Boolean).join(".");
    const perf = kind === "performance";
    const sev: Sev = perf ? (l.level === "ERROR" ? "medium" : l.level === "WARN" ? "low" : "info") : (ADVISOR_SEV[l.name] ?? levelSev(l.level));
    return {
      fingerprint: fp("sb", ref, "advisor", l.name, l.cache_key ?? obj),
      source: "supabase", target_id: tid(ref), check_code: `advisor.${l.name}`,
      category: perf ? "performance" : (l.name?.startsWith("auth_") ? "config" : "data"), severity: sev,
      title: `${l.title}${obj ? `: ${obj}` : ""}`, detail: String(l.detail ?? l.description ?? "").replace(/\\`/g, "`"),
      remediation: l.remediation, meta: { lint: l.name, level: l.level, object: m },
    } as Finding;
  });
}

function authChecks(ref: string, a: any): Finding[] {
  const out: Finding[] = [];
  const f = (code: string, sev: Sev, title: string, detail: string, remediation: string, meta: any = {}) =>
    out.push({ fingerprint: fp("sb", ref, "auth", code), source: "supabase", target_id: tid(ref), check_code: `auth.${code}`, category: "config", severity: sev, title, detail, remediation, meta });
  if (!a) return out;
  const fix = "Supabase › Authentication › Sign In / Providers";
  if (a.disable_signup === false) f("signup_open", "medium", "Anyone can create an account", "New users can sign themselves up. For internal NFG apps people should only be added by an admin (or through the central NFG login).", `${fix}: turn off "Allow new users to sign up".`);
  if (a.external_anonymous_users_enabled) f("anonymous", "medium", "Anonymous sign-ins are on", "Anyone can get a signed-in session without an account. Every policy written for 'authenticated' also lets them in.", `${fix}: turn off anonymous sign-ins unless the app needs them.`);
  if ((a.password_min_length ?? 6) < 10) f("pw_length", "medium", `Passwords can be ${a.password_min_length ?? 6} characters`, "Short passwords are easy to guess.", "Authentication › Policies: set the minimum to at least 10 and require letters, digits and symbols.", { value: a.password_min_length });
  if (a.mfa_totp_enroll_enabled === false && a.mfa_totp_verify_enabled === false) f("mfa_off", "low", "Authenticator-app MFA is switched off", "Nobody on this project can add a second factor.", "Authentication › Multi-Factor: enable TOTP.");
  if ((a.jwt_exp ?? 3600) > 3600) f("jwt_long", "low", `Access tokens live ${Math.round((a.jwt_exp ?? 0) / 60)} minutes`, "A stolen token stays valid for longer than the recommended hour.", "Authentication › Sessions: set the JWT expiry to 3600 seconds or less.", { value: a.jwt_exp });
  if (a.refresh_token_rotation_enabled === false) f("refresh_rotation", "medium", "Refresh tokens are not rotated", "A stolen refresh token can be reused indefinitely.", "Authentication › Sessions: turn on refresh-token rotation.");
  const site = String(a.site_url ?? "");
  if (/^http:\/\/(?!localhost|127\.)/.test(site)) f("site_http", "medium", "Site URL is plain http", `Site URL is ${site}. Sign-in links and tokens travel unencrypted.`, "Authentication › URL Configuration: use https.");
  const allow = String(a.uri_allow_list ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const wild = allow.filter((u) => /\*\*|^\*|https?:\/\/\*/.test(u));
  const local = allow.filter((u) => /localhost|127\.0\.0\.1/.test(u));
  if (wild.length) f("redirect_wild", "medium", "Sign-in redirects allow wildcards", `Allowed redirect URLs include ${wild.join(", ")}. A broad wildcard can let a look-alike site receive tokens.`, "Authentication › URL Configuration: list exact URLs.", { urls: wild });
  if (local.length) f("redirect_local", "low", "Sign-in redirects allow localhost", `Allowed: ${local.join(", ")}. Fine while building; remove it once the app is live.`, "Authentication › URL Configuration: remove localhost entries.", { urls: local });
  if (!a.smtp_host && a.disable_signup === false) f("smtp_default", "low", "Emails go through Supabase's shared mail server", "The built-in mailer is rate limited and not meant for production.", "Authentication › SMTP: set up your own mail server (e.g. Microsoft 365).");
  if (a.disable_signup === false && !a.security_captcha_enabled) f("captcha", "low", "Open sign-up without CAPTCHA", "Bots can create accounts and send emails in bulk.", "Authentication › Attack Protection: enable CAPTCHA or close sign-up.");
  if (a.security_manual_linking_enabled) f("manual_linking", "low", "Manual identity linking is on", "Signed-in users can link other identities to their account.", "Turn it off unless the app needs it.");
  const providers = Object.keys(a).filter((k) => /^external_[a-z_]+_enabled$/.test(k) && a[k] && !/anonymous|email|phone/.test(k)).map((k) => k.replace(/^external_|_enabled$/g, ""));
  if (providers.length) f("providers", "info", `Social / SSO sign-in: ${providers.join(", ")}`, "These outside sign-in providers are switched on.", "Check each provider is still needed and its client secret is current.", { providers });
  return out;
}

async function postureOne(p: { ref: string; name: string }, s: Record<string, any>) {
  const ref = p.ref, T = tid(ref), F: Finding[] = [], P: Finding[] = [], stats: Record<string, unknown> = {};
  const add = (f: Finding) => F.push(f);
  const tryStep = async (name: string, fn: () => Promise<void>) => {
    try { await fn(); } catch (e) { const l = (stats.errors ??= []) as string[]; l.push(`${name}: ${(e as Error).message.slice(0, 200)}`); }
  };

  await tryStep("advisors", async () => { F.push(...await advisors(ref, "security")); });
  await tryStep("performance advisors", async () => { P.push(...await advisors(ref, "performance")); });
  await tryStep("auth config", async () => { F.push(...authChecks(ref, await mgmt(`/projects/${ref}/config/auth`))); });

  await tryStep("network", async () => {
    const n = await mgmt(`/projects/${ref}/network-restrictions`);
    const v4 = n?.config?.dbAllowedCidrs ?? [], v6 = n?.config?.dbAllowedCidrsV6 ?? [];
    const open = (!v4.length && !v6.length) || v4.includes("0.0.0.0/0") || v6.includes("::/0");
    if (open) add({ fingerprint: fp("sb", ref, "network.open"), source: "supabase", target_id: T, check_code: "network.open", category: "exposure", severity: "medium",
      title: "Database accepts connections from any address", detail: "Anyone on the internet can try to log in to Postgres directly (port 5432/6543). Only the password stands in the way.",
      remediation: "Project Settings › Database › Network Restrictions: allow only the office and server addresses that need direct access.", meta: { v4, v6 } });
  });
  await tryStep("ssl", async () => {
    const r = await mgmt(`/projects/${ref}/ssl-enforcement`);
    if (r?.currentConfig?.database === false) add({ fingerprint: fp("sb", ref, "ssl.off"), source: "supabase", target_id: T, check_code: "ssl.off", category: "exposure", severity: "high",
      title: "Database allows unencrypted connections", detail: "Direct connections may send passwords and data in clear text.", remediation: "Project Settings › Database › SSL: enforce SSL on incoming connections." });
  });
  await tryStep("backups", async () => {
    const b = await mgmt(`/projects/${ref}/database/backups`);
    const last = (b?.backups ?? []).filter((x: any) => x.status === "COMPLETED").map((x: any) => x.inserted_at).sort().pop();
    stats.pitr = !!b?.pitr_enabled; stats.last_backup = last;
    if (!b?.pitr_enabled && (!last || Date.now() - Date.parse(last) > 48 * 3600e3))
      add({ fingerprint: fp("sb", ref, "backup.stale"), source: "supabase", target_id: T, check_code: "backup.stale", category: "reliability", severity: "medium",
        title: last ? "No database backup in the last 48 hours" : "No database backups found",
        detail: last ? `Last completed backup: ${last}.` : "This project shows no completed backups (free projects have none).", remediation: "Use a paid plan for daily backups, or turn on point-in-time recovery for important data." });
  });

  // API keys: inventory and legacy JWT keys
  await tryStep("api keys", async () => {
    const keys: any[] = await mgmt(`/projects/${ref}/api-keys`) ?? [];
    let legacy: any = null;
    try { legacy = await mgmt(`/projects/${ref}/api-keys/legacy`); } catch { /* older API */ }
    const rows = await Promise.all(keys.map(async (k) => ({
      target_id: T, kind: "api_key", name: k.name ?? k.id, digest: await sha(String(k.id ?? "") + String(k.hash ?? k.api_key ?? "")),
      is_secret: k.type === "secret" || k.name === "service_role", meta: { type: k.type, prefix: k.prefix ?? null, description: k.description ?? null, created: k.inserted_at ?? null },
    })));
    stats.api_keys = await syncInventory("wd_secret", { target_id: T, kind: "api_key" }, rows, { kind: "api_key", label: (r) => r.name, digest: "digest" });
    const legacyOn = legacy ? legacy.enabled !== false : keys.some((k) => k.type === "legacy");
    if (legacyOn) add({ fingerprint: fp("sb", ref, "keys.legacy"), source: "supabase", target_id: T, check_code: "keys.legacy", category: "secrets", severity: "medium",
      title: "Legacy anon / service_role JWT keys still work", detail: "The old JWT keys never expire and cannot be rotated one at a time. A leaked service_role JWT gives full database access.",
      remediation: "Move every app to the publishable and secret keys (sb_publishable_ / sb_secret_), then Project Settings › API Keys › disable legacy keys." });
    const secrets = keys.filter((k) => k.type === "secret");
    if (secrets.length > 3) add({ fingerprint: fp("sb", ref, "keys.many_secret"), source: "supabase", target_id: T, check_code: "keys.many_secret", category: "secrets", severity: "low",
      title: `${secrets.length} secret API keys`, detail: "Each secret key is full access. Unused ones are risk without benefit.", remediation: "Delete secret keys nothing uses (Traffic shows which key prefixes are in use)." });
  });

  // edge functions
  let fns: any[] = [];
  await tryStep("edge functions", async () => {
    fns = await mgmt(`/projects/${ref}/functions`) ?? [];
    const rows = fns.map((f) => ({ target_id: T, slug: f.slug, name: f.name, version: f.version, status: f.status, verify_jwt: f.verify_jwt,
      created_src: f.created_at ? iso(f.created_at) : null, updated_src: f.updated_at ? iso(f.updated_at) : null }));
    stats.functions = await syncInventory("wd_edge_function", { target_id: T }, rows, { kind: "edge_function", label: (r) => r.slug, digest: "version" });
    for (const f of fns.filter((x) => x.verify_jwt === false && x.status === "ACTIVE"))
      add({ fingerprint: fp("sb", ref, "fn.nojwt", f.slug), source: "supabase", target_id: T, check_code: "function.no_jwt", category: "access", severity: "medium",
        title: `Edge function ${f.slug} accepts calls without a sign-in token`, detail: "JWT verification is off, so anyone with the URL can call it. Fine for webhooks and cron calls only if the function checks its own secret.",
        remediation: "Confirm the function checks a shared secret or signature; otherwise deploy it with verify_jwt on.", meta: { slug: f.slug, version: f.version } });
  });

  // edge function secrets (names and a fingerprint of the value; never the value)
  await tryStep("secrets", async () => {
    const sec: any[] = await mgmt(`/projects/${ref}/secrets`) ?? [];
    const rows = await Promise.all(sec.filter((x) => !/^SUPABASE_/.test(x.name)).map(async (x) => ({ target_id: T, kind: "edge_secret", name: x.name, digest: await sha(String(x.value ?? "")), is_secret: true })));
    stats.secrets = await syncInventory("wd_secret", { target_id: T, kind: "edge_secret" }, rows, { kind: "secret", label: (r) => r.name, digest: "digest" });
    const old: any[] = await q(db.from("wd_secret").select("name, first_seen, changed_at").match({ target_id: T, kind: "edge_secret", active: true }));
    for (const o of old) {
      const since = Date.parse(o.changed_at ?? o.first_seen);
      if (Date.now() - since > 180 * 86400e3 && /KEY|SECRET|TOKEN|PASSWORD/i.test(o.name))
        add({ fingerprint: fp("sb", ref, "secret.age", o.name), source: "supabase", target_id: T, check_code: "secret.age", category: "secrets", severity: "low",
          title: `Secret ${o.name} has not changed in 6 months`, detail: "Long-lived secrets are more likely to have leaked somewhere.", remediation: "Rotate it at the source, then update the edge function secret." });
    }
  });

  // database checks (one read-only query)
  await tryStep("database", async () => {
    const [r] = await sql(ref, `
      select
        (select coalesce(json_agg(json_build_object('s', schemaname, 't', tablename, 'p', policyname, 'cmd', cmd, 'roles', roles)), '[]')
           from pg_policies
          where schemaname not in ('auth','storage','realtime','supabase_functions','vault','cron','net','extensions','graphql','graphql_public','pgsodium','supabase_migrations')
            and roles && array['anon','public']::name[] and cmd in ('INSERT','UPDATE','DELETE','ALL')
            and coalesce(qual, 'true') = 'true' and coalesce(with_check, 'true') = 'true') as open_write,
        (select coalesce(json_agg(json_build_object('s', schemaname, 't', tablename, 'p', policyname)), '[]')
           from pg_policies
          where schemaname not in ('auth','storage','realtime','supabase_functions','vault','cron','net','extensions','graphql','graphql_public','pgsodium','supabase_migrations')
            and roles && array['anon','public']::name[] and cmd = 'SELECT' and qual = 'true') as open_read,
        (select coalesce(json_agg(json_build_object('id', id, 'limit', file_size_limit, 'mime', allowed_mime_types)), '[]') from storage.buckets where public) as public_buckets,
        (select coalesce(json_agg(rolname), '[]') from pg_roles where rolcanlogin and (rolsuper or rolbypassrls)
            and rolname not in ('postgres','supabase_admin','supabase_auth_admin','supabase_storage_admin','supabase_replication_admin','supabase_read_only_user',
                                'supabase_realtime_admin','supabase_etl_admin','authenticator','pgbouncer','supabase_functions_admin','dashboard_user','supabase_privileged_role')) as risky_roles,
        (select json_build_object('total', count(*), 'new_24h', count(*) filter (where created_at > now() - interval '24 hours'),
            'stale_90d', count(*) filter (where coalesce(last_sign_in_at, created_at) < now() - interval '90 days' and banned_until is null),
            'anonymous', count(*) filter (where is_anonymous)) from auth.users) as users,
        (select count(distinct user_id) from auth.mfa_factors where status = 'verified') as mfa_users,
        (select coalesce(json_agg(c), '[]') from (select usename as role, coalesce(application_name, '') as app, host(client_addr) as addr, coalesce(state, '') as state, count(*) as n
            from pg_stat_activity where backend_type = 'client backend' group by 1, 2, 3, 4) c) as connections,
        (select setting::int from pg_settings where name = 'max_connections') as max_conn,
        pg_database_size(current_database()) as db_bytes,
        to_regclass('cron.job') is not null as has_cron,
        to_regclass('extensions.pg_stat_statements') is not null as has_pss`);
    if (!r) return;
    stats.users = r.users; stats.mfa_users = r.mfa_users; stats.db_bytes = r.db_bytes;
    for (const w of r.open_write ?? []) add({ fingerprint: fp("sb", ref, "rls.open_write", w.s, w.t, w.p), source: "supabase", target_id: T, check_code: "rls.open_write", category: "data", severity: "high",
      title: `Anyone can ${w.cmd === "ALL" ? "change" : String(w.cmd).toLowerCase()} rows in ${w.s}.${w.t}`, detail: `Policy "${w.p}" lets ${(w.roles || []).join(", ")} ${w.cmd} with no condition (true).`,
      remediation: "Tighten the policy to signed-in users and a real condition, or write through a function that checks permissions.", meta: w });
    for (const w of r.open_read ?? []) add({ fingerprint: fp("sb", ref, "rls.open_read", w.s, w.t, w.p), source: "supabase", target_id: T, check_code: "rls.open_read", category: "data", severity: "medium",
      title: `Anyone can read ${w.s}.${w.t} without signing in`, detail: `Policy "${w.p}" lets the public read every row with the publishable key, which is in the browser.`,
      remediation: "If the data is not meant to be public, limit the policy to authenticated users (and their own rows).", meta: w });
    for (const b of r.public_buckets ?? []) add({ fingerprint: fp("sb", ref, "storage.public", b.id), source: "supabase", target_id: T, check_code: "storage.public", category: "data", severity: b.limit ? "low" : "medium",
      title: `Storage bucket ${b.id} is public`, detail: `Anyone with a file's URL can download it${b.limit ? "" : ", and there is no file-size limit"}.`,
      remediation: "Make the bucket private and hand out signed URLs, unless the files are meant to be public.", meta: b });
    for (const role of r.risky_roles ?? []) add({ fingerprint: fp("sb", ref, "role.super", role), source: "supabase", target_id: T, check_code: "role.superuser", category: "access", severity: "high",
      title: `Database login ${role} bypasses all security`, detail: "This login is a superuser or bypasses row-level security.", remediation: "Remove the attribute or the login if it is not needed." });
    const u = r.users || {};
    if (u.anonymous > 0) stats.anonymous_users = u.anonymous;
    if (u.stale_90d > 0) add({ fingerprint: fp("sb", ref, "users.stale"), source: "supabase", target_id: T, check_code: "users.stale", category: "access", severity: "low",
      title: `${u.stale_90d} account${u.stale_90d === 1 ? "" : "s"} unused for 90 days`, detail: `Of ${u.total} accounts, ${u.stale_90d} have not signed in for 90 days and are not blocked.`,
      remediation: "Ban or delete accounts that are no longer needed (leavers, test users).", meta: u });
    if (u.total > 0 && Number(r.mfa_users) / u.total < 0.5 && u.total >= 5) add({ fingerprint: fp("sb", ref, "users.mfa"), source: "supabase", target_id: T, check_code: "users.mfa", category: "access", severity: "info",
      title: `${r.mfa_users} of ${u.total} accounts use MFA`, detail: "Most accounts sign in with a password only.", remediation: "Require a second factor in the app for admin roles at least.", meta: { total: u.total, mfa: r.mfa_users } });

    // connections: snapshot, and direct logins from outside
    const conns: any[] = r.connections ?? [];
    await insertMany("wd_db_connection", conns.map((c) => ({ target_id: T, role_name: c.role, app_name: c.app, client_addr: c.addr, state: c.state, connections: c.n })));
    const total = conns.reduce((a, c) => a + Number(c.n), 0);
    if (r.max_conn && total / r.max_conn > 0.8) P.push({ fingerprint: fp("sb", ref, "conn.high"), source: "supabase", target_id: T, check_code: "connections.high", category: "reliability", severity: "medium",
      title: `${total} of ${r.max_conn} database connections in use`, detail: "The database is close to refusing new connections.", remediation: "Use the pooler (port 6543) for apps and scripts; look for connection leaks." });
    const known = s.known_ips || [];
    for (const c of conns) {
      if (!c.addr || isPrivateIp(c.addr) || ipInList(c.addr, known)) continue;
      if (/^(postgrest|realtime|supavisor|Supabase|pg_net|pgbouncer|storage|gotrue|auth)/i.test(c.app) || /^supabase_|^authenticator$/.test(c.role)) continue;
      add({ fingerprint: fp("sb", ref, "conn.direct", c.role, c.addr, new Date().toISOString().slice(0, 10)), source: "supabase", target_id: T, check_code: "connection.direct", category: "activity", severity: c.role === "postgres" ? "high" : "medium",
        title: `Direct database login as ${c.role} from ${c.addr}`, detail: `${c.n} connection(s), application "${c.app || "unknown"}". Not on the known addresses list.`,
        remediation: "If this is you or a known server, add the address in Settings › Known addresses; otherwise change the database password now.", meta: c });
    }

    // scheduled outbound calls (pg_cron)
    if (r.has_cron) {
      const jobs = await sql(ref, `select jobname, schedule, active, left(command, 1500) as command from cron.job`);
      const out: any[] = [];
      for (const j of jobs) for (const m of String(j.command).matchAll(/https?:\/\/([a-z0-9.-]+)(\/[^\s'"]*)?/gi))
        out.push({ target_id: T, via: "cron", host: m[1].toLowerCase(), detail: `${j.jobname} (${j.schedule})${j.active ? "" : " paused"}`.slice(0, 200) });
      const uniq = [...new Map(out.map((o) => [o.via + o.host + o.detail, o])).values()];
      stats.outbound = await syncInventory("wd_outbound", { target_id: T, via: "cron" }, uniq, { kind: "outbound", label: (o) => `${o.host} · ${o.detail}` });
      stats.cron_jobs = jobs.length;
    }

    // slow queries
    if (r.has_pss) {
      const top = await sql(ref, `select s.queryid::text as queryid, r.rolname as role, s.calls, round(s.total_exec_time::numeric, 1) as total_ms,
          round(s.mean_exec_time::numeric, 2) as mean_ms, round(s.max_exec_time::numeric, 2) as max_ms, s.rows, left(s.query, 2000) as query
        from extensions.pg_stat_statements s join pg_roles r on r.oid = s.userid
        where s.query not ilike '%pg_stat_statements%' and r.rolname not in ('supabase_admin','supabase_read_only_user')
        order by s.total_exec_time desc limit 25`);
      await insertMany("wd_query_stat", top.map((x: any) => ({ target_id: T, queryid: x.queryid, role_name: x.role, calls: x.calls, total_ms: x.total_ms, mean_ms: x.mean_ms, max_ms: x.max_ms, rows_out: x.rows, query: x.query })));
      const slow = Number(s.slow_query_ms ?? 500);
      for (const x of top.filter((x: any) => Number(x.mean_ms) > slow && Number(x.calls) >= 50))
        P.push({ fingerprint: fp("sb", ref, "query.slow", x.queryid), source: "supabase", target_id: T, check_code: "query.slow", category: "performance", severity: Number(x.mean_ms) > slow * 4 ? "high" : "medium",
          title: `Slow query: ${Math.round(Number(x.mean_ms))} ms on average, ${x.calls} runs`, detail: String(x.query).slice(0, 400),
          remediation: "Check the plan with EXPLAIN ANALYZE; add an index on the columns in WHERE / JOIN, or cache the result.", meta: { queryid: x.queryid, role: x.role, mean_ms: x.mean_ms, calls: x.calls } });
    }
  });

  await patchTargetMeta(T, { posture: { at: nowIso(), ...stats, functions_count: fns.length } });
  const a = await syncFindings(`supabase:posture:${ref}`, F);
  const b = await syncFindings(`supabase:perf:${ref}`, P);
  return { ref, findings: F.length, perf: P.length, sync: a, perf_sync: b, errors: stats.errors };
}

// organisation members without MFA
async function orgs(list: { org: string }[]) {
  const out: any[] = [];
  for (const org of [...new Set(list.map((p) => p.org).filter(Boolean))]) {
    const T = `supabase-org:${org}`;
    try {
      const members: any[] = await mgmt(`/organizations/${org}/members`) ?? [];
      await upsertTargets([{ id: T, kind: "supabase", ref: org, name: `Supabase organisation ${org}`, meta: { org: true, members: members.map((m) => ({ name: m.user_name, email: m.email, role: m.role_name, mfa: m.mfa_enabled })) } }]);
      const F: Finding[] = members.filter((m) => m.mfa_enabled === false).map((m) => ({
        fingerprint: fp("sborg", org, "member.nomfa", m.user_id ?? m.email), source: "supabase", target_id: T, check_code: "org.member_no_mfa", category: "access",
        severity: /owner|admin/i.test(m.role_name ?? "") ? "critical" : "high",
        title: `${m.user_name || m.email} (${m.role_name}) has no MFA on Supabase`, detail: "Anyone with this person's password can open every project in the organisation, read all data and see all keys.",
        remediation: "Ask them to turn on MFA (Account › Security), then enforce MFA for the organisation (Organisation settings › Security).", meta: { role: m.role_name },
      }));
      out.push({ org, members: members.length, sync: await syncFindings(`supabase:org:${org}`, F) });
    } catch (e) { out.push({ org, error: (e as Error).message.slice(0, 200) }); }
  }
  return out;
}

export async function runPosture() {
  if (!PAT) { await setConnector("supabase", { ok: false, note: "SUPABASE_PAT secret not set" }); return { skipped: "SUPABASE_PAT not set" }; }
  const s = await settings();
  const list = await projects();
  const res = await pool(list, 3, (p) => postureOne(p, s));
  const org = await orgs(list);
  await q(db.rpc("wd_posture_snapshot"));
  const failed = res.filter((r) => r.status === "rejected").map((r: any) => r.reason?.message?.slice(0, 200));
  await setConnector("supabase", { ok: !failed.length, projects: list.length, failed: failed.length });
  return { projects: list.length, results: res.map((r: any) => r.value ?? { error: r.reason?.message }), org };
}

// ================================================================== logs
const TRAFFIC_SQL = `
select toStartOfFifteenMinutes(timestamp) as b,
  log_attributes['request.method'] as method,
  arrayStringConcat(arraySlice(splitByChar('/', log_attributes['request.path']), 1, if(splitByChar('/', log_attributes['request.path'])[4] = 'rpc', 5, 4)), '/') as path,
  toInt32OrZero(log_attributes['response.status_code']) as status,
  log_attributes['request.cf.country'] as country, log_attributes['request.cf.city'] as city,
  log_attributes['request.cf.asOrganization'] as asn, log_attributes['request.headers.cf_connecting_ip'] as ip,
  log_attributes['request.sb.apikey.apikey.prefix'] as kp, log_attributes['request.sb.jwt.authorization.payload.role'] as jr,
  log_attributes['request.sb.auth_user'] as uid,
  multiIf(log_attributes['request.headers.user_agent'] ilike '%SupabaseEdgeRuntime%' or log_attributes['request.headers.user_agent'] like 'Deno/%', 'supabase',
          match(log_attributes['request.headers.user_agent'], '(?i)bot|crawl|spider|scan|zgrab|masscan|nuclei|sqlmap'), 'bot',
          match(log_attributes['request.headers.user_agent'], '(?i)curl|python|wget|go-http|okhttp|axios|node|postman|insomnia|powershell|java/'), 'script',
          log_attributes['request.headers.user_agent'] like 'Mozilla/%', 'browser', log_attributes['request.headers.user_agent'] = '', 'none', 'other') as agent,
  count() as n, sum(toInt64OrZero(log_attributes['response.headers.content_length'])) as bytes,
  round(avg(toFloat64OrZero(log_attributes['response.origin_time'])), 1) as ms
from logs where source = 'edge_logs'
group by b, method, path, status, country, city, asn, ip, kp, jr, uid, agent
limit 20000`;
const FUNC_SQL = `
select toStartOfFifteenMinutes(timestamp) as b, log_attributes['request.method'] as method,
  arrayStringConcat(arraySlice(splitByChar('/', log_attributes['request.pathname']), 1, 4), '/') as path,
  toInt32OrZero(log_attributes['response.status_code']) as status,
  log_attributes['request.cf.country'] as country, log_attributes['request.cf.city'] as city,
  log_attributes['request.cf.asOrganization'] as asn, log_attributes['request.headers.cf_connecting_ip'] as ip,
  multiIf(log_attributes['request.headers.user_agent'] ilike '%SupabaseEdgeRuntime%' or log_attributes['request.headers.user_agent'] like 'Deno/%' or log_attributes['request.headers.user_agent'] like 'pg_net/%', 'supabase',
          match(log_attributes['request.headers.user_agent'], '(?i)bot|crawl|spider|scan'), 'bot',
          match(log_attributes['request.headers.user_agent'], '(?i)curl|python|wget|go-http|okhttp|axios|node|postman|insomnia|powershell|java/'), 'script',
          log_attributes['request.headers.user_agent'] like 'Mozilla/%', 'browser', log_attributes['request.headers.user_agent'] = '', 'none', 'other') as agent,
  count() as n, round(avg(toFloat64OrZero(log_attributes['execution_time_ms'])), 1) as ms
from logs where source = 'function_edge_logs' and log_attributes['request.method'] != 'OPTIONS'
group by b, method, path, status, country, city, asn, ip, agent
limit 10000`;
const AUDIT_SQL = `
select timestamp as at, log_attributes['auth_audit_event.action'] as action, log_attributes['auth_audit_event.actor_id'] as actor_id,
  log_attributes['auth_audit_event.actor_username'] as email, log_attributes['auth_audit_event.audit_log_id'] as id,
  log_attributes['auth_audit_event.user_agent'] as ua, log_attributes['auth_audit_event.request_id'] as rid,
  log_attributes['auth_audit_event.log_type'] as log_type
from logs where source = 'auth_audit_logs' and log_attributes['auth_audit_event.action'] not in ('token_refreshed', 'token_revoked')
limit 5000`;
const AUTHLOG_SQL = `
select timestamp as at, log_attributes['request_id'] as rid, log_attributes['remote_addr'] as ip, toInt32OrZero(log_attributes['status']) as status,
  log_attributes['path'] as path, log_attributes['error_code'] as code, log_attributes['error'] as err, log_attributes['referer'] as referer
from logs where source = 'auth_logs' and log_attributes['msg'] = 'request completed'
  and (toInt32OrZero(log_attributes['status']) >= 400 or log_attributes['path'] in ('/token', '/verify', '/signup', '/otp', '/recover', '/logout', '/user', '/factors', '/magiclink', '/invite'))
  and log_attributes['path'] not like '/.well-known%'
limit 10000`;
const PG_SQL = `
select log_attributes['parsed.error_severity'] as sev, log_attributes['parsed.sql_state_code'] as code,
  substring(event_message, 1, 160) as msg, log_attributes['parsed.user_name'] as usr, log_attributes['parsed.connection_from'] as host, count() as n
from logs where source = 'postgres_logs' and log_attributes['parsed.error_severity'] in ('ERROR', 'FATAL', 'PANIC')
group by sev, code, msg, usr, host order by n desc limit 200`;

const keyType = (kp: string, jr: string) =>
  kp.startsWith("sb_secret_") ? "secret" : jr === "service_role" ? "service_role_jwt" : jr === "authenticated" ? "user" :
  kp.startsWith("sb_publishable_") ? "publishable" : jr === "anon" ? "anon_jwt" : "none";
const channelOf = (path: string) => {
  const s = path.split("/")[1] || "";
  return ({ rest: "rest", auth: "auth", storage: "storage", realtime: "realtime", graphql: "graphql", functions: "function" } as any)[s] ?? "other";
};

async function logsOne(p: { ref: string; name: string }, s: Record<string, any>) {
  const ref = p.ref, T = tid(ref);
  const t = await q(db.from("wd_target").select("meta").eq("id", T).single());
  const end = new Date(Date.now() - 60_000);
  let start = t.meta?.logs_until ? new Date(t.meta.logs_until) : new Date(end.getTime() - 3600e3);
  if (end.getTime() - start.getTime() > 23.5 * 3600e3) start = new Date(end.getTime() - 23.5 * 3600e3);
  if (end <= start) return { ref, skipped: true };
  const S = iso(start), E = iso(end);
  const known: string[] = s.known_ips || [], allowed = new Set<string>(s.allowed_countries || ["ZA"]);
  const F: Finding[] = [];
  const day = S.slice(0, 10);

  const [traffic, funcs, audit, authlog, pg] = await Promise.all([
    logs(ref, TRAFFIC_SQL, S, E), logs(ref, FUNC_SQL, S, E).catch(() => []), logs(ref, AUDIT_SQL, S, E).catch(() => []),
    logs(ref, AUTHLOG_SQL, S, E).catch(() => []), logs(ref, PG_SQL, S, E).catch(() => []),
  ]);

  const ipCountry = new Map<string, string>();
  const rows = traffic.map((r: any) => {
    if (r.ip && r.country) ipCountry.set(r.ip, r.country);
    return { bucket: r.b + "Z", target_id: T, channel: channelOf(r.path || ""), method: r.method, path: r.path, status: r.status,
      country: r.country || null, city: r.city || null, asn_org: r.asn || null, ip: r.ip || null, key_type: keyType(r.kp || "", r.jr || ""),
      key_id: r.kp || null, auth_user: r.uid || null, agent: r.agent, requests: Number(r.n), bytes_out: Number(r.bytes) || 0, avg_ms: r.ms };
  });
  const frows = funcs.map((r: any) => ({ bucket: r.b + "Z", target_id: T, channel: "function", method: r.method, path: r.path, status: r.status,
    country: r.country || null, city: r.city || null, asn_org: r.asn || null, ip: r.ip || null, key_type: null, key_id: null, auth_user: null,
    agent: r.agent, requests: Number(r.n), bytes_out: 0, avg_ms: r.ms }));
  await insertMany("wd_traffic", [...rows, ...frows]);

  // ---- heuristics on traffic
  const byIp = new Map<string, { n: number; denied: number; bytes: number; country: string; asn: string; agents: Set<string> }>();
  for (const r of rows) {
    if (!r.ip) continue;
    const x = byIp.get(r.ip) ?? { n: 0, denied: 0, bytes: 0, country: r.country ?? "", asn: r.asn_org ?? "", agents: new Set() };
    x.n += r.requests; x.bytes += r.bytes_out; if (r.status === 401 || r.status === 403) x.denied += r.requests; x.agents.add(r.agent);
    byIp.set(r.ip, x);
    // secret keys
    if ((r.key_type === "secret" || r.key_type === "service_role_jwt") && r.agent !== "supabase" && !ipInList(r.ip, known)) {
      const browser = r.agent === "browser";
      F.push({ fingerprint: fp("sb", ref, "act.secret_key", r.key_id ?? r.key_type, r.ip, day), source: "supabase", target_id: T, check_code: browser ? "activity.secret_key_browser" : "activity.secret_key_unknown_ip",
        category: "activity", severity: browser ? "critical" : "high",
        title: browser ? `Secret key used from a web browser (${r.ip})` : `Secret key used from an unfamiliar address ${r.ip}`,
        detail: `${r.key_id || r.key_type} called ${r.method} ${r.path} from ${r.city ?? ""} ${r.country ?? ""} (${r.asn_org ?? "unknown network"}), agent ${r.agent}. ${browser ? "A secret key in a browser means it is in front-end code or someone copied it." : "Not a Supabase function and not on the known addresses list."}`,
        remediation: browser ? "Rotate the secret key now (Project Settings › API Keys), then find where it leaked (Netlify scan, repo)." : "If this is a known server, add it to Settings › Known addresses. If not, rotate the key.",
        meta: { ip: r.ip, key: r.key_id, agent: r.agent, path: r.path, country: r.country, asn: r.asn_org } });
    }
  }
  const deniedT = Number(s.denied_request_threshold ?? 200), dlT = Number(s.download_mb_threshold ?? 100) * 1048576;
  for (const [ip, x] of byIp) {
    if (ipInList(ip, known)) continue;
    if (x.denied >= deniedT) F.push({ fingerprint: fp("sb", ref, "act.denied", ip, day), source: "supabase", target_id: T, check_code: "activity.probing", category: "activity", severity: "medium",
      title: `${x.denied} refused requests from ${ip}`, detail: `${ip} (${x.country}, ${x.asn}) was refused ${x.denied} times out of ${x.n} requests. Looks like probing or a broken script.`,
      remediation: "Look at Traffic for this address. Block it with Network Restrictions / Netlify if it is hostile.", meta: { ip, ...x, agents: [...x.agents] } });
    if (x.bytes >= dlT) F.push({ fingerprint: fp("sb", ref, "act.download", ip, day), source: "supabase", target_id: T, check_code: "activity.large_download", category: "activity", severity: x.agents.has("browser") ? "medium" : "high",
      title: `${(x.bytes / 1048576).toFixed(0)} MB sent to ${ip}`, detail: `${ip} (${x.country}, ${x.asn}) pulled ${(x.bytes / 1048576).toFixed(1)} MB in ${x.n} requests since ${S.slice(11, 16)} UTC.`,
      remediation: "Check who this is and what they read (Traffic › by address). Unexpected bulk reads may be data leaving.", meta: { ip, bytes: x.bytes, requests: x.n } });
    if (x.country && !allowed.has(x.country) && x.agents.has("browser") && x.n >= 20)
      F.push({ fingerprint: fp("sb", ref, "act.country", x.country, day), source: "supabase", target_id: T, check_code: "activity.foreign_browser", category: "activity", severity: "low",
        title: `People using ${p.name} from ${x.country}`, detail: `Browser traffic from ${ip} in ${x.country} (${x.asn}): ${x.n} requests.`,
        remediation: "Expected if staff travel; otherwise check which account it was.", meta: { ip, country: x.country } });
  }
  const bots = rows.filter((r) => r.agent === "bot" || r.agent === "script").reduce((m, r) => m.set(r.ip, (m.get(r.ip) ?? 0) + r.requests), new Map());
  for (const [ip, n] of bots) if (n >= 100 && !ipInList(ip, known))
    F.push({ fingerprint: fp("sb", ref, "act.script", ip, day), source: "supabase", target_id: T, check_code: "activity.script", category: "activity", severity: "low",
      title: `Scripted calls from ${ip}`, detail: `${n} requests with a script or scanner user agent.`, remediation: "Fine if it is one of ours (add it to Known addresses).", meta: { ip, n } });

  // ---- auth events
  const reqIp = new Map<string, string>();
  for (const a of authlog) if (a.rid) reqIp.set(a.rid, a.ip);
  const events: any[] = audit.map((a: any) => {
    const ip = reqIp.get(a.rid) || null;
    return { at: a.at + "Z", target_id: T, action: a.action, actor_id: a.actor_id || null, actor_email: a.email || null, ip, country: ip ? ipCountry.get(ip) ?? null : null,
      user_agent: (a.ua || "").slice(0, 300) || null, ok: true, meta: { log_type: a.log_type }, src_id: `${ref}:${a.id}` };
  });
  const fails = authlog.filter((a: any) => a.status >= 400 && a.status !== 404 && !(a.path === "/user" && a.status === 403 && a.code === "bad_jwt"));
  for (const a of fails) events.push({ at: a.at + "Z", target_id: T, action: a.path === "/token" ? "failed_login" : `failed${a.path.replace(/\//g, "_")}`,
    actor_id: null, actor_email: null, ip: a.ip || null, country: a.ip ? ipCountry.get(a.ip) ?? null : null, user_agent: null, ok: false,
    meta: { status: a.status, code: a.code, error: String(a.err ?? "").slice(0, 200), referer: a.referer }, src_id: `${ref}:req:${a.rid}` });
  if (events.length) await insertMany("wd_auth_event", events, { onConflict: "src_id", ignoreDuplicates: true });

  const failT = Number(s.failed_login_threshold ?? 10);
  const failByIp = new Map<string, number>();
  for (const a of fails.filter((x: any) => x.path === "/token" || x.path === "/verify" || x.path === "/otp")) failByIp.set(a.ip, (failByIp.get(a.ip) ?? 0) + 1);
  for (const [ip, n] of failByIp) if (n >= failT && !ipInList(ip, known))
    F.push({ fingerprint: fp("sb", ref, "act.bruteforce", ip, day), source: "supabase", target_id: T, check_code: "activity.password_guessing", category: "activity", severity: n >= failT * 5 ? "critical" : "high",
      title: `${n} failed sign-ins from ${ip}`, detail: `${ip} (${ipCountry.get(ip) ?? "unknown country"}) failed to sign in to ${p.name} ${n} times since ${S.slice(11, 16)} UTC.`,
      remediation: "Possible password guessing. Block the address, check the accounts it tried, turn on CAPTCHA / rate limits.", meta: { ip, n } });
  for (const e of events.filter((e) => e.ok && e.action === "login" && e.country && !allowed.has(e.country)))
    F.push({ fingerprint: fp("sb", ref, "act.login_country", e.actor_email, e.country, day), source: "supabase", target_id: T, check_code: "activity.login_abroad", category: "activity", severity: "high",
      title: `${e.actor_email ?? "A user"} signed in from ${e.country}`, detail: `Sign-in to ${p.name} from ${e.ip} (${e.country}). Countries you expect: ${[...allowed].join(", ")}.`,
      remediation: "Confirm with the person. If it was not them, sign them out everywhere and reset the password.", meta: { ip: e.ip, email: e.actor_email } });
  for (const e of events.filter((e) => ["user_deleted", "user_invited", "user_signedup", "identity_unlinked", "factor_deleted", "user_modified"].includes(e.action) && e.ok)) {
    if (e.action === "user_signedup") continue; // counted below
    if (e.action === "factor_deleted") F.push({ fingerprint: fp("sb", ref, "act.factor_deleted", e.actor_id, day), source: "supabase", target_id: T, check_code: "activity.mfa_removed", category: "activity", severity: "medium",
      title: `${e.actor_email ?? "A user"} removed an MFA factor`, detail: `On ${p.name} at ${e.at}.`, remediation: "Check it was intended.", meta: { email: e.actor_email } });
  }
  const signups = events.filter((e) => e.action === "user_signedup").length;
  if (signups >= 5) F.push({ fingerprint: fp("sb", ref, "act.signups", day), source: "supabase", target_id: T, check_code: "activity.signups", category: "activity", severity: "medium",
    title: `${signups} new accounts on ${p.name}`, detail: `Since ${S.slice(11, 16)} UTC.`, remediation: "Expected for a launch; otherwise check for bot sign-ups and close sign-up.", meta: { n: signups } });

  // ---- database errors
  const pwFails = pg.filter((x: any) => x.code === "28P01" || /password authentication failed/i.test(x.msg));
  const pwN = pwFails.reduce((a: number, x: any) => a + Number(x.n), 0);
  if (pwN >= 5) F.push({ fingerprint: fp("sb", ref, "act.pg_password", day), source: "supabase", target_id: T, check_code: "activity.db_password_guessing", category: "activity", severity: "high",
    title: `${pwN} failed database logins`, detail: pwFails.slice(0, 5).map((x: any) => `${x.n}× ${x.usr ?? ""} ${x.host ?? ""}: ${x.msg}`).join("\n"),
    remediation: "Someone is trying database passwords. Restrict Network Restrictions to known addresses and use a long random password.", meta: { n: pwN } });
  const perm = pg.filter((x: any) => x.code === "42501").reduce((a: number, x: any) => a + Number(x.n), 0);
  if (perm >= 50) F.push({ fingerprint: fp("sb", ref, "act.pg_denied", day), source: "supabase", target_id: T, check_code: "activity.db_permission_denied", category: "activity", severity: "low",
    title: `${perm} "permission denied" errors in the database`, detail: "Calls blocked by grants or row-level security. Usually an app bug; sometimes someone exploring.",
    remediation: "See Postgres logs for the table and role.", meta: { n: perm } });
  const errs = pg.filter((x: any) => x.sev !== "LOG").reduce((a: number, x: any) => a + Number(x.n), 0);

  await patchTargetMeta(T, { logs_until: E, logs: { at: nowIso(), requests: rows.reduce((a, r) => a + r.requests, 0), fn_calls: frows.reduce((a, r) => a + r.requests, 0), auth_events: events.length, pg_errors: errs } });
  const sync = await syncFindings("supabase:activity", F, false);
  return { ref, rows: rows.length + frows.length, events: events.length, activity: F.length, sync };
}

export async function runLogs() {
  if (!PAT) return { skipped: "SUPABASE_PAT not set" };
  const s = await settings();
  const list = await projects();
  const res = await pool(list, 3, (p) => logsOne(p, s));
  return { projects: list.length, results: res.map((r: any) => r.value ?? { error: r.reason?.message?.slice(0, 300) }) };
}
