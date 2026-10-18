// NFG Watchdog collector (edge function wd-collect on NFG-Watchdog).
// Called by pg_cron (header x-wd-cron, checked against the vault secret) or by a Watchdog admin's "Run now"
// (their own session, which must be at aal2 and on the wd_user list as admin). Answers at once; the job runs in the background.
// Jobs: logs (15 min), supabase (hourly posture), netlify (hourly), entra (hourly), prune (nightly, 90 days), all.
//
// Secrets (Edge Functions › Secrets on NFG-Watchdog):
//   WD_SUPABASE_PAT      access token of a read-only member of the NFG Supabase organisation
//   NETLIFY_TOKEN        Netlify personal access token (read)
//   ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET   the Watchdog app registration (directory read only)
//   MAIL_CLIENT_ID / MAIL_CLIENT_SECRET [/ MAIL_TENANT_ID]   the existing "NFG Normandien – Mail" app (Mail.Send) for alerts
//   MAIL_FROM            optional: defaults to noreply@normandien.co.za
//   WD_TEAMS_WEBHOOK     optional: Teams workflow URL for alerts
//   WD_PORTAL_URL        optional: defaults to https://watchdog.normandien.co.za
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
import { db, q, nowIso, SB_URL, syncFindings, fp, type Finding } from "./lib.ts";
import { runPosture, runLogs, supabaseReady } from "./supabase.ts";
import { runNetlify, netlifyReady } from "./netlify.ts";
import { runEntra, entraReady } from "./entra.ts";
import { deliverAlerts } from "./alerts.ts";
import { mailReady } from "./mail.ts";

const ORIGINS = [/^https:\/\/watchdog\.normandien\.co\.za$/, /^https:\/\/[a-z0-9-]+\.netlify\.app$/, /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/];
const cors = (req: Request) => {
  const o = req.headers.get("origin") ?? "";
  return { "Access-Control-Allow-Origin": ORIGINS.some((r) => r.test(o)) ? o : "https://watchdog.normandien.co.za", "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Allow-Methods": "POST, OPTIONS", Vary: "Origin" };
};
const json = (req: Request, body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors(req), "content-type": "application/json" } });

async function prune() {
  const cut = new Date(Date.now() - 90 * 86400e3).toISOString(), cutDay = cut.slice(0, 10);
  const plan: [string, string, string][] = [
    ["wd_traffic", "bucket", cut], ["wd_auth_event", "at", cut], ["wd_db_connection", "observed_at", cut], ["wd_query_stat", "observed_at", cut],
    ["wd_audit_external", "at", cut], ["wd_entra_signin", "at", cut], ["wd_change", "at", cut], ["wd_run", "started_at", cut], ["wd_alert", "at", cut],
    ["wd_access_log", "at", cut], ["wd_posture_daily", "day", cutDay], ["wd_netlify_deploy", "created_src", cut],
  ];
  const out: Record<string, number | string> = {};
  for (const [t, c, v] of plan) {
    const r = await db.from(t).delete({ count: "exact" }).lt(c, v);
    out[t] = r.error ? r.error.message : r.count ?? 0;
  }
  const f = await db.from("wd_finding").delete({ count: "exact" }).eq("status", "resolved").lt("resolved_at", cut);
  out.wd_finding = f.count ?? 0;
  for (const t of ["wd_edge_function", "wd_secret", "wd_outbound"]) {
    const r = await db.from(t).delete({ count: "exact" }).eq("active", false).lt("last_seen", cut);
    out[t] = r.count ?? 0;
  }
  out.quiet_activity_closed = await q(db.rpc("wd_close_quiet_activity"));
  return out;
}

// Watchdog watching itself: missing connections, failing or silent jobs
async function selfCheck() {
  const F: Finding[] = [];
  const base = { source: "watchdog", target_id: null, category: "config" as const };
  if (!supabaseReady()) F.push({ ...base, fingerprint: fp("wd", "conn", "supabase"), check_code: "watchdog.no_supabase", severity: "high", title: "Watchdog cannot see the Supabase projects yet",
    detail: "The WD_SUPABASE_PAT secret is not set, so no project is being checked.", remediation: "Create an access token for a read-only org member and save it as WD_SUPABASE_PAT on NFG-Watchdog › Edge Functions › Secrets." });
  if (!netlifyReady()) F.push({ ...base, fingerprint: fp("wd", "conn", "netlify"), check_code: "watchdog.no_netlify", severity: "medium", title: "Watchdog cannot see Netlify yet",
    detail: "The NETLIFY_TOKEN secret is not set.", remediation: "Netlify › User settings › Applications › New access token; save it as NETLIFY_TOKEN." });
  if (!entraReady()) F.push({ ...base, fingerprint: fp("wd", "conn", "entra"), check_code: "watchdog.no_entra", severity: "medium", title: "Watchdog cannot see Entra ID / 365 yet",
    detail: "ENTRA_TENANT_ID, ENTRA_CLIENT_ID or ENTRA_CLIENT_SECRET is not set.", remediation: "Register the NFG Watchdog app in Entra (see the go-live checklist) and save the three secrets." });
  if (!mailReady()) F.push({ ...base, fingerprint: fp("wd", "conn", "mail"), check_code: "watchdog.no_mail", severity: "medium", title: "Watchdog cannot send email yet",
    detail: "MAIL_CLIENT_ID or MAIL_CLIENT_SECRET is not set, so alerts are recorded but not emailed.", remediation: "Entra › App registrations › NFG Normandien – Mail › Certificates & secrets › New client secret \"NFG Watchdog\". Save MAIL_CLIENT_ID (its Application ID) and MAIL_CLIENT_SECRET on NFG-Watchdog, plus MAIL_TENANT_ID if ENTRA_TENANT_ID is not set." });
  const runs: any[] = await q(db.from("wd_run").select("job, ok, started_at, error").gte("started_at", new Date(Date.now() - 3 * 3600e3).toISOString()).order("started_at", { ascending: false }));
  for (const job of ["logs", "supabase"]) {
    const last = runs.find((r) => r.job === job);
    if (last && last.ok === false) F.push({ ...base, fingerprint: fp("wd", "job", job), check_code: "watchdog.job_failed", severity: "medium", category: "reliability" as any,
      title: `Watchdog's ${job} job failed`, detail: String(last.error ?? "").slice(0, 400), remediation: "Admin › Runs shows the error. Usually an expired token." });
  }
  await syncFindings("watchdog:self", F);
}

const JOBS: Record<string, () => Promise<unknown>> = {
  logs: runLogs, supabase: runPosture, netlify: runNetlify, entra: runEntra, prune,
  all: async () => ({ supabase: await runPosture(), netlify: await runNetlify(), entra: await runEntra(), logs: await runLogs() }),
};

async function run(job: string, byUser: string | null) {
  const { data: row } = await db.from("wd_run").insert({ job, by_user: byUser }).select("id").single();
  let ok = true, stats: unknown = {}, error: string | null = null;
  try { stats = await JOBS[job](); } catch (e) { ok = false; error = (e as Error).message?.slice(0, 1000) ?? String(e); }
  try { if (job !== "prune") { await selfCheck(); (stats as any).alerts = await deliverAlerts(); } } catch (e) { error = (error ? error + "; " : "") + "alerts: " + (e as Error).message; }
  await db.from("wd_run").update({ finished_at: nowIso(), ok, stats, error }).eq("id", row?.id);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(req) });
  const job = new URL(req.url).searchParams.get("job") ?? "";
  if (!JOBS[job]) return json(req, { error: "Unknown job" }, 400);

  let byUser: string | null = null;
  const cronSecret = req.headers.get("x-wd-cron");
  if (cronSecret) {
    const ok = await q(db.rpc("wd_cron_ok", { p_secret: cronSecret })).catch(() => false);
    if (!ok) return json(req, { error: "Not allowed" }, 401);
    byUser = "schedule";
  } else {
    const auth = req.headers.get("authorization") ?? "";
    if (!auth.startsWith("Bearer ")) return json(req, { error: "Sign in first" }, 401);
    const user = createClient(SB_URL, Deno.env.get("SUPABASE_ANON_KEY") ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { global: { headers: { Authorization: auth } }, auth: { persistSession: false } });
    const { data: me } = await user.rpc("wd_me");
    if (!me || me.role !== "admin" || !me.active || me.aal !== "aal2") return json(req, { error: "Only a Watchdog admin (signed in with the authenticator app) can run the collector." }, 403);
    byUser = me.email;
  }
  // @ts-ignore EdgeRuntime is provided by Supabase
  EdgeRuntime.waitUntil(run(job, byUser));
  return json(req, { started: job }, 202);
});
