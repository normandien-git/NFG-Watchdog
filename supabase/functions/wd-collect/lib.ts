// NFG Watchdog collector: shared helpers (database, findings, inventory, small utilities).
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

export const SB_URL = Deno.env.get("SUPABASE_URL")!;
export const db = createClient(SB_URL, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

export type Sev = "critical" | "high" | "medium" | "low" | "info";
export type Finding = {
  fingerprint: string; source: string; target_id?: string | null; check_code: string; category: string;
  severity: Sev; title: string; detail?: string; remediation?: string; meta?: Record<string, unknown>;
};

export const q = async (p: PromiseLike<{ data: any; error: any }>): Promise<any> => {
  const r = await p;
  if (r.error) throw new Error(r.error.message ?? String(r.error));
  return r.data;
};

export const sha = async (s: string) => {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
};
export const fp = (...parts: unknown[]) => parts.map((p) => String(p ?? "")).join("|");
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const iso = (d: Date | number) => new Date(d).toISOString();
export const nowIso = () => new Date().toISOString();

// run fn over items, n at a time
export async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<PromiseSettledResult<R>[]> {
  const out: PromiseSettledResult<R>[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      try { out[k] = { status: "fulfilled", value: await fn(items[k]) }; }
      catch (e) { out[k] = { status: "rejected", reason: e }; }
    }
  });
  await Promise.all(workers);
  return out;
}

// fetch JSON with retries on 429 / 5xx
export async function getJson(url: string, init: RequestInit = {}, tries = 4): Promise<any> {
  for (let a = 1; ; a++) {
    const r = await fetch(url, init);
    if (r.ok) {
      const t = await r.text();
      return t ? JSON.parse(t) : null;
    }
    if ((r.status === 429 || r.status >= 500) && a < tries) {
      const ra = Number(r.headers.get("retry-after")) || a * 3;
      await sleep(Math.min(ra, 20) * 1000);
      continue;
    }
    const body = (await r.text()).slice(0, 300);
    const err = new Error(`${r.status} ${url.replace(/\?.*$/, "")}: ${body}`) as Error & { status?: number };
    err.status = r.status;
    throw err;
  }
}

// ---------- settings ----------
let _settings: Record<string, any> | null = null;
export async function settings(): Promise<Record<string, any>> {
  if (_settings) return _settings;
  const rows = await q(db.from("wd_setting").select("key, value"));
  _settings = Object.fromEntries(rows.map((r: any) => [r.key, r.value]));
  return _settings!;
}
export async function setConnector(name: string, info: Record<string, unknown>) {
  const s = await settings();
  const c = { ...(s.connectors || {}), [name]: { ...info, at: nowIso() } };
  s.connectors = c;
  await q(db.from("wd_setting").update({ value: c, updated_at: nowIso() }).eq("key", "connectors"));
}

// ---------- IP helpers ----------
const v4 = (ip: string) => ip.split(".").reduce((a, o) => (a << 8) + (Number(o) & 255), 0) >>> 0;
export function ipInList(ip: string | null | undefined, list: string[] = []): boolean {
  if (!ip) return false;
  for (const e of list) {
    const [net, bits] = String(e).trim().split("/");
    if (!bits) { if (net === ip) return true; continue; }
    if (ip.includes(":") || net.includes(":")) { if (ip.startsWith(net.replace(/::.*$/, ""))) return true; continue; }
    const b = Number(bits), mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
    if ((v4(ip) & mask) === (v4(net) & mask)) return true;
  }
  return false;
}
export const isPrivateIp = (ip?: string | null) =>
  !ip || /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);

// ---------- targets ----------
export async function upsertTargets(rows: { id: string; kind: string; ref: string; name: string; url?: string; meta?: any }[]) {
  if (!rows.length) return;
  await q(db.from("wd_target").upsert(rows.map((r) => ({ ...r, last_seen: nowIso(), active: true })), { onConflict: "id" }));
}
export async function patchTargetMeta(id: string, patch: Record<string, unknown>) {
  const t = await q(db.from("wd_target").select("meta").eq("id", id).maybeSingle());
  await q(db.from("wd_target").update({ meta: { ...(t?.meta || {}), ...patch } }).eq("id", id));
}

// ---------- findings ----------
export async function syncFindings(scope: string, findings: Finding[], resolveMissing = true) {
  const seen = new Map<string, Finding>();
  for (const f of findings) seen.set(f.fingerprint, f);          // one row per fingerprint
  return await q(db.rpc("wd_findings_sync", { p_scope: scope, p_findings: [...seen.values()], p_resolve_missing: resolveMissing }));
}

// ---------- inventory with a change log ----------
const PK: Record<string, string[]> = {
  wd_edge_function: ["target_id", "slug"],
  wd_secret: ["target_id", "kind", "name"],
  wd_outbound: ["target_id", "via", "host", "detail"],
};
// rows: the full current set for `match` (e.g. {target_id, kind}). digest: the field that marks a change.
export async function syncInventory(table: string, match: Record<string, string>, rows: any[], o: { kind: string; label: (r: any) => string; digest?: string }) {
  const pk = PK[table];
  const key = (r: any) => pk.map((k) => String(r[k] ?? "")).join("|");
  const existing: any[] = await q(db.from(table).select("*").match(match));
  const ex = new Map(existing.map((r) => [key(r), r]));
  const now = nowIso(), changes: any[] = [], seen = new Set<string>();
  for (const r of rows) {
    const k = key(r), e = ex.get(k);
    seen.add(k);
    r.last_seen = now; r.active = true;
    if (!e || !e.active) changes.push({ target_id: r.target_id, kind: o.kind, item: o.label(r), action: "added", detail: {} });
    else if (o.digest && e[o.digest] != null && String(e[o.digest]) !== String(r[o.digest] ?? "")) {
      changes.push({ target_id: r.target_id, kind: o.kind, item: o.label(r), action: "changed", detail: { field: o.digest } });
      if (table === "wd_secret") r.changed_at = now;
    }
  }
  for (let i = 0; i < rows.length; i += 500) await q(db.from(table).upsert(rows.slice(i, i + 500), { onConflict: pk.join(",") }));
  const gone = existing.filter((e) => e.active && !seen.has(key(e)));
  for (const g of gone) {
    const m: Record<string, unknown> = {}; pk.forEach((k) => (m[k] = g[k]));
    await q(db.from(table).update({ active: false }).match(m));
    changes.push({ target_id: g.target_id, kind: o.kind, item: o.label(g), action: "removed", detail: {} });
  }
  if (changes.length) await q(db.from("wd_change").insert(changes));
  return { added: changes.filter((c) => c.action === "added").length, removed: gone.length, changed: changes.filter((c) => c.action === "changed").length };
}

export const insertMany = async (table: string, rows: any[], opts: { onConflict?: string; ignoreDuplicates?: boolean } = {}) => {
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    if (opts.onConflict) await q(db.from(table).upsert(chunk, { onConflict: opts.onConflict, ignoreDuplicates: opts.ignoreDuplicates ?? false }));
    else await q(db.from(table).insert(chunk));
  }
};

// secret-looking strings in code or config. Values are never stored: only the pattern name and a short masked sample.
export const SECRET_PATTERNS: { code: string; name: string; re: RegExp; sev: Sev }[] = [
  { code: "sb_secret", name: "Supabase secret API key", re: /sb_secret_[A-Za-z0-9_-]{20,}/g, sev: "critical" },
  { code: "sb_pat", name: "Supabase personal access token", re: /sbp_[a-f0-9]{40}/g, sev: "critical" },
  { code: "netlify_pat", name: "Netlify personal access token", re: /nfp_[A-Za-z0-9]{30,}/g, sev: "critical" },
  { code: "aws_key", name: "AWS access key", re: /AKIA[0-9A-Z]{16}/g, sev: "critical" },
  { code: "private_key", name: "Private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----(?:\\[rn]|\s)+[A-Za-z0-9+\/=]{64,}/g, sev: "critical" },   // the marker plus real key data, not code that builds a PEM
  { code: "stripe_live", name: "Stripe live secret key", re: /sk_live_[0-9a-zA-Z]{20,}/g, sev: "critical" },
  { code: "sendgrid", name: "SendGrid API key", re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, sev: "critical" },
  { code: "entra_secret", name: "Microsoft Entra client secret", re: /(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])/g, sev: "critical" },
  { code: "slack_token", name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, sev: "high" },
  { code: "twilio", name: "Twilio API key", re: /SK[0-9a-fA-F]{32}/g, sev: "medium" },
  { code: "google_key", name: "Google API key (often meant to be public: check its restrictions)", re: /AIza[0-9A-Za-z_-]{35}/g, sev: "low" },
];
export const mask = (s: string) => (s.length <= 12 ? s.slice(0, 4) + "…" : s.slice(0, 10) + "…" + s.slice(-3));

// JWTs whose payload says service_role (legacy Supabase secret key)
export function findServiceRoleJwts(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g)) {
    try {
      const p = JSON.parse(atob(m[1].replace(/-/g, "+").replace(/_/g, "/")));
      if (p.role === "service_role" || p.role === "supabase_admin") out.push(m[0]);
    } catch { /* not a JWT */ }
  }
  return out;
}
export function scanSecrets(text: string): { code: string; name: string; sev: Sev; sample: string }[] {
  const hits: { code: string; name: string; sev: Sev; sample: string }[] = [];
  for (const p of SECRET_PATTERNS) for (const m of text.matchAll(p.re)) hits.push({ code: p.code, name: p.name, sev: p.sev, sample: mask(m[0]) });
  for (const j of findServiceRoleJwts(text)) hits.push({ code: "service_role_jwt", name: "Supabase service_role key (legacy JWT)", sev: "critical", sample: mask(j) });
  return hits;
}
