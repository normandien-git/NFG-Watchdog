// NFG Watchdog collector: Netlify (hourly). Sites, deploys, functions, environment variables (names only),
// team members and audit log, plus a live look at each site: HTTPS, security headers and secrets in the served code.
import { db, q, sha, fp, nowIso, pool, getJson, upsertTargets, patchTargetMeta, syncFindings, syncInventory, insertMany,
  setConnector, scanSecrets, SECRET_PATTERNS, findServiceRoleJwts, type Finding } from "./lib.ts";

const API = "https://api.netlify.com/api/v1";
const TOKEN = Deno.env.get("NETLIFY_TOKEN") ?? "";
const nf = (path: string) => getJson(API + path, { headers: { Authorization: `Bearer ${TOKEN}` } });
const tid = (id: string) => `netlify:${id}`;
export const netlifyReady = () => !!TOKEN;

const PUBLIC_PREFIX = /^(VITE_|NEXT_PUBLIC_|PUBLIC_|REACT_APP_|GATSBY_|NUXT_PUBLIC_|EXPO_PUBLIC_)/;
const SECRETISH = /(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|TOKEN|API_KEY|_KEY$|CLIENT_SECRET|WEBHOOK)/i;

// fetch the live site and the scripts it loads (same origin, follows imports), scan for leaked secrets
async function crawl(base: string) {
  const origin = new URL(base).origin;
  const seen = new Set<string>(), queue = [base], hits: { file: string; code: string; name: string; sev: any; sample: string }[] = [];
  let headers: Headers | null = null, status = 0, files = 0, bytes = 0;
  const projects = new Set<string>();
  while (queue.length && files < 60) {
    const url = queue.shift()!;
    if (seen.has(url)) continue;
    seen.add(url);
    let r: Response;
    try { r = await fetch(url, { redirect: "follow", headers: { "user-agent": "NFG-Watchdog/1.0 (+security scan)" } }); } catch { continue; }
    if (url === base) { headers = r.headers; status = r.status; }
    if (!r.ok) { await r.body?.cancel(); continue; }
    const type = r.headers.get("content-type") || "";
    if (!/html|javascript|json|text\/plain|ecmascript/.test(type)) { await r.body?.cancel(); continue; }
    const text = (await r.text()).slice(0, 4_000_000);
    files++; bytes += text.length;
    for (const h of scanSecrets(text)) hits.push({ file: new URL(url).pathname, ...h });
    for (const m of text.matchAll(/https:\/\/([a-z]{20})\.supabase\.co/g)) projects.add(m[1]);
    // links to more code on the same site
    const refs = [
      ...[...text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]),
      ...[...text.matchAll(/<link[^>]+href=["']([^"']+\.(?:js|mjs|json))["']/gi)].map((m) => m[1]),
      ...[...text.matchAll(/(?:import|from)\s*\(?\s*["'`](\.{0,2}\/[^"'`]+\.m?js)["'`]/g)].map((m) => m[1]),
    ];
    for (const ref of refs) {
      try { const u = new URL(ref, url); if (u.origin === origin && !seen.has(u.href)) queue.push(u.href.split("#")[0]); } catch { /* bad url */ }
    }
  }
  return { headers, status, files, bytes, hits, projects: [...projects] };
}

function headerChecks(siteId: string, name: string, url: string, h: Headers | null): Finding[] {
  if (!h) return [];
  const T = tid(siteId), out: Finding[] = [];
  const f = (code: string, sev: any, title: string, detail: string, rem: string) =>
    out.push({ fingerprint: fp("nf", siteId, "hdr", code), source: "netlify", target_id: T, check_code: `header.${code}`, category: "exposure", severity: sev, title: `${name}: ${title}`, detail, remediation: rem });
  const csp = h.get("content-security-policy") || "";
  const how = "Add it under [[headers]] for \"/*\" in netlify.toml (or a _headers file).";
  if (!h.get("strict-transport-security")) f("hsts", "medium", "no HSTS header", `${url} does not tell browsers to always use https.`, `${how} Strict-Transport-Security: max-age=31536000; includeSubDomains`);
  if (!csp) f("csp", "medium", "no Content-Security-Policy", "Without a CSP, injected script runs with full access to the signed-in session.", `${how} Start with default-src 'self' plus the Supabase, CDN and font hosts the app uses.`);
  else if (/unsafe-inline/.test(csp) && /script-src[^;]*unsafe-inline|default-src[^;]*unsafe-inline/.test(csp)) f("csp_inline", "low", "CSP allows inline script", "unsafe-inline in script-src weakens the policy.", "Move inline scripts into files or use hashes/nonces.");
  if (!h.get("x-frame-options") && !/frame-ancestors/.test(csp)) f("frame", "low", "can be framed by other sites", "No X-Frame-Options or frame-ancestors: open to click-jacking.", `${how} X-Frame-Options: DENY`);
  if ((h.get("x-content-type-options") || "").toLowerCase() !== "nosniff") f("nosniff", "low", "no X-Content-Type-Options", "Browsers may guess file types.", `${how} X-Content-Type-Options: nosniff`);
  if (!h.get("referrer-policy")) f("referrer", "low", "no Referrer-Policy", "Full URLs (with any tokens in them) can leak to other sites.", `${how} Referrer-Policy: strict-origin-when-cross-origin`);
  if (!h.get("permissions-policy")) f("permissions", "info", "no Permissions-Policy", "Camera, microphone and location are not locked down.", `${how} Permissions-Policy: camera=(), microphone=(), geolocation=()`);
  return out;
}

async function siteOne(site: any, account: any, knownRefs: Set<string>) {
  const T = tid(site.id), F: Finding[] = [], stats: Record<string, unknown> = {};
  const name = site.name, url = site.ssl_url || site.url;
  const errors: string[] = [];
  const step = async (n: string, fn: () => Promise<void>) => { try { await fn(); } catch (e) { errors.push(`${n}: ${(e as Error).message.slice(0, 200)}`); } };

  if (site.custom_domain && site.force_ssl === false) F.push({ fingerprint: fp("nf", site.id, "force_ssl"), source: "netlify", target_id: T, check_code: "site.force_ssl", category: "exposure", severity: "high",
    title: `${name}: http is not redirected to https`, detail: `${site.custom_domain} can be opened over plain http.`, remediation: "Netlify › Domain management › HTTPS: turn on Force HTTPS." });

  // deploys (last 20) and functions in the live deploy
  await step("deploys", async () => {
    const deps: any[] = await nf(`/sites/${site.id}/deploys?per_page=20`) ?? [];
    await insertMany("wd_netlify_deploy", deps.map((d) => ({ id: d.id, target_id: T, state: d.state, context: d.context, branch: d.branch, commit_ref: d.commit_ref,
      committer: d.committer ?? null, title: (d.title ?? "").slice(0, 300), created_src: d.created_at, published_src: d.published_at ?? null, observed_at: nowIso() })), { onConflict: "id" });
    stats.last_deploy = deps[0]?.created_at;
    const live = site.published_deploy?.id ? await nf(`/deploys/${site.published_deploy.id}`) : null;
    const fns: any[] = live?.available_functions ?? [];
    stats.functions = await syncInventory("wd_edge_function", { target_id: T }, fns.map((f) => ({ target_id: T, slug: f.n, name: f.n, version: null, status: "ACTIVE",
      verify_jwt: null, created_src: null, updated_src: live?.published_at ?? null })), { kind: "edge_function", label: (r) => r.slug });
    const edge: any[] = live?.edge_functions_present ? (live?.edge_functions ?? []) : [];
    stats.edge_functions = edge.length;
  });

  // environment variables: names, scopes and a fingerprint (values are read in memory to check for leaks, never kept)
  await step("env", async () => {
    const env: any[] = await nf(`/accounts/${account.id}/env?site_id=${site.id}`) ?? [];
    const rows = await Promise.all(env.map(async (e) => {
      const vals = (e.values ?? []).map((v: any) => String(v.value ?? ""));
      const joined = vals.join("\u0000");
      if (PUBLIC_PREFIX.test(e.key)) {
        const leaks = scanSecrets(joined).filter((h) => h.sev === "critical" || h.sev === "high");
        if (leaks.length || findServiceRoleJwts(joined).length) F.push({ fingerprint: fp("nf", site.id, "env.public_secret", e.key), source: "netlify", target_id: T, check_code: "env.public_secret", category: "secrets", severity: "critical",
          title: `${name}: secret in browser variable ${e.key}`, detail: `${e.key} has a public prefix, so the build puts it into the JavaScript everyone downloads. It holds: ${leaks.map((l) => l.name).join(", ")}.`,
          remediation: "Rotate that secret now, remove it from the variable, and move the call that needs it into a server-side function." });
      } else if (SECRETISH.test(e.key) && !e.is_secret && (e.scopes ?? []).includes("builds"))
        F.push({ fingerprint: fp("nf", site.id, "env.not_secret", e.key), source: "netlify", target_id: T, check_code: "env.not_secret", category: "secrets", severity: "low",
          title: `${name}: ${e.key} is not marked as secret`, detail: "Its value shows in the Netlify UI and deploy logs to anyone on the team.", remediation: "Netlify › Environment variables: edit it and tick 'Contains secret values'." });
      return { target_id: T, kind: "netlify_env", name: e.key, digest: await sha(joined), is_secret: !!e.is_secret, scopes: e.scopes ?? null,
        meta: { contexts: (e.values ?? []).map((v: any) => v.context), updated_by: e.updated_by?.full_name ?? e.updated_by?.email ?? null, updated: e.updated_at ?? null } };
    }));
    stats.env = await syncInventory("wd_secret", { target_id: T, kind: "netlify_env" }, rows, { kind: "netlify_env", label: (r) => r.name, digest: "digest" });
  });

  // live look at the site
  await step("live scan", async () => {
    const c = await crawl(url);
    stats.scan = { files: c.files, bytes: c.bytes, status: c.status, projects: c.projects };
    if (c.status === 401 || c.status === 403) {
      // password / Netlify visitor protection: the scan only sees Netlify's sign-in wall, so its headers say nothing about the site
      F.push({ fingerprint: fp("nf", site.id, "protected"), source: "netlify", target_id: T, check_code: "site.protected", category: "exposure", severity: "info",
        title: `${name}: protected, so the live scan could not look inside`, detail: `${url} answered ${c.status}. Headers and leaked-secret checks are skipped while it is private.`,
        remediation: "Nothing to do. Once it is public (or on its custom domain), the next hourly check scans it." });
      return;
    }
    F.push(...headerChecks(site.id, name, url, c.headers));
    const byKind = new Map<string, typeof c.hits>();
    for (const h of c.hits) byKind.set(h.code, [...(byKind.get(h.code) ?? []), h]);
    for (const [code, hs] of byKind) {
      const h0 = hs[0];
      F.push({ fingerprint: fp("nf", site.id, "leak", code), source: "netlify", target_id: T, check_code: `leak.${code}`, category: "secrets", severity: h0.sev,
        title: `${name}: ${h0.name} in the published site`, detail: `Found ${hs.length}× in ${[...new Set(hs.map((x) => x.file))].slice(0, 5).join(", ")} (e.g. ${h0.sample}). Anyone who opens the site can read it.`,
        remediation: h0.sev === "low" ? "Check the key is restricted to your domains and APIs." : "Treat it as compromised: rotate it today, remove it from the code, redeploy.", meta: { files: [...new Set(hs.map((x) => x.file))], count: hs.length } });
    }
    for (const ref of c.projects) if (knownRefs.size && !knownRefs.has(ref)) F.push({ fingerprint: fp("nf", site.id, "unknown_project", ref), source: "netlify", target_id: T, check_code: "site.unknown_supabase", category: "data", severity: "medium",
      title: `${name} talks to Supabase project ${ref}, which Watchdog cannot see`, detail: "The project is not in the organisation the Watchdog access token covers. Data may be going somewhere unmanaged.",
      remediation: "Find out whose project it is; move it into the NFG organisation or remove it.", meta: { ref } });
  });

  await upsertTargets([{ id: T, kind: "netlify", ref: site.id, name, url, meta: {
    account: account.slug, custom_domain: site.custom_domain, aliases: site.domain_aliases ?? [], repo: site.build_settings?.repo_url ?? null,
    branch: site.build_settings?.repo_branch ?? null, published: site.published_deploy?.published_at ?? null, force_ssl: site.force_ssl, ...stats, errors,
  } }]);
  const sync = await syncFindings(`netlify:${site.id}`, F);
  return { site: name, findings: F.length, sync, errors };
}

async function accountOne(account: any) {
  const T = `netlify:account:${account.id}`, F: Finding[] = [];
  let members: any[] = [];
  try { members = await nf(`/${account.slug}/members`) ?? []; } catch { /* plan without members api */ }
  await upsertTargets([{ id: T, kind: "netlify", ref: account.id, name: `Netlify team ${account.name ?? account.slug}`, meta: { account: true, members: members.map((m) => ({ name: m.full_name, email: m.email, role: m.role })) } }]);
  const owners = members.filter((m) => /owner/i.test(m.role ?? ""));
  if (owners.length > 3) F.push({ fingerprint: fp("nf", account.id, "owners"), source: "netlify", target_id: T, check_code: "team.owners", category: "access", severity: "low",
    title: `${owners.length} Netlify team owners`, detail: owners.map((o) => o.email).join(", "), remediation: "Keep two owners; make the rest developers." });
  // audit log
  try {
    const ev: any[] = await nf(`/accounts/${account.id}/audit?per_page=100`) ?? [];
    await insertMany("wd_audit_external", ev.map((e) => {
      const p = e.payload ?? e;
      return { id: `netlify:${e.id}`, source: "netlify", at: p.timestamp ?? e.created_at ?? nowIso(), actor: p.actor_email ?? p.actor_name ?? null, action: p.action ?? p.log_type ?? null,
        target: p.traits?.site_name ?? p.traits?.name ?? null, ip: p.traits?.ip ?? null, meta: p.traits ?? {} };
    }), { onConflict: "id", ignoreDuplicates: true });
    const risky = ev.filter((e) => /token|member|role|env|deploy_key|sso|two_factor|access/i.test((e.payload ?? e).action ?? "") && Date.now() - Date.parse((e.payload ?? e).timestamp ?? 0) < 2 * 3600e3);
    for (const e of risky) {
      const p = e.payload ?? e;
      F.push({ fingerprint: fp("nf", account.id, "audit", e.id), source: "netlify", target_id: T, check_code: "activity.netlify_admin", category: "activity", severity: "medium",
        title: `Netlify: ${p.actor_name ?? p.actor_email ?? "someone"} ${String(p.action).replace(/_/g, " ")}`, detail: JSON.stringify(p.traits ?? {}).slice(0, 400),
        remediation: "Check this change was expected.", meta: p });
    }
  } catch { /* audit log needs a business plan */ }
  await syncFindings(`netlify:account:${account.id}`, F.filter((f) => f.category !== "activity"));
  await syncFindings("netlify:activity", F.filter((f) => f.category === "activity"), false);
  return { account: account.slug, members: members.length };
}

export async function runNetlify() {
  if (!TOKEN) { await setConnector("netlify", { ok: false, note: "NETLIFY_TOKEN secret not set" }); return { skipped: "NETLIFY_TOKEN not set" }; }
  const accounts: any[] = await nf("/accounts") ?? [];
  const sites: any[] = [];
  for (let page = 1; page < 10; page++) {
    const batch: any[] = await nf(`/sites?filter=all&per_page=100&page=${page}`) ?? [];
    sites.push(...batch);
    if (batch.length < 100) break;
  }
  const refs = new Set<string>((await q(db.from("wd_target").select("ref").eq("kind", "supabase"))).map((r: any) => r.ref));
  const acc = await Promise.all(accounts.map(accountOne));
  const byId = new Map(accounts.map((a) => [a.id, a]));
  const res = await pool(sites, 4, (s) => siteOne(s, byId.get(s.account_id) ?? accounts[0], refs));
  const ids = sites.map((s) => tid(s.id));
  if (ids.length) await q(db.from("wd_target").update({ active: false }).eq("kind", "netlify").not("id", "like", "netlify:account:%").not("id", "in", `(${ids.map((x) => `"${x}"`).join(",")})`));
  const failed = res.filter((r) => r.status === "rejected").length;
  await setConnector("netlify", { ok: !failed, sites: sites.length, accounts: accounts.length, failed });
  return { accounts: acc, sites: sites.length, results: res.map((r: any) => r.value ?? { error: r.reason?.message?.slice(0, 300) }) };
}
export { SECRET_PATTERNS };
