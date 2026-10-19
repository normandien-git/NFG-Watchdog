// NFG Guard › Integrations: projects and sites, edge functions, secrets and keys (names only), Entra / 365 apps,
// API calls in and out, Netlify deploys.
import { H } from "./watchdog.js";
const esc = H.esc;

// ---------------------------------------------------------------- Projects & sites
H.screen("targets", async (main, ctx) => {
  H.loading(main);
  const targets = await H.targets(true);
  const [open, posture] = await Promise.all([
    H.all(() => H.db.from("wd_finding").select("id, target_id, severity, category, title").eq("status", "open")),
    H.q(H.db.from("wd_posture_daily").select("day, target_id, score").gte("day", new Date(Date.now() - 3 * 86400e3).toISOString().slice(0, 10)).order("day")),
  ]);
  if (ctx.stale()) return;
  const score = new Map(); for (const p of posture) score.set(p.target_id, p.score);
  const rows = [...targets.values()].map((t) => {
    const f = open.filter((o) => o.target_id === t.id && o.category !== "performance");
    return { ...t, score: score.get(t.id) ?? null, open: f.length, hi: f.filter((o) => H.SEV_RANK[o.severity] >= 4).length,
      checked: t.meta?.posture?.at ?? t.meta?.at ?? t.last_seen };
  });
  main.innerHTML = H.title("Projects & sites", "Everything Guard found to watch: Supabase projects and organisation, Netlify sites and team, the Entra tenant. New ones are picked up automatically.") +
    H.table([
      { h: "Name", w: "2fr", f: (r) => `<b>${esc(r.name)}</b>${r.active ? "" : " " + H.tag("gone", "mute")}<br><span class="sub-t mono">${esc(r.url || r.ref)}</span>`, sv: (r) => r.name },
      { h: "Kind", w: "130px", f: (r) => H.kindTag(r.id), sv: (r) => r.id },
      { h: "Score", w: "80px", cls: "n", f: (r) => r.score == null ? "–" : `<b class="${r.score >= 85 ? "good" : r.score >= 60 ? "warnc" : "bad"}">${r.score}</b>`, sv: (r) => r.score ?? -1 },
      { h: "Open", w: "80px", cls: "n", f: (r) => H.u0(r.open), sv: (r) => r.open },
      { h: "High+", w: "80px", cls: "n", f: (r) => r.hi ? `<b class="bad">${r.hi}</b>` : "0", sv: (r) => r.hi },
      { h: "Details", w: "2fr", f: (r) => esc(detailLine(r)) },
      { h: "Checked", w: "110px", f: (r) => esc(H.ago(r.checked)), sv: (r) => r.checked },
    ], rows, { search: true, min: 980, rowAttrs: () => "" });
  H.rowClick(main, (r) => openTarget(r, open));
  if (ctx.ctx?.open) { const r = rows.find((x) => x.id === ctx.ctx.open); if (r) openTarget(r, open); }
});
function detailLine(t) {
  const m = t.meta || {};
  if (t.kind === "supabase" && m.org) return `${(m.members || []).length} members`;
  if (t.kind === "supabase") return [m.region, m.pg ? `Postgres ${String(m.pg).split(".")[0]}` : "", m.posture?.users ? `${m.posture.users.total} users` : "", m.posture?.functions_count != null ? `${m.posture.functions_count} functions` : "", m.posture?.db_bytes ? H.bytes(m.posture.db_bytes) : ""].filter(Boolean).join(" · ");
  if (t.kind === "netlify" && m.account) return `${(m.members || []).length} members`;
  if (t.kind === "netlify") return [m.custom_domain, m.repo ? m.repo.replace(/^https:\/\/github.com\//, "") : "", m.scan?.projects?.length ? `uses ${m.scan.projects.length} Supabase project(s)` : ""].filter(Boolean).join(" · ");
  if (t.kind === "entra") return `${m.apps ?? 0} app registrations`;
  return "";
}
async function openTarget(t, open) {
  const f = open.filter((o) => o.target_id === t.id).sort((a, b) => H.SEV_RANK[b.severity] - H.SEV_RANK[a.severity]);
  const m = t.meta || {};
  const facts = [];
  if (t.kind === "supabase" && !m.org) {
    facts.push(["Region", m.region], ["Postgres", m.pg], ["Accounts", m.posture?.users ? `${m.posture.users.total} (${m.posture.mfa_users ?? 0} with MFA, ${m.posture.users.new_24h} new in 24 h)` : ""],
      ["Database size", m.posture?.db_bytes ? H.bytes(m.posture.db_bytes) : ""], ["Backups", m.posture ? (m.posture.pitr ? "Point-in-time recovery" : m.posture.last_backup ? `Last ${H.dateTime(m.posture.last_backup)}` : "None found") : ""],
      ["Traffic, last pass", m.logs ? `${H.u0(m.logs.requests)} calls, ${H.u0(m.logs.fn_calls)} function calls, ${H.u0(m.logs.auth_events)} auth events` : ""],
      ["Logs read up to", m.logs_until ? H.dateTime(m.logs_until) : ""], ["Check errors", (m.posture?.errors || []).join("; ")]);
  } else if (t.kind === "netlify" && !m.account) {
    facts.push(["Domain", [m.custom_domain, ...(m.aliases || [])].filter(Boolean).join(", ")], ["Repository", m.repo ? `${m.repo} (${m.branch || ""})` : ""], ["Published", H.dateTime(m.published)],
      ["Force https", m.force_ssl ? "Yes" : "No"], ["Supabase projects it calls", (m.scan?.projects || []).map((r) => H.tname(`supabase:${r}`)).join(", ")],
      ["Scanned", m.scan ? `${m.scan.files} files, ${H.bytes(m.scan.bytes)}` : ""], ["Check errors", (m.errors || []).join("; ")]);
  } else facts.push(["Members", (m.members || []).map((x) => `${x.name || x.email} (${x.role}${x.mfa === false ? ", no MFA" : ""})`).join(", ")]);
  await H.sheet({ title: t.name, wide: true, ok: null,
    html: `<div class="row">${H.kindTag(t.id)} ${t.url ? `<a href="${esc(t.url)}" target="_blank" rel="noopener" class="mono">${esc(t.url)}</a>` : ""}</div>` +
      `<dl class="kv">${facts.filter((x) => x[1]).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` +
      `<h3>Open findings (${f.length})</h3>` + (f.length ? `<div class="wd-flist">${f.map((x) => `<button type="button" class="wd-fi" data-f="${x.id}">${H.sev(x.severity)} <span>${esc(x.title)}</span></button>`).join("")}</div>` : `<p class="sub-t">None.</p>`),
    onOpen: (form, close) => form.querySelectorAll("[data-f]").forEach((b) => { b.onclick = () => { close(null); H.go("findings", { ctx: { open: Number(b.dataset.f), target: t.id } }); }; }) });
}

// ---------------------------------------------------------------- Edge functions
H.screen("functions", async (main, ctx) => {
  H.loading(main);
  await H.targets();
  const [fns, use] = await Promise.all([
    H.q(H.db.from("wd_edge_function").select("*").eq("active", true)),
    H.q(H.db.rpc("wd_function_usage", { p_hours: 168 })),
  ]);
  if (ctx.stale()) return;
  const u = new Map(use.map((x) => [`${x.target_id}|${x.slug}`, x]));
  const rows = fns.map((f) => ({ ...f, use: u.get(`${f.target_id}|${f.slug}`) || {} }));
  main.innerHTML = H.title("Edge functions", "Every Supabase edge function and Netlify function, whether it checks for a sign-in token, and how much it was called in the last 7 days.") +
    H.table([
      { h: "Function", w: "1.6fr", f: (r) => `<b class="mono">${esc(r.slug)}</b>`, sv: (r) => r.slug },
      { h: "Where", w: "1.5fr", f: (r) => `${esc(H.tname(r.target_id))}<br>${H.kindTag(r.target_id)}`, sv: (r) => H.tname(r.target_id) },
      { h: "Version", w: "80px", cls: "n", f: (r) => r.version ?? "", sv: (r) => r.version ?? 0 },
      { h: "Sign-in check", w: "120px", f: (r) => r.verify_jwt === false ? H.tag("off", "warn") : r.verify_jwt ? H.tag("on", "ok") : `<span class="sub-t">n/a</span>`, sv: (r) => String(r.verify_jwt) },
      { h: "Calls · 7 d", w: "100px", cls: "n", f: (r) => H.u0(r.use.calls || 0), sv: (r) => Number(r.use.calls || 0), tot: (rows) => rows.reduce((a, r) => a + Number(r.use.calls || 0), 0) },
      { h: "Failed", w: "80px", cls: "n", f: (r) => r.use.errors ? `<b>${H.u0(r.use.errors)}</b>` : "", sv: (r) => Number(r.use.errors || 0) },
      { h: "Avg ms", w: "80px", cls: "n", f: (r) => H.u0(r.use.avg_ms), sv: (r) => Number(r.use.avg_ms || 0) },
      { h: "Callers", w: "80px", cls: "n", f: (r) => H.u0(r.use.ips || 0), sv: (r) => Number(r.use.ips || 0) },
      { h: "Last call", w: "110px", f: (r) => esc(H.ago(r.use.last)), sv: (r) => r.use.last || "" },
      { h: "Deployed", w: "110px", f: (r) => esc(H.shortDate(r.updated_src)), sv: (r) => r.updated_src || "" },
    ], rows, { search: true, min: 1100, sort: { h: "Calls · 7 d", dir: -1 }, empty: "No functions found yet." }) +
    `<p class="sub-t">Netlify function call counts are not available from Netlify's API; Supabase counts come from each project's function logs.</p>`;
});

// ---------------------------------------------------------------- Secrets & keys
H.screen("secrets", async (main, ctx) => {
  H.loading(main);
  await H.targets();
  const st = { kind: "" };
  const KIND = { edge_secret: "Edge function secrets", api_key: "Supabase API keys", netlify_env: "Netlify variables", entra_password: "Entra client secrets", entra_certificate: "Entra certificates" };
  const all = await H.all(() => H.db.from("wd_secret").select("target_id, kind, name, is_secret, scopes, expires_at, meta, first_seen, last_seen, changed_at").eq("active", true).order("name"));
  if (ctx.stale()) return;
  const draw = () => {
    const rows = all.filter((r) => !st.kind || r.kind === st.kind);
    main.innerHTML = H.title("Secrets & keys", "Where every secret lives and when it last changed. Guard keeps names and a fingerprint only, never the values, so it can tell you when one changes.") +
      `<div class="chips">${[["", "All"], ...Object.entries(KIND)].map(([k, l]) => `<button class="chip${st.kind === k ? " on" : ""}" data-k="${k}">${esc(l)} (${all.filter((r) => !k || r.kind === k).length})</button>`).join("")}</div>` +
      H.table([
        { h: "Name", w: "2fr", f: (r) => r.kind.startsWith("entra") ? `<b>${esc(r.meta?.app ?? "")}</b><br><span class="sub-t">${esc(r.meta?.label || r.meta?.hint || "")}</span>` : `<b class="mono">${esc(r.name)}</b>${r.meta?.prefix ? `<br><span class="sub-t mono">${esc(r.meta.prefix)}…</span>` : ""}`, sv: (r) => r.meta?.app ?? r.name },
        { h: "Kind", w: "1.2fr", f: (r) => esc(KIND[r.kind] || r.kind) + (r.kind === "api_key" && r.meta?.type ? ` · ${esc(r.meta.type)}` : "") },
        { h: "Where", w: "1.5fr", f: (r) => esc(H.tname(r.target_id)) },
        { h: "Secret", w: "80px", f: (r) => r.is_secret ? H.tag("yes", "warn") : H.tag("no", "mute"), sv: (r) => String(r.is_secret) },
        { h: "Expires", w: "120px", f: (r) => { const d = H.daysTo(r.expires_at); return r.expires_at ? `${esc(H.shortDate(r.expires_at))}<br>${d < 0 ? H.tag("expired", "mute") : d <= 30 ? H.tag(`${d} days`, d <= 7 ? "err" : "warn") : `<span class="sub-t">${d} days</span>`}` : ""; }, sv: (r) => r.expires_at || "9999" },
        { h: "Last changed", w: "120px", f: (r) => esc(r.changed_at ? H.shortDate(r.changed_at) : `not since ${H.shortDate(r.first_seen)}`), sv: (r) => r.changed_at || r.first_seen },
        { h: "Scopes", w: "1fr", f: (r) => esc((r.scopes || []).join(", ")) },
      ], rows, { search: true, min: 1000, empty: "Nothing yet." });
    main.querySelectorAll("[data-k]").forEach((b) => { b.onclick = () => { st.kind = b.dataset.k; draw(); }; });
  };
  draw();
});

// ---------------------------------------------------------------- Entra / 365 apps
const HIGH = ["Directory.ReadWrite.All", "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "full_access_as_app", "Domain.ReadWrite.All",
  "User.ReadWrite.All", "Group.ReadWrite.All", "Mail.ReadWrite", "Mail.Send", "Mail.Read", "Files.ReadWrite.All", "Sites.FullControl.All", "Sites.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "UserAuthenticationMethod.ReadWrite.All"];
H.screen("entra", async (main, ctx) => {
  H.loading(main);
  const [apps, creds] = await Promise.all([
    H.q(H.db.from("wd_entra_app").select("*").eq("active", true).order("display_name")),
    H.q(H.db.from("wd_secret").select("name, kind, expires_at, meta").in("kind", ["entra_password", "entra_certificate"]).eq("active", true)),
  ]);
  if (ctx.stale()) return;
  const next = new Map();
  for (const c of creds) { const a = c.meta?.app_id; if (c.expires_at && new Date(c.expires_at) > new Date() && (!next.has(a) || c.expires_at < next.get(a))) next.set(a, c.expires_at); }
  main.innerHTML = H.title("Entra / 365 apps", "Our app registrations: what each may do in Microsoft 365, when its secrets expire, when it was last used and how often people or the app signed in through it.") +
    H.table([
      { h: "App", w: "1.8fr", f: (r) => `<b>${esc(r.display_name)}</b>${r.meta?.deactivated ? " " + H.tag("deactivated", "mute") : r.meta?.enabled === false ? " " + H.tag("disabled", "mute") : ""}<br><span class="sub-t mono">${esc(r.app_id)}</span>`, sv: (r) => r.display_name },
      { h: "Can do (no user)", w: "2fr", f: (r) => (r.permissions || []).filter((p) => p.type === "Application" && p.granted).map((p) => H.tag(p.name, HIGH.includes(p.name) ? "err" : "mute")).join(" ") || `<span class="sub-t">nothing</span>`,
        sv: (r) => (r.permissions || []).filter((p) => p.type === "Application" && p.granted && HIGH.includes(p.name)).length },
      { h: "On behalf of users", w: "1.4fr", f: (r) => `<span class="sub-t">${esc((r.permissions || []).filter((p) => p.type === "Delegated").map((p) => p.name).join(", "))}</span>` },
      { h: "Next expiry", w: "110px", f: (r) => { const e = next.get(r.app_id); const d = H.daysTo(e); return e ? `${esc(H.shortDate(e))}${d <= 30 ? "<br>" + H.tag(`${d} days`, d <= 7 ? "err" : "warn") : ""}` : `<span class="sub-t">${r.meta?.secrets || r.meta?.certs ? "expired" : "none"}</span>`; }, sv: (r) => next.get(r.app_id) || "9999" },
      { h: "Last used", w: "110px", f: (r) => esc(r.last_sign_in ? H.ago(r.last_sign_in) : "never"), sv: (r) => r.last_sign_in || "" },
      { h: "Sign-ins · 30 d", w: "100px", cls: "n", f: (r) => H.u0(r.sign_ins_30d || 0), sv: (r) => r.sign_ins_30d || 0 },
      { h: "Owners", w: "1.2fr", f: (r) => esc((r.owners || []).join(", ")) || H.tag("none", "warn") },
    ], apps.sort((a, b) => (a.meta?.deactivated ? 1 : 0) - (b.meta?.deactivated ? 1 : 0)), { search: true, min: 1150, rowAttrs: () => "", empty: "Nothing yet. Set up the Entra connection (Admin › Collector runs)." });
  H.rowClick(main, async (a) => {
    const sis = await H.q(H.db.from("wd_entra_signin").select("at, principal, is_sp, ip, city, country, ok, failure, resource").eq("app_id", a.app_id).order("at", { ascending: false }).limit(200));
    const byWho = new Map(); for (const s of sis) { const k = s.principal || "?"; const x = byWho.get(k) ?? { n: 0, ips: new Set(), last: s.at }; x.n++; if (s.ip) x.ips.add(`${s.ip} ${s.country || ""}`); byWho.set(k, x); }
    await H.sheet({ title: a.display_name, wide: true, ok: null,
      html: `<dl class="kv"><dt>App ID</dt><dd class="mono">${esc(a.app_id)}</dd><dt>Created</dt><dd>${esc(H.shortDate(a.created_src))}</dd><dt>Who can sign in</dt><dd>${esc(a.audience)}</dd>` +
        `<dt>Redirect addresses</dt><dd>${(a.redirect_uris || []).map(esc).join("<br>") || "none"}</dd><dt>Owners</dt><dd>${esc((a.owners || []).join(", ") || "none")}</dd></dl>` +
        `<h3>Permissions</h3>` + H.table([
          { h: "Permission", w: "1.6fr", f: (p) => `<span class="mono">${esc(p.name)}</span>${HIGH.includes(p.name) && p.type === "Application" ? " " + H.tag("broad", "err") : ""}` },
          { h: "Type", w: "1fr", f: (p) => esc(p.type === "Application" ? "App (no user)" : "On behalf of a user") },
          { h: "API", w: "1.2fr", f: (p) => esc(p.resource) },
          { h: "Granted", w: "90px", f: (p) => p.granted ? H.tag("yes", "ok") : H.tag("requested", "mute") },
        ], a.permissions || [], { min: 560 }) +
        `<h3>Who signs in through it (last 200)</h3>` + H.table([
          { h: "Who", w: "1.6fr", f: (r) => esc(r[0]) },
          { h: "Times", w: "80px", cls: "n", f: (r) => H.u0(r[1].n), sv: (r) => r[1].n },
          { h: "From", w: "2fr", f: (r) => `<span class="sub-t">${esc([...r[1].ips].slice(0, 4).join(", "))}</span>` },
          { h: "Last", w: "110px", f: (r) => esc(H.ago(r[1].last)) },
        ], [...byWho], { min: 560, empty: "No sign-ins recorded (needs Entra ID P1 for sign-in logs)." }) });
  });
});

// ---------------------------------------------------------------- API calls in and out
H.screen("api", async (main, ctx) => {
  await H.targets();
  const st = { hours: 24 };
  const draw = async () => {
    H.loading(main);
    const [s, out] = await Promise.all([H.q(H.db.rpc("wd_traffic_summary", { p_hours: st.hours, p_target: null })), H.q(H.db.from("wd_outbound").select("*").eq("active", true).order("host"))]);
    if (ctx.stale()) return;
    main.innerHTML = H.title("API calls in & out", "In: what each project is asked for (tables, functions, auth, storage), how often, how much data and how many fail. Out: calls the databases make to other services on a schedule.") +
      `<div class="filters">${H.period(st.hours)}</div>` +
      `<h2>Calls in</h2>` + H.table([
        { h: "Project", w: "1.3fr", f: (r) => esc(H.tname(r.target_id)) },
        { h: "Kind", w: "100px", k: "channel" },
        { h: "Call", w: "2.2fr", f: (r) => `<span class="mono">${esc(r.method)} ${esc(r.path)}</span>`, sv: (r) => r.path },
        { h: "Calls", w: "90px", cls: "n", f: (r) => H.u0(r.n), sv: (r) => Number(r.n), tot: true },
        { h: "Data out", w: "100px", cls: "n", f: (r) => H.bytes(r.b), sv: (r) => Number(r.b) },
        { h: "Avg ms", w: "80px", cls: "n", f: (r) => H.u0(r.ms), sv: (r) => Number(r.ms || 0) },
        { h: "Failed", w: "80px", cls: "n", f: (r) => r.bad ? `<b>${H.u0(r.bad)}</b>` : "", sv: (r) => Number(r.bad || 0) },
      ], s.by_path || [], { search: true, min: 960, limit: 300, empty: "No calls in this period." }) +
      `<h2>Calls out (scheduled)</h2>` + H.table([
        { h: "Project", w: "1.4fr", f: (r) => esc(H.tname(r.target_id)) },
        { h: "Via", w: "100px", k: "via" },
        { h: "To", w: "1.6fr", f: (r) => `<span class="mono">${esc(r.host)}</span>` },
        { h: "Job", w: "2fr", f: (r) => esc(r.detail) },
        { h: "Since", w: "110px", f: (r) => esc(H.shortDate(r.first_seen)), sv: (r) => r.first_seen },
      ], out, { search: true, min: 820, empty: "No scheduled outbound calls found." }) +
      `<p class="sub-t">Calls made from inside edge functions are not visible in Supabase's logs yet; the function list shows which functions exist and who calls them.</p>`;
    main.querySelectorAll("[data-period]").forEach((b) => { b.onclick = () => { st.hours = Number(b.dataset.period); draw(); }; });
  };
  await draw();
});

// ---------------------------------------------------------------- Netlify deploys
H.screen("deploys", async (main, ctx) => {
  H.loading(main);
  await H.targets();
  const rows = await H.q(H.db.from("wd_netlify_deploy").select("*").order("created_src", { ascending: false }).limit(500));
  if (ctx.stale()) return;
  main.innerHTML = H.title("Netlify deploys", "What went live on each site, from which branch and commit, and who pushed it. Last 90 days.") +
    H.table([
      { h: "When", w: "130px", f: (r) => esc(H.dateTime(r.created_src)), sv: (r) => r.created_src },
      { h: "Site", w: "1.4fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "State", w: "100px", f: (r) => H.tag(r.state, r.state === "ready" ? "ok" : r.state === "error" ? "err" : "mute") },
      { h: "Context", w: "120px", k: "context" },
      { h: "Branch / commit", w: "1.2fr", f: (r) => `${esc(r.branch || "")} <span class="mono sub-t">${esc(String(r.commit_ref || "").slice(0, 7))}</span>` },
      { h: "Message", w: "2.4fr", f: (r) => esc(r.title || "") },
      { h: "By", w: "1fr", f: (r) => esc(r.committer || "") },
    ], rows, { search: true, min: 1000, empty: "No deploys yet." });
});
