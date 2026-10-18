// NFG Watchdog: the menu, Overview and My account.
import { H } from "./watchdog.js";
const esc = H.esc;

H.MENU = [
  { k: "home", n: "Overview", secs: [{ h: "", items: [{ n: "Overview", s: "home" }] }] },
  { k: "sec", n: "Security", secs: [
    { h: "", items: [
      { n: "Findings", s: "findings" },
      { n: "Suspicious activity", s: "activity" },
      { n: "Change log", s: "changes" },
    ]},
  ]},
  { k: "acc", n: "Access", secs: [
    { h: "", items: [
      { n: "Who is connecting", s: "connecting" },
      { n: "Sign-ins", s: "signins" },
      { n: "Database logins", s: "dbconn" },
      { n: "People with admin access", s: "people" },
    ]},
  ]},
  { k: "int", n: "Integrations", secs: [
    { h: "Inventory", items: [
      { n: "Projects & sites", s: "targets" },
      { n: "Edge functions", s: "functions" },
      { n: "Secrets & keys", s: "secrets" },
      { n: "Entra / 365 apps", s: "entra" },
    ]},
    { h: "Traffic", items: [
      { n: "API calls in & out", s: "api" },
      { n: "Netlify deploys", s: "deploys" },
    ]},
  ]},
  { k: "perf", n: "Performance", secs: [
    { h: "", items: [
      { n: "Slow queries", s: "queries" },
      { n: "Performance findings", s: "perf_findings" },
      { n: "Uptime & errors", s: "uptime", d: "Error rates, response times and failed function calls per project over time, with alerts when they jump." },
    ]},
  ]},
  { k: "alr", n: "Alerts", secs: [
    { h: "", items: [
      { n: "Alerts", s: "alerts" },
      { n: "Alert rules", s: "rules" },
    ]},
  ]},
  { k: "adm", n: "Admin", sep: true, secs: [
    { h: "", items: [
      { n: "Collector runs", s: "runs" },
      { n: "Settings", s: "settings" },
      { n: "Users", s: "users" },
      { n: "Watchdog access log", s: "accesslog" },
    ]},
  ]},
];
Object.assign(H.SCREEN_PERM, { users: "admin", accesslog: "admin", settings: "admin" });

H.ICONS = {
  home: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  sec: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/><path d="M11 8v3M11 13.5v.5"/>',
  acc: '<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M16 11l2 2 4-4"/>',
  int: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8 7.5l3 8M16 7.5l-3 8M8.5 6h7"/>',
  perf: '<path d="M3 13a9 9 0 0 1 18 0"/><path d="M12 13l4-5"/><path d="M3 17h18"/>',
  alr: '<path d="M6 16V11a6 6 0 0 1 12 0v5l2 2H4z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
  adm: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/>',
};

// ---------------------------------------------------------------- Overview
H.screen("home", async (main, ctx) => {
  H.loading(main);
  const since24 = new Date(Date.now() - 86400e3).toISOString();
  const [targets, open, posture, sum, failRes, changes, conn, runs] = await Promise.all([
    H.targets(),
    H.all(() => H.db.from("wd_finding").select("id, severity, category, source, target_id, title, first_seen, last_seen, status").eq("status", "open").order("id")),
    H.q(H.db.from("wd_posture_daily").select("day, target_id, score, critical, high").gte("day", new Date(Date.now() - 30 * 86400e3).toISOString().slice(0, 10)).order("day")),
    H.q(H.db.rpc("wd_traffic_summary", { p_hours: 24 })),
    H.db.from("wd_auth_event").select("id", { count: "exact", head: true }).eq("ok", false).gte("at", since24),
    H.q(H.db.from("wd_change").select("at, target_id, kind, item, action, by_user").order("at", { ascending: false }).limit(12)),
    H.q(H.db.from("wd_setting").select("value").eq("key", "connectors").single()),
    H.q(H.db.from("wd_run").select("job, ok, started_at, finished_at").order("started_at", { ascending: false }).limit(40)),
  ]);
  if (ctx.stale()) return;
  const failCount = failRes.count ?? 0;
  const sec = open.filter((f) => f.category !== "performance");
  const n = (s) => sec.filter((f) => f.severity === s).length;
  const act24 = sec.filter((f) => f.category === "activity" && f.last_seen >= since24).length;
  // score: latest day per target, averaged over active targets
  const latest = new Map();
  for (const p of posture) latest.set(p.target_id, p);
  const scores = [...latest.values()].filter((p) => targets.get(p.target_id)?.active !== false);
  const score = scores.length ? Math.round(scores.reduce((a, p) => a + p.score, 0) / scores.length) : null;
  const byDay = new Map();
  for (const p of posture) { const d = byDay.get(p.day) ?? []; d.push(p.score); byDay.set(p.day, d); }
  const trend = [...byDay].map(([day, s]) => ({ day, v: Math.round(s.reduce((a, b) => a + b, 0) / s.length) }));
  const t = sum.totals || {};
  const c = conn.value || {};
  const lastRun = (job) => runs.find((r) => r.job === job);
  const conns = [["supabase", "Supabase"], ["netlify", "Netlify"], ["entra", "Entra / 365"], ["alerts", "Alerts"]];

  const scoreCls = score == null ? "" : score >= 85 ? "good" : score >= 60 ? "warn" : "bad";
  main.innerHTML = H.title("Security overview", "Everything Watchdog watches: Supabase projects, Netlify sites and the Entra / 365 apps they use. Checks run every hour; traffic and sign-ins every 15 minutes.",
      H.btn("Run all checks now", "admin", { cls: "pri", attrs: "data-runall" })) +
    (conns.some(([k]) => !c[k]?.ok) ? `<div class="banner">Some connections are not working yet: ${conns.filter(([k]) => !c[k]?.ok).map(([k, l]) => `<b>${esc(l)}</b>${c[k]?.note ? ` (${esc(c[k].note)})` : ""}`).join(", ")}. <button class="link" data-go="runs">See Collector runs</button></div>` : "") +
    `<div class="kpis">` +
      `<div class="card wd-score ${scoreCls}"><span class="kpi-l">Security score</span><span class="kpi">${score == null ? "–" : score}<small>/100</small></span><span class="sub-t">${scores.length ? `Average of ${scores.length} projects and sites` : "Waiting for the first checks"}</span></div>` +
      `<button class="card kc" data-go="findings" data-sev="critical"><span class="kpi-l">Critical</span><span class="kpi ${n("critical") ? "bad" : ""}">${n("critical")}</span><span class="sub-t">open findings</span></button>` +
      `<button class="card kc" data-go="findings" data-sev="high"><span class="kpi-l">High</span><span class="kpi ${n("high") ? "warnc" : ""}">${n("high")}</span><span class="sub-t">open findings</span></button>` +
      `<button class="card kc" data-go="activity"><span class="kpi-l">Suspicious activity</span><span class="kpi">${act24}</span><span class="sub-t">flagged in the last 24 hours</span></button>` +
      `<button class="card kc" data-go="connecting"><span class="kpi-l">API calls · 24 h</span><span class="kpi">${H.u0(t.requests)}</span><span class="sub-t">${H.u0(t.ips)} addresses, ${H.u0(t.countries)} countries</span></button>` +
      `<button class="card kc" data-go="connecting"><span class="kpi-l">Data out · 24 h</span><span class="kpi">${H.bytes(t.bytes)}</span><span class="sub-t">${H.u0(t.denied)} refused requests</span></button>` +
      `<button class="card kc" data-go="signins"><span class="kpi-l">Failed sign-ins · 24 h</span><span class="kpi ${failCount > 20 ? "warnc" : ""}">${H.u0(failCount)}</span><span class="sub-t">across all projects</span></button>` +
      `<button class="card kc" data-go="connecting"><span class="kpi-l">Secret-key calls · 24 h</span><span class="kpi">${H.u0(t.secret_calls)}</span><span class="sub-t">not from Supabase functions</span></button>` +
    `</div>` +
    `<div class="wd-2">` +
      `<section class="card"><div class="row"><h2>Needs attention</h2><button class="link" style="margin-left:auto" data-go="findings">All findings</button></div>` +
        H.table([
          { h: "Severity", w: "92px", f: (r) => H.sev(r.severity), sv: (r) => -H.SEV_RANK[r.severity] },
          { h: "What", w: "3fr", f: (r) => `<b>${esc(r.title)}</b>` },
          { h: "Where", w: "1.2fr", f: (r) => esc(H.tname(r.target_id)) },
          { h: "Since", w: "110px", f: (r) => esc(H.ago(r.first_seen)), sv: (r) => r.first_seen },
        ], sec.filter((f) => H.SEV_RANK[f.severity] >= 4).sort((a, b) => H.SEV_RANK[b.severity] - H.SEV_RANK[a.severity] || (a.first_seen < b.first_seen ? 1 : -1)),
          { empty: "Nothing critical or high is open.", limit: 12, min: 520, rowAttrs: (r) => `data-fid="${r.id}"` }) +
      `</section>` +
      `<section class="card"><h2>Open findings by severity</h2>` +
        H.hbars(["critical", "high", "medium", "low", "info"].map((s) => ({ labelHtml: H.sev(s), v: n(s), cls: `b-${s}` }))) +
        `<h2 style="margin-top:8px">API calls per hour · 24 h</h2>` +
        H.columns((sum.series || []).map((x) => ({ y: x.n, label: `${H.timeOnly(x.h)}: ${H.u0(x.n)} calls, ${H.bytes(x.b)} out${x.d ? `, ${H.u0(x.d)} refused` : ""}` })), { aria: "API calls per hour", foot: sum.series?.length ? [H.timeOnly(sum.series[0].h), H.timeOnly(sum.series.at(-1).h)] : null }) +
        (trend.length > 1 ? `<h2 style="margin-top:8px">Security score · 30 days</h2>` + H.columns(trend.map((x) => ({ y: x.v, label: `${H.shortDate(x.day)}: ${x.v}/100` })), { aria: "Score per day", foot: [H.shortDate(trend[0].day), H.shortDate(trend.at(-1).day)] }) : "") +
      `</section>` +
    `</div>` +
    `<section><div class="row"><h2>Projects and sites</h2><button class="link" style="margin-left:auto" data-go="targets">Inventory</button></div><div class="wd-tiles">` +
      [...targets.values()].filter((x) => x.active && !x.meta?.org && !x.meta?.account).map((x) => {
        const p = latest.get(x.id), f = sec.filter((o) => o.target_id === x.id);
        const crit = f.filter((o) => H.SEV_RANK[o.severity] >= 4).length;
        return `<button class="wd-tile ${p ? (p.score >= 85 ? "good" : p.score >= 60 ? "warn" : "bad") : ""}" data-target="${esc(x.id)}"><span class="wd-tk">${H.kindTag(x.id)}</span><b>${esc(x.name)}</b>` +
          `<span class="wd-ts">${p ? `${p.score}<small>/100</small>` : "–"}</span><span class="sub-t">${f.length} open${crit ? `, <b>${crit} high or critical</b>` : ""}</span></button>`;
      }).join("") + (targets.size ? "" : `<p class="sub-t">Nothing yet. Add the access tokens (Admin › Collector runs explains how), then run the checks.</p>`) +
    `</div></section>` +
    `<section class="card"><div class="row"><h2>Latest changes</h2><button class="link" style="margin-left:auto" data-go="changes">Change log</button></div>` +
      H.table([
        { h: "When", w: "130px", f: (r) => esc(H.dateTime(r.at)), sv: (r) => r.at },
        { h: "What", w: "2.5fr", f: (r) => `${H.tag(r.action, r.action === "opened" || r.action === "reopened" ? "err" : r.action === "resolved" ? "ok" : "mute")} ${esc(r.item)}` },
        { h: "Where", w: "1.2fr", f: (r) => esc(H.tname(r.target_id)) },
      ], changes, { empty: "No changes recorded yet.", min: 520 }) +
    `</section>` +
    `<p class="sub-t">Last runs: ${["logs", "supabase", "netlify", "entra"].map((j) => { const r = lastRun(j); return `${j} ${r ? `${H.ago(r.started_at)}${r.ok === false ? " (failed)" : ""}` : "never"}`; }).join(" · ")}</p>`;

  main.querySelectorAll("[data-go]").forEach((b) => { b.onclick = () => H.go(b.dataset.go, { ctx: b.dataset.sev ? { sev: b.dataset.sev } : undefined }); });
  main.querySelectorAll("[data-target]").forEach((b) => { b.onclick = () => H.go("targets", { ctx: { open: b.dataset.target } }); });
  main.querySelectorAll("[data-fid]").forEach((r) => { r.onclick = () => H.go("findings", { ctx: { open: Number(r.dataset.fid) } }); });
  const ra = main.querySelector("[data-runall]");
  if (ra && !ra.disabled) ra.onclick = () => H.runJob("all").catch((e) => H.toast(e.message, true));
});

// ---------------------------------------------------------------- My account
H.screen("me", async (main) => {
  const { data: { user } } = await H.db.auth.getUser();
  const { data: fl } = await H.db.auth.mfa.listFactors();
  main.innerHTML = H.title("My account", "Your Watchdog sign-in. It is separate from your NFG app login on purpose: if the NFG login is ever compromised, Watchdog still stands.") +
    `<div class="card" style="max-width:640px"><dl class="kv"><dt>Name</dt><dd>${esc(H.me.name || "")}</dd><dt>Email</dt><dd>${esc(user?.email)}</dd>` +
    `<dt>Role</dt><dd>${esc(H.ROLE_NAME[H.me.role])}</dd><dt>Last sign-in</dt><dd>${esc(H.dateTime(user?.last_sign_in_at))}</dd>` +
    `<dt>Authenticator apps</dt><dd>${(fl?.totp ?? []).filter((f) => f.status === "verified").map((f) => esc(f.friendly_name || "App")).join(", ") || "None"}</dd></dl>` +
    `<div class="row"><button class="btn" data-pw>Change password</button><button class="btn" data-out>Sign out of all sessions</button></div></div>`;
  main.querySelector("[data-pw]").onclick = async () => {
    const ok = await H.sheet({ title: "Change password", ok: "Save",
      html: `<label class="fld">New password (14 characters or more)<input name="pw" type="password" minlength="14" autocomplete="new-password" required></label><label class="fld">Same again<input name="pw2" type="password" minlength="14" autocomplete="new-password" required></label>`,
      collect: async (f) => { if (f.pw.value !== f.pw2.value) return "The two passwords are different."; const { error } = await H.db.auth.updateUser({ password: f.pw.value }); return error ? error.message : true; } });
    if (ok) { H.toast("Password changed"); H.db.rpc("wd_touch", { p_action: "password changed" }); }
  };
  main.querySelector("[data-out]").onclick = () => H.signOut("global");
});
