// NFG Guard › Access: who is connecting (from where, with which key, how much data leaves), sign-ins,
// direct database logins, and the people who hold admin access to Supabase, Netlify and our Entra apps.
import { H } from "./watchdog.js";
const esc = H.esc;
const KEY = { secret: ["Secret key", "err"], service_role_jwt: ["service_role JWT", "err"], user: ["Signed-in user", "ok"], publishable: ["Publishable key", "mute"],
  anon_jwt: ["Legacy anon key", "warn"], none: ["No key", "mute"], function: ["Edge function", "info"] };
const keyTag = (k) => { const x = KEY[k] || [k, "mute"]; return H.tag(x[0], x[1]); };
const AGENT = { browser: "Browser", supabase: "Supabase function", script: "Script", bot: "Bot / scanner", server: "Server", none: "No agent", other: "Other" };

// ---------------------------------------------------------------- Who is connecting
H.screen("connecting", async (main, ctx) => {
  await H.targets();
  const st = { hours: ctx.ctx?.hours ?? 24, target: ctx.ctx?.target ?? "", tab: "ip" };
  const draw = async () => {
    H.loading(main);
    const [s, names] = await Promise.all([H.q(H.db.rpc("wd_traffic_summary", { p_hours: st.hours, p_target: st.target || null })), H.q(H.db.rpc("wd_user_names"))]);
    if (ctx.stale()) return;
    const email = new Map(names.map((n) => [`${n.target_id}|${n.actor_id}`, n.email]));
    const t = s.totals || {};
    const tabs = [["ip", "By address"], ["country", "By country"], ["key", "By key"], ["user", "By user"], ["target", "By project"]];
    let body = "";
    if (st.tab === "ip") body = H.table([
      { h: "Address", w: "150px", f: (r) => `<span class="mono">${esc(r.ip)}</span>`, sv: (r) => r.ip },
      { h: "Where", w: "1.3fr", f: (r) => `${esc([r.city, r.country].filter(Boolean).join(", "))}<br><span class="sub-t">${esc(r.asn || "")}</span>`, sv: (r) => r.country },
      { h: "Calls", w: "90px", cls: "n", f: (r) => H.u0(r.n), sv: (r) => Number(r.n), tot: true },
      { h: "Data out", w: "100px", cls: "n", f: (r) => H.bytes(r.b), sv: (r) => Number(r.b), tot: (rows) => rows.reduce((a, r) => a + Number(r.b), 0), fmt: H.bytes },
      { h: "Refused", w: "80px", cls: "n", f: (r) => r.denied ? `<b>${H.u0(r.denied)}</b>` : "", sv: (r) => Number(r.denied || 0) },
      { h: "Keys", w: "1.4fr", f: (r) => (r.keys || []).map(keyTag).join(" ") },
      { h: "Client", w: "1fr", f: (r) => esc((r.agents || []).map((a) => AGENT[a] || a).join(", ")) },
      { h: "Projects", w: "1.3fr", f: (r) => esc((r.targets || []).map(H.tname).join(", ")) },
      { h: "Last", w: "100px", f: (r) => esc(H.ago(r.last)), sv: (r) => r.last },
    ], s.by_ip || [], { search: "Search address, country, network, project", min: 1100, empty: "No traffic in this period." });
    if (st.tab === "country") body = `<div class="wd-2"><div class="card">${H.hbars((s.by_country || []).slice(0, 15).map((r) => ({ label: r.country, v: r.n })))}</div><div>` + H.table([
      { h: "Country", w: "100px", k: "country" },
      { h: "Calls", w: "1fr", cls: "n", f: (r) => H.u0(r.n), sv: (r) => Number(r.n), tot: true },
      { h: "Data out", w: "1fr", cls: "n", f: (r) => H.bytes(r.b), sv: (r) => Number(r.b) },
      { h: "Addresses", w: "1fr", cls: "n", f: (r) => H.u0(r.ips), sv: (r) => Number(r.ips) },
    ], s.by_country || [], { min: 420 }) + "</div></div>";
    if (st.tab === "key") body = `<p class="sub-t">Which keys call each project. A secret key (or service_role JWT) from anything other than a Supabase function deserves a look; from a browser it means the key has leaked.</p>` + H.table([
      { h: "Project", w: "1.4fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "Key", w: "1.2fr", f: (r) => keyTag(r.key_type), sv: (r) => r.key_type },
      { h: "Key prefix", w: "1.2fr", f: (r) => `<span class="mono">${esc(r.key_id || "")}</span>` },
      { h: "Client", w: "1fr", f: (r) => esc(AGENT[r.agent] || r.agent) + ((r.key_type === "secret" || r.key_type === "service_role_jwt") && r.agent === "browser" ? ` ${H.sev("critical")}` : "") },
      { h: "Calls", w: "100px", cls: "n", f: (r) => H.u0(r.n), sv: (r) => Number(r.n) },
      { h: "Addresses", w: "100px", cls: "n", f: (r) => H.u0(r.ips), sv: (r) => Number(r.ips) },
      { h: "Last", w: "100px", f: (r) => esc(H.ago(r.last)), sv: (r) => r.last },
    ], s.by_key || [], { search: true, min: 900, sort: { h: "Calls", dir: -1 } });
    if (st.tab === "user") body = `<p class="sub-t">Signed-in users of each project, from their tokens. Names come from sign-in events Guard has seen.</p>` + H.table([
      { h: "Project", w: "1.3fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "User", w: "1.8fr", f: (r) => esc(email.get(`${r.target_id}|${r.auth_user}`) || "") + `<br><span class="mono sub-t">${esc(r.auth_user)}</span>`, sv: (r) => email.get(`${r.target_id}|${r.auth_user}`) || r.auth_user },
      { h: "Calls", w: "90px", cls: "n", f: (r) => H.u0(r.n), sv: (r) => Number(r.n) },
      { h: "Data out", w: "100px", cls: "n", f: (r) => H.bytes(r.b), sv: (r) => Number(r.b) },
      { h: "Addresses", w: "90px", cls: "n", f: (r) => H.u0(r.ips), sv: (r) => Number(r.ips) },
      { h: "Countries", w: "100px", f: (r) => esc((r.countries || []).filter(Boolean).join(", ")) },
      { h: "Last", w: "100px", f: (r) => esc(H.ago(r.last)), sv: (r) => r.last },
    ], s.by_user || [], { search: true, min: 860 });
    if (st.tab === "target") body = H.table([
      { h: "Project", w: "2fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "Calls", w: "1fr", cls: "n", f: (r) => H.u0(r.n), sv: (r) => Number(r.n), tot: true },
      { h: "Data out", w: "1fr", cls: "n", f: (r) => H.bytes(r.b), sv: (r) => Number(r.b), tot: (rows) => rows.reduce((a, r) => a + Number(r.b), 0), fmt: H.bytes },
      { h: "Refused", w: "1fr", cls: "n", f: (r) => H.u0(r.denied), sv: (r) => Number(r.denied || 0) },
      { h: "Server errors", w: "1fr", cls: "n", f: (r) => H.u0(r.errors), sv: (r) => Number(r.errors || 0) },
      { h: "Addresses", w: "1fr", cls: "n", f: (r) => H.u0(r.ips), sv: (r) => Number(r.ips) },
      { h: "Users", w: "1fr", cls: "n", f: (r) => H.u0(r.users), sv: (r) => Number(r.users) },
    ], s.by_target || [], { min: 760 });

    main.innerHTML = H.title("Who is connecting", "Every call into the Supabase projects: from which address, country and network, with which key, as which user, and how much data went out.") +
      `<div class="filters">${H.period(st.hours)}<label class="fld grow">Project<select data-t><option value="">All projects</option>${[...H._targets.values()].filter((x) => x.kind === "supabase" && !x.meta?.org).map((x) => `<option value="${esc(x.id)}"${st.target === x.id ? " selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label></div>` +
      `<div class="kpis"><div class="card"><span class="kpi-l">Calls</span><span class="kpi">${H.u0(t.requests)}</span></div>` +
      `<div class="card"><span class="kpi-l">Data out</span><span class="kpi">${H.bytes(t.bytes)}</span></div>` +
      `<div class="card"><span class="kpi-l">Addresses</span><span class="kpi">${H.u0(t.ips)}</span><span class="sub-t">${H.u0(t.countries)} countries</span></div>` +
      `<div class="card"><span class="kpi-l">Signed-in users</span><span class="kpi">${H.u0(t.users)}</span></div>` +
      `<div class="card"><span class="kpi-l">Refused</span><span class="kpi">${H.u0(t.denied)}</span><span class="sub-t">401 / 403</span></div>` +
      `<div class="card"><span class="kpi-l">Secret-key calls</span><span class="kpi ${t.secret_calls ? "warnc" : ""}">${H.u0(t.secret_calls)}</span><span class="sub-t">not from Supabase functions</span></div></div>` +
      `<div class="card">${H.columns((s.series || []).map((x) => ({ y: x.n, label: `${H.dateTime(x.h)}: ${H.u0(x.n)} calls, ${H.bytes(x.b)} out` })), { aria: "Calls per hour", foot: s.series?.length ? [H.dateTime(s.series[0].h), H.dateTime(s.series.at(-1).h)] : null })}</div>` +
      `<div class="tabs" role="tablist">${tabs.map(([k, l]) => `<button class="tab${st.tab === k ? " on" : ""}" data-tab="${k}" role="tab">${l}</button>`).join("")}</div>` + body;
    main.querySelectorAll("[data-period]").forEach((b) => { b.onclick = () => { st.hours = Number(b.dataset.period); draw(); }; });
    main.querySelectorAll("[data-tab]").forEach((b) => { b.onclick = () => { st.tab = b.dataset.tab; draw(); }; });
    main.querySelector("[data-t]").onchange = (e) => { st.target = e.target.value; draw(); };
  };
  await draw();
});

// ---------------------------------------------------------------- Sign-ins
H.screen("signins", async (main, ctx) => {
  await H.targets();
  const st = { days: 7, target: "", fails: false, tab: "people" };
  const draw = async () => {
    H.loading(main);
    const rows = await H.all(() => {
      let x = H.db.from("wd_auth_event").select("at, target_id, action, actor_email, ip, country, user_agent, ok, meta").gte("at", new Date(Date.now() - st.days * 86400e3).toISOString()).order("at", { ascending: false });
      if (st.target) x = x.eq("target_id", st.target);
      if (st.fails) x = x.eq("ok", false);
      return x;
    }, 1000, 20000);
    if (ctx.stale()) return;
    const people = new Map();
    for (const r of rows.filter((r) => r.actor_email)) {
      const p = people.get(r.actor_email) ?? { email: r.actor_email, logins: 0, events: 0, ips: new Set(), countries: new Set(), projects: new Set(), last: r.at };
      p.events++; if (r.action === "login") p.logins++;
      if (r.ip) p.ips.add(r.ip); if (r.country) p.countries.add(r.country); p.projects.add(H.tname(r.target_id));
      people.set(r.actor_email, p);
    }
    const failsByIp = new Map();
    for (const r of rows.filter((r) => !r.ok)) failsByIp.set(r.ip, (failsByIp.get(r.ip) ?? 0) + 1);
    main.innerHTML = H.title("Sign-ins", "Sign-ins, sign-ups, password resets and failures on every Supabase project (from each project's auth logs).") +
      `<div class="filters"><label class="fld">Period<select data-d>${[1, 7, 30, 90].map((d) => `<option value="${d}"${st.days === d ? " selected" : ""}>${d === 1 ? "24 hours" : d + " days"}</option>`).join("")}</select></label>` +
      `<label class="fld grow">Project<select data-t><option value="">All projects</option>${[...H._targets.values()].filter((x) => x.kind === "supabase" && !x.meta?.org).map((x) => `<option value="${esc(x.id)}"${st.target === x.id ? " selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>` +
      `<label class="chk"><input type="checkbox" data-f${st.fails ? " checked" : ""}> Failures only</label></div>` +
      `<div class="tabs">${[["people", "By person"], ["events", "Every event"], ["fails", "Failures by address"]].map(([k, l]) => `<button class="tab${st.tab === k ? " on" : ""}" data-tab="${k}">${l}</button>`).join("")}</div>` +
      (st.tab === "people" ? H.table([
        { h: "Person", w: "2fr", f: (r) => esc(r.email), sv: (r) => r.email },
        { h: "Sign-ins", w: "90px", cls: "n", f: (r) => H.u0(r.logins), sv: (r) => r.logins },
        { h: "Events", w: "90px", cls: "n", f: (r) => H.u0(r.events), sv: (r) => r.events },
        { h: "Addresses", w: "90px", cls: "n", f: (r) => H.u0(r.ips.size), sv: (r) => r.ips.size },
        { h: "Countries", w: "110px", f: (r) => esc([...r.countries].join(", ")) },
        { h: "Projects", w: "2fr", f: (r) => esc([...r.projects].join(", ")) },
        { h: "Last", w: "120px", f: (r) => esc(H.ago(r.last)), sv: (r) => r.last },
      ], [...people.values()], { search: true, min: 860, sort: { h: "Sign-ins", dir: -1 }, empty: "No sign-ins recorded in this period." }) :
      st.tab === "events" ? H.table([
        { h: "When", w: "130px", f: (r) => esc(H.dateTime(r.at)), sv: (r) => r.at },
        { h: "Project", w: "1.2fr", f: (r) => esc(H.tname(r.target_id)) },
        { h: "Event", w: "1.2fr", f: (r) => (r.ok ? "" : H.tag("failed", "err") + " ") + esc(String(r.action).replace(/_/g, " ")) },
        { h: "Who", w: "1.6fr", f: (r) => esc(r.actor_email || r.meta?.error || "") },
        { h: "From", w: "1.3fr", f: (r) => `<span class="mono">${esc(r.ip || "")}</span> ${esc(r.country || "")}`, sv: (r) => r.ip },
        { h: "Browser", w: "1.6fr", f: (r) => `<span class="sub-t">${esc(String(r.user_agent || "").slice(0, 80))}</span>` },
      ], rows, { search: true, min: 1000, limit: 1000 }) :
      H.table([
        { h: "Address", w: "1fr", f: (r) => `<span class="mono">${esc(r[0] || "unknown")}</span>`, sv: (r) => r[0] },
        { h: "Failures", w: "1fr", cls: "n", f: (r) => H.u0(r[1]), sv: (r) => r[1] },
      ], [...failsByIp], { min: 400, sort: { h: "Failures", dir: -1 }, empty: "No failures." }));
    main.querySelector("[data-d]").onchange = (e) => { st.days = Number(e.target.value); draw(); };
    main.querySelector("[data-t]").onchange = (e) => { st.target = e.target.value; draw(); };
    main.querySelector("[data-f]").onchange = (e) => { st.fails = e.target.checked; draw(); };
    main.querySelectorAll("[data-tab]").forEach((b) => { b.onclick = () => { st.tab = b.dataset.tab; draw(); }; });
  };
  await draw();
});

// ---------------------------------------------------------------- Database logins
H.screen("dbconn", async (main, ctx) => {
  H.loading(main);
  await H.targets();
  const rows = await H.q(H.db.from("wd_db_connection").select("observed_at, target_id, role_name, app_name, client_addr, state, connections").gte("observed_at", new Date(Date.now() - 3 * 3600e3).toISOString()).order("observed_at", { ascending: false }).limit(3000));
  if (ctx.stale()) return;
  const latest = new Map();
  for (const r of rows) if (!latest.has(r.target_id)) latest.set(r.target_id, r.observed_at);
  const now = rows.filter((r) => latest.get(r.target_id) === r.observed_at);
  const outside = (a) => a && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fc|fd|fe80)/i.test(a);
  main.innerHTML = H.title("Database logins", "Who is connected straight to each Postgres database right now (taken every hour). Apps should come in through the API; a login from an outside address is worth knowing about.") +
    H.table([
      { h: "Project", w: "1.4fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "Database role", w: "1.2fr", f: (r) => `<span class="mono">${esc(r.role_name || "")}</span>` },
      { h: "Application", w: "1.4fr", f: (r) => esc(r.app_name || "") },
      { h: "From", w: "1.2fr", f: (r) => `<span class="mono">${esc(r.client_addr || "inside Supabase")}</span>${outside(r.client_addr) ? " " + H.tag("outside", "warn") : ""}`, sv: (r) => r.client_addr },
      { h: "State", w: "120px", k: "state" },
      { h: "Connections", w: "110px", cls: "n", f: (r) => H.u0(r.connections), sv: (r) => Number(r.connections), tot: true },
      { h: "Taken", w: "100px", f: (r) => esc(H.ago(r.observed_at)), sv: (r) => r.observed_at },
    ], now, { search: true, min: 960, empty: "No snapshot yet. It is taken by the hourly Supabase check." });
});

// ---------------------------------------------------------------- People with admin access
H.screen("people", async (main, ctx) => {
  H.loading(main);
  const targets = await H.targets(true);
  const apps = await H.q(H.db.from("wd_entra_app").select("display_name, owners, active").eq("active", true));
  if (ctx.stale()) return;
  const rows = [];
  for (const t of targets.values()) {
    if (t.meta?.org) for (const m of t.meta.members || []) rows.push({ where: t.name, kind: "Supabase organisation", who: m.name || m.email, email: m.email, role: m.role, mfa: m.mfa });
    if (t.meta?.account) for (const m of t.meta.members || []) rows.push({ where: t.name, kind: "Netlify team", who: m.name || m.email, email: m.email, role: m.role, mfa: null });
  }
  for (const a of apps) for (const o of a.owners || []) rows.push({ where: a.display_name, kind: "Entra app owner", who: o, email: o, role: "Owner", mfa: null });
  main.innerHTML = H.title("People with admin access", "Everyone who can change the platforms themselves: Supabase organisation members, Netlify team members and owners of our Entra app registrations. Leavers should not be here.") +
    H.table([
      { h: "Person", w: "1.6fr", f: (r) => `<b>${esc(r.who)}</b>${r.email && r.email !== r.who ? `<br><span class="sub-t">${esc(r.email)}</span>` : ""}`, sv: (r) => r.who },
      { h: "Where", w: "1.6fr", f: (r) => esc(r.where) },
      { h: "Kind", w: "1.2fr", f: (r) => esc(r.kind) },
      { h: "Role", w: "1fr", f: (r) => esc(r.role || "") },
      { h: "MFA", w: "90px", f: (r) => r.mfa === true ? H.tag("on", "ok") : r.mfa === false ? H.tag("off", "err") : `<span class="sub-t">unknown</span>`, sv: (r) => String(r.mfa) },
    ], rows, { search: true, min: 820, empty: "Nothing yet: this fills in once the Supabase, Netlify and Entra connections work." });
});
