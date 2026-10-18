// NFG Watchdog › Alerts and Admin: alerts, alert rules, collector runs and connections, settings, users, access log.
import { H } from "./watchdog.js";
const esc = H.esc;
const CATS = { access: "Access", data: "Data exposure", config: "Settings", secrets: "Secrets", exposure: "Internet exposure", activity: "Activity", performance: "Performance", reliability: "Reliability" };
const SOURCES = { supabase: "Supabase", netlify: "Netlify", entra: "Entra / 365", watchdog: "Watchdog" };

// ---------------------------------------------------------------- Alerts
H.screen("alerts", async (main, ctx) => {
  const st = { status: "open" };
  const draw = async () => {
    H.loading(main);
    const rows = await H.q((() => { let x = H.db.from("wd_alert").select("*, wd_finding(id, title, target_id, status)").order("at", { ascending: false }).limit(500); if (st.status !== "all") x = x.eq("status", st.status); return x; })());
    if (ctx.stale()) return;
    main.innerHTML = H.title("Alerts", "Findings that matched an alert rule and were sent (or tried to be). Acknowledge an alert once someone is on it.",
        H.btn("Acknowledge all shown", "work", { attrs: "data-ackall" })) +
      `<div class="seg" role="group">${[["open", "Open"], ["ack", "Acknowledged"], ["closed", "Closed"], ["all", "All"]].map(([k, l]) => `<button type="button" data-st="${k}" class="${st.status === k ? "on" : ""}">${l}</button>`).join("")}</div>` +
      H.table([
        { h: "When", w: "130px", f: (r) => esc(H.dateTime(r.at)), sv: (r) => r.at },
        { h: "Severity", w: "92px", f: (r) => H.sev(r.severity), sv: (r) => -H.SEV_RANK[r.severity] },
        { h: "Alert", w: "3fr", f: (r) => `<b>${esc(r.title)}</b><br><span class="sub-t">${esc(H.tname(r.wd_finding?.target_id))}</span>` },
        { h: "Sent", w: "1.4fr", f: (r) => r.delivered ? `${H.tag("sent", "ok")} ${esc(r.channel)}` : `${H.tag("not sent", "warn")} <span class="sub-t">${esc(r.delivery_error || "waiting")}</span>` },
        { h: "Status", w: "1fr", f: (r) => r.status === "open" ? H.tag("open", "err") : `${H.tag(r.status, "mute")}<br><span class="sub-t">${esc(r.ack_by || "")}</span>` },
      ], rows, { search: true, min: 900, rowAttrs: () => "", empty: "No alerts." });
    main.querySelectorAll("[data-st]").forEach((b) => { b.onclick = () => { st.status = b.dataset.st; draw(); }; });
    const all = main.querySelector("[data-ackall]");
    if (all && !all.disabled) all.onclick = async () => {
      const ids = rows.filter((r) => r.status === "open").map((r) => r.id);
      if (!ids.length) return;
      const { error } = await H.db.rpc("wd_alert_ack", { p_ids: ids, p_status: "ack" });
      if (error) H.toast(error.message, true); else { H.toast(`${ids.length} acknowledged`); draw(); }
    };
    H.rowClick(main, async (r) => {
      const v = await H.sheet({ title: r.title, ok: null,
        html: `<div class="row">${H.sev(r.severity)} ${H.tag(r.status)}</div><dl class="kv"><dt>When</dt><dd>${esc(H.dateTime(r.at))}</dd><dt>Sent to</dt><dd>${esc(r.channel)} · ${esc((r.recipients || []).join(", "))}</dd>` +
          (r.delivery_error ? `<dt>Problem</dt><dd>${esc(r.delivery_error)}</dd>` : "") + (r.ack_by ? `<dt>Handled by</dt><dd>${esc(r.ack_by)} ${esc(H.dateTime(r.ack_at))}</dd>` : "") + `</dl>`,
        extra: `<button type="button" class="btn" data-open>Open the finding</button>` + (r.status !== "ack" ? H.btn("Acknowledge", "work", { attrs: 'data-s="ack"' }) : "") + (r.status !== "closed" ? H.btn("Close", "work", { attrs: 'data-s="closed"' }) : ""),
        onOpen: (form, close) => {
          form.querySelector("[data-open]").onclick = () => { close(null); H.go("findings", { ctx: { open: r.finding_id } }); };
          form.querySelectorAll("[data-s]").forEach((b) => { if (!b.disabled) b.onclick = async () => { const { error } = await H.db.rpc("wd_alert_ack", { p_ids: [r.id], p_status: b.dataset.s }); if (error) form.err(error.message); else close(true); }; });
        } });
      if (v) draw();
    });
  };
  await draw();
});

// ---------------------------------------------------------------- Alert rules
H.screen("rules", async (main, ctx) => {
  H.loading(main);
  const rows = await H.q(H.db.from("wd_alert_rule").select("*").order("id"));
  if (ctx.stale()) return;
  main.innerHTML = H.title("Alert rules", "Which findings send an alert, how, and to whom. Each finding alerts once when it opens (and again if it comes back after being resolved).",
      H.btn("New rule", "admin", { cls: "pri", attrs: "data-new" })) +
    H.table([
      { h: "Rule", w: "2fr", f: (r) => `<b>${esc(r.name)}</b>${r.enabled ? "" : " " + H.tag("off", "mute")}` },
      { h: "From", w: "110px", f: (r) => `${H.sev(r.min_severity)} up` },
      { h: "Types", w: "1.4fr", f: (r) => esc((r.categories || []).map((c) => CATS[c] || c).join(", ") || "All") },
      { h: "Sources", w: "1.2fr", f: (r) => esc((r.sources || []).map((c) => SOURCES[c] || c).join(", ") || "All") },
      { h: "How", w: "100px", f: (r) => esc({ email: "Email", teams: "Teams", both: "Email + Teams" }[r.channel]) },
      { h: "To", w: "1.6fr", f: (r) => esc((r.recipients || []).join(", ") || "Alert emails setting") },
    ], rows, { min: 900, rowAttrs: () => "" }) +
    `<p class="sub-t">Email goes out through Microsoft 365 from the mailbox in Settings. Teams uses a Workflows webhook (secret WD_TEAMS_WEBHOOK on the NFG-Watchdog project).</p>`;
  const edit = async (r = {}) => {
    const ok = await H.sheet({ title: r.id ? "Edit rule" : "New rule", ok: "Save", wide: true,
      html: `<div class="dlg-fields"><label class="fld">Name<input name="name" required value="${esc(r.name || "")}"></label>` +
        `<label class="fld">Lowest severity<select name="min">${Object.entries(H.SEV).map(([k, l]) => `<option value="${k}"${(r.min_severity || "high") === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>` +
        `<label class="fld">How<select name="channel">${[["email", "Email"], ["teams", "Teams"], ["both", "Email and Teams"]].map(([k, l]) => `<option value="${k}"${(r.channel || "email") === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>` +
        `<label class="fld">To (emails, comma separated; empty = the Alert emails setting)<input name="rcp" value="${esc((r.recipients || []).join(", "))}"></label></div>` +
        `<h3>Types (none ticked = all)</h3><div class="chips">${Object.entries(CATS).map(([k, l]) => `<label class="chk"><input type="checkbox" name="cat" value="${k}"${(r.categories || []).includes(k) ? " checked" : ""}> ${l}</label>`).join("")}</div>` +
        `<h3>Sources (none ticked = all)</h3><div class="chips">${Object.entries(SOURCES).map(([k, l]) => `<label class="chk"><input type="checkbox" name="src" value="${k}"${(r.sources || []).includes(k) ? " checked" : ""}> ${l}</label>`).join("")}</div>` +
        `<label class="chk"><input type="checkbox" name="on"${r.enabled === false ? "" : " checked"}> Rule is on</label>`,
      collect: async (f) => {
        const rcp = f.rcp.value.split(/[,;\s]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
        if (rcp.some((x) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(x))) return "One of the email addresses does not look right.";
        const { error } = await H.db.rpc("wd_rule_save", { p_id: r.id ?? null, p_name: f.name.value.trim(), p_enabled: f.on.checked, p_min: f.min.value,
          p_categories: [...f.querySelectorAll("[name=cat]:checked")].map((x) => x.value), p_sources: [...f.querySelectorAll("[name=src]:checked")].map((x) => x.value), p_channel: f.channel.value, p_recipients: rcp });
        return error ? error.message : true;
      } });
    if (ok) { H.toast("Saved"); H.go("rules", { push: false }); }
  };
  const nb = main.querySelector("[data-new]");
  if (nb && !nb.disabled) nb.onclick = () => edit();
  if (H.can("admin")) H.rowClick(main, edit);
});

// ---------------------------------------------------------------- Collector runs and connections
H.screen("runs", async (main, ctx) => {
  H.loading(main);
  const [runs, conn] = await Promise.all([
    H.q(H.db.from("wd_run").select("*").order("started_at", { ascending: false }).limit(150)),
    H.q(H.db.from("wd_setting").select("value").eq("key", "connectors").single()),
  ]);
  if (ctx.stale()) return;
  const c = conn.value || {};
  const card = (k, title, how) => {
    const x = c[k];
    return `<div class="card"><div class="row"><h2>${esc(title)}</h2><span style="margin-left:auto">${x ? (x.ok ? H.tag("working", "ok") : H.tag("not working", "err")) : H.tag("not set up", "warn")}</span></div>` +
      `<p class="sub-t">${x?.note ? esc(x.note) : x ? esc(Object.entries(x).filter(([kk]) => !["ok", "at", "note", "errors"].includes(kk)).map(([kk, v]) => `${kk}: ${v}`).join(" · ")) : ""}${x?.at ? ` · checked ${esc(H.ago(x.at))}` : ""}</p>` +
      (x?.errors ? `<p class="sub-t">${esc([].concat(x.errors).join("; "))}</p>` : "") + `<details><summary class="sub-t">How to set it up</summary><div class="wd-how">${how}</div></details></div>`;
  };
  const sec = (n) => `<span class="mono">${n}</span>`;
  main.innerHTML = H.title("Collector runs", "The collector runs on a schedule: traffic and sign-ins every 15 minutes, settings checks hourly, clean-up nightly. Its keys live only in the NFG-Watchdog edge function secrets.",
      ["logs", "supabase", "netlify", "entra"].map((j) => H.btn(`Run ${j}`, "admin", { attrs: `data-run="${j}"` })).join("")) +
    `<div class="grid3">` +
      card("supabase", "Supabase", `<ol><li>Invite a new member to the NFG Supabase organisation with the <b>Read-only</b> role (e.g. watchdog@normandien.co.za) and turn on MFA for that account.</li><li>Signed in as that member: Account › Access Tokens › Generate new token, name it "NFG Watchdog".</li><li>NFG-Watchdog › Edge Functions › Secrets: add ${sec("SUPABASE_PAT")} with the token.</li></ol><p>Read-only keeps the token from changing anything if it ever leaks.</p>`) +
      card("netlify", "Netlify", `<ol><li>Netlify › User settings › Applications › Personal access tokens › New access token "NFG Watchdog", with an expiry date you will diarise.</li><li>Add it as ${sec("NETLIFY_TOKEN")} on NFG-Watchdog.</li></ol>`) +
      card("entra", "Entra ID / 365", `<ol><li>Entra admin centre › App registrations › New registration "NFG Watchdog", this organisation only, no redirect.</li><li>API permissions › Microsoft Graph › Application: ${sec("Application.Read.All")}, ${sec("AuditLog.Read.All")}, ${sec("Directory.Read.All")} and, for alert emails, ${sec("Mail.Send")}. Grant admin consent.</li><li>Limit Mail.Send to the alert mailbox with an Exchange application access policy.</li><li>Certificates & secrets › New client secret (12 months).</li><li>Add ${sec("ENTRA_TENANT_ID")}, ${sec("ENTRA_CLIENT_ID")} and ${sec("ENTRA_CLIENT_SECRET")} on NFG-Watchdog.</li></ol><p>Sign-in logs need Entra ID P1 (included in Microsoft 365 Business Premium).</p>`) +
      card("alerts", "Alerts", `<p>Email: set Settings › Alert mailbox (needs the Entra connection with Mail.Send). Teams: create a Workflows "post to a channel when a webhook request is received" flow and add its URL as ${sec("WD_TEAMS_WEBHOOK")}.</p>`) +
    `</div><h2>Runs</h2>` +
    H.table([
      { h: "Started", w: "140px", f: (r) => esc(H.dateTime(r.started_at)), sv: (r) => r.started_at },
      { h: "Job", w: "100px", k: "job" },
      { h: "Result", w: "110px", f: (r) => r.ok === true ? H.tag("done", "ok") : r.ok === false ? H.tag("failed", "err") : H.tag("running", "info") },
      { h: "Took", w: "80px", cls: "n", f: (r) => r.finished_at ? `${Math.round((new Date(r.finished_at) - new Date(r.started_at)) / 1000)} s` : "" },
      { h: "By", w: "1fr", f: (r) => esc(r.by_user || "") },
      { h: "Summary", w: "3fr", f: (r) => `<span class="sub-t">${esc(r.error || summary(r.stats))}</span>` },
    ], runs, { min: 900, rowAttrs: () => "", empty: "No runs yet." });
  main.querySelectorAll("[data-run]").forEach((b) => { if (!b.disabled) b.onclick = () => H.runJob(b.dataset.run).catch((e) => H.toast(e.message, true)); });
  H.rowClick(main, (r) => H.sheet({ title: `${r.job} · ${H.dateTime(r.started_at)}`, wide: true, ok: null, html: `<pre class="wd-pre">${esc(JSON.stringify({ error: r.error, ...r.stats }, null, 2))}</pre>` }));
});
function summary(s) {
  if (!s) return "";
  if (s.skipped) return s.skipped;
  const bits = [];
  if (s.projects != null) bits.push(`${s.projects} projects`);
  if (s.sites != null) bits.push(`${s.sites} sites`);
  if (s.apps != null) bits.push(`${s.apps} apps`);
  if (s.alerts) bits.push(`alerts: ${s.alerts.sent ?? 0} sent${s.alerts.pending ? `, ${s.alerts.pending} waiting` : ""}`);
  if (s.wd_traffic != null) bits.push(`cleaned up ${Object.values(s).filter((v) => typeof v === "number").reduce((a, b) => a + b, 0)} old rows`);
  return bits.join(" · ");
}

// ---------------------------------------------------------------- Settings
const SET_TYPE = { allowed_countries: "list", known_ips: "list", alert_emails: "list", excluded_projects: "list", alert_mailbox: "text",
  failed_login_threshold: "number", denied_request_threshold: "number", download_mb_threshold: "number", slow_query_ms: "number" };
const SET_NAME = { allowed_countries: "Countries we work from", known_ips: "Known addresses", alert_emails: "Alert emails", alert_mailbox: "Alert mailbox",
  failed_login_threshold: "Failed sign-ins before flagging", denied_request_threshold: "Refused requests before flagging", download_mb_threshold: "Large download (MB)",
  slow_query_ms: "Slow query (ms)", excluded_projects: "Projects to leave alone" };
H.screen("settings", async (main, ctx) => {
  H.loading(main);
  const rows = (await H.q(H.db.from("wd_setting").select("*").order("key"))).filter((r) => SET_TYPE[r.key]);
  if (ctx.stale()) return;
  const show = (r) => SET_TYPE[r.key] === "list" ? (r.value || []).join(", ") || "none" : String(r.value ?? "") || "not set";
  main.innerHTML = H.title("Settings", "What Watchdog treats as normal. Changes apply from the next collector run and are kept in the change log.") +
    H.table([
      { h: "Setting", w: "1.4fr", f: (r) => `<b>${esc(SET_NAME[r.key] || r.key)}</b><br><span class="sub-t">${esc(r.note || "")}</span>` },
      { h: "Value", w: "1.6fr", f: (r) => `<span class="mono">${esc(show(r))}</span>` },
      { h: "Changed", w: "1fr", f: (r) => `${esc(H.ago(r.updated_at))}<br><span class="sub-t">${esc(r.updated_by || "")}</span>`, sv: (r) => r.updated_at },
    ], rows, { min: 760, rowAttrs: () => "" });
  H.rowClick(main, async (r) => {
    const type = SET_TYPE[r.key];
    const ok = await H.sheet({ title: SET_NAME[r.key] || r.key, ok: "Save",
      html: `<p class="sub-t">${esc(r.note || "")}</p>` + (type === "list"
        ? `<label class="fld">One per line (or comma separated)<textarea name="v" rows="6">${esc((r.value || []).join("\n"))}</textarea></label>`
        : `<label class="fld">Value<input name="v" ${type === "number" ? 'type="number" min="1"' : ""} value="${esc(r.value ?? "")}"></label>`),
      collect: async (f) => {
        let v = f.v.value.trim();
        if (type === "list") {
          v = v.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
          if (r.key === "allowed_countries") { v = v.map((x) => x.toUpperCase()); if (v.some((x) => !/^[A-Z]{2}$/.test(x))) return "Use two-letter country codes, e.g. ZA, NA, BW."; }
          if (r.key === "known_ips" && v.some((x) => !/^[0-9a-f:.]+(\/\d{1,3})?$/i.test(x))) return "Each line must be an address or range, e.g. 41.0.0.10 or 196.21.0.0/24.";
          if (r.key === "alert_emails" && v.some((x) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(x))) return "One of the email addresses does not look right.";
        } else if (type === "number") { v = Number(v); if (!(v > 0)) return "Must be a number above 0."; }
        const { error } = await H.db.rpc("wd_setting_set", { p_key: r.key, p_value: v });
        return error ? error.message : true;
      } });
    if (ok) { H.toast("Saved"); H.go("settings", { push: false }); }
  });
});

// ---------------------------------------------------------------- Users
H.screen("users", async (main, ctx) => {
  H.loading(main);
  const rows = await H.q(H.db.from("wd_user").select("*").order("email"));
  if (ctx.stale()) return;
  main.innerHTML = H.title("Users", "Who may open Watchdog. Being on this list is not enough: the person also needs a Watchdog login (see below) and an authenticator app.",
      H.btn("Add a person", "admin", { cls: "pri", attrs: "data-new" })) +
    H.table([
      { h: "Person", w: "2fr", f: (r) => `<b>${esc(r.full_name || "")}</b><br><span class="sub-t">${esc(r.email)}</span>`, sv: (r) => r.email },
      { h: "Role", w: "1fr", f: (r) => esc(H.ROLE_NAME[r.role]) },
      { h: "Login", w: "1fr", f: (r) => r.auth_id ? H.tag("has a login", "ok") : H.tag("no login yet", "warn") },
      { h: "Access", w: "1fr", f: (r) => r.active ? H.tag("on", "ok") : H.tag("off", "mute") },
      { h: "Last seen", w: "1fr", f: (r) => esc(r.last_seen ? H.ago(r.last_seen) : "never"), sv: (r) => r.last_seen || "" },
    ], rows, { min: 760, rowAttrs: () => "" }) +
    `<div class="note"><b>Giving someone a login.</b> Supabase › NFG-Watchdog › Authentication › Users › Add user › Create new user, with their email, a long temporary password and "Auto confirm" ticked. Send the password separately. They set up their authenticator app on first sign-in and should change the password under My account. Watchdog links the login to this list by email.</div>`;
  const edit = async (r = {}) => {
    const ok = await H.sheet({ title: r.email ? r.email : "Add a person", ok: "Save",
      html: `<label class="fld">Email<input name="email" type="email" required value="${esc(r.email || "")}" ${r.email ? "readonly" : ""}></label>` +
        `<label class="fld">Name<input name="name" value="${esc(r.full_name || "")}"></label>` +
        `<label class="fld">Role<select name="role">${Object.entries(H.ROLE_NAME).map(([k, l]) => `<option value="${k}"${(r.role || "viewer") === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>` +
        `<p class="sub-t">View only: reads everything. Analyst: also accepts risks and handles alerts. Admin: also changes settings, rules and users, and runs the collector.</p>` +
        `<label class="chk"><input type="checkbox" name="on"${r.active === false ? "" : " checked"}> Access on</label>`,
      collect: async (f) => { const { error } = await H.db.rpc("wd_user_save", { p_email: f.email.value, p_name: f.name.value.trim() || null, p_role: f.role.value, p_active: f.on.checked }); return error ? error.message : true; } });
    if (ok) { H.toast("Saved"); H.go("users", { push: false }); }
  };
  const nb = main.querySelector("[data-new]");
  if (nb && !nb.disabled) nb.onclick = () => edit();
  H.rowClick(main, edit);
});

// ---------------------------------------------------------------- Watchdog access log
H.screen("accesslog", async (main, ctx) => {
  H.loading(main);
  const rows = await H.q(H.db.from("wd_access_log").select("*").order("at", { ascending: false }).limit(1000));
  if (ctx.stale()) return;
  main.innerHTML = H.title("Watchdog access log", "Who signed in to Watchdog itself, from where. Watchdog's own Supabase project is also watched like every other project.") +
    H.table([
      { h: "When", w: "140px", f: (r) => esc(H.dateTime(r.at)), sv: (r) => r.at },
      { h: "Who", w: "1.6fr", f: (r) => esc(r.email) },
      { h: "What", w: "1.2fr", f: (r) => esc(r.action) },
      { h: "From", w: "1.2fr", f: (r) => `<span class="mono">${esc(String(r.detail?.ip || "").split(",")[0])}</span>` },
      { h: "Browser", w: "2fr", f: (r) => `<span class="sub-t">${esc(r.detail?.agent || "")}</span>` },
    ], rows, { search: true, min: 860 });
});
