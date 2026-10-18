// NFG Watchdog › Security: findings (posture, data exposure, secrets, config), suspicious activity, change log.
// Performance findings use the same list with a preset filter.
import { H } from "./watchdog.js";
const esc = H.esc;

const CATS = { access: "Access", data: "Data exposure", config: "Settings", secrets: "Secrets", exposure: "Internet exposure", activity: "Activity", performance: "Performance", reliability: "Reliability" };
const SOURCES = { supabase: "Supabase", netlify: "Netlify", entra: "Entra / 365", watchdog: "Watchdog" };
const STATUS = { open: ["Open", "err"], accepted: ["Risk accepted", "warn"], resolved: ["Resolved", "ok"] };

export async function openFinding(id, after) {
  const f = await H.q(H.db.from("wd_finding").select("*").eq("id", id).maybeSingle());
  if (!f) { H.toast("That finding is no longer there (resolved findings are kept 90 days).", true); return; }
  const alerts = await H.q(H.db.from("wd_alert").select("at, channel, delivered, delivery_error, status").eq("finding_id", id).order("at", { ascending: false }).limit(5));
  const st = STATUS[f.status];
  const rem = String(f.remediation || "");
  const remHtml = /^https?:\/\//.test(rem) ? `<a href="${esc(rem)}" target="_blank" rel="noopener">${esc(rem)}</a>` : esc(rem);
  const meta = Object.keys(f.meta || {}).length ? `<details><summary class="sub-t">Technical detail</summary><pre class="wd-pre">${esc(JSON.stringify(f.meta, null, 2))}</pre></details>` : "";
  const v = await H.sheet({ title: f.title, wide: true, ok: null,
    html: `<div class="row">${H.sev(f.severity)} ${H.tag(st[0], st[1])} ${H.tag(CATS[f.category] || f.category)} ${H.kindTag(f.target_id)} <span class="sub-t">${esc(H.tname(f.target_id))}</span></div>` +
      (f.detail ? `<p style="white-space:pre-wrap">${esc(f.detail)}</p>` : "") +
      (rem ? `<div class="note"><b>What to do</b><br>${remHtml}</div>` : "") +
      `<dl class="kv"><dt>First seen</dt><dd>${esc(H.dateTime(f.first_seen))}</dd><dt>Last seen</dt><dd>${esc(H.dateTime(f.last_seen))} (${H.u0(f.seen_count)} checks)</dd>` +
      (f.resolved_at ? `<dt>Resolved</dt><dd>${esc(H.dateTime(f.resolved_at))}</dd>` : "") +
      (f.status === "accepted" ? `<dt>Accepted by</dt><dd>${esc(f.accepted_by)}${f.accepted_until ? ` until ${esc(H.shortDate(f.accepted_until))}` : ""}</dd>` : "") +
      (f.note ? `<dt>Note</dt><dd>${esc(f.note)}</dd>` : "") +
      `<dt>Check</dt><dd class="mono">${esc(f.check_code)}</dd>` +
      (alerts.length ? `<dt>Alerts</dt><dd>${alerts.map((a) => `${esc(H.dateTime(a.at))} · ${esc(a.channel)} · ${a.delivered ? "sent" : esc(a.delivery_error || "not sent yet")}`).join("<br>")}</dd>` : "") + `</dl>` + meta,
    extra: f.status === "open" ? H.btn("Accept the risk", "work", { attrs: "data-accept" }) : f.status === "accepted" ? H.btn("Reopen", "work", { attrs: "data-reopen" }) : "",
    onOpen: (form, close) => {
      const a = form.querySelector("[data-accept]"), r = form.querySelector("[data-reopen]");
      if (a && !a.disabled) a.onclick = async () => {
        close(null);
        const ok = await H.sheet({ title: "Accept the risk", ok: "Accept",
          html: `<p class="sub-t">The finding stays on record but stops counting against the score and stops alerting. If it is still there after the date, it opens again.</p>` +
            `<label class="fld">Why is this acceptable?<textarea name="note" rows="3" required placeholder="e.g. This webhook checks a signature itself."></textarea></label>` +
            `<label class="fld">Review again on (optional)<input name="until" type="date"></label>`,
          collect: async (fm) => { const { error } = await H.db.rpc("wd_finding_set", { p_id: f.id, p_status: "accepted", p_note: fm.note.value, p_until: fm.until.value || null }); return error ? error.message : true; } });
        if (ok) { H.toast("Risk accepted"); after?.(); }
      };
      if (r && !r.disabled) r.onclick = async () => {
        const { error } = await H.db.rpc("wd_finding_set", { p_id: f.id, p_status: "open", p_note: null, p_until: null });
        if (error) { form.err(error.message); return; }
        close(true); H.toast("Reopened"); after?.();
      };
    } });
  return v;
}

function findingsScreen(key, preset) {
  H.screen(key, async (main, ctx) => {
    H.loading(main);
    await H.targets();
    const st = { status: "open", sev: ctx.ctx?.sev ?? "", source: "", cat: preset?.cat ?? "", target: ctx.ctx?.target ?? "", ...(H._fstate?.[key] ?? {}) };
    if (ctx.ctx?.sev) st.sev = ctx.ctx.sev;
    const draw = async () => {
      let q = () => {
        let x = H.db.from("wd_finding").select("id, severity, category, source, target_id, check_code, title, first_seen, last_seen, status, note, accepted_until").order("last_seen", { ascending: false });
        if (st.status !== "all") x = x.eq("status", st.status);
        if (st.sev) x = x.eq("severity", st.sev);
        if (st.source) x = x.eq("source", st.source);
        if (st.target) x = x.eq("target_id", st.target);
        if (preset?.cat) x = x.eq("category", preset.cat);
        else if (st.cat) x = x.eq("category", st.cat);
        else x = x.neq("category", "performance");
        return x;
      };
      const rows = await H.all(q);
      if (ctx.stale()) return;
      (H._fstate ||= {})[key] = st;
      const count = (s) => rows.filter((r) => r.severity === s).length;
      main.innerHTML = H.title(preset?.title ?? "Findings", preset?.sub ?? "Every problem Watchdog has found. Each one says what it is and what to do. Fixed problems resolve on the next check; you can accept a risk with a reason.") +
        `<div class="filters">` +
          `<div class="seg" role="group" aria-label="Status">${[["open", "Open"], ["accepted", "Accepted"], ["resolved", "Resolved"], ["all", "All"]].map(([k, l]) => `<button type="button" data-st="${k}" class="${st.status === k ? "on" : ""}">${l}</button>`).join("")}</div>` +
          `<label class="fld">Severity<select data-f="sev"><option value="">Any</option>${Object.entries(H.SEV).map(([k, l]) => `<option value="${k}"${st.sev === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>` +
          `<label class="fld">Source<select data-f="source"><option value="">Any</option>${Object.entries(SOURCES).map(([k, l]) => `<option value="${k}"${st.source === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>` +
          (preset?.cat ? "" : `<label class="fld">Type<select data-f="cat"><option value="">All but performance</option>${Object.entries(CATS).map(([k, l]) => `<option value="${k}"${st.cat === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>`) +
          `<label class="fld grow">Project or site<select data-f="target"><option value="">All</option>${[...H._targets.values()].map((t) => `<option value="${esc(t.id)}"${st.target === t.id ? " selected" : ""}>${esc(t.name)}</option>`).join("")}</select></label>` +
        `</div>` +
        `<div class="chips">${["critical", "high", "medium", "low", "info"].map((s) => `<span class="sub-t">${H.sev(s)} ${count(s)}</span>`).join("")}</div>` +
        H.table([
          { h: "Severity", w: "92px", f: (r) => H.sev(r.severity), sv: (r) => -H.SEV_RANK[r.severity] },
          { h: "Finding", w: "3fr", f: (r) => `<b>${esc(r.title)}</b>${r.note ? `<br><span class="sub-t">${esc(r.note)}</span>` : ""}`, sv: (r) => r.title },
          { h: "Where", w: "1.3fr", f: (r) => `${esc(H.tname(r.target_id))}<br>${H.kindTag(r.target_id)}`, sv: (r) => H.tname(r.target_id) },
          { h: "Type", w: "120px", f: (r) => esc(CATS[r.category] || r.category), sv: (r) => r.category },
          { h: "First seen", w: "110px", f: (r) => esc(H.shortDate(r.first_seen)), sv: (r) => r.first_seen },
          { h: "Last seen", w: "110px", f: (r) => esc(H.ago(r.last_seen)), sv: (r) => r.last_seen },
          { h: "Status", w: "110px", f: (r) => H.tag(STATUS[r.status][0], STATUS[r.status][1]), sv: (r) => r.status },
        ], rows, { search: "Search findings", sort: { h: "Severity" }, min: 900, empty: st.status === "open" ? "Nothing open. Good." : "Nothing here.", rowAttrs: () => "", limit: 500 });
      H.rowClick(main, (r) => openFinding(r.id, draw));
      main.querySelectorAll("[data-st]").forEach((b) => { b.onclick = () => { st.status = b.dataset.st; draw(); }; });
      main.querySelectorAll("[data-f]").forEach((s) => { s.onchange = () => { st[s.dataset.f] = s.value; draw(); }; });
    };
    await draw();
    if (ctx.ctx?.open) openFinding(ctx.ctx.open, draw);
  });
}
// the rows a table is showing right now (after search and sort), so a click maps to the right finding
function currentRows(t) {
  let rows = t.rows;
  const q = (t.q || "").trim().toLowerCase();
  const txt = (c, r) => (c.sv ? c.sv(r) : c.k ? r[c.k] : c.f ? String(c.f(r) ?? "").replace(/<[^>]*>/g, "") : "");
  if (q) rows = rows.filter((r) => t.cols.some((c) => String(txt(c, r) ?? "").toLowerCase().includes(q)));
  if (t.sort) {
    const c = t.cols[t.sort.i], dir = t.sort.dir;
    rows = [...rows].sort((a, b) => { const x = txt(c, a), y = txt(c, b); if (x === y) return 0; if (x === null || x === undefined || x === "") return 1; if (y === null || y === undefined || y === "") return -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "en-ZA", { numeric: true })) * dir; });
  }
  return t.opts.limit ? rows.slice(0, t.opts.limit) : rows;
}
H.currentRows = currentRows;
// click on a row of the (only) table in root -> fn(row)
// (listens on the table itself: the main area is reused by every screen)
H.rowClick = (root, fn) => root.querySelectorAll(".tbl").forEach((tb) => tb.addEventListener("click", (e) => {
  const tr = e.target.closest(".tr.click"); if (!tr || e.target.closest("a,button:not(.c)")) return;
  const t = H._tables[tr.closest(".t").id];
  const idx = [...tr.parentNode.children].filter((x) => x.classList.contains("click")).indexOf(tr);
  const r = currentRows(t)[idx];
  if (r) fn(r);
}));

findingsScreen("findings");
findingsScreen("perf_findings", { cat: "performance", title: "Performance findings", sub: "Slow queries, missing indexes and other things that make the apps slower. They do not count towards the security score." });

// ---------------------------------------------------------------- Suspicious activity
H.screen("activity", async (main, ctx) => {
  H.loading(main);
  await H.targets();
  const since = new Date(Date.now() - 14 * 86400e3).toISOString();
  const [acts, events] = await Promise.all([
    H.q(H.db.from("wd_finding").select("id, severity, check_code, target_id, title, detail, first_seen, last_seen, seen_count, status").eq("category", "activity").gte("last_seen", since).order("last_seen", { ascending: false }).limit(500)),
    H.q(H.db.from("wd_auth_event").select("at, target_id, action, actor_email, ip, country, ok, meta").eq("ok", false).gte("at", new Date(Date.now() - 86400e3).toISOString()).order("at", { ascending: false }).limit(300)),
  ]);
  if (ctx.stale()) return;
  main.innerHTML = H.title("Suspicious activity", "Things that happened, as opposed to settings: secret keys used from odd places, password guessing, sign-ins from abroad, big downloads, probing, app credential changes. Last 14 days.") +
    H.table([
      { h: "Severity", w: "92px", f: (r) => H.sev(r.severity), sv: (r) => -H.SEV_RANK[r.severity] },
      { h: "What happened", w: "3fr", f: (r) => `<b>${esc(r.title)}</b><br><span class="sub-t">${esc(String(r.detail ?? "").slice(0, 220))}</span>`, sv: (r) => r.title },
      { h: "Where", w: "1.2fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "Last seen", w: "130px", f: (r) => esc(H.dateTime(r.last_seen)), sv: (r) => r.last_seen },
      { h: "Status", w: "100px", f: (r) => H.tag(STATUS[r.status][0], STATUS[r.status][1]), sv: (r) => r.status },
    ], acts, { search: true, min: 860, empty: "No suspicious activity in the last 14 days.", rowAttrs: () => "" }) +
    `<h2>Failed sign-ins and refused auth calls · 24 hours</h2>` +
    H.table([
      { h: "When", w: "130px", f: (r) => esc(H.dateTime(r.at)), sv: (r) => r.at },
      { h: "Project", w: "1.2fr", f: (r) => esc(H.tname(r.target_id)) },
      { h: "What", w: "1.2fr", f: (r) => esc(String(r.action).replace(/_/g, " ")) },
      { h: "Why", w: "1.6fr", f: (r) => esc(r.meta?.error || r.meta?.code || "") },
      { h: "From", w: "1.2fr", f: (r) => `<span class="mono">${esc(r.ip || "")}</span> ${esc(r.country || "")}`, sv: (r) => r.ip },
    ], events, { search: true, min: 760, empty: "No failed sign-ins in the last 24 hours." });
  const first = main.querySelector(".tbl");
  H.rowClick({ querySelectorAll: () => [first] }, (r) => openFinding(r.id, () => H.go("activity", { push: false })));
});

// ---------------------------------------------------------------- Change log
H.screen("changes", async (main, ctx) => {
  H.loading(main);
  await H.targets();
  const st = { kind: "", days: 7 };
  const KIND = { finding: "Findings", edge_function: "Edge functions", secret: "Edge function secrets", netlify_env: "Netlify variables", api_key: "API keys", entra_credential: "Entra credentials", outbound: "Outbound calls", user: "Watchdog users", setting: "Watchdog settings" };
  const draw = async () => {
    const rows = await H.all(() => {
      let x = H.db.from("wd_change").select("at, target_id, kind, item, action, detail, by_user").gte("at", new Date(Date.now() - st.days * 86400e3).toISOString()).order("at", { ascending: false });
      if (st.kind) x = x.eq("kind", st.kind);
      return x;
    }, 1000, 10000);
    if (ctx.stale()) return;
    main.innerHTML = H.title("Change log", "What changed and when: findings opening and closing, functions deployed, secrets and keys added, changed or removed, settings. Kept 90 days.") +
      `<div class="filters"><label class="fld">Kind<select data-k><option value="">Everything</option>${Object.entries(KIND).map(([k, l]) => `<option value="${k}"${st.kind === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>` +
      `<label class="fld">Period<select data-d>${[1, 7, 30, 90].map((d) => `<option value="${d}"${st.days === d ? " selected" : ""}>${d === 1 ? "24 hours" : d + " days"}</option>`).join("")}</select></label></div>` +
      H.table([
        { h: "When", w: "140px", f: (r) => esc(H.dateTime(r.at)), sv: (r) => r.at },
        { h: "Kind", w: "150px", f: (r) => esc(KIND[r.kind] || r.kind) },
        { h: "Change", w: "100px", f: (r) => H.tag(r.action, ["opened", "reopened", "removed"].includes(r.action) ? "err" : ["resolved", "added"].includes(r.action) ? "ok" : "mute") },
        { h: "Item", w: "3fr", f: (r) => esc(r.item) + (r.detail?.severity ? ` ${H.sev(r.detail.severity)}` : "") + (r.detail?.note ? `<br><span class="sub-t">${esc(r.detail.note)}</span>` : "") },
        { h: "Where", w: "1.3fr", f: (r) => esc(r.target_id ? H.tname(r.target_id) : "Watchdog") },
        { h: "By", w: "1fr", f: (r) => esc(r.by_user || "collector") },
      ], rows, { search: true, min: 900, limit: 1000, empty: "No changes in this period." });
    main.querySelector("[data-k]").onchange = (e) => { st.kind = e.target.value; draw(); };
    main.querySelector("[data-d]").onchange = (e) => { st.days = Number(e.target.value); draw(); };
  };
  await draw();
});
