// NFG Watchdog shell: sign-in (own accounts + authenticator app), rail, module menu, top bar, router and helpers.
// Layout and helpers come from NFG Fleet / Hive / Core so it looks and behaves like the other NFG apps.
// The difference: Watchdog does NOT use the central NFG login. People sign in with a Watchdog account
// (NFG-Watchdog project), and must use an authenticator app every time (aal2). Nothing loads before that.
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm";
import { WD_URL, WD_KEY, PORTAL_URL, IDLE_MINUTES } from "./config.js";

const sb = createClient(WD_URL, WD_KEY, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, storageKey: "wd.auth", flowType: "pkce" } });

export const H = {
  db: sb, URL: WD_URL, PORTAL_URL, me: null,
  SCREENS: {}, MENU: [], ICONS: {}, PARENT: {},
  cur: { screen: "home" }, stack: [], menuOpen: false, pinned: false, token: 0,
};

// ---------- roles: viewer reads; analyst works findings and alerts; admin changes settings, rules and users ----------
H.SCREEN_PERM = {};
H.can = (p) => !p || (p === "work" ? ["admin", "analyst"].includes(H.me?.role) : p === "admin" ? H.me?.role === "admin" : true);
const allowed = (s) => H.can(H.SCREEN_PERM[s]);
H.allowed = allowed;
H.ROLE_NAME = { admin: "Watchdog admin", analyst: "Analyst", viewer: "View only" };

// ---------- small helpers ----------
H.esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
H.shortDate = (d) => d ? new Date(d).toLocaleDateString("en-ZA", { day: "numeric", month: "short", year: "numeric" }) : "";
H.dateTime = (d) => d ? `${H.shortDate(d)} ${new Date(d).toLocaleTimeString("en-ZA", { hour: "2-digit", minute: "2-digit" })}` : "";
H.timeOnly = (d) => d ? new Date(d).toLocaleTimeString("en-ZA", { hour: "2-digit", minute: "2-digit" }) : "";
H.ago = (d) => {
  if (!d) return "";
  const s = (Date.now() - new Date(d).getTime()) / 1000;
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
};
const nf = (dp) => new Intl.NumberFormat("en-US", { minimumFractionDigits: dp, maximumFractionDigits: dp });
const fmt = (v, dp) => (v === null || v === undefined || v === "" || isNaN(v)) ? "" : nf(dp).format(Number(v)).replace(/,/g, " ").replace(".", ",");
H.u0 = (v) => fmt(v, 0);
H.n1 = (v) => fmt(v, 1);
H.bytes = (b) => { b = Number(b) || 0; if (b < 1024) return `${b} B`; if (b < 1048576) return `${H.n1(b / 1024)} KB`; if (b < 1073741824) return `${H.n1(b / 1048576)} MB`; return `${H.n1(b / 1073741824)} GB`; };
H.daysTo = (d) => d ? Math.round((new Date(d) - Date.now()) / 86400000) : null;
H.toast = (msg, isError) => {
  const t = document.getElementById("toast");
  t.textContent = msg; t.className = "show" + (isError ? " err" : "");
  clearTimeout(H._tt); H._tt = setTimeout(() => { t.className = ""; }, 3200);
};
H.icon = (paths, cls) => `<svg class="${cls || ""}" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
const I = {
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>', back: '<path d="M15 5l-7 7 7 7"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 5v6h-6"/>', out: '<path d="M10 4H5v16h5"/><path d="M14 8l4 4-4 4M18 12H9"/>',
  pin: '<path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7"/>', close: '<path d="M6 6l12 12M18 6L6 18"/>', chev: '<path d="M6 9l6 6 6-6"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  apps: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/>',
};
H.I = I;
H.title = (h, sub, actionsHtml) =>
  `<div class="row"><h1>${H.esc(h)}</h1>${actionsHtml ? `<div class="row" style="margin-left:auto">${actionsHtml}</div>` : ""}</div>` +
  (sub ? `<p class="sub-t">${H.esc(sub)}</p>` : "");
H.tag = (text, kind) => `<span class="tag t-${kind || "mute"}">${H.esc(text)}</span>`;
H.SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
H.SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
H.sev = (s) => `<span class="sev s-${H.esc(s)}">${H.esc(H.SEV[s] || s)}</span>`;
H.loading = (main) => { main.innerHTML = '<div class="loading">Loading…</div>'; };
H.failed = (main, err) => { console.error(err); main.innerHTML = `<div class="banner err">Could not load that. ${H.esc(err?.message ?? String(err))}</div>`; };
H.q = (promise) => promise.then((r) => { if (r.error) throw r.error; return r.data; });
H.all = async (build, size = 1000, max = 20000) => {
  const out = [];
  for (let from = 0; from < max; from += size) {
    const rows = await H.q(build().range(from, from + size - 1));
    out.push(...rows);
    if (rows.length < size) return out;
  }
  return out;
};
// targets (projects, sites, tenants) by id, loaded once per session and on refresh
H.targets = async (force) => {
  if (!H._targets || force) {
    const rows = await H.q(sb.from("wd_target").select("id, kind, ref, name, url, meta, active, last_seen").order("kind").order("name"));
    H._targets = new Map(rows.map((r) => [r.id, r]));
  }
  return H._targets;
};
H.tname = (id) => H._targets?.get(id)?.name ?? (id ? String(id).replace(/^[a-z-]+:/, "") : "Watchdog");
H.kindTag = (id) => { const k = String(id ?? "").split(":")[0]; return H.tag({ supabase: "Supabase", "supabase-org": "Supabase org", netlify: "Netlify", entra: "Entra" }[k] ?? "Watchdog", "mute"); };
H.period = (cur, hours = [24, 168, 720, 2160]) => `<div class="seg" role="group" aria-label="Period">${hours.map((h) =>
  `<button type="button" data-period="${h}" class="${h === cur ? "on" : ""}">${h === 24 ? "24 hours" : h === 168 ? "7 days" : h === 720 ? "30 days" : "90 days"}</button>`).join("")}</div>`;

// Column chart (one series): bars with a hover label. rows = [{x, y, label}]
H.columns = (rows, o = {}) => {
  const max = Math.max(1, ...rows.map((r) => Number(r.y) || 0));
  return `<div class="wd-cols" role="img" aria-label="${H.esc(o.aria || "Chart")}">` + rows.map((r) =>
    `<div class="wd-col" tabindex="0" title="${H.esc(r.label)}"><i style="height:${Math.max(2, Math.round((Number(r.y) || 0) / max * 100))}%"></i><span class="wd-tip">${H.esc(r.label)}</span></div>`).join("") +
    `</div>${o.foot ? `<div class="wd-cols-foot sub-t"><span>${H.esc(o.foot[0])}</span><span>${H.esc(o.foot[1])}</span></div>` : ""}`;
};
// Horizontal bars with labels and values
H.hbars = (rows, o = {}) => {
  const max = Math.max(1, ...rows.map((r) => Number(r.v) || 0));
  return `<div class="wd-hb">` + rows.map((r) => `<div class="wd-hbr"><span class="wd-hbl">${r.labelHtml ?? H.esc(r.label)}</span>` +
    `<span class="wd-hbt"><i class="${r.cls || ""}" style="width:${Math.max(1, Math.round((Number(r.v) || 0) / max * 100))}%"></i></span><span class="n">${H.esc(o.fmt ? o.fmt(r.v) : H.u0(r.v))}</span></div>`).join("") + "</div>";
};

// Table (sortable, filterable, totalled). cols = [{h, k|f, cls, w, sv(r), tot}], rows; opts {min, empty, rowAttrs(r), search, sort:{k,dir}, limit}
H._tables = {};
let tableSeq = 0;
const cellText = (c, r) => (c.sv ? c.sv(r) : c.k ? r[c.k] : c.f ? String(c.f(r) ?? "").replace(/<[^>]*>/g, "") : "");
const tableBody = (t) => {
  const { cols, opts } = t;
  let rows = t.rows;
  const q = (t.q || "").trim().toLowerCase();
  if (q) rows = rows.filter((r) => cols.some((c) => String(cellText(c, r) ?? "").toLowerCase().includes(q)));
  if (t.sort) {
    const c = cols[t.sort.i], dir = t.sort.dir;
    rows = [...rows].sort((a, b) => {
      const x = cellText(c, a), y = cellText(c, b);
      if (x === y) return 0;
      if (x === null || x === undefined || x === "") return 1;
      if (y === null || y === undefined || y === "") return -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "en-ZA", { numeric: true })) * dir;
    });
  }
  const shown = opts.limit ? rows.slice(0, opts.limit) : rows;
  let h = `<div class="tr th">${cols.map((c, i) => `<button type="button" class="c sortc ${c.cls || ""}" data-sort="${i}">${H.esc(c.h)}${t.sort && t.sort.i === i ? (t.sort.dir > 0 ? " ▲" : " ▼") : ""}</button>`).join("")}</div>`;
  if (!shown.length) h += `<div class="tr"><div class="c full sub-t">${H.esc(q ? "Nothing matches that." : (opts.empty || "Nothing to show yet."))}</div></div>`;
  shown.forEach((r) => {
    h += `<div class="tr${opts.rowAttrs ? " click" : ""}" ${opts.rowAttrs ? opts.rowAttrs(r) : ""}>` +
      cols.map((c) => `<div class="c ${c.cls || ""}">${c.f ? (c.f(r) ?? "") : H.esc(r[c.k])}</div>`).join("") + "</div>";
  });
  if (cols.some((c) => c.tot)) {
    h += `<div class="tr tot">${cols.map((c, i) => {
      if (!c.tot) return `<div class="c ${c.cls || ""}">${i === 0 ? `Total (${H.u0(rows.length)})` : ""}</div>`;
      const v = typeof c.tot === "function" ? c.tot(rows) : rows.reduce((s, r) => s + (Number(cellText(c, r)) || 0), 0);
      return `<div class="c ${c.cls || ""}">${H.esc(c.fmt ? c.fmt(v) : H.u0(v))}</div>`;
    }).join("")}</div>`;
  }
  if (opts.limit && rows.length > opts.limit) h += `<div class="tr"><div class="c full sub-t">Showing ${H.u0(opts.limit)} of ${H.u0(rows.length)}. Search to narrow it down.</div></div>`;
  t.count = rows.length;
  return h;
};
H.table = (cols, rows, opts = {}) => {
  const id = "t" + (++tableSeq);
  const t = { cols, rows, opts, q: "", sort: null };
  if (opts.sort) { const i = cols.findIndex((c) => c.k === opts.sort.k || c.h === opts.sort.h); if (i >= 0) t.sort = { i, dir: opts.sort.dir || 1 }; }
  H._tables[id] = t;
  const template = cols.map((c) => c.w || "1fr").join(" ");
  const search = opts.search ? `<div class="tsearch"><input type="search" data-tsearch="${id}" placeholder="${H.esc(typeof opts.search === "string" ? opts.search : "Search")}" aria-label="Search this list"><span class="sub-t" data-tcount="${id}">${H.u0(rows.length)}</span></div>` : "";
  return search + `<div class="tbl"><div class="t" id="${id}" style="--cols:${template};--min:${opts.min || 640}px">${tableBody(t)}</div></div>`;
};
const redrawTable = (id) => {
  const el = document.getElementById(id), t = H._tables[id];
  if (!el || !t) return;
  el.innerHTML = tableBody(t);
  const n = document.querySelector(`[data-tcount="${id}"]`);
  if (n) n.textContent = H.u0(t.count);
};
document.addEventListener("click", (e) => {
  const b = e.target.closest(".sortc");
  if (!b) return;
  const id = b.closest(".t")?.id, t = H._tables[id];
  if (!t) return;
  const i = Number(b.dataset.sort);
  t.sort = t.sort && t.sort.i === i ? { i, dir: -t.sort.dir } : { i, dir: 1 };
  redrawTable(id);
});
document.addEventListener("input", (e) => {
  const id = e.target.dataset?.tsearch;
  if (!id || !H._tables[id]) return;
  H._tables[id].q = e.target.value;
  redrawTable(id);
});
H.btn = (label, perm, o = {}) => {
  const ok = H.can(perm);
  return `<button type="button" class="btn ${o.cls || ""}" ${o.attrs || ""}${ok ? "" : ` disabled title="${H.esc(o.why || (perm === "admin" ? "Only a Watchdog admin can do this" : "You need the analyst or admin role for this"))}"`}>${H.esc(label)}</button>`;
};

// ---------- in-page dialogs ----------
H.sheet = (o) => new Promise((resolve) => {
  const wrap = document.createElement("div");
  wrap.className = "dlg-wrap";
  wrap.innerHTML = `<form class="dlg" role="dialog" aria-modal="true" aria-label="${H.esc(o.title)}"${o.wide ? ' style="max-width:820px"' : ""}>` +
    `<h2>${H.esc(o.title)}</h2>${o.html || ""}<p class="dlg-err" hidden></p>` +
    `<div class="row dlg-btns">${o.extra || ""}<span style="flex:1"></span><button type="button" class="btn" data-x>${H.esc(o.cancel || (o.ok ? "Cancel" : "Close"))}</button>` +
    (o.ok ? `<button type="submit" class="btn ${o.danger ? "danger" : "pri"}">${H.esc(o.ok)}</button>` : "") + "</div></form>";
  document.body.appendChild(wrap);
  const form = wrap.querySelector("form");
  const close = (v) => { wrap.remove(); resolve(v); };
  form.err = (t) => { const er = form.querySelector(".dlg-err"); er.hidden = !t; er.textContent = t || ""; };
  wrap.querySelector("[data-x]").onclick = () => close(null);
  wrap.addEventListener("keydown", (e) => { if (e.key === "Escape") close(null); });
  form.onsubmit = async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    try {
      const v = o.collect ? await o.collect(form) : true;
      if (typeof v === "string") { form.err(v); return; }
      close(v);
    } catch (err) { form.err(err.message || String(err)); }
    finally { if (btn) btn.disabled = false; }
  };
  if (o.onOpen) o.onOpen(form, close);
  const f = form.querySelector("input,select,textarea") || form.querySelector("button[type=submit]");
  if (f) f.focus();
});
H.confirm = (title, text, ok, danger) => H.sheet({ title, html: `<p class="sub-t">${H.esc(text)}</p>`, ok: ok || "Confirm", danger }).then((v) => !!v);

// run a collector job now (admins). The job runs in the background; Admin › Runs shows the result.
H.runJob = async (job) => {
  const { data: { session } } = await sb.auth.getSession();
  const r = await fetch(`${WD_URL}/functions/v1/wd-collect?job=${encodeURIComponent(job)}`, { method: "POST", headers: { Authorization: `Bearer ${session?.access_token}`, apikey: WD_KEY } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `The collector said ${r.status}`);
  H.toast(`Started: ${job}. Results show up in a minute or two.`);
};

// ---------- screens and router ----------
H.screen = (key, fn) => { H.SCREENS[key] = fn; };
const initials = (name) => String(name || "?").split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("");
const findItem = (screen) => {
  for (const m of H.MENU) for (const s of m.secs) for (const it of s.items) if (it.s === screen) return { mod: m, sec: s.h, item: it };
  return null;
};
const modItems = (m) => m.secs.flatMap((s) => s.items);

H.shell = () => {
  const b = window.APP_BUILD, name = H.me.name || H.me.email;
  const rail = H.MENU.filter((m) => modItems(m).length).map((m) => (m.sep ? '<div class="railsep"></div>' : "") +
    `<button class="mod" data-mod="${m.k}">${H.icon(H.ICONS[m.k] || "")}${H.esc(m.n)}</button>`).join("");
  document.getElementById("app").innerHTML =
    '<div class="app">' +
    '<aside class="rail" aria-label="Modules"><div class="brand"><img src="assets/watchdog-mark-white.svg" alt="NFG Watchdog"><div class="word">WATCHDOG</div></div>' +
    `<div class="mods">${rail}</div>` +
    `<div class="fleet-sw"><a class="home-link" href="${H.esc(PORTAL_URL)}" target="_blank" rel="noopener" title="NFG Home (separate sign-in)">${H.icon(I.apps)}<span>NFG apps</span></a></div>` +
    `<button class="me" id="meBtn" title="${H.esc(name)}"><span class="av">${H.esc(initials(name))}</span><span class="nm">${H.esc(String(name).split(/[\s@]/)[0])}</span></button></aside>` +
    '<aside class="sub" id="osub" aria-label="Module menu" hidden></aside>' +
    '<button class="scrim" id="oscrim" aria-label="Close menu" hidden></button>' +
    '<div class="col"><div class="topbar">' +
    `<button class="ib" id="tbMenu" aria-label="Menu">${H.icon(I.menu)}</button>` +
    `<button class="ib" id="tbBack" aria-label="Back" hidden>${H.icon(I.back)}</button>` +
    '<div class="crumbs" id="crumbs"></div>' +
    '<div class="tools">' +
    `<button class="ib" id="tbRefresh" aria-label="Refresh" title="Refresh">${H.icon(I.refresh)}</button>` +
    `<button class="ib" id="tbOut" aria-label="Sign out" title="Sign out">${H.icon(I.out)}</button></div></div>` +
    '<main class="main" id="main"></main>' +
    `<div class="status"><span>Signed in as ${H.esc(name)} · ${H.esc(H.ROLE_NAME[H.me.role] || H.me.role)} · authenticator app verified</span>` +
    `<span title="Code version and when it was last updated">Watchdog · v${b.version} · ${b.date} ${b.time}</span></div>` +
    "</div></div>";
  document.querySelectorAll(".mod").forEach((el) => { el.onclick = () => H.railClick(el.dataset.mod); });
  document.getElementById("tbMenu").onclick = () => H.toggleMenu();
  document.getElementById("oscrim").onclick = () => H.closeMenu();
  document.getElementById("tbBack").onclick = () => H.back();
  document.getElementById("tbRefresh").onclick = async () => { await H.targets(true); H.go(H.cur.screen, { push: false, ctx: H.cur.ctx }); H.toast("Refreshed"); };
  document.getElementById("tbOut").onclick = async () => {
    const v = await H.sheet({ title: "Sign out?", html: `<label class="chk"><input type="checkbox" name="all"> Also sign out my other Watchdog sessions</label>`, ok: "Sign out", collect: (f) => ({ all: f.all.checked }) });
    if (v) H.signOut(v.all ? "global" : "local");
  };
  document.getElementById("meBtn").onclick = () => H.go("me");
};

H.railClick = (k) => {
  const m = H.MENU.find((x) => x.k === k);
  const items = modItems(m);
  if (items.length === 1) { H.closeMenu(true); H.go(items[0].s); return; }
  H.menuMod = k;
  if (H.pinned) { H.renderMenu(); H.go(items[0].s); return; }
  H.menuOpen = true; H.renderMenu();
};
H.toggleMenu = () => {
  const info = findItem(H.cur.screen);
  H.menuMod = info ? info.mod.k : H.menuMod;
  const m = H.MENU.find((x) => x.k === H.menuMod);
  if (!m || modItems(m).length < 2) return;
  H.menuOpen = !H.menuOpen; H.renderMenu();
};
H.closeMenu = (keepPin) => {
  H.menuOpen = false;
  if (!keepPin && H.pinned) { H.pinned = false; try { localStorage.setItem("wd.pinned", "0"); } catch {} }
  H.renderMenu();
};
H.menuSecs = (() => { try { return JSON.parse(localStorage.getItem("wd.menu.open") || "{}") || {}; } catch { return {}; } })();
const secOpen = (key) => (key in H.menuSecs ? H.menuSecs[key] : key === H.cur.mod + "|" + (H.cur.sec || ""));
H.renderMenu = () => {
  const sub = document.getElementById("osub"), scrim = document.getElementById("oscrim");
  const m = H.MENU.find((x) => x.k === H.menuMod);
  const show = m && modItems(m).length > 1 && (H.menuOpen || H.pinned);
  sub.hidden = !show; scrim.hidden = !(show && !H.pinned);
  sub.className = "sub " + (H.pinned ? "pinned" : "over");
  if (!show) return;
  sub.innerHTML = `<div class="subhd"><h2>${H.esc(m.n)}</h2>` +
    `<button class="ib${H.pinned ? " on" : ""}" id="subPin" aria-label="Keep menu open" title="Keep this menu open">${H.icon(I.pin)}</button>` +
    `<button class="ib" id="subClose" aria-label="Close menu">${H.icon(I.close)}</button></div>` +
    '<div class="subbd">' + m.secs.map((s) => {
      const key = m.k + "|" + s.h, open = !s.h || secOpen(key);
      return `<div class="sec${open ? " open" : ""}">` + (s.h ? `<button class="sech" data-k="${H.esc(key)}" aria-expanded="${open}"><span>${H.esc(s.h)}</span>${H.icon(I.chev)}</button>` : "") + '<div class="secit">' +
      s.items.map((it) => `<button class="item${it.s === H.cur.screen ? " on" : ""}" data-s="${it.s}">${H.esc(it.n)}` +
        (!allowed(it.s) ? `<span class="lk" title="Your role cannot open this">${H.icon(I.lock)}</span>` : it.d && !H.SCREENS[it.s] ? '<span class="lk">soon</span>' : "") + "</button>").join("") +
      "</div></div>";
    }).join("") + "</div>";
  sub.querySelectorAll(".item").forEach((el) => { el.onclick = () => { if (!H.pinned) H.menuOpen = false; H.go(el.dataset.s); }; });
  sub.querySelectorAll(".sech").forEach((b) => {
    b.onclick = () => {
      const open = !b.parentNode.classList.contains("open");
      b.parentNode.classList.toggle("open", open); b.setAttribute("aria-expanded", open);
      H.menuSecs[b.dataset.k] = open;
      try { localStorage.setItem("wd.menu.open", JSON.stringify(H.menuSecs)); } catch {}
    };
  });
  document.getElementById("subPin").onclick = () => {
    H.pinned = !H.pinned;
    try { localStorage.setItem("wd.pinned", H.pinned ? "1" : "0"); } catch {}
    H.menuOpen = true; H.renderMenu();
  };
  document.getElementById("subClose").onclick = () => H.closeMenu();
};

H.go = (screen, o = {}) => {
  if (o.push !== false && H.cur.screen && !(H.cur.screen === screen && H.cur.ctx === o.ctx)) {
    H.stack.push({ screen: H.cur.screen, ctx: H.cur.ctx });
    if (H.stack.length > 30) H.stack.shift();
  }
  const parent = o.parent || H.PARENT[screen];
  const info = findItem(screen) || (parent && findItem(parent)) || { mod: H.MENU[0], sec: "", item: null };
  if (!findItem(screen) && parent) info.item = null;
  H.cur = { screen, ctx: o.ctx, mod: info.mod.k, sec: info.sec || "" };
  H.menuMod = info.mod.k;
  if (H.menuSecs[info.mod.k + "|" + H.cur.sec] === false) delete H.menuSecs[info.mod.k + "|" + H.cur.sec];
  document.querySelectorAll(".mod").forEach((el) => el.classList.toggle("on", el.dataset.mod === info.mod.k));
  document.getElementById("tbBack").hidden = !H.stack.length;
  H.renderMenu();
  const page = o.crumb || (info.item ? info.item.n : screen === "me" ? "My account" : screen);
  document.getElementById("crumbs").innerHTML =
    `<button class="c1" id="crMod">${H.esc(info.mod.n)}</button>` +
    (info.sec ? `<span class="sep">▸</span><span>${H.esc(info.sec)}</span>` : "") +
    (info.mod.k === "home" && screen === "home" ? "" : `<span class="sep">▸</span><span class="cur">${H.esc(page)}</span>`);
  document.getElementById("crMod").onclick = () => H.toggleMenu();
  try { history.replaceState(null, "", screen === "home" ? location.pathname : `#${screen}`); } catch {}
  const main = document.getElementById("main");
  window.scrollTo(0, 0);
  const tok = ++H.token;
  const ctx = { stale: () => tok !== H.token, ctx: o.ctx, item: info.item };
  const fn = H.SCREENS[screen];
  if (!allowed(screen)) {
    main.innerHTML = `<div class="lock"><div class="ring">${H.icon(I.lock)}</div><h1>${H.esc(info.item ? info.item.n : "Locked")}</h1>` +
      `<p class="sub-t">Your Watchdog role (${H.esc(H.ROLE_NAME[H.me.role])}) cannot open this screen. A Watchdog admin can change your role in Admin › Users.</p></div>`;
    return;
  }
  if (!fn) {
    main.innerHTML = H.title(info.item ? info.item.n : "Not built yet") + '<p><span class="tag t-mute">Planned screen</span></p>' +
      (info.item?.d ? `<p class="sub-t">${H.esc(info.item.d)}</p>` : "");
    return;
  }
  Promise.resolve().then(() => fn(main, ctx)).catch((e) => H.failed(main, e));
};
H.back = () => { const p = H.stack.pop(); if (p) H.go(p.screen, { push: false, ctx: p.ctx }); };

// ================================================================== sign-in
const app = () => document.getElementById("app");
const card = (inner) => {
  app().innerHTML = `<div class="login"><div class="login-card"><div class="wd-login-brand"><img src="assets/watchdog-mark.svg" alt=""><div><b>NFG WATCHDOG</b><span>IT security and health</span></div></div>${inner}</div></div>`;
  return app().querySelector(".login-card");
};
const errLine = (c, t) => { const e = c.querySelector("[data-err]"); e.hidden = !t; e.textContent = t || ""; };

function loginScreen(msg) {
  const c = card(`<p class="sub-t">Sign in with your Watchdog account. This is not your NFG app login.</p>` +
    (msg ? `<div class="banner">${H.esc(msg)}</div>` : "") +
    `<form data-f class="wd-stack"><label class="fld">Email<input name="email" type="email" autocomplete="username" required></label>` +
    `<label class="fld">Password<input name="pw" type="password" autocomplete="current-password" required></label>` +
    `<p class="dlg-err" data-err hidden></p><button class="btn pri wide" type="submit">Sign in</button></form>` +
    `<button class="linkbtn" data-forgot type="button">Forgot your password?</button>`);
  const f = c.querySelector("[data-f]");
  f.email.focus();
  f.onsubmit = async (e) => {
    e.preventDefault(); errLine(c, "");
    const b = f.querySelector("button"); b.disabled = true;
    const { error } = await sb.auth.signInWithPassword({ email: f.email.value.trim().toLowerCase(), password: f.pw.value });
    b.disabled = false;
    if (error) { errLine(c, error.message === "Invalid login credentials" ? "That email and password do not match." : error.message); return; }
    gate();
  };
  c.querySelector("[data-forgot]").onclick = async () => {
    const email = f.email.value.trim().toLowerCase();
    if (!email) { errLine(c, "Type your email first, then click Forgot your password."); return; }
    await sb.auth.resetPasswordForEmail(email, { redirectTo: location.origin + location.pathname });
    loginScreen("If that address has a Watchdog account, a reset link is on its way. You will still need your authenticator app.");
  };
}

async function mfaEnrol() {
  const { data: fl } = await sb.auth.mfa.listFactors();
  for (const f of (fl?.all ?? []).filter((x) => x.status !== "verified")) await sb.auth.mfa.unenroll({ factorId: f.id });
  const { data, error } = await sb.auth.mfa.enroll({ factorType: "totp", issuer: "NFG Watchdog", friendlyName: `Watchdog ${new Date().toISOString().slice(0, 16)}` });
  if (error) { loginScreen(error.message); return; }
  const c = card(`<h2>Set up your authenticator app</h2><p class="sub-t">Watchdog needs a code from an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…) every time you sign in. Scan this code with the app.</p>` +
    `<img class="wd-qr" src="${H.esc(data.totp.qr_code)}" alt="QR code for your authenticator app">` +
    `<details><summary class="sub-t">Can't scan it?</summary><p class="mono" style="overflow-wrap:anywhere">${H.esc(data.totp.secret)}</p></details>` +
    `<form data-f class="wd-stack"><label class="fld">6-digit code from the app<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>` +
    `<p class="dlg-err" data-err hidden></p><button class="btn pri wide" type="submit">Verify and continue</button></form><button class="linkbtn" data-out type="button">Cancel and sign out</button>`);
  const f = c.querySelector("[data-f]"); f.code.focus();
  c.querySelector("[data-out]").onclick = () => H.signOut("local");
  f.onsubmit = async (e) => {
    e.preventDefault(); errLine(c, "");
    const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: data.id, code: f.code.value.trim() });
    if (error) { errLine(c, "That code did not work. Check the time on your phone and try the next code."); f.code.select(); return; }
    gate();
  };
}

async function mfaChallenge() {
  const { data: fl } = await sb.auth.mfa.listFactors();
  const factor = (fl?.totp ?? []).find((x) => x.status === "verified");
  if (!factor) return mfaEnrol();
  const c = card(`<h2>Authenticator code</h2><p class="sub-t">Open your authenticator app and type the 6-digit code for NFG Watchdog.</p>` +
    `<form data-f class="wd-stack"><label class="fld">Code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>` +
    `<p class="dlg-err" data-err hidden></p><button class="btn pri wide" type="submit">Continue</button></form><button class="linkbtn" data-out type="button">Use a different account</button>`);
  const f = c.querySelector("[data-f]"); f.code.focus();
  c.querySelector("[data-out]").onclick = () => H.signOut("local");
  f.onsubmit = async (e) => {
    e.preventDefault(); errLine(c, "");
    const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: factor.id, code: f.code.value.trim() });
    if (error) { errLine(c, "That code did not work. Try the next one."); f.code.select(); return; }
    gate();
  };
}

function newPassword() {
  const c = card(`<h2>Choose a new password</h2><p class="sub-t">At least 14 characters. A passphrase of four or more words works well.</p>` +
    `<form data-f class="wd-stack"><label class="fld">New password<input name="pw" type="password" autocomplete="new-password" minlength="14" required></label>` +
    `<label class="fld">Same again<input name="pw2" type="password" autocomplete="new-password" minlength="14" required></label>` +
    `<p class="dlg-err" data-err hidden></p><button class="btn pri wide" type="submit">Save password</button></form>`);
  const f = c.querySelector("[data-f]"); f.pw.focus();
  f.onsubmit = async (e) => {
    e.preventDefault(); errLine(c, "");
    if (f.pw.value !== f.pw2.value) { errLine(c, "The two passwords are different."); return; }
    const { error } = await sb.auth.updateUser({ password: f.pw.value });
    if (error) { errLine(c, error.message); return; }
    H.recovering = false;
    try { sessionStorage.removeItem("wd.recover"); } catch {}
    H.toast("Password changed");
    gate();
  };
}

function notListed(me) {
  card(`<h2>No access to Watchdog</h2><p class="sub-t">${H.esc(me?.email || "This account")} can sign in, but is ${me?.listed ? "switched off" : "not on the Watchdog list"}. Ask a Watchdog admin to add you in Admin › Users.</p>` +
    `<button class="btn wide" data-out type="button">Sign out</button>`).querySelector("[data-out]").onclick = () => H.signOut("local");
}

H.signOut = async (scope = "local") => {
  try { await sb.rpc("wd_touch", { p_action: scope === "global" ? "sign-out (all sessions)" : "sign-out" }); } catch {}
  await sb.auth.signOut({ scope });
  location.hash = "";
  loginScreen(scope === "global" ? "Signed out of every Watchdog session." : "Signed out.");
};

// signed out after IDLE_MINUTES without a click, key or scroll
let idleT;
const idle = () => { clearTimeout(idleT); idleT = setTimeout(() => { if (H.me) { H.me = null; H.signOut("local"); } }, IDLE_MINUTES * 60000); };
["click", "keydown", "scroll", "touchstart"].forEach((ev) => document.addEventListener(ev, idle, { passive: true }));

sb.auth.onAuthStateChange((ev) => {
  if (ev === "PASSWORD_RECOVERY") { H.recovering = true; try { sessionStorage.setItem("wd.recover", "1"); } catch {} setTimeout(gate, 0); }
  if (ev === "SIGNED_OUT" && H.me) { H.me = null; loginScreen("Your session ended. Sign in again."); }
});

let started = false;
async function gate() {
  const { data: { session } } = await sb.auth.getSession();
  if (!session) return loginScreen();
  const { data: aal } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
  if (aal?.currentLevel !== "aal2") return aal?.nextLevel === "aal2" ? mfaChallenge() : mfaEnrol();
  try { H.recovering = H.recovering || sessionStorage.getItem("wd.recover") === "1"; } catch {}
  if (H.recovering) return newPassword();
  const { data: me, error } = await sb.rpc("wd_me");
  if (error) { loginScreen(error.message); return; }
  if (!me?.listed || !me.active) return notListed(me);
  H.me = me;
  sb.rpc("wd_touch", { p_action: "sign-in" }).then(() => {}, () => {});
  idle();
  await H.targets(true);
  if (started) { H.shell(); H.go("home", { push: false }); return; }
  started = true;
  H.shell();
  const hash = location.hash.slice(1);
  const m = hash.match(/^finding=(\d+)$/);
  if (m) H.go("findings", { push: false, ctx: { open: Number(m[1]) } });
  else H.go(hash && H.SCREENS[hash] ? hash : "home", { push: false });
}

H.start = () => {
  try { H.pinned = localStorage.getItem("wd.pinned") === "1"; } catch { H.pinned = false; }
  gate();
};
