// NFG Guard › Performance: the slowest database queries per project (pg_stat_statements, taken hourly).
import { H } from "./watchdog.js";
const esc = H.esc;

H.screen("queries", async (main, ctx) => {
  await H.targets();
  const st = { target: "", sort: "total" };
  const draw = async () => {
    H.loading(main);
    const rows = await H.q((() => {
      let x = H.db.from("wd_query_stat").select("observed_at, target_id, queryid, role_name, calls, total_ms, mean_ms, max_ms, rows_out, query").gte("observed_at", new Date(Date.now() - 3 * 3600e3).toISOString()).order("observed_at", { ascending: false }).limit(2000);
      if (st.target) x = x.eq("target_id", st.target);
      return x;
    })());
    if (ctx.stale()) return;
    const latest = new Map();
    for (const r of rows) if (!latest.has(r.target_id)) latest.set(r.target_id, r.observed_at);
    const now = rows.filter((r) => latest.get(r.target_id) === r.observed_at);
    const slow = Number((await H.q(H.db.from("wd_setting").select("value").eq("key", "slow_query_ms").single())).value || 500);
    main.innerHTML = H.title("Slow queries", "The 25 queries that use the most database time in each project, since its statistics were last reset. Average time is what each run costs; total time is what hurts the database most.") +
      `<div class="filters"><label class="fld grow">Project<select data-t><option value="">All projects</option>${[...H._targets.values()].filter((x) => x.kind === "supabase" && !x.meta?.org).map((x) => `<option value="${esc(x.id)}"${st.target === x.id ? " selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label></div>` +
      H.table([
        { h: "Project", w: "1.2fr", f: (r) => esc(H.tname(r.target_id)) },
        { h: "Query", w: "3.2fr", f: (r) => `<span class="mono wd-q">${esc(String(r.query).replace(/\s+/g, " ").slice(0, 220))}</span>`, sv: (r) => r.query },
        { h: "Avg ms", w: "90px", cls: "n", f: (r) => Number(r.mean_ms) > slow ? `<b class="bad">${H.n1(r.mean_ms)}</b>` : H.n1(r.mean_ms), sv: (r) => Number(r.mean_ms) },
        { h: "Runs", w: "90px", cls: "n", f: (r) => H.u0(r.calls), sv: (r) => Number(r.calls) },
        { h: "Total s", w: "90px", cls: "n", f: (r) => H.n1(Number(r.total_ms) / 1000), sv: (r) => Number(r.total_ms) },
        { h: "Max ms", w: "90px", cls: "n", f: (r) => H.u0(r.max_ms), sv: (r) => Number(r.max_ms) },
        { h: "Rows", w: "90px", cls: "n", f: (r) => H.u0(r.rows_out), sv: (r) => Number(r.rows_out) },
        { h: "Role", w: "110px", f: (r) => `<span class="mono">${esc(r.role_name)}</span>` },
      ], now, { search: true, min: 1150, sort: { h: "Total s", dir: -1 }, rowAttrs: () => "", empty: "No query statistics yet. They are taken by the hourly Supabase check." });
    main.querySelector("[data-t]").onchange = (e) => { st.target = e.target.value; draw(); };
    H.rowClick(main, async (r) => {
      const hist = await H.q(H.db.from("wd_query_stat").select("observed_at, calls, mean_ms").eq("target_id", r.target_id).eq("queryid", r.queryid).order("observed_at").limit(2160));
      await H.sheet({ title: "Query", wide: true, ok: null,
        html: `<dl class="kv"><dt>Project</dt><dd>${esc(H.tname(r.target_id))}</dd><dt>Role</dt><dd class="mono">${esc(r.role_name)}</dd><dt>Average</dt><dd>${H.n1(r.mean_ms)} ms over ${H.u0(r.calls)} runs</dd><dt>Slowest</dt><dd>${H.u0(r.max_ms)} ms</dd></dl>` +
          `<pre class="wd-pre">${esc(r.query)}</pre>` +
          (hist.length > 1 ? `<h3>Average time, hour by hour</h3>` + H.columns(hist.map((h) => ({ y: h.mean_ms, label: `${H.dateTime(h.observed_at)}: ${H.n1(h.mean_ms)} ms avg, ${H.u0(h.calls)} runs` })), { aria: "Average ms per snapshot", foot: [H.dateTime(hist[0].observed_at), H.dateTime(hist.at(-1).observed_at)] }) : "") +
          `<p class="sub-t">To fix: run EXPLAIN ANALYZE on it in the SQL editor; look for sequential scans on big tables and add an index on the columns in WHERE and JOIN.</p>` });
    });
  };
  await draw();
});
