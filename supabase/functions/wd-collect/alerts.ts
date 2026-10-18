// NFG Watchdog collector: alerting. Open findings that match a rule become alerts (database function wd_alert_queue);
// this sends them: one digest per channel and recipient list, by email (Microsoft 365, the NFG Normandien – Mail app) and/or a Teams workflow webhook.
import { db, q, nowIso, settings, setConnector } from "./lib.ts";
import { sendMail, mailReady, MAIL_FROM } from "./mail.ts";

const TEAMS = Deno.env.get("WD_TEAMS_WEBHOOK") ?? "";
const PORTAL = Deno.env.get("WD_PORTAL_URL") ?? "https://watchdog.normandien.co.za";
const SEV_COLOUR: Record<string, string> = { critical: "#8f1d18", high: "#c2410c", medium: "#714200", low: "#1f4469", info: "#55585c" };
const esc = (s: unknown) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

function emailHtml(items: any[]) {
  const rows = items.map((a) => {
    const f = a.wd_finding || {};
    return `<tr><td style="padding:8px 10px;border-bottom:1px solid #e3e3e3;vertical-align:top"><span style="display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;background:${SEV_COLOUR[a.severity]};font-size:11px;font-weight:700;text-transform:uppercase">${esc(a.severity)}</span></td>` +
      `<td style="padding:8px 10px;border-bottom:1px solid #e3e3e3"><b>${esc(a.title)}</b><br><span style="color:#55585c">${esc(String(f.detail ?? "").slice(0, 400))}</span>` +
      (f.remediation ? `<br><span style="color:#000">What to do: ${esc(f.remediation)}</span>` : "") +
      `<br><a href="${PORTAL}/#finding=${a.finding_id}" style="color:#000">Open in Watchdog</a></td></tr>`;
  }).join("");
  return `<div style="font-family:Lato,Arial,sans-serif;font-size:14px;color:#000"><div style="background:#000;color:#F1B80E;padding:12px 16px;font-weight:900;letter-spacing:.16em">NFG WATCHDOG</div>` +
    `<p style="padding:12px 16px 0">${items.length} new ${items.length === 1 ? "issue needs" : "issues need"} a look.</p><table style="border-collapse:collapse;width:100%;max-width:760px">${rows}</table>` +
    `<p style="color:#55585c;font-size:12px;padding:12px 16px">Sent by NFG Watchdog. Change who gets these in Watchdog › Alerts › Rules.</p></div>`;
}

async function sendEmail(to: string[], subject: string, html: string) {
  const s = await settings();
  const from = String(s.alert_mailbox || "").trim() || MAIL_FROM;
  await sendMail(from, to, subject, html);
}
async function sendTeams(items: any[]) {
  if (!TEAMS) throw new Error("WD_TEAMS_WEBHOOK secret not set");
  const body = [{ type: "TextBlock", size: "Medium", weight: "Bolder", text: `NFG Watchdog: ${items.length} new issue${items.length === 1 ? "" : "s"}` },
    ...items.slice(0, 20).map((a) => ({ type: "TextBlock", wrap: true, text: `**${a.severity.toUpperCase()}** ${a.title}` }))];
  const r = await fetch(TEAMS, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "message", attachments: [{
    contentType: "application/vnd.microsoft.card.adaptive", content: { $schema: "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4", body,
      actions: [{ type: "Action.OpenUrl", title: "Open Watchdog", url: PORTAL }] } }] }) });
  if (!r.ok) throw new Error(`Teams ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

export async function deliverAlerts() {
  const queued = await q(db.rpc("wd_alert_queue"));
  const pending: any[] = await q(db.from("wd_alert").select("id, severity, title, channel, recipients, finding_id, wd_finding(detail, remediation, source, target_id)")
    .eq("delivered", false).gte("at", new Date(Date.now() - 24 * 3600e3).toISOString()).order("at").limit(200));
  if (!pending.length) return { queued, sent: 0 };
  const groups = new Map<string, any[]>();
  for (const a of pending) { const k = `${a.channel}|${(a.recipients ?? []).sort().join(",")}`; groups.set(k, [...(groups.get(k) ?? []), a]); }
  let sent = 0;
  const order = ["critical", "high", "medium", "low", "info"];
  for (const [k, items] of groups) {
    items.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    const [channel] = k.split("|");
    const errs: string[] = [];
    const top = items[0];
    const subject = `[Watchdog] ${top.severity.toUpperCase()}: ${top.title}${items.length > 1 ? ` (+${items.length - 1} more)` : ""}`;
    if (channel === "email" || channel === "both") { try { await sendEmail(items[0].recipients ?? [], subject, emailHtml(items)); } catch (e) { errs.push((e as Error).message); } }
    if (channel === "teams" || channel === "both") { try { await sendTeams(items); } catch (e) { errs.push((e as Error).message); } }
    const ok = !errs.length;
    await q(db.from("wd_alert").update(ok ? { delivered: true, delivered_at: nowIso(), delivery_error: null } : { delivery_error: errs.join("; ").slice(0, 500) }).in("id", items.map((i) => i.id)));
    if (ok) sent += items.length;
  }
  await setConnector("alerts", { ok: sent === pending.length, pending: pending.length - sent, teams: !!TEAMS, email: mailReady() });
  return { queued, sent, pending: pending.length };
}
