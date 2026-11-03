// NFG Guard collector: Exchange Online mailboxes (daily). Forwarding (the mailbox setting and inbox rules), who else can
// open, read or send as each mailbox, and when it was last used.
// Read-only. The Guard Entra app (ENTRA_* secrets) needs the application permission Exchange.ManageAsApp
// (Office 365 Exchange Online API, admin consent) and the Entra role Global Reader on its service principal.
// Calls go to the same admin REST endpoint the ExchangeOnlineManagement PowerShell module uses (InvokeCommand): the
// documented Exchange Admin API v2 does not cover Get-MailboxPermission, Get-RecipientPermission or Get-InboxRule yet.
import { db, q, fp, nowIso, pool, getJson, setConnector, settings, syncFindings, insertMany, type Finding, type Sev } from "./lib.ts";
import { graph } from "./entra.ts";

const TENANT = Deno.env.get("ENTRA_TENANT_ID") ?? "";
const CLIENT = Deno.env.get("ENTRA_CLIENT_ID") ?? "";
const SECRET = Deno.env.get("ENTRA_CLIENT_SECRET") ?? "";
export const exchangeReady = () => !!(TENANT && CLIENT && SECRET);
const TGT = () => `entra:${TENANT}`;
const BUDGET_MS = 300_000;   // stop starting new mailboxes after 5 minutes; the rest are done first on the next run

let tok: { v: string; exp: number } | null = null;
async function exoToken() {
  if (tok && tok.exp > Date.now() + 60_000) return tok.v;
  const r = await getJson(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLIENT, client_secret: SECRET, grant_type: "client_credentials", scope: "https://outlook.office365.com/.default" }),
  });
  tok = { v: r.access_token, exp: Date.now() + Number(r.expires_in) * 1000 };
  return tok.v;
}

let ANCHOR = "";
async function exo(cmdlet: string, params: Record<string, unknown> = {}): Promise<any[]> {
  const out: any[] = [];
  let url: string | null = `https://outlook.office365.com/adminapi/beta/${TENANT}/InvokeCommand`;
  const body = JSON.stringify({ CmdletInput: { CmdletName: cmdlet, Parameters: params } });
  while (url) {
    const r: any = await getJson(url, { method: "POST", body, headers: { Authorization: `Bearer ${await exoToken()}`, "content-type": "application/json",
      Accept: "application/json", "X-AnchorMailbox": ANCHOR, "X-ResponseFormat": "json", Prefer: "odata.maxpagesize=1000" } });
    out.push(...(Array.isArray(r?.value) ? r.value : r ? [r] : []));
    url = r?.["@odata.nextLink"] ?? null;
  }
  return out;
}

// ---------- small parsers (the REST output mixes strings, arrays and /Date(...)/ values)
const list = (v: unknown): string[] => v == null ? [] : Array.isArray(v) ? v.map(String) : String(v).split(/,\s*/).filter(Boolean);   // rights: "FullAccess, ReadPermission"
const arr = (v: unknown): string[] => v == null ? [] : Array.isArray(v) ? v.map(String) : [String(v)];                                  // names may contain commas
const when = (v: unknown): string | null => {
  if (!v) return null;
  const m = /Date\((-?\d+)/.exec(String(v));
  const t = m ? Number(m[1]) : Date.parse(String(v));
  return Number.isFinite(t) && t > 0 ? new Date(t).toISOString() : null;
};
const bytesOf = (v: any): number | null => {
  const s = typeof v === "object" && v ? (v.Value ?? JSON.stringify(v)) : String(v ?? "");
  const m = /\(([\d,]+) bytes\)/.exec(String(s));
  return m ? Number(m[1].replace(/,/g, "")) : null;
};
const addrOf = (s: string): string | null => {
  const m = /smtp:([^\]\s"]+)/i.exec(s) ?? /([^\s<>"\[\]:]+@[^\s<>"\[\]]+)/.exec(s);
  return m ? m[1].toLowerCase() : null;
};
const userOf = (u: any): string => typeof u === "string" ? u : u?.DisplayName ?? u?.RecipientPrincipal?.DisplayName ?? u?.UserType?.Value ?? JSON.stringify(u ?? "");
const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

export async function runMail() {
  if (!exchangeReady()) { await setConnector("exchange", { ok: false, note: "ENTRA_* secrets not set" }); return { skipped: "Entra not set up" }; }
  const started = Date.now();
  const s = await settings();
  const idleDays = Number(s.mailbox_idle_days ?? 90);
  const org = await graph(`/v1.0/organization?$select=id,verifiedDomains`);
  const initial = (org?.value?.[0]?.verifiedDomains ?? []).find((d: any) => d.isInitial)?.name;
  ANCHOR = `UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@${initial}`;

  let boxes: any[];
  try { boxes = await exo("Get-Mailbox", { ResultSize: "Unlimited" }); }
  catch (e: any) {
    const note = e.status === 401 || e.status === 403
      ? "Guard's Entra app needs Exchange.ManageAsApp (admin consent) and the Global Reader role"
      : `Exchange: ${String(e.message).slice(0, 200)}`;
    await setConnector("exchange", { ok: false, note });
    throw new Error(note);
  }
  const errors: string[] = [];
  const step = async <T>(n: string, fn: () => Promise<T>, dflt: T): Promise<T> => { try { return await fn(); } catch (e) { errors.push(`${n}: ${(e as Error).message.slice(0, 200)}`); return dflt; } };
  const domains = new Set<string>((await step("accepted domains", () => exo("Get-AcceptedDomain"), [] as any[])).map((d) => String(d.DomainName ?? d.Name).toLowerCase()));
  const spam = await step("outbound policy", () => exo("Get-HostedOutboundSpamFilterPolicy"), [] as any[]);
  const autoFwd = String((spam.find((p) => p.IsDefault) ?? spam[0])?.AutoForwardingMode ?? "Automatic");   // Automatic = Microsoft blocks external auto-forwarding
  const sendAs = await step("send as", () => exo("Get-RecipientPermission", { ResultSize: "Unlimited", AccessRights: "SendAs" }), [] as any[]);

  // ---- the mailbox list (cheap, every mailbox every run)
  const prev: any[] = await q(db.from("wd_mailbox").select("*"));
  const old = new Map(prev.map((r) => [r.id, r]));
  const byKey = new Map<string, string>();
  const base = boxes.filter((b) => !b.IsInactiveMailbox).map((b) => {
    const id = String(b.ExchangeGuid ?? b.Guid ?? b.ExternalDirectoryObjectId);
    for (const k of [b.Identity, b.Name, b.Alias, b.DisplayName, b.PrimarySmtpAddress, b.UserPrincipalName, b.Id]) if (k) byKey.set(String(k).toLowerCase(), id);
    return { id, upn: b.UserPrincipalName ?? null, smtp: String(b.PrimarySmtpAddress ?? "").toLowerCase() || null, display_name: b.DisplayName ?? b.Name,
      kind: String(b.RecipientTypeDetails ?? "UserMailbox"), hidden: !!b.HiddenFromAddressListsEnabled, created_src: when(b.WhenMailboxCreated ?? b.WhenCreated),
      forward_smtp: b.ForwardingSmtpAddress ? addrOf(String(b.ForwardingSmtpAddress)) : null, forward_to: b.ForwardingAddress ? String(b.ForwardingAddress) : null,
      deliver_and_forward: b.DeliverToMailboxAndForward ?? null, send_on_behalf: arr(b.GrantSendOnBehalfTo), send_as: [] as string[],
      last_seen: nowIso(), active: true };
  });
  const rowById = new Map(base.map((r) => [r.id, r]));
  for (const p of sendAs) {
    const who = String(p.Trustee ?? "");
    if (p.IsInherited || !who || /^NT AUTHORITY\\SELF$/i.test(who) || /^S-1-5-/.test(who)) continue;
    const r = rowById.get(byKey.get(String(p.Identity ?? "").toLowerCase()) ?? "");
    if (r && !r.send_as.includes(who)) r.send_as.push(who);
  }
  await insertMany("wd_mailbox", base, { onConflict: "id" });
  const ids = base.map((r) => r.id);
  if (ids.length) await q(db.from("wd_mailbox").update({ active: false }).eq("active", true).not("id", "in", `(${ids.map((x) => `"${x}"`).join(",")})`));

  // ---- per mailbox (four calls each): oldest-checked first, within the time budget
  const order = [...base].sort((a, b) => String(old.get(a.id)?.checked_at ?? "").localeCompare(String(old.get(b.id)?.checked_at ?? "")));
  let done = 0, skipped = 0;
  const detail: any[] = [];
  await pool(order, 8, async (b) => {
    if (Date.now() - started > BUDGET_MS) { skipped++; return; }
    const id = b.smtp || b.upn;
    const [perms, inbox, rules, stats] = await Promise.all([
      step(`permissions ${id}`, () => exo("Get-MailboxPermission", { Identity: id }), null as any),
      step(`inbox ${id}`, () => exo("Get-MailboxFolderPermission", { Identity: `${id}:\\Inbox` }), [] as any[]),
      step(`rules ${id}`, () => exo("Get-InboxRule", { Mailbox: id }), null as any),
      step(`statistics ${id}`, () => exo("Get-MailboxStatistics", { Identity: id }), null as any),
    ]);
    // every row carries the same columns (a bulk upsert nulls missing ones); a call that failed keeps the last known value
    const o = old.get(b.id) ?? {};
    const row: any = { id: b.id, checked_at: nowIso(), full_access: o.full_access ?? [], inbox_access: o.inbox_access ?? [], forward_rules: o.forward_rules ?? [],
      last_action: o.last_action ?? null, last_logon: o.last_logon ?? null, items: o.items ?? null, size_bytes: o.size_bytes ?? null };
    if (perms) row.full_access = perms.filter((p: any) => !p.IsInherited && !p.Deny && !/^NT AUTHORITY\\SELF$/i.test(String(p.User)) && !/^S-1-5-/.test(String(p.User)))
      .map((p: any) => ({ who: String(p.User), rights: list(p.AccessRights) })).filter((p: any) => p.rights.some((r: string) => r !== "ReadPermission"));
    if (inbox.length) row.inbox_access = inbox.map((p: any) => ({ who: userOf(p.User), rights: list(p.AccessRights) }))
      .filter((p: any) => p.rights.length && !p.rights.every((r: string) => r === "None") && !/^anonymous$/i.test(p.who))
      .map((p: any) => (/^default$/i.test(p.who) ? { ...p, who: "Everyone in NFG (Default)" } : p));
    if (rules) row.forward_rules = rules.map((r: any) => ({ name: r.Name, enabled: r.Enabled !== false,
      to: [...arr(r.ForwardTo), ...arr(r.ForwardAsAttachmentTo), ...arr(r.RedirectTo)].map((x) => addrOf(x) ?? (/\[EX:/i.test(x) ? `${x.replace(/\s*\[EX:.*$/i, "").replace(/"/g, "")} (internal)` : x)),
      how: r.RedirectTo ? "redirect" : r.ForwardAsAttachmentTo ? "forward as attachment" : "forward" })).filter((r: any) => r.to.length);
    const st = Array.isArray(stats) ? stats[0] : null;
    if (st) Object.assign(row, { last_action: when(st.LastUserActionTime), last_logon: when(st.LastLogonTime), items: st.ItemCount ?? null, size_bytes: bytesOf(st.TotalItemSize) });
    detail.push(row); done++;
  });
  await insertMany("wd_mailbox", detail, { onConflict: "id" });

  // ---- external forwarding, findings, changes (over the whole stored set, so mailboxes not reached this run keep theirs)
  const rows: any[] = await q(db.from("wd_mailbox").select("*").eq("active", true));
  const external = (a: string | null) => !!a && a.includes("@") && domains.size > 0 && !domains.has(a.split("@")[1]);
  const fx: any[] = [];
  for (const r of rows) {
    const ext = [...new Set([r.forward_smtp, ...(r.forward_rules ?? []).filter((x: any) => x.enabled).flatMap((x: any) => x.to)].filter(external))];
    if (!same(ext, r.forward_external)) fx.push({ id: r.id, forward_external: ext });
    r.forward_external = ext;
  }
  if (fx.length) await insertMany("wd_mailbox", fx, { onConflict: "id" });

  const tgt = TGT(), F: Finding[] = [], A: Finding[] = [], changes: any[] = [];
  const day = nowIso().slice(0, 10);
  const blocked = autoFwd !== "On";
  const name = (r: any) => `${r.display_name} (${r.smtp ?? r.upn})`;
  for (const r of rows) {
    if (r.forward_external?.length) F.push({ fingerprint: fp("mx", r.id, "fwd.external", ...r.forward_external.slice().sort()), source: "entra", target_id: tgt, check_code: "mail.forward_external",
      category: "data", severity: (blocked ? "medium" : "high") as Sev, title: `${r.display_name} forwards mail outside NFG to ${r.forward_external.join(", ")}`,
      detail: `${name(r)} sends a copy of incoming mail to ${r.forward_external.join(", ")}${r.forward_smtp && external(r.forward_smtp) ? " (mailbox forwarding set by an admin)" : " (an inbox rule)"}. ` +
        (blocked ? "The outbound spam policy blocks automatic forwarding to outside addresses, so this probably fails, but it is set up." : "The outbound spam policy allows automatic forwarding to outside addresses, so this mail is leaving."),
      remediation: "Check with the person. If it is not needed, remove the forwarding (Exchange admin centre › Mailboxes › Mail flow settings) or the inbox rule.", meta: { mailbox: r.smtp, to: r.forward_external } });
    const open = (r.inbox_access ?? []).find((a: any) => /Default/.test(a.who));
    if (open) F.push({ fingerprint: fp("mx", r.id, "inbox.default"), source: "entra", target_id: tgt, check_code: "mail.inbox_open", category: "access", severity: "medium",
      title: `Everyone in NFG can open ${r.display_name}'s inbox`, detail: `${name(r)}: the Inbox folder gives "Default" (every person in the organisation) ${open.rights.join(", ")}.`,
      remediation: "Outlook › right-click Inbox › Properties › Permissions: set Default to None, and give named people access instead.", meta: { mailbox: r.smtp, rights: open.rights } });
  }
  const cut = Date.now() - idleDays * 86400e3;
  const idle = rows.filter((r) => r.kind === "UserMailbox" && r.checked_at && (!r.last_action || Date.parse(r.last_action) < cut) && !(r.created_src && Date.parse(r.created_src) > cut));
  if (idle.length) F.push({ fingerprint: fp("mx", "idle"), source: "entra", target_id: tgt, check_code: "mail.idle", category: "access", severity: "low",
    title: `${idle.length} user mailbox${idle.length === 1 ? "" : "es"} not used in ${idleDays} days`, detail: idle.slice(0, 30).map((r) => r.smtp ?? r.upn).join(", ") + (idle.length > 30 ? ", ..." : ""),
    remediation: "Leavers: block sign-in and convert to a shared mailbox (frees the licence) or remove. See Access › Mailboxes › Not in use.", meta: { n: idle.length } });

  // changes since the last run (only where Guard had looked before, so the first run does not flood)
  const fmtAccess = (r: any) => new Map<string, string[]>([
    ...(r.full_access ?? []).map((a: any) => [`${a.who}|full`, a.rights] as [string, string[]]),
    ...(r.inbox_access ?? []).map((a: any) => [`${a.who}|inbox`, a.rights] as [string, string[]]),
    ...(r.send_as ?? []).map((w: string) => [`${w}|sendas`, ["SendAs"]] as [string, string[]]),
    ...(r.send_on_behalf ?? []).map((w: string) => [`${w}|behalf`, ["SendOnBehalf"]] as [string, string[]]),
  ]);
  const LABEL: Record<string, string> = { full: "full access", inbox: "inbox access", sendas: "send as", behalf: "send on behalf" };
  for (const r of rows) {
    const o = old.get(r.id);
    if (!o || !o.checked_at) continue;
    const before = fmtAccess(o), after = fmtAccess(r);
    for (const [k, rights] of after) if (!before.has(k)) {
      const [who, kind] = k.split("|");
      changes.push({ target_id: tgt, kind: "mailbox", item: `${r.smtp}: ${who} (${LABEL[kind]})`, action: "added", detail: { rights } });
      A.push({ fingerprint: fp("mx", r.id, "act.access", k, day), source: "entra", target_id: tgt, check_code: "activity.mailbox_access", category: "activity",
        severity: kind === "full" || /Default/.test(who) ? "high" : "medium", title: `${who} was given ${LABEL[kind]} to ${r.display_name}`,
        detail: `${name(r)}: ${rights.join(", ")}. Seen by Guard's daily mailbox check.`, remediation: "Confirm it was asked for. If not, remove it in the Exchange admin centre (Mailboxes › Delegation).", meta: { mailbox: r.smtp, who, rights } });
    }
    for (const k of before.keys()) if (!after.has(k)) { const [who, kind] = k.split("|"); changes.push({ target_id: tgt, kind: "mailbox", item: `${r.smtp}: ${who} (${LABEL[kind]})`, action: "removed", detail: {} }); }
    const fwdNow = [r.forward_smtp, r.forward_to, ...(r.forward_rules ?? []).flatMap((x: any) => x.to)].filter(Boolean);
    const fwdThen = new Set([o.forward_smtp, o.forward_to, ...(o.forward_rules ?? []).flatMap((x: any) => x.to)].filter(Boolean));
    for (const a of fwdNow.filter((a) => !fwdThen.has(a))) {
      changes.push({ target_id: tgt, kind: "mailbox", item: `${r.smtp}: forwards to ${a}`, action: "added", detail: {} });
      A.push({ fingerprint: fp("mx", r.id, "act.forward", a, day), source: "entra", target_id: tgt, check_code: "activity.mailbox_forward", category: "activity",
        severity: external(a) ? "high" : "medium", title: `${r.display_name} now forwards mail to ${a}`, detail: `${name(r)}: new ${r.forward_smtp === a || r.forward_to === a ? "mailbox forwarding" : "inbox rule"}${external(a) ? ", to an outside address" : ""}.`,
        remediation: "Forwarding is a common step after a mailbox is taken over. Confirm with the person; if it was not them, remove it, reset their password and sign them out everywhere.", meta: { mailbox: r.smtp, to: a } });
    }
  }
  if (changes.length) await q(db.from("wd_change").insert(changes));

  const a = await syncFindings("entra:mail", F);
  const b = await syncFindings("entra:mail_activity", A, false);
  await setConnector("exchange", { ok: !errors.length || done > 0, mailboxes: rows.length, checked: done, waiting: skipped, auto_forwarding: autoFwd, domains: [...domains], errors: errors.length ? errors.slice(0, 10) : undefined });
  return { mailboxes: rows.length, checked: done, waiting: skipped, forwarding_external: rows.filter((r) => r.forward_external?.length).length, idle: idle.length, findings: F.length, activity: A.length, sync: a, activity_sync: b, errors: errors.slice(0, 20), seconds: Math.round((Date.now() - started) / 1000) };
}
