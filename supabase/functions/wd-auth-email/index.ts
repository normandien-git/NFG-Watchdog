// NFG Watchdog: Supabase Auth "Send Email" hook (edge function wd-auth-email on NFG-Watchdog, verify_jwt off).
// Supabase Auth calls this instead of SMTP for every sign-in email (password reset, invite, confirmations). We send it as
// noreply@normandien.co.za through Microsoft Graph with the existing "NFG Normandien – Mail" app, the same way Fleet and Tech send.
// Only Supabase Auth can call it: each request is signed with the hook secret (Standard Webhooks), checked below.
//
// Secrets: SEND_EMAIL_HOOK_SECRET (from Authentication › Hooks, "v1,whsec_…"), MAIL_CLIENT_ID, MAIL_CLIENT_SECRET,
//          MAIL_TENANT_ID (or ENTRA_TENANT_ID), optional MAIL_FROM (defaults to noreply@normandien.co.za).

const HOOK = (Deno.env.get("SEND_EMAIL_HOOK_SECRET") ?? "").replace(/^v1,/, "").replace(/^whsec_/, "");
const TENANT = Deno.env.get("MAIL_TENANT_ID") || Deno.env.get("ENTRA_TENANT_ID") || "";
const CLIENT = Deno.env.get("MAIL_CLIENT_ID") ?? "";
const SECRET = Deno.env.get("MAIL_CLIENT_SECRET") ?? "";
const FROM = (Deno.env.get("MAIL_FROM") || "noreply@normandien.co.za").trim();
const SB_URL = Deno.env.get("SUPABASE_URL")!;

const fail = (status: number, message: string) =>
  new Response(JSON.stringify({ error: { http_code: status, message } }), { status, headers: { "content-type": "application/json" } });
const esc = (s: unknown) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

// ---------- Standard Webhooks signature ----------
const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function verified(req: Request, body: string): Promise<boolean> {
  const id = req.headers.get("webhook-id"), ts = req.headers.get("webhook-timestamp"), sig = req.headers.get("webhook-signature");
  if (!HOOK || !id || !ts || !sig) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;                       // replay window: 5 minutes
  const key = await crypto.subtle.importKey("raw", b64(HOOK), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${id}.${ts}.${body}`)));
  const want = btoa(String.fromCharCode(...mac));
  return sig.split(" ").some((p) => {
    const v = p.split(",")[1] ?? "";
    if (v.length !== want.length) return false;
    let d = 0; for (let i = 0; i < v.length; i++) d |= v.charCodeAt(i) ^ want.charCodeAt(i);   // constant time
    return d === 0;
  });
}

// ---------- Microsoft Graph ----------
async function sendMail(to: string, subject: string, html: string) {
  if (!TENANT || !CLIENT || !SECRET) throw new Error("MAIL_TENANT_ID / MAIL_CLIENT_ID / MAIL_CLIENT_SECRET not set");
  const t = await fetch(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLIENT, client_secret: SECRET, grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" }),
  });
  if (!t.ok) throw new Error(`Graph token ${t.status}: ${(await t.text()).slice(0, 200)}`);
  const { access_token } = await t.json();
  const r = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(FROM)}/sendMail`, {
    method: "POST", headers: { Authorization: `Bearer ${access_token}`, "content-type": "application/json" },
    body: JSON.stringify({ message: { subject, body: { contentType: "HTML", content: html }, toRecipients: [{ emailAddress: { address: to } }] }, saveToSentItems: false }),
  });
  if (!r.ok) throw new Error(`Graph sendMail ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

// ---------- the emails ----------
const COPY: Record<string, { subject: string; lead: string; button: string }> = {
  recovery: { subject: "Reset your NFG Watchdog password", lead: "Someone asked to reset the password for your NFG Watchdog account. If it was you, choose a new password with the button below.", button: "Choose a new password" },
  invite: { subject: "Your NFG Watchdog account", lead: "An NFG Watchdog account has been set up for you. Open it with the button below.", button: "Open NFG Watchdog" },
  magiclink: { subject: "Your NFG Watchdog sign-in link", lead: "Use the button below to sign in to NFG Watchdog.", button: "Sign in" },
  signup: { subject: "Confirm your NFG Watchdog email", lead: "Confirm this email address for your NFG Watchdog account.", button: "Confirm my email" },
  email_change: { subject: "Confirm your new NFG Watchdog email", lead: "Confirm the change of email address on your NFG Watchdog account.", button: "Confirm the change" },
  email: { subject: "Your NFG Watchdog sign-in link", lead: "Use the button below to sign in to NFG Watchdog.", button: "Sign in" },
};

function page(lead: string, inner: string) {
  return `<div style="font-family:Lato,Arial,sans-serif;font-size:14px;color:#000;max-width:560px">` +
    `<div style="background:#000;color:#F1B80E;padding:12px 16px;font-weight:900;letter-spacing:.16em">NFG WATCHDOG</div>` +
    `<div style="padding:16px"><p>${esc(lead)}</p>${inner}` +
    `<p style="color:#55585c;font-size:12px;margin-top:24px">If you did not ask for this, ignore this email; nothing changes. Questions: NFG IT.</p></div></div>`;
}
const btn = (href: string, label: string) =>
  `<p><a href="${esc(href)}" style="display:inline-block;background:#F1B80E;color:#000;font-weight:700;padding:10px 18px;border-radius:6px;text-decoration:none">${esc(label)}</a></p>` +
  `<p style="color:#55585c;font-size:12px">The link works once and expires within an hour.</p>`;
const verifyLink = (hash: string, type: string, redirect: string) =>
  `${SB_URL}/auth/v1/verify?token=${encodeURIComponent(hash)}&type=${encodeURIComponent(type)}&redirect_to=${encodeURIComponent(redirect)}`;

Deno.serve(async (req) => {
  if (req.method !== "POST") return fail(405, "POST only");
  const body = await req.text();
  if (!(await verified(req, body))) return fail(401, "Bad signature");
  let p: any;
  try { p = JSON.parse(body); } catch { return fail(400, "Bad payload"); }
  const user = p.user ?? {}, d = p.email_data ?? {};
  const type = String(d.email_action_type ?? "");
  const redirect = String(d.redirect_to || d.site_url || "");
  try {
    if (type === "reauthentication") {
      await sendMail(user.email, "Your NFG Watchdog confirmation code",
        page("Type this code in NFG Watchdog to confirm it is you:", `<p style="font-size:26px;font-weight:900;letter-spacing:.2em">${esc(d.token)}</p>`));
    } else if (type === "email_change") {
      const c = COPY.email_change;
      if (d.token_hash_new && user.new_email) {
        // secure change: the current address gets token_hash_new, the new address gets token_hash (Supabase's naming)
        await sendMail(user.email, c.subject, page(c.lead, btn(verifyLink(d.token_hash_new, type, redirect), c.button)));
        await sendMail(user.new_email, c.subject, page(c.lead, btn(verifyLink(d.token_hash, type, redirect), c.button)));
      } else {
        await sendMail(user.new_email || user.email, c.subject, page(c.lead, btn(verifyLink(d.token_hash, type, redirect), c.button)));
      }
    } else if (type === "recovery" || type === "magiclink" || type === "email") {
      // code only, no link: Microsoft's Safe Links scanner opens links before the person does and uses them up
      const recovery = type === "recovery";
      await sendMail(user.email, recovery ? "Your NFG Watchdog password reset code" : "Your NFG Watchdog sign-in code",
        page(recovery ? "Someone asked to reset the password for your NFG Watchdog account. If it was you, type this code on the Watchdog reset screen:" : "Type this code in NFG Watchdog to sign in:",
          `<p style="font-size:28px;font-weight:900;letter-spacing:.25em;margin:18px 0">${esc(d.token)}</p><p style="color:#55585c;font-size:12px">The code works once and expires within an hour. Only the newest code works.</p>`));
    } else {
      const c = COPY[type] ?? COPY.magiclink;
      await sendMail(user.email, c.subject, page(c.lead, btn(verifyLink(d.token_hash, type, redirect), c.button)));
    }
  } catch (e) {
    console.error("wd-auth-email", type, (e as Error).message);
    return fail(500, "The email could not be sent. Ask NFG IT.");
  }
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
});
