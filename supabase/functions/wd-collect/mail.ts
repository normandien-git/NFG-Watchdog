// NFG Watchdog collector: sending email through Microsoft 365 with the existing "NFG Normandien – Mail" app registration
// (Graph Mail.Send, limited by an Exchange application access policy to the noreply mailbox). Kept apart from the Entra
// connection so a mail-only secret never gets the directory read permissions, and the read app never gets Mail.Send.
import { getJson } from "./lib.ts";

const TENANT = Deno.env.get("MAIL_TENANT_ID") || Deno.env.get("ENTRA_TENANT_ID") || "";
const CLIENT = Deno.env.get("MAIL_CLIENT_ID") ?? "";
const SECRET = Deno.env.get("MAIL_CLIENT_SECRET") ?? "";
export const MAIL_FROM = (Deno.env.get("MAIL_FROM") || "noreply@normandien.co.za").trim();
export const mailReady = () => !!(TENANT && CLIENT && SECRET);

let tok: { v: string; exp: number } | null = null;
async function token() {
  if (tok && tok.exp > Date.now() + 60_000) return tok.v;
  const r = await getJson(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLIENT, client_secret: SECRET, grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" }),
  });
  tok = { v: r.access_token, exp: Date.now() + Number(r.expires_in) * 1000 };
  return tok.v;
}

export async function sendMail(from: string, to: string[], subject: string, html: string) {
  if (!mailReady()) throw new Error("Email not set up: add MAIL_TENANT_ID, MAIL_CLIENT_ID and MAIL_CLIENT_SECRET (the NFG Normandien – Mail app)");
  if (!to.length) throw new Error("No recipients");
  await getJson(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(from)}/sendMail`, {
    method: "POST", headers: { Authorization: `Bearer ${await token()}`, "content-type": "application/json" },
    body: JSON.stringify({ message: { subject, body: { contentType: "HTML", content: html }, toRecipients: to.map((a) => ({ emailAddress: { address: a } })) }, saveToSentItems: false }),
  }, 2);
}
