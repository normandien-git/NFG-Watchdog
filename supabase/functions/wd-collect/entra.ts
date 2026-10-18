// NFG Watchdog collector: Microsoft Entra ID / 365 (hourly). Our app registrations, what they may do,
// their secrets and certificates, who signs in through them and from where, and changes to them.
// Needs an app registration with application permissions: Application.Read.All, AuditLog.Read.All, Directory.Read.All
// Alert emails do NOT go through this app: they use the NFG Normandien – Mail app (mail.ts).
import { db, q, fp, nowIso, pool, getJson, upsertTargets, patchTargetMeta, syncFindings, syncInventory, insertMany, setConnector, settings, type Finding, type Sev } from "./lib.ts";

const TENANT = Deno.env.get("ENTRA_TENANT_ID") ?? "";
const CLIENT = Deno.env.get("ENTRA_CLIENT_ID") ?? "";
const SECRET = Deno.env.get("ENTRA_CLIENT_SECRET") ?? "";
export const entraReady = () => !!(TENANT && CLIENT && SECRET);
const T = () => `entra:${TENANT}`;

let tok: { v: string; exp: number } | null = null;
export async function graphToken() {
  if (tok && tok.exp > Date.now() + 60_000) return tok.v;
  const r = await getJson(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLIENT, client_secret: SECRET, grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" }),
  });
  tok = { v: r.access_token, exp: Date.now() + Number(r.expires_in) * 1000 };
  return tok.v;
}
export async function graph(path: string, init: RequestInit = {}): Promise<any> {
  const url = path.startsWith("http") ? path : `https://graph.microsoft.com${path}`;
  return getJson(url, { ...init, headers: { Authorization: `Bearer ${await graphToken()}`, "content-type": "application/json", ConsistencyLevel: "eventual", ...(init.headers || {}) } });
}
async function graphAll(path: string, max = 5000): Promise<any[]> {
  const out: any[] = [];
  let next: string | null = path;
  while (next && out.length < max) { const r: any = await graph(next); out.push(...(r.value ?? [])); next = r["@odata.nextLink"] ?? null; }
  return out;
}

// application permissions that let an app read or change a lot
const HIGH: Record<string, Sev> = {
  "Directory.ReadWrite.All": "critical", "Application.ReadWrite.All": "critical", "AppRoleAssignment.ReadWrite.All": "critical",
  "RoleManagement.ReadWrite.Directory": "critical", "full_access_as_app": "critical", "Domain.ReadWrite.All": "critical",
  "User.ReadWrite.All": "high", "Group.ReadWrite.All": "high", "Mail.ReadWrite": "high", "Mail.Send": "high", "Mail.Read": "high",
  "Files.ReadWrite.All": "high", "Sites.FullControl.All": "high", "Sites.ReadWrite.All": "high", "Policy.ReadWrite.ConditionalAccess": "critical",
  "UserAuthenticationMethod.ReadWrite.All": "critical", "Calendars.ReadWrite": "medium", "Files.Read.All": "medium", "Sites.Read.All": "medium",
  "Directory.Read.All": "medium", "User.Read.All": "low", "AuditLog.Read.All": "low",
};

const resCache = new Map<string, any>();
async function resource(appId: string) {
  if (resCache.has(appId)) return resCache.get(appId);
  const r = await graph(`/v1.0/servicePrincipals?$filter=appId eq '${appId}'&$select=id,appId,displayName,appRoles,oauth2PermissionScopes`).catch(() => null);
  const sp = r?.value?.[0] ?? null;
  resCache.set(appId, sp);
  return sp;
}

const resIdCache = new Map<string, Promise<any>>();
function resourceById(id: string) {
  if (!resIdCache.has(id)) resIdCache.set(id, graph(`/v1.0/servicePrincipals/${id}?$select=id,appId,displayName,appRoles,oauth2PermissionScopes`).catch(() => null));
  return resIdCache.get(id)!;
}

export async function runEntra() {
  if (!entraReady()) { await setConnector("entra", { ok: false, note: "ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET not set" }); return { skipped: "Entra not set up" }; }
  const s = await settings();
  const tgt = T(), F: Finding[] = [], A: Finding[] = [], errors: string[] = [];
  const step = async (n: string, fn: () => Promise<void>) => { try { await fn(); } catch (e) { errors.push(`${n}: ${(e as Error).message.slice(0, 250)}`); } };
  const org = await graph(`/v1.0/organization?$select=id,displayName,verifiedDomains`).catch(() => null);
  await upsertTargets([{ id: tgt, kind: "entra", ref: TENANT, name: `Entra ID · ${org?.value?.[0]?.displayName ?? TENANT}`, meta: {} }]);
  const t0 = await q(db.from("wd_target").select("meta").eq("id", tgt).single());
  const since = new Date(t0.meta?.signins_until ? Date.parse(t0.meta.signins_until) : Date.now() - 24 * 3600e3);
  const now = new Date();

  // ---- app registrations
  let apps: any[] = [];
  await step("applications", async () => {
    apps = await graphAll(`/v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess,web,spa,publicClient&$expand=owners($select=userPrincipalName,displayName)&$top=999`);
  });
  const sps = new Map<string, any>();
  await step("service principals", async () => {
    const list = await graphAll(`/v1.0/servicePrincipals?$filter=appOwnerOrganizationId eq ${TENANT}&$select=id,appId,displayName,accountEnabled&$top=999`);
    for (const sp of list) sps.set(sp.appId, sp);
  });
  const lastSign = new Map<string, string>();
  await step("sign-in activity", async () => {
    const act = await graphAll(`/beta/reports/servicePrincipalSignInActivities?$top=999`);
    for (const a of act) {
      const d = [a.lastSignInActivity?.lastSignInDateTime, a.delegatedClientSignInActivity?.lastSignInDateTime, a.applicationAuthenticationClientSignInActivity?.lastSignInDateTime].filter(Boolean).sort().pop();
      if (d) lastSign.set(a.appId, d);
    }
  });

  const secretRows: any[] = [], appRows: any[] = [];
  await pool(apps, 5, async (app) => {
    const sp = sps.get(app.appId);
    // granted application permissions (what the app can do without a user)
    const perms: any[] = [];
    if (sp) {
      const grants = await graphAll(`/v1.0/servicePrincipals/${sp.id}/appRoleAssignments`).catch(() => []);
      for (const g of grants) {
        const res = await resourceById(g.resourceId);
        const role = res?.appRoles?.find((r: any) => r.id === g.appRoleId);
        perms.push({ resource: g.resourceDisplayName, name: role?.value ?? g.appRoleId, type: "Application", granted: true });
      }
      const dele = await graphAll(`/v1.0/servicePrincipals/${sp.id}/oauth2PermissionGrants`).catch(() => []);
      for (const d of dele) for (const sc of String(d.scope ?? "").split(" ").filter(Boolean)) perms.push({ resource: "consented", name: sc, type: "Delegated", granted: true, consent: d.consentType });
    }
    // requested but maybe not granted
    for (const rra of app.requiredResourceAccess ?? []) {
      const res = await resource(rra.resourceAppId);
      for (const ra of rra.resourceAccess ?? []) {
        const isRole = ra.type === "Role";
        const def = isRole ? res?.appRoles?.find((r: any) => r.id === ra.id) : res?.oauth2PermissionScopes?.find((r: any) => r.id === ra.id);
        const nm = def?.value ?? ra.id;
        if (!perms.some((p) => p.name === nm && p.type === (isRole ? "Application" : "Delegated"))) perms.push({ resource: res?.displayName ?? rra.resourceAppId, name: nm, type: isRole ? "Application" : "Delegated", granted: false });
      }
    }
    const redirects = [...(app.web?.redirectUris ?? []), ...(app.spa?.redirectUris ?? []), ...(app.publicClient?.redirectUris ?? [])];
    const last = lastSign.get(app.appId) ?? null;
    appRows.push({ app_id: app.appId, object_id: app.id, sp_id: sp?.id ?? null, display_name: app.displayName, created_src: app.createdDateTime, audience: app.signInAudience,
      permissions: perms, redirect_uris: redirects, owners: (app.owners ?? []).map((o: any) => o.userPrincipalName ?? o.displayName), last_sign_in: last, last_seen: nowIso(), active: true,
      meta: { enabled: sp?.accountEnabled ?? null, secrets: (app.passwordCredentials ?? []).length, certs: (app.keyCredentials ?? []).length } });

    const name = app.displayName;
    const base = { source: "entra", target_id: tgt };
    // permissions
    for (const p of perms.filter((p) => p.type === "Application" && p.granted && HIGH[p.name])) {
      F.push({ ...base, fingerprint: fp("en", app.appId, "perm", p.name), check_code: "entra.high_permission", category: "access", severity: HIGH[p.name],
        title: `${name} can ${p.name} across the whole tenant`, detail: `Application permission ${p.name} (${p.resource}) is granted. Anyone holding this app's secret can use it without a user signing in.`,
        remediation: p.name.startsWith("Mail.") ? "Limit it to the mailboxes it needs with an Exchange application access policy (or RBAC for Applications)." : "Remove it if not needed, or swap it for a narrower permission.", meta: { app_id: app.appId, permission: p.name } });
    }
    if (app.signInAudience && app.signInAudience !== "AzureADMyOrg") F.push({ ...base, fingerprint: fp("en", app.appId, "audience"), check_code: "entra.multitenant", category: "access", severity: "medium",
      title: `${name} accepts sign-ins from other organisations`, detail: `Sign-in audience is ${app.signInAudience}.`, remediation: "Set Supported account types to 'this organisational directory only' unless outsiders must sign in." });
    const httpRedirects = redirects.filter((u: string) => /^http:\/\/(?!localhost|127\.0\.0\.1)/.test(u));
    const wild = redirects.filter((u: string) => u.includes("*"));
    if (httpRedirects.length || wild.length) F.push({ ...base, fingerprint: fp("en", app.appId, "redirects"), check_code: "entra.redirects", category: "config", severity: "medium",
      title: `${name} has unsafe sign-in redirect addresses`, detail: [...httpRedirects, ...wild].join(", "), remediation: "Use exact https addresses only." });
    // credentials
    const creds = [...(app.passwordCredentials ?? []).map((c: any) => ({ ...c, kind: "entra_password" })), ...(app.keyCredentials ?? []).map((c: any) => ({ ...c, kind: "entra_certificate" }))];
    let live = 0;
    for (const c of creds) {
      const end = c.endDateTime ? Date.parse(c.endDateTime) : null, start = c.startDateTime ? Date.parse(c.startDateTime) : null;
      const label = `${name} · ${c.displayName || c.hint || c.keyId?.slice(0, 8)}`;
      secretRows.push({ target_id: tgt, kind: c.kind, name: `${app.appId}:${c.keyId}`, digest: c.keyId, is_secret: true, expires_at: c.endDateTime ?? null,
        meta: { app: name, app_id: app.appId, label: c.displayName ?? null, hint: c.hint ?? null, start: c.startDateTime ?? null } });
      if (!end) continue;
      const days = Math.round((end - Date.now()) / 86400e3);
      if (days >= 0) live++;
      if (days < 0 && days > -90) F.push({ ...base, fingerprint: fp("en", app.appId, "cred.expired", c.keyId), check_code: "entra.credential_expired", category: "secrets", severity: "low",
        title: `${label}: ${c.kind === "entra_password" ? "secret" : "certificate"} expired ${-days} days ago`, detail: "If something still uses it, it has stopped working.", remediation: "Delete the expired credential; create a new one only if the integration still runs." });
      else if (days >= 0 && days <= 30) F.push({ ...base, fingerprint: fp("en", app.appId, "cred.expiring", c.keyId), check_code: "entra.credential_expiring", category: "reliability", severity: days <= 7 ? "high" : "medium",
        title: `${label}: ${c.kind === "entra_password" ? "secret" : "certificate"} expires in ${days} days`, detail: `Expires ${c.endDateTime.slice(0, 10)}. The integration stops working then.`, remediation: "Create a new secret, update it where it is used (edge function secret, Netlify env), then delete the old one." });
      if (start && end - start > 2 * 366 * 86400e3 && c.kind === "entra_password") F.push({ ...base, fingerprint: fp("en", app.appId, "cred.long", c.keyId), check_code: "entra.credential_long", category: "secrets", severity: "low",
        title: `${label}: secret valid for ${Math.round((end - start) / 86400e3 / 365)} years`, detail: "Long-lived secrets are hard to track and likely to leak.", remediation: "Use 6–12 month secrets, or a certificate." });
    }
    if (live && (!last || Date.now() - Date.parse(last) > 90 * 86400e3)) F.push({ ...base, fingerprint: fp("en", app.appId, "unused"), check_code: "entra.unused_with_credentials", category: "access", severity: "low",
      title: `${name} has not been used for 90 days but has live credentials`, detail: last ? `Last sign-in ${last.slice(0, 10)}.` : "No sign-in recorded.", remediation: "Delete its secrets (or the app) if nothing uses it any more." });
    if (!(app.owners ?? []).length) F.push({ ...base, fingerprint: fp("en", app.appId, "noowner"), check_code: "entra.no_owner", category: "config", severity: "info",
      title: `${name} has no owner`, detail: "Nobody is named as responsible for it.", remediation: "Add an owner in Entra › App registrations › Owners." });
  });
  await insertMany("wd_entra_app", appRows, { onConflict: "app_id" });
  if (appRows.length) await q(db.from("wd_entra_app").update({ active: false }).not("app_id", "in", `(${appRows.map((a) => `"${a.app_id}"`).join(",")})`));
  const credStats = await syncInventory("wd_secret", { target_id: tgt, kind: "entra_password" }, secretRows.filter((r) => r.kind === "entra_password"), { kind: "entra_credential", label: (r) => `${r.meta?.app ?? ""} secret ${r.meta?.label ?? r.meta?.hint ?? ""}` });
  await syncInventory("wd_secret", { target_id: tgt, kind: "entra_certificate" }, secretRows.filter((r) => r.kind === "entra_certificate"), { kind: "entra_credential", label: (r) => `${r.meta?.app ?? ""} certificate ${r.meta?.label ?? ""}` });

  // ---- sign-ins through our apps (users and the apps themselves)
  const ourApps = appRows.map((a) => a.app_id);
  const allowed = new Set<string>(s.allowed_countries || ["ZA"]);
  let signins = 0;
  await step("sign-ins", async () => {
    const rows: any[] = [];
    const sinceIso = since.toISOString();
    const sp = await graphAll(`/beta/auditLogs/signIns?$filter=createdDateTime ge ${sinceIso} and signInEventTypes/any(t: t eq 'servicePrincipal')&$top=500`, 5000).catch((e) => { errors.push(`sp sign-ins: ${e.message.slice(0, 150)}`); return []; });
    for (const x of sp) rows.push({ id: x.id, at: x.createdDateTime, app_id: x.appId, app_name: x.appDisplayName, principal: x.servicePrincipalName ?? x.appDisplayName, is_sp: true,
      ip: x.ipAddress, city: x.location?.city ?? null, country: x.location?.countryOrRegion ?? null, ok: (x.status?.errorCode ?? 0) === 0, failure: x.status?.failureReason ?? null, client_app: x.clientAppUsed ?? null, resource: x.resourceDisplayName ?? null });
    for (let i = 0; i < ourApps.length; i += 10) {
      const f = ourApps.slice(i, i + 10).map((a) => `appId eq '${a}'`).join(" or ");
      const us = await graphAll(`/v1.0/auditLogs/signIns?$filter=createdDateTime ge ${sinceIso} and (${f})&$top=500`, 5000).catch(() => []);
      for (const x of us) rows.push({ id: x.id, at: x.createdDateTime, app_id: x.appId, app_name: x.appDisplayName, principal: x.userPrincipalName, is_sp: false,
        ip: x.ipAddress, city: x.location?.city ?? null, country: x.location?.countryOrRegion ?? null, ok: (x.status?.errorCode ?? 0) === 0, failure: x.status?.failureReason ?? null, client_app: x.clientAppUsed ?? null, resource: x.resourceDisplayName ?? null });
    }
    await insertMany("wd_entra_signin", rows, { onConflict: "id", ignoreDuplicates: true });
    signins = rows.length;
    const day = now.toISOString().slice(0, 10);
    // an app signing in from a country we do not expect
    for (const r of rows.filter((r) => r.is_sp && r.ok && r.country && !allowed.has(r.country)))
      A.push({ source: "entra", target_id: tgt, fingerprint: fp("en", r.app_id, "act.sp_country", r.country, day), check_code: "activity.app_signin_abroad", category: "activity", severity: "medium",
        title: `${r.app_name} signed in from ${r.country} (${r.ip})`, detail: `The app authenticated with its own credentials from ${r.city ?? ""} ${r.country}. Supabase/Netlify functions run in Europe and the US, so check against where the app is hosted.`,
        remediation: "If the location is not where the app runs, rotate its secret now.", meta: r });
    const failByApp = new Map<string, number>();
    for (const r of rows.filter((r) => r.is_sp && !r.ok)) failByApp.set(r.app_name, (failByApp.get(r.app_name) ?? 0) + 1);
    for (const [app, n] of failByApp) if (n >= 10) A.push({ source: "entra", target_id: tgt, fingerprint: fp("en", app, "act.sp_fail", day), check_code: "activity.app_signin_failures", category: "activity", severity: "medium",
      title: `${app}: ${n} failed app sign-ins`, detail: "Usually an expired or wrong secret; sometimes someone trying an old secret.", remediation: "Check the credential in use." });
    // usage counts for the last 30 days
    const { data: counts } = await db.rpc("wd_entra_counts");
    for (const c of counts ?? []) await db.from("wd_entra_app").update({ sign_ins_30d: c.n }).eq("app_id", c.app_id);
  });

  // ---- changes to apps and credentials
  await step("directory audit", async () => {
    const ev = await graphAll(`/v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge ${since.toISOString()} and category eq 'ApplicationManagement'&$top=500`, 2000);
    await insertMany("wd_audit_external", ev.map((e) => ({ id: `entra:${e.id}`, source: "entra", at: e.activityDateTime,
      actor: e.initiatedBy?.user?.userPrincipalName ?? e.initiatedBy?.app?.displayName ?? null, action: e.activityDisplayName,
      target: (e.targetResources ?? []).map((t: any) => t.displayName).filter(Boolean).join(", "), ip: e.initiatedBy?.user?.ipAddress ?? null, meta: { result: e.result, category: e.category } })), { onConflict: "id", ignoreDuplicates: true });
    for (const e of ev.filter((e) => /credential|certificate|secret|consent|app role assignment|delegated permission/i.test(e.activityDisplayName)))
      A.push({ source: "entra", target_id: tgt, fingerprint: fp("en", "audit", e.id), check_code: "activity.entra_app_change", category: "activity",
        severity: /consent|app role assignment/i.test(e.activityDisplayName) ? "high" : "medium",
        title: `Entra: ${e.activityDisplayName} on ${(e.targetResources ?? []).map((t: any) => t.displayName).filter(Boolean).join(", ") || "an app"}`,
        detail: `By ${e.initiatedBy?.user?.userPrincipalName ?? e.initiatedBy?.app?.displayName ?? "unknown"} at ${e.activityDateTime}.`, remediation: "Confirm the change was planned.", meta: { id: e.id } });
  });

  await patchTargetMeta(tgt, { signins_until: now.toISOString(), at: nowIso(), apps: appRows.length, signins, errors, credentials: credStats });
  const a = await syncFindings("entra:apps", F);
  const b = await syncFindings("entra:activity", A, false);
  await setConnector("entra", { ok: !errors.length, apps: appRows.length, errors: errors.length ? errors : undefined });
  return { apps: appRows.length, signins, findings: F.length, activity: A.length, sync: a, activity_sync: b, errors };
}
