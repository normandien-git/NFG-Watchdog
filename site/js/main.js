// NFG Watchdog: load order. Shell (sign-in), menu and Overview, then each area, then start.
import { H } from "./watchdog.js";
await import("./menu.js");       // menu, Overview, My account
await import("./security.js");   // Findings, Suspicious activity, Change log, Performance findings (and the row-click helper)
await import("./access.js");     // Who is connecting, Sign-ins, Database logins, People with admin access
await import("./inventory.js");  // Projects & sites, Edge functions, Secrets & keys, Entra apps, API in & out, Netlify deploys
await import("./perf.js");       // Slow queries
await import("./admin.js");      // Alerts, Alert rules, Collector runs, Settings, Users, Access log
H.start();
