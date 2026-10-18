// NFG Watchdog: where the app's data lives, and the version stamp.
// Watchdog signs in against its OWN Supabase project (NFG-Watchdog), not the central NFG login.
// Bump APP_BUILD by 0.01 with every change that goes live, with the date and time (SAST), and start the commit message with it.
export const WD_URL = "https://opckmndqounbhqksouxx.supabase.co";              // NFG-Watchdog project
export const WD_KEY = "sb_publishable_nEj3oPiULc6TZsZe4QGPnA_p3CQqL4y";       // publishable: safe in the browser, RLS (members at aal2) does the rest
export const PORTAL_URL = "https://auth.normandien.co.za";                     // NFG Home, for the All apps link
export const IDLE_MINUTES = 30;                                                // signed out after this long without activity
export const APP_BUILD = { app: "Watchdog", version: "0.01", date: "2026-10-18", time: "09:30" };
window.APP_BUILD = APP_BUILD;
