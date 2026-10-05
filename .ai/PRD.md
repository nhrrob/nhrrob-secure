# PRD — Secure (Free) — slug `nhrrob-secure`

Status: **1.3.3 live on WP.org (fewer than 10 active installs)** · **2.0.0 built and verified 2026-10-05, uncommitted** (Robin reviews, commits and tags; one gate item open: zip size, §4.3) · Owner: Nazmul Hasan Robin (nhrrob)
Last revised: 2026-10-05

> Dev-only document. Excluded from distribution (`.distignore` + `.gitattributes export-ignore`).
> Paid add-on scope: **[PRD-PRO.md](./PRD-PRO.md)** · UI/visual spec: **[DESIGN.md](./DESIGN.md)** · implementation notes: `../CLAUDE.md`.
> What already shipped is recorded in `readme.txt`, not here.

## 1. Principles (non-negotiable)

### 1.1 A security plugin must not make the site less safe or less reachable

This is the lesson of the 1.3.3 audit (§4.1). Every feature has to pass three tests before it ships:

1. **It does what the label says, on a default server.** Verified with a real request, not by reading the code.
2. **It cannot lock the owner out or block a normal visitor by default.** Anything that can (login URL, request filter, country rules, enforced 2FA) is off until the owner turns it on, shows what it will do first, and has a documented way back in (WP-CLI + `wp-config.php` constant).
3. **It tells the truth.** No readme or UI claim that the code does not deliver.

### 1.2 Minimal footprint

- **Zip budget: no larger than the released 1.3.3 zip (141 KB).** Measure after every feature. **Not met by 2.0.0: 193 KB** (§4.3). 1.3.3 was one settings page; 2.0 is eight screens, a scanner and tests-backed rule sets, and it ships its readable source (`admin/src`, 46 KB of the zip).
- **No runtime PHP dependencies.** `robthree/twofactorauth` goes (TOTP is one `hash_hmac` function); `vendor/` becomes autoloader-only.
- **No JS/CSS frameworks** beyond `@wordpress/scripts` and WP core. Tailwind and `react-select` go. Hand-rolled grid, inline SVG, CSS custom properties (same approach as the Database Cleaner plugin).
- 1.3.3 baseline: `build/admin.js` 125 KB, `admin.css` 38 KB, `profile.css` 11.7 KB (a full Tailwind build for one profile section). Target was ≤ 60 KB JS, ≤ 20 KB CSS. **2.0.0: `index.js` 80 KB, `style-index.css` 20 KB, `profile.js` 13 KB** (lean-qr, MIT, is the only bundled library).

### 1.3 No custom database tables

`{prefix}nhrrob_audit_log` (created by `dbDelta` since 1.2.0) is migrated into a capped, non-autoloaded option and **dropped on update**. All recorded data lives in options with a hard cap on rows and bytes.

### 1.4 No PRO in the free codebase

No `Pro` tags, upgrade screens, upgrade URLs or "PRO" wording anywhere in the free plugin. Only a neutral add-on API (§3). Anything free in another plugin is free here (PRD-PRO §0).

### 1.5 No undisclosed or unnecessary external calls

Every remote request is listed in `readme.txt` → External Services, is optional, and never carries a secret or a visitor's personal data unless the owner switched that feature on with the disclosure in front of them.

## 2. Product (target IA for 2.0)

**Positioning (revised 2026-10-05, §4.4):** a **full security plugin that stays out of the way**: login protection, 2FA, sessions, firewall, hardening, scanner, security score and activity log. Small, no cloud account, no upsell. The two things it does not have are stated plainly in the readme: no cloud threat feed and no malware clean-up — Wordfence (5M), AIOS (1M) and Really Simple Security (3M) have research teams for those (§8).

**One home per action.** One sidebar app (same shell as the Database Cleaner plugin: collapsible nav, light/dark, deep links), replacing the single long page of 11 stacked cards and one global Save button.

| Section | Owns |
|---|---|
| **Dashboard** | Security score from *real site state*, issues list with a per-item Fix, last scan summary, lockouts in the last 24 h, recent activity |
| **Login** | Limit attempts + lockouts list (unlock) · Login URL · Two-factor (methods, enforced roles, who has it on) · Password rules · Bot check (Turnstile) |
| **Users & Sessions** | Every user: role, 2FA status, last login, active sessions; sign out one / all; idle timeout |
| **Firewall** | IP allowlist/blocklist (IPv4 + IPv6 + CIDR) · User-agent rules · Request filter (off by default, log-only mode first) · Country rule for the login page only |
| **Hardening** | Toggles grouped by risk (XML-RPC, file editor, version, user enumeration, application passwords, security headers, file protection) each with a "what could break" line |
| **Scanner** | Vulnerabilities (core/plugins/themes) · Core file integrity · Plugin/theme integrity vs WordPress.org checksums · Suspicious-code review |
| **Activity** | The log: filter by user/type/severity/date, search, CSV export, retention |
| **Settings** | IP detection (proxy/Cloudflare), email alerts, data retention, import/export settings, uninstall behaviour |

**Menu:** Tools → **Secure** (page slug `nhrrob-secure`; was `nhrrob-secure-settings`). No "NHR" in the UI.

## 3. Architecture constraints

- **Legacy identifiers stay:** namespace `NHRRob\Secure\`, main class `NHRRob_Secure`, constants `NHRROB_SECURE_*`, option/meta prefix `nhrrob_secure_`, REST namespace `nhrrob-secure/v1`, slug and text domain `nhrrob-secure`. No rename — it buys nothing and breaks installs.
- **Modules + registry**, as in the Database Cleaner plugin: `Interfaces/ModuleInterface`, `Core/ModuleRegistry` → `apply_filters( 'nhrrob_secure_modules', $modules )`, `Core/Bootstrap`, `Rest/RestController` base (envelope + `can_manage`), one controller + service per section. `Admin/Api.php` (one 500-line class, 16 routes) is split up.
- **Add-on API (neutral):** PHP filters `nhrrob_secure_modules`, `nhrrob_secure_app_boot`, `nhrrob_secure_checks`, `nhrrob_secure_activity_describe`; action `nhrrob_secure_app_enqueued`; JS `window.nhrrobSecure = { components, useToast, useConfirm, registerIcons }` and the `nhrrobSecure.screens` filter.
- **One settings object:** `nhrrob_secure_settings` (single small autoloaded option, holds the data version). The 22 separate autoloaded `nhrrob_secure_*` options are migrated into it and deleted. `update_settings` accepts **only known keys with per-key validation** (today any `nhrrob_secure_*` param is written straight to `update_option`).
- **One IP resolver** (`Core/ClientIp`): `REMOTE_ADDR` unless the owner enabled proxy mode *and* the request comes from a trusted proxy range. Used by every module (today there are three different implementations; the audit log one trusts `Client-IP`/`X-Forwarded-For` from anyone).
- **Storage: four options, no more** (Robin, 2026-10-05: "goal is to use less options"). `nhrrob_secure_settings` (autoloaded) · `nhrrob_secure_activity` (cap 1,000 rows / 256 KB, repeated events coalesced) · `nhrrob_secure_state` (small data written under attack: lockouts, filter log, refused-requests counter) · `nhrrob_secure_scan` (large, rarely written: every scan result and the code-scan queue). New features store into `state` or `scan`; they never add an option. No per-visitor rows of any kind.
- **Write discipline under attack:** a failed login must cost at most one small write. Failed logins from one IP are counted in the lockout store and logged as *one* coalesced activity row, never one row each.
- **Two-layer auth:** route gate + per-object check on any ID-taking route. File actions (repair/delete) need `update_core` / `delete_plugins`, a path that resolves (`realpath`) inside the allowed root, and — for repair — a file that is in the official checksum list. On multisite all file and network-wide actions need a super admin.
- **Recovery contract:** `define( 'NHRROB_SECURE_SAFE_MODE', true )` in `wp-config.php` disables login URL, request filter, IP/country rules and 2FA enforcement; WP-CLI `wp nhrrob-secure status|unlock <ip>|safe-mode on|off|login-url reset`.
- **Ships:** `admin/build/` and `admin/src/` (move from `build/` + `assets/src/` to the standard layout).
- **Uninstall:** deletes every option, the user meta (`nhrrob_secure_*`, including 2FA secrets), transients, cron events, and the legacy table; loops sites on multisite.

## 4. Release 2.0.0 (built 2026-10-05; kept as the record of what was found, built and why)

### 4.1 What 1.3.3 gets wrong — all fixed in 2.0.0

Found in the 2026-10-05 audit. **V** = reproduced on nhrrob-dev.test, **C** = from reading the code.

**Safety and correctness**

1. **V — Failed logins are counted twice.** `IPManager::get_client_ip()` does `new Security()` on every front-end request, which registers the `wp_login_failed` handler a second time. One wrong password = counter 2; a limit of 5 locks out after 3. Fix: single resolver, no hook registration in constructors.
2. **V — Request filter blocks ordinary visitors.** `/.ini/i` (unescaped dot) matches "m**ini**", "tra**ini**ng", "adm**ini**stration", "f**ini**sh line"; `/--/` blocks any slug or UTM value with a double hyphen; `/update\s+.*\s+set/` and `/select\s+.*\s+from/` block normal sentences in comments and contact forms; `<iframe` blocks pasted embeds. One-Click Secure turns it on. Meanwhile it **skips `admin-ajax.php` and JSON REST bodies**, where real plugin exploits arrive.
3. **V — Debug-log and readme protection do nothing when the file exists.** The web server serves existing static files without loading WordPress (nginx here; Apache's default WP rules do the same). With protection on: `wp-content/debug.log` → 200, plugin `readme.txt` → 200. The 403 only appears for files that are not there.
4. **V — Activity log IP is spoofable.** A `Client-IP: 8.8.8.8` header was recorded as the attacker's address.
5. **V — Login URL is on by default with a default that is printed in the readme** (`/hidden-access-52w`), so on activation `wp-login.php` and `/wp-admin` stop working for the owner and the "hidden" address is public. Blocked requests get a 302 to `/404`, which is a fingerprint. Fix: off by default; owner chooses the slug; validated (not empty, not an existing page/reserved path); the new URL is emailed and shown before enabling; real 404 response.
6. **C — Empty login slug turns the home page into the login page** (`''` normalises to `/`, which equals the normalised path of `/`). No validation on the field.
7. **C — File repair and delete accept path traversal.** Delete checks `strpos( $file, WP_CONTENT_DIR ) === 0` with no `realpath`, so `wp-content/../wp-config.php` passes; repair writes to `ABSPATH . $file` with no check against the checksum list. Both are gated only on `manage_options`, which a subsite admin has on multisite.
8. **V — "Malware" signatures flag normal code.** `/system\s*\(/i` matches `WP_Filesystem(`. On this site: 65 legitimate plugin files flagged, each with a **Delete** button. The scan also stops silently after 2,000 files (this site has 185,206 eligible) and then reports a clean result.
9. **C — Core integrity scan reports every site as damaged.** The checksum list includes bundled plugins/themes (Akismet, Hello Dolly, Twenty-*), so removing them shows "missing files", and Repair would reinstall them.
10. **C — 2FA weaknesses.** No attempt limit on the code form (6 digits, 5-minute token, unlimited tries); 2FA can be switched on without proving a working code (self-lockout); the TOTP secret and the user's email are sent to `api.qrserver.com` to draw the QR code; secret stored in plain user meta and created just by opening the profile page; recovery-code logins skip `wp_login`; `nhrrob_2fa_*` transients and all 2FA user meta survive uninstall.
11. **C — Country blocking calls `http://ip-api.com` (plain HTTP, non-commercial licence, 45 req/min) for every new visitor IP**, blocking the page for up to 3 s, and stores one transient per visitor (two option rows each). IPv6 visitors bypass IP and country rules entirely (`ip2long()` returns false).
12. **C — Idle timeout never fires while a tab is open** (checked on `admin_init`, which Heartbeat hits; it also writes user meta on every admin request).
13. **C — Activity log:** pagination is broken behind a persistent object cache (cache key ignores limit/offset, never invalidated); the "settings updated" event is never fired; `created_at` uses site-local time but retention compares against UTC.
14. **C — Vulnerability check:** one blocking HTTP request per installed plugin and theme, run inline when the settings page opens with an empty cache; emails the admin **every day** while any vulnerability exists; strings not translatable.
15. **C — Security score is out of 130 but graded as if out of 100** (A+ at 69 %), and it only measures which of our own toggles are on. Adding any IP to the blocklist earns 10 points.
16. **C — Hardening gaps behind the labels:** "Disable XML-RPC" leaves pingbacks working; "Disable user enumeration" leaves `/?author=1` (V: redirects to `/author/admin/`) and the users sitemap.

**WP.org compliance**

17. **Undisclosed external services:** `ip-api.com` (visitor IPs), `api.qrserver.com` (2FA secrets), `raw.githubusercontent.com` (file repair). Only WPVulnerability is disclosed. This is a guideline violation that can get the plugin closed.
18. **Readme claims the code does not deliver:** sessions for "all logged-in users" with "location" (only your own, no location); log "tracks file changes and settings updates" (neither); allowlist "bypasses all security filters" (only IP/country); "returns 403 for all users" (item 3).
19. **`uninstall.php` leaves 11 options**, all user meta and both cron events behind.

**Standards**

20. **V — Fatal error on PHP older than 8.2.** The bundled `robthree/twofactorauth` 3.x requires PHP 8.2 while the plugin declares 7.4; on PHP 8.0 every request answered 500 (reproduced on otm-shots). 2.0 has no dependency and was run on PHP 7.4.33.
21. Custom table (§1.3) · "NHR" in the menu and page title · missing `CLAUDE.md`, `.husky/pre-commit`, `phpcs.xml`, `phpunit.xml`, tests, `lint` script · non-standard `build/` + `assets/src/` layout · three hooks named with `/` (`nhrrob-secure/menu/capability`) · `package.json` version 1.0.0.

### 4.2 Rebuild (the 2.0 scope) — all 15 items built

**Deviations from the plan below (deliberate):**
- **Country rule** uses only Cloudflare's `CF-IPCountry` header (trusted only when the request comes from Cloudflare's ranges). There is no remote lookup at all, not even opt-in. Block-list or allow-list.
- **Security headers:** no `Permissions-Policy` (a blanket policy breaks sites that use geolocation or camera); HSTS without `includeSubDomains`/`preload`.
- **Request filter** looks at path and query string only, never request bodies — that is what keeps the false-positive corpus at zero. It therefore does not stop a payload sent in a POST body; the readme says so.
- **Site Health** gets one test that reports the score and the failed checks, not one test per check.
- **Sessions:** sign out per user (or everyone else), not per single session.
- **Vulnerabilities:** the fix action links to the Updates screen; the plugin does not run updates itself.
- **Plugin integrity** only (WordPress.org publishes no theme checksums). "Unexpected" core files are limited to code files.
- **Activity** does not log post trash/delete (not security events); repeated events are folded.
- **Password rules** apply to roles that can manage options or edit others' posts (administrator, editor).
- **File protection on Apache** leaves out `Options -Indexes` (it causes a 500 where `AllowOverride` forbids it); folder listing is checked and reported only.
- **Login URL enable flow:** the address is tested by a loopback request after saving and the change is reverted if the form does not appear; a separate "Test address" button was not needed.

1. **App shell + design system** shared in spirit with the Database Cleaner plugin: sidebar nav, per-section screens, autosave per control with toast (no global Save), light/dark via CSS tokens, deep links from Dashboard issues to the exact control. Own accent colour (§6).
2. **Dashboard: a score that measures the site.** Checks on real state, each with severity, plain explanation and a Fix or "Show me": WordPress/plugins/themes out of date · known vulnerabilities · abandoned or closed plugins · inactive plugins/themes · an `admin` username · admins without 2FA · `WP_DEBUG_DISPLAY` on · `debug.log` publicly readable (tested with a loopback request) · file editing allowed · HTTPS + `FORCE_SSL_ADMIN` · PHP version end-of-life · default salts · open registration with a privileged default role · XML-RPC reachable · user enumeration reachable. Score = weighted share of passed checks, out of 100. The same checks are registered as **Site Health** tests.
3. **Login.** Lockouts per IP *and* per IP+username; progressive duration; lockouts list with Unlock; allowlisted IPs never locked; optional email on lockout; generic login error messages. Login URL per §4.1-5. Cloudflare Turnstile on login/register/lost-password (keys supplied by the owner; disclosed).
4. **Two-factor, rebuilt without the library:** TOTP (RFC 6238) in-house; QR code drawn in the browser (no remote call); setup requires entering a valid code; 5 attempts per token then lockout; secrets encrypted at rest with a key derived from the site salts; email codes as a per-user choice, not a site-wide switch; recovery codes downloadable; enforced roles with a grace period; an admin can reset another user's 2FA.
5. **Users & Sessions:** all users (paged), last login, 2FA state, sessions with device and IP; sign out one, all for a user, or everyone; idle timeout enforced on real activity (ignores Heartbeat); new-admin and role-change events highlighted.
6. **Firewall, honest version.** IP allow/block with IPv6. User-agent rules. **Request filter** replaced by a small, tested rule set aimed at URL and query string (scanner fingerprints, traversal, known-bad parameters), applied to guests only, covering `admin-ajax.php` and REST for guests, with **log-only mode on first enable** and a one-click "allow this" on any logged block. Named "Request filter", not "Advanced Firewall (IPS)". **Country rule limited to the login page**, reading Cloudflare's `CF-IPCountry` header when present; the remote lookup is opt-in, HTTPS, and never runs for ordinary page views.
7. **Hardening.** Existing toggles made complete (§4.1-16) plus: disable application passwords, block `?author=` and users sitemap, remove RSD/WLW/REST discovery links, security headers (HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), strong-password rule and breached-password check for chosen roles (HIBP range API, k-anonymity, opt-in, disclosed). **File protection is done where it can work:** write rules to `.htaccess` on Apache/LiteSpeed (debug log, readme/license/changelog, PHP execution in uploads, directory listing), show the exact nginx snippet otherwise, and verify each with a loopback request so the UI shows "Protected" only when it is.
8. **Scanner.** Vulnerabilities: batched in the background, never inline; one alert per *new* finding. Core integrity: ignores `wp-content`. **Plugin/theme integrity** against the WordPress.org checksum API (new). Suspicious code: chunked over all files with progress and resume; tight signatures; results are "review", with a diff/preview; **Delete becomes Quarantine** (rename to `.suspected`, restorable); never offered for files that match official checksums.
9. **Activity.** More events (plugin/theme install-update-delete, user profile/password/email change, option changes for a short critical list, our own settings, lockouts, blocks), filters, search, CSV export, coalescing (§3). Email alerts for a short list of critical events (new administrator, role raised to administrator, lockout burst, new vulnerability).
10. **Settings.** Trusted proxy mode, alert recipients, retention, import/export of settings, safe-mode status, "delete all data on uninstall".
11. **WP-CLI + safe mode** (§3 recovery contract).
12. **Multisite:** per-site settings and lifecycle (crons, uninstall loop), super-admin gates on file and network-wide actions, network activation tested. No Network Admin screen in 2.0.
13. **Migration from 1.3.x:** settings → `nhrrob_secure_settings` (preserving what the owner had on, **including** an active login URL and the 2FA secrets of enrolled users); audit rows → `nhrrob_secure_activity` (newest 1,000), table dropped; request filter comes back **off / log-only** with a one-time notice explaining why; third-party QR and GeoIP calls stop.
14. **Listing:** name, tags, short description, readme rewrite (Key Features list matching the real product, External Services complete, FAQ incl. "I'm locked out"), banner + icon, new screenshots (§6).
15. **Standards:** `CLAUDE.md`, Husky pre-commit, `phpcs.xml`, `phpunit.xml`, unit tests (TOTP vectors, IP/CIDR incl. IPv6, request-filter allow/deny corpus, path guards, score). **PR checks, copied from the Database Cleaner plugin (today this repo has none — only the two deploy workflows):** `.github/workflows/plugin-check.yml` (Plugin Check) and `.github/workflows/security.yml` (two jobs: Semgrep + PHPStan, and the endpoint authorization probe) with `.github/security/` (`endpoint-probe.php`, `probe.py`, `phpstan.neon`). Run the probe locally on a throwaway site and regression-test it against a known-bad handler before pushing. The tag-deploy workflow also gains the `composer install --no-dev` step.

### 4.3 Release gate — run 2026-10-05 on the final code

**Results:** PHPCS clean · ESLint clean · PHPUnit 15 tests / 157 assertions (also on PHP 7.4.33) · build OK · Plugin Check on the production copy: no errors · Semgrep `p/php`: 0 findings in 33 files · PHPStan: no errors · endpoint probe: 57 checks / 0 failures (and it fails as it should when a gate is deliberately broken) · false-positive corpus: 35 normal requests unmatched, 23 probes matched (unit test) plus live requests on the dev site · upgrade from released 1.3.3 on otm-shots with a visitor making the first request: settings, login address, two-factor user (plain secret → encrypted on first use, mixed-case recovery code) and address rules carried over, table dropped, legacy options and transients gone · lockout drills: unlock by WP-CLI, safe mode on/off · `.htaccess` rules on a real Apache 2.4: debug.log, readme/changelog and PHP in uploads → 403, normal files → 200 (the rules were tested; writing them through WordPress on an Apache-hosted site was not) · multisite on otm-ms: network activate, per-site settings, site admin refused on file and network-wide actions, deactivate, uninstall leaves nothing · real WordPress on PHP 7.4.33 and 8.0.30 · 10 screenshots, banner and icon redone · docs synced.

**Open: zip size against the 141 KB budget (§1.2) — 193 KB after the first build, 225 KB after §4.4.** By part: `includes/` 73 KB, `admin/src/` 46 KB, `admin/build/` 35 KB, `vendor/` 10 KB, readme 6 KB. Options: accept 193 KB as the baseline of the rebuild; or stop shipping `admin/src` and link the public repository in the readme (≈147 KB — against the standing rule that source ships); or cut features. Robin decides.

Checklist that was run:


PHPCS · lint · PHPUnit · build · anonymous + subscriber probe of every route · Semgrep · PHPStan · Plugin Check on a production build · PHP 7.4 compatibility · **false-positive corpus** (a crawl of a normal site, comment and contact-form posts, WooCommerce checkout, block editor saves — zero blocks) · **lockout drills** (wrong slug, lost 2FA device, own IP blocked → recover with safe mode and WP-CLI) · file-protection check on Apache and nginx · upgrade from released 1.3.3 with login URL + 2FA active · multisite lifecycle · zip ≤ 141 KB · doc sync · screenshots. Then Robin reviews, commits and tags.

### 4.4 Full security plugin: features added after the first 2.0 build (decided 2026-10-05)

Robin: "we are a security plugin" — the first build was pitched as login security only. The plugin is repositioned as a full security plugin and the gaps against the full suites (Wordfence, All-In-One Security, Kadence Security, Really Simple Security, Sucuri) are closed one by one, in this order. Everything here is free. **All 15 were built and tested on 2026-10-05.**

| # | Feature | What it is | Status |
|---|---|---|---|
| 1 | **Reposition** | Title "NHR Secure – Security, Firewall, 2FA, Login Protection & Activity Log"; tags `security, firewall, 2fa, limit login attempts, activity log`; banner and readme lead with all six areas. In-app label stays "Secure". | ✅ done |
| 2 | **Scheduled scans** | WordPress files, plugin files and the suspicious-code review run on a schedule (off / daily / weekly) in the background, with one alert per new finding. | ✅ done |
| 3 | **File change monitoring** | A fingerprint per plugin and theme (themes and plugins that WordPress.org cannot verify included). A change that did not come from an install or update is reported and alerted. | ✅ done |
| 4 | **Probe lockout** | An address that keeps requesting files that do not exist (`.php`, `.env`, backups…) is locked out of the whole site for a while. Only probe-type 404s count, so broken links and crawlers are not affected. | ✅ done |
| 5 | **More bot checks** | reCAPTCHA v2 and hCaptcha next to Turnstile. | ✅ done |
| 6 | **Trusted devices** | "Don't ask again on this browser for 30 days" on the two-factor step; listed and revocable per user. | ✅ done |
| 7 | **Password expiry and forced change** | Passwords of chosen roles expire after N days; "require a new password" for one user, a role or everyone. | ✅ done |
| 8 | **Weekly summary email** | Score, new findings, lockouts and refused requests of the week. | ✅ done |
| 9 | **Country rule scope** | Sign-in page only (default) or the whole site. Still Cloudflare's header; no GeoIP database is bundled. | ✅ done |
| 10 | **Request filter: form submissions** | Optional: also check what signed-out visitors submit, with the three rule types that do not match normal writing (traversal, stream wrappers, PHP code). | ✅ done |
| 11 | **More hardening and checks** | Switch: REST API for signed-in users only (with an allow-list for public namespaces). Checks: world-writable `wp-config.php`, default `wp_` table prefix. | ✅ done |
| 12 | **Two-factor outside wp-admin** | `[nhrrob_secure_2fa]` shortcode and a WooCommerce "My account" tab, so customers and members can enrol. | ✅ done |
| 13 | **Database scan** | Posts, options and widgets checked for injected scripts, hidden iframes and obfuscated JavaScript. A list to review. | ✅ done |
| 14 | **Passkeys** | Sign in with a passkey as the second step (WebAuthn, verified in-house, no library). | ✅ done |
| 15 | **Network Admin screen** | For multisite: every site's score and key settings in one place. | ✅ done |

**Considered and left out, with the reason:**
- **Firewall rule feed, malware signature database, live blocklist of bad addresses** — need a research team and a service.
- **Rate limiting of all requests** — needs a write per request without an object cache; the probe lockout (4) covers the abusive case.
- **Country lookup without Cloudflare** — a GeoIP database is tens of megabytes and needs a licence key.
- **Salt rotation, database prefix change** — rewriting `wp-config.php` or renaming tables from a plugin is how sites get broken; the checks report them instead.
- **Automatic malware removal** — a wrong automatic delete is worse than the finding.

**Zip size after all 15 and the storage change: 226 KB** (was 193 KB before them; 1.3.3 was 141 KB). `index.js` 89 KB, `profile.js` 15 KB.

**Gate re-run on the final code (2026-10-05):** PHPCS clean · ESLint clean · PHPUnit 27 tests / 257 assertions on PHP 8.4 and 7.4.33 · Plugin Check: no errors · Semgrep: 0 findings in 41 files · PHPStan: no errors · endpoint probe: 69 checks / 0 failures (38 routes) · multisite: Network Admin table for 4 sites, uninstall leaves nothing.

**Tested live on the dev site:** scheduled run tick by tick · file-change detection (edit, restore, accept) · probe lockout (16 broken links and images ignored, lock after the 10th probe, unlock) · REST for signed-in users only · form-data rules · trusted browser (skips the step on the same browser, asked on another) · forced password change (kept on the profile screen, cleared by a new password) · weekly summary text · database scan (planted iframe and script found) · two-factor shortcode on a front-end page · passkeys end to end in Chromium with a virtual authenticator (register, sign in, a different authenticator refused).

**Not exercised:** reCAPTCHA and hCaptcha against the live services (no keys); the WooCommerce account-page hook (WooCommerce is not on the dev site; the same render function is used by the shortcode, which was tested); passkeys on a physical device; the scheduled scan and weekly summary firing from real WP-Cron rather than being driven by hand.

### 4.5 Parity to-do: every major feature of the popular security plugins (decided 2026-10-05)

Robin: "we should have all major features. we should not be less than other plugins." This is the list of what Wordfence, All-In-One Security, Kadence Security, Really Simple Security, Sucuri and WP Activity Log have that we still lack and that can be built without a research team or a paid service. Everything is free. Built in this order; status is updated as each one lands. Each item must still pass §1.1 (off by default if it can lock out or break; verified with a real request; a way back).

**A. Setup and everyday use**

| # | Feature | What it is | Status |
|---|---|---|---|
| 1 | **One-click recommended setup** | One button on the Dashboard applies the safe recommended settings (nothing that can lock out), shows exactly what will change first, and can be undone. Restores what 1.x called "One-Click Secure". | to do |
| 2 | **Setup wizard** | First-run steps: visitor address detection, login protection, two-factor for the owner, schedule, alerts. Skippable. | to do |
| 3 | **Network-wide settings (multisite)** | A network administrator can push a settings profile to all sites or lock chosen settings. | to do |

**B. Firewall and traffic**

| # | Feature | What it is | Status |
|---|---|---|---|
| 4 | **Firewall before WordPress loads** | Optional early mode: the address rules, user-agent rules and request filter run from a small loader (`auto_prepend_file` through `.user.ini` / `.htaccess`) before WordPress and plugins start. Tested by a loopback request and removed automatically if the site stops answering. | to do |
| 5 | **Rate limiting** | Limit requests per address per minute for the sign-in page, XML-RPC, REST and search, and optionally all pages; uses the object cache when there is one, and a small capped store otherwise. | to do |
| 6 | **Live traffic** | Recent requests from signed-out visitors and bots (address, path, result, user agent), kept in a small capped ring; block or allow an address from the list. Off by default. | to do |
| 7 | **reCAPTCHA v3** | Score-based check with no challenge, next to v2, hCaptcha and Turnstile. Also offer the bot check on the comment form. | to do |
| 8 | **Blocklist import** | Paste or upload a list of addresses and ranges; export the current rules. | to do |

**C. Scanning and repair**

| # | Feature | What it is | Status |
|---|---|---|---|
| 9 | **Repair plugin files** | Replace a changed file of a WordPress.org plugin with the official copy (checksum-verified before writing, same guards as core repair). | to do |
| 10 | **Theme comparison** | Compare WordPress.org themes with their official release by downloading the release zip once per version and hashing it; repair from it. | to do |
| 11 | **Automatic security updates** | When the vulnerability check finds a fix, optionally update that plugin or theme straight away (per item opt-out; logged and emailed). | to do |
| 12 | **Abandoned software** | Flag plugins not updated for two years or not tested with the last three WordPress releases. | to do |
| 13 | **Scan more places** | `.htaccess` and `wp-config.php` for injected rules and code; `mu-plugins` and drop-ins listed explicitly; cron events that call unknown code. | to do |

**D. Hardening tools**

| # | Feature | What it is | Status |
|---|---|---|---|
| 14 | **Secret keys rotation** | Replace the salts in `wp-config.php` with new ones (signs everyone out). A backup copy is written first and the result is verified by a loopback request; restored automatically on failure. | to do |
| 15 | **Database prefix change** | Rename the tables and update `wp-config.php` and the prefix-dependent rows, behind a backup of the affected rows and a typed confirmation; verified and rolled back on failure. | to do |
| 16 | **File permissions** | List files and folders with unsafe permissions and fix them in one click. | to do |
| 17 | **HTTPS enforcement** | Force HTTPS for admin and front end, with a loopback test before it is applied; report mixed content. | to do |
| 18 | **Registration and comment protection** | Honeypot field and optional manual approval for new registrations; bot check and honeypot on comments. | to do |
| 19 | **Content protection** | Hotlink protection for images (Apache rules / nginx lines), and an option to refuse the site being shown in frames on other sites. | to do |
| 20 | **Disable unused features** | Switches for RSS/Atom feeds, the REST index for visitors, oEmbed discovery, and the `X-Powered-By` and `Server` hints where the server allows. | to do |

**E. Accounts and logging**

| # | Feature | What it is | Status |
|---|---|---|---|
| 21 | **Simultaneous-session limit** | At most N sessions per user; the oldest is ended, or the new sign-in is refused. | to do |
| 22 | **Sign-in by email link** | Optional passwordless sign-in for chosen roles: a one-time link sent to the account's email. | to do |
| 23 | **Sign-in notifications** | Email the user when their account signs in from a new browser or address. | to do |
| 24 | **Temporary access** | Create an account that expires on a date, for support staff and contractors. | to do |
| 25 | **Deeper activity log** | Posts and pages (published, changed, trashed), media, menus, widgets, comments moderation, and WooCommerce orders, products and settings when WooCommerce is active. | to do |
| 26 | **Slack and webhook alerts** | Send the existing alerts to a Slack channel or any webhook URL. | to do |
| 27 | **Reports** | A printable security report (score, findings, activity of the period) for the owner or a client. | to do |

**Still not possible without a service** (unchanged): firewall rules and malware signatures from a research team, a live blocklist of known-bad addresses, virtual patching, country lookup without Cloudflare.

**Storage:** none of these may add an option (§3). Live traffic and rate-limit counters go into `nhrrob_secure_state` (or the object cache when there is one) and must stay small.

**Cost:** every item adds to a zip that is 225 KB against the 141 KB of 1.3.3 (§4.3). The zip is measured after each item and the total reported; if the size has to come down, the first lever is not shipping `admin/src` (§4.3).

## 5. Backlog (after 2.0; all free if they ship)

- **Passkeys (WebAuthn)** as a 2FA method and passwordless login — free in Kadence Security (ex-Solid), paid in WP 2FA; needs a small in-house verifier to respect §1.2.
- File-change monitoring with a baseline for plugins that are not on WordPress.org.
- Scan of `wp_options`, widgets and posts for injected scripts and redirects (requested from the Database Cleaner PRD).
- Weekly email summary.
- Network Admin screen.
- Local country database (only if the size can be justified; today it cannot).

## 6. Decisions taken for the build (Robin said "go ahead and implement" on 2026-10-05 after seeing the mockup built on these recommendations)

1. **Name.** The slug never changes. Used: **NHR Secure – Login Security, 2FA, Limit Login Attempts & Activity Log** (in-app and menu label: **Secure**). Drops "Firewall" from the title until the request filter has earned it; adds "Limit Login Attempts", the highest-volume search term this plugin genuinely serves. Alternative if the firewall stays in the title: *NHR Secure – Login Security, 2FA, Firewall & Activity Log*.
2. **Tags (max 5).** Was: `security, hide admin, login protection, debug log, 2fa`. Used: `security, limit login attempts, 2fa, hide login, activity log`.
3. **Scope.** Used: the request filter and scanner are kept, rebuilt as §4.2-6/8 describes; country rules apply to the login page only. The alternative is to remove the request filter and suspicious-code scan entirely and ship a pure login/account security plugin (smaller, zero false-positive risk).
4. **Accent colour.** The Database Cleaner plugin owns violet/indigo. Used for Secure: teal, same token structure, so the two read as siblings but are not confused. The current banner (blue/purple, "PROTECT ADMIN AREA") and icon are redrawn either way.
5. **Version:** 2.0.0.

**Still open:** the zip size (§4.3).

## 7. Decided (don't relitigate)

- No custom tables; the audit table is migrated and dropped (§1.3).
- No runtime dependencies; no Tailwind; no react-select (§1.2).
- Legacy `NHRRob` / `nhrrob_secure_` identifiers stay (§3).
- Nothing that can lock the owner out is on by default (§1.1).
- Not a WAF and not a malware cleaner; the readme says so (§2).

## 8. Market (checked 2026-10-05 via the WordPress.org API unless noted)

| Plugin | Active installs | What it owns | Paid tier (from the vendor's pricing page) |
|---|---|---|---|
| Wordfence | 5,000,000 | WAF with rule feed, malware signatures, 2FA, login security | Premium tiers; real-time rules, IP blocklist and country blocking are paid (*pricing page did not load; not re-verified today*) |
| Really Simple Security | 3,000,000 | SSL, hardening, vulnerabilities, 2FA | $49 / $99 / $199 per year (1 / 5 / 25 sites) |
| WPS Hide Login | 2,000,000 | Login URL only | Free only |
| All-In-One Security (AIOS) | 1,000,000 | Firewall, login security, 2FA, file scan | $89 / $149 / $249 / $349 per year (2 / 10 / 35 / unlimited sites) |
| Limit Login Attempts Reloaded | 1,000,000 | Lockouts, allow/deny lists, 2FA | Country rules and cloud IP lists are paid; lifetime $104.99 / $349.99 |
| Loginizer | 1,000,000 | Lockouts, login extras | Paid tier exists (*not checked*) |
| Kadence Security (was Solid / iThemes) | 700,000 | Brute force, 2FA, passkeys, password rules | *Not checked* |
| Sucuri Security | 600,000 | Audit, integrity, hardening | Cloud WAF is a paid service (*not checked*) |
| WP Activity Log | 300,000 | Activity log | *Not checked*; alerts are a paid feature per earlier research (2026-09-27) |
| Simple History | 300,000 | Activity log | Same note |
| Admin and Site Enhancements | 200,000 | Includes login URL, limit attempts, hardening toggles | *Not checked* |
| WP 2FA | 100,000 | 2FA | Premium $79–$149/yr: per-role policies, passkeys, trusted devices, WooCommerce; Enterprise $89–$199/yr |
| Two Factor (community plugin) | 100,000 | 2FA | Free only |
| Jetpack Protect, MalCare, NinjaFirewall, Hide My WP Ghost, Anti-Malware (GOTMLS), Login Lockdown | 100,000 each | Scanning / firewall / hiding | Mixed |
| Patchstack | 60,000 | Virtual patching | From $69/month |
| WPVulnerability | 10,000 | Vulnerability list (the API we use) | Free only |
| **NHR Secure** | **< 10** | — | — |

**Reading the table.** The search terms `security`, `firewall` and `malware` are held by plugins with research teams and seven-figure installs. The reachable ground is the specialist terms where a single-purpose plugin with 1–2 M installs does one job: *limit login attempts*, *hide login*, *2FA*, *activity log*. No plugin with real traction does all four in one small, account-free package with a clean UI — that is the gap. **What we already give free that others charge for:** per-role 2FA enforcement (WP 2FA Premium), country rules (Limit Login Attempts Reloaded Business, AIOS Premium).

**Missing versus the market (all planned free, §4.2 / §5):** lockouts by IP with a manageable list · IPv6 · bot check on login · security headers · password rules and breached-password check · sessions for all users · plugin/theme integrity checks · a score based on site state · log filters, search and export · email alerts · passkeys · WP-CLI and a recovery path · multisite · settings import/export.

Sources: `https://api.wordpress.org/plugins/info/1.2/` for every slug above · https://really-simple-ssl.com/pro/ · https://teamupdraft.com/all-in-one-security/pricing/ · https://melapress.com/wordpress-2fa/pricing/ · https://www.limitloginattempts.com/plans/ · https://patchstack.com/pricing/
