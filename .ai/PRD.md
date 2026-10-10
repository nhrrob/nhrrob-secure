# PRD — Secure (Free) — slug `nhrrob-secure`

Status: **2.0.0 live on WP.org** · **2.1.0 (parity work, §4.5) built on `dev`, uncommitted, gate partly run** · earlier: **1.3.3 live on WP.org (fewer than 10 active installs)** · **2.0.0 built and verified 2026-10-05; PR #14 (dev → main) open; independent review done and fixed the same day (§4.6)** (Robin reviews, merges and tags; one gate item open: zip size, §4.3) · Owner: Nazmul Hasan Robin (nhrrob)
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
- **Rate limiting of all requests** — needs a write per request without an object cache; the probe lockout (4) covers the abusive case. *(Revisited in §4.5-5: built for sites with a persistent object cache.)*
- **Country lookup without Cloudflare** — a GeoIP database is tens of megabytes and needs a licence key.
- **Salt rotation, database prefix change** — rewriting `wp-config.php` or renaming tables from a plugin is how sites get broken; the checks report them instead. *(Revisited in §4.5: key rotation is built with a parse check, a loopback test and an automatic restore, item 14; the prefix change stays out, item 15.)*
- **Automatic malware removal** — a wrong automatic delete is worse than the finding.

**Zip size after all 15 and the storage change: 226 KB** (was 193 KB before them; 1.3.3 was 141 KB). `index.js` 89 KB, `profile.js` 15 KB.

**Gate re-run on the final code (2026-10-05):** PHPCS clean · ESLint clean · PHPUnit 27 tests / 257 assertions on PHP 8.4 and 7.4.33 · Plugin Check: no errors · Semgrep: 0 findings in 41 files · PHPStan: no errors · endpoint probe: 69 checks / 0 failures (38 routes) · multisite: Network Admin table for 4 sites, uninstall leaves nothing.

**Tested live on the dev site:** scheduled run tick by tick · file-change detection (edit, restore, accept) · probe lockout (16 broken links and images ignored, lock after the 10th probe, unlock) · REST for signed-in users only · form-data rules · trusted browser (skips the step on the same browser, asked on another) · forced password change (kept on the profile screen, cleared by a new password) · weekly summary text · database scan (planted iframe and script found) · two-factor shortcode on a front-end page · passkeys end to end in Chromium with a virtual authenticator (register, sign in, a different authenticator refused).

**Not exercised:** reCAPTCHA and hCaptcha against the live services (no keys); the WooCommerce account-page hook (WooCommerce is not on the dev site; the same render function is used by the shortcode, which was tested); passkeys on a physical device; the scheduled scan and weekly summary firing from real WP-Cron rather than being driven by hand.

### 4.5 Parity work: every major feature of the popular security plugins (decided 2026-10-05, triaged and built for 2.1.0)

Robin, 2026-10-05: "we should have all major features. we should not be less than other plugins." Then, the same day: "add all these features. make sure no duplicate feature is added. review the whole plugin features and then implement if needed. don't make the plugin garbage."

The 27 candidates below are what Wordfence, All-In-One Security, Kadence Security, Really Simple Security, Sucuri and WP Activity Log have that 2.0.0 lacked. Each one was checked against the code of 2.0.0 before anything was written, and lands in one of three groups:

- **Build** — a real gap. Free, off by default if it can lock out or break, verified with a real request (§1.1).
- **Covered** — the plugin or WordPress itself already does it. Building it again would give one action two homes (§2).
- **Not built** — it cannot pass §1.1 or §3, or it is not a security feature. The reason is written down so it is not proposed again without new facts.

Status values: `to do` · `done` (built and verified; the note says how) · `covered` · `not built`.

**A. Setup and everyday use**

| # | Feature | Decision | What is built / why not | Status |
|---|---|---|---|---|
| 1 | One-click recommended setup | Build | A card on the Dashboard lists the safe recommended settings that are still off (nothing that can lock out), each with a tick box; "Apply" switches the ticked ones on and "Undo" puts back exactly what was there. The previous values are kept in `scan.setup_undo`. | done |
| 2 | Setup wizard | Covered by 1 | A multi-step wizard would be a second home for the same switches. The setup card is the first-run step: it is the first thing on the Dashboard until it is applied or dismissed, and the visitor-address warning already sits above it. | covered |
| 3 | Network-wide settings (multisite) | Build (copy), not built (lock) | Network Admin → Secure: "Copy the settings of one site to every site" (super admin; leaves out the login address, file protection and address rules, which are per site). **Locking** settings is not built: it needs a network-level option and a locked state on every control of every screen. | done |

**B. Firewall and traffic**

| # | Feature | Decision | What is built / why not | Status |
|---|---|---|---|---|
| 4 | Firewall before WordPress loads | Not built | `auto_prepend_file` is set through `.user.ini`, which PHP caches for five minutes: the loopback test right after switching it on tests nothing, and removing the loader file inside that window (deactivate, uninstall, a deleted plugin folder) makes every PHP request fail. It can only be removed cleanly by leaving a file behind. The rules already run on `plugins_loaded`, before any plugin handles a request. | not built |
| 5 | Rate limiting | Build | Requests per address per minute for the sign-in page, XML-RPC, the REST API, search and comment posts, for visitors who are not signed in. Counted in the persistent object cache only: without one, every request would cost an option write (§3 write discipline), so the switch explains that and stays off. Answers 429 with `Retry-After`. | done |
| 6 | Live traffic | Not built | One write per page view of every visitor, which §3 forbids, for a list that is analytics rather than protection. The part that matters is already there: request-filter matches, refused requests, lockouts and the activity log. Added instead: "Block address" on a request-filter match. | not built |
| 7 | reCAPTCHA v3, bot check on comments | Build | reCAPTCHA v3 (score, no challenge) next to Turnstile, reCAPTCHA v2 and hCaptcha; an option to put the bot check on the comment form for visitors. | done |
| 8 | Blocklist import and export | Build | Paste a list of addresses and ranges (one per line) as Block or Allow; copy the current rules as a list. Rules that would block the person importing are dropped. | done |

**C. Scanning and repair**

| # | Feature | Decision | What is built / why not | Status |
|---|---|---|---|---|
| 9 | Repair plugin files | Build | Replace a changed file of a WordPress.org plugin with the official copy; the file must be in the release's checksum list and the download must match it before anything is written. | done |
| 10 | Theme comparison | Build | WordPress.org publishes no theme checksums, so the release zip is downloaded and each file compared; a theme that has not changed since it last matched is not downloaded again. Repair from the same zip. | done |
| 11 | Automatic security updates | Not built | Built and drilled on 2026-10-05 (core's `auto_update_plugin` filter, opt-in), then removed the same day: Plugin Check flags any use of that filter (`update_modification_detected`), and Robin's rule is that nothing ships that the WordPress.org review team might object to. The vulnerabilities panel links to the Updates screen instead, as before. | not built |
| 12 | Abandoned software | Build | A Dashboard check: plugins whose latest WordPress.org release was not tested with any of the last three WordPress releases. Read from the update data WordPress already holds; no extra request. "Not updated for two years" would need one request per plugin and says the same thing. | done |
| 13 | Scan more places | Build (files), not built (cron) | `.htaccess`, `.user.ini` and `wp-config.php` are checked for injected rules and code; must-use plugins and drop-ins are listed by name. **Cron events** are not checked: an event that malware scheduled looks exactly like any other, so the list would be noise. | done |

**D. Hardening tools**

| # | Feature | Decision | What is built / why not | Status |
|---|---|---|---|---|
| 14 | Secret keys rotation | Build | New keys and salts written to `wp-config.php` (signs everyone out). Only when all eight are plain strings in the file; the new file is parsed before it replaces the old one, the site is then requested and the old file is put back if it does not answer; stored two-factor secrets are re-encrypted with the new key in the same step. | done |
| 15 | Database prefix change | Not built | Table names are readable through `information_schema` by the same SQL injection the prefix is meant to hinder, so it protects against nothing. The change cannot be atomic across the database and `wp-config.php`: for a moment the site has no tables and shows the WordPress installer. The low-severity check stays and says so. | not built |
| 16 | File permissions | Build | The key files and folders with their permissions; anything writable by every account on the server is flagged and fixed in one click (only that bit is removed). Replaces the single `wp-config.php` check. | done |
| 17 | HTTPS enforcement | Covered | With an `https://` site address WordPress already redirects visitors and forces HTTPS for sign-in and the dashboard, and "Send security headers" adds HSTS. For a site still on `http://`, Site Health has core's own tested one-click switch. Added: the failing HTTPS check links there. A mixed-content report is not built: core rewrites the site's own `http://` addresses after that switch. | covered |
| 18 | Registration and comment protection | Build (honeypot), not built (approval) | A hidden field on the registration and comment forms that people never see and form-filling bots fill in. Bot check on comments is item 7. **Manual approval of new accounts** is not built: it is an account workflow, and shop and membership sign-up flows sign the new user in straight away. | done |
| 19 | Content protection | Covered / not built | Refusing frames on other sites is already part of "Send security headers" (`X-Frame-Options`). Hotlink protection is about bandwidth, not security, and its rules break images in feed readers, search results and CDNs. | not built |
| 20 | Disable unused features | Build | Switches for RSS/Atom feeds and for the discovery links in the page head (REST, oEmbed, shortlink, RSD); "Hide the WordPress version" also removes PHP's `X-Powered-By`. The REST index for visitors is already covered by "REST API for signed-in users only"; the `Server` header cannot be changed from PHP. | done |

**E. Accounts and logging**

| # | Feature | Decision | What is built / why not | Status |
|---|---|---|---|---|
| 21 | Simultaneous-session limit | Build | At most N sessions per user; the oldest is ended. "Refuse the new sign-in" is not offered: it locks out an owner whose old session is on a lost device. | done |
| 22 | Sign-in by email link | Not built | It replaces the password with access to a mailbox and adds a new sign-in path for visitors who are not signed in. Nothing in this plugin replaces the password (§7); passkeys are a second step for the same reason. | not built |
| 23 | Sign-in notifications | Build | Email the user when their account signs in on a browser it has not used before (a cookie marks known browsers, so a changed address or a browser update does not cause mail). For accounts that can edit the site. | done |
| 24 | Temporary access | Build | An expiry date on an account, set from Users: after it the account cannot sign in, its sessions end and application passwords stop working. The account is created on WordPress's own Add User screen. | done |
| 25 | Deeper activity log | Build | Optional: posts and pages (published, changed, trashed, deleted), media, menus, widgets, comment moderation and WooCommerce settings and order status changes, when done by a signed-in user. Info rows, folded per item, so they make room first when the log is full. | done |
| 26 | Slack and webhook alerts | Build | Every alert email is also posted to a webhook address (Slack-compatible `text`). | done |
| 27 | Reports | Build | A printable report from the Dashboard: score, what to fix, what passed, the week's numbers and the important activity. | done |

**Still not possible without a service** (unchanged): firewall rules and malware signatures from a research team, a live blocklist of known-bad addresses, virtual patching, country lookup without Cloudflare.

**Storage:** none of these adds an option (§3). New settings are keys of `nhrrob_secure_settings`; undo data and theme results are parts of `nhrrob_secure_scan`; rate-limit counters live in the object cache only. Two new user meta keys: `nhrrob_secure_known` (known browsers) and `nhrrob_secure_expires`.

**Verified 2026-10-05 (version 2.1.0, uncommitted on `dev`):** PHPCS clean · ESLint clean · build OK · PHPUnit 43 tests / 400 assertions · endpoint probe 91 checks / 0 failures. Live drills on otm-shots with real requests: setup apply / undo / dismiss · permissions fix · key rotation (two-factor secret still readable, only the eight lines changed) and its restore path (site made to fail, file byte-identical afterwards) · honeypot on comments and registration · comment bot check with Turnstile's test keys · feeds and head links · session limit (three sign-ins, oldest ended) · end date on an account · new-browser email · webhook payload · list import · rate limit against a real Redis (20 allowed, then 429 with `Retry-After`, pages and signed-in users untouched) · plugin and theme file repair from WordPress.org · injected `.htaccess` rules found · content log. Multisite copy on otm-ms.

**Found while drilling and fixed:** three sign-ins in the same second ended the newest session (now the new session always stays) · a default theme bundled with WordPress differs from its WordPress.org release in readme, stylesheet header and fonts, so only PHP, JavaScript and template files are compared.

**Rest of the gate, run the same day:** all eight screens opened in headless Chrome signed in as an administrator: every panel renders, no console errors; setup apply and undo, the printable report (print view hides the menus), list import and the disabled rate-limit switch were driven through the UI · PHP 7.4.33 lint of every file and the unit tests on 7.4.33 and 8.4 · production copy (`.distignore`, `composer install --no-dev`) · Plugin Check on that copy: no errors, no warnings (after item 11 was removed).

**Zip: 271 KB** (239 KB after §4.6; 1.3.3 was 141 KB). `index.js` 110 KB (was 93), `includes/` grew by seven services.

**Rule added by Robin, 2026-10-05:** "we can't add anything that review team might object. so better to skip those features." Item 11 was removed for it; Plugin Check on the production copy is then clean.

**Not done:** reCAPTCHA v3 against Google (no keys; markup and score rule only) · Semgrep and PHPStan (not installed on this machine; they run on the PR) · new screenshots for `.wordpress-org/` (the screens changed) · upgrade drill from the released 2.0.0 (no stored shape changed, so `DB_VERSION` stays 2.0.0).

### 4.7 Next release — 2.2.0: AI readiness (read-only) + PHP matrix (built 2026-10-10, unreleased)

- **Abilities API** (`Core\Abilities`, WordPress 6.9+, inert before): `nhrrob-secure/get-security-status` and `nhrrob-secure/list-vulnerabilities`, both read-only, both administrators only (the second with the Scanner section's network gate). Exposed to MCP through the WordPress MCP Adapter, which is not bundled (§1.2).
- **Deliberately not built:** any ability that changes something (settings, unlock, safe mode, scans, repairs, quarantine) — §1.1: an agent acting on a wrong or injected instruction must not be able to weaken or lock the site. And any ability that returns the login address, address rules, usernames, visitor addresses or activity rows: the output goes to the agent's AI provider. Comes back only with a concrete request and an answer to both reasons.
- **WP-CLI:** `wp nhrrob-secure status --format=json`.
- **PHP:** supported and tested 7.4 → 8.5, plus 8.6 (non-blocking until its GA). `.github/workflows/php.yml`: PHPCS with PHPCompatibilityWP, then per version a syntax check, PHPUnit and `.github/ci/smoke.php` inside a real WordPress.

## 5. Backlog (after 2.1; all free if they ship)

Built since this list was written and removed from it: passkeys, file-change monitoring, the database scan, the weekly summary and the Network Admin screen (all §4.4).

- Local country database (only if the size can be justified; today it cannot).
- Locking chosen settings network-wide (§4.5-3).
- Anything marked "not built" in §4.5 comes back only with new facts that answer the reason given there.

### 4.6 Independent review and fixes (2026-10-05)

Robin: "do a full review of the code changes on this branch. security performance etc with a different model. check if there is any blocker or major issues. find out the issue list and fix all." Two read-only reviews were run on other models: security (1 blocker, 10 major, 14 minor) and performance/correctness (2 blockers, 11 major, 15 minor). Everything below is fixed in the code and was checked with a real request or a unit test unless it says otherwise.

**Blockers**
1. **Two-factor codes could be guessed without limit.** Five tries per challenge, but a new sign-in issued a new challenge, and the challenge ran before the lockout check. Now every wrong code counts against the account (5 in 15 minutes pause its second step, doubling to 24 h, owner emailed) and against the address; the challenge refuses a locked address itself. Drill: the fifth wrong code across three fresh challenges ended it, and the right password then got "try again in 15 minutes".
2. **The admin app did not load on WordPress 6.0–6.5** (the bundle needs a script WordPress ships since 6.6; `createRoot` since 6.2). The script is now provided where it is missing and the entry files fall back to `render()`. Checked on a clean WordPress 6.0 (React 17): all eight screens and the profile setup render, no console errors. "Requires at least: 6.0" stays true.
3. **The scheduled scan cancelled itself after its first phase** (the schedule check mistook the run's own next tick for a wrong schedule). Fixed and unit tested; a phase that dies three times is skipped instead of blocking the rest.

**Major**
- A stolen session could replace the second factor → setup routes refuse while one is on; an admin cannot reset their own from the Users screen; the owner is emailed on every change.
- Multisite: signing in through a site with two-factor off skipped the step → the challenge is hooked network-wide. Scanner is for network admins only.
- Lockouts: parallel guesses lost counts (compare-and-swap `Core\Store`), a valid account could reset the count for another (per-username forgiveness), IPv6 rotation (per /64), live locks could be pushed out of the list (never pruned).
- Behind a proxy with the default setting one attacker locked out everyone → Cloudflare is recognised by its address ranges without being told; behind another local proxy nothing is counted until the owner sets it, and the Dashboard says so.
- Bot check could be used to test passwords and was skipped for two-factor users → runs before the two-factor step and answers the same either way. *(Not exercised against a live provider.)*
- Probe lockout could be triggered from another website and blocked the sign-in form → cross-site requests are not counted; the lock applies to the public site only.
- Quarantined files kept ".php" in their name (some servers still run them) → `shell_php.suspected`.
- "Hide usernames" broke the editor for editors and authors → applies to visitors only; also covers `author` sent by form post.
- Request filter: a pattern that fails to run now counts as a match; comment padding can neither hide nor stall the SQL rule (unit test with a 20,000-comment decoy).
- Refused requests cost two option writes and an activity read each → at most one write a minute per address.
- Activity log could be flushed by an attacker or a busy shop → sign-ins logged for users who can edit the site, refused-request rows capped at 200, routine rows make room first.
- Idle timeout signed out shoppers → only for users who can work in the dashboard; front-end page views count as activity.
- File-change monitor forgot everything on any update, including translations → forgets only what the update touched.
- Scan results: concurrent writers overwrote each other → per-part compare-and-swap; one vulnerability stepper at a time.
- Database scan looked at the first 500 candidate rows only → pages through all of them within 10 seconds, says so when it ran out of time.
- 1.x migration: 22 queries per visitor request on a never-opened site, a short window on default settings during migration, and an interrupted run never finished → first run stamps the version once, overlapping requests work from the 1.x settings in memory, each step can be repeated. Drill on a clean site: visitor-triggered migration, interrupted run, fresh first run.

**Minor (fixed):** six screens had no error state (endless "Loading…") · error toasts stay 12 s · failed vulnerability lookups are reported as incomplete and no longer re-announce old findings · forced password change and required two-factor no longer redirect form posts and uploads · unreadable folders and huge folders no longer end a scan · uploads check says "could not check" for a 404 on servers whose rules are not ours · deactivation no longer creates an empty `.htaccess` · uninstall clears scheduled events even when data is kept, and finds `.htaccess` when WordPress has its own directory · no translated text before `init` in the 403 page · redirect rewriting limited to this site's own `wp-login.php`, sign-in page marked not cacheable · full sentences for plugin/theme activity rows · activity byte cap enforced at every size · large form posts are not built into one string · Network Admin rows cached 5 minutes · CSV guard covers tab and carriage return · passwords set by other code (`wp_set_password`) end trusted browsers · user-agent and country rules that would shut out their author are refused · a Dashboard warning for the published 1.x default sign-in address · `password_force` could be corrupted by its sanitize case · dead `Turnstile.php` removed.

**Not changed, with the reason:** a per-username limit across all addresses (anyone could then lock the owner out by name) · setting names in "settings changed" rows stay as identifiers (a label map for ~60 keys would add size) · the 1.x login address is carried over without re-validation (keeping a working address is the point of migrating on the first request) · routes registered per user and unused CSS were raised as unconfirmed and not reproduced.

**Gate re-run on the fixed code:** PHPCS clean · ESLint clean · PHPUnit 29 tests / 304 assertions on PHP 8.4 and 7.4.33 · build OK · Plugin Check: no errors · Semgrep: 0 findings in 42 files · PHPStan: no errors · endpoint probe: 69 checks / 0 failures · live drills on otm-shots (two-factor guessing, lockout from a locked address, 20 parallel wrong passwords, request filter with decoy, probe lockout incl. cross-site, scheduled run tick by tick) · clean WordPress 6.0 on PHP 8.0 in a browser · multisite on otm-ms (network-wide challenge, scanner gate, uninstall leaves nothing). **Zip: 239 KB** (226 KB before the fixes; 1.3.3 was 141 KB).

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
