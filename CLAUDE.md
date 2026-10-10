# NHR Secure — project notes

Slug `nhrrob-secure` · display name "NHR Secure – Security, Firewall, 2FA, Login Protection & Activity Log" · in-app and menu label **Secure** (Tools → Secure; never "NHR" in the UI).

Planning docs (dev-only, never shipped): `.ai/PRD.md` (free scope, the 1.3.3 audit, and §4.5: what was built for 2.1 and what was deliberately left out — read it before proposing a feature), `.ai/PRD-PRO.md`, `.ai/DESIGN.md`, `.ai/design/mockup.html`, `.ai/design/brand/` (banner + icon SVG sources).

## Rules that are specific to this plugin

1. **A security plugin must not make the site less safe or less reachable.** Anything that can lock the owner out or block a visitor is off by default, and safe mode must switch it off. Verify a protection with a real request, not by reading the code.
2. **Legacy identifiers stay**: namespace `NHRRob\Secure\`, class `NHRRob_Secure`, constants `NHRROB_SECURE_*`, option/meta/hook prefix `nhrrob_secure_`, CSS prefix `nhrrob-secure-`, REST namespace `nhrrob-secure/v1`, JS globals `nhrrobSecureApp` / `nhrrobSecure`.
3. **No database tables.** No runtime PHP dependencies (`vendor/` is the autoloader only). No JS/CSS framework beyond `@wordpress/scripts`; `lean-qr` (MIT, profile bundle only) is the one bundled library.
4. **No PRO wording or surface** anywhere in the plugin. Add-ons use the neutral API below.
5. **Every external call is disclosed** in `readme.txt` → External Services, is optional, and never carries a secret or visitor data. No per-visitor remote lookups.
6. **One client address**: always `Core\Ip::client()`. Never read `REMOTE_ADDR` or forwarded headers anywhere else.
7. **Write discipline under attack**: a failed sign-in or refused request costs at most one small option write. Never one row per request (`Activity::record()` with `coalesce`).

## Layout

```
nhrrob-secure.php          main class, constants, activation, maybe_upgrade(), crons
uninstall.php              per-site cleanup (respects delete_on_uninstall), user meta, .htaccess block
includes/
  Core/     Settings, Ip, Activity, State, Store, Alerts, Upgrade, Bootstrap, Module, ModuleRegistry, Abilities
  Services/ LoginGuard, LoginUrl, BotCheck, Honeypot, Totp, TwoFactor, Passkeys, Passwords, Sessions, Access,
            Firewall, RateLimit, Hardening, FileProtection, Permissions, Salts, Scan, Vulnerabilities,
            Integrity, Monitor, DatabaseScan, CodeScan, Schedule, Summary, Checks, Setup, EventLogger
  Rest/     RestController (base), SettingsController, SecurityController, ScannerController, TwoFactorController
  Admin/    AppPage (Tools → Secure, enqueue, boot data), NetworkPage (multisite overview and "copy one site's settings to all", server-rendered)
  Cli/      Commands (wp nhrrob-secure …)
  Interfaces/ModuleInterface
admin/src/                 React source: index.js, app.js, api.js, components/ (incl. Report.js, the printable report), screens/, style.scss, profile.js(+scss)
admin/build/               compiled output (ships)
tests/                     PHPUnit + WP_Mock
.github/workflows/         plugin-check.yml, security.yml, php.yml (PR checks), two deploy workflows
.github/security/          endpoint-probe.php, probe.py, phpstan.neon
.github/ci/                smoke.php (runtime smoke test, used by php.yml)
```

## Stored data (all options; only the first is autoloaded)

| Option | Holds | Cap |
|---|---|---|
| `nhrrob_secure_settings` (autoloaded) | every setting + `db_version` | fixed keys |
| `nhrrob_secure_activity` | activity rows, newest first (`t,u,k,a,l,i,s,n,d`) | 1,000 rows / 256 KB / retention days |
| `nhrrob_secure_state` | hot, small data written under attack — `lockouts` (per address, or per /64 for IPv6: `c,u,l,x,v` for sign-in + `q,ql,px,pv` for probe lockouts), `filter_log`, `blocked` (per day), `denied` (last counted refusal per address) | 300 addresses / 100 rows / 7 days |
| `nhrrob_secure_scan` | cold, large data — last result per check: `vuln`, `vuln_run`, `core` (with `config` findings and `loaders`), `plugins`, `plugins_run`, `themes` (with `clean`: version and fingerprint of themes that matched), `themes_run`, `files`, `monitor`, `database`, `code` (code-scan queue + findings), `scheduled*`, `setup` (undo values of the recommended setup, or `dismissed`) | lists capped; 200 code findings |

**Four options, no more** (Robin, 2026-10-05: "goal is to use less options"). New features store into `state` (if written per request or per failed sign-in — keep it small) or `scan` (if large and written rarely) through `Core\State` and `Services\Scan`; they do not add an option. `state` and `scan` are separate on purpose: merging them would make every failed sign-in rewrite the scan results.

Rate-limit counters are **not stored**: they live in the persistent object cache (group `nhrrob_secure_rate`, two-minute keys), and the feature cannot be switched on without one.

User meta: `nhrrob_secure_2fa_enabled|method|secret|recovery_codes|pending|last_step|due|trusted|fails`, `nhrrob_secure_passkeys`, `nhrrob_secure_pw_changed|pw_must`, `nhrrob_secure_last_login`, `nhrrob_secure_last_activity`, `nhrrob_secure_known` (hashes of browsers the account has used, for sign-in notifications), `nhrrob_secure_expires` (end date of temporary access). Transients: `nhrrob_secure_2fa_{md5}` (sign-in challenge, 10 min), `nhrrob_secure_pk_{id}` (passkey registration challenge), `nhrrob_secure_pw_{id}`, `nhrrob_secure_alert_{md5}`, `nhrrob_secure_vuln_lock` (one stepper at a time); site transient `nhrrob_secure_network` (Network Admin rows, 5 min). Cookies: `nhrrob_secure_trust_{COOKIEHASH}` (trusted browser), `nhrrob_secure_known_{COOKIEHASH}` (known browser, one year). Cron: `nhrrob_secure_vulnerability_check` (daily, reschedules itself per batch), `nhrrob_secure_scan` (daily/weekly per `scan_schedule`, walks its phases one tick a minute), `nhrrob_secure_summary` (weekly, when on).

A change of stored shape needs a migration: bump `NHRRob_Secure::DB_VERSION` and add the step to `Core\Upgrade::run()`. An install coming from 1.x migrates on its first request of any kind; later bumps wait for admin/cron/CLI.

## REST routes (`nhrrob-secure/v1`)

Gate `can_manage` = `manage_options`. `can_manage_files` adds "super admin on multisite". `can_repair` adds `update_core`. On multisite the whole Scanner section (module capability `manage_network`, every route behind `can_manage_files`) is for network admins: plugin, theme and core files are shared by all sites.

- `GET /dashboard` · `GET|POST /settings` · `POST /settings/import` · `POST /settings/test-alert` · `POST /setup`, `/setup/undo`, `/setup/close` (recommended setup) · `GET /login` · `POST /login/unlock`
- `GET /users` (also needs `list_users`) · `POST /users/{id}/signout`, `/reset-2fa` and `/force-password` (per-object `edit_user`) · `POST /users/force-password` (role or everyone; needs `edit_users`) · `POST /users/{id}/expiry` (per-object `edit_user`; refuses the caller's own id) · `POST /users/signout-all` (files gate)
- `GET /firewall` · `POST|DELETE /firewall/rules` · `POST /firewall/rules/import` (pasted list)
- `GET /hardening` (file protection, permissions, whether the keys can be rotated) · `POST /hardening/check` · `POST /hardening/permissions` and `POST /hardening/keys` (files gate)
- `GET /activity` · `GET /activity/export`
- `GET /scanner` · `POST /scanner/vulnerabilities|plugins|themes|monitor|code` (stepped by the browser) · `POST /scanner/plugins/repair` (adds `update_plugins`) · `POST /scanner/themes/repair` (adds `update_themes`) · `POST /scanner/database` · `POST /scanner/monitor/accept` (files gate) · `POST /scanner/core` · `POST /scanner/core/repair` (repair gate) · `POST /scanner/code/view` · `POST /scanner/code/quarantine|restore` (files gate)
- `GET /2fa` · `POST /2fa/begin|confirm|passkey|disable|recovery|forget-browsers` — any signed-in user, own account only, only while two-factor is on; `disable` and `recovery` re-check the password.

## Abilities (AI agents, MCP)

`Core\Abilities`, WordPress 6.9+ (the `wp_abilities_api_*` hooks only fire when something asks for the registry). Category `nhrrob-secure`, flagged `public` + `show_in_rest` + `mcp.public` so the WordPress MCP Adapter (not bundled) exposes them.

- `nhrrob-secure/get-security-status` (gate `can_manage`): score, safe mode, every check without its `fix` link, and the Dashboard counts. Reads only: unlike `GET /dashboard` it never starts the file-protection check.
- `nhrrob-secure/list-vulnerabilities` (gate `can_manage_files`, the Scanner section's): the stored result of the last check; never starts one.

**Read-only, and it stays that way** (rule 1): no ability changes a setting, unlocks an address, runs a scan or touches a file. **Nothing an ability returns may identify how to reach or attack the site**, because the output goes to the agent's AI provider: no login address or slug, address rules, usernames, visitor addresses, activity rows, file paths from scans or settings. `tests/AbilitiesTest.php` pins the list, the gates and the read-only annotation; a new ability also needs the readme FAQ and PRD §4.7 updated.

## Invariants (do not weaken)

- `Settings::update()` writes known keys only, each through `sanitize()`. Internal keys (`db_version`, `safe_mode`, `request_filter_since`, `ip_rules`) are never writable from `/settings`.
- A block rule that matches the requester's own address is refused (`SecurityController::add_rule`, and import drops such rules).
- Moving the login address: slug validated (`Settings::slug_problem`), pretty permalinks required, tested with a loopback request and **reverted if the form does not appear**, then emailed.
- File actions never take a free path: core repair only for files in the official checksum list **and** only when the download matches that checksum; quarantine/restore only for paths in the scan's own findings/quarantine lists, resolved with `realpath` inside `wp-content`.
- Plugin and theme repair follow the same rule: the plugin or theme must be installed, the file must be in that release (`validate_file` first), a plugin download must match the release's checksum, and a theme file comes out of the release zip from `downloads.wordpress.org`. Theme comparison looks at PHP, JavaScript and template files only: the copy of a default theme bundled with WordPress differs from WordPress.org in readme, stylesheet header and fonts.
- **Key rotation** (`Services\Salts`) only replaces the eight values when each is a plain string defined exactly once; the new file must parse (`token_get_all( …, TOKEN_PARSE )`), is swapped in with `rename()`, and the old one is put back if the home page then answers 5xx. Two-factor secrets are encrypted with a key made from `AUTH_KEY . AUTH_SALT`, so they are re-encrypted for the new values in the same step. **Anything else that changes the salts (`wp config shuffle-salts`, a manual edit) makes stored app secrets unreadable**; those users reset two-factor.
- The permissions fix removes the "others may write" bit and nothing else, and only for the fixed list in `Permissions::paths()`.
- Rate limiting counts in the object cache only, signed-out visitors only, and never ordinary page views (`RateLimit::bucket`).
- The session limit ends the oldest sessions; the session just created always stays (`Sessions::newest( …, $keep )`), also when several sign-ins share a second.
- Temporary access: an end date cannot be put on the caller's own account; after it, `authenticate` (40) refuses, `init` ends live sessions and application passwords are unavailable.
- The recommended setup (`Services\Setup`) may only contain settings that cannot lock anyone out or turn a visitor away.
- Content logging (`log_content`) records only what a signed-in user did, as info rows folded per item and hour.
- `.htaccess` rules are removed again if the home page answers 5xx after writing them, on deactivation and on uninstall.
- Two-factor: setup needs a working code. **Every** wrong code counts twice: against the address (`LoginGuard::register_failure`) and against the account (`nhrrob_secure_2fa_fails`; 5 in 15 minutes pause that account's second step, 15 min doubling to 24 h, and email its owner) — a new challenge never buys new guesses. The challenge (authenticate 50) checks the address lock and the account hold itself, because it exits before `LoginGuard` (100); the bot check runs at 45 and answers the same for a right and a wrong password. A second step that is on cannot be replaced: `/2fa/begin|confirm|passkey` answer 409 until it is switched off (password needed), and `/users/{id}/reset-2fa` refuses the caller's own id. On multisite the challenge is hooked on every site, whatever that site's `twofa_enabled` says (enrolment is user meta, shared by the network). The challenge only starts when a password was submitted; TOTP steps are single-use; secrets are stored `v1:`-encrypted (sodium secretbox, key from `wp_salt('auth')`); 1.x plain secrets are read and encrypted on first use.
- The request filter inspects path and query string of signed-out visitors. Request bodies are looked at only when `filter_forms` is on, and then only with the `traversal`, `wrapper` and `code` rules (`Firewall::match_body`) — never the SQL or script rules, which normal writing can match.
- Probe lockout counts only 404s whose path looks like a file hunt (`Firewall::is_probe_path`); pages, images and assets never count.
- Passkeys (`Services\Passkeys`): no library. Every sign-in checks type, challenge, origin, RP-ID hash, user-present flag, signature (OpenSSL) and that the counter moved forward. Verified against Node-generated vectors in `tests/fixtures/passkey.json` (regenerate with `node tests/fixtures/make-passkey-vectors.js`). A passkey is a second step, never a password replacement.
- A new password clears trusted browsers and the must-change flag (`Passwords::mark_changed`).
- `Monitor` keeps a changed item's old fingerprint until the owner accepts the change; an install or update forgets **only the items it touched** (`Monitor::touched()`; a translation or core update forgets nothing).
- `Ip::resolve()` believes a forwarded header only from Cloudflare's ranges (cloudflare **and** direct mode: a request from a Cloudflare address is Cloudflare) or a trusted/local proxy (proxy mode). When `ip_source` is `direct`, the request comes from a private address and carries a forwarded header, nothing is counted (`LoginGuard::address_is_shared()`) and the Dashboard says so.
- Counters are never read-modify-written with `update_option`: `Core\Store::mutate()` (compare-and-swap) is behind `State`, `Scan::set()` and `Activity::record()`, so parallel requests cannot lose a failed sign-in or overwrite another part.
- Lockouts: a successful sign-in forgives only its own username (`LoginGuard::forgive`); a running lock is never pruned; a probe lock (`px`) keeps an address off the public site at `init`, never off wp-login.php or a signed-in user, and cross-site requests (`Sec-Fetch-Site`) are not counted.
- The request filter treats a pattern that fails to run as a match (never fail open) and uses atomic groups for comment runs.
- A quarantined file's name keeps no `.php` (`CodeScan::quarantine_name`): `shell.php` → `shell_php.suspected`.
- Activity log: sign-ins/sign-outs only for users with `edit_posts`; refused-request rows capped at 200; when full, info rows go before warnings and criticals. The idle timeout also applies only to users with `edit_posts`.
- `Schedule::sync()` reads the recurring event only (`Schedule::recurrence`); a run's one-off tick must not be mistaken for the schedule. A phase that dies three times is skipped.
- The bundles need the `react-jsx-runtime` handle (WordPress 6.6+); `AppPage::jsx_runtime()` provides it on 6.0–6.5, and the entry files fall back to `render()` where `createRoot` is missing. Verified on a clean WordPress 6.0.

## Add-on API

PHP filters `nhrrob_secure_modules`, `nhrrob_secure_app_boot`, `nhrrob_secure_checks`, `nhrrob_secure_activity_describe`, `nhrrob_secure_cloudflare_ranges`, `nhrrob_secure_menu_capability`; action `nhrrob_secure_app_enqueued` (script handle `nhrrob-secure-index`). JS: `window.nhrrobSecure = { components, useToast, useConfirm, registerIcons }` and the `nhrrobSecure.screens` filter.

## Recovery

`define( 'NHRROB_SECURE_SAFE_MODE', true );` or `wp nhrrob-secure safe-mode on` pauses the login address, lockouts, request filter, address/country rules and the two-factor step. Other commands: `status`, `unlock <ip>|--all`, `login-url reset`, `reset-2fa <user>`.

## Commands

```
npm run build          # admin/build
npm run lint           # ESLint (text domain enforced in .eslintrc.js)
composer run phpcs     # WordPress Coding Standards
composer run test:unit # PHPUnit: filter corpus, TOTP vectors, address rules, lockouts, signatures, score, review fixes, 2.1 decisions (ParityTest), abilities
wp eval-file .github/ci/smoke.php   # inside a WordPress install: every GET route and read-only ability, fails on any PHP notice from the plugin
```

**PHP support: 7.4 and every later version, tested through 8.6.** `composer.json` pins `config.platform.php` to 7.4.33 so dev dependencies resolve to versions that run on every supported PHP. `composer run phpcs` includes the `PHPCompatibilityWP` ruleset (`testVersion` 7.4-). `.github/workflows/php.yml` runs on every PR: PHPCS, then per PHP version (7.4–8.5 required, 8.6 non-blocking until its GA) a syntax check, PHPUnit and `.github/ci/smoke.php` in a real WordPress. When a new PHP version reaches GA, move it from `include` into the `php` list and add the next one as experimental.

`vendor/` in git is the **production** autoloader (plain PSR-4, no dev packages). `composer install` to run the tests rewrites `vendor/composer/*`; put it back with `git checkout -- vendor` before committing.

`typescript` is pinned to `~6.0` in `package.json` only because the lint plugin does not load with 7.x.

## Release gate (run all before a release; see `.ai/skills/release_plugin.md`)

PHPCS · lint · PHPUnit · build · production copy (`rsync --exclude-from=.distignore`, `composer install --no-dev`) · Plugin Check on that copy · Semgrep `p/php` · PHPStan (`.github/security/phpstan.neon`) · endpoint probe (REST routes and abilities) with `--self-service /2fa`, run from inside the installed copy and regression-tested against a deliberately broken gate · PHP 7.4–8.6 syntax check, unit tests and smoke test (the **PHP Compatibility** workflow, `php.yml`, green on the PR) · upgrade from the released version on a throwaway site with a visitor making the first request · lockout drills (wrong slug, lost 2FA, own address blocked → safe mode) · multisite activate/deactivate/uninstall · zip size · doc sync (readme Key Features, this file, PRD, DESIGN) · screenshots.

Throwaway sites used for this: `~/Sites/otm-shots` (single site, PHP 8.0; demo data seeded for screenshots) and `~/Sites/otm-ms` (multisite). Never run the probe or seed scripts on a site with real data.
