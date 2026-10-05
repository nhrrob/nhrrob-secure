# NHR Secure — project notes

Slug `nhrrob-secure` · display name "NHR Secure – Security, Firewall, 2FA, Login Protection & Activity Log" · in-app and menu label **Secure** (Tools → Secure; never "NHR" in the UI).

Planning docs (dev-only, never shipped): `.ai/PRD.md` (free scope + the 1.3.3 audit), `.ai/PRD-PRO.md`, `.ai/DESIGN.md`, `.ai/design/mockup.html`, `.ai/design/brand/` (banner + icon SVG sources).

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
  Core/     Settings, Ip, Activity, Alerts, Upgrade, Bootstrap, Module, ModuleRegistry
  Services/ LoginGuard, LoginUrl, BotCheck, Totp, TwoFactor, Passkeys, Passwords, Sessions, Firewall,
            Hardening, FileProtection, Scan, Vulnerabilities, Integrity, Monitor, DatabaseScan, CodeScan,
            Schedule, Summary, Checks, EventLogger
  Rest/     RestController (base), SettingsController, SecurityController, ScannerController, TwoFactorController
  Admin/    AppPage (Tools → Secure, enqueue, boot data), NetworkPage (multisite overview, server-rendered)
  Cli/      Commands (wp nhrrob-secure …)
  Interfaces/ModuleInterface
admin/src/                 React source: index.js, app.js, api.js, components/, screens/, style.scss, profile.js(+scss)
admin/build/               compiled output (ships)
tests/                     PHPUnit + WP_Mock
.github/workflows/         plugin-check.yml, security.yml (PR checks), two deploy workflows
.github/security/          endpoint-probe.php, probe.py, phpstan.neon
```

## Stored data (all options; only the first is autoloaded)

| Option | Holds | Cap |
|---|---|---|
| `nhrrob_secure_settings` (autoloaded) | every setting + `db_version` | fixed keys |
| `nhrrob_secure_activity` | activity rows, newest first (`t,u,k,a,l,i,s,n,d`) | 1,000 rows / 256 KB / retention days |
| `nhrrob_secure_state` | hot, small data written under attack — `lockouts` (per address: `c,u,l,x,v` + `q,ql,p` for probe lockouts), `filter_log`, `blocked` (per day) | 300 addresses / 100 rows / 7 days |
| `nhrrob_secure_scan` | cold, large data — last result per check: `vuln`, `vuln_run`, `core`, `plugins`, `plugins_run`, `files`, `monitor`, `database`, `code` (code-scan queue + findings), `scheduled*` | lists capped; 200 code findings |

**Four options, no more** (Robin, 2026-10-05: "goal is to use less options"). New features store into `state` (if written per request or per failed sign-in — keep it small) or `scan` (if large and written rarely) through `Core\State` and `Services\Scan`; they do not add an option. `state` and `scan` are separate on purpose: merging them would make every failed sign-in rewrite the scan results.

User meta: `nhrrob_secure_2fa_enabled|method|secret|recovery_codes|pending|last_step|due|trusted`, `nhrrob_secure_passkeys`, `nhrrob_secure_pw_changed|pw_must`, `nhrrob_secure_last_login`, `nhrrob_secure_last_activity`. Transients: `nhrrob_secure_2fa_{md5}` (sign-in challenge, 10 min), `nhrrob_secure_pk_{id}` (passkey registration challenge), `nhrrob_secure_pw_{id}`, `nhrrob_secure_alert_{md5}`. Cookie: `nhrrob_secure_trust_{COOKIEHASH}` (trusted browser). Cron: `nhrrob_secure_vulnerability_check` (daily, reschedules itself per batch), `nhrrob_secure_scan` (daily/weekly per `scan_schedule`, walks its phases one tick a minute), `nhrrob_secure_summary` (weekly, when on).

A change of stored shape needs a migration: bump `NHRRob_Secure::DB_VERSION` and add the step to `Core\Upgrade::run()`. An install coming from 1.x migrates on its first request of any kind; later bumps wait for admin/cron/CLI.

## REST routes (`nhrrob-secure/v1`)

Gate `can_manage` = `manage_options`. `can_manage_files` adds "super admin on multisite". `can_repair` adds `update_core`.

- `GET /dashboard` · `GET|POST /settings` · `POST /settings/import` · `GET /login` · `POST /login/unlock`
- `GET /users` (also needs `list_users`) · `POST /users/{id}/signout`, `/reset-2fa` and `/force-password` (per-object `edit_user`) · `POST /users/force-password` (role or everyone; needs `edit_users`) · `POST /users/signout-all` (files gate)
- `GET /firewall` · `POST|DELETE /firewall/rules`
- `GET /hardening` · `POST /hardening/check`
- `GET /activity` · `GET /activity/export`
- `GET /scanner` · `POST /scanner/vulnerabilities|plugins|monitor|code` (stepped by the browser) · `POST /scanner/database` · `POST /scanner/monitor/accept` (files gate) · `POST /scanner/core` · `POST /scanner/core/repair` (repair gate) · `POST /scanner/code/view` · `POST /scanner/code/quarantine|restore` (files gate)
- `GET /2fa` · `POST /2fa/begin|confirm|passkey|disable|recovery|forget-browsers` — any signed-in user, own account only, only while two-factor is on; `disable` and `recovery` re-check the password.

## Invariants (do not weaken)

- `Settings::update()` writes known keys only, each through `sanitize()`. Internal keys (`db_version`, `safe_mode`, `request_filter_since`, `ip_rules`) are never writable from `/settings`.
- A block rule that matches the requester's own address is refused (`SecurityController::add_rule`, and import drops such rules).
- Moving the login address: slug validated (`Settings::slug_problem`), pretty permalinks required, tested with a loopback request and **reverted if the form does not appear**, then emailed.
- File actions never take a free path: core repair only for files in the official checksum list **and** only when the download matches that checksum; quarantine/restore only for paths in the scan's own findings/quarantine lists, resolved with `realpath` inside `wp-content`.
- `.htaccess` rules are removed again if the home page answers 5xx after writing them, on deactivation and on uninstall.
- Two-factor: setup needs a working code; challenge allows 5 tries then counts as a failed sign-in; TOTP steps are single-use; secrets are stored `v1:`-encrypted (sodium secretbox, key from `wp_salt('auth')`); 1.x plain secrets are read and encrypted on first use.
- The request filter inspects path and query string of signed-out visitors. Request bodies are looked at only when `filter_forms` is on, and then only with the `traversal`, `wrapper` and `code` rules (`Firewall::match_body`) — never the SQL or script rules, which normal writing can match.
- Probe lockout counts only 404s whose path looks like a file hunt (`Firewall::is_probe_path`); pages, images and assets never count.
- Passkeys (`Services\Passkeys`): no library. Every sign-in checks type, challenge, origin, RP-ID hash, user-present flag, signature (OpenSSL) and that the counter moved forward. Verified against Node-generated vectors in `tests/fixtures/passkey.json` (regenerate with `node tests/fixtures/make-passkey-vectors.js`). A passkey is a second step, never a password replacement.
- A new password clears trusted browsers and the must-change flag (`Passwords::mark_changed`).
- `Monitor` keeps a changed item's old fingerprint until the owner accepts the change; an install or update clears all fingerprints (`upgrader_process_complete`).
- `Ip::resolve()` believes a forwarded header only from Cloudflare's ranges (cloudflare mode) or a trusted/local proxy (proxy mode).

## Add-on API

PHP filters `nhrrob_secure_modules`, `nhrrob_secure_app_boot`, `nhrrob_secure_checks`, `nhrrob_secure_activity_describe`, `nhrrob_secure_cloudflare_ranges`, `nhrrob_secure_menu_capability`; action `nhrrob_secure_app_enqueued` (script handle `nhrrob-secure-index`). JS: `window.nhrrobSecure = { components, useToast, useConfirm, registerIcons }` and the `nhrrobSecure.screens` filter.

## Recovery

`define( 'NHRROB_SECURE_SAFE_MODE', true );` or `wp nhrrob-secure safe-mode on` pauses the login address, lockouts, request filter, address/country rules and the two-factor step. Other commands: `status`, `unlock <ip>|--all`, `login-url reset`, `reset-2fa <user>`.

## Commands

```
npm run build          # admin/build
npm run lint           # ESLint (text domain enforced in .eslintrc.js)
composer run phpcs     # WordPress Coding Standards
composer run test:unit # PHPUnit: filter corpus, TOTP vectors, address rules, lockouts, signatures, score
```

`typescript` is pinned to `~6.0` in `package.json` only because the lint plugin does not load with 7.x.

## Release gate (run all before a release; see `.ai/skills/release_plugin.md`)

PHPCS · lint · PHPUnit · build · production copy (`rsync --exclude-from=.distignore`, `composer install --no-dev`) · Plugin Check on that copy · Semgrep `p/php` · PHPStan (`.github/security/phpstan.neon`) · endpoint probe with `--self-service /2fa`, run from inside the installed copy and regression-tested against a deliberately broken gate · PHP 7.4 lint + unit tests · upgrade from the released version on a throwaway site with a visitor making the first request · lockout drills (wrong slug, lost 2FA, own address blocked → safe mode) · multisite activate/deactivate/uninstall · zip size · doc sync (readme Key Features, this file, PRD, DESIGN) · screenshots.

Throwaway sites used for this: `~/Sites/otm-shots` (single site, PHP 8.0; demo data seeded for screenshots) and `~/Sites/otm-ms` (multisite). Never run the probe or seed scripts on a site with real data.
