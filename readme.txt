=== NHR Secure – Security, Firewall, 2FA, Login Protection & Activity Log ===
Contributors: nhrrob
Tags: security, firewall, 2fa, limit login attempts, activity log
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress security that stays out of the way: login protection, two-factor, firewall, hardening, a scanner and an activity log.

== Description ==

NHR Secure is a complete security plugin for WordPress: it protects the sign-in form and the accounts behind it, filters hostile requests, hardens the site, scans for known vulnerabilities and changed files, and keeps a record of what happened. It is small, needs no account or cloud service, and has no upsells.

Everything lives in one screen under **Tools → Secure**, with a light and a dark theme. Changes save as you make them.

**Nothing that could lock you out is on by default**, and there is always a way back in: one line in `wp-config.php` or one WP-CLI command (see the FAQ).

= Key Features =

**Dashboard**

* A security score out of 100, built from checks of your site as it is today: known vulnerabilities, pending updates, administrators without two-factor, an `admin` username, open registration, HTTPS, debug output, secret keys, PHP version, exposed files and more.
* A "To fix" list ordered by seriousness, where each item takes you to the right setting.
* The same result appears in **Tools → Site Health**.

**Login**

* **Limit login attempts.** An address is locked out after repeated failures, with lockouts that get longer for repeat offenders. See who is locked out and unlock them with one click.
* **Move the sign-in page.** Choose your own login address; `wp-login.php` and `wp-admin` then answer "Not found" to anyone who is not signed in. The new address is tested and emailed to you before it takes effect.
* **Two-factor authentication.** Authenticator app (Google Authenticator, Authy, 1Password and others), passkeys, or emailed codes, with recovery codes. Users set it up on their profile and must prove it works before it switches on. Require it for the roles you choose, with a grace period.
* **Trusted browsers.** Optionally let users skip the second step on a browser for 7, 30 or 90 days.
* **Two-factor outside wp-admin.** The `[nhrrob_secure_2fa]` shortcode and WooCommerce's "Account details" page let customers and members enrol.
* **Generic sign-in errors**, so the form does not confirm that a username exists.
* **Bot check** with Cloudflare Turnstile, Google reCAPTCHA v2 or hCaptcha on the sign-in, register and lost-password forms (optional, with your own keys).

**Users & Sessions**

* Every user with their role, two-factor status, last sign-in and active sessions.
* Sign out one user or everyone else, reset a user's two-factor, and sign out idle users automatically.
* **Password expiry** for administrators and editors, and **"require a new password"** for one user, a role or everyone.

**Firewall**

* **Address rules** for IPv4 and IPv6, single addresses or ranges. Allowed addresses skip every rule and are never locked out.
* **Request filter** for probing requests: path traversal, hunts for config and backup files, and SQL or script fragments in the address. It starts in log-only mode so you can see what it would refuse, and any match can be allowed with one click. It checks the address of visitors who are not signed in; checking submitted forms is optional and limited to rules that normal writing cannot trigger.
* **Probe lockout.** An address that keeps asking for files that do not exist (`.php`, `.env`, backups) is locked out of the whole site. Broken links and missing images do not count.
* **Country rule** for the sign-in page or the whole site (when your site is behind Cloudflare) and **user-agent rules**.

**Hardening**

* Turn off XML-RPC, the theme and plugin file editor and application passwords; hide usernames from visitors and the WordPress version; send security headers; limit the REST API to signed-in users with a list of routes left public.
* Require strong passwords for administrators and editors, and optionally refuse passwords found in known breaches.
* Every switch says what could stop working, so you can decide.
* **File protection that is verified.** The plugin requests `debug.log`, readme files and the uploads folder from your own site and shows what came back. On Apache and LiteSpeed it can add the rules for you; on nginx it shows the lines to add.

**Scanner**

* **Known vulnerabilities** in WordPress, plugins and themes, checked daily, with one alert per new finding.
* **WordPress files** compared with the official release: changed, missing, and files that do not belong.
* **Plugin files** compared with their WordPress.org releases.
* **Code changes outside updates.** A fingerprint of every plugin and theme, including the ones WordPress.org cannot verify; a change without a new version is reported.
* **Database content** checked for invisible iframes and obfuscated JavaScript in posts and settings.
* **Suspicious code** review of every PHP file in `wp-content`. Findings can be viewed and quarantined (renamed so they cannot run) and restored. Nothing is deleted.
* **Scheduled scans**, daily or weekly, in the background, with an email when something new turns up.

**Activity**

* Sign-ins, lockouts, user and role changes, plugin and theme changes, changes to critical site settings, and what the firewall refused.
* Search, filter by type and importance, export to CSV. Bursts are folded into one entry.
* Email alerts for a new administrator, a new vulnerability, a new scan finding or a burst of lockouts, and an optional weekly summary.

**Small and tidy**

* No database tables. Everything is stored in a handful of capped options.
* No visitor is looked up with an outside service.
* Settings can be exported and imported. WP-CLI commands are included.

= What it is not =

NHR Secure has no cloud threat feed and is not a malware cleaner. The request filter runs inside WordPress, and the scanner finds things for a person to review. If your site has been hacked, ask a professional clean-up service.

== Installation ==

1. Upload the `nhrrob-secure` folder to `/wp-content/plugins/`, or install it from **Plugins → Add New**.
2. Activate the plugin.
3. Open **Tools → Secure**. The Dashboard shows what to fix first.

== Frequently Asked Questions ==

= I'm locked out. How do I get back in? =

Add this line to `wp-config.php`, above the line that says "That's all, stop editing":

`define( 'NHRROB_SECURE_SAFE_MODE', true );`

Safe mode pauses the moved login address, lockouts, the request filter, address and country rules and the two-factor step, and leaves your settings as they are. Sign in at `wp-login.php`, fix the setting, then remove the line.

With WP-CLI you can also run `wp nhrrob-secure safe-mode on`, `wp nhrrob-secure unlock --all`, `wp nhrrob-secure login-url reset` or `wp nhrrob-secure reset-2fa <user>`.

= Where are the settings? =

Under **Tools → Secure**.

= Is anything switched on when I activate the plugin? =

Limiting login attempts and generic sign-in errors are on. Everything that could lock you out or block a visitor (the moved login address, two-factor, the request filter, address and country rules, hardening switches) is off until you turn it on.

= I am updating from 1.x. What changes? =

Your settings are kept, including a moved login address and your users' two-factor setup. Two things change on purpose: the old "advanced firewall" is replaced by a smaller request filter that starts in log-only mode, and country rules now apply to the sign-in page unless you choose the whole site. The audit table from 1.x is copied into the new activity log and removed. The settings screen moved to **Tools → Secure**.

= Does two-factor work with any authenticator app? =

Yes. It uses the standard time-based codes (TOTP) that Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden and others support. The QR code is drawn in your browser; the secret is never sent to an outside service.

= A user lost their phone. What now? =

They can sign in with one of their recovery codes. Otherwise an administrator can reset their two-factor under **Tools → Secure → Users & Sessions**, or with `wp nhrrob-secure reset-2fa <user>`.

= Why does file protection say my debug log is readable? =

A file that exists is handed out by the web server before WordPress loads, so a plugin cannot guard it from PHP. On Apache and LiteSpeed, switch on "Protect these files". On nginx, add the lines shown on the Hardening screen to your server configuration, or send them to your host.

= Will the request filter block my visitors? =

It is off by default and starts in log-only mode. It looks at the address of a request, and only for visitors who are not signed in. Checking submitted forms is a separate switch that uses only the rules normal writing cannot trigger. Check the list of matches for about a week, allow anything that is yours, then switch it to Block.

= Does it work on multisite? =

Yes. Each site has its own settings, and Network Admin → Settings → Secure shows every site's score in one table. Actions that change files or end everyone's sessions need a network administrator.

= Do passkeys replace the password? =

No. A passkey is the second step after the password, like a code from an authenticator app. It needs HTTPS. Recovery codes work when the passkey is not at hand.

= How do customers set up two-factor without wp-admin? =

Put the `[nhrrob_secure_2fa]` shortcode on any page. With WooCommerce it also appears under My account → Account details.

= Does the plugin create database tables? =

No. Version 1.x created one table; 2.0 moves its contents into the activity log and removes it.

== External Services ==

The plugin works without any outside service. The connections below are made only for the feature named.

**WPVulnerability** (`www.wpvulnerability.net`) — the vulnerability check.
Sent: the slug of each installed plugin and theme, and your WordPress version. Nothing about your site, users or visitors. When: once a day, and when you press "Check now".
Service: https://www.wpvulnerability.com/ · Privacy: https://www.wpvulnerability.com/privacy/

**WordPress.org** (`api.wordpress.org`, `downloads.wordpress.org`, `core.svn.wordpress.org`) — the file comparisons.
Sent: your WordPress version and language, and the slug and version of each plugin, to fetch the official checksums; the path of a core file when you choose to replace it with the official copy. When: only when you press "Compare now" or "Replace".
Privacy: https://wordpress.org/about/privacy/

**Bot check: Cloudflare Turnstile, Google reCAPTCHA or hCaptcha** — off unless you switch it on, choose one provider and enter your own keys.
While it is on, the sign-in, register and lost-password screens load that provider's script in the visitor's browser, and the plugin sends the visitor's token and IP address to the provider to verify it.
Cloudflare Turnstile (`challenges.cloudflare.com`): Terms https://www.cloudflare.com/website-terms/ · Privacy https://www.cloudflare.com/privacypolicy/
Google reCAPTCHA (`www.google.com/recaptcha`): Terms https://policies.google.com/terms · Privacy https://policies.google.com/privacy
hCaptcha (`js.hcaptcha.com`, `api.hcaptcha.com`): Terms https://www.hcaptcha.com/terms · Privacy https://www.hcaptcha.com/privacy

**Have I Been Pwned – Pwned Passwords** (`api.pwnedpasswords.com`) — "Refuse passwords found in known breaches". Off unless you switch it on.
Sent: the first five characters of the SHA-1 hash of a password, when an administrator or editor sets one. The password itself never leaves your site.
Terms: https://haveibeenpwned.com/TermsOfUse · Privacy: https://haveibeenpwned.com/Privacy

File protection and the test of a moved login address make requests from your site to itself.

== Source Code ==

The admin app is built with `@wordpress/scripts`. The readable source is included in the plugin under `admin/src/`, and the compiled files are in `admin/build/`. The two-factor setup screen uses the MIT-licensed lean-qr library (https://github.com/davidje13/lean-qr) to draw the QR code in the browser.

== Screenshots ==

1. Dashboard: a score from real checks of your site, and what to fix first.
2. Login: attempt limits, who is locked out, the moved login address, two-factor and the bot check.
3. Users & Sessions: two-factor status and active sessions for every user.
4. Firewall: address rules and the request filter in log-only mode.
5. Hardening: each switch says what could stop working; file protection shows a tested result.
6. Scanner: known vulnerabilities, WordPress and plugin file comparison, suspicious code review.
7. Activity: search, filter and export what happened on your site.
8. Settings: visitor address detection, email alerts, data and the lockout recovery lines.
9. Two-factor setup on the user's profile.
10. Dark theme.

== Changelog ==

= 2.0.0 - 05/10/2026 =
- New: a rebuilt admin screen under Tools → Secure with eight sections, light and dark themes, and settings that save as you change them.
- New: security score out of 100 from checks of the site itself, also shown in Site Health.
- New: lockouts by address with a list you can unlock from, longer lockouts for repeat offenders, and optional emails.
- New: two-factor setup that requires a working code, an attempt limit on the code form, per-user choice of app or email, encrypted secrets, and a grace period for required roles.
- New: passkeys as a second step, trusted browsers, and two-factor setup outside wp-admin (shortcode and WooCommerce account page).
- New: password expiry and "require a new password" for a user, a role or everyone.
- New: scheduled scans, file-change monitoring for every plugin and theme, and a database content check.
- New: probe lockout, optional checking of submitted forms, REST API for signed-in users only, and reCAPTCHA and hCaptcha next to Turnstile.
- New: weekly summary email and a Network Admin overview for multisite.
- New: Users & Sessions screen for all users.
- New: IPv6 and ranges in address rules; a request filter with a log-only mode; a country rule for the sign-in page or the whole site.
- New: more hardening switches, security headers, password rules and an optional breached-password check.
- New: file protection that is tested against your own site, with rules for Apache/LiteSpeed and lines to copy for nginx.
- New: plugin file comparison, a resumable suspicious-code review with quarantine, and vulnerability alerts sent once per finding.
- New: activity search, filters and CSV export; email alerts; settings import and export.
- New: safe mode (`NHRROB_SECURE_SAFE_MODE`) and WP-CLI commands (`wp nhrrob-secure`).
- New: multisite support.
- Changed: the moved login address is off for new installs and must be chosen by you. Existing installs keep theirs.
- Changed: the "advanced firewall" is replaced by the request filter, which starts in log-only mode after the update.
- Changed: country rules use the country reported by Cloudflare and apply to the sign-in page unless you choose the whole site.
- Changed: the plugin no longer creates a database table; the audit table is migrated and removed.
- Fixed: a fatal error on PHP older than 8.2. The plugin has no bundled PHP library any more and runs on PHP 7.4 and later.
- Fixed: one failed sign-in was counted twice.
- Fixed: the firewall refused ordinary requests such as searches containing "mini" or addresses with a double hyphen.
- Fixed: the address recorded in the log could be faked with a request header.
- Fixed: file repair and delete accepted paths outside their folder.
- Fixed: the code scan flagged normal code and stopped after 2,000 files.
- Fixed: the core file check reported removed bundled themes and plugins as missing.
- Fixed: the idle timeout did not sign out a user with an open tab.
- Fixed: uninstall left options and user data behind.
- Removed: the QR code and visitor country lookups through outside services.
- Developers: the `nhrrob-secure/menu/capability` filter is now `nhrrob_secure_menu_capability`.

= 1.3.3 - 25/09/2026 =
- WordPress tested up to version is updated to 7.1

= 1.3.2 - 09/05/2026 =
- WordPress tested up to version is updated to 7.0
- Few minor bug fixes & improvements

= 1.3.1 - 07/02/2026 =
- Fixed: Forced logout issue for 2FA users

= 1.3.0 - 28/01/2026 =
- Added: Security Health Check with scoring system (A+ to F grade)
- Added: One-Click Secure feature to apply recommended settings instantly
- Added: Advanced Firewall (IPS) with real-time protection against SQL Injection, XSS, and LFI attacks
- Added: IP Management with Whitelist and Blacklist (CIDR support)
- Added: Country Blocking for 90+ countries using GeoIP lookup with caching
- Improved: Dark mode styling for all components
- Improved: Overall security dashboard UI/UX

= 1.2.0 - 17/01/2026 =
- Added: User Session Management (View active sessions, remote logout, idle timeout)
- Added: Hardening & Firewall (Disable XML-RPC, File Editor, Version Hiding, User Enumeration)
- Added: User-Agent Blocking
- Added: Audit Logs for security events
- Fixed: Dark mode improvements
- Improved: UI enhancements

= 1.1.0 - 13/01/2026 =
- Added: Vulnerability Checker
- Added: File Scanner to check file integrity
- Improved: UI for scan results
- Few minor bug fixing & improvements

= 1.0.6 - 11/01/2026 =
- Fixed: Fatal error due to missing vendor files

= 1.0.5 - 11/01/2026 =
- Added: Email OTP feature
- Added: Recovery codes for 2FA
- Added: Enforce 2FA for specific roles
- Added: Dark mode support
- Few minor bug fixing & improvements

= 1.0.4 - 09/01/2026 =
- Added: Modern React-powered settings page under Tools → NHR Secure
- Added: Enable/disable all features from admin interface
- Added: Configurable login attempts limit (1-20)
- Added: Customizable login page URL from settings
- Added: Two-factor authentication (2FA) feature

= 1.0.3 - 05/01/2026 =
- Added: Custom login page.
- Added: Hide debug log.

= 1.0.2 - 04/12/2025 =
- Initial release. Cheers!!
- Added plugin assets (icons, banners & screenshot).
- Fixed fatal error related to function name.

= 1.0.1 - 30/11/2025 =
- Few minor bug fixing & improvements

= 1.0.0 - 23/10/2025 =
- Initial beta release. Cheers!

== Upgrade Notice ==

= 2.0.0 =
A rebuilt plugin. Your settings, login address and two-factor users are kept. The old firewall is replaced by a request filter that starts in log-only mode. The settings screen is now under Tools → Secure.
