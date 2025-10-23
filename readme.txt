=== NHR Secure ===
Contributors: nhrrob
Tags: security, admin, login, debug, protection, limit
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A lightweight WordPress security plugin that protects your admin area, blocks access to debug logs, and limits login attempts.

== Description ==

Keep your WordPress site safe with minimal effort. NHR Secure helps you:

- Hide or protect your admin area from unauthorized access.
- Block access to debug logs.
- Limit login attempts to prevent brute-force attacks.

**Features at a glance:**

### 🚀 Protect Admin Access
Prevent unauthorized users from accessing `/wp-admin`, keeping your dashboard safe. You can also customize the login URL using a filter.

### 🔒 Secure Debug Logs
Block access to debug logs to prevent unauthorized users from viewing sensitive information.

### ⚡ Limit Login Attempts
Stop brute-force attacks by temporarily blocking IPs after repeated failed login attempts.

### 🌟 Lightweight & Minimal
Designed to deliver maximum security with minimal code. No complex settings or configuration needed.

### 💬 Simple & Effective
Install, activate, and your site is protected instantly.

== Installation ==

1. Upload the `nhrrob-secure` plugin folder to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Protection starts automatically — no configuration required.


== Frequently Asked Questions ==

= Does this plugin hide admin login path (/wp-admin)? =

Yes. NHR Secure restricts access to `/wp-admin` for unauthorized users. You can also change the login URL using the provided filter.

= Can I access debug logs? =

Debug logs are protected from public access. Only authorized users can access them via your server.

= Does it limit login attempts? =
Yes. Repeated failed login attempts from the same IP will be temporarily blocked to prevent brute-force attacks.

= Do I need other plugins? =
No. NHR Secure is standalone and works independently.

= Will it affect my site performance? =
No. NHR Secure is lightweight and designed to have minimal impact on your WordPress performance.


== Screenshots ==

1. Failed login attempts are blocked.
2. Debug logs are protected from public access.


== Changelog ==

= 1.0.0 - 23/10/2025 =
- Initial beta release. Cheers!


== Upgrade Notice ==

= 1.0.0 =
- This is the initial release. Feel free to share any feature request at the plugin support forum page.