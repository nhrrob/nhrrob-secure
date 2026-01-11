=== NHR Secure – Hide Admin, Limit Login & 2FA ===
Contributors: nhrrob
Tags: security, hide admin, login protection, debug log, 2fa
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.0.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A lightweight WordPress security plugin to protect your admin area with a custom login URL, hide debug logs, limit login attempts, and add 2FA.
== Description ==

Keep your WordPress site safe with minimal effort. NHR Secure helps you:

- Hide or protect your admin area from unauthorized access.
- Limit login attempts to prevent brute-force attacks.
- Hide debug logs to prevent sensitive information disclosure.
- Add 2FA to your WordPress site.

### **Features at a glance:**

### 🔒 Limit Login Attempts
Stop brute-force attacks by temporarily blocking IPs after repeated failed login attempts.
- Configurable attempt limit (1-20, default: 5)
- Blocks based on IP + Username combination
- Auto-unblock after 2 hours

### 🔐 Custom Login Page
Hide wp-login.php and use a custom login URL.
- Default custom URL: `/hidden-access-52w`
- Blocks direct access to wp-login.php and wp-admin for guests

### 🛡️ Protect Debug Log File
Blocks direct access to `/wp-content/debug.log`
- Returns 403 Forbidden for all users

### ⚙️ Modern Settings Page
Configure everything from a beautiful React-powered interface.
- Located under **Tools → NHR Secure**
- **Dark Mode** support for comfortable viewing
- Enable/disable each feature

### 🔐 Two-Factor Authentication (2FA)
Enable two-factor authentication for users.
- Support for **Authenticator Apps** and **Email OTP**
- **Enforce 2FA** for specific user roles (e.g., Administrators)
- **Recovery Codes** for emergency access
- QR code setup for Authenticator Apps

### ⚡ Lightweight & Minimal
Designed to deliver maximum security with minimal code. No bloat, no complexity.
- Compatible with most WordPress themes and plugins.

== Installation ==

1. Upload the `nhrrob-secure` plugin folder to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Tools → NHR Secure** to configure settings.

== Frequently Asked Questions ==

= How do I access the settings page? =
Navigate to **Tools → NHR Secure** in your WordPress admin dashboard.

= Does it limit login attempts? =
Yes. Repeated failed login attempts from the same IP will be temporarily blocked to prevent brute-force attacks. You can configure the limit (1-20 attempts) from the settings page.

= What is the default custom login URL? =
The default custom login URL is `/hidden-access-52w`. You can change this in the settings page under Tools → NHR Secure.

= How does 2FA work? =
2FA (Two-Factor Authentication) adds an extra layer of security to your WordPress site. When enabled, users must enter a code from their 2FA app (e.g., Google Authenticator, Authy) in addition to their username and password to log in.

= Can I disable specific features? =
Yes. You can enable or disable each feature from the settings page under Tools → NHR Secure.

== Screenshots ==

1. Failed login attempts are blocked.
2. Custom login page.
3. Debug log is hidden.
4. Modern React-powered settings page.
5. Modern React-powered settings page - part 2.
6. 2FA setup in user profile.
7. Dark mode support.


== Changelog ==

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

= 1.0.0 =
- This is the initial release. Feel free to share any feature request at the plugin support forum page.