# NHR Secure

WordPress security that stays out of the way: login protection, two-factor authentication, firewall, hardening, a scanner and an activity log.

- WordPress.org: https://wordpress.org/plugins/nhrrob-secure/
- Settings: **Tools → Secure**
- Locked out? `define( 'NHRROB_SECURE_SAFE_MODE', true );` in `wp-config.php`, or `wp nhrrob-secure safe-mode on`.

## Development

```
composer install
npm install
npm run build
npm run lint && composer run phpcs && composer run test:unit
```

Architecture, stored data, REST routes and the release gate are documented in `CLAUDE.md`.
