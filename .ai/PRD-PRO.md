# PRD — Secure PRO (add-on)

Status: **plan only — nothing built, no repo** · Owner: Nazmul Hasan Robin (nhrrob)
Last revised: 2026-10-05

> Dev-only document. Excluded from distribution (`.distignore` + `.gitattributes export-ignore`).
> Free/core scope: **[PRD.md](./PRD.md)**.

## 0. The free-vs-PRO rule (non-negotiable)

1. **If a feature is free in any other WordPress plugin, it is free here.**
2. **If a feature is listed in the free PRD, it is free.**
3. **PRO carries major features only.** No padding ("longer retention", "more rows").
4. **Re-check before building.** Every candidate below is marked *verify*: its market status was reasoned from the 2026-10-05 research, not exhaustively confirmed.

## 1. Honest starting point

- The free plugin has **fewer than 10 active installs** and, as of 1.3.3, defects that would generate one-star reviews at scale (PRD §4.1). There is nobody to sell to yet.
- Security is the hardest WordPress category to charge in: the incumbents sell **threat intelligence** (firewall rules, malware signatures, virtual patches) produced by research teams. We cannot produce a feed, so PRO must not depend on one.
- **Launch trigger: ~1,000 active installs of 2.0**, same rule as the Database Cleaner add-on. Until then all effort goes into the free plugin. This document exists so the free architecture (add-on API, PRD §3) leaves room.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Delivery | Separate add-on plugin extending the core through `nhrrob_secure_modules` and the JS `nhrrobSecure.screens` filter |
| Licensing/billing | Freemius, in the add-on only |
| Free-side discoverability | None (PRD §1.4) |
| AI | WordPress core AI Client (WP 7.0+, the owner's own provider); no SDK, no keys stored by us |

## 3. Candidate features (pick at most three; all *verify*)

### 3.1 Account Guard
Stops the most common post-compromise step: a quiet new administrator or a hijacked session.
- **New-device / new-country sign-in detection** for chosen roles, with an email carrying a signed **"This wasn't me"** link that ends every session for that user, forces a password reset and locks the account.
- **Administrator approval:** a new administrator account, or a role raised to administrator, stays pending until an existing administrator confirms it. Catches accounts created by an exploited plugin or directly in the database (detected on the next request and reverted).
- **Critical-setting watch with auto-revert:** `users_can_register`, `default_role`, `siteurl`/`home`, `admin_email` — revert and alert when changed outside an allowed context.

*Market:* trusted devices are paid in WP 2FA Premium; alerts are paid in WP Activity Log and Simple History; Wordfence free emails on admin sign-in and can list admins created outside WordPress, but does not hold or revert them. **Verify:** Shield Security's free "Security Admin" restricts user and option changes behind a PIN — if that covers approval, this moves to free. Basic email alerts are free in Stream, which is why plain alerts are in the free PRD.

### 3.2 AI Security Analyst
Turns raw findings into decisions, using the owner's own AI provider.
- **Flagged-file review:** for each suspicious file, a verdict with reasons ("standard use of `WP_Filesystem`" vs "obfuscated loader, decodes and evaluates a remote payload"), then the recommended action.
- **Incident timeline:** "what happened between Tuesday and today?" — a readable account built from the activity log, lockouts and file changes.
- **Vulnerability plan:** the vulnerability list turned into an ordered to-do with real exposure in mind (is the vulnerable feature even reachable on this site?).
- Privacy default: metadata only; file contents are sent per action with explicit consent, secrets redacted.

*Market:* nothing comparable found in a free plugin. **Verify** before build; the category is moving fast.

### 3.3 Deep Scan
What a file-signature scan cannot see.
- **Database and content scan:** injected scripts, hidden redirects and spam links in `wp_options`, widgets, posts and user records; rogue cron events; tampered `.htaccess`.
- **Baseline integrity for plugins that are not on WordPress.org** (premium and custom code): approve a known-good state, alert on drift, show the diff.
- **Scheduled**, with a report.

*Market:* **verify carefully** — Wordfence free already scans posts and comments for known-bad URLs and compares WordPress.org plugins to their originals; MalCare and Sucuri do database scanning as paid services. If the free tools cover the database part well enough, only the non-WordPress.org baseline remains, and that alone is too thin for rule 3 — fold it into free.

## 4. Considered and rejected for PRO

| Idea | Why not |
|---|---|
| Country blocking | Already free here; paid elsewhere, but taking it away breaks rule 2 |
| Per-role 2FA policies | Already free here |
| Passkeys | Free in Kadence Security → free (PRD §5) |
| Email / Slack alerts on log events | Free in Stream → free |
| Virtual patching, real-time firewall rules, malware signature feed | Needs a research team and a feed service |
| Fleet dashboard, white-label reports | Agencies already use MainWP / ManageWP; large attack surface for a small add-on |
| Temporary and magic-link logins, salt rotation, force-logout-all | Free in single-purpose plugins |

## 5. Pricing (placeholder until launch)

Same structure as the Database Cleaner add-on: $39 / $79 / $149 per year (1 / 5 / unlimited sites) plus a lifetime tier. Reference points from 2026-10-05: Really Simple Security $49 / $99 / $199; AIOS $89 / $149 / $249 / $349; WP 2FA Premium $79–$149. Re-check at launch.

## 6. Order of work

1. Ship free 2.0 (PRD §4). 2. Grow to ~1,000 installs. 3. Re-run §3 market checks. 4. Build the surviving features, Account Guard first (no AI dependency, clearest job).
