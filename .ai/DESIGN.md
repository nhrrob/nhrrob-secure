# DESIGN — Secure admin app

> Dev-only document. Excluded from distribution. Clickable reference: `design/mockup.html`. Brand sources: `design/brand/`.
> Implemented in `admin/src/style.scss` (tokens) and `admin/src/components/ui.js` (primitives).

## 1. Direction

A sibling of the Database Cleaner app: same shell (gradient app bar, collapsible left nav, one screen per section), same token structure, **teal** instead of violet so the two are related but never confused. wp-admin density and the system font stack. No framework, no icon font, no images: CSS custom properties and inline SVG only.

The plugin name shown in the UI is **Secure**. "NHR" never appears.

## 2. Tokens (`.nhrrob-secure-app`)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--ns-primary` | `#0b8a8f` | `#2cc0b8` | switches, focus ring, icons |
| `--ns-primary-600` | `#08747a` | `#57d3cc` | links, soft-button text |
| `--ns-grad-a` → `--ns-grad-b` | `#0a7c86` → `#12a594` | `#0a6f78` → `#0f9384` | app bar, active nav, primary button |
| `--ns-soft` | `#e6f5f4` | `#17373a` | soft button, selected chip, hover |
| `--ns-success` / `-bg` | `#12a15c` / `#e8f7ef` | `#3ccf8a` / 14 % | passed, protected, allow |
| `--ns-warning` / `-bg` | `#c96a04` / `#fdf1e0` | `#f5a742` / 14 % | high, "could break" |
| `--ns-danger` / `-bg` | `#d6362a` / `#fdecea` | `#f2685c` / 15 % | critical, block, exposed |
| `--ns-info` / `-bg` | `#2a7fd6` / `#e8f1fc` | `#6aaef2` / 14 % | medium, notes |
| `--ns-surface` / `--ns-bg` / `--ns-sunken` | `#fff` / `#f4f8f8` / `#eef3f3` | `#162326` / `#0f181a` / `#111c1f` | panel / page / table head, code |
| `--ns-border` / `-strong` | `#e1eaea` / `#cfdcdc` | `#24363a` / `#33494e` | |
| `--ns-text` / `--ns-muted` | `#0f1f24` / `#5a6e74` | `#e3eeee` / `#93a8ad` | |

Neutrals lean toward the teal accent. Semantic colours (good / warning / critical) are separate from the accent and carry state; the accent never means "good".

**Dark theme:** the same tokens redefined under `@media (prefers-color-scheme: dark)` guarded by `:not([data-theme="light"])`, and again under `[data-theme="dark"]`, so the app-bar toggle wins both ways. Dark mode darkens the whole screen, as in the Database Cleaner: `html:has(.nhrrob-secure-app…)` paints wp-admin's page canvas and footer with the dark background, so there is no light frame around the app. The choice is remembered in `localStorage` (`nhrrob-secure-theme`); the nav state in `nhrrob-secure-nav`.

## 3. Components

- **Panel** — titled card; optional icon, meta text and actions in the header; `flush` for tables; `anchor` gives it the id `nhrrob-secure-panel-{anchor}` so Dashboard fixes can scroll to it (focus ring for 1.6 s).
- **Row** — one setting: label (+ optional pill), help, an amber "Could break: …" line, extra controls underneath, a Switch on the right. Hardening is a list of Rows.
- **Switch, Seg, Chips, TagList, TextSetting** — every control saves on change (text inputs on blur/Enter) and confirms with a toast. There is no Save button anywhere.
- **Pill** — `ok | warn | bad | info | off`, always with a dot so state is not carried by colour alone.
- **Grid** — plain table, uppercase muted header on a sunken band, `is-mono` for addresses and paths, `is-wrap` for long text, actions right-aligned and allowed to wrap. Wide tables scroll inside `.nhrrob-secure-scroll`; the page never scrolls sideways.
- **Note** — info (blue) or warn (amber) block for the one thing the owner must read.
- **Gauge** — inline SVG ring, score in the middle; teal ≥ 80, amber ≥ 50, red below.
- **Issue list** (Dashboard) — a coloured left edge by severity, the finding in bold, a muted detail line, a severity pill and one action.
- **Setup list** (Dashboard) — the recommended settings that are still off, one tick box each, a primary "Switch N on" and a quiet "Not now". After applying, a Note offers Undo / Keep them.
- **Report** (Dashboard → Printable report) — a plain document inside the app (`components/Report.js`): score, numbers, to fix, passed, recent warnings. `@media print` hides wp-admin's menu and bar, the app bar and the nav, so the report is the only thing on paper.
- **Toast** bottom-right (success 3 s, errors 12 s so the text can be read); a screen whose data cannot be loaded shows a warning note instead of an endless "Loading…"; **Confirm dialog** for anything that ends sessions, moves the login address or renames a file.

## 4. Screens

Dashboard · Login · Users & Sessions · Firewall · Hardening · Scanner · Activity · Settings (separated from the rest in the nav). One home per action; a new feature goes into one of these.

Where the 2.1 features live: **Dashboard** recommended setup, printable report · **Login** bot check on comments, bot trap, sign-in notifications · **Users & Sessions** temporary access (a select per user row), session limit · **Firewall** paste / copy a list, "Block address" on a match, rate limiting · **Hardening** feeds and head-link switches, file permissions, secret keys · **Scanner** configuration findings (in the WordPress files panel), "Replace" on changed plugin files, theme files · **Settings** webhook address with a test button, content logging.

## 5. Copy

Plain words from the owner's side: "sign in", "address" (not IP where the meaning is clear), "locked out", "Could break". Say what a control does and what it cannot do (the request filter "is not a network firewall"; the scanner "is not a malware cleaner"). Errors say what went wrong and what to do next.

## 6. Two-factor on the profile screen

Not part of the app: it uses wp-admin's own buttons, notices and inputs so it looks native on `profile.php`. The QR code is drawn in the browser on a white tile (it must stay black on white in every theme).

## 7. Brand

Icon: white outlined shield with a check on the teal gradient, 56 px corner radius at 256. Banner: the same mark, "Protect your WordPress site in minutes", the five headline areas, and a score card. Sources are SVG in `design/brand/`; render with `rsvg-convert` to `.wordpress-org/` (1544×500, 772×250, 256, 128).
