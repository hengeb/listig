# Routes

HTTP routes of the web UI and API.

## Routes

Every route not scoped to a specific list lives under the reserved `/_/` prefix. List-scoped routes
are a single bare path segment (`/{listname}`), which can never collide with a `/_/...` route
regardless of registration order, since the latter always has ≥2 segments with a static first
segment — one requirement is that no list is ever named `_` (enforced fail-fast in
`ListConfig::__construct()`, see [ListConfig with property hooks](../architecture/providers-and-members.md#listconfig-with-property-hooks)).

`ListConfig::__construct()` also fail-fast rejects a list name containing anything outside
`[A-Za-z0-9_-]` (`ListConfig::VALID_NAME_PATTERN`) — a positive allowlist, not a blocklist of
specific bad characters. This exists specifically to keep a name from colliding with
`docker/nginx.conf`'s `location ~ \.php$ { return 404; }`: that rule matches on the URL path
alone, with no awareness of which names are actually configured lists, so a list literally named
e.g. `news.php` would have every one of its web routes (manage page, archive viewer, unsubscribe
link, moderation preview, List Management API) silently 404 at the nginx layer, before Slim ever
sees the request — while mail distribution over IMAP/SMTP (which never touches nginx) kept working
regardless, making the list look fine until someone actually clicked a generated link. Since every
provider constructs its lists through this one class, the check applies uniformly regardless of
where the name comes from (LDAP `cn`, a `config-table`/CSV/database row, a `list-providers`/`lists:`
YAML key).

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/_/login` | — | Login form |
| POST | `/_/login` | — | Send magic link (rate-limited) |
| GET | `/_/login/verify` | — | Verify token, create session |
| GET | `/_/login/oidc` | — | OIDC login initiation + callback — only registered when configured, see [Authentication (OIDC)](../architecture/web-ui.md#authentication-oidc) |
| POST | `/_/api/logout` | user | Destroy session |
| GET | `/` | user | Dashboard: subscribed lists |
| GET | `/{listname}` | user | Manage page (owner) or reduced info page (non-owner) — see [`/{listname}` — owner vs. non-owner view](../architecture/web-ui.md#listname--owner-vs-non-owner-view) |
| POST | `/_/api/moderation/{id}/accept` | owner | Accept moderation item |
| POST | `/_/api/moderation/{id}/reject` | owner | Reject moderation item |
| GET | `/{listname}/compose` | user | Form for a first mail to an external address — see [Masked reply addresses](../architecture/masked-replies.md#masked-reply-addresses) |
| POST | `/_/api/leave/{listname}` | member | Leave a list the logged-in user is a member of (the "Unsubscribe" button) |
| POST | `/_/api/join/{listname}` | user | Join an `open`, visible list as the logged-in user — see [Join / visibility](../architecture/web-ui.md#visibility-and-join-policy) |
| POST | `/_/api/compose/{listname}` | user | Issue the masked address for the entered recipient (returns a `mailto:` link) |
| GET | `/{listname}/moderation/{id}` | owner | Preview a still-pending mail — see [Preview: pending mail](../architecture/moderation.md#preview-pending-mail) |
| GET | `/{listname}/moderation/{id}/frame` | owner | Preview: sandboxed HTML body |
| GET | `/{listname}/moderation/{id}/attachment/{index}` | owner (or signed token) | Preview: attachment download/inline |
| GET | `/{listname}/bounce/{id}` | owner | Preview a bounce mail — see [Bounce preview](../architecture/bounces.md#bounce-preview) |
| GET | `/{listname}/bounce/{id}/frame` | owner | Preview: sandboxed HTML body |
| GET | `/{listname}/bounce/{id}/attachment/{index}` | owner (or signed token) | Preview: attachment download/inline |
| GET | `/_/api/live/{listname}` | owner | HTML fragment (`list/manage-live.latte`): delivery queue + bounces, polled by the manage page — see [Manage page live refresh](../architecture/web-ui.md#manage-page-live-refresh) |
| GET | `/_/api/queue/{listname}` | owner | Queue status |
| DELETE | `/_/api/queue/{id}` | owner | Delete failed entry |
| POST | `/_/api/queue/{id}/retry` | owner | Retry failed entry |
| DELETE | `/_/api/archive/{listname}/{id}` | owner | Permanently delete a single archived mail (IMAP + index) — see [Deleting an archived mail](../architecture/archive.md#archive-viewer) |
| GET | `/{listname}/unsubscribe` | token | Confirmation page for the unsubscribe link of a mail — changes nothing, see [Unsubscribe endpoint](../architecture/web-ui.md#unsubscribe-endpoint) |
| POST | `/{listname}/unsubscribe` | token | Unsubscribe (the confirmation form and RFC 8058 one-click) |
| GET | `/{listname}/archive` | per-list `archive` mode | Archive: threaded table view — see [Archive viewer](../architecture/archive.md#archive-viewer) |
| GET | `/{listname}/archive/{id}` | per-list `archive` mode | Archive: single message |
| GET | `/{listname}/archive/{id}/frame` | per-list `archive` mode | Archive: sandboxed HTML body |
| GET | `/{listname}/archive/{id}/attachment/{index}` | per-list `archive` mode | Archive: attachment download/inline |
| PUT | `/{listname}/{mail}` | Bearer | List Management API: immediate subscribe — see [List Management API](../architecture/api.md#list-management-api) |
| DELETE | `/{listname}/{mail}` | Bearer | List Management API: unsubscribe |
| POST | `/{listname}/subscribe` | Bearer | List Management API: request double opt-in |
| GET | `/{listname}/subscribe/confirm` | token in link | List Management API: confirm double opt-in |
| POST | `/{listname}/encrypt-password` | Bearer | List Management API: encrypt + persist a password |
| GET | `/_/health` | — | Health check: DB + LDAP reachability |

Static assets (CSS/JS/images) live under `public/assets/` as plain files — `style.css`, `script.js`
plus per-page JS (`archive-index.js`, `archive-show.js`, `list-manage.js`, `compose.js`), and `logo.svg`/
`logo-mark.svg` (see [App name (`app-name`)](../architecture/web-ui.md#app-name-app-name)) — never routed through Slim at all. nginx
(`docker/nginx.conf`) has an explicit `location /assets/ { try_files $uri =404; }` block serving
these directly, and a fallback `location / { try_files $uri /index.php$is_args$args; }` that only
reaches the Slim front controller when no real file matches — so `public/assets/...` needs no
reserved-name carve-out of its own. `public/favicon.ico`/`.png`/`.svg` sit directly under `public/`
instead (outside `/assets/`) and are picked up the same way, via the `location /` fallback finding
the real file before it reaches `index.php` — only `favicon.ico` is actually referenced anywhere
(the browser's own default `/favicon.ico` request; `layout.latte` has no explicit `<link rel="icon">`
of its own, so an operator wanting the `.png`/`.svg` variant linked needs to add one via the
`custom_head` block, see [Custom layout](../architecture/web-ui.md#custom-layout)). Only `index.php` itself is ever passed to php-fpm
(`location = /index.php`); any other `.php` request is rejected with `404`
(`location ~ \.php$ { return 404; }` — see [Quiet 404/405 logging](../architecture/deployment.md#building-from-source-development) for how that interacts with Slim's
own exception logging).
