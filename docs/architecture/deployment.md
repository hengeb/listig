# Deployment and Docker

How Listig is packaged, deployed and logged by nginx. Reference for operators and for work on `docker/`.

## Docker Setup

One image, built from `docker/Dockerfile`: PHP 8.5 (php-fpm) + nginx + the worker loop, all baked into the same container and managed by `supervisord` (`docker/supervisord.conf`) as three processes — nginx (`docker/nginx.conf`, `fastcgi_pass 127.0.0.1:9000` — same container, no network/DNS involved), php-fpm, and `bin/worker.php` (IMAP polling + queue sending loop). Only MariaDB is a separate container. `docker/entrypoint.sh` is the image's `ENTRYPOINT`, running before any of that: it calls `bin/migrate.php` to apply pending database migrations, then `exec`s `CMD` (the `supervisord` invocation) — see [Database migrations](../reference/database-schema.md#database-migrations) for why this lives here rather than inside the worker loop.

### Simplest deployment (published image, no repo checkout)

`deploy/` holds the three template files needed to run Listig this way — nothing else is needed: MariaDB + the published `ghcr.io/hengeb/listig:latest` image, nothing built locally, no repo clone needed. All three live flat in the operator's own directory (no `config/` subfolder — `compose.yml.example`'s volume mount is `./config.yml:/app/config/config.yml:ro`):

```
mkdir listig && cd listig
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/compose.yml.example
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/.env.example
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/config.yml.example

cp compose.yml.example compose.yml
cp .env.example .env
cp config.yml.example config.yml
# edit .env and config.yml to match your setup

docker compose up -d
```

No manual migration step: the app container's entrypoint applies the schema itself on first start (see [Database migrations](../reference/database-schema.md#database-migrations)). `compose.yml`/`config.yml` are the operator's real files — gitignored/dockerignored the same as `.env`, never meant to be committed back (see below). Requires the GHCR package to be public (see [CI: build & publish](#ci-test-build--publish-githubworkflowsciyml)); if it's private, `docker login ghcr.io` first.

### Mailbox requirements

Listig needs no MTA configuration, but each list's mailbox must behave in a few ways:

- **IMAP and SMTP access** for the list (`imap-*`/`smtp-*` keys, usually via `mail-user`/`mail-password`), and the list address (`list-mail`) must be delivered to that mailbox.
- **`+tag` addresses must reach the same inbox.** Listig generates addresses of the form `{localPart}+tag@{domain}` and finds the tag in the raw `To` header (bounces also in `Delivered-To`/`X-Original-To`, which the mail server may set instead): `+accept-…`/`+reject-…` (moderation replies, [Moderation](moderation.md)), `+bounce+…` (per-recipient VERP envelope, [Bounces](bounces.md#1-which-recipient-a-signed-per-recipient-bounce-address-verp)) and `+r-…` (masked replies, [Masked reply addresses](masked-replies.md)) and `+re-…` (the archive's "reply" button, [ADR-0020](../adr/0020-reply-thread-tag.md)). A mail server without plus-addressing (or a catch-all that delivers them to the list's inbox) loses moderation replies and bounces. For `type: subaddress` lists the tag has its own meaning, see [type: subaddress](providers-and-members.md#type-subaddress--subaddress-forwarding).
- **`Authentication-Results` on every mail** if senders should receive reject / pending notices — see [Sender authentication](security-and-tokens.md#sender-authentication). At a third-party provider, set `trusted-authserv-id` ([per-list keys](../reference/list-config-keys.md)).

### Building from source (development)

Run via `docker/compose.yaml` (**app** + **db**, builds the image from this checkout instead of pulling it), or directly:
```
docker build -f docker/Dockerfile -t listig .
docker run -d -p 8080:80 --env-file .env -v $(pwd)/config/config.yml:/app/config/config.yml:ro listig
```

Configuration via `config.yml` (structure below) and `.env` for DB credentials and `APP_SECRET`. Neither is committed — `deploy/config.yml.example` and `deploy/.env.example` are the templates (the single source of truth for both this flow and [Simplest deployment](#simplest-deployment-published-image-no-repo-checkout) above); copy each into place (`config/config.yml`, `.env`, both at repo root/`config/` per `docker/compose.yaml`'s mounts) and edit before first run. Both `.gitignore` and `.dockerignore` exclude `.env` and `config/config.yml` (the real files, not the `.example` templates), so neither a commit nor a build (e.g. via `COPY . .`) can accidentally bake real secrets in.
`config.yml` may contain secrets via `$VAR` references to environment variables, or directly (e.g. LDAP bind password). Mount as a volume — never bake into the Docker image. `.dockerignore` also excludes `/vendor/`, so a host-side `composer install` (dev dependencies, host-specific builds) can never overwrite the `--no-dev` production `vendor/` that `docker/Dockerfile` installs inside the image.

`docker/php.ini` (`display_errors = Off`, `log_errors = On`, `error_log = /dev/stderr`) overrides the base image's development-oriented defaults (`display_errors = STDOUT`, `log_errors = Off`) — see [Security Notes](security-and-tokens.md#security-notes) for why this is load-bearing, not just tidiness.

**Access logging (`docker logs`)** — nginx's own access log is the canonical one: `docker/nginx.conf` sets `access_log /dev/stdout combined if=$loggable;`, where `$loggable` is built from two independent maps, ANDed together via string concatenation (`access_log`'s own `if=` only accepts a single variable, so both exclusions have to collapse into one): `map $request_uri $loggable_uri { ~^/_/health 0; default 1; }` excludes Docker's own `HEALTHCHECK` (`/_/health`, hit every ~30s — see [Health check](#health-check-_health) below), and `map $status $loggable_status { 404 0; 405 0; default 1; }` excludes plain 404s and 405s — the dominant shape of automated bot/scanner traffic (probes for `wp-content/`, PHP shells, etc., see [Quiet 404/405 logging](#building-from-source-development) below), which otherwise drowns out anything actually worth seeing (5xx, real errors) in `docker logs`. `map "$loggable_uri$loggable_status" $loggable { 11 1; default 0; }` then combines them: only a request that's loggable by *both* criteria (`"11"`) is logged; any other combination is suppressed. `$status` is safe to key a `map` on here despite being a response-phase variable — `access_log`'s own `if=` is evaluated at the point the log line is actually written, after the response status is already final, same as `$request_uri`. Every status other than 404/405 (2xx/3xx/401/403/429/5xx/...) still logs exactly as before — this narrowly targets "URL doesn't exist"/"wrong method for this URL," never a real failure. `docker/php-fpm-pool.conf` (copied to `/usr/local/etc/php-fpm.d/zz-listig.conf` — the `zz-` prefix sorts it after the base image's own `docker.conf`/`zz-docker.conf`, so its directive wins) disables php-fpm's *own* access log entirely (`access.log = /dev/null`, overriding `docker.conf`'s `access.log = /proc/self/fd/2`) so every request is logged exactly once, through nginx, not twice.

**Quiet 404/405 logging** — `docker/nginx.conf`'s `location ~ \.php$ { return 404; }` (see [Routes](../reference/routes.md#routes)) already intercepts most automated bot/scanner traffic (probes for `wp-content/`, PHP shells, etc.) before it ever reaches PHP-FPM, so those never generate a PHP-level log entry at all. A request that *doesn't* end in `.php` but still matches no route (e.g. `/wp-content/`) reaches Slim, which throws `Slim\Exception\HttpNotFoundException`; by default `$app->addErrorMiddleware($displayErrorDetails, true, true)` (`public/index.php` — see [Security Notes](security-and-tokens.md#security-notes) for why `$displayErrorDetails` is `false`) logs every exception's full type/message/file/line/stack trace via `error_log()` — redundant for a 404 specifically (this class of request is overwhelmingly the same bot noise the `.php` rule already filters out, and — now that nginx's own access log excludes 404s too, see [Access logging](#building-from-source-development) above — there is no access-log line left to be redundant *with* either, it would just be pure noise with nothing to justify it). A request whose *path* happens to match a registered route, but not for the HTTP method used, is the same story one level over: Slim throws `Slim\Exception\HttpMethodNotAllowedException` instead of a 404, but it's just as often the same bot/scanner noise, and just as redundant to log twice — confirmed live, an automated `GET /.git/HEAD` scan happened to path-match the `{listname}/{mail}` route (registered `PUT`/`DELETE` only, see [Routes](../reference/routes.md#routes)) purely by segment count, producing both a full verbose PHP-level log entry *and* its own nginx access-log line for a probe with nothing to do with application logic. `docker/nginx.conf`'s `map $status $loggable_status` therefore excludes 405 the same way it already excludes 404 (see [Access logging](#building-from-source-development) above — both are "not really an application-level event" cases, not real failures), and `src/Http/QuietBotNoiseErrorHandler.php` (a small `Slim\Handlers\ErrorHandler` subclass whose `writeToErrorLog()` is a no-op) is registered for *both* `HttpNotFoundException` and `HttpMethodNotAllowedException` via two `$errorMiddleware->setErrorHandler(...)` calls (same handler instance for both) in `public/index.php` — the response body/status is unaffected, only the log writes are skipped, on both layers, for both statuses. Every other exception type (a real 500, a config error, ...) still goes through Slim's default `ErrorHandler` and is logged in full on both layers, unchanged.

Access logging is done by nginx's own `map`/`access_log ... if=` rather than php-fpm's access log, whose `access.suppress_path[]` proved unreliable — see [ADR-0012](../adr/0012-nginx-map-access-logging.md).

**Set `hostname` explicitly in config.yml.** It's used to build every link Listig generates (login, dashboard, manage page, unsubscribe, moderation) — see `{hostname}` above. Without it, `ListConfig`/`'app.hostname'` (`config/container.php`) fall back to PHP's `gethostname()`, which in a container returns the container's own internal hostname (a random ID or the compose service name) — never the public domain a reverse proxy actually exposes the app under, and there's no way to derive that automatically: the worker has no incoming request to read a `Host` header from at all, and even on the web side, deriving it from the request would make worker-generated links (unsubscribe, moderation) and web-generated links (login) disagree whenever the same instance is reachable under more than one name. `bin/worker.php` logs a warning at startup (`error_log`, not a hard failure) if `hostname` resolves to empty, precisely because this is easy to miss and the resulting links are silently wrong rather than erroring.

`'app.hostname'` is not a raw read of the config key — it goes through `VariableResolver::resolve()` (`'app.hostname.resolved'`, using the merged root default config as its own lookup context, same pattern as a provider's `list-mail` bootstrap resolution), so a root-level alias like `domain: $DOMAINNAME` / `hostname: "lists.{domain}"` actually resolves `{domain}` instead of leaking the literal `{domain}` into every generated URL. `'app.language'`/`'worker.batch-size'`/`'worker.sleep-seconds'` — the other scalar root keys read via `getResolvedDefault()` — go through the same resolution for consistency, even though templating them is a less common case than `hostname`. `db-*` (read directly by `PDO::class`) is the deliberate exception: those are `VariableResolver::BLOCKED_KEYS`, meant to stay pure `$VAR`-substituted literals, never `{}`-templated.

### CI: test, build & publish (`.github/workflows/ci.yml`)

Triggers: push to `main`, `v*` tags, pull requests, manual dispatch. Two jobs; `build` has `needs: test`, so a red test, lint or static-analysis check can never publish an image.

- **`test`** — on the runner with `shivammathur/setup-php` (PHP 8.5, the Dockerfile's version; Composer cache keyed on `composer.lock`): `composer validate --strict`, `composer install` (dev dependencies, with `--ignore-platform-req=ext-imap --ignore-platform-req=ext-ldap`: the suite only covers the pure-logic layer and needs neither these nor `apcu`), `php -l` over `src/ bin/ config/ public/`, `composer test`, `composer stan`. Deliberately not the Dockerfile's exact extension set: that would make every run compile `pecl imap`, and the image itself is built in the `build` job anyway. See [Testing](testing.md#ci).
- **`build`** — builds `docker/Dockerfile` with `docker/build-push-action` and the GitHub Actions cache backend (`type=gha`) so unchanged apt/pecl/composer layers aren't rebuilt every run. On pull requests it only builds (no login, `push: false`) to catch Dockerfile errors early; on `main`/tags it pushes to the GitHub Container Registry as `ghcr.io/<owner>/<repo>` (`${{ github.repository }}` — no hardcoded name, works under any fork/rename). Tagging (`docker/metadata-action`): the branch name on a branch push, the git tag and derived semver on a version tag, the commit SHA always, and `latest` only on the default branch. Auth is the repo's own `GITHUB_TOKEN` (`permissions: packages: write` on this job only) — no PAT or secret to manage. First push creates the package as **private** by default; make it public under the repo's Packages settings if it should be pullable without authentication.

Workflow-level `permissions: contents: read`; a newer run cancels an older one for the same pull request, never on `main` or a tag. Dev-only files (`tests/`, `phpunit.xml`, `phpstan*`, `.github/`) are excluded from the image via `.dockerignore`.

---

## Health check (`/_/health`)

Returns HTTP 200 with JSON `{"db": "ok", "ldap": "ok"}` if both reachable, HTTP 503 (`"error"` for the failing key) otherwise. Used for Docker health checks. DB check is a plain `SELECT 1` against the global PDO connection. LDAP check (`checkLdapReachability()` in `public/index.php`) attempts a bind against every distinct LDAP server referenced anywhere in `config.yml` — both `type: ldap` list-providers and any `member-resolver: {type: ldap}` sub-config nested under `type: inline`/`database`/`yaml` providers; if no LDAP server is configured at all, it reports `ok` trivially (nothing to check).

---
