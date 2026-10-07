# ADR-0012: Log requests through nginx's `map` + `access_log ... if=`

Status: Accepted

## Context

Every request should be logged exactly once, with its real URL, excluding Docker's `HEALTHCHECK` and automated 404/405 noise.

## Decision

nginx's own access log is canonical (`access_log /dev/stdout combined if=$loggable`, with `$loggable` built from two `map`s over `$request_uri` and `$status`); `docker/php-fpm-pool.conf` disables php-fpm's own access log (`access.log = /dev/null`).

## Alternatives considered

php-fpm's access log as the canonical one (see below).

> This wasn't the first design tried. php-fpm's own access log was briefly the canonical one instead, with `docker/php-fpm-pool.conf` overriding just its `access.format`: the default format's `%r` specifier logs `SCRIPT_NAME`, which is always literally `/index.php` — every request funnels through `docker/nginx.conf`'s `try_files $uri /index.php$is_args$args`, so by the time php-fpm sees it that's genuinely the only script name there is, regardless of what the client actually requested; `%{REQUEST_URI}e` (reading the `REQUEST_URI` FastCGI param, set from nginx's `$request_uri` via `/etc/nginx/fastcgi_params` — unlike `$uri`/`SCRIPT_NAME`, never touched by the internal `try_files` rewrite) fixed that part. Excluding `/_/health` from *that* log was then attempted via php-fpm's own `access.suppress_path[]` pool directive — confirmed to compile and load without error, but empirically unreliable in live testing (suppressed some requests and not others with no consistent relationship to the configured path, including once suppressing a `/_/health` hit that should have matched and *not* suppressing a `/testliste/archive` hit under a config that should have matched everything). Given that, the whole approach was replaced with nginx's `map`/`access_log ... if=`, which is standard, long-established nginx behavvior rather than a php-fpm mechanism with unclear-in-practice matching semantics.

## Consequences

Plain 404/405 responses are not logged at all, on either layer (`QuietBotNoiseErrorHandler` suppresses Slim's verbose exception log for them).
