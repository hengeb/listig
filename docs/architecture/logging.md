# Logging

Log levels and debug tracing.

## Logging

Global log level configured in `config.yml` (default: `info`). Per-list override via `log-level` key.
Levels: `debug`, `info`, `warning`, `error`.
Log to stdout (Docker-friendly), structured (JSON) where possible.

### Debug logging

`Hengeb\Listig\Logging\Logger` (`debug()`; `info()` for the rare hint that should be visible at the default level, e.g. the missing `trusted-authserv-id` hint) is a small, level-gated wrapper around `error_log()` — `LogLevel` (`Debug < Info < Warning < Error`, `src/Logging/LogLevel.php`) makes the four documented levels an actual, enforced ordering instead of a decorative config key: a message only reaches `error_log()` when the effective threshold is `debug` itself, since `debug()` is the *only* level `Logger` currently emits. The effective threshold is `'app.log-level'` (config.yml root default, resolved the same `getResolvedDefault()`-backed way as `'app.language'`/`'app.name'`) unless the call passes a specific list's `$list->logLevel` as the second argument, in which case that list's own `log-level` override (already resolved through the normal 5-level config merge, see [Configuration priority](config.md#configuration-priority-low--high)) applies instead — necessary because `bin/worker.php` builds one `Logger` for the whole process lifetime (see [Worker loop — config reload](worker-and-queue.md#worker-loop--config-reload)) while iterating many lists that may each set their own level.

This is scoped tracing, not a retrofit of the whole codebase's logging: the pre-existing ~44 `error_log()` calls throughout `src/`/`bin/` (IMAP failures, moderation errors, rate-limit hits, blocked-variable disclosures, ...) are deliberately **not** routed through `Logger` — they represent operational problems an operator should always see on stdout regardless of the configured level, and migrating all of them to be level-gated (so e.g. `log-level: error` would suppress today's unconditional warnings) was out of scope for what was actually asked; only new, previously-nonexistent low-priority tracing was added, gated behind `debug`. Call sites, all passing the relevant list's `logLevel` where one is in scope:

- **`AuthController::sendMagicLink()`** — one line per login *request* (email, before validation), then exactly one outcome line: link sent (list-scoped level), no matching member found, or rate-limited (both global-level, since no list is known yet in the negative cases).
- **`AuthController::verifyToken()`** — one line per successful magic-link login (global level — the token payload only carries `listCn` as a string at this point, not a `ListConfig` instance, and resolving one via `ListProvider::getList()` purely to pick a log threshold wasn't worth the extra lookup).
- **`AuthController::loginOidc()`** — one line per successful OIDC login (list-scoped level), mirroring the magic-link success line for parity between the two login methods.
- **`ImapPoller::poll()`** — one summary line per cycle when unseen UIDs exist ("found N unseen mail(s) ... UID(s) ..."), then one line per mail actually fetched (UID + Message-ID — deliberately not the subject, since "Never log MIME content, passwords, or tokens" under Security Notes is written as an unconditional rule and a debug log is not an exemption worth carving out for it).
- **`MailProcessor::process()`** — one summary line before the recipient loop (recipient count + `batch_id`), then one line per `QueueWriter::enqueue()` call (recipient address + `batch_id`) — covers "das Enqueuen für alle Mitglieder" end to end, one line per member.
- **`SpamFilter::match()`** — one line per matched `filters:` rule (list-scoped level): the rule's 1-based position among `filters:` entries (not the internal 0-based array index — matches how an operator would refer to "the third rule" in their own `filters.yml`), its `action`, and every condition that matched with the *resolved* pattern it was actually compared against (post-`{}`-substitution, not the raw config text) — e.g. `Listig: filters: rule #2 matched (action: discard) — subject: "spam", from: "MAILER-DAEMON@hengeb.de"`. Nothing is logged when no rule matches at all.

Registered in `config/container.php`: `'app.log-level'` (the global default string) and `Logger::class` (constructed from it via `LogLevel::fromString()`), injected into `AuthController`, `ImapPoller`, `MailProcessor`, and `SpamFilter` alongside their existing dependencies.

---
