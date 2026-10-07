# ADR-0014: Block credential keys at resolution time, not by filtering the context

Status: Accepted

## Context

`ListConfig::createContext()` is the only context builder and returns the full raw config, including passwords and hosts. Values resolved for user-visible output must never reach them, even through aliases or recursion.

Background (moved from the former CLAUDE.md, wording preserved):

> Enforcing this at the point of `{}` resolution — rather than by filtering the context array before it's built — is what makes the protection apply even when no `ListConfig` exists yet: `InlineListProvider`/`YamlListProvider`/`SubaddressListProvider` all resolve a list's `list-mail` template against the raw, just-merged provider config (see [`list-mail`](../architecture/config.md#list-mail) above), before any `ListConfig` object is constructed. Passing `ResolutionPurpose::Disclosed` to that `VariableResolver::resolve()` call blocks `list-mail: "{mail-password}"` from resolving to the literal plaintext password, the same way as everywhere else, with no dependency on a `ListConfig` instance.

## Decision

`VariableResolver::resolve()` takes a `ResolutionPurpose`. Under `Disclosed` (the default), reaching a key in `BLOCKED_KEYS` at any recursion depth yields `*CLASSIFIED*` and an unconditional `error_log()`. `Trusted` bypasses the check and is used only by the six `ListConfig` connection properties (`imapHost/User/Password`, `smtpHost/User/Password`). The numeric/enum properties (`imap-port`, `smtp-secure`, ...) stay on `Disclosed` to avoid leaking fragments of a password via an `(int)` cast.

## Alternatives considered

Pre-filtering the context array (a separate "safe" context builder) — would not protect resolution that happens before any `ListConfig` exists (`list-mail` templates are resolved against the raw merged provider config).

## Consequences

Protection applies uniformly to every `Disclosed` resolution regardless of the calling code path; the blocked-key log line is deliberately not level-gated.
