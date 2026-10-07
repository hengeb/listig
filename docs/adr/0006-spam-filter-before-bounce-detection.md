# ADR-0006: Run the spam filter before bounce detection

Status: Accepted

## Context

`filters:` rules (config.yml) were checked after bounce detection, so a spam-content match against a bounce was unreachable: every bounce was logged and forwarded to the owners regardless of what the operator's rules said.

Background (moved from the former CLAUDE.md, wording preserved):

> **Spam filter checked before bounce detection** — the opposite of every other check, which all stay *after* bounce detection specifically because a real bounce may legitimately fail auth/lack a valid subaddress/etc. (see below). This one reversal is deliberate: it lets an operator write a `filters:` rule matching a particular unwanted bounce (e.g. a known noisy auto-responder, or a specific `MAILER-DAEMON` host) and have it silently dropped via `action: discard` instead of always being logged to `bounce_log` and forwarded to the owner. Before this reordering, bounce detection ran first and a spam-content match against a bounce mail was unreachable — the mail was always handled as a bounce regardless of what `filters:` said. The tradeoff: **any** `filters:` rule that happens to also match real bounce content will now intercept that bounce before it's ever logged/forwarded, not just ones an operator intentionally wrote for that purpose — a broad `subject: /error/i` rule, say, would now swallow bounces mentioning "error" in the subject too, silently. Confirmed live: a mail with `From: MAILER-DAEMON@...` that also matched a `filters:` rule was rejected/discarded as spam and never reached `isBounce()` at all; the same mail without a matching rule was still correctly classified as a bounce, unchanged.

## Decision

`IncomingMailFilter` checks `filters:` as step 2, before bounce detection (step 3) — the only check ordered before it; all others stay after, because a real bounce may legitimately fail SPF/DKIM or carry no valid subaddress.

## Alternatives considered

Keeping bounce detection first (no way to silence a known noisy auto-responder).

## Consequences

Any `filters:` rule that happens to match real bounce content intercepts that bounce before it is logged or forwarded, not just rules written for that purpose.
