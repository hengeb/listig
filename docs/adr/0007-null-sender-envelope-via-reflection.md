# ADR-0007: Build the null-sender envelope with Reflection

Status: Accepted

## Context

System notifications must be sent with `MAIL FROM:<>` (RFC 5321 null reverse-path) so that a compliant receiving MTA never generates a DSN for them — otherwise a bounce of a bounce-forward loops (about 100 consecutive bounces were observed from a single spam-rejected mail). symfony/mailer 7.4 has no supported way to build an `Envelope` with an empty sender: `Address` validates and is `final`, and `Envelope::setSender()` validates too.

## Decision

`NullSenderEnvelope extends Envelope`, skips the validating parent constructor, creates the empty `Address` via `ReflectionClass::newInstanceWithoutConstructor()` and writes the private `$sender` property via `ReflectionProperty`. `SmtpTransport::doMailFromCommand()` does no validation of its own, so the empty address reaches the wire as `MAIL FROM:<>`. Isolated in one small class and covered by `NullSenderEnvelopeTest`.

## Alternatives considered

Setting a `Return-Path` header (see below).

> Setting a `Return-Path` header on the message instead is not an alternative — confirmed by reading `symfony/mailer`'s own source: `AbstractTransport::send()` only derives an envelope from the message's own headers (`DelayedEnvelope::getSenderFromHeaders()`, which does check `Sender`, then `Return-Path`, then `From`, in that order) when `Envelope::create($message)` is called, i.e. when `Mailer::send()` is invoked with `$envelope === null`. Listig never does that — every call site (`QueueSender::sendOne()`, `NotificationMailer::send()`) always passes an explicit `Envelope`/`NullSenderEnvelope` object — so that header-based fallback path is never reached, and a `Return-Path` header would have zero effect on the actual SMTP envelope sender here regardless of its value. `NullSenderEnvelope`'s Reflection approach remains the only way to produce a literal `MAIL FROM:<>` with this library/version.

## Consequences

Depends on private internals of symfony/mailer; re-check on upgrades. This is one of three loop-prevention layers (see [Bounces](../architecture/bounces.md)).
