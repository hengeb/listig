<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mime\Address;

/**
 * An Envelope whose sender is RFC 5321's null reverse-path (`MAIL FROM:<>`) —
 * used for outbound notification mails (see NotificationMailer) so a
 * compliant receiving MTA never generates a bounce back to Listig for one of
 * its own notifications, which would otherwise loop through BounceHandler
 * indefinitely (bounce → forwarded to owners → rejected by the owner's
 * server → new bounce → ...).
 *
 * There is no supported way to build this through symfony/mailer 7.4's public
 * API (confirmed against the exact pinned version, composer.lock): both
 * `Address::__construct()` (always validates via egulias/email-validator and
 * rejects an empty address) and `Envelope::setSender()` (its own independent
 * "must contain an @" regex check) reject an empty address outright, and
 * `Address` is declared `final`, so it can't be subclassed to skip
 * validation either. Reflection is the only way around it — isolated here,
 * in one small, single-purpose class, rather than spread across
 * NotificationMailer. `SmtpTransport::doMailFromCommand()` builds the actual
 * `MAIL FROM:<%s>` command straight from `getSender()->getEncodedAddress()`
 * with no validation of its own, so an empty address there correctly
 * produces the literal `MAIL FROM:<>` line.
 *
 * Setting a `Return-Path` header on the message instead is not an alternative
 * here, even though symfony/mailer's own `DelayedEnvelope::getSenderFromHeaders()`
 * does check `Return-Path` (after `Sender`, before `From`) when deriving an
 * envelope from message headers. That derivation only ever runs when
 * `Mailer::send()` is called with `$envelope === null` — `AbstractTransport::send()`
 * builds a `DelayedEnvelope` via `Envelope::create($message)` exactly in that
 * case, never otherwise. Every call site in this codebase (`QueueSender::sendOne()`,
 * `NotificationMailer::send()`) always passes an explicit `Envelope`/
 * `NullSenderEnvelope` instance, so that header-derivation path is never reached
 * regardless of what headers the message carries — a `Return-Path` header would
 * be silently ignored for envelope purposes. This Reflection-based subclass
 * remains the only way to produce `MAIL FROM:<>` with symfony/mailer 7.4.
 */
final class NullSenderEnvelope extends Envelope
{
    /** @param Address[] $recipients */
    public function __construct(array $recipients)
    {
        // Deliberately skips parent::__construct() — it would call
        // setSender() on a real Address just to validate it, which is
        // exactly the check being bypassed below.
        $this->setRecipients($recipients);

        $addressReflection = new \ReflectionClass(Address::class);
        $emptySender = $addressReflection->newInstanceWithoutConstructor();
        $addressReflection->getProperty('address')->setValue($emptySender, '');
        $addressReflection->getProperty('name')->setValue($emptySender, '');

        (new \ReflectionProperty(Envelope::class, 'sender'))->setValue($this, $emptySender);
    }
}
