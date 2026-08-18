<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\NullSenderEnvelope;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mime\Address;

class NullSenderEnvelopeTest extends TestCase
{
    public function testSenderAddressIsEmpty(): void
    {
        // RFC 5321 null reverse-path (MAIL FROM:<>) — SmtpTransport builds the
        // command straight from getEncodedAddress(), so this must be ''.
        $envelope = new NullSenderEnvelope([new Address('someone@example.org')]);
        $this->assertSame('', $envelope->getSender()->getAddress());
    }

    public function testRecipientsArePreserved(): void
    {
        $recipients = [new Address('alice@example.org'), new Address('bob@example.org')];
        $envelope = new NullSenderEnvelope($recipients);

        $addresses = array_map(fn(Address $a) => $a->getAddress(), $envelope->getRecipients());
        $this->assertSame(['alice@example.org', 'bob@example.org'], $addresses);
    }

    public function testEmptyRecipientListStillRejectedBySymfonysOwnValidation(): void
    {
        // NullSenderEnvelope bypasses symfony/mailer's *sender* validation
        // (Address::__construct()'s reject-empty check) via Reflection, but
        // never touches setRecipients() — Envelope's own "at least one
        // recipient" rule still applies unchanged.
        $this->expectException(\Symfony\Component\Mailer\Exception\InvalidArgumentException::class);
        new NullSenderEnvelope([]);
    }
}
