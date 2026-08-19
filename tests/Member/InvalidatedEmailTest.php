<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Member\InvalidatedEmail;
use PHPUnit\Framework\TestCase;

class InvalidatedEmailTest extends TestCase
{
    public function testFormatPreservesOriginalAddressAndReasonAndUsesInvalidTld(): void
    {
        $result = InvalidatedEmail::build('alice@example.org', 'MAILBOX_FULL');

        $this->assertStringStartsWith('alice@example.org.BOUNCE_MAILBOX_FULL.', $result);
        $this->assertStringEndsWith('.invalid', $result);
    }

    public function testFormatUsesHumanReadableDateNotUnixTimestamp(): void
    {
        $result = InvalidatedEmail::build('alice@example.org', 'USER_UNKNOWN');
        $today = (new \DateTimeImmutable())->format('Y-m-d');

        $this->assertSame("alice@example.org.BOUNCE_USER_UNKNOWN.{$today}.invalid", $result);
    }

    public function testDifferentReasonCodesProduceDifferentPlaceholders(): void
    {
        $a = InvalidatedEmail::build('bob@example.org', 'SPAM');
        $b = InvalidatedEmail::build('bob@example.org', 'MAILBOX_FULL');

        $this->assertStringContainsString('.BOUNCE_SPAM.', $a);
        $this->assertStringContainsString('.BOUNCE_MAILBOX_FULL.', $b);
        $this->assertNotSame($a, $b);
    }
}
