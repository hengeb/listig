<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Queue;

use Hengeb\Listig\Queue\SpamRejectionDetector;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mailer\Exception\TransportException;

class SpamRejectionDetectorTest extends TestCase
{
    public function testDomainOfExtractsDomainCaseInsensitively(): void
    {
        $detector = new SpamRejectionDetector();
        $this->assertSame('gmail.com', $detector->domainOf('Alice@Gmail.COM'));
    }

    public function testDomainOfReturnsEmptyStringForMalformedAddress(): void
    {
        $detector = new SpamRejectionDetector();
        $this->assertSame('', $detector->domainOf('not-an-email'));
    }

    public function testRejectionFromBuiltinTrustedDomainWithSpamTextMatches(): void
    {
        $detector = new SpamRejectionDetector();
        $exception = new TransportException('550 5.7.1 Message rejected as spam');
        $this->assertTrue($detector->isSpamRejection($exception, 'someone@gmail.com'));
    }

    public function testRejectionFromUntrustedDomainNeverMatchesEvenWithSpamText(): void
    {
        // A malicious/misconfigured server could otherwise forge a "spam"
        // response to make Listig discard mail for unrelated recipients.
        $detector = new SpamRejectionDetector();
        $exception = new TransportException('550 message rejected as spam');
        $this->assertFalse($detector->isSpamRejection($exception, 'someone@totally-unknown-domain.example'));
    }

    public function testRejectionFromTrustedDomainWithoutSpamTextDoesNotMatch(): void
    {
        $detector = new SpamRejectionDetector();
        $exception = new TransportException('550 5.1.1 mailbox does not exist');
        $this->assertFalse($detector->isSpamRejection($exception, 'someone@gmail.com'));
    }

    public function testNonTransportExceptionNeverMatches(): void
    {
        $detector = new SpamRejectionDetector();
        $exception = new \RuntimeException('spam');
        $this->assertFalse($detector->isSpamRejection($exception, 'someone@gmail.com'));
    }

    public function testAdditionalReliableDomainIsRecognized(): void
    {
        $detector = new SpamRejectionDetector(['custom-provider.example']);
        $exception = new TransportException('rejected as spam');
        $this->assertTrue($detector->isSpamRejection($exception, 'someone@custom-provider.example'));
    }

    public function testAdditionalDomainsAreNormalizedCaseAndWhitespace(): void
    {
        $detector = new SpamRejectionDetector([' Custom-Provider.EXAMPLE ']);
        $exception = new TransportException('rejected as spam');
        $this->assertTrue($detector->isSpamRejection($exception, 'someone@custom-provider.example'));
    }

    public function testBuiltinDomainsRemainTrustedAlongsideAdditionalOnes(): void
    {
        // reliable-spam-reporters: is always additive, never a replacement for
        // the built-in baseline.
        $detector = new SpamRejectionDetector(['custom-provider.example']);
        $exception = new TransportException('rejected as spam');
        $this->assertTrue($detector->isSpamRejection($exception, 'someone@gmail.com'));
    }

    public function testUncofiguredExtraDomainsStillLeavesBuiltinListWorking(): void
    {
        $detector = new SpamRejectionDetector([]);
        $exception = new TransportException('rejected as spam');
        $this->assertTrue($detector->isSpamRejection($exception, 'someone@yahoo.com'));
    }

    public function testSpamCheckIsCaseInsensitiveInResponseText(): void
    {
        $detector = new SpamRejectionDetector();
        $exception = new TransportException('550 Message REJECTED AS SPAM');
        $this->assertTrue($detector->isSpamRejection($exception, 'someone@gmail.com'));
    }
}
