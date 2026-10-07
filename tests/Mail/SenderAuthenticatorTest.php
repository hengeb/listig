<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\OrganizationalDomain;
use Hengeb\Listig\Mail\SenderAuthenticator;
use PHPUnit\Framework\TestCase;

class SenderAuthenticatorTest extends TestCase
{
    private function auth(string $headers, string $from = 'alice@example.com'): bool
    {
        return (new SenderAuthenticator(new HeaderFilter(), new OrganizationalDomain()))
            ->isAuthenticated($headers, $from);
    }

    public function testAlignedDkimPassAuthenticates(): void
    {
        $this->assertTrue($this->auth("Authentication-Results: mx.example.org; dkim=pass header.d=example.com\r\n"));
    }

    public function testDkimPassForSubdomainOfFromDomainAligns(): void
    {
        $this->assertTrue($this->auth("Authentication-Results: mx.example.org; dkim=pass header.d=mail.example.com\r\n"));
        $this->assertTrue($this->auth("Authentication-Results: mx.example.org; dkim=pass header.d=example.com\r\n", 'a@news.example.com'));
    }

    public function testUnalignedDkimPassDoesNotAuthenticate(): void
    {
        $this->assertFalse($this->auth("Authentication-Results: mx.example.org; dkim=pass header.d=other.org\r\n"));
    }

    public function testSecondAlignedSignatureSuffices(): void
    {
        $h = "Authentication-Results: mx.example.org; dkim=pass header.d=forwarder.org; dkim=pass header.d=example.com\r\n";
        $this->assertTrue($this->auth($h));
    }

    public function testAlignedSpfPassAuthenticates(): void
    {
        $this->assertTrue($this->auth("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=bounce@mail.example.com\r\n"));
    }

    public function testSpfPassOfOtherDomainDoesNotAuthenticate(): void
    {
        $this->assertFalse($this->auth("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=x@forwarder.org\r\n"));
    }

    public function testSpfPassWithoutMailfromDoesNotAuthenticate(): void
    {
        $this->assertFalse($this->auth("Authentication-Results: mx.example.org; spf=pass smtp.helo=example.com\r\n"));
    }

    public function testDmarcPassAuthenticates(): void
    {
        $this->assertTrue($this->auth("Authentication-Results: mx.example.org; dmarc=pass header.from=example.com\r\n"));
        $this->assertTrue($this->auth("Authentication-Results: mx.example.org; dmarc=pass\r\n"));
    }

    public function testDmarcPassForOtherHeaderFromDoesNotAuthenticate(): void
    {
        $this->assertFalse($this->auth("Authentication-Results: mx.example.org; dmarc=pass header.from=other.org\r\n"));
    }

    public function testFailAndNoneDoNotAuthenticate(): void
    {
        $this->assertFalse($this->auth("Authentication-Results: mx.example.org; dkim=fail header.d=example.com; spf=softfail smtp.mailfrom=a@example.com; dmarc=none\r\n"));
    }

    public function testForgedHeaderBelowTheTopmostOneIsIgnored(): void
    {
        $h = "Authentication-Results: mx.example.org; dkim=none; spf=none\r\n"
            . "Authentication-Results: attacker.example; dkim=pass header.d=example.com; dmarc=pass\r\n";
        $this->assertFalse($this->auth($h));
    }

    public function testMissingHeaderDoesNotAuthenticate(): void
    {
        $this->assertFalse($this->auth("From: alice@example.com\r\n"));
    }

    public function testEmptyOrMalformedFromDoesNotAuthenticate(): void
    {
        $h = "Authentication-Results: mx.example.org; dkim=pass header.d=example.com\r\n";
        $this->assertFalse($this->auth($h, ''));
    }

    public function testHeaderInBodyIsIgnored(): void
    {
        $this->assertFalse($this->auth("Subject: x\r\n\r\nAuthentication-Results: mx.example.org; dkim=pass header.d=example.com\r\n"));
    }
}
