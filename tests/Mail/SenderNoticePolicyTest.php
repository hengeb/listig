<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\OrganizationalDomain;
use Hengeb\Listig\Mail\SenderAuthenticator;
use Hengeb\Listig\Mail\SenderNoticePolicy;
use Hengeb\Listig\RateLimit\RateLimiter;
use PhpImap\IncomingMail;
use PHPUnit\Framework\TestCase;

class SenderNoticePolicyTest extends TestCase
{
    private const AUTH = "Authentication-Results: mx.example.org; dkim=pass header.d=example.com\r\n";

    private function policy(bool $throttled = false): SenderNoticePolicy
    {
        $limiter = $this->createStub(RateLimiter::class);
        $limiter->method('isNoticeThrottled')->willReturn($throttled);
        $headerFilter = new HeaderFilter();
        return new SenderNoticePolicy(new SenderAuthenticator($headerFilter, new OrganizationalDomain()), $limiter, $headerFilter);
    }

    private function list(array $raw = []): ListConfig
    {
        return new ListConfig('mylist', 'mylist@example.org', $raw);
    }

    private function mail(string $headers = self::AUTH, string $from = 'alice@example.com'): IncomingMail
    {
        $mail = new IncomingMail();
        $mail->headersRaw = $headers;
        $mail->fromAddress = $from;
        return $mail;
    }

    public function testAuthenticatedSenderGetsNoticeWithOriginal(): void
    {
        $d = $this->policy()->decide($this->list(), $this->mail(), 'reject.public_denied');
        $this->assertTrue($d->send);
        $this->assertTrue($d->attachOriginal);
    }

    public function testUnauthenticatedSenderGetsNothingByDefault(): void
    {
        $this->expectErrorLog(); // suppressions are logged on purpose
        $d = $this->policy()->decide($this->list(), $this->mail("From: x\r\n"), 'reject.public_denied');
        $this->assertFalse($d->send);
        $this->assertSame('unauthenticated', $d->suppressReason);
    }

    public function testForgedHeaderBelowTheTopmostOneDoesNotCount(): void
    {
        $this->expectErrorLog();
        $forged = "Authentication-Results: mx.example.org; dkim=none
"
            . "Authentication-Results: attacker.example; dkim=pass header.d=example.com
";
        $this->assertFalse($this->policy()->decide($this->list(), $this->mail($forged), null)->send);
    }

    public function testAlwaysSendsToUnauthenticatedWithoutOriginal(): void
    {
        $d = $this->policy()->decide($this->list(['sender-notices' => 'always']), $this->mail("From: x\r\n"), 'reject.public_denied');
        $this->assertTrue($d->send);
        $this->assertFalse($d->attachOriginal);
    }

    public function testNeverSuppressesEvenForAuthenticated(): void
    {
        $this->expectErrorLog(); // suppressions are logged on purpose
        $d = $this->policy()->decide($this->list(['sender-notices' => 'never']), $this->mail(), null);
        $this->assertFalse($d->send);
        $this->assertSame('disabled', $d->suppressReason);
    }

    public function testAuthFailAndSpamAreNeverNotifiedEvenWhenAlways(): void
    {
        $this->expectErrorLog(); // suppressions are logged on purpose
        foreach (['reject.auth_failed', 'reject.spam', 'reject.unauthenticated'] as $reason) {
            foreach (['authenticated', 'always'] as $mode) {
                $d = $this->policy()->decide($this->list(['sender-notices' => $mode]), $this->mail(), $reason);
                $this->assertFalse($d->send, "$reason / $mode");
            }
        }
    }

    public function testThrottledSenderIsSuppressed(): void
    {
        $this->expectErrorLog(); // suppressions are logged on purpose
        $d = $this->policy(throttled: true)->decide($this->list(), $this->mail(), null);
        $this->assertFalse($d->send);
        $this->assertSame('throttled', $d->suppressReason);
    }

    public function testSizeExceededNeverAttachesOriginal(): void
    {
        $d = $this->policy()->decide($this->list(), $this->mail(), 'reject.size_exceeded');
        $this->assertTrue($d->send);
        $this->assertFalse($d->attachOriginal);
    }

    public function testMissingSenderIsSilentlySkipped(): void
    {
        $this->assertFalse($this->policy()->decide($this->list(), $this->mail(self::AUTH, ''), null)->send);
    }

    public function testConfiguredAuthservIdRejectsForgedTopmostHeader(): void
    {
        $this->expectErrorLog();
        $forged = "Authentication-Results: attacker.example; dkim=pass header.d=example.com\r\n"
            . "Authentication-Results: mx.example.org; dkim=none\r\n";
        $list = $this->list(['trusted-authserv-id' => 'mx.example.org']);
        $d = $this->policy()->decide($list, $this->mail($forged), null);
        $this->assertFalse($d->send);
        $this->assertTrue($this->policy()->decide($this->list(), $this->mail($forged), null)->send);
    }
}
