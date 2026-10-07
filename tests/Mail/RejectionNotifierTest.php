<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Mail\OrganizationalDomain;
use Hengeb\Listig\Mail\RejectionNotifier;
use Hengeb\Listig\Mail\SenderAuthenticator;
use Hengeb\Listig\Mail\SenderNoticePolicy;
use Hengeb\Listig\RateLimit\RateLimiter;
use PhpImap\IncomingMail;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

/** End to end through the notifier: who gets a notice, and with or without the original. */
class RejectionNotifierTest extends TestCase
{
    private function notifier(NotificationMailer $mailer): RejectionNotifier
    {
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturnArgument(0);
        $headerFilter = new HeaderFilter();
        $policy = new SenderNoticePolicy(
            new SenderAuthenticator($headerFilter, new OrganizationalDomain()),
            $this->createStub(RateLimiter::class),
            $headerFilter,
        );
        return new RejectionNotifier($mailer, $translator, $policy);
    }

    private function mail(string $authResults): IncomingMail
    {
        $mail = new IncomingMail();
        $mail->headersRaw = $authResults;
        $mail->fromAddress = 'alice@example.com';
        $mail->subject = 'Hi';
        return $mail;
    }

    private function list(): ListConfig
    {
        return new ListConfig('mylist', 'mylist@example.org', []);
    }

    public function testAuthenticatedSenderGetsNoticeWithOriginal(): void
    {
        $mailer = $this->createMock(NotificationMailer::class);
        $mailer->expects($this->once())->method('send')
            ->with($this->anything(), 'alice@example.com', $this->anything(), $this->anything(), 'RAW', 'original.eml', 'message/rfc822');
        $this->notifier($mailer)->notify(
            $this->list(),
            $this->mail("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=alice@example.com\r\n"),
            'RAW',
            'reject.public_denied',
        );
    }

    public function testForgedSenderGetsNothing(): void
    {
        $this->expectErrorLog();
        $mailer = $this->createMock(NotificationMailer::class);
        $mailer->expects($this->never())->method('send');
        $this->notifier($mailer)->notify(
            $this->list(),
            $this->mail("Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=alice@example.com\r\n"),
            'RAW',
            'reject.auth_failed',
        );
    }
}
