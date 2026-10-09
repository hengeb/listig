<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Logging\LogLevel;
use Hengeb\Listig\Logging\Logger;
use Hengeb\Listig\Mail\BodyPersonalizer;
use Hengeb\Listig\Mail\BounceSuppressionList;
use Hengeb\Listig\Mail\FooterAppender;
use Hengeb\Listig\Mail\HeaderFilter;
use Hengeb\Listig\Mail\MailProcessor;
use Hengeb\Listig\Mail\ReplyTarget;
use Hengeb\Listig\Mail\ReplyTargetStore;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Mail\ReplyThreadStore;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Queue\QueueWriter;
use Hengeb\Listig\Token\TokenService;
use PhpImap\IncomingMail;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mime\Email;
use Symfony\Contracts\Translation\TranslatorInterface;

/** A mail to a `+re-{TOKEN}` address is distributed as a threaded reply from the list address (ADR-0020). */
class MailProcessorThreadReplyTest extends TestCase
{
    /** @var Email[] */
    private array $sent = [];

    private function process(string $to, ?array $parent, string $extraHeaders = '', array $rawConfig = ['reply-to' => 'list'], ?ReplyTargetStore $targets = null): Email
    {
        $threads = $this->createStub(ReplyThreadStore::class);
        $threads->method('extractToken')->willReturn(str_contains($to, '+re-') ? 'tok' : null);
        $threads->method('resolveMail')->willReturn($parent);

        $this->sent = [];
        $queue = $this->createStub(QueueWriter::class);
        $queue->method('enqueue')->willReturnCallback(function (string $listCn, Email $email) {
            $this->sent[] = $email;
        });

        $processor = new MailProcessor(
            new HeaderFilter(),
            new BodyPersonalizer(),
            new FooterAppender(),
            $queue,
            new TokenService(str_repeat('k', 32)),
            'lists.example.org',
            new Logger(LogLevel::Error),
            $this->createStub(TranslatorInterface::class),
            $this->createStub(BounceSuppressionList::class),
            $targets ?? $this->createStub(ReplyTargetStore::class),
            $threads,
        );

        $mail = new IncomingMail();
        $mail->headersRaw = "To: $to\r\nFrom: m@example.org\r\nMessage-ID: <new@x>\r\n$extraHeaders";
        $mail->subject = 'Re: Hallo';
        $mail->fromAddress = 'm@example.org';
        // textPlain is private with a lazy IMAP-backed __get() — Reflection is the only way to seed it (see SpamFilterTest).
        (new \ReflectionProperty($mail, 'textPlain'))->setValue($mail, 'Antwort');
        $mail->to = [$to => null];
        $mail->cc = [];
        $list = new ListConfig('news', 'news@example.org', $rawConfig, new InlineMemberResolver(['m@example.org', 'n@example.org'], ['o@example.org']));

        $processor->process($mail, "raw\r\n", $list);
        $this->assertNotEmpty($this->sent);
        return $this->sent[0];
    }

    public function testReplyIsThreadedUnderTheArchivedMailAndTheTokenAddressIsHidden(): void
    {
        $email = $this->process('news+re-tok@example.org', ['message_id' => 'parent@x', 'thread_root' => 'root@x']);
        $this->assertSame('<parent@x>', $email->getHeaders()->get('In-Reply-To')->getBodyAsString());
        $this->assertSame('<root@x> <parent@x>', $email->getHeaders()->get('References')->getBodyAsString());
        $to = array_map(fn($a) => $a->getAddress(), $email->getTo());
        $this->assertSame(['news@example.org'], $to, 'recipients must see the list address, not the token');
    }

    public function testReplyToTheThreadRootNeedsNoSeparateRootReference(): void
    {
        $email = $this->process('news+re-tok@example.org', ['message_id' => 'root@x', 'thread_root' => 'root@x']);
        $this->assertSame('<root@x>', $email->getHeaders()->get('References')->getBodyAsString());
    }

    public function testHeadersTheClientSetItselfAreKept(): void
    {
        $email = $this->process('news+re-tok@example.org', ['message_id' => 'parent@x', 'thread_root' => 'root@x'], "In-Reply-To: <own@x>\r\n");
        $this->assertSame('<own@x>', $email->getHeaders()->get('In-Reply-To')->getBodyAsString());
    }

    public function testTokenThatNoLongerResolvesStillHidesTheAddressWithoutThreading(): void
    {
        // e.g. accepted from moderation long after arrival — IncomingMailFilter rejected a dead token at arrival already.
        $email = $this->process('news+re-tok@example.org', null);
        $this->assertFalse($email->getHeaders()->has('In-Reply-To'));
        $this->assertSame(['news@example.org'], array_map(fn($a) => $a->getAddress(), $email->getTo()));
    }

    public function testPlainMailIsUntouched(): void
    {
        $email = $this->process('news@example.org', null);
        $this->assertFalse($email->getHeaders()->has('In-Reply-To'));
        $this->assertSame(['news@example.org'], array_map(fn($a) => $a->getAddress(), $email->getTo()));
    }

    /** The archive's "reply to the author" button on a `reply-to: sender` list: private, answered through the author's token. */
    public function testRelayedReplyOnASenderListIsPrivateAndKeepsTheBackAndForthAnonymous(): void
    {
        $targets = $this->createStub(ReplyTargetStore::class);
        $targets->method('extractToken')->willReturn('tok');
        $targets->method('resolve')->willReturn(new ReplyTarget(new Member('n@example.org'), false));
        $targets->method('tokenFor')->willReturn('REPLIER');

        $email = $this->process('news+r-tok@example.org', null, '', ['reply-to' => 'sender'], $targets);

        $this->assertSame(['news+r-REPLIER@example.org'], array_map(fn($a) => $a->getAddress(), $email->getReplyTo()), 'not the replier\'s real address, not the list');
        $this->assertSame(['news@example.org'], array_map(fn($a) => $a->getAddress(), $email->getTo()));
        $this->assertCount(1, $this->sent, 'only the author gets a copy');
    }
}
