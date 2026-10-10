<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Queue;

use Hengeb\Listig\Queue\QueueMime;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

class QueueMimeTest extends TestCase
{
    private function email(string $text, string $unsubscribeToken = 'T1', string $attachment = 'PDF-BYTES'): Email
    {
        $email = (new Email())
            ->from(new Address('list@example.org', 'List'))
            ->to(new Address('list@example.org'))
            ->subject('Hello')
            ->text($text)
            ->html('<p>' . $text . '</p>')
            ->attach($attachment, 'doc.pdf', 'application/pdf');
        $email->getHeaders()->addIdHeader('Message-ID', 'fixed@example.org');
        $email->getHeaders()->addTextHeader('List-Unsubscribe', "<https://example.org/u?token={$unsubscribeToken}>");
        return $email;
    }

    public function testHeadersAndBodyTogetherAreTheWholeMessage(): void
    {
        $email = $this->email('Hi');
        [$headers, $body] = QueueMime::split($email);

        $this->assertStringContainsString('List-Unsubscribe: <https://example.org/u?token=T1>', $headers);
        $this->assertStringContainsString('Subject: Hello', $headers);
        $this->assertStringNotContainsString('Content-Type', $headers, 'the part headers belong to the (shared) body');
        $this->assertStringStartsWith('Content-Type: multipart/mixed; boundary=', $body);
        $this->assertStringEndsWith("\r\n", $headers);

        // What a receiving server would parse: one header block, a blank line (inside $body), the content.
        $whole = $headers . $body;
        preg_match('/boundary=([^\s;"]+)/', $whole, $m);
        $this->assertStringContainsString('--' . $m[1] . "\r\n", $whole);
        $this->assertStringContainsString('--' . $m[1] . "--\r\n", $whole);
    }

    public function testTheSameContentBuiltTwiceHasTheSameKeyDespiteDifferentBoundaries(): void
    {
        [, $a] = QueueMime::split($this->email('Hi'));
        [, $b] = QueueMime::split($this->email('Hi'));

        $this->assertNotSame($a, $b, 'random boundaries make the raw bodies differ');
        $this->assertSame(QueueMime::bodyKey($a), QueueMime::bodyKey($b));
    }

    public function testRecipientSpecificHeadersDoNotChangeTheBodyKey(): void
    {
        [$h1, $b1] = QueueMime::split($this->email('Hi', 'TOKEN-ALICE'));
        [$h2, $b2] = QueueMime::split($this->email('Hi', 'TOKEN-BOB'));

        $this->assertNotSame($h1, $h2);
        $this->assertSame(QueueMime::bodyKey($b1), QueueMime::bodyKey($b2));
    }

    public function testDifferentContentOrAttachmentGivesADifferentKey(): void
    {
        [, $base] = QueueMime::split($this->email('Hi'));
        [, $text] = QueueMime::split($this->email('Hello Alice'));
        [, $file] = QueueMime::split($this->email('Hi', 'T1', 'OTHER-BYTES'));

        $this->assertNotSame(QueueMime::bodyKey($base), QueueMime::bodyKey($text));
        $this->assertNotSame(QueueMime::bodyKey($base), QueueMime::bodyKey($file));
    }

    public function testAPlainTextMailWithoutBoundariesIsKeyedByItsContent(): void
    {
        $plain = fn(string $t) => (new Email())->from('a@example.org')->to('b@example.org')->text($t);
        [, $a] = QueueMime::split($plain('Hi'));
        [, $b] = QueueMime::split($plain('Hi'));
        [, $c] = QueueMime::split($plain('Ho'));

        $this->assertSame(QueueMime::bodyKey($a), QueueMime::bodyKey($b));
        $this->assertNotSame(QueueMime::bodyKey($a), QueueMime::bodyKey($c));
    }
}
