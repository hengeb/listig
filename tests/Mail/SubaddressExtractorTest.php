<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\SubaddressExtractor;
use PhpImap\IncomingMail;
use PHPUnit\Framework\TestCase;

class SubaddressExtractorTest extends TestCase
{
    private function listWithMail(string $mail): ListConfig
    {
        return new ListConfig('fwd', $mail, []);
    }

    public function testExtractsSubaddressFromToHeader(): void
    {
        $mail = new IncomingMail();
        $mail->to = ['fwd+alice@example.org' => 'Alice'];

        $subaddress = SubaddressExtractor::extract($mail, $this->listWithMail('fwd@example.org'));
        $this->assertSame('alice', $subaddress);
    }

    public function testExtractsSubaddressFromCcHeader(): void
    {
        $mail = new IncomingMail();
        $mail->cc = ['fwd+bob@example.org' => 'Bob'];

        $subaddress = SubaddressExtractor::extract($mail, $this->listWithMail('fwd@example.org'));
        $this->assertSame('bob', $subaddress);
    }

    public function testReturnsNullWhenNoSubaddressPresent(): void
    {
        $mail = new IncomingMail();
        $mail->to = ['fwd@example.org' => ''];

        $subaddress = SubaddressExtractor::extract($mail, $this->listWithMail('fwd@example.org'));
        $this->assertNull($subaddress);
    }

    public function testDoesNotMatchDifferentDomain(): void
    {
        // fwd+alice@other-domain.com must NOT match, even though the local part
        // and subaddress look right — domain must match too.
        $mail = new IncomingMail();
        $mail->to = ['fwd+alice@other-domain.com' => ''];

        $subaddress = SubaddressExtractor::extract($mail, $this->listWithMail('fwd@example.org'));
        $this->assertNull($subaddress);
    }

    public function testDoesNotMatchDifferentLocalPart(): void
    {
        $mail = new IncomingMail();
        $mail->to = ['other+alice@example.org' => ''];

        $subaddress = SubaddressExtractor::extract($mail, $this->listWithMail('fwd@example.org'));
        $this->assertNull($subaddress);
    }

    public function testMatchIsCaseInsensitive(): void
    {
        $mail = new IncomingMail();
        $mail->to = ['FWD+Alice@Example.ORG' => ''];

        $subaddress = SubaddressExtractor::extract($mail, $this->listWithMail('fwd@example.org'));
        $this->assertSame('Alice', $subaddress);
    }
}
