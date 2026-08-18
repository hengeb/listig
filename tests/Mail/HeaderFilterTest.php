<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\HeaderFilter;
use PHPUnit\Framework\TestCase;

class HeaderFilterTest extends TestCase
{
    private HeaderFilter $headerFilter;

    protected function setUp(): void
    {
        $this->headerFilter = new HeaderFilter();
    }

    public function testUnfoldsWrappedHeaderLine(): void
    {
        $raw = "Subject: Hello\r\n World\r\nFrom: alice@example.org";
        $this->assertSame("Subject: Hello World\r\nFrom: alice@example.org", $this->headerFilter->unfold($raw));
    }

    public function testReadHeaderFindsSimpleValue(): void
    {
        $raw = "Subject: Test Mail\r\nFrom: alice@example.org\r\n";
        $this->assertSame('Test Mail', $this->headerFilter->readHeader($raw, 'Subject'));
    }

    public function testReadHeaderIsCaseInsensitive(): void
    {
        $raw = "SUBJECT: Test Mail\r\n";
        $this->assertSame('Test Mail', $this->headerFilter->readHeader($raw, 'subject'));
    }

    public function testReadHeaderReturnsNullWhenAbsent(): void
    {
        $raw = "From: alice@example.org\r\n";
        $this->assertNull($this->headerFilter->readHeader($raw, 'Subject'));
    }

    public function testReadHeaderHandlesFoldedValue(): void
    {
        $raw = "Subject: Hello\r\n World\r\n";
        $this->assertSame('Hello World', $this->headerFilter->readHeader($raw, 'Subject'));
    }

    public function testReadMessageIdStripsAngleBrackets(): void
    {
        $raw = "Message-ID: <abc123@example.org>\r\n";
        $this->assertSame('abc123@example.org', $this->headerFilter->readMessageId($raw));
    }

    public function testReadMessageIdReturnsNullWhenAbsent(): void
    {
        $this->assertNull($this->headerFilter->readMessageId("From: alice@example.org\r\n"));
    }

    public function testReadMessageIdReturnsNullForEmptyValue(): void
    {
        $this->assertNull($this->headerFilter->readMessageId("Message-ID: <>\r\n"));
    }

    public function testReadAuthResultsParsesSpfAndDkim(): void
    {
        $raw = "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=alice@example.org; dkim=fail\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('pass', $result['spf']);
        $this->assertSame('fail', $result['dkim']);
    }

    public function testReadAuthResultsHandlesSemicolonWithNoSpace(): void
    {
        // Some MTAs write "spf=fail;" with no space — a bare \S+ would swallow
        // the semicolon and beyond.
        $raw = "Authentication-Results: mx.example.org; spf=fail;dkim=pass;\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('fail', $result['spf']);
        $this->assertSame('pass', $result['dkim']);
    }

    public function testReadAuthResultsReturnsNullsWhenAbsent(): void
    {
        $result = $this->headerFilter->readAuthResults("From: alice@example.org\r\n");
        $this->assertNull($result['spf']);
        $this->assertNull($result['dkim']);
    }

    public function testReadAuthResultsIsCaseInsensitiveForValues(): void
    {
        $raw = "Authentication-Results: mx.example.org; SPF=PASS\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('pass', $result['spf']);
    }
}
