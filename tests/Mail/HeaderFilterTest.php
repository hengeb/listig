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

    public function testReadAuthResultsExtractsDkimSigningDomain(): void
    {
        $raw = "Authentication-Results: mx.example.org;\r\n"
            . " dkim=pass header.i=@gmail.com header.s=20230601 header.d=gmail.com header.b=abc123\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('pass', $result['dkim']);
        $this->assertSame('gmail.com', $result['dkimDomain']);
    }

    public function testReadAuthResultsDkimDomainIsLowercased(): void
    {
        $raw = "Authentication-Results: mx.example.org; dkim=pass header.d=Gmail.COM\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('gmail.com', $result['dkimDomain']);
    }

    public function testReadAuthResultsDkimDomainNullWhenDkimMissing(): void
    {
        $raw = "Authentication-Results: mx.example.org; spf=pass\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertNull($result['dkimDomain']);
    }

    public function testReadAuthResultsDkimDomainNullWhenNoHeaderDParam(): void
    {
        $raw = "Authentication-Results: mx.example.org; dkim=pass\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('pass', $result['dkim']);
        $this->assertNull($result['dkimDomain']);
    }

    public function testReadAuthResultsUsesOnlyTheTopmostHeader(): void
    {
        // The own MTA prepends its header; a header supplied by the sender further down must lose.
        $raw = "Authentication-Results: mx.example.org; dkim=none\r\n"
            . "Authentication-Results: evil.example; dkim=pass header.d=bank.de\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('none', $result['dkim']);
        $this->assertNull($result['dkimDomain']);
    }

    public function testReadAuthResultsIgnoresVersionAfterAuthservId(): void
    {
        $raw = "Authentication-Results: MX.Example.org 1; spf=pass\r\n";
        $this->assertSame('pass', $this->headerFilter->readAuthResults($raw)['spf']);
    }

    public function testReadAuthResultsIgnoresCommentsAndQuotedSeparators(): void
    {
        $raw = "Authentication-Results: mx.example.org; spf=fail (sender SPF; dkim=pass header.d=bank.de) smtp.mailfrom=a@x.de;\r\n"
            . " dkim=none reason=\"x; dkim=pass\"\r\n";
        $result = $this->headerFilter->readAuthResults($raw);
        $this->assertSame('fail', $result['spf']);
        $this->assertSame('none', $result['dkim']);
    }

    public function testReadAuthResultsOnlyReadsTheHeaderBlock(): void
    {
        // BounceHandler passes a whole MIME message; quoted headers in the body must not count.
        $raw = "From: a@b.de\r\n\r\nAuthentication-Results: mx.example.org; dkim=pass header.d=bank.de\r\n";
        $this->assertNull($this->headerFilter->readAuthResults($raw)['dkim']);
    }

    public function testWithoutTrustedIdsTheTopmostHeaderCountsWhateverItsId(): void
    {
        $raw = "Authentication-Results: whatever.example; dkim=pass header.d=a.de\r\n"
            . "Authentication-Results: mx.example.org; dkim=fail\r\n";
        $this->assertSame('pass', $this->headerFilter->readAuthResults($raw)['dkim']);
        $this->assertSame('pass', $this->headerFilter->readAuthResults($raw, [])['dkim']);
    }

    public function testTrustedIdIgnoresForgedHeaderAboveTheRealOne(): void
    {
        $raw = "Authentication-Results: evil.example; dkim=pass header.d=bank.de\r\n"
            . "Authentication-Results: mx.example.org; dkim=none\r\n";
        $result = $this->headerFilter->readAuthResults($raw, ['mx.example.org']);
        $this->assertSame('none', $result['dkim']);
        $this->assertNull($result['dkimDomain']);
    }

    public function testTrustedIdWithoutMatchingHeaderYieldsNothing(): void
    {
        $raw = "Authentication-Results: evil.example; spf=pass; dkim=pass header.d=bank.de\r\n";
        $result = $this->headerFilter->readAuthResults($raw, ['mx.example.org']);
        $this->assertNull($result['spf']);
        $this->assertNull($result['dkim']);
        $this->assertNull($this->headerFilter->parseAuthResults($raw, ['mx.example.org']));
        $this->assertNull($this->headerFilter->parseAuthResults("From: a@b.de\r\n", ['mx.example.org']));
    }

    public function testTrustedIdsMatchAnyOfSeveralValuesCaseInsensitively(): void
    {
        $raw = "Authentication-Results: MX2.Example.org 1; spf=pass\r\n";
        $this->assertSame('pass', $this->headerFilter->readAuthResults($raw, ['mx1.example.org', 'mx2.example.org'])['spf']);
    }

    public function testTrustedIdMatchWorksOnFoldedHeader(): void
    {
        $raw = "Authentication-Results:\r\n mx.example.org 1;\r\n dkim=pass\r\n header.d=example.com\r\n";
        $result = $this->headerFilter->readAuthResults($raw, ['mx.example.org']);
        $this->assertSame('pass', $result['dkim']);
        $this->assertSame('example.com', $result['dkimDomain']);
    }

    public function testTrustedIdMergesSeparateHeadersOfTheSameServerTopmostFirst(): void
    {
        // e.g. opendkim and an SPF filter each write their own header with the same id.
        $raw = "Authentication-Results: mx.example.org; dkim=fail header.d=a.de\r\n"
            . "Authentication-Results: evil.example; spf=pass\r\n"
            . "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=a@a.de; dkim=pass header.d=a.de\r\n";
        $result = $this->headerFilter->readAuthResults($raw, ['mx.example.org']);
        $this->assertSame('pass', $result['spf']);
        $this->assertSame('fail', $result['dkim'], 'topmost matching header wins per method');
        $header = $this->headerFilter->parseAuthResults($raw, ['mx.example.org']);
        $this->assertCount(2, $header->all('dkim'));
    }

    public function testReadAuthservIdsListsDistinctIdsTopmostFirst(): void
    {
        $raw = "Authentication-Results: mx.example.org; spf=pass\r\n"
            . "Authentication-Results: other.example 1; dkim=none\r\n"
            . "Authentication-Results: MX.example.org; dkim=pass\r\n";
        $this->assertSame(['mx.example.org', 'other.example'], $this->headerFilter->readAuthservIds($raw));
        $this->assertSame([], $this->headerFilter->readAuthservIds("From: a@b.de\r\n"));
    }

    public function testReadAllConnectingIpsExtractsEveryHopInOrder(): void
    {
        // The exact real-world shape confirmed in production: a topmost
        // local LMTP hand-off (from a combined send+receive server to its
        // own mailbox) followed by a purely local injection (no "from"
        // clause at all — this is what actually proves the bounce was
        // genuinely generated locally, not externally SMTP-submitted).
        $raw = "Received: from mail.example.org ([10.11.0.5])\r\n"
            . " by mail.example.org with LMTP id abc123\r\n"
            . " (envelope-from <>) for <someone@example.org>; Thu, 20 Aug 2026 12:00:00 +0200\r\n"
            . "Received: by mail.example.org (Postfix)\r\n"
            . " id def456; Thu, 20 Aug 2026 11:59:00 +0200\r\n";
        $this->assertSame(['10.11.0.5'], $this->headerFilter->readAllConnectingIps($raw));
    }

    public function testReadAllConnectingIpsExtractsIpv6(): void
    {
        $raw = "Received: from relay.example.org (relay.example.org [2001:db8::1])\r\n"
            . " by mail.example.org; Thu, 20 Aug 2026 12:00:00 +0000\r\n";
        $this->assertSame(['2001:db8::1'], $this->headerFilter->readAllConnectingIps($raw));
    }

    public function testReadAllConnectingIpsFindsExternalHopBehindLocalOne(): void
    {
        // The attack scenario this method exists to catch: an attacker's
        // forged bounce, submitted directly via SMTP, still gets a genuine
        // "from ATTACKER-IP" hop added by the receiving server itself
        // *before* the same final local LMTP hand-off every message shows —
        // so the external IP must still surface even though it isn't the
        // topmost header.
        $raw = "Received: from mail.example.org ([10.11.0.5])\r\n"
            . " by mail.example.org with LMTP; Thu, 20 Aug 2026 12:00:01 +0200\r\n"
            . "Received: from attacker.example ([203.0.113.66])\r\n"
            . " by mail.example.org with ESMTP; Thu, 20 Aug 2026 12:00:00 +0200\r\n";
        $this->assertSame(['10.11.0.5', '203.0.113.66'], $this->headerFilter->readAllConnectingIps($raw));
    }

    public function testReadAllConnectingIpsReturnsEmptyArrayWhenNoReceivedHeader(): void
    {
        $this->assertSame([], $this->headerFilter->readAllConnectingIps("From: alice@example.org\r\n"));
    }

    public function testReadAllConnectingIpsSkipsHeaderWithNoBracketedIp(): void
    {
        $raw = "Received: from localhost by mail.example.org (Postfix, from userid 0);\r\n"
            . " Thu, 20 Aug 2026 12:00:00 +0000\r\n";
        $this->assertSame([], $this->headerFilter->readAllConnectingIps($raw));
    }

    public function testNormalizeIpCanonicalizesIpv6ZeroCompression(): void
    {
        // "2001:db8::1" and "2001:0db8:0000:0000:0000:0000:0000:0001" must
        // compare equal after normalization, even though they're spelled
        // differently — BounceHandler compares against operator-configured
        // trusted IPs, which may not use the exact same compressed form a
        // real Received header happens to use.
        $this->assertSame(
            HeaderFilter::normalizeIp('2001:db8::1'),
            HeaderFilter::normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001'),
        );
    }

    public function testNormalizeIpReturnsNullForInvalidInput(): void
    {
        $this->assertNull(HeaderFilter::normalizeIp('not-an-ip'));
    }

    public function testIsPublicIpFalseForRfc1918PrivateRanges(): void
    {
        $this->assertFalse(HeaderFilter::isPublicIp('10.11.0.5'));
        $this->assertFalse(HeaderFilter::isPublicIp('172.16.0.1'));
        $this->assertFalse(HeaderFilter::isPublicIp('192.168.1.1'));
    }

    public function testIsPublicIpFalseForLoopbackAndReserved(): void
    {
        $this->assertFalse(HeaderFilter::isPublicIp('127.0.0.1'));
        $this->assertFalse(HeaderFilter::isPublicIp('::1'));
    }

    public function testIsPublicIpFalseForIpv6UniqueLocal(): void
    {
        $this->assertFalse(HeaderFilter::isPublicIp('fc00::1'));
    }

    public function testIsPublicIpTrueForRoutableAddress(): void
    {
        $this->assertTrue(HeaderFilter::isPublicIp('203.0.113.66'));
    }
}
