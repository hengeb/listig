<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\BounceCause;
use Hengeb\Listig\Mail\BounceCauseClassifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class BounceCauseClassifierTest extends TestCase
{
    public function testSpamReasonIsClassifiedAsSpam(): void
    {
        $result = (new BounceCauseClassifier())->classify('550 5.7.1 Message rejected as spam');
        $this->assertSame(BounceCause::Spam, $result);
    }

    public function testUnrecognizedReasonIsNotClassified(): void
    {
        $result = (new BounceCauseClassifier())->classify('450 4.7.1 Greylisted, please try again later');
        $this->assertNull($result);
    }

    public function testNullReasonIsNotClassified(): void
    {
        $this->assertNull((new BounceCauseClassifier())->classify(null));
    }

    public function testSpamCheckIsCaseInsensitive(): void
    {
        $result = (new BounceCauseClassifier())->classify('550 Message REJECTED AS SPAM');
        $this->assertSame(BounceCause::Spam, $result);
    }

    public function testUserUnknownStatusCodeIsClassified(): void
    {
        $result = (new BounceCauseClassifier())->classify('550 5.1.1 <user@example.com>: Recipient address rejected: User unknown');
        $this->assertSame(BounceCause::UserUnknown, $result);
    }

    #[DataProvider('userUnknownStatusCodeProvider')]
    public function testEachUserUnknownStatusCodeIsClassified(string $code): void
    {
        $result = (new BounceCauseClassifier())->classify("550 $code Bad destination");
        $this->assertSame(BounceCause::UserUnknown, $result);
    }

    public static function userUnknownStatusCodeProvider(): array
    {
        return [['5.1.1'], ['5.1.2'], ['5.1.3'], ['5.1.6'], ['5.1.10'], ['4.4.3'], ['5.4.3'], ['4.4.4'], ['5.4.4']];
    }

    public function testPostfixDnsFailureIsClassifiedAsUserUnknown(): void
    {
        // A real bounce confirmed live on the test instance: Postfix's own
        // Diagnostic-Code for "domain doesn't exist" carries no status code
        // at all in its own free text — only the separate Status: field
        // does. BounceHandler::extractClassificationText() concatenates
        // both before handing them to classify(), so this reproduces
        // exactly what the classifier actually receives.
        $diagnosticCode = 'X-Postfix; Host or domain name not found. Name service error '
            . 'for name=mhasdfasdfasdfasdfasdfasdfn.de type=AAAA: Host not found';
        $status = '5.4.4';
        $result = (new BounceCauseClassifier())->classify($diagnosticCode . ' ' . $status);
        $this->assertSame(BounceCause::UserUnknown, $result);
    }

    public function testDiagnosticCodeAloneWithoutStatusStillClassifiesViaKeyword(): void
    {
        // The keyword fallback must also work standalone, in case a future
        // caller (or a server omitting Status: entirely) only ever supplies
        // the free-text Diagnostic-Code.
        $result = (new BounceCauseClassifier())->classify(
            'X-Postfix; Host or domain name not found. Name service error for name=example.invalid type=AAAA: Host not found'
        );
        $this->assertSame(BounceCause::UserUnknown, $result);
    }

    public function testUserUnknownKeywordFallbackWithoutCleanStatusCode(): void
    {
        $result = (new BounceCauseClassifier())->classify('550 unknown user, no mailbox here');
        $this->assertSame(BounceCause::UserUnknown, $result);
    }

    public function testStatusCodeMatchIsWordBoundaryNotSubstring(): void
    {
        // "5.1.10" must not falsely match on a bare "1.1" or "1.10" substring
        // search, and vice versa — these two codes must be told apart.
        $result110 = (new BounceCauseClassifier())->classify('550 5.1.10 Recipient address has null MX');
        $this->assertSame(BounceCause::UserUnknown, $result110);

        $resultUnrelated = (new BounceCauseClassifier())->classify('550 25.1.100 unrelated vendor-specific code');
        $this->assertNull($resultUnrelated);
    }

    public function testMailboxFullStatusCodeIsClassified(): void
    {
        $result = (new BounceCauseClassifier())->classify('452 4.2.2 Mailbox full');
        $this->assertSame(BounceCause::MailboxFull, $result);
    }

    public function testMailboxFullPermanentStatusCodeIsClassified(): void
    {
        $result = (new BounceCauseClassifier())->classify('552 5.2.2 Mailbox full');
        $this->assertSame(BounceCause::MailboxFull, $result);
    }

    public function testMailboxFullKeywordFallback(): void
    {
        $result = (new BounceCauseClassifier())->classify('452 quota exceeded for this recipient');
        $this->assertSame(BounceCause::MailboxFull, $result);
    }

    public function testSpamTakesPriorityOverOtherCauses(): void
    {
        // A rare but possible overlap (e.g. a server phrasing a spam rejection
        // in a way that also happens to contain "does not exist") — Spam is
        // checked first, matching containsSpamIndicator()'s own precedent from
        // the synchronous SpamRejectionDetector path.
        $result = (new BounceCauseClassifier())->classify('550 5.7.1 rejected as spam, mailbox does not exist');
        $this->assertSame(BounceCause::Spam, $result);
    }
}
