<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\BounceCause;
use Hengeb\Listig\Mail\BounceCauseClassifier;
use Hengeb\Listig\Queue\SpamRejectionDetector;
use PHPUnit\Framework\TestCase;

class BounceCauseClassifierTest extends TestCase
{
    private function classifier(array $additionalReliableDomains = []): BounceCauseClassifier
    {
        return new BounceCauseClassifier(new SpamRejectionDetector($additionalReliableDomains));
    }

    public function testSpamReasonFromReliableDomainIsClassifiedAsSpam(): void
    {
        $result = $this->classifier()->classify('550 5.7.1 Message rejected as spam', 'someone@gmail.com');
        $this->assertSame(BounceCause::Spam, $result);
    }

    public function testSpamReasonFromUnreliableDomainIsNotClassified(): void
    {
        // Same trust boundary as SpamRejectionDetector::isSpamRejection() — a
        // forged/misconfigured bounce must not be able to trigger the
        // automatic action for a domain Listig has no reason to trust.
        $result = $this->classifier()->classify('rejected as spam', 'someone@totally-unknown-domain.example');
        $this->assertNull($result);
    }

    public function testNonSpamReasonFromReliableDomainIsNotClassified(): void
    {
        $result = $this->classifier()->classify('550 5.1.1 mailbox does not exist', 'someone@gmail.com');
        $this->assertNull($result);
    }

    public function testNullReasonIsNotClassified(): void
    {
        $this->assertNull($this->classifier()->classify(null, 'someone@gmail.com'));
    }

    public function testNullFailedRecipientIsNotClassified(): void
    {
        $this->assertNull($this->classifier()->classify('rejected as spam', null));
    }

    public function testConfiguredAdditionalReliableDomainIsRecognized(): void
    {
        $result = $this->classifier(['custom-provider.example'])
            ->classify('rejected as spam', 'someone@custom-provider.example');
        $this->assertSame(BounceCause::Spam, $result);
    }

    public function testSpamCheckIsCaseInsensitive(): void
    {
        $result = $this->classifier()->classify('550 Message REJECTED AS SPAM', 'someone@gmail.com');
        $this->assertSame(BounceCause::Spam, $result);
    }
}
