<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\BounceCause;
use Hengeb\Listig\Mail\BounceCauseClassifier;
use PHPUnit\Framework\TestCase;

class BounceCauseClassifierTest extends TestCase
{
    public function testSpamReasonIsClassifiedAsSpam(): void
    {
        $result = (new BounceCauseClassifier())->classify('550 5.7.1 Message rejected as spam');
        $this->assertSame(BounceCause::Spam, $result);
    }

    public function testNonSpamReasonIsNotClassified(): void
    {
        $result = (new BounceCauseClassifier())->classify('550 5.1.1 mailbox does not exist');
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
}
