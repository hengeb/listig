<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\FilterResult;
use PHPUnit\Framework\TestCase;

class FilterResultTest extends TestCase
{
    public function testDiscardIsOnlyIsDiscard(): void
    {
        $result = FilterResult::discard();
        $this->assertTrue($result->isDiscard);
        $this->assertFalse($result->isBounce);
        $this->assertFalse($result->isReject);
        $this->assertFalse($result->isModeration);
        $this->assertFalse($result->isDistribute);
        $this->assertFalse($result->forceDelete);
    }

    public function testDiscardWithForceDelete(): void
    {
        $result = FilterResult::discard(forceDelete: true);
        $this->assertTrue($result->forceDelete);
    }

    public function testBounceIsOnlyIsBounce(): void
    {
        $result = FilterResult::bounce();
        $this->assertTrue($result->isBounce);
        $this->assertFalse($result->isDiscard);
    }

    public function testRejectCarriesReasonAndParams(): void
    {
        $result = FilterResult::reject('reject.size_exceeded', ['%max_size%' => 100]);
        $this->assertTrue($result->isReject);
        $this->assertSame('reject.size_exceeded', $result->reason);
        $this->assertSame(['%max_size%' => 100], $result->reasonParams);
    }

    public function testRejectDefaultsToNoForceDelete(): void
    {
        $result = FilterResult::reject('reject.auth_failed');
        $this->assertFalse($result->forceDelete);
    }

    public function testRejectCanForceDelete(): void
    {
        // Spam filter matches force-delete regardless of the list's archive: setting.
        $result = FilterResult::reject('reject.spam', forceDelete: true);
        $this->assertTrue($result->forceDelete);
    }

    public function testModerationIsOnlyIsModeration(): void
    {
        $result = FilterResult::moderation();
        $this->assertTrue($result->isModeration);
        $this->assertFalse($result->isDistribute);
    }

    public function testDistributeIsOnlyIsDistribute(): void
    {
        $result = FilterResult::distribute();
        $this->assertTrue($result->isDistribute);
        $this->assertFalse($result->isModeration);
    }
}
