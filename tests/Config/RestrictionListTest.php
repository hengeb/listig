<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config;

use Hengeb\Listig\Config\RestrictionList;
use PHPUnit\Framework\TestCase;

class RestrictionListTest extends TestCase
{
    public function testUnrelatedAddressIsNeverRestricted(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org']]);
        $this->assertFalse($list->isSendRestricted('mylist', 'other@x.org'));
    }

    public function testEntryWithNoListsOrExceptAppliesToEveryList(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org']]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
        $this->assertTrue($list->isSendRestricted('another-list', 'blocked@x.org'));
    }

    public function testMatchIsCaseInsensitive(): void
    {
        $list = new RestrictionList([['mail' => 'Blocked@X.org']]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
    }

    public function testDefaultDoesNotRestrictReceiving(): void
    {
        // Default is write-only — receive: true is the implicit default and
        // means "do NOT also block receiving".
        $list = new RestrictionList([['mail' => 'blocked@x.org']]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
        $this->assertFalse($list->isReceiveRestricted('mylist', 'blocked@x.org'));
    }

    public function testReceiveFalseAlsoBlocksReceiving(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org', 'receive' => false]]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
        $this->assertTrue($list->isReceiveRestricted('mylist', 'blocked@x.org'));
    }

    public function testListsScopesTheRestrictionToNamedLists(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org', 'lists' => ['mylist']]]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
        $this->assertFalse($list->isSendRestricted('other-list', 'blocked@x.org'));
    }

    public function testExceptExcludesNamedListsFromAGlobalRestriction(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org', 'except' => ['board-internal']]]);
        $this->assertFalse($list->isSendRestricted('board-internal', 'blocked@x.org'));
        $this->assertTrue($list->isSendRestricted('any-other-list', 'blocked@x.org'));
    }

    public function testUntilInTheFutureStillRestricts(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org', 'until' => '2099-01-01']]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
    }

    public function testUntilInThePastNoLongerRestricts(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org', 'until' => '2020-01-01']]);
        $this->assertFalse($list->isSendRestricted('mylist', 'blocked@x.org'));
    }

    public function testNoUntilMeansIndefinite(): void
    {
        $list = new RestrictionList([['mail' => 'blocked@x.org']]);
        $this->assertTrue($list->isSendRestricted('mylist', 'blocked@x.org'));
    }

    public function testMultipleEntriesAreIndependentlyEvaluated(): void
    {
        $list = new RestrictionList([
            ['mail' => 'a@x.org'],
            ['mail' => 'b@x.org', 'receive' => false],
        ]);
        $this->assertTrue($list->isSendRestricted('mylist', 'a@x.org'));
        $this->assertFalse($list->isReceiveRestricted('mylist', 'a@x.org'));
        $this->assertTrue($list->isReceiveRestricted('mylist', 'b@x.org'));
    }

    public function testEmptyRestrictionListRestrictsNothing(): void
    {
        $list = new RestrictionList([]);
        $this->assertFalse($list->isSendRestricted('mylist', 'anyone@x.org'));
        $this->assertFalse($list->isReceiveRestricted('mylist', 'anyone@x.org'));
    }
}
