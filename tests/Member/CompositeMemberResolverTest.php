<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Member\CompositeMemberResolver;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Member\MemberResolver;
use PHPUnit\Framework\TestCase;

class CompositeMemberResolverTest extends TestCase
{
    public function testGetMembersUnionsAllSources(): void
    {
        $a = new InlineMemberResolver(['alice@example.org'], []);
        $b = new InlineMemberResolver(['bob@example.org'], []);
        $composite = new CompositeMemberResolver([$a, $b], []);

        $emails = array_map(fn(Member $m) => $m->email, $composite->getMembers('any'));
        sort($emails);
        $this->assertSame(['alice@example.org', 'bob@example.org'], $emails);
    }

    public function testGetMembersDedupesByEmailFirstSourceWins(): void
    {
        $a = new InlineMemberResolver([['mail' => 'alice@example.org', 'firstname' => 'FromA']], []);
        $b = new InlineMemberResolver([['mail' => 'alice@example.org', 'firstname' => 'FromB']], []);
        $composite = new CompositeMemberResolver([$a, $b], []);

        $members = $composite->getMembers('any');
        $this->assertCount(1, $members);
        $this->assertSame('FromA', $members[0]->attributes['firstname']);
    }

    public function testDedupeIsCaseInsensitive(): void
    {
        $a = new InlineMemberResolver(['Alice@Example.org'], []);
        $b = new InlineMemberResolver(['alice@example.org'], []);
        $composite = new CompositeMemberResolver([$a, $b], []);
        $this->assertCount(1, $composite->getMembers('any'));
    }

    public function testMemberSourcesAndOwnerSourcesAreIndependent(): void
    {
        $memberSource = new InlineMemberResolver(['alice@example.org'], []);
        $ownerSource = new InlineMemberResolver([], ['bob@example.org']);
        $composite = new CompositeMemberResolver([$memberSource], [$ownerSource]);

        $this->assertSame('alice@example.org', $composite->getMembers('any')[0]->email);
        $this->assertSame('bob@example.org', $composite->getOwners('any')[0]->email);
        $this->assertEmpty(array_filter($composite->getMembers('any'), fn($m) => $m->email === 'bob@example.org'));
    }

    public function testAddMemberTriesEachSourceUntilOneSucceeds(): void
    {
        $throwing = $this->createStub(MemberResolver::class);
        $throwing->method('addMember')->willThrowException(new \RuntimeException('nope'));

        $succeeding = $this->createMock(MemberResolver::class);
        $succeeding->expects($this->once())->method('addMember');

        $composite = new CompositeMemberResolver([$throwing, $succeeding], []);
        $composite->addMember('mylist', new Member('new@example.org'));
    }

    public function testAddMemberThrowsLastErrorIfEverySourceFails(): void
    {
        $a = $this->createStub(MemberResolver::class);
        $a->method('addMember')->willThrowException(new \RuntimeException('error from a'));
        $b = $this->createStub(MemberResolver::class);
        $b->method('addMember')->willThrowException(new \RuntimeException('error from b'));

        $composite = new CompositeMemberResolver([$a, $b], []);
        $this->expectExceptionMessage('error from b');
        $composite->addMember('mylist', new Member('new@example.org'));
    }

    public function testAddMemberThrowsWhenNoSourcesConfiguredAtAll(): void
    {
        $composite = new CompositeMemberResolver([], []);
        $this->expectException(\RuntimeException::class);
        $composite->addMember('mylist', new Member('new@example.org'));
    }

    public function testRemoveMemberCallsEverySourceThatSupportsRemoval(): void
    {
        $supporting1 = $this->createMock(MemberResolver::class);
        $supporting1->method('supportsRemoval')->willReturn(true);
        $supporting1->expects($this->once())->method('removeMember');

        $supporting2 = $this->createMock(MemberResolver::class);
        $supporting2->method('supportsRemoval')->willReturn(true);
        $supporting2->expects($this->once())->method('removeMember');

        $notSupporting = $this->createMock(MemberResolver::class);
        $notSupporting->method('supportsRemoval')->willReturn(false);
        $notSupporting->expects($this->never())->method('removeMember');

        $composite = new CompositeMemberResolver([$supporting1, $supporting2, $notSupporting], []);
        $composite->removeMember('mylist', 'alice@example.org');
    }

    public function testSupportsRemovalTrueIfAnySourceSupportsIt(): void
    {
        $notSupporting = new InlineMemberResolver(['alice@example.org'], []); // always false
        $supporting = $this->createStub(MemberResolver::class);
        $supporting->method('supportsRemoval')->willReturn(true);

        $composite = new CompositeMemberResolver([$notSupporting, $supporting], []);
        $this->assertTrue($composite->supportsRemoval());
    }

    public function testSupportsRemovalFalseIfNoSourceSupportsIt(): void
    {
        $composite = new CompositeMemberResolver([new InlineMemberResolver([], [])], []);
        $this->assertFalse($composite->supportsRemoval());
    }

    public function testFindByEmailSearchesAllSources(): void
    {
        $memberSource = new InlineMemberResolver(['alice@example.org'], []);
        $ownerSource = new InlineMemberResolver([], ['bob@example.org']);
        $composite = new CompositeMemberResolver([$memberSource], [$ownerSource]);

        $this->assertSame('bob@example.org', $composite->findByEmail('bob@example.org')?->email);
        $this->assertNull($composite->findByEmail('nobody@example.org'));
    }

    public function testEmptySourcesBehaveLikeAnEmptyResolver(): void
    {
        $composite = new CompositeMemberResolver([], []);
        $this->assertSame([], $composite->getMembers('any'));
        $this->assertSame([], $composite->getOwners('any'));
        $this->assertNull($composite->findByEmail('anyone@example.org'));
    }
}
