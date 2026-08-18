<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Member\InlineMemberResolver;
use PHPUnit\Framework\TestCase;

class InlineMemberResolverTest extends TestCase
{
    public function testToMemberFromPlainStringHasNoAttributes(): void
    {
        $member = InlineMemberResolver::toMember('alice@example.org');
        $this->assertSame('alice@example.org', $member->email);
        $this->assertSame([], $member->attributes);
    }

    public function testToMemberFromMapExposesEveryOtherKeyAsAttribute(): void
    {
        $member = InlineMemberResolver::toMember([
            'mail' => 'bob@example.org',
            'firstname' => 'Bob',
            'pronoun' => 'he',
        ]);
        $this->assertSame('bob@example.org', $member->email);
        $this->assertSame(['firstname' => 'Bob', 'pronoun' => 'he'], $member->attributes);
    }

    public function testMailAliasesArrayIsJoinedToCommaString(): void
    {
        $member = InlineMemberResolver::toMember([
            'mail' => 'bob@example.org',
            'mail-aliases' => ['bob.smith@example.org', 'b@example.org'],
        ]);
        $this->assertSame('bob.smith@example.org,b@example.org', $member->attributes['mail-aliases']);
    }

    public function testMailAliasesAsPlainStringPassesThroughUnchanged(): void
    {
        $member = InlineMemberResolver::toMember([
            'mail' => 'bob@example.org',
            'mail-aliases' => 'already,a,string',
        ]);
        $this->assertSame('already,a,string', $member->attributes['mail-aliases']);
    }

    public function testGetMembersAndGetOwnersAreIndependent(): void
    {
        $resolver = new InlineMemberResolver(['alice@example.org'], ['bob@example.org']);
        $this->assertCount(1, $resolver->getMembers('any-list'));
        $this->assertSame('alice@example.org', $resolver->getMembers('any-list')[0]->email);
        $this->assertSame('bob@example.org', $resolver->getOwners('any-list')[0]->email);
    }

    public function testFindByEmailSearchesBothMembersAndOwners(): void
    {
        $resolver = new InlineMemberResolver(['alice@example.org'], ['bob@example.org']);
        $this->assertSame('bob@example.org', $resolver->findByEmail('bob@example.org')?->email);
        $this->assertNull($resolver->findByEmail('nobody@example.org'));
    }

    public function testFindByEmailIsCaseInsensitive(): void
    {
        $resolver = new InlineMemberResolver(['Alice@Example.org'], []);
        $this->assertNotNull($resolver->findByEmail('alice@example.org'));
    }

    public function testSupportsRemovalIsAlwaysFalse(): void
    {
        $resolver = new InlineMemberResolver(['alice@example.org'], []);
        $this->assertFalse($resolver->supportsRemoval());
    }

    public function testRemoveMemberThrows(): void
    {
        $resolver = new InlineMemberResolver(['alice@example.org'], []);
        $this->expectException(\RuntimeException::class);
        $resolver->removeMember('mylist', 'alice@example.org');
    }

    public function testAddMemberThrows(): void
    {
        $resolver = new InlineMemberResolver([], []);
        $this->expectException(\RuntimeException::class);
        $resolver->addMember('mylist', InlineMemberResolver::toMember('new@example.org'));
    }

    public function testEmptyConstructorArgumentsProduceEmptyResults(): void
    {
        $resolver = new InlineMemberResolver([], []);
        $this->assertSame([], $resolver->getMembers('any'));
        $this->assertSame([], $resolver->getOwners('any'));
    }
}
