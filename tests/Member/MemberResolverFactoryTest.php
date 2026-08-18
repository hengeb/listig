<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Member\CsvMemberResolver;
use Hengeb\Listig\Member\InlineMemberResolver;
use Hengeb\Listig\Member\LdapMemberResolver;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Member\MemberResolverFactory;
use Hengeb\Listig\Member\NullMemberResolver;
use PHPUnit\Framework\TestCase;

class MemberResolverFactoryTest extends TestCase
{
    public function testCreateWithNullConfigReturnsNullMemberResolver(): void
    {
        $factory = new MemberResolverFactory();
        $this->assertInstanceOf(NullMemberResolver::class, $factory->create(null, []));
    }

    public function testCreateWithUnknownTypeReturnsNullMemberResolver(): void
    {
        $factory = new MemberResolverFactory();
        $this->assertInstanceOf(NullMemberResolver::class, $factory->create(['type' => 'not-a-real-type'], []));
    }

    public function testCreateBuildsLdapResolver(): void
    {
        $factory = new MemberResolverFactory();
        $resolver = $factory->create([
            'type' => 'ldap',
            'ldap-host' => 'ldap://fake',
            'ldap-base-dn' => 'dc=example,dc=org',
            'ldap-bind-dn' => 'cn=admin',
            'ldap-bind-password' => 'secret',
        ], []);
        $this->assertInstanceOf(LdapMemberResolver::class, $resolver);
    }

    public function testCreateBuildsCsvResolver(): void
    {
        $factory = new MemberResolverFactory();
        $resolver = $factory->create(['type' => 'csv', 'file' => '/tmp/does-not-need-to-exist.csv'], []);
        $this->assertInstanceOf(CsvMemberResolver::class, $resolver);
    }

    public function testCreateCsvWithoutFileThrows(): void
    {
        $factory = new MemberResolverFactory();
        $this->expectException(\RuntimeException::class);
        $factory->create(['type' => 'csv'], []);
    }

    public function testBuildSourcesWithNullOrEmptyReturnsNoSources(): void
    {
        $factory = new MemberResolverFactory();
        $this->assertSame([], $factory->buildSources(null, []));
        $this->assertSame([], $factory->buildSources([], []));
    }

    public function testBuildSourcesWithBareStringBecomesInlineResolver(): void
    {
        $factory = new MemberResolverFactory();
        $sources = $factory->buildSources(['alice@example.org'], []);
        $this->assertCount(1, $sources);
        $this->assertInstanceOf(InlineMemberResolver::class, $sources[0]);
        $this->assertSame('alice@example.org', $sources[0]->getMembers('any')[0]->email);
    }

    public function testBuildSourcesWithBareMapBecomesInlineResolver(): void
    {
        $factory = new MemberResolverFactory();
        $sources = $factory->buildSources([['mail' => 'alice@example.org', 'firstname' => 'Alice']], []);
        $this->assertSame('Alice', $sources[0]->getMembers('any')[0]->attributes['firstname']);
    }

    public function testBuildSourcesWithMixedResolverConfigAndBareEntries(): void
    {
        $factory = new MemberResolverFactory();
        $sources = $factory->buildSources([
            ['type' => 'csv', 'file' => '/tmp/does-not-need-to-exist.csv'],
            'alice@example.org',
        ], []);
        $this->assertCount(2, $sources);
        $this->assertInstanceOf(CsvMemberResolver::class, $sources[0]);
        $this->assertInstanceOf(InlineMemberResolver::class, $sources[1]);
    }

    public function testBuildSourcesWithSingleResolverConfigMapNotWrappedInList(): void
    {
        $factory = new MemberResolverFactory();
        $sources = $factory->buildSources(['type' => 'csv', 'file' => '/tmp/does-not-need-to-exist.csv'], []);
        $this->assertCount(1, $sources);
        $this->assertInstanceOf(CsvMemberResolver::class, $sources[0]);
    }

    public function testBuildComposedResolverCombinesAllThreeLevelsAdditively(): void
    {
        $factory = new MemberResolverFactory();
        $resolver = $factory->buildComposedResolver(
            memberResolverLevels: [null, null, null],
            membersLevels: [['global@x.org'], ['provider@x.org'], ['list@x.org']],
            ownerResolverLevels: [null, null, null],
            ownersLevels: [null, null, null],
            resolvedProviderConfig: [],
        );
        $emails = array_map(fn(Member $m) => $m->email, $resolver->getMembers('any'));
        sort($emails);
        $this->assertSame(['global@x.org', 'list@x.org', 'provider@x.org'], $emails);
    }

    public function testBuildComposedResolverDedupesSameEmailAcrossLevels(): void
    {
        $factory = new MemberResolverFactory();
        $resolver = $factory->buildComposedResolver(
            memberResolverLevels: [null, null, null],
            membersLevels: [['dup@x.org'], ['dup@x.org'], null],
            ownerResolverLevels: [null, null, null],
            ownersLevels: [null, null, null],
            resolvedProviderConfig: [],
        );
        $this->assertCount(1, $resolver->getMembers('any'));
    }

    public function testBuildComposedResolverIncludesExtraBaseInBothRoles(): void
    {
        $extraBase = new InlineMemberResolver(['base@x.org'], ['base@x.org']);
        $factory = new MemberResolverFactory();
        $resolver = $factory->buildComposedResolver(
            memberResolverLevels: [null, null, null],
            membersLevels: [null, null, null],
            ownerResolverLevels: [null, null, null],
            ownersLevels: [null, null, null],
            resolvedProviderConfig: [],
            extraBase: $extraBase,
        );
        $this->assertSame('base@x.org', $resolver->getMembers('any')[0]->email);
        $this->assertSame('base@x.org', $resolver->getOwners('any')[0]->email);
    }

    public function testBuildComposedResolverWithNothingConfiguredIsEmptyNotError(): void
    {
        $factory = new MemberResolverFactory();
        $resolver = $factory->buildComposedResolver([], [], [], [], []);
        $this->assertSame([], $resolver->getMembers('any'));
        $this->assertSame([], $resolver->getOwners('any'));
    }
}
