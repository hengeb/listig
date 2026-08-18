<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Member;

use Hengeb\Listig\Member\LdapMemberResolver;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Ldap\Entry;

/**
 * entryToMember() is a pure data transformation with no LDAP connection
 * involved — testable directly against a fake Entry, without a real directory.
 */
class LdapMemberResolverTest extends TestCase
{
    private LdapMemberResolver $resolver;
    private \ReflectionMethod $entryToMember;

    protected function setUp(): void
    {
        $this->resolver = new LdapMemberResolver('ldap://fake', 'dc=example,dc=org', 'cn=admin', 'secret');
        $this->entryToMember = new \ReflectionMethod($this->resolver, 'entryToMember');
    }

    private function member(array $attributes)
    {
        $entry = new Entry('cn=test,dc=example,dc=org', $attributes);
        return $this->entryToMember->invoke($this->resolver, $entry);
    }

    public function testSingleMailValueBecomesPrimaryEmail(): void
    {
        $member = $this->member(['cn' => ['alice'], 'mail' => ['alice@example.org']]);
        $this->assertSame('alice@example.org', $member->email);
        $this->assertArrayNotHasKey('mail-aliases', $member->attributes);
    }

    public function testMultipleMailValuesFirstIsPrimaryRestBecomeAliases(): void
    {
        $member = $this->member([
            'cn' => ['bob'],
            'mail' => ['bob@example.org', 'bob.smith@example.org', 'b@example.org'],
        ]);
        $this->assertSame('bob@example.org', $member->email);
        $this->assertSame('bob.smith@example.org,b@example.org', $member->attributes['mail-aliases']);
    }

    public function testCnIsDuplicatedIntoUsernameAttribute(): void
    {
        $member = $this->member(['cn' => ['alice'], 'mail' => ['alice@example.org']]);
        $this->assertSame('alice', $member->attributes['username']);
        $this->assertSame('alice', $member->attributes['cn'], 'cn is still exposed under its own name too');
    }

    public function testGivenNameAndSnFallBackIntoFirstnameLastname(): void
    {
        $member = $this->member([
            'cn' => ['alice'],
            'mail' => ['alice@example.org'],
            'givenName' => ['Alice'],
            'sn' => ['Wonder'],
        ]);
        $this->assertSame('Alice', $member->attributes['firstname']);
        $this->assertSame('Wonder', $member->attributes['lastname']);
    }

    public function testExistingFirstnameLastnameAreNeverOverwritten(): void
    {
        // A directory that happens to carry its own real firstname/lastname
        // attributes (non-standard, but not impossible) must win over the
        // givenName/sn convenience fallback.
        $member = $this->member([
            'cn' => ['alice'],
            'mail' => ['alice@example.org'],
            'givenName' => ['Alice'],
            'sn' => ['Wonder'],
            'firstname' => ['CustomFirst'],
            'lastname' => ['CustomLast'],
        ]);
        $this->assertSame('CustomFirst', $member->attributes['firstname']);
        $this->assertSame('CustomLast', $member->attributes['lastname']);
    }

    public function testArbitraryAttributeIsExposedUnderItsOwnName(): void
    {
        $member = $this->member([
            'cn' => ['alice'],
            'mail' => ['alice@example.org'],
            'employeeNumber' => ['4711'],
        ]);
        $this->assertSame('4711', $member->attributes['employeeNumber']);
    }

    public function testMailAttributeIsNeverExposedAsAnOrdinaryAttribute(): void
    {
        $member = $this->member(['cn' => ['alice'], 'mail' => ['alice@example.org']]);
        $this->assertArrayNotHasKey('mail', $member->attributes);
    }

    public function testMissingMailAttributeResolvesToEmptyEmail(): void
    {
        $member = $this->member(['cn' => ['alice']]);
        $this->assertSame('', $member->email);
    }
}
