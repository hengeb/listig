<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Config;

use Hengeb\Listig\Config\ConnectionConfig;
use PHPUnit\Framework\TestCase;

class ConnectionConfigTest extends TestCase
{
    public function testDnsCanBeComposedFromAnotherKey(): void
    {
        $config = ConnectionConfig::resolve([
            'ldap-base-dn' => 'dc=example,dc=org',
            'ldap-bind-dn' => 'cn=admin,{ldap-base-dn}',
            'ldap-list-dn' => 'ou=groups,{ldap-base-dn}',
            'ldap-empty-group-member' => '{ldap-bind-dn}',
        ]);

        $this->assertSame('cn=admin,dc=example,dc=org', $config['ldap-bind-dn']);
        $this->assertSame('ou=groups,dc=example,dc=org', $config['ldap-list-dn']);
        $this->assertSame('cn=admin,dc=example,dc=org', $config['ldap-empty-group-member'], 'a reference to a templated key resolves through the chain');
    }

    public function testConnectionValuesMayReferenceBlockedKeysBecauseTheyAreNeverShown(): void
    {
        $config = ConnectionConfig::resolve(['mail-user' => 'list@example.org', 'db-user' => '{mail-user}']);
        $this->assertSame('list@example.org', $config['db-user']);
    }

    public function testPasswordsAreNeverTreatedAsTemplates(): void
    {
        $config = ConnectionConfig::resolve(['ldap-bind-password' => 'se{cr}et', 'db-password' => '{mail-password}']);
        $this->assertSame('se{cr}et', $config['ldap-bind-password']);
        $this->assertSame('{mail-password}', $config['db-password']);
    }

    public function testOtherKeysAndPlainValuesStayAsTheyAre(): void
    {
        $input = ['footer' => 'Hello {display-name}', 'ldap-host' => 'ldap://ldap:389/', 'list-mail' => '{list-name}@{domain}'];
        $this->assertSame($input, ConnectionConfig::resolve($input));
    }

    public function testFallbackContextIsConsultedForMissingKeys(): void
    {
        $config = ConnectionConfig::resolve(['ldap-bind-dn' => 'cn=admin,{ldap-base-dn}'], ['ldap-base-dn' => 'dc=x']);
        $this->assertSame('cn=admin,dc=x', $config['ldap-bind-dn']);
    }
}
