<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Mail;

use Hengeb\Listig\Mail\OrganizationalDomain;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class OrganizationalDomainTest extends TestCase
{
    #[DataProvider('cases')]
    public function testOf(string $domain, string $expected): void
    {
        $this->assertSame($expected, (new OrganizationalDomain())->of($domain));
    }

    public static function cases(): array
    {
        return [
            ['example.org', 'example.org'],
            ['Mail.Example.ORG.', 'example.org'],
            ['a.b.example.org', 'example.org'],
            ['foo.co.uk', 'foo.co.uk'],
            ['mail.foo.co.uk', 'foo.co.uk'],
            ['evil.github.io', 'evil.github.io'],
            ['localhost', 'localhost'],
        ];
    }

    public function testAlignment(): void
    {
        $d = new OrganizationalDomain();
        $this->assertTrue($d->aligned('mail.example.org', 'example.org'));
        $this->assertTrue($d->aligned('EXAMPLE.org', 'news.example.org'));
        $this->assertFalse($d->aligned('example.org', 'example.com'));
        $this->assertFalse($d->aligned('evil.co.uk', 'bank.co.uk'));
        $this->assertFalse($d->aligned('', ''));
    }
}
