<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Http;

use Hengeb\Listig\Http\RequestPath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;

class RequestPathTest extends TestCase
{
    #[DataProvider('accepted')]
    public function testAcceptsSameOriginRelativePaths(string $next): void
    {
        $this->assertSame($next, RequestPath::sanitizeNext($next));
    }

    public static function accepted(): array
    {
        return [['/'], ['/team'], ['/team/archive'], ['/team/archive/5?page=2'], ['/team/archive?x=a%20b']];
    }

    #[DataProvider('rejected')]
    public function testRejectsAnythingThatCouldLeaveTheSite(mixed $next): void
    {
        $this->assertNull(RequestPath::sanitizeNext($next));
    }

    public static function rejected(): array
    {
        return [
            [null], [''], [['/team']], [42],
            ['https://evil.example/'], ['http://evil.example'], ['//evil.example'], ['/\\evil.example'],
            ['evil.example/path'], ['javascript:alert(1)'], ['team'],
            ["/team\r\nSet-Cookie: x=1"], ["/team\x00"],
            ['/' . str_repeat('a', 600)],
        ];
    }

    public function testWithNextBuildsTheLoginUrlOfTheCurrentRequest(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', 'https://lists.example.org/team/archive?page=2');
        $this->assertSame('/_/login?next=%2Fteam%2Farchive%3Fpage%3D2', RequestPath::withNext('/_/login', $request));
        $this->assertSame('/_/login/oidc?next=%2Fteam%2Farchive%3Fpage%3D2', RequestPath::withNext('/_/login/oidc', $request));
        $this->assertSame('/team/archive?page=2', RequestPath::sanitizeNext(urldecode('%2Fteam%2Farchive%3Fpage%3D2')));
    }
}
