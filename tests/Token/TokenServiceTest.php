<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Token;

use Hengeb\Listig\Token\TokenService;
use PHPUnit\Framework\TestCase;

class TokenServiceTest extends TestCase
{
    private TokenService $tokenService;

    protected function setUp(): void
    {
        $this->tokenService = new TokenService('test-hmac-key');
    }

    public function testSignAndVerifyRoundTrip(): void
    {
        $token = $this->tokenService->sign('login', 'mylist', 'alice');
        $payload = $this->tokenService->verify($token, 'login', 300);
        $this->assertSame(['mylist', 'alice'], $payload);
    }

    public function testVerifyRejectsWrongPurpose(): void
    {
        $token = $this->tokenService->sign('login', 'mylist', 'alice');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Token purpose mismatch');
        $this->tokenService->verify($token, 'unsubscribe', 300);
    }

    public function testVerifyRejectsTamperedPayload(): void
    {
        $token = $this->tokenService->sign('login', 'mylist', 'alice');
        [$encoded, $hmac] = explode('.', $token, 2);
        $tampered = $encoded . 'X' . '.' . $hmac;
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid token signature');
        $this->tokenService->verify($tampered, 'login', 300);
    }

    public function testVerifyRejectsTokenSignedWithDifferentKey(): void
    {
        $otherService = new TokenService('a-completely-different-key');
        $token = $otherService->sign('login', 'mylist', 'alice');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid token signature');
        $this->tokenService->verify($token, 'login', 300);
    }

    public function testVerifyRejectsMalformedToken(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid token format');
        $this->tokenService->verify('not-a-valid-token-at-all', 'login', 300);
    }

    public function testVerifyRejectsExpiredToken(): void
    {
        // Sign a token whose embedded timestamp is already outside maxAge by
        // directly crafting one the way sign() does, but backdated.
        $data = json_encode(['login', time() - 1000, 'mylist', 'alice']);
        $hmac = hash_hmac('sha256', $data, 'test-hmac-key');
        $token = rtrim(strtr(base64_encode($data), '+/', '-_'), '=') . '.' . $hmac;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Token expired');
        $this->tokenService->verify($token, 'login', 300);
    }

    public function testTokenIsUrlSafe(): void
    {
        // Sign something whose base64 would normally contain '+'/'/' — confirm the
        // token string contains only URL-safe characters plus the '.' separator.
        $token = $this->tokenService->sign('login', str_repeat('x', 50));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[a-f0-9]+$/', $token);
    }

    public function testDifferentPurposesWithSamePayloadShapeAreNotInterchangeable(): void
    {
        // A token signed for 'login' must not verify successfully for 'unsubscribe'
        // even though both happen to take ($listCn, $userCn) as payload.
        $loginToken = $this->tokenService->sign('login', 'mylist', 'alice');
        $this->expectException(\InvalidArgumentException::class);
        $this->tokenService->verify($loginToken, 'unsubscribe', 300);
    }

    public function testPayloadPreservesOrderAndTypes(): void
    {
        $token = $this->tokenService->sign('accept', 'mylist', 42, 12345);
        $payload = $this->tokenService->verify($token, 'accept', 300);
        $this->assertSame(['mylist', 42, 12345], $payload);
    }
}
