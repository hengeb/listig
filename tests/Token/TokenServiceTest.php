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
        // directly crafting one the way sign() does, but backdated. Reaches
        // the private encodePayload() via Reflection — there's no other way
        // to backdate a token's own embedded timestamp.
        $encodePayload = new \ReflectionMethod(TokenService::class, 'encodePayload');
        $data = $encodePayload->invoke(null, ['login', time() - 1000, 'mylist', 'alice']);
        $truncatedHmac = new \ReflectionMethod(TokenService::class, 'truncatedHmac');
        $hmac = $truncatedHmac->invoke($this->tokenService, $data);
        $token = rtrim(strtr(base64_encode($data), '+/', '-_'), '=') . '.' . $hmac;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Token expired');
        $this->tokenService->verify($token, 'login', 300);
    }

    public function testTokenIsUrlSafe(): void
    {
        // Sign something whose base64 would normally contain '+'/'/' — confirm the
        // token string contains only URL-safe characters plus the '.' separator.
        // Both halves (payload and truncated HMAC) are base64url now, not hex.
        $token = $this->tokenService->sign('login', str_repeat('x', 50));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token);
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

    public function testLargeIntegerRoundTrips(): void
    {
        // IMAP UIDVALIDITY-shaped values are commonly a full Unix timestamp,
        // well beyond what fits in a single varint byte — confirm the
        // multi-byte continuation-bit path round-trips correctly.
        $large = 1787245467;
        $token = $this->tokenService->sign('bounce', 'mylist', $large);
        $payload = $this->tokenService->verify($token, 'bounce', 300);
        $this->assertSame(['mylist', $large], $payload);
    }

    public function testSignRejectsNegativeInteger(): void
    {
        // TokenService only ever signs non-negative values in practice
        // (timestamps, IDs, CRC32 fingerprints) — a negative int would be
        // silently misencoded by the unsigned varint format, so it's
        // rejected outright instead.
        $this->expectException(\InvalidArgumentException::class);
        $this->tokenService->sign('bounce', 'mylist', -1);
    }

    public function testEncodedTokenIsMeaningfullyShorterThanFullHexHmac(): void
    {
        // Regression guard for the reason this encoding exists at all:
        // bounce/accept/reject tokens are embedded in an email address
        // local-part (RFC 5321's 64-byte limit). Confirmed live as a real,
        // not just theoretical, gap: the previous JSON+full-HMAC encoding
        // produced a bounce token alone north of 110 characters — already
        // over budget before the "+bounce+" prefix is even counted. This
        // compares against that exact previous shape (plain JSON + untruncated
        // hex HMAC) for the same payload, not an arbitrary constant, so the
        // guard stays meaningful if field sizes shift slightly later.
        $payload = ['bounce', time(), 'it-team', 280];
        $oldStyleData = json_encode($payload);
        $oldStyleToken = rtrim(strtr(base64_encode($oldStyleData), '+/', '-_'), '=')
            . '.' . hash_hmac('sha256', $oldStyleData, 'test-hmac-key');

        $newToken = $this->tokenService->sign('bounce', 'it-team', 280);

        $this->assertLessThan(strlen($oldStyleToken) - 30, strlen($newToken));
    }
}
