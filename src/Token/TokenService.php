<?php

declare(strict_types=1);

namespace Hengeb\Listig\Token;

class TokenService
{
    /**
     * @param string $hmacKey Purpose-scoped subkey derived from APP_SECRET via
     * KeyDerivation::derive() — never the raw APP_SECRET itself, so that a
     * weakness in another use of APP_SECRET (e.g. password encryption) cannot
     * carry over to token forgery, and vice versa.
     */
    public function __construct(
        private readonly string $hmacKey,
    ) {
    }

    /**
     * Signs an arbitrary, purpose-specific payload. Callers decide what goes in
     * $payload and in what order — TokenService only cares about $purpose (checked
     * on verify) and the timestamp (for the caller-supplied max age).
     */
    public function sign(string $purpose, mixed ...$payload): string
    {
        $data = json_encode([$purpose, time(), ...$payload], JSON_THROW_ON_ERROR);
        $hmac = hash_hmac('sha256', $data, $this->hmacKey);
        $encoded = rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        return $encoded . '.' . $hmac;
    }

    /**
     * @return array The payload passed to sign(), in the same order.
     * @throws \InvalidArgumentException on invalid signature, purpose mismatch, or expiry
     */
    public function verify(string $token, string $expectedPurpose, int $maxAge): array
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            throw new \InvalidArgumentException('Invalid token format');
        }

        [$encoded, $hmac] = $parts;

        $data = base64_decode(strtr($encoded, '-_', '+/'));
        if ($data === false) {
            throw new \InvalidArgumentException('Invalid token encoding');
        }

        $expectedHmac = hash_hmac('sha256', $data, $this->hmacKey);
        if (!hash_equals($expectedHmac, $hmac)) {
            throw new \InvalidArgumentException('Invalid token signature');
        }

        try {
            $decoded = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \InvalidArgumentException('Invalid token payload');
        }

        $purpose = $decoded[0] ?? null;
        $issuedAt = $decoded[1] ?? null;
        if (!is_string($purpose) || !is_int($issuedAt)) {
            throw new \InvalidArgumentException('Invalid token payload');
        }

        if ($purpose !== $expectedPurpose) {
            throw new \InvalidArgumentException('Token purpose mismatch');
        }

        if (time() - $issuedAt > $maxAge) {
            throw new \InvalidArgumentException('Token expired');
        }

        return array_slice($decoded, 2);
    }
}
