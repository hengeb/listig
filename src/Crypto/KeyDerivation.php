<?php

declare(strict_types=1);

namespace Hengeb\Listig\Crypto;

/**
 * Derives purpose-scoped subkeys from APP_SECRET via HKDF-SHA256, so that no two
 * cryptographic uses (token HMAC, IMAP/SMTP password encryption, ...) ever operate
 * on the same key material. Each call site defines its own $context string.
 */
final class KeyDerivation
{
    public static function derive(string $appSecret, string $context): string
    {
        return hash_hkdf('sha256', $appSecret, 32, $context);
    }
}
