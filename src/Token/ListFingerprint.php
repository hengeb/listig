<?php

declare(strict_types=1);

namespace Hengeb\Listig\Token;

/**
 * A short, non-cryptographic fingerprint of a list's own name
 * (`ListConfig::$name`), used only as a defense-in-depth "does this token
 * actually belong to this list" sanity check inside a signed token's own
 * payload — never the token's actual security boundary (that's
 * TokenService's HMAC signature over the whole payload, fingerprint
 * included, so a forged fingerprint value is unreachable without first
 * breaking the signature). Deliberately not the full list name:
 * bounce/accept/reject tokens are embedded directly in an email address
 * local-part (RFC 5321's 64-byte limit), and a raw list name has no length
 * bound an operator is required to respect — see CLAUDE.md "Token Format"
 * for the numbers that made this necessary.
 *
 * A single byte (0-255) is enough for this purpose: an accidental collision
 * between two differently-named lists only ever weakens a secondary sanity
 * check that a genuine cross-list mismatch would otherwise catch — the
 * token's own HMAC still fully secures the row/recipient it actually
 * refers to regardless — and a Listig instance with anywhere near 256 lists
 * is far outside this project's realistic scale.
 */
final class ListFingerprint
{
    public static function of(string $listCn): int
    {
        return crc32($listCn) & 0xFF;
    }

    private function __construct()
    {
    }
}
