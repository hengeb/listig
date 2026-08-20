<?php

declare(strict_types=1);

namespace Hengeb\Listig\Token;

class TokenService
{
    /**
     * Truncated HMAC-SHA256 output length, in bytes (96 bits) — see CLAUDE.md
     * "Token Format" for the full reasoning. RFC 2104/NIST SP 800-107 both
     * explicitly allow a truncated MAC as long as the remaining length still
     * gives an adequate security margin against forgery; 96 bits is
     * comfortably beyond any realistic brute-force capability even across a
     * token's full multi-day validity window, while meaningfully shortening
     * every token — several of which (bounce/accept/reject) are embedded
     * directly in an email address local-part, bound by RFC 5321's 64-byte
     * limit.
     */
    private const int HMAC_BYTES = 12;

    private const string TYPE_STRING = "\x00";
    private const string TYPE_INT = "\x01";

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
     * on verify) and the timestamp (for the caller-supplied max age). Every value
     * must be string|int (see encodePayload()) — TokenService still has no notion
     * of what any of it *means*, only how to serialize string|int compactly.
     */
    public function sign(string $purpose, mixed ...$payload): string
    {
        $data = self::encodePayload([$purpose, time(), ...$payload]);
        $encoded = rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        return $encoded . '.' . $this->truncatedHmac($data);
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

        if (!hash_equals($this->truncatedHmac($data), $hmac)) {
            throw new \InvalidArgumentException('Invalid token signature');
        }

        $decoded = self::decodePayload($data);

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

    /**
     * Truncated (HMAC_BYTES) HMAC-SHA256 over $data, base64url-encoded (no
     * padding — HMAC_BYTES is a multiple of 3, so none is ever needed)
     * rather than hex. Same number of underlying security bits either way —
     * base64 just packs 6 bits/character against hex's 4, so this costs
     * noticeably fewer characters for the same truncated byte length (16 vs
     * 24 characters at HMAC_BYTES=12) — meaningful for tokens embedded in an
     * email address local-part, see CLAUDE.md "Token Format".
     */
    private function truncatedHmac(string $data): string
    {
        $raw = hash_hmac('sha256', $data, $this->hmacKey, true);
        return rtrim(strtr(base64_encode(substr($raw, 0, self::HMAC_BYTES)), '+/', '-_'), '=');
    }

    /**
     * Compact, purpose-agnostic binary encoding for a flat list of string|int
     * values — replaces an earlier JSON+base64 encoding, which was confirmed
     * live to make several tokens (bounce/accept/reject, embedded in an email
     * address local-part) exceed RFC 5321's 64-byte local-part limit for
     * anything but the shortest list names. Each value is tagged with its own
     * type byte (TYPE_STRING/TYPE_INT) so decodePayload() can read a stream of
     * mixed string|int values with no schema known in advance — the same
     * "TokenService doesn't hardcode a payload shape" property the previous
     * JSON encoding had, just far less verbose: no quoting/braces/commas, and
     * an integer costs only as many bytes as its actual magnitude needs
     * (encodeVarint()) instead of up to 10 ASCII digits.
     */
    private static function encodePayload(array $values): string
    {
        $out = '';
        foreach ($values as $value) {
            if (is_int($value)) {
                $out .= self::TYPE_INT . self::encodeVarint($value);
            } elseif (is_string($value)) {
                $out .= self::TYPE_STRING . self::encodeVarint(strlen($value)) . $value;
            } else {
                throw new \InvalidArgumentException('TokenService payload values must be string or int');
            }
        }
        return $out;
    }

    private static function decodePayload(string $data): array
    {
        $offset = 0;
        $length = strlen($data);
        $values = [];
        while ($offset < $length) {
            $type = $data[$offset];
            $offset++;
            if ($type === self::TYPE_STRING) {
                $strLen = self::decodeVarint($data, $offset);
                if ($strLen < 0 || $offset + $strLen > $length) {
                    throw new \InvalidArgumentException('Invalid token payload');
                }
                $values[] = substr($data, $offset, $strLen);
                $offset += $strLen;
            } elseif ($type === self::TYPE_INT) {
                $values[] = self::decodeVarint($data, $offset);
            } else {
                throw new \InvalidArgumentException('Invalid token payload');
            }
        }
        return $values;
    }

    /**
     * LEB128-style unsigned varint: 7 payload bits per byte, high bit set on
     * every byte but the last ("more bytes follow"). Only non-negative values
     * are ever signed here (timestamps, IDs, CRC32 fingerprints) — negative
     * input is rejected rather than silently misencoded.
     */
    private static function encodeVarint(int $value): string
    {
        if ($value < 0) {
            throw new \InvalidArgumentException('TokenService cannot encode a negative integer');
        }
        $bytes = '';
        do {
            $byte = $value & 0x7F;
            $value >>= 7;
            if ($value !== 0) {
                $byte |= 0x80;
            }
            $bytes .= chr($byte);
        } while ($value !== 0);
        return $bytes;
    }

    /** $offset is advanced past the consumed bytes, for the caller to keep decoding subsequent values. */
    private static function decodeVarint(string $data, int &$offset): int
    {
        $result = 0;
        $shift = 0;
        $length = strlen($data);
        do {
            // shift > 63 means a malformed/truncated varint kept its
            // continuation bit set well beyond any value TokenService itself
            // ever signs (PHP ints are 64-bit) — reject rather than loop.
            if ($offset >= $length || $shift > 63) {
                throw new \InvalidArgumentException('Invalid token payload');
            }
            $byte = ord($data[$offset]);
            $offset++;
            $result |= ($byte & 0x7F) << $shift;
            $shift += 7;
        } while ($byte & 0x80);
        return $result;
    }
}
