<?php

declare(strict_types=1);

namespace Hengeb\Listig\Token;

class TokenService
{
    /**
     * Truncated HMAC-SHA256 output length, in bytes (96 bits) — see docs/architecture/security-and-tokens.md
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
    private const string TYPE_NULL = "\x02";

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
     * must be string|int|null (see encodePayload()) — TokenService still has no
     * notion of what any of it *means*, only how to serialize those compactly.
     */
    public function sign(string $purpose, mixed ...$payload): string
    {
        $data = self::encodePayload([$purpose, time(), ...$payload]);
        return rtrim(strtr(base64_encode($data . $this->truncatedHmac($data)), '+/', '-_'), '=');
    }

    /**
     * @return array The payload passed to sign(), in the same order.
     * @throws \InvalidArgumentException on invalid signature, purpose mismatch, or expiry
     */
    public function verify(string $token, string $expectedPurpose, int $maxAge): array
    {
        $decoded = base64_decode(strtr($token, '-_', '+/'));
        if ($decoded === false || strlen($decoded) < self::HMAC_BYTES) {
            throw new \InvalidArgumentException('Invalid token format');
        }

        // No separator between the payload and its signature — HMAC_BYTES is
        // fixed, so the signature is always exactly the last HMAC_BYTES bytes
        // once base64-decoded, with everything before it being the payload.
        // An earlier version joined the two halves' own separate base64
        // encodings with a "." — dropping that (and the second, independent
        // base64-rounding-up it implied) shaves a few more bytes off every
        // token, meaningful for the ones embedded in an email address
        // local-part — see docs/architecture/security-and-tokens.md "Token Format".
        $data = substr($decoded, 0, -self::HMAC_BYTES);
        $hmac = substr($decoded, -self::HMAC_BYTES);

        if (!hash_equals($this->truncatedHmac($data), $hmac)) {
            throw new \InvalidArgumentException('Invalid token signature');
        }

        $payload = self::decodePayload($data);

        $purpose = $payload[0] ?? null;
        $issuedAt = $payload[1] ?? null;
        if (!is_string($purpose) || !is_int($issuedAt)) {
            throw new \InvalidArgumentException('Invalid token payload');
        }

        if ($purpose !== $expectedPurpose) {
            throw new \InvalidArgumentException('Token purpose mismatch');
        }

        if (time() - $issuedAt > $maxAge) {
            throw new \InvalidArgumentException('Token expired');
        }

        return array_slice($payload, 2);
    }

    /**
     * Truncated (HMAC_BYTES), raw-binary HMAC-SHA256 over $data — the
     * *whole* token (payload + this) is base64url-encoded together by
     * sign()/verify(), not this in isolation, so no encoding happens here;
     * see docs/architecture/security-and-tokens.md "Token Format" for why HMAC_BYTES=12 (96 bits) rather
     * than the full 32-byte digest.
     */
    private function truncatedHmac(string $data): string
    {
        return substr(hash_hmac('sha256', $data, $this->hmacKey, true), 0, self::HMAC_BYTES);
    }

    /**
     * Compact, purpose-agnostic binary encoding for a flat list of
     * string|int|null values — replaces an earlier JSON+base64 encoding,
     * which was confirmed live to make several tokens (bounce/accept/reject,
     * embedded in an email address local-part) exceed RFC 5321's 64-byte
     * local-part limit for anything but the shortest list names. Each value
     * is tagged with its own type byte (TYPE_STRING/TYPE_INT/TYPE_NULL) so
     * decodePayload() can read a stream of mixed values with no schema known
     * in advance — the same "TokenService doesn't hardcode a payload shape"
     * property the previous JSON encoding had, just far less verbose: no
     * quoting/braces/commas, and an integer costs only as many bytes as its
     * actual magnitude needs (encodeVarint()) instead of up to 10 ASCII
     * digits. TYPE_NULL exists specifically because a caller-optional field
     * (e.g. ListApiController::requestSubscribe()'s firstname/lastname/
     * username, `?? null` when the request body omits them, later
     * distinguished from an explicit empty string by
     * attributesFromBody()'s own `!== null` filter) needs to round-trip as
     * genuinely absent, not coerced into some other value — JSON natively
     * supported `null`, and this encoding needs to too, for the same reason.
     */
    private static function encodePayload(array $values): string
    {
        $out = '';
        foreach ($values as $value) {
            if (is_int($value)) {
                $out .= self::TYPE_INT . self::encodeVarint($value);
            } elseif (is_string($value)) {
                $out .= self::TYPE_STRING . self::encodeVarint(strlen($value)) . $value;
            } elseif ($value === null) {
                $out .= self::TYPE_NULL;
            } else {
                throw new \InvalidArgumentException('TokenService payload values must be string, int, or null');
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
            } elseif ($type === self::TYPE_NULL) {
                $values[] = null;
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
