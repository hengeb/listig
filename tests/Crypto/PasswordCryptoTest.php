<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Crypto;

use Hengeb\Listig\Crypto\PasswordCrypto;
use PHPUnit\Framework\TestCase;

class PasswordCryptoTest extends TestCase
{
    private PasswordCrypto $crypto;

    protected function setUp(): void
    {
        $this->crypto = new PasswordCrypto(str_repeat('k', 32));
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $encrypted = $this->crypto->encrypt('super-secret-password');
        $this->assertSame('super-secret-password', $this->crypto->decrypt($encrypted));
    }

    public function testEncryptedValueMatchesWireFormat(): void
    {
        $encrypted = $this->crypto->encrypt('password');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/=]+:[A-Za-z0-9+\/=]+$/', $encrypted);
    }

    public function testEncryptUsesRandomIvEachTime(): void
    {
        // Two encryptions of the same plaintext must not produce identical
        // ciphertext — otherwise the IV isn't actually random per call.
        $a = $this->crypto->encrypt('same-password');
        $b = $this->crypto->encrypt('same-password');
        $this->assertNotSame($a, $b);
        $this->assertSame('same-password', $this->crypto->decrypt($a));
        $this->assertSame('same-password', $this->crypto->decrypt($b));
    }

    public function testDecryptRejectsMalformedInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->crypto->decrypt('not-a-valid-encrypted-value');
    }

    public function testDecryptRejectsWrongKey(): void
    {
        $encrypted = $this->crypto->encrypt('password');
        $otherCrypto = new PasswordCrypto(str_repeat('x', 32));
        $this->expectException(\InvalidArgumentException::class);
        $otherCrypto->decrypt($encrypted);
    }

    public function testDecryptIfEncryptedDecryptsAnEncryptedValue(): void
    {
        $encrypted = $this->crypto->encrypt('password');
        $this->assertSame('password', $this->crypto->decryptIfEncrypted($encrypted));
    }

    public function testDecryptIfEncryptedPassesThroughPlaintext(): void
    {
        // A config.yml-sourced plaintext password (e.g. $VAR-substituted) must
        // never be mistaken for an encrypted value and mangled.
        $this->assertSame('plain-password-from-env', $this->crypto->decryptIfEncrypted('plain-password-from-env'));
    }

    public function testDecryptIfEncryptedPassesThroughEmptyString(): void
    {
        $this->assertSame('', $this->crypto->decryptIfEncrypted(''));
    }

    public function testDecryptIfEncryptedDoesNotMisdetectCoincidentalColonShape(): void
    {
        // A plaintext value that happens to contain a colon but isn't valid
        // base64:base64 with a 16-byte IV must still pass through unchanged.
        $value = 'not-base64:either-side';
        $this->assertSame($value, $this->crypto->decryptIfEncrypted($value));
    }
}
