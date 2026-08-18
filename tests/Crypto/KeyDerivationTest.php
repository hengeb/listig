<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Crypto;

use Hengeb\Listig\Crypto\KeyDerivation;
use PHPUnit\Framework\TestCase;

class KeyDerivationTest extends TestCase
{
    public function testDerivationIsDeterministic(): void
    {
        $a = KeyDerivation::derive('secret', 'context-a');
        $b = KeyDerivation::derive('secret', 'context-a');
        $this->assertSame($a, $b);
    }

    public function testDifferentContextsProduceDifferentKeys(): void
    {
        // The whole point of per-purpose subkeys: a weakness in one use (e.g.
        // password encryption) must not carry over to another (token HMAC).
        $tokenKey = KeyDerivation::derive('secret', 'listig-token-hmac');
        $passwordKey = KeyDerivation::derive('secret', 'listig-password-encryption');
        $this->assertNotSame($tokenKey, $passwordKey);
    }

    public function testDifferentSecretsProduceDifferentKeys(): void
    {
        $a = KeyDerivation::derive('secret-one', 'same-context');
        $b = KeyDerivation::derive('secret-two', 'same-context');
        $this->assertNotSame($a, $b);
    }

    public function testDerivedKeyIs32Bytes(): void
    {
        // AES-256-CBC needs a 32-byte key.
        $key = KeyDerivation::derive('secret', 'context');
        $this->assertSame(32, strlen($key));
    }
}
