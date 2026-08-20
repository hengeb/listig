<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Token;

use Hengeb\Listig\Token\ListFingerprint;
use PHPUnit\Framework\TestCase;

class ListFingerprintTest extends TestCase
{
    public function testSameListNameProducesSameFingerprint(): void
    {
        $this->assertSame(ListFingerprint::of('it-team'), ListFingerprint::of('it-team'));
    }

    public function testFingerprintFitsInASingleByte(): void
    {
        $fingerprint = ListFingerprint::of('a-fairly-long-list-name-for-testing-purposes');
        $this->assertGreaterThanOrEqual(0, $fingerprint);
        $this->assertLessThanOrEqual(0xFF, $fingerprint);
    }

    public function testDifferentListNamesUsuallyProduceDifferentFingerprints(): void
    {
        // Not a strict guarantee (only 256 possible values, collisions are
        // expected by design — see the class docblock), but a basic sanity
        // check that this isn't accidentally constant for every input.
        $this->assertNotSame(ListFingerprint::of('testliste'), ListFingerprint::of('announce'));
    }
}
