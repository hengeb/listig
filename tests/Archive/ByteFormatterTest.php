<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Archive;

use Hengeb\Listig\Archive\ByteFormatter;
use PHPUnit\Framework\TestCase;

class ByteFormatterTest extends TestCase
{
    public function testNullReturnsEmptyString(): void
    {
        $this->assertSame('', ByteFormatter::format(null));
    }

    public function testBytesBelowOneKilobyteHaveNoDecimal(): void
    {
        $this->assertSame('512 B', ByteFormatter::format(512));
    }

    public function testZeroBytes(): void
    {
        $this->assertSame('0 B', ByteFormatter::format(0));
    }

    public function testKilobytes(): void
    {
        $this->assertSame('1.0 KB', ByteFormatter::format(1024));
    }

    public function testMegabytes(): void
    {
        $this->assertSame('1.5 MB', ByteFormatter::format((int) (1.5 * 1024 * 1024)));
    }

    public function testGigabytes(): void
    {
        $this->assertSame('2.0 GB', ByteFormatter::format(2 * 1024 * 1024 * 1024));
    }

    public function testTerabytesIsTheLargestUnit(): void
    {
        // Even an absurdly large value must stop scaling at TB.
        $huge = 5 * 1024 * 1024 * 1024 * 1024 * 1024; // 5 PB worth of bytes
        $result = ByteFormatter::format($huge);
        $this->assertStringEndsWith('TB', $result);
    }
}
