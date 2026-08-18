<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Variable;

use Hengeb\Listig\Variable\VariableFilter;
use PHPUnit\Framework\TestCase;

class VariableFilterTest extends TestCase
{
    public function testLowercase(): void
    {
        $this->assertSame('alice', VariableFilter::apply('lowercase', 'ALICE'));
    }

    public function testUppercase(): void
    {
        $this->assertSame('ALICE', VariableFilter::apply('uppercase', 'alice'));
    }

    public function testUrlencodeUsesRfc3986NotFormEncoding(): void
    {
        // rawurlencode(), not urlencode() — a space becomes %20, not '+'.
        $this->assertSame('a%20b', VariableFilter::apply('urlencode', 'a b'));
    }

    public function testDefaultPassesNonEmptyValueThrough(): void
    {
        $this->assertSame('value', VariableFilter::apply('default:fallback', 'value'));
    }

    public function testDefaultUsesArgWhenValueIsEmpty(): void
    {
        $this->assertSame('fallback', VariableFilter::apply('default:fallback', ''));
    }

    public function testMatchReplacesExactValue(): void
    {
        $this->assertSame('Lieber', VariableFilter::apply('match:he=>Lieber,she=>Liebe', 'he'));
        $this->assertSame('Liebe', VariableFilter::apply('match:he=>Lieber,she=>Liebe', 'she'));
    }

    public function testMatchWithNoMatchReturnsEmptyStringNotOriginalValue(): void
    {
        $this->assertSame('', VariableFilter::apply('match:he=>Lieber', 'unknown'));
    }

    public function testMatchIsCaseSensitive(): void
    {
        $this->assertSame('', VariableFilter::apply('match:he=>Lieber', 'HE'));
    }

    public function testMatchTrimsWhitespaceAroundPairs(): void
    {
        $this->assertSame('Lieber', VariableFilter::apply('match: he => Lieber ', 'he'));
    }

    public function testUnknownFilterPassesValueThroughUnfiltered(): void
    {
        // The leading '@' doesn't actually suppress error_log() (it only
        // silences PHP-level errors/warnings) — declare the real expectation.
        $this->expectErrorLog();
        $this->assertSame('value', VariableFilter::apply('nonexistent', 'value'));
    }
}
